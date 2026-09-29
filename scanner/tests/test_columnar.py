"""Columnar and data-lake formats in S3 (Parquet, ORC, Avro, gzip and zstd CSV and JSON
lines), and Glue Data Catalog tables with Lake Formation respected. S3 runs against
moto; Glue against botocore's Stubber. Every value is made up."""

from __future__ import annotations

import ast
import gzip
import hashlib
import io
import json
from typing import Any

import pytest
from botocore.exceptions import ClientError
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, RESULTS, Env, config, shared_detector
from conftest import REPO
from sensitive_data_scanner.config import read_config, store_rules
from sensitive_data_scanner.discovery import glue_location
from sensitive_data_scanner.scan.avro import AvroError, AvroReader
from sensitive_data_scanner.scan.columnar import columnar_kind, scan_rows, sniff
from sensitive_data_scanner.sources import s3 as s3_module
from synthetic import CARDS, SSN_A, dashed
from table_fixtures import (
    Glue,
    arrow_table,
    avro_bytes,
    glue_table,
    orc_bytes,
    parquet_bytes,
    zstd_bytes,
)

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
PACKAGE = REPO / "scanner" / "src" / "sensitive_data_scanner"
EXPECTED = {
    ("card_number", "card"),
    ("ssn", "us_ssn"),
    ("date_of_birth", "dob"),
    ("payment", "card"),
}


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def columns(doc: dict[str, Any], key: str) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (f["resource"]["column"], f["class"]): f
        for f in doc["findings"]
        if f["resource"]["key"] == key
    }


# ------------------------------------------------------------------ formats


@pytest.mark.parametrize(
    ("key", "body", "fmt"),
    [
        ("lake/customers/part-0.parquet", parquet_bytes, "parquet"),
        ("lake/customers/part-0.snappy.parquet", parquet_bytes, "parquet"),
        ("lake/customers/part-0.orc", orc_bytes, "orc"),
        ("lake/customers/part-0.avro", avro_bytes, "avro"),
        ("lake/customers/part-00000", parquet_bytes, "parquet"),  # no extension: magic bytes
    ],
)
def test_each_columnar_format_gives_column_findings(
    env: Env, key: str, body: Any, fmt: str
) -> None:
    env.put(key, body())
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    found = columns(doc, key)
    assert set(found) == EXPECTED, fmt
    card = found[("card_number", "card")]
    assert (card["format"], card["count"], card["confidence"]) == (fmt, 2, "high")
    assert [o["pointer"] for o in card["offsets"]] == ["/0/card_number", "/1/card_number"]
    assert found[("payment", "card")]["offsets"][0]["pointer"] == "/0/payment/pan"
    assert doc["coverage"][0]["formats"] == {fmt: 1}
    # The order ids and the clean note are not findings.
    assert not {c for c, _ in found} & {"order_id", "note", "customer_id"}


@pytest.mark.parametrize("codec", ["null", "deflate", "snappy", "zstandard", "bzip2", "xz"])
def test_every_avro_codec(codec: str) -> None:
    records = list(AvroReader(io.BytesIO(avro_bytes(codec))))
    assert [r["card_number"] for r in records] == [CARDS["visa"], CARDS["jcb"]]
    assert records[0]["date_of_birth"] == "1981-07-04"
    assert records[0]["payment"] == {"pan": CARDS["amex"]}


def test_avro_that_is_not_avro_is_refused() -> None:
    with pytest.raises(AvroError):
        AvroReader(io.BytesIO(b"PAR1 not avro"))
    data = bytearray(avro_bytes("deflate"))
    data[-5] ^= 0xFF  # the sync marker at the end no longer matches
    with pytest.raises(AvroError):
        list(AvroReader(io.BytesIO(bytes(data))))


def test_gzip_and_zstd_csv_and_json_lines(env: Env) -> None:
    csv_text = f"name,card_number\nA,{CARDS['visa']}\n"
    jsonl = json.dumps({"ssn": dashed(SSN_A), "note": "x"}) + "\n" + json.dumps({"n": 1}) + "\n"
    env.put("exports/a.csv.gz", gzip.compress(csv_text.encode()))
    env.put("exports/b.csv.zst", zstd_bytes(csv_text.encode()))
    env.put("exports/c.jsonl.zst", zstd_bytes(jsonl.encode()))
    env.put("exports/d.jsonl.gz", gzip.compress(jsonl.encode()))
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    found = {(f["resource"]["key"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {
        ("exports/a.csv.gz", "card"),
        ("exports/b.csv.zst", "card"),
        ("exports/c.jsonl.zst", "us_ssn"),
        ("exports/d.jsonl.gz", "us_ssn"),
    }
    assert found[("exports/b.csv.zst", "card")]["format"] == "csv"
    assert found[("exports/c.jsonl.zst", "us_ssn")]["offsets"][0]["pointer"] == "/0/ssn"


def test_a_large_parquet_file_is_read_by_range_up_to_the_row_cap(env: Env) -> None:
    rows = [
        {
            "id": i,
            "card_number": CARDS["visa"] if i == 3 else hashlib.sha256(str(i).encode()).hexdigest(),
        }
        for i in range(40_000)
    ]
    body = parquet_bytes(arrow_table(rows), row_group_size=1000)
    env.put("lake/big.parquet", body)
    doc = env.run(config(columnar_max_rows=1000))
    assert doc is not None
    cov = doc["coverage"][0]
    assert cov["partial"] == 1
    assert 0 < cov["bytesScanned"] < len(body) // 4  # the footer and one row group
    assert set(columns(doc, "lake/big.parquet")) == {("card_number", "card")}


def test_a_byte_cap_before_the_first_batch_is_stated(env: Env) -> None:
    env.put("lake/x.parquet", parquet_bytes())
    doc = env.run(config(max_object_bytes=1024))
    assert doc is not None
    cov = doc["coverage"][0]
    assert (cov["partial"], cov["skipped"]) == (1, {"columnar": 1})


def test_without_pyarrow_columnar_files_are_named_skipped(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(s3_module, "pyarrow_available", lambda: False)
    env.put("lake/a.parquet", parquet_bytes())
    env.put("lake/b.orc", orc_bytes())
    env.put("lake/c.jsonl.zst", zstd_bytes(b'{"a": 1}\n'))
    env.put("lake/d.avro", avro_bytes("snappy"))
    env.put("lake/e.avro", avro_bytes("deflate"))  # the standard library is enough
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    cov = doc["coverage"][0]
    assert cov["skipped"] == {"columnar": 4}
    assert cov["formats"] == {"avro": 1}
    assert {f["resource"]["key"] for f in doc["findings"]} == {"lake/e.avro"}


def test_kind_by_extension_and_magic() -> None:
    assert columnar_kind("a/b.snappy.parquet") == "parquet"
    assert columnar_kind("a/part-00000-1.gz.parquet") == "parquet"
    assert columnar_kind("a/b.orc") == "orc"
    assert columnar_kind("a/b.avro") == "avro"
    assert columnar_kind("a/b.csv") is None
    assert sniff(b"PAR1....") == "parquet"
    assert sniff(b"ORC\x0a") == "orc"
    assert sniff(b"Obj\x01") == "avro"
    assert sniff(b"{}") is None


def test_a_value_split_by_rows_is_not_joined() -> None:
    rows = [{"n": CARDS["visa"][:8]}, {"n": CARDS["visa"][8:]}]
    result = scan_rows("csv", ["n"], rows, shared_detector(), 100)
    assert result.by_column == {}


def test_config_for_columnar_and_lake_formation() -> None:
    c = read_config({"RESULTS_BUCKET": RESULTS, "COLUMNAR_MAX_ROWS": "50"})
    assert (c.columnar_max_rows, c.glue_lake_formation) == (50, "read")
    assert (
        read_config({"RESULTS_BUCKET": RESULTS, "GLUE_LAKE_FORMATION": "skip"}).glue_lake_formation
        == "skip"
    )
    with pytest.raises(ValueError):
        read_config({"RESULTS_BUCKET": RESULTS, "GLUE_LAKE_FORMATION": "grant"})


# ------------------------------------------------------------------ Glue


def test_glue_location() -> None:
    assert glue_location("s3://b/lake/customers") == ("b", "lake/customers/")
    assert glue_location("s3a://b/lake/") == ("b", "lake/")
    assert glue_location("s3://b") == ("b", "")
    assert glue_location("jdbc:postgresql://x") is None


def test_glue_tables_name_database_table_and_column(env: Env) -> None:
    env.put("lake/customers/part-0.parquet", parquet_bytes())
    # A CSV table with no header: its columns come from the catalog.
    env.put("lake/legacy/2026/09/28/data.csv", f"c-001\x01{CARDS['visa']}\x01hello\n")
    env.put("loose/notes.txt", f"ssn {dashed(SSN_A)}")
    glue = Glue()
    glue.databases("lake", link="shared")
    glue.tables(
        "lake",
        [
            glue_table(
                "customers",
                f"s3://{DATA}/lake/customers",
                serde="org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
            ),
            glue_table(
                "legacy",
                f"s3://{DATA}/lake/legacy/",
                serde="org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                columns=["customer_id", "pan", "comment"],
            ),
            glue_table("recent", f"s3://{DATA}/lake/customers", table_type="VIRTUAL_VIEW"),
            glue_table("remote", "jdbc:postgresql://db.example.com/app"),
        ],
    )
    env.clients.glue = glue.client
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3", "glue_table"}),
            deny=store_rules(f"s3:{RESULTS}"),
        )
    )
    assert doc is not None
    valid(doc)
    glue.stub.assert_no_pending_responses()
    by = {
        (f["resource"].get("catalog", {}).get("table"), f["resource"].get("column"), f["class"])
        for f in doc["findings"]
    }
    assert by == {
        ("customers", "card_number", "card"),
        ("customers", "ssn", "us_ssn"),
        ("customers", "date_of_birth", "dob"),
        ("customers", "payment", "card"),
        ("legacy", "pan", "card"),
        (None, None, "us_ssn"),  # the bucket's own source reads what no table covers
    }
    f = next(f for f in doc["findings"] if f["resource"].get("column") == "pan")
    assert f["resource"]["catalog"] == {"database": "lake", "table": "legacy"}
    assert f["offsets"][0]["pointer"] == "/0/pan"
    kinds = {c["kind"]: c for c in doc["coverage"] if c["target"] == "lake.customers"}
    assert kinds["glue_table"]["scanned"] == 1
    stores = {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}
    assert stores[("glue_table", "lake.customers")]["location"] == f"{DATA}/lake/customers/"
    assert stores[("glue_table", "lake.recent")]["catalogObject"] == "view"
    assert stores[("glue_table", "lake.remote")]["catalogObject"] == "not_s3"
    assert stores[("glue_table", "shared.*")]["catalogObject"] == "resource_link"
    # Each object is read once: by its table, not again by its bucket.
    s3_cov = next(c for c in doc["coverage"] if c["kind"] == "s3")
    assert s3_cov["scanned"] == 1


def test_lake_formation_denials_are_gaps_never_worked_around(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.put("governed/part-0.parquet", parquet_bytes())
    glue = Glue()
    glue.databases("lake", "hr")
    glue.tables(
        "lake",
        [glue_table("governed", f"s3://{DATA}/governed/", lake_formation=True)],
    )
    glue.denied("hr", "Insufficient Lake Formation permission(s) on hr")
    env.clients.glue = glue.client
    real = env.clients.s3.get_object

    def get_object(**kw: Any) -> Any:
        if kw["Key"].startswith("governed/"):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetObject")
        return real(**kw)

    monkeypatch.setattr(env.clients.s3, "get_object", get_object)
    doc = env.run(config(s3_targets=[], discover=frozenset({"glue_table"})))
    assert doc is not None
    valid(doc)
    stores = {s["name"]: s for s in doc["discovery"]["stores"]}
    assert (stores["lake.governed"]["status"], stores["lake.governed"]["reason"]) == (
        "error",
        "lake_formation",
    )
    assert stores["lake.governed"]["lakeFormation"] is True
    assert (stores["hr.*"]["status"], stores["hr.*"]["reason"]) == ("error", "lake_formation")
    assert doc["findings"] == []


def test_lake_formation_tables_can_be_left_alone(env: Env) -> None:
    glue = Glue()
    glue.databases("lake")
    glue.tables("lake", [glue_table("governed", f"s3://{DATA}/g/", lake_formation=True)])
    env.clients.glue = glue.client
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"glue_table"}), glue_lake_formation="skip")
    )
    assert doc is not None
    s = doc["discovery"]["stores"][0]
    assert (s["status"], s["reason"]) == ("skipped", "lake_formation")


def test_the_scanner_never_asks_lake_formation_for_access() -> None:
    """No Lake Formation client, no credential vending: a denial stays a denial."""
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("client"):
                named = [a.value for a in node.args if isinstance(a, ast.Constant)]
                assert "lakeformation" not in named, path.name
            if isinstance(node, ast.Attribute):
                assert node.attr not in (
                    "get_data_access",
                    "get_temporary_glue_table_credentials",
                    "get_temporary_glue_partition_credentials",
                    "grant_permissions",
                    "batch_grant_permissions",
                ), path.name
