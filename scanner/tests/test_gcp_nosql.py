"""Firestore, Datastore, Spanner and Bigtable: sampled reads with viewer and reader roles.

Every Google call goes to a stubbed session (gcp_fakes.py); every value is made up.
"""

from __future__ import annotations

from typing import Any

from aws_fixtures import shared_detector
from gcp_fakes import KEY, NOW, PROJECT, Cloud, NoSql, asset, b64, error, settings, vpc_denied
from sensitive_data_core.findings import key_hash
from sensitive_data_gcp.resources import resource_name_hash
from sensitive_data_gcp.runner import run_scan
from sensitive_data_gcp.sources.bigtable import decode_rows
from sensitive_data_gcp.sources.documents import value
from synthetic import CARDS, SSN_A, dashed
from test_gcp_gcs import valid

FS = "firestore.googleapis.com/Database"
SP = "spanner.googleapis.com/Database"
BT = "bigtableadmin.googleapis.com/Table"
SPANNER_DB = f"projects/{PROJECT}/instances/inst-main/databases/ledger"
SPANNER_PG = f"projects/{PROJECT}/instances/inst-main/databases/pgledger"
TABLE = f"projects/{PROJECT}/instances/bt-main/tables/events"
DOCS = [
    {"name": "A", "card": CARDS["visa"], "profile": {"ssn": dashed(SSN_A)}, "raw": b"\x00\x01"},
    {"name": "B", "tags": ["x", f"card {CARDS['mastercard']}"]},
]


def cloud() -> tuple[Cloud, NoSql]:
    c = Cloud()
    n = NoSql(c)
    c.assets[FS] = [
        asset(FS, f"//firestore.googleapis.com/projects/{PROJECT}/databases/(default)"),
        asset(FS, f"//firestore.googleapis.com/projects/{PROJECT}/databases/legacy"),
        asset(FS, f"//firestore.googleapis.com/projects/{PROJECT}/databases/fenced"),
    ]
    n.firestore[(PROJECT, "(default)")] = {
        "type": "FIRESTORE_NATIVE",
        "kms": KEY,
        "collections": {"customers": DOCS, "empty": []},
    }
    n.firestore[(PROJECT, "legacy")] = {
        "type": "DATASTORE_MODE",
        "collections": {"Payment": DOCS},
    }
    n.fail["databases/fenced"] = vpc_denied()
    c.assets[SP] = [
        asset(SP, f"//spanner.googleapis.com/{SPANNER_DB}"),
        asset(SP, f"//spanner.googleapis.com/{SPANNER_PG}"),
    ]
    n.spanner[SPANNER_DB] = {
        "dialect": "GOOGLE_STANDARD_SQL",
        "kms": KEY,
        "bytes": "blob",
        "tables": {
            "Orders": [
                {"CardNumber": CARDS["amex"], "Note": f"ssn {dashed(SSN_A)}", "blob": "AAE="}
            ]
        },
    }
    n.spanner[SPANNER_PG] = {
        "dialect": "POSTGRESQL",
        "tables": {"payments": [{"card": CARDS["discover"]}]},
    }
    c.assets[BT] = [asset(BT, f"//bigtableadmin.googleapis.com/{TABLE}")]
    n.bigtable[TABLE] = {
        f"card#{CARDS['visa']}": {
            "profile:card": CARDS["jcb"],
            "profile:photo": b"\x89PNG\x00\x00",
        },
        "user#2": {"profile:note": "nothing"},
    }
    n.bigtable_keys[f"projects/{PROJECT}/instances/bt-main"] = KEY
    return c, n


def run(c: Cloud, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(DISCOVER="firestore,datastore,spanner,bigtable", **env),
        c.clients(),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}


def found(doc: dict[str, Any], service: str) -> set[tuple[str, str, str]]:
    return {
        (f["resource"].get("table", ""), f["resource"]["field"], f["class"])
        for f in doc["findings"]
        if f["resource"]["service"] == service
    }


def test_each_kind_is_discovered_with_its_key_and_gaps() -> None:
    c, _ = cloud()
    s = stores(run(c))
    native = s[("firestore", f"{PROJECT}/(default)")]
    assert native["status"] == "scanned" and native["atRestKeyHash"] == key_hash(KEY)
    assert native["resourceNameHash"] == resource_name_hash(
        f"//firestore.googleapis.com/projects/{PROJECT}/databases/(default)"
    )
    assert s[("datastore", f"{PROJECT}/legacy")]["status"] == "scanned"
    assert ("datastore", f"{PROJECT}/(default)") not in s  # each database under its mode only
    fenced = s[("firestore", f"{PROJECT}/fenced")]
    assert (fenced["status"], fenced["reason"]) == ("error", "network")
    assert ("datastore", f"{PROJECT}/fenced") not in s  # reported once
    assert s[("spanner", "inst-main/ledger")]["atRestKeyHash"] == key_hash(KEY)
    assert s[("spanner", "inst-main/pgledger")]["atRestEncryption"] == "service_managed"
    assert s[("bigtable", "bt-main/events")]["atRestKeyHash"] == key_hash(KEY)


def test_firestore_and_datastore_are_read_by_field_with_queries_only() -> None:
    c, n = cloud()
    doc = run(c, DOCUMENTS_MAX_PER_COLLECTION="10")
    assert {("customers", "card", "card"), ("customers", "profile", "us_ssn")} <= found(
        doc, "firestore"
    )
    assert ("customers", "tags", "card") in found(doc, "firestore")
    assert {("Payment", "card", "card"), ("Payment", "profile", "us_ssn")} <= found(
        doc, "datastore"
    )
    f = next(x for x in doc["findings"] if x["resource"]["service"] == "firestore")
    assert (f["resource"]["store"], f["resource"]["readBy"], f["format"]) == (
        "(default)",
        "query",
        "json",
    )
    assert f["link"].startswith("https://console.cloud.google.com/firestore/databases/")
    limits = [q["structuredQuery"]["limit"] for q in n.queries if "structuredQuery" in q]
    assert limits and set(limits) == {10}
    # Only queries and listings go to Firestore and Datastore.
    docs = [q for q in n.queries if "rowsLimit" not in q]
    assert docs and all("query" in q or "structuredQuery" in q or "pageSize" in q for q in docs)


def test_spanner_is_sampled_in_single_use_read_only_transactions() -> None:
    c, n = cloud()
    doc = run(c)
    assert ("Orders", "CardNumber", "card") in found(doc, "spanner")
    assert ("Orders", "Note", "us_ssn") in found(doc, "spanner")
    assert ("public.payments", "card", "card") in found(doc, "spanner")
    assert all(b["transaction"] == {"singleUse": {"readOnly": {"strong": True}}} for b in n.sql)
    samples = [b["sql"] for b in n.sql if "LIMIT" in b["sql"]]
    assert "SELECT * FROM `Orders` LIMIT 1000" in samples
    assert 'SELECT * FROM "public"."payments" LIMIT 1000' in samples
    assert all(b["sql"].lstrip().upper().startswith("SELECT") for b in n.sql)
    assert len(n.sessions) == 2 and len(n.deleted) == 2  # every session deleted after
    f = next(x for x in doc["findings"] if x["resource"]["service"] == "spanner")
    assert (f["resource"]["store"], f["resource"]["database"], f["format"]) == (
        "inst-main",
        f["resource"]["database"],
        "sql",
    )


def test_spanner_off_lists_databases_and_opens_no_session() -> None:
    """C2 (#105): GCP_SPANNER off (on by default): each database is `read_not_configured`,
    naming the setting, and no session (one of the named exceptions) is ever made."""
    c, n = cloud()
    doc = run(c, GCP_SPANNER="off")
    s = stores(doc)
    for name in ("inst-main/ledger", "inst-main/pgledger"):
        st = s[("spanner", name)]
        assert (st["status"], st["reason"], st["toggle"]) == (
            "skipped",
            "read_not_configured",
            "GCP_SPANNER",
        )
    assert n.sessions == [] and n.sql == []
    assert not found(doc, "spanner")


def test_bigtable_reads_the_latest_cells_and_the_row_key() -> None:
    c, n = cloud()
    doc = run(c, BIGTABLE_MAX_ROWS="50")
    got = found(doc, "bigtable")
    assert ("events", "profile:card", "card") in got
    assert ("events", "rowKey", "card") in got  # a key can hold a value too
    assert not any(f.endswith("photo") for _, f, _ in got)  # not text: not read
    reads = [q for q in n.queries if "rowsLimit" in q]
    assert reads == [{"rowsLimit": "50", "filter": {"cellsPerColumnLimitFilter": 1}}]
    f = next(x for x in doc["findings"] if x["resource"]["service"] == "bigtable")
    assert (f["resource"]["store"], f["resource"]["readBy"]) == ("bt-main", "read_rows")


def test_a_refused_read_is_its_stores_gap() -> None:
    c, n = cloud()
    n.fail["databases/ledger"] = error(403, "PERMISSION_DENIED", message="no select")
    n.fail[":readRows"] = error(403, "PERMISSION_DENIED", message="no readRows")
    s = stores(run(c))
    assert s[("spanner", "inst-main/ledger")]["reason"] == "access_denied"
    assert s[("bigtable", "bt-main/events")]["reason"] == "access_denied"


def test_a_pass_resumes_at_the_next_collection() -> None:
    c, n = cloud()
    n.firestore[(PROJECT, "(default)")]["collections"] = {f"c{i}": DOCS for i in range(5)}
    doc = run(c, MAX_ITEMS_PER_RUN="6")
    native = stores(doc)[("firestore", f"{PROJECT}/(default)")]
    assert native.get("backlog") or native["status"] == "deferred"
    before = sum(1 for q in n.queries if "structuredQuery" in q)
    run(c)
    after = sum(1 for q in n.queries if "structuredQuery" in q)
    assert 0 < after - before < 5  # only the collections the first run did not reach


def test_values_decode_and_bytes_are_dropped() -> None:
    assert value({"mapValue": {"fields": {"a": {"integerValue": "4"}}}}) == {"a": "4"}
    assert value({"bytesValue": "AAE="}) is None
    assert value({"entityValue": {"properties": {"x": {"stringValue": "y"}}}}) == {"x": "y"}
    rows = decode_rows(
        [
            {
                "chunks": [
                    {
                        "rowKey": b64("k1"),
                        "familyName": "f",
                        "qualifier": b64("q"),
                        "value": b64("v"),
                    },
                    {"resetRow": True},
                ]
            },
            {
                "chunks": [
                    {
                        "rowKey": b64("k2"),
                        "familyName": {"value": "f"},
                        "qualifier": b64("q"),
                        "value": b64("ab"),
                        "valueSize": 4,
                    },
                    {"value": b64("cd"), "commitRow": True},
                ]
            },
        ]
    )
    assert rows == [{"rowKey": "k2", "f:q": "abcd"}]
