"""RDS and Aurora by snapshot export, the opt-in Data API mode, and DynamoDB Export to S3.

RDS, the Data API and DynamoDB answer through botocore's Stubber; the
results bucket (where AWS would write the exports) is moto's. The test puts
the export's files where AWS would. Every value is made up.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import RESULTS, Env, config
from conftest import REPO
from ddb_fixtures import Ddb, describe
from sensitive_data_scanner.config import DataApiTarget, data_api_targets, read_config
from sensitive_data_scanner.sources.exports import ExportQuota, delete_prefix, due
from sensitive_data_scanner.sources.rds import (
    export_table_of,
    quote_identifier,
    select_sql,
    tables_sql,
)
from synthetic import CARDS, SSN_A, SSN_B, dashed
from table_fixtures import arrow_table, parquet_bytes

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
ROLE = "arn:aws:iam::123456789012:role/sds-rds-export"
KEY = "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000000"
CLUSTER_ARN = "arn:aws:rds:us-west-2:123456789012:cluster:orders"
SECRET_ARN = "arn:aws:secretsmanager:us-west-2:123456789012:secret:orders-ro-AbCdEf"  # noqa: S105 - an ARN
SNAP_ARN = "arn:aws:rds:us-west-2:123456789012:cluster-snapshot:rds:orders-2026-09-29-06-10"
RDS_ONLY = frozenset({"rds"})


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


def client(service: str) -> tuple[Any, Stubber]:
    c: Any = boto3.client(
        service,  # type: ignore[call-overload]
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    stub = Stubber(c)
    stub.activate()
    return c, stub


def estate(stub: Stubber, *, member: bool = True) -> None:
    """One Aurora PostgreSQL cluster, and what discovery must leave alone."""
    stub.add_response(
        "describe_db_clusters",
        {
            "DBClusters": [
                {"DBClusterIdentifier": "orders", "Engine": "aurora-postgresql", "TagList": []},
                {"DBClusterIdentifier": "graph", "Engine": "neptune"},
            ]
        },
    )
    instances = [{"DBInstanceIdentifier": "reports", "Engine": "sqlserver-se"}]
    if member:
        instances.append(
            {
                "DBInstanceIdentifier": "orders-1",
                "Engine": "aurora-postgresql",
                "DBClusterIdentifier": "orders",
            }
        )
    stub.add_response("describe_db_instances", {"DBInstances": instances})


def snapshots(
    stub: Stubber, arn: str = SNAP_ARN, ident: str = "rds:orders-2026-09-29-06-10"
) -> None:
    stub.add_response(
        "describe_db_cluster_snapshots",
        {
            "DBClusterSnapshots": [
                {
                    "DBClusterSnapshotArn": arn,
                    "DBClusterSnapshotIdentifier": ident,
                    "SnapshotCreateTime": dt.datetime(2026, 9, 29, 6, 10, tzinfo=dt.UTC),
                    "Status": "available",
                },
                {
                    "DBClusterSnapshotArn": arn + "-older",
                    "DBClusterSnapshotIdentifier": "older",
                    "SnapshotCreateTime": dt.datetime(2026, 9, 28, 6, 10, tzinfo=dt.UTC),
                    "Status": "available",
                },
            ]
        },
        {"DBClusterIdentifier": "orders", "SnapshotType": "automated"},
    )


def task_status(stub: Stubber, status: str) -> None:
    stub.add_response(
        "describe_export_tasks",
        {"ExportTasks": [{"ExportTaskIdentifier": "x", "Status": status}]},
        {"ExportTaskIdentifier": ANY},
    )


def rds_config(**kw: Any) -> Any:
    base: dict[str, Any] = {
        "s3_targets": [],
        "discover": RDS_ONLY,
        "rds_export_role_arn": ROLE,
        "rds_export_kms_key_arn": KEY,
    }
    base.update(kw)
    return config(**base)


def put_export(env: Env, task: str) -> None:
    """What RDS writes: Parquet per table and partition, and its own JSON."""
    base = f"exports/rds/{task}/"
    rows1 = [{"id": 1, "card_number": CARDS["visa"], "note": "hello"}]
    rows2 = [{"id": 2, "card_number": CARDS["jcb"], "note": "order 12345"}]
    for key, rows in (
        (f"{base}app/public.customers/1/part-00000-a.gz.parquet", rows1),
        (f"{base}app/public.customers/2/part-00000-b.gz.parquet", rows2),
        (f"{base}app/public.people/1/part-00000-c.gz.parquet", [{"ssn": dashed(SSN_A)}]),
    ):
        env.clients.s3.put_object(Bucket=RESULTS, Key=key, Body=parquet_bytes(arrow_table(rows)))
    env.clients.s3.put_object(Bucket=RESULTS, Key=f"{base}export_info_{task}.json", Body=b"{}")


def exports_left(env: Env) -> list[str]:
    r = env.clients.s3.list_objects_v2(Bucket=RESULTS, Prefix="exports/")
    return [o["Key"] for o in r.get("Contents", [])]


# ------------------------------------------------------------------ RDS snapshot export


def test_rds_snapshot_export_from_start_to_cleanup(env: Env) -> None:
    rds, stub = client("rds")
    env.clients.rds = rds
    cfg = rds_config()
    # Run 1: discover, find the latest automated snapshot, start one export.
    estate(stub)
    snapshots(stub)
    stub.add_response(
        "start_export_task",
        {"ExportTaskIdentifier": "t", "Status": "STARTING"},
        {
            "ExportTaskIdentifier": ANY,
            "SourceArn": SNAP_ARN,
            "S3BucketName": RESULTS,
            "S3Prefix": "exports/rds",
            "IamRoleArn": ROLE,
            "KmsKeyId": KEY,
        },
    )
    first = env.run(cfg)
    assert first is not None
    valid(first)
    s = stores(first)
    assert (s["orders"]["status"], s["orders"]["reason"], s["orders"]["exportStatus"]) == (
        "deferred",
        "export_pending",
        "starting",
    )
    assert (s["graph"]["reason"], s["graph"]["engine"]) == ("unsupported", "neptune")
    assert s["reports"]["reason"] == "unsupported"
    assert "orders-1" not in s  # a cluster member: its cluster's snapshot covers it
    task = env.state()["cursors"]["rds:cluster:orders"]["task"]
    assert task.startswith("sds-")
    # Run 2: still exporting.
    estate(stub)
    task_status(stub, "IN_PROGRESS")
    second = env.run(cfg)
    assert second is not None
    assert stores(second)["orders"]["reason"] == "export_pending"
    # Run 3: complete. Read the Parquet by column, then delete the export.
    put_export(env, task)
    estate(stub)
    task_status(stub, "COMPLETE")
    third = env.run(cfg)
    assert third is not None
    valid(third)
    stub.assert_no_pending_responses()
    found = {
        (f["resource"]["table"], f["resource"]["column"], f["class"]): f for f in third["findings"]
    }
    assert set(found) == {
        ("public.customers", "card_number", "card"),
        ("public.people", "ssn", "us_ssn"),
    }
    card = found[("public.customers", "card_number", "card")]
    assert card["resource"] | {} == {
        "type": "rds_column",
        "engine": "aurora-postgresql",
        "dbType": "cluster",
        "cluster": "orders",
        "database": "app",
        "table": "public.customers",
        "column": "card_number",
        "readBy": "snapshot_export",
        "snapshotTime": "2026-09-29T06:10:00+00:00",
    }
    assert card["count"] == 2  # two part files, one card each: added up
    assert card["offsets"] == []  # rows are gone with the export
    assert card["link"].startswith("https://us-west-2.console.aws.amazon.com/rds/home")
    cov = next(c for c in third["coverage"] if c["kind"] == "rds")
    assert (cov["scanned"], cov["formats"], cov["passComplete"]) == (3, {"parquet": 3}, True)
    assert exports_left(env) == []  # cleaned up
    assert stores(third)["orders"]["status"] == "scanned"
    # Run 4: the same latest snapshot: nothing to export, findings kept.
    estate(stub)
    snapshots(stub)
    fourth = env.run(cfg)
    assert fourth is not None
    stub.assert_no_pending_responses()
    assert len(fourth["findings"]) == 2
    assert stores(fourth)["orders"]["snapshotTime"] == "2026-09-29T06:10:00+00:00"


def test_rds_export_needs_the_role_and_key(env: Env) -> None:
    rds, stub = client("rds")
    env.clients.rds = rds
    estate(stub)
    doc = env.run(rds_config(rds_export_role_arn=None))
    assert doc is not None
    stub.assert_no_pending_responses()  # no snapshot call, no export
    assert stores(doc)["orders"]["reason"] == "export_not_configured"


def test_no_snapshot_is_reported(env: Env) -> None:
    rds, stub = client("rds")
    env.clients.rds = rds
    estate(stub)
    stub.add_response("describe_db_cluster_snapshots", {"DBClusterSnapshots": []})
    doc = env.run(rds_config())
    assert doc is not None
    assert (stores(doc)["orders"]["status"], stores(doc)["orders"]["reason"]) == (
        "skipped",
        "no_snapshot",
    )


def test_a_failed_export_is_cleaned_up_and_not_retried_for_the_same_snapshot(env: Env) -> None:
    rds, stub = client("rds")
    env.clients.rds = rds
    estate(stub)
    snapshots(stub)
    stub.add_response("start_export_task", {"ExportTaskIdentifier": "t"})
    env.run(rds_config())
    task = env.state()["cursors"]["rds:cluster:orders"]["task"]
    env.clients.s3.put_object(Bucket=RESULTS, Key=f"exports/rds/{task}/partial.json", Body=b"{}")
    estate(stub)
    task_status(stub, "FAILED")
    failed = env.run(rds_config())
    assert failed is not None
    valid(failed)
    assert (stores(failed)["orders"]["status"], stores(failed)["orders"]["reason"]) == (
        "error",
        "export_failed",
    )
    assert exports_left(env) == []
    estate(stub)
    snapshots(stub)  # the same snapshot: no second export
    again = env.run(rds_config())
    assert again is not None
    stub.assert_no_pending_responses()
    assert stores(again)["orders"]["reason"] == "export_failed"


def test_exports_per_run_are_capped(env: Env) -> None:
    rds, stub = client("rds")
    env.clients.rds = rds
    estate(stub)
    snapshots(stub)  # looked up; no export may start this run
    doc = env.run(rds_config(max_exports_per_run=0))
    assert doc is not None
    stub.assert_no_pending_responses()
    assert (stores(doc)["orders"]["status"], stores(doc)["orders"]["reason"]) == (
        "deferred",
        "budget",
    )


def test_export_helpers() -> None:
    assert export_table_of("app/public.customers/1/part-00000-x.gz.parquet") == (
        "app",
        "public.customers",
    )
    assert export_table_of("export_info_x.json") is None
    q = ExportQuota(1)
    assert q.take() and not q.take()
    now = dt.datetime(2026, 9, 29, tzinfo=dt.UTC)
    assert due(None, now, 7)
    assert not due((now - dt.timedelta(days=2)).isoformat(), now, 7)
    assert due((now - dt.timedelta(days=8)).isoformat(), now, 7)


def test_cleanup_never_leaves_the_exports_prefix(env: Env) -> None:
    for prefix in ("findings/", "state/", "exports", "data/exports-x/"):
        with pytest.raises(ValueError, match="exports prefix"):
            delete_prefix(env.clients.s3, RESULTS, prefix)


# ------------------------------------------------------------------ Data API (opt-in)


def data_api(
    stub: Stubber, engine: str, tables: list[tuple[str, str]], rows: dict[str, list[dict[str, Any]]]
) -> None:
    stub.add_response("begin_transaction", {"transactionId": "tx-1"})
    if engine == "postgresql":
        stub.add_response(
            "execute_statement",
            {},
            {
                "resourceArn": CLUSTER_ARN,
                "secretArn": SECRET_ARN,
                "database": "app",
                "sql": "SET TRANSACTION READ ONLY",
                "formatRecordsAs": "JSON",
                "transactionId": "tx-1",
            },
        )
    listed = [{"table_schema": s, "table_name": t} for s, t in tables]
    stub.add_response("execute_statement", {"formattedRecords": json.dumps(listed)})
    for s, t in sorted(tables):
        stub.add_response(
            "execute_statement",
            {"formattedRecords": json.dumps(rows.get(t, []))},
            {
                "resourceArn": CLUSTER_ARN,
                "secretArn": SECRET_ARN,
                "database": "app",
                "sql": select_sql(engine, s, t, 1000),
                "formatRecordsAs": "JSON",
                "transactionId": "tx-1",
            },
        )
    stub.add_response(
        "rollback_transaction",
        {"transactionStatus": "Rollback Complete"},
        {"resourceArn": CLUSTER_ARN, "secretArn": SECRET_ARN, "transactionId": "tx-1"},
    )


def target(engine: str = "postgresql") -> DataApiTarget:
    return DataApiTarget(
        cluster_arn=CLUSTER_ARN, secret_arn=SECRET_ARN, database="app", engine=engine
    )


@pytest.mark.parametrize("engine", ["postgresql", "mysql"])
def test_data_api_reads_read_only_and_always_rolls_back(env: Env, engine: str) -> None:
    rd, stub = client("rds-data")
    env.clients.rds_data = rd
    weird = 'odd"name`; DROP TABLE x; --'
    data_api(
        stub,
        engine,
        [("public", "customers"), ("public", weird)],
        {
            "customers": [{"id": 1, "card_number": CARDS["visa"]}, {"id": 2, "card_number": None}],
            weird: [{"ssn": dashed(SSN_A)}],
        },
    )
    doc = env.run(config(s3_targets=[], data_api_targets=[target(engine)]))
    assert doc is not None
    valid(doc)
    stub.assert_no_pending_responses()  # the rollback included
    found = {(f["resource"]["table"], f["resource"]["column"], f["class"]) for f in doc["findings"]}
    assert found == {
        ("public.customers", "card_number", "card"),
        (f"public.{weird}", "ssn", "us_ssn"),
    }
    f = doc["findings"][0]
    assert (f["resource"]["readBy"], f["format"]) == ("data_api", "sql")
    assert doc["coverage"][0]["scanned"] == 2


def test_data_api_rolls_back_when_a_statement_fails(env: Env) -> None:
    rd, stub = client("rds-data")
    env.clients.rds_data = rd
    stub.add_response("begin_transaction", {"transactionId": "tx-1"})
    stub.add_client_error(
        "execute_statement", service_error_code="BadRequestException", http_status_code=400
    )
    stub.add_response("rollback_transaction", {"transactionStatus": "Rollback Complete"})
    doc = env.run(config(s3_targets=[], data_api_targets=[target()]))
    assert doc is not None
    stub.assert_no_pending_responses()
    assert doc["coverage"][0]["error"] == "BadRequestException"


def test_sql_is_the_scanners_own_and_identifiers_are_quoted() -> None:
    assert quote_identifier('a"b', "postgresql") == '"a""b"'
    assert quote_identifier("a`b", "mysql") == "`a``b`"
    assert select_sql("postgresql", "public", 'x"; DROP TABLE y; --', 5) == (
        'SELECT * FROM "public"."x""; DROP TABLE y; --" LIMIT 5'
    )
    sql, params = tables_sql("postgresql", ("public", "sales"))
    assert ":s0" in sql and ":s1" in sql and "sales" not in sql
    assert params[1] == {"name": "s1", "value": {"stringValue": "sales"}}


def test_data_api_config() -> None:
    raw = json.dumps(
        [
            {
                "clusterArn": CLUSTER_ARN,
                "secretArn": SECRET_ARN,
                "database": "app",
                "engine": "mysql",
                "maxRowsPerTable": 50,
            }
        ]
    )
    t = data_api_targets(raw)[0]
    assert (t.engine, t.max_rows_per_table, t.max_tables) == ("mysql", 50, 200)
    for bad in (
        '[{"clusterArn": "x", "secretArn": "y", "database": "d", "engine": "mysql"}]',
        json.dumps(
            [
                {
                    "clusterArn": CLUSTER_ARN,
                    "secretArn": SECRET_ARN,
                    "database": "app",
                    "engine": "oracle",
                }
            ]
        ),
        json.dumps(
            [
                {
                    "clusterArn": CLUSTER_ARN,
                    "secretArn": SECRET_ARN,
                    "database": "app",
                    "engine": "mysql",
                    "sql": "x",
                }
            ]
        ),
    ):
        with pytest.raises(ValueError):
            data_api_targets(bad)
    c = read_config({"RESULTS_BUCKET": RESULTS})
    assert c.data_api_targets == []  # off by default
    assert (c.dynamodb_export, c.max_exports_per_run, c.export_min_interval_days) == (False, 1, 7)
    with pytest.raises(ValueError):
        read_config({"RESULTS_BUCKET": RESULTS, "RDS_EXPORT_ROLE_ARN": "not-an-arn"})


# ------------------------------------------------------------------ DynamoDB Export to S3

TABLE_ARN = "arn:aws:dynamodb:us-west-2:123456789012:table/events"


def ddb_estate(ddb: Ddb) -> None:
    ddb.stub.add_response("list_tables", {"TableNames": ["events", "ledger"]})
    for name in ("events", "ledger"):
        d = describe(name, sort_key=False)
        d["Table"].update(
            TableStatus="ACTIVE",
            TableSizeBytes=50 * 1024**3,
            TableArn=f"arn:aws:dynamodb:us-west-2:123456789012:table/{name}",
        )
        ddb.stub.add_response("describe_table", d)
        ddb.stub.add_response(
            "describe_continuous_backups",
            {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED" if name == "events" else "DISABLED"
                    },
                }
            },
            {"TableName": name},
        )


def test_dynamodb_export_for_a_large_table(env: Env) -> None:
    ddb = Ddb()
    env.clients.dynamodb = ddb.client
    cfg = config(s3_targets=[], discover=frozenset({"dynamodb"}), dynamodb_export=True)
    digest = hashlib.sha256(TABLE_ARN.encode()).hexdigest()[:12]
    prefix = f"exports/dynamodb/{digest}"
    ddb_estate(ddb)
    ddb.stub.add_response(
        "export_table_to_point_in_time",
        {"ExportDescription": {"ExportArn": f"{TABLE_ARN}/export/01"}},
        {
            "TableArn": TABLE_ARN,
            "S3Bucket": RESULTS,
            "S3Prefix": prefix,
            "ExportFormat": "DYNAMODB_JSON",
            "ExportType": "FULL_EXPORT",
            "ClientToken": ANY,
            "S3SseAlgorithm": "AES256",
        },
    )
    first = env.run(cfg)
    assert first is not None
    valid(first)
    s = stores(first)
    assert (s["events"]["status"], s["events"]["reason"], s["events"]["readBy"]) == (
        "deferred",
        "export_pending",
        "export",
    )
    assert (s["ledger"]["reason"], s["ledger"]["pitr"]) == ("pitr_off", False)
    base = f"{prefix}/AWSDynamoDB/01234-abcd/"
    lines = [
        json.dumps(
            {"Item": {"pk": {"S": f"C#{CARDS['visa']}"}, "note": {"S": f"ssn {dashed(SSN_B)}"}}}
        ),
        json.dumps({"Item": {"pk": {"S": "C#2"}, "note": {"S": "nothing here"}}}),
    ]
    env.clients.s3.put_object(
        Bucket=RESULTS, Key=f"{base}data/abc.json.gz", Body=gzip.compress("\n".join(lines).encode())
    )
    env.clients.s3.put_object(Bucket=RESULTS, Key=f"{base}manifest-summary.json", Body=b"{}")
    ddb_estate(ddb)
    ddb.stub.add_response(
        "describe_export",
        {
            "ExportDescription": {
                "ExportStatus": "COMPLETED",
                "ExportManifest": f"{base}manifest-summary.json",
            }
        },
    )
    d = describe("events", sort_key=False)
    ddb.stub.add_response("describe_table", d)
    second = env.run(cfg)
    assert second is not None
    valid(second)
    ddb.stub.assert_no_pending_responses()
    found = {(f["resource"]["attributePath"], f["class"]) for f in second["findings"]}
    assert found == {("note", "us_ssn"), ("pk", "card")}  # the key holds a card too
    f = second["findings"][0]
    assert f["resource"]["type"] == "dynamodb_item"
    assert f["resource"]["key"] == {"pk": "C#################"}
    assert exports_left(env) == []
    assert stores(second)["events"]["status"] == "scanned"


def test_the_handler_makes_a_client_for_each_kind_it_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    from sensitive_data_scanner import handler

    made: list[str] = []

    def fake_client(name: str, **kw: Any) -> str:
        made.append(name)
        return name

    monkeypatch.setattr("boto3.client", fake_client)
    seen: dict[str, Any] = {}

    def run_scan(config: Any, clients: Any, **kw: Any) -> None:
        seen["clients"] = clients

    monkeypatch.setattr(handler, "run_scan", run_scan)
    raw = json.dumps(
        [{"clusterArn": CLUSTER_ARN, "secretArn": SECRET_ARN, "database": "app", "engine": "mysql"}]
    )
    for k, v in {"RESULTS_BUCKET": RESULTS, "DISCOVER": "all", "RDS_DATA_API": raw}.items():
        monkeypatch.setenv(k, v)

    class Context:
        invoked_function_arn = "arn:aws:lambda:us-west-2:123456789012:function:sds"

        def get_remaining_time_in_millis(self) -> int:
            return 900_000

    assert handler.handler({}, Context()) == {"status": "locked"}
    c = seen["clients"]
    assert (c.dynamodb, c.glue, c.rds, c.rds_data) == ("dynamodb", "glue", "rds", "rds-data")
    assert set(made) == {"s3", "logs", "dynamodb", "glue", "rds", "rds-data"}
