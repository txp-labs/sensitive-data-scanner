"""Redshift and Redshift Serverless: discovery, and sampled read-only SQL over the Data API.

Redshift, Redshift Serverless and the Data API answer through botocore's
Stubber; the results bucket is moto's. Every value is made up.
"""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import Env, config
from conftest import REPO
from sensitive_data_scanner.config import read_config, store_rules
from sensitive_data_scanner.scan.sql import REDSHIFT, sample_sql, tables_sql
from sensitive_data_scanner.sources import redshift as rs_module
from synthetic import CARDS, SSN_A, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
RS = frozenset({"redshift"})
WG_ARN = "arn:aws:redshift-serverless:us-west-2:123456789012:workgroup/x"


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


class Aws:
    """Stubbed Redshift, Redshift Serverless and Data API clients, given to the run."""

    def __init__(self, env: Env) -> None:
        self.rs, self.rs_stub = client("redshift")
        self.sl, self.sl_stub = client("redshift-serverless")
        self.data, self.data_stub = client("redshift-data")
        self.n = 0
        env.clients.services.update(
            {"redshift": self.rs, "redshift-serverless": self.sl, "redshift-data": self.data}
        )

    def estate(self, *, workgroups: bool = True) -> None:
        self.rs_stub.add_response(
            "describe_clusters",
            {
                "Clusters": [
                    {
                        "ClusterIdentifier": "warehouse",
                        "ClusterStatus": "available",
                        "DBName": "dev",
                    },
                    {"ClusterIdentifier": "archive", "ClusterStatus": "paused"},
                    {"ClusterIdentifier": "resizing", "ClusterStatus": "resizing"},
                ]
            },
        )
        self.sl_stub.add_response(
            "list_namespaces",
            {
                "namespaces": [{"namespaceName": "main-ns", "dbName": "analytics"}]
                if workgroups
                else []
            },
        )
        self.sl_stub.add_response(
            "list_workgroups",
            {
                "workgroups": [
                    {
                        "workgroupName": "adhoc",
                        "namespaceName": "main-ns",
                        "status": "AVAILABLE",
                        "workgroupArn": WG_ARN,
                    }
                ]
                if workgroups
                else []
            },
        )

    def statement(
        self,
        sql: str | Any,
        rows: list[dict[str, Any]] | None,
        *,
        auth: dict[str, Any],
        database: str,
        status: str = "FINISHED",
        polls: int = 0,
        params: list[dict[str, str]] | None = None,
    ) -> None:
        """One Data API statement: execute, describe (after `polls` running), result pages."""
        expected: dict[str, Any] = {"Sql": sql, "Database": database, **auth}
        if params:
            expected["Parameters"] = params
        self.n += 1
        sid = f"stmt-{self.n}"
        self.data_stub.add_response("execute_statement", {"Id": sid}, expected)
        for _ in range(polls):
            self.data_stub.add_response("describe_statement", {"Id": sid, "Status": "STARTED"})
        self.data_stub.add_response(
            "describe_statement",
            {"Id": sid, "Status": status, "HasResultSet": rows is not None},
            {"Id": sid},
        )
        if status != "FINISHED" or rows is None:
            return
        names = list(dict.fromkeys(k for r in rows for k in r)) or ["x"]
        records = [[_field(r.get(n)) for n in names] for r in rows]
        # Two pages when there are two or more rows, so NextToken is followed.
        half = max(1, len(records) // 2) if len(records) > 1 else len(records)
        meta = [{"name": n} for n in names]
        if len(records) > 1:
            self.data_stub.add_response(
                "get_statement_result",
                {"Records": records[:half], "ColumnMetadata": meta, "NextToken": "p2"},
                {"Id": sid},
            )
            self.data_stub.add_response(
                "get_statement_result",
                {"Records": records[half:], "ColumnMetadata": meta},
                {"Id": sid, "NextToken": "p2"},
            )
        else:
            self.data_stub.add_response(
                "get_statement_result", {"Records": records, "ColumnMetadata": meta}, {"Id": sid}
            )

    def database(
        self,
        name: str,
        tables: dict[tuple[str, str], list[dict[str, Any]]],
        *,
        auth: dict[str, Any],
        failing: tuple[str, str] | None = None,
    ) -> None:
        sql, _ = tables_sql(REDSHIFT, ())
        listed = [{"table_schema": s, "table_name": t} for s, t in tables]
        self.statement(sql, listed, auth=auth, database=name)
        for (s, t), rows in sorted(tables.items()):
            status = "FAILED" if failing == (s, t) else "FINISHED"
            self.statement(
                sample_sql(REDSHIFT, s, t, 1000),
                rows,
                auth=auth,
                database=name,
                status=status,
                polls=1,
            )


def _field(v: Any) -> dict[str, Any]:
    if v is None:
        return {"isNull": True}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"longValue": v}
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)


CLUSTER = {"ClusterIdentifier": "warehouse"}
WORKGROUP = {"WorkgroupName": "adhoc"}


def test_off_by_default_discovers_and_reports(env: Env) -> None:
    aws = Aws(env)
    aws.estate()
    doc = env.run(config(s3_targets=[], discover=RS))
    assert doc is not None
    valid(doc)
    aws.data_stub.assert_no_pending_responses()  # not one statement
    s = stores(doc)
    assert (s["warehouse"]["status"], s["warehouse"]["reason"]) == (
        "skipped",
        "read_not_configured",
    )
    assert (s["warehouse"]["deployment"], s["warehouse"]["database"]) == ("provisioned", "dev")
    assert (s["adhoc"]["reason"], s["adhoc"]["deployment"], s["adhoc"]["database"]) == (
        "read_not_configured",
        "serverless",
        "analytics",
    )
    assert s["archive"]["reason"] == "paused"
    assert (s["resizing"]["reason"], s["resizing"]["state"]) == ("unsupported", "resizing")
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.redshift_read, c.redshift_max_rows, c.redshift_max_tables) == ("off", 1000, 500)


def test_iam_mode_samples_every_table_by_column(env: Env) -> None:
    aws = Aws(env)
    aws.estate()
    # Stores run in name order: the workgroup "adhoc", then the cluster "warehouse".
    aws.data_stub.add_response(
        "list_databases",
        {"Databases": ["analytics"]},
        {"WorkgroupName": "adhoc", "Database": "analytics"},
    )
    aws.database("analytics", {("public", "events"): [{"payload": "nothing"}]}, auth=WORKGROUP)
    aws.data_stub.add_response(
        "list_databases",
        {"Databases": ["dev", "padb_harvest", "sales"]},
        {"ClusterIdentifier": "warehouse", "Database": "dev"},
    )
    aws.database(
        "dev",
        {
            ("public", "customers"): [
                {"id": 1, "card_number": CARDS["visa"], "note": "hello"},
                {"id": 2, "card_number": None, "note": "x"},
            ],
            ("hr", 'odd"name'): [{"ssn": dashed(SSN_A), "ok": True, "amount": 1.5}],
        },
        auth=CLUSTER,
    )
    aws.database("sales", {}, auth=CLUSTER)
    doc = env.run(config(s3_targets=[], discover=RS, redshift_read="iam"))
    assert doc is not None
    valid(doc)
    aws.data_stub.assert_no_pending_responses()
    found = {
        (
            f["resource"]["service"],
            f["resource"]["database"],
            f["resource"]["table"],
            f["resource"]["field"],
            f["class"],
        )
        for f in doc["findings"]
    }
    assert found == {
        ("redshift", "dev", "public.customers", "card_number", "card"),
        ("redshift", "dev", 'hr.odd"name', "ssn", "us_ssn"),
    }
    f = next(f for f in doc["findings"] if f["class"] == "card")
    assert f["resource"] == {
        "type": "store_field",
        "service": "redshift",
        "store": "warehouse",
        "database": "dev",
        "table": "public.customers",
        "field": "card_number",
        "readBy": "data_api",
    }
    assert (f["format"], f["offsets"]) == ("sql", [])
    assert f["link"].startswith("https://us-west-2.console.aws.amazon.com/redshiftv2/home")
    s = stores(doc)
    assert (s["warehouse"]["status"], s["adhoc"]["status"]) == ("scanned", "scanned")
    cov = {c["target"]: c for c in doc["coverage"]}
    assert (cov["cluster:warehouse"]["scanned"], cov["cluster:warehouse"]["formats"]) == (
        2,
        {"sql": 2},
    )
    assert cov["workgroup:adhoc"]["passComplete"] is True


def test_db_user_mode_names_the_user_on_clusters_only(env: Env) -> None:
    aws = Aws(env)
    aws.estate()
    user = {**CLUSTER, "DbUser": "sds_reader"}
    aws.data_stub.add_response(
        "list_databases", {"Databases": ["analytics"]}, {**WORKGROUP, "Database": "analytics"}
    )
    aws.database("analytics", {}, auth=WORKGROUP)
    aws.data_stub.add_response(
        "list_databases", {"Databases": ["dev"]}, {**user, "Database": "dev"}
    )
    aws.database("dev", {("public", "t"): [{"a": "b"}]}, auth=user)
    doc = env.run(
        config(s3_targets=[], discover=RS, redshift_read="db_user", redshift_db_user="sds_reader")
    )
    assert doc is not None
    aws.data_stub.assert_no_pending_responses()
    s = stores(doc)
    assert s["warehouse"]["status"] == "scanned"
    # A user who can see no table is a coverage gap, not a clean pass.
    assert (s["adhoc"]["status"], s["adhoc"]["reason"]) == ("skipped", "no_grant")
    with pytest.raises(ValueError, match="REDSHIFT_DB_USER"):
        read_config({"RESULTS_BUCKET": "x", "REDSHIFT_READ": "db-user"})
    with pytest.raises(ValueError, match="REDSHIFT_DB_USER"):
        read_config({"RESULTS_BUCKET": "x", "REDSHIFT_DB_USER": "x; drop"})
    c = read_config({"RESULTS_BUCKET": "x", "REDSHIFT_READ": "db-user", "REDSHIFT_DB_USER": "r"})
    assert (c.redshift_read, c.redshift_db_user) == ("db_user", "r")


def test_a_failed_table_is_unreadable_and_the_pass_goes_on(env: Env) -> None:
    aws = Aws(env)
    aws.estate(workgroups=False)
    aws.data_stub.add_response("list_databases", {"Databases": ["dev"]})
    aws.database(
        "dev",
        {("public", "a"): [], ("public", "b"): [{"card": CARDS["jcb"]}]},
        auth=CLUSTER,
        failing=("public", "a"),
    )
    doc = env.run(config(s3_targets=[], discover=RS, redshift_read="iam"))
    assert doc is not None
    aws.data_stub.assert_no_pending_responses()
    cov = doc["coverage"][0]
    assert (cov["unreadable"], cov["scanned"], cov["passComplete"]) == (1, 1, True)
    assert [f["class"] for f in doc["findings"]] == ["card"]


def test_an_error_listing_databases_is_the_stores_error(env: Env) -> None:
    aws = Aws(env)
    aws.estate(workgroups=False)
    aws.data_stub.add_client_error(
        "list_databases", service_error_code="AccessDeniedException", http_status_code=400
    )
    doc = env.run(config(s3_targets=[], discover=RS, redshift_read="iam"))
    assert doc is not None
    valid(doc)
    s = stores(doc)["warehouse"]
    assert (s["status"], s["reason"], s["error"]) == (
        "error",
        "access_denied",
        "AccessDeniedException",
    )


def test_the_budget_resumes_at_the_next_table(env: Env) -> None:
    aws = Aws(env)
    tables = {("public", "a"): [{"card": CARDS["visa"]}], ("public", "b"): [{"ssn": dashed(SSN_A)}]}
    cfg = config(s3_targets=[], discover=RS, redshift_read="iam", max_items_per_run=1)
    aws.estate(workgroups=False)
    aws.data_stub.add_response("list_databases", {"Databases": ["dev"]})
    sql, _ = tables_sql(REDSHIFT, ())
    listed = [{"table_schema": s, "table_name": t} for s, t in tables]
    aws.statement(sql, listed, auth=CLUSTER, database="dev")
    aws.statement(
        sample_sql(REDSHIFT, "public", "a", 1000),
        tables[("public", "a")],
        auth=CLUSTER,
        database="dev",
    )
    first = env.run(cfg)
    assert first is not None
    aws.data_stub.assert_no_pending_responses()
    assert first["coverage"][0]["backlog"] is True
    assert stores(first)["warehouse"]["backlog"] is True
    aws.estate(workgroups=False)
    aws.data_stub.add_response("list_databases", {"Databases": ["dev"]})
    aws.statement(sql, listed, auth=CLUSTER, database="dev")
    aws.statement(
        sample_sql(REDSHIFT, "public", "b", 1000),
        tables[("public", "b")],
        auth=CLUSTER,
        database="dev",
    )
    second = env.run(cfg)
    assert second is not None
    aws.data_stub.assert_no_pending_responses()
    assert {f["class"] for f in second["findings"]} == {"card", "us_ssn"}
    assert second["coverage"][0]["passComplete"] is True


def test_a_statement_that_never_finishes_is_given_up_on(env: Env) -> None:
    aws = Aws(env)
    aws.data_stub.add_response("execute_statement", {"Id": "slow"})
    clock = iter(range(0, 10_000, 30))
    src = rs_module.RedshiftSource(
        aws.data,
        identifier="warehouse",
        serverless=False,
        database="dev",
        region="us-west-2",
        statement_seconds=60,
    )
    from sensitive_data_scanner.sources.base import Budget

    budget = Budget(10, 10**9, 10_000, clock=lambda: float(next(clock)))
    for _ in range(3):
        aws.data_stub.add_response("describe_statement", {"Id": "slow", "Status": "STARTED"})
    execute = src._execute("dev", budget)
    with pytest.raises(rs_module.StatementTimeout):
        execute("SELECT 1", [])


def test_deny_by_tag_and_serverless_tags(env: Env) -> None:
    aws = Aws(env)
    aws.rs_stub.add_response(
        "describe_clusters",
        {
            "Clusters": [
                {
                    "ClusterIdentifier": "warehouse",
                    "ClusterStatus": "available",
                    "Tags": [{"Key": "scan", "Value": "false"}],
                }
            ]
        },
    )
    aws.sl_stub.add_response("list_namespaces", {"namespaces": []})
    aws.sl_stub.add_response(
        "list_workgroups",
        {
            "workgroups": [
                {"workgroupName": "adhoc", "status": "AVAILABLE", "workgroupArn": "arn:x"}
            ]
        },
    )
    aws.sl_stub.add_client_error(
        "list_tags_for_resource", service_error_code="AccessDeniedException", http_status_code=400
    )
    doc = env.run(
        config(s3_targets=[], discover=RS, redshift_read="iam", deny=store_rules("tag:scan=false"))
    )
    assert doc is not None
    s = stores(doc)
    assert s["warehouse"]["reason"] == "denied"
    assert (s["adhoc"]["reason"], s["adhoc"]["error"]) == (
        "tags_unreadable",
        "AccessDeniedException",
    )


def test_a_listing_failure_is_named_and_the_other_type_still_listed(env: Env) -> None:
    aws = Aws(env)
    aws.rs_stub.add_client_error(
        "describe_clusters", service_error_code="AccessDenied", http_status_code=403
    )
    aws.sl_stub.add_response("list_namespaces", {"namespaces": []})
    aws.sl_stub.add_response(
        "list_workgroups",
        {
            "workgroups": [
                {"workgroupName": "adhoc", "status": "AVAILABLE", "workgroupArn": "arn:x"}
            ]
        },
    )
    doc = env.run(config(s3_targets=[], discover=RS))
    assert doc is not None
    valid(doc)
    assert doc["discovery"]["listErrors"] == {"redshift": "AccessDenied"}
    assert stores(doc)["adhoc"]["reason"] == "read_not_configured"


def test_the_sql_is_the_scanners_own() -> None:
    assert sample_sql(REDSHIFT, "public", 'x"; DROP TABLE y; --', 5) == (
        'SELECT * FROM "public"."x""; DROP TABLE y; --" LIMIT 5'
    )
    sql, params = tables_sql(REDSHIFT, ("public", "sales"))
    assert "svv_tables" in sql and ":s0" in sql and "sales" not in sql
    assert params == [("s0", "public"), ("s1", "sales")]
    sql, params = tables_sql(REDSHIFT, ())
    assert "table_type = 'BASE TABLE'" in sql and params == []
