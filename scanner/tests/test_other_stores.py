"""Other stores: ElastiCache and MemoryDB (reported; exported RDB snapshots read in S3),
Timestream and Keyspaces (sampled read-only queries).

Every AWS answer comes from botocore's Stubber (S3 is moto's); the Keyspaces CQL session is
a fake. Every value is made up.
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
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.sources.other_stores import KeyspacesSource, TimestreamSource
from synthetic import CARDS, SSN_A, SSN_B, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    # Every finding the runner writes says what storage encryption it sat under (1.5).
    assert all("atRestEncryption" in f for f in doc["findings"])


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}


def stubs(env: Env, *services: str) -> dict[str, Stubber]:
    out = {}
    for s in services:
        c: Any = boto3.client(
            s,  # type: ignore[call-overload]
            region_name="us-west-2",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
        )
        stub = Stubber(c)
        stub.activate()
        env.clients.services[s] = c
        out[s] = stub
    return out


# ------------------------------------------------------------------ ElastiCache, MemoryDB


def test_caches_are_in_memory_with_their_snapshots_counted(env: Env) -> None:
    s = stubs(env, "elasticache", "memorydb")
    ec, mdb = s["elasticache"], s["memorydb"]
    ec.add_response(
        "describe_snapshots",
        {
            "Snapshots": [
                {"SnapshotName": "a", "ReplicationGroupId": "sessions"},
                {"SnapshotName": "b", "ReplicationGroupId": "sessions"},
                {"SnapshotName": "c", "CacheClusterId": "memo"},
            ]
        },
    )
    ec.add_response(
        "describe_serverless_cache_snapshots",
        {
            "ServerlessCacheSnapshots": [
                {"ServerlessCacheConfiguration": {"ServerlessCacheName": "carts"}}
            ]
        },
    )
    ec.add_response(
        "describe_replication_groups",
        {
            "ReplicationGroups": [
                {
                    "ReplicationGroupId": "sessions",
                    "Status": "available",
                    "MemberClusters": ["sessions-001", "sessions-002"],
                }
            ]
        },
    )
    ec.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {"CacheClusterId": "sessions-001", "ReplicationGroupId": "sessions"},
                {"CacheClusterId": "memo", "CacheClusterStatus": "available"},
            ]
        },
    )
    ec.add_response(
        "describe_serverless_caches",
        {"ServerlessCaches": [{"ServerlessCacheName": "carts", "Status": "creating"}]},
    )
    mdb.add_response(
        "describe_snapshots", {"Snapshots": [{"Name": "s", "ClusterConfiguration": {"Name": "db"}}]}
    )
    mdb.add_response("describe_clusters", {"Clusters": [{"Name": "db"}]})
    doc = env.run(config(s3_targets=[], discover=frozenset({"elasticache", "memorydb"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)
    assert ("elasticache", "sessions-001") not in st  # a member: its group is the store
    g = st[("elasticache", "sessions")]
    assert (g["reason"], g["deployment"], g["snapshots"]) == ("in_memory", "replication_group", 2)
    assert (
        st[("elasticache", "memo")]["deployment"],
        st[("elasticache", "memo")]["snapshots"],
    ) == (
        "cluster",
        1,
    )
    carts = st[("elasticache", "carts")]
    assert (carts["deployment"], carts["snapshots"], carts["state"]) == (
        "serverless",
        1,
        "creating",
    )
    assert (st[("memorydb", "db")]["reason"], st[("memorydb", "db")]["snapshots"]) == (
        "in_memory",
        1,
    )


def test_an_exported_snapshot_in_s3_is_read(env: Env) -> None:
    body = b"REDIS0011\xfa\tredis-ver\x057.1.0\x00" + f"\x10card:{CARDS['visa']}".encode()
    env.put("exports/elasticache/sessions-0001.rdb", body + b"\xff" + b"\x00" * 8)
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    [f] = doc["findings"]
    assert (f["resource"]["key"], f["class"]) == ("exports/elasticache/sessions-0001.rdb", "card")
    assert doc["coverage"][0]["formats"] == {"rdb": 1}


# ------------------------------------------------------------------ Timestream


INFLUX_ARN = "arn:aws:timestream-influxdb:us-west-2:123456789012:db-instance/abcdefghij"


def timestream_estate(s: dict[str, Stubber]) -> None:
    s["timestream-write"].add_response("list_databases", {"Databases": [{"DatabaseName": "iot"}]})
    s["timestream-write"].add_response(
        "list_tables",
        {
            "Tables": [
                {"TableName": "readings", "TableStatus": "ACTIVE", "Arn": "arn:t1"},
                {"TableName": "old", "TableStatus": "DELETING", "Arn": "arn:t2"},
            ]
        },
        {"DatabaseName": "iot"},
    )
    s["timestream-influxdb"].add_response(
        "list_db_instances",
        {
            "items": [
                {
                    "id": "abcdefghij",
                    "name": "metrics",
                    "arn": INFLUX_ARN,
                }
            ]
        },
    )


def test_timestream_samples_each_table_with_one_query(env: Env) -> None:
    s = stubs(env, "timestream-write", "timestream-query", "timestream-influxdb")
    timestream_estate(s)
    sql = 'SELECT * FROM "iot"."readings" WHERE time > ago(1d) LIMIT 1000'
    q = s["timestream-query"]
    q.add_response(
        "query",
        {"QueryId": "q1", "Rows": [], "ColumnInfo": [], "NextToken": "n1"},
        {"QueryString": sql},
    )
    columns = [
        {"Name": "device", "Type": {"ScalarType": "VARCHAR"}},
        {"Name": "card_number", "Type": {"ScalarType": "VARCHAR"}},
        {"Name": "tags", "Type": {"ArrayColumnInfo": {"Type": {"ScalarType": "VARCHAR"}}}},
    ]
    q.add_response(
        "query",
        {
            "QueryId": "q1",
            "ColumnInfo": columns,
            "Rows": [
                {
                    "Data": [
                        {"ScalarValue": "d-1"},
                        {"ScalarValue": CARDS["visa"]},
                        {"ArrayValue": [{"ScalarValue": f"ssn {dashed(SSN_A)}"}]},
                    ]
                },
                {"Data": [{"ScalarValue": "d-2"}, {"NullValue": True}, {"NullValue": True}]},
            ],
        },
        {"QueryString": sql, "NextToken": "n1"},
    )
    doc = env.run(config(s3_targets=[], discover=frozenset({"timestream"})))
    assert doc is not None
    valid(doc)
    q.assert_no_pending_responses()
    found = {(f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert found == {("card_number", "card"), ("tags", "us_ssn")}
    f = next(f for f in doc["findings"] if f["class"] == "card")
    assert f["resource"] == {
        "type": "store_field",
        "service": "timestream",
        "store": "iot",
        "table": "readings",
        "field": "card_number",
        "readBy": "query",
    }
    st = stores(doc)
    assert st[("timestream", "iot.readings")]["status"] == "scanned"
    assert st[("timestream", "iot.old")]["reason"] == "unsupported"
    assert (
        st[("timestream", "metrics")]["reason"],
        st[("timestream", "metrics")]["deployment"],
    ) == (
        "no_read_path",
        "influxdb",
    )
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.timestream_max_rows, c.timestream_lookback_days, c.keyspaces_max_rows) == (
        1000,
        1,
        1000,
    )


def test_timestream_sql_quotes_names() -> None:
    src = TimestreamSource(None, database='a"b', table="t; DROP", region="us-west-2", max_rows=5)
    assert src.sql() == 'SELECT * FROM "a""b"."t; DROP" WHERE time > ago(1d) LIMIT 5'


# ------------------------------------------------------------------ Keyspaces


class FakeSession:
    def __init__(self, rows: dict[str, list[dict[str, Any]]], fail: int = 0) -> None:
        self.rows = rows
        self.seen: list[str] = []
        self.fail = fail

    def execute(self, cql: str) -> list[dict[str, Any]]:
        self.seen.append(cql)
        if self.fail:
            self.fail -= 1
            raise ConnectionError
        return self.rows.get(cql, [])


KS = "arn:aws:cassandra:us-west-2:123456789012:/keyspace"


def keyspaces_estate(ks: Stubber) -> None:
    ks.add_response(
        "list_keyspaces",
        {
            "keyspaces": [
                {
                    "keyspaceName": "system_schema",
                    "resourceArn": f"{KS}/system_schema/",
                    "replicationStrategy": "SINGLE_REGION",
                },
                {
                    "keyspaceName": "app",
                    "resourceArn": f"{KS}/app/",
                    "replicationStrategy": "SINGLE_REGION",
                },
            ]
        },
    )
    ks.add_response(
        "list_tables",
        {
            "tables": [
                {
                    "keyspaceName": "app",
                    "tableName": "users",
                    "resourceArn": f"{KS}/app/table/users",
                }
            ]
        },
        {"keyspaceName": "app"},
    )


def test_keyspaces_samples_each_table_over_cql(env: Env) -> None:
    s = stubs(env, "keyspaces")
    keyspaces_estate(s["keyspaces"])
    cql = 'SELECT * FROM "app"."users" LIMIT 1000'
    session = FakeSession({cql: [{"id": "u1", "ssn": dashed(SSN_B), "card": None}]}, fail=1)
    made: list[str] = []

    def factory(region: str) -> FakeSession:
        made.append(region)
        return session

    env.clients.services["keyspaces-cql"] = factory
    doc = env.run(config(s3_targets=[], discover=frozenset({"keyspaces"})))
    assert doc is not None
    valid(doc)
    # A dead session is replaced once; system keyspaces are never listed or read.
    assert session.seen == [cql, cql] and made == ["us-west-2", "us-west-2"]
    [f] = doc["findings"]
    assert (f["resource"]["service"], f["resource"]["store"], f["resource"]["table"]) == (
        "keyspaces",
        "app",
        "users",
    )
    assert (f["resource"]["field"], f["class"], f["format"]) == ("ssn", "us_ssn", "cql")
    assert set(stores(doc)) == {("keyspaces", "app.users")}
    KeyspacesSource._sessions.clear()


def test_the_keyspaces_session_is_tls_and_sigv4(monkeypatch: pytest.MonkeyPatch) -> None:
    import cassandra.cluster
    from cassandra_sigv4.auth import SigV4AuthProvider

    from sensitive_data_scanner.sources.other_stores import keyspaces_session

    seen: dict[str, Any] = {}

    class Cluster:
        def __init__(self, hosts: list[str], **kw: Any) -> None:
            seen["hosts"] = hosts
            seen.update(kw)

        def connect(self) -> str:
            return "session"

    monkeypatch.setattr(cassandra.cluster, "Cluster", Cluster)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    assert keyspaces_session("us-west-2") == "session"
    assert seen["hosts"] == ["cassandra.us-west-2.amazonaws.com"]
    assert (seen["port"], seen["protocol_version"]) == (9142, 4)
    assert seen["ssl_options"] == {"server_hostname": "cassandra.us-west-2.amazonaws.com"}
    assert isinstance(seen["auth_provider"], SigV4AuthProvider)
