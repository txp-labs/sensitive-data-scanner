"""Discovery: every store in the account and region is listed, read or reported as not read.

S3 and CloudWatch Logs run against moto; DynamoDB against botocore's Stubber.
All values are made up.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, REGION, RESULTS, Env, config, epoch_ms
from conftest import REPO
from ddb_fixtures import Ddb, describe
from sensitive_data_scanner.config import (
    SamplingRule,
    StoreRule,
    discover_kinds,
    parse_rule,
    read_config,
    sampling_rules,
    store_rules,
)
from sensitive_data_scanner.discovery import Store, decide
from sensitive_data_scanner.events import event_details
from synthetic import CARDS, SSN_A, dashed, printed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
ALL = frozenset({"s3", "cloudwatch_logs", "dynamodb", "glue_table", "rds"})
# `all` is every kind, including the adapters' (sources/aws.py).
EVERY = ALL | {
    "redshift",
    "opensearch",
    "documentdb",
    "neptune",
    "ebs",
    "backup",
    "efs",
    "fsx",
    "kinesis",
    "firehose",
    "sqs",
}
THREE = frozenset({"s3", "cloudwatch_logs", "dynamodb"})
SELF_GROUP = "/aws/lambda/sensitive-data-scanner"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}


def bucket(env: Env, name: str, region: str = REGION, tags: dict[str, str] | None = None) -> Any:
    s3 = env.clients.s3 if region == REGION else boto3.client("s3", region_name=region)
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": "us-west-2"})
    if tags:
        s3.put_bucket_tagging(
            Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}
        )
    return s3


def table_desc(name: str, size: int = 1000, status: str = "ACTIVE") -> dict[str, Any]:
    d = describe(name, sort_key=False)
    d["Table"].update(
        TableStatus=status,
        TableSizeBytes=size,
        ItemCount=3,
        TableArn=f"arn:aws:dynamodb:{REGION}:123456789012:table/{name}",
    )
    return d


def item(note: str, pk: str = "u#1") -> dict[str, Any]:
    return {"pk": {"S": pk}, "note": {"S": note}}


def recent_ms() -> int:
    return epoch_ms(__import__("datetime").datetime.now(__import__("datetime").UTC)) - 3_600_000


# ------------------------------------------------------------------ configuration


def test_discover_kinds() -> None:
    assert discover_kinds(None) == frozenset()
    assert discover_kinds("all") == EVERY
    assert discover_kinds("s3, logs") == {"s3", "cloudwatch_logs"}
    with pytest.raises(ValueError, match="unknown kind"):
        discover_kinds("s3,mainframe")


def test_rules_by_name_glob_and_tag() -> None:
    assert parse_rule("s3:prod-*") == StoreRule(kind="s3", name="prod-*")
    assert parse_rule("logs:/aws/lambda/*") == StoreRule(
        kind="cloudwatch_logs", name="/aws/lambda/*"
    )
    assert parse_rule("*-archive") == StoreRule(name="*-archive")
    assert parse_rule("tag:scan=false") == StoreRule(tag_key="scan", tag_value="false")
    assert parse_rule("tag:pii") == StoreRule(tag_key="pii")
    assert parse_rule("dynamodb:tag:team=data*") == StoreRule(
        kind="dynamodb", tag_key="team", tag_value="data*"
    )
    r = parse_rule("logs:/aws/lambda/*")
    assert r.matches("cloudwatch_logs", "/aws/lambda/fn", None)
    assert not r.matches("s3", "/aws/lambda/fn", None)
    t = parse_rule("tag:team=data*")
    assert t.matches("s3", "x", {"team": "data-eng"})
    assert not t.matches("s3", "x", {"team": "web"})
    assert not t.matches("s3", "x", None)
    assert parse_rule("tag:pii").matches("s3", "x", {"pii": ""})
    assert len(store_rules("s3:a*, tag:x=1 ,logs:/b")) == 3
    with pytest.raises(ValueError):
        parse_rule("tag:")


def test_sampling_rules_parse_and_validate() -> None:
    rules = sampling_rules(
        '[{"match": "s3:lake-*", "samplePercent": 10, "maxObjectsPerPrefix": 5}]'
    )
    assert rules == (SamplingRule(StoreRule(kind="s3", name="lake-*"), 10, 5),)
    for bad in (
        "{}",
        "[1]",
        '[{"samplePercent": 10}]',
        '[{"match": "x", "samplePercent": 0}]',
        '[{"match": "x", "other": 1}]',
        "not json",
    ):
        with pytest.raises(ValueError):
            sampling_rules(bad)


def test_read_config_discovery_settings() -> None:
    c = read_config(
        {
            "RESULTS_BUCKET": RESULTS,
            "DISCOVER": "all",
            "DISCOVER_ALLOW": "tag:scan=yes",
            "DISCOVER_DENY": "s3:*-logs",
            "DISCOVER_SAMPLING": '[{"match": "dynamodb:*", "samplePercent": 25}]',
            "AWS_LAMBDA_LOG_GROUP_NAME": SELF_GROUP,
            "MAX_OBJECTS_PER_RUN": "500",
            "MAX_LOG_EVENTS_PER_RUN": "600",
            "MAX_TABLE_ITEMS_PER_RUN": "700",
            "MAX_RUN_SECONDS": "300",
            "S3_MAX_OBJECTS_PER_PREFIX": "20",
            "DYNAMODB_SAMPLE_PERCENT": "50",
            "DYNAMODB_MAX_TABLE_BYTES": "1000",
        }
    )
    assert c.discover == EVERY
    assert c.self_log_group == SELF_GROUP
    assert (c.max_objects_per_run, c.max_log_events_per_run, c.max_table_items_per_run) == (
        500,
        600,
        700,
    )
    assert (c.max_run_seconds, c.s3_max_objects_per_prefix, c.dynamodb_sample_percent) == (
        300,
        20,
        50,
    )
    assert c.sampling_for("dynamodb", "t", None) == (25, None)
    # Off by default: the explicit configuration alone, as before.
    assert read_config({"RESULTS_BUCKET": RESULTS}).discover == frozenset()


def test_deny_wins_and_an_unreadable_tag_never_lets_a_denied_store_through() -> None:
    c = config(
        discover=ALL,
        allow=store_rules("s3:data-*"),
        deny=store_rules("s3:data-private*,tag:scan=no"),
    )
    s = Store("s3", "data-private-1")
    decide(s, c)
    assert (s.status, s.reason) == ("skipped", "denied")
    s = Store("s3", "data-public", tags={"scan": "no"})
    decide(s, c)
    assert s.reason == "denied"
    s = Store("s3", "data-public")
    decide(s, c, tag_error="AccessDenied")
    assert (s.reason, s.error) == ("tags_unreadable", "AccessDenied")
    s = Store("s3", "other")
    decide(s, c, None)
    assert s.reason == "not_allowed"
    s = Store("s3", "data-public", tags={})
    decide(s, c)
    assert s.status == "pending"


# ------------------------------------------------------------------ end to end


def test_discovery_reads_every_kind_and_reports_every_store(env: Env) -> None:
    env.put("exports/customers.csv", "name,card_number\nA,{}\n".format(CARDS["visa"]))
    bucket(env, "example-archive-logs").put_object(
        Bucket="example-archive-logs", Key="a.txt", Body=f"ssn {dashed(SSN_A)}".encode()
    )
    bucket(env, "example-other-region", region="us-east-1")
    env.log("/aws/lambda/fulfill", "s", [(recent_ms(), f"card {printed(CARDS['visa'])}")])
    env.log(SELF_GROUP, "s", [(recent_ms(), "run.start")])
    ddb = Ddb()
    ddb.stub.add_response(
        "list_tables", {"TableNames": ["example-big", "example-orders", "example-staging"]}
    )
    ddb.stub.add_response("describe_table", table_desc("example-big", size=50 * 1024**3))
    ddb.stub.add_response("describe_table", table_desc("example-orders"))
    ddb.stub.add_response("describe_table", table_desc("example-staging", status="ARCHIVED"))
    # The run: the one table read is described again, then scanned.
    ddb.stub.add_response("describe_table", table_desc("example-orders"))
    ddb.stub.add_response(
        "scan",
        {"Items": [item(f"ssn {dashed(SSN_A)}")], "Count": 1, "ScannedCount": 1},
        {"TableName": "example-orders", "Limit": ANY},
    )
    env.clients.dynamodb = ddb.client
    doc = env.run(
        config(
            s3_targets=[],
            discover=THREE,
            deny=store_rules("s3:*-archive-logs"),
            self_log_group=SELF_GROUP,
            dynamodb_max_table_bytes=10 * 1024**3,
        )
    )
    assert doc is not None
    valid(doc)
    ddb.stub.assert_no_pending_responses()
    s = stores(doc)
    assert s[("s3", DATA)]["status"] == "scanned"
    assert s[("s3", RESULTS)] | {} == {
        "kind": "s3",
        "name": RESULTS,
        "origin": "discovery",
        "status": "skipped",
        "reason": "self",
    }
    assert s[("s3", "example-archive-logs")]["reason"] == "denied"
    assert ("s3", "example-other-region") not in s  # the other region's scanner reads it
    assert s[("cloudwatch_logs", "/aws/lambda/fulfill")]["status"] == "scanned"
    assert s[("cloudwatch_logs", SELF_GROUP)]["reason"] == "self"
    assert s[("dynamodb", "example-big")]["reason"] == "too_large"
    assert s[("dynamodb", "example-big")]["sizeBytes"] == 50 * 1024**3
    assert s[("dynamodb", "example-orders")]["status"] == "scanned"
    assert (
        s[("dynamodb", "example-staging")]["reason"],
        s[("dynamodb", "example-staging")]["tableStatus"],
    ) == (
        "unsupported",
        "ARCHIVED",
    )
    kinds = {f["resource"]["type"]: f["class"] for f in doc["findings"]}
    assert kinds == {"s3_object": "card", "log_event": "card", "dynamodb_item": "us_ssn"}
    summary = doc["discovery"]
    assert summary["byReason"] == {"denied": 1, "self": 2, "too_large": 1, "unsupported": 1}
    assert summary["byStatus"]["scanned"] == 3
    assert summary["storesTotal"] == len(summary["stores"]) == 8
    # Stores not read come first, so a truncated list still shows every gap.
    assert summary["stores"][0]["status"] == "skipped"


def test_the_explicit_configuration_keeps_working_beside_discovery(env: Env) -> None:
    env.put("connect/x/a.txt", f"card {printed(CARDS['visa'])}")
    env.put("elsewhere/b.txt", f"card {printed(CARDS['visa'])}")
    doc = env.run(config(s3_targets=[(DATA, "connect/")], discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    s = stores(doc)
    assert s[("s3", DATA)]["origin"] == "config"
    # The named prefix is read, once; the rest of the bucket is not.
    assert [c["target"] for c in doc["coverage"]] == [f"{DATA}/connect/"]
    assert {f["resource"]["key"] for f in doc["findings"]} == {"connect/x/a.txt"}


def test_allow_by_tag(env: Env) -> None:
    bucket(env, "example-tagged", tags={"pii-scan": "yes"}).put_object(
        Bucket="example-tagged", Key="a.txt", Body=f"card {printed(CARDS['visa'])}".encode()
    )
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"s3"}), allow=store_rules("tag:pii-scan=yes"))
    )
    assert doc is not None
    s = stores(doc)
    assert s[("s3", "example-tagged")]["status"] == "scanned"
    assert s[("s3", DATA)]["reason"] == "not_allowed"
    assert {f["resource"]["bucket"] for f in doc["findings"]} == {"example-tagged"}


def test_the_budget_defers_stores_and_the_next_run_starts_with_them(env: Env) -> None:
    names = [f"example-b{i}" for i in range(5)]
    for n in names:
        bucket(env, n).put_object(
            Bucket=n, Key="a.txt", Body=f"card {printed(CARDS['visa'])}".encode()
        )
    cfg = config(
        s3_targets=[],
        discover=frozenset({"s3"}),
        deny=store_rules(f"s3:{DATA}"),
        max_objects_per_run=2,
    )
    first = env.run(cfg)
    assert first is not None
    valid(first)
    s = stores(first)
    scanned = {n for n in names if s[("s3", n)]["status"] == "scanned"}
    deferred = {n for n in names if s[("s3", n)]["status"] == "deferred"}
    assert len(scanned) == 2
    assert {s[("s3", n)]["reason"] for n in deferred} == {"budget"}
    assert env.state()["rotation"] == f"s3:{sorted(deferred)[0]}/"
    second = env.run(cfg)
    third = env.run(cfg)
    assert second is not None and third is not None
    read = {f["resource"]["bucket"] for f in third["findings"]}
    assert read == set(names)  # every store reached within three runs, findings carried over


def test_objects_per_prefix_and_per_store_sampling(env: Env) -> None:
    for d in ("dt=2026-09-27", "dt=2026-09-28"):
        for i in range(4):
            env.put(f"lake/{d}/part-{i}.json", json.dumps({"n": i}))
    cfg = config(
        s3_targets=[],
        discover=frozenset({"s3"}),
        deny=store_rules(f"s3:{RESULTS}"),
        sampling=sampling_rules(f'[{{"match": "s3:{DATA}", "maxObjectsPerPrefix": 1}}]'),
    )
    doc = env.run(cfg)
    assert doc is not None
    valid(doc)
    cov = doc["coverage"][0]
    assert (cov["scanned"], cov["sampledOut"]) == (2, 6)
    assert stores(doc)[("s3", DATA)]["maxObjectsPerPrefix"] == 1


def test_objects_per_prefix_carries_over_a_run_cut_by_the_budget(env: Env) -> None:
    for i in range(4):
        env.put(f"lake/dt=1/part-{i}.txt", "x")
    cfg = config(s3_max_objects_per_prefix=3, max_items_per_run=2)
    first = env.run(cfg)
    second = env.run(cfg)
    assert first is not None and second is not None
    assert first["coverage"][0]["scanned"] == 2
    assert (second["coverage"][0]["scanned"], second["coverage"][0]["sampledOut"]) == (1, 1)


def test_dynamodb_is_sampled_by_parallel_scan_segment(env: Env) -> None:
    ddb = Ddb()
    ddb.stub.add_response("list_tables", {"TableNames": ["example-events"]})
    ddb.stub.add_response("describe_table", table_desc("example-events", size=40 * 1024**3))
    ddb.stub.add_response("describe_table", table_desc("example-events"))
    ddb.stub.add_response(
        "scan",
        {"Items": [item("hello")], "Count": 1, "ScannedCount": 1},
        {"TableName": "example-events", "Limit": ANY, "Segment": 0, "TotalSegments": 4},
    )
    env.clients.dynamodb = ddb.client
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"dynamodb"}),
            sampling=sampling_rules('[{"match": "dynamodb:*", "samplePercent": 25}]'),
        )
    )
    assert doc is not None
    valid(doc)
    ddb.stub.assert_no_pending_responses()
    # 40 GiB at 25% is 10 GiB: within the cap, so it is read, sampled.
    assert stores(doc)[("dynamodb", "example-events")]["samplePercent"] == 25
    cov = doc["coverage"][0]
    assert (cov["samplePercent"], cov["sampledOut"]) == (25, 3)


def test_a_kms_key_the_scanner_may_not_use_is_a_named_gap(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.put("secret/a.txt", "x")
    real = env.clients.s3.get_object

    def get_object(**kw: Any) -> Any:
        if kw.get("Bucket") == DATA:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized to kms:Decrypt"}},
                "GetObject",
            )
        return real(**kw)

    monkeypatch.setattr(env.clients.s3, "get_object", get_object)
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    cov = doc["coverage"][0]
    assert (cov["unreadable"], cov["kmsDenied"], cov["error"]) == (1, 1, "AccessDenied")
    s = stores(doc)[("s3", DATA)]
    assert (s["status"], s["reason"], s["gaps"]) == (
        "error",
        "kms_access",
        {"kmsDenied": 1, "unreadable": 1},
    )


def test_a_store_of_unsupported_files_only_says_so(env: Env) -> None:
    env.put("calls/a.wav", b"RIFF-fake")
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert doc is not None
    s = stores(doc)[("s3", DATA)]
    assert (s["status"], s["reason"], s["gaps"]) == (
        "scanned",
        "unsupported_format",
        {"unsupportedFormat": 1},
    )


def test_a_listing_that_fails_is_named_and_the_other_kinds_still_run(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.log("/aws/lambda/fulfill", "s", [(recent_ms(), f"card {printed(CARDS['visa'])}")])

    def denied(name: str) -> Any:
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListBuckets")

    monkeypatch.setattr(env.clients.s3, "get_paginator", denied)
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3", "cloudwatch_logs"})))
    assert doc is not None
    valid(doc)
    assert doc["discovery"]["listErrors"] == {"s3": "AccessDenied"}
    assert doc["findingsTotal"] == 1


def test_delivery_log_groups_are_reported_unsupported(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Pages:
        def paginate(self, **kw: Any) -> list[dict[str, Any]]:
            return [
                {
                    "logGroups": [
                        {
                            "logGroupName": "/vendedlogs/x",
                            "logGroupClass": "DELIVERY",
                            "storedBytes": 9,
                        }
                    ]
                }
            ]

    monkeypatch.setattr(env.clients.logs, "get_paginator", lambda name: Pages())
    doc = env.run(config(s3_targets=[], discover=frozenset({"cloudwatch_logs"})))
    assert doc is not None
    valid(doc)
    s = stores(doc)[("cloudwatch_logs", "/vendedlogs/x")]
    assert (s["status"], s["reason"], s["logGroupClass"], s["sizeBytes"]) == (
        "skipped",
        "unsupported",
        "DELIVERY",
        9,
    )


def test_wall_time_cap_defers_what_it_does_not_reach(env: Env) -> None:
    for n in ("example-t1", "example-t2"):
        bucket(env, n).put_object(Bucket=n, Key="a.txt", Body=b"x")

    class Clock:
        t = time.monotonic()

        def __call__(self) -> float:
            self.t += 7.0  # every look at the clock costs seven seconds
            return self.t

    clock: Callable[[], float] = Clock()
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"s3"}), max_run_seconds=20), clock=clock
    )
    assert doc is not None
    assert doc["discovery"]["byStatus"].get("deferred", 0) >= 1


def test_events_split_coverage_and_stores_too() -> None:
    doc = {
        "schema": "s",
        "findings": [{"id": f"{i:032d}", "pad": "x" * 900} for i in range(100)],
        "coverage": [{"target": f"t{i}", "pad": "y" * 900} for i in range(150)],
        "discovery": {
            "stores": [{"name": f"s{i}", "pad": "z" * 900} for i in range(300)],
            "storesTotal": 300,
            "byStatus": {},
        },
    }
    details = event_details(doc)
    assert len(details) > 2
    assert all(len(json.dumps(d)) < 256_000 for d in details)
    assert sum(len(d["findings"]) for d in details) == 100
    assert sum(len(d["coverage"]) for d in details) == 150
    assert sum(len(d["discovery"]["stores"]) for d in details) == 300
    assert all(d["discovery"]["storesTotal"] == 300 for d in details)


def test_rotation_state_is_plain(env: Env) -> None:
    env.put("a.txt", "x")
    env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert env.state()["rotation"] is None


def test_log_events_have_their_own_cap(env: Env) -> None:
    t = recent_ms()
    for g in ("/aws/lambda/a", "/aws/lambda/b"):
        env.log(g, "s", [(t + i, f"event {i}") for i in range(5)])
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"cloudwatch_logs"}), max_log_events_per_run=4)
    )
    assert doc is not None
    valid(doc)
    assert sum(c["scanned"] for c in doc["coverage"]) == 4
    assert all(c["partial"] == 1 for c in doc["coverage"])
