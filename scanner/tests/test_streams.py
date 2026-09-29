"""Streams and queues: Kinesis (sampled from TRIM_HORIZON, never checkpointed), Firehose
destinations (read as S3), and SQS dead-letter queues (opt-in, VisibilityTimeout=0).

Kinesis, Firehose and SQS answer through botocore's Stubber; S3 is moto's. Every value is
made up.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import boto3
from botocore.stub import ANY, Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, Env, config
from conftest import REPO
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.sources.streams import s3_locations
from synthetic import CARDS, SSN_A, SSN_B, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


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


# ------------------------------------------------------------------ Kinesis

SHARD_A = "shardId-000000000000"
SHARD_B = "shardId-000000000001"


def kinesis_estate(k: Stubber) -> None:
    k.add_response(
        "list_streams",
        {
            "StreamNames": ["clicks", "new"],
            "HasMoreStreams": False,
            "StreamSummaries": [
                {
                    "StreamName": "clicks",
                    "StreamARN": "arn:aws:kinesis:us-west-2:1:stream/clicks",
                    "StreamStatus": "ACTIVE",
                },
                {
                    "StreamName": "new",
                    "StreamARN": "arn:aws:kinesis:us-west-2:1:stream/new",
                    "StreamStatus": "CREATING",
                },
            ],
        },
    )


def shards(k: Stubber) -> None:
    k.add_response(
        "list_shards",
        {
            "Shards": [
                {
                    "ShardId": s,
                    "HashKeyRange": {"StartingHashKey": "0", "EndingHashKey": "1"},
                    "SequenceNumberRange": {"StartingSequenceNumber": "1"},
                }
                for s in (SHARD_B, SHARD_A)
            ]
        },
        {"StreamName": "clicks"},
    )


def records(k: Stubber, shard: str, batches: list[list[bytes]]) -> None:
    k.add_response(
        "get_shard_iterator",
        {"ShardIterator": f"it-{shard}-0"},
        {"StreamName": "clicks", "ShardId": shard, "ShardIteratorType": "TRIM_HORIZON"},
    )
    for i, batch in enumerate(batches):
        k.add_response(
            "get_records",
            {
                "Records": [
                    {"SequenceNumber": str(n), "Data": d, "PartitionKey": "p"}
                    for n, d in enumerate(batch)
                ],
                "NextShardIterator": f"it-{shard}-{i + 1}",
                "MillisBehindLatest": 1000 if i + 1 < len(batches) else 0,
            },
            {"ShardIterator": f"it-{shard}-{i}", "Limit": ANY},
        )


def test_kinesis_samples_each_shard_from_trim_horizon(env: Env) -> None:
    s = stubs(env, "kinesis")
    k = s["kinesis"]
    kinesis_estate(k)
    shards(k)
    records(
        k,
        SHARD_A,
        [
            [],  # an empty first batch at TRIM_HORIZON, with more behind it
            [
                json.dumps({"card": CARDS["visa"], "note": "x"}).encode(),
                gzip.compress(f"ssn {dashed(SSN_A)}".encode()),
                b"\x00\x01\x02binary\x00" * 10,
            ],
        ],
    )
    records(k, SHARD_B, [[json.dumps({"pan": CARDS["jcb"]}).encode()]])
    doc = env.run(config(s3_targets=[], discover=frozenset({"kinesis"})))
    assert doc is not None
    valid(doc)
    k.assert_no_pending_responses()
    found = {(f["resource"]["store"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("clicks", "card"), ("clicks", "us_ssn")}
    card = found[("clicks", "card")]
    assert card["resource"] == {
        "type": "store_field",
        "service": "kinesis",
        "store": "clicks",
        "field": "records",
        "readBy": "shard_sample",
    }
    assert card["count"] == 2  # one card in each shard, merged
    cov = next(c for c in doc["coverage"] if c["kind"] == "kinesis")
    assert (cov["listed"], cov["scanned"], cov["skipped"], cov["passComplete"]) == (
        2,
        3,
        {"binary": 1},
        True,
    )
    st = stores(doc)
    assert st[("kinesis", "clicks")]["status"] == "scanned"
    assert (st[("kinesis", "new")]["reason"], st[("kinesis", "new")]["state"]) == (
        "unsupported",
        "CREATING",
    )
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.kinesis_records_per_shard, c.kinesis_max_shards) == (100, 50)


def test_kinesis_resumes_at_the_next_shard_and_keeps_no_position(env: Env) -> None:
    s = stubs(env, "kinesis")
    k = s["kinesis"]
    cfg = config(s3_targets=[], discover=frozenset({"kinesis"}), max_items_per_run=1)
    kinesis_estate(k)
    shards(k)
    records(k, SHARD_A, [[json.dumps({"card": CARDS["visa"]}).encode()]])
    first = env.run(cfg)
    assert first is not None
    k.assert_no_pending_responses()
    cursor = next(v for key, v in env.state()["cursors"].items() if key.startswith("kinesis:"))
    assert cursor["after"] == SHARD_A  # which shard is next: never a sequence number
    assert "Sequence" not in json.dumps(cursor)
    kinesis_estate(k)
    shards(k)
    records(k, SHARD_B, [[json.dumps({"ssn": dashed(SSN_B)}).encode()]])
    second = env.run(cfg)
    assert second is not None
    k.assert_no_pending_responses()
    assert {f["class"] for f in second["findings"]} == {"card", "us_ssn"}


# ------------------------------------------------------------------ Firehose


def test_s3_locations_follow_every_destination() -> None:
    dest = {
        "DestinationId": "d",
        "ExtendedS3DestinationDescription": {
            "BucketARN": "arn:aws:s3:::lake",
            "Prefix": "fh/!{timestamp:yyyy}/",
            "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/",
            "S3BackupDescription": {"BucketARN": "arn:aws:s3:::backup", "Prefix": ""},
        },
    }
    assert s3_locations(dest) == [("backup", ""), ("lake", "errors/"), ("lake", "fh/")]
    nested = {
        "RedshiftDestinationDescription": {
            "S3DestinationDescription": {"BucketARN": "arn:aws:s3:::stage", "Prefix": "rs/"},
        }
    }
    assert s3_locations(nested) == [("stage", "rs/")]
    whole = {
        "S3DestinationDescription": {"BucketARN": "arn:aws:s3:::w", "Prefix": "a/"},
        "X": {"BucketARN": "arn:aws:s3:::w", "Prefix": ""},
    }
    assert s3_locations(whole) == [("w", "")]


def describe(name: str, destinations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": name,
            "DeliveryStreamARN": f"arn:aws:firehose:us-west-2:123456789012:deliverystream/{name}",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamType": "DirectPut",
            "VersionId": "1",
            "Destinations": destinations,
            "HasMoreDestinations": False,
        }
    }


def test_firehose_destinations_are_read_as_s3_once(env: Env) -> None:
    s = stubs(env, "firehose")
    fh = s["firehose"]
    env.put("fh/2026/09/29/part-1", json.dumps({"card": CARDS["amex"]}))
    env.put("errors/processing-failed/x", f"ssn {dashed(SSN_A)}")
    env.put("other/data.txt", f"card {CARDS['discover']}")
    fh.add_response(
        "list_delivery_streams",
        {"DeliveryStreamNames": ["to-lake"], "HasMoreDeliveryStreams": True},
        {"Limit": 100},
    )
    fh.add_response(
        "list_delivery_streams",
        {"DeliveryStreamNames": ["to-splunk"], "HasMoreDeliveryStreams": False},
        {"Limit": 100, "ExclusiveStartDeliveryStreamName": "to-lake"},
    )
    arn = f"arn:aws:s3:::{DATA}"
    fh.add_response(
        "describe_delivery_stream",
        describe(
            "to-lake",
            [
                {
                    "DestinationId": "d1",
                    "ExtendedS3DestinationDescription": {
                        "BucketARN": arn,
                        "Prefix": "fh/!{timestamp:yyyy}/",
                        "ErrorOutputPrefix": "errors/",
                        "RoleARN": "arn:aws:iam::123456789012:role/r",
                        "BufferingHints": {},
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {},
                    },
                }
            ],
        ),
        {"DeliveryStreamName": "to-lake"},
    )
    fh.add_response(
        "describe_delivery_stream",
        describe("to-splunk", [{"DestinationId": "d2", "SplunkDestinationDescription": {}}]),
        {"DeliveryStreamName": "to-splunk"},
    )
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3", "firehose"}),
            deny=__import__("sensitive_data_scanner.config").config.store_rules(
                "s3:example-scanner-results"
            ),
        )
    )
    assert doc is not None
    valid(doc)
    fh.assert_no_pending_responses()
    keys = sorted(f["resource"]["key"] for f in doc["findings"])
    # Each object once: the stream's prefixes by the stream, the rest by the bucket.
    assert keys == ["errors/processing-failed/x", "fh/2026/09/29/part-1", "other/data.txt"]
    cov = {c["target"]: c for c in doc["coverage"]}
    assert cov[f"{DATA}/fh/"]["scanned"] == 1
    assert cov[f"{DATA}/errors/"]["scanned"] == 1
    assert cov[f"{DATA}/"]["scanned"] == 1
    st = stores(doc)
    assert (st[("firehose", "to-lake")]["status"], st[("firehose", "to-lake")]["destinations"]) == (
        "scanned",
        ["S3"],
    )
    assert (st[("firehose", "to-splunk")]["reason"]) == "no_s3_destination"
    assert "s3Locations" not in st[("firehose", "to-lake")]


# ------------------------------------------------------------------ SQS


def queue(name: str) -> str:
    return f"https://sqs.us-west-2.amazonaws.com/123456789012/{name}"


def arn(name: str) -> str:
    return f"arn:aws:sqs:us-west-2:123456789012:{name}"


def sqs_estate(q: Stubber) -> None:
    names = ["audit", "audit-dlq", "final-dlq", "orders", "orders-dlq"]
    q.add_response("list_queues", {"QueueUrls": [queue(n) for n in names]})
    redrive = {
        "audit": "audit-dlq",
        "audit-dlq": "final-dlq",
        "orders": "orders-dlq",
    }
    for n in names:
        a = {"QueueArn": arn(n), "ApproximateNumberOfMessages": "3"}
        if n in redrive:
            a["RedrivePolicy"] = json.dumps(
                {"deadLetterTargetArn": arn(redrive[n]), "maxReceiveCount": 5}
            )
        q.add_response(
            "get_queue_attributes",
            {"Attributes": a},
            {"QueueUrl": queue(n), "AttributeNames": ["All"]},
        )


def receive(q: Stubber, name: str, messages: list[dict[str, Any]]) -> None:
    q.add_response(
        "receive_message",
        {"Messages": messages},
        {
            "QueueUrl": queue(name),
            "MaxNumberOfMessages": 10,
            "VisibilityTimeout": 0,
            "WaitTimeSeconds": 0,
            "MessageAttributeNames": ["All"],
        },
    )


def test_sqs_reads_only_dead_letter_queues_and_only_when_on(env: Env) -> None:
    s = stubs(env, "sqs")
    q = s["sqs"]
    sqs_estate(q)
    off = env.run(config(s3_targets=[], discover=frozenset({"sqs"})))
    assert off is not None
    valid(off)
    q.assert_no_pending_responses()  # listed; nothing received
    st = stores(off)
    assert st[("sqs", "orders")]["reason"] == "live_queue"
    assert (st[("sqs", "orders-dlq")]["reason"], st[("sqs", "orders-dlq")]["deadLetterQueue"]) == (
        "read_not_configured",
        True,
    )
    assert st[("sqs", "orders-dlq")]["approximateMessages"] == 3
    sqs_estate(q)
    msg = {
        "MessageId": "m-1",
        "ReceiptHandle": "r",
        "Body": json.dumps({"card": CARDS["visa"]}),
        "MessageAttributes": {"ssn": {"StringValue": dashed(SSN_B), "DataType": "String"}},
    }
    receive(q, "final-dlq", [msg])
    receive(q, "final-dlq", [msg])  # the same message again: VisibilityTimeout=0
    receive(q, "orders-dlq", [])
    on = env.run(config(s3_targets=[], discover=frozenset({"sqs"}), sqs_dlq_read=True))
    assert on is not None
    valid(on)
    q.assert_no_pending_responses()
    st = stores(on)
    assert st[("sqs", "audit-dlq")]["reason"] == "redrive_would_change"
    assert st[("sqs", "final-dlq")]["status"] == "scanned"
    assert st[("sqs", "orders-dlq")]["status"] == "scanned"
    found = {(f["resource"]["store"], f["class"]) for f in on["findings"]}
    assert found == {("final-dlq", "card"), ("final-dlq", "us_ssn")}
    f = on["findings"][0]
    assert (f["resource"]["service"], f["resource"]["field"], f["resource"]["readBy"]) == (
        "sqs",
        "messages",
        "receive",
    )
    cov = {c["target"]: c for c in on["coverage"]}
    assert (cov["final-dlq"]["listed"], cov["final-dlq"]["passComplete"]) == (1, True)
    assert read_config({"RESULTS_BUCKET": "x"}).sqs_dlq_read is False
