"""The storage encryption on every finding (1.5, #35), and the PCI DSS notes.

S3 is moto's (its objects' encryption headers and the bucket's default); the other
stores answer through botocore's Stubber. Every value and key id is made up.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from aws_fixtures import DATA, Env, config
from sensitive_data_core.findings import (
    ClassFinding,
    encryption_facts,
    finding_json,
    key_hash,
    pci_note,
)
from sensitive_data_scanner.sources.encryption import (
    KeyClassifier,
    dynamodb_facts,
    log_group_facts,
    rds_facts,
    s3_bucket_facts,
    s3_object_facts,
)
from synthetic import CARDS, SSN_A, dashed
from test_streams import SHARD_A, kinesis_estate, records, stubs, valid

CMK_ID = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
AWS_MANAGED_ID = "aaaabbbb-cccc-4ddd-8eee-ffff00001111"
CUSTOMER_ARN = f"arn:aws:kms:us-west-2:123456789012:key/{CMK_ID}"
AWS_ARN = f"arn:aws:kms:us-west-2:123456789012:key/{AWS_MANAGED_ID}"


class _Clients:
    """Just enough of runner.Clients for a classifier: a client per service."""

    def __init__(self, kms: Any | None) -> None:
        self.services: dict[str, Any] = {} if kms is None else {"kms": kms}

    def client(self, service: str) -> Any:
        if service not in self.services:
            raise ValueError("no client")
        return self.services[service]


def kms_stub(aliases: list[dict[str, str]] | None = None, *, denied: bool = False) -> Any:
    kms = boto3.client(
        "kms",
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    stub = Stubber(kms)
    if denied:
        stub.add_client_error("list_aliases", "AccessDeniedException")
    else:
        stub.add_response("list_aliases", {"Aliases": aliases or [], "Truncated": False})
    stub.activate()
    return kms


ALIASES = [
    {"AliasName": "alias/aws/s3", "TargetKeyId": AWS_MANAGED_ID},
    {"AliasName": "alias/payments", "TargetKeyId": CMK_ID},
    {"AliasName": "alias/unused"},
]


# ------------------------------------------------------------------ the classifier


def test_keys_are_told_apart_by_the_accounts_aliases() -> None:
    keys = KeyClassifier(_Clients(kms_stub(ALIASES)))
    assert keys.facts(key=AWS_ARN) == {"atRestEncryption": "service_managed"}
    assert keys.facts(key=CUSTOMER_ARN) == {
        "atRestEncryption": "customer_managed_key",
        "atRestKeyHash": hashlib.sha256(CMK_ID.encode()).hexdigest(),
    }
    assert keys.facts(key=CMK_ID)["atRestEncryption"] == "customer_managed_key"
    assert keys.facts(key="alias/payments")["atRestEncryption"] == "customer_managed_key"
    assert keys.facts(key="arn:aws:kms:us-west-2:1:alias/payments")["atRestKeyHash"] == key_hash(
        CMK_ID
    )
    # An AWS managed key's alias needs no listing; a key in another account is the customer's.
    assert keys.facts(key="alias/aws/sqs") == {"atRestEncryption": "service_managed"}
    other = "arn:aws:kms:us-west-2:210987654321:key/mrk-0123456789abcdef0123456789abcdef"
    assert keys.facts(key=other)["atRestEncryption"] == "customer_managed_key"
    # Not encrypted, not said, the service's own key, a name that is no key.
    assert keys.facts(encrypted=False) == {"atRestEncryption": "none"}
    assert keys.facts(encrypted=None) == {"atRestEncryption": "unknown"}
    assert keys.facts() == {"atRestEncryption": "service_managed"}
    assert keys.facts(key="alias/gone") == {"atRestEncryption": "unknown"}


def test_without_the_alias_listing_a_key_is_unknown_with_its_hash() -> None:
    keys = KeyClassifier(_Clients(kms_stub(denied=True)))
    assert keys.facts(key=CUSTOMER_ARN) == {
        "atRestEncryption": "unknown",
        "atRestKeyHash": key_hash(CMK_ID),
    }
    assert keys.facts(key="alias/aws/ebs") == {"atRestEncryption": "service_managed"}
    # No KMS client at all (a test, or a region with KMS out of reach): the same.
    assert KeyClassifier(_Clients(None)).facts(key=AWS_ARN)["atRestEncryption"] == "unknown"


def test_each_store_s_own_configuration() -> None:
    keys = KeyClassifier(_Clients(kms_stub(ALIASES)))
    assert s3_object_facts(keys, {}) == {"atRestEncryption": "none"}
    assert s3_object_facts(keys, {"ServerSideEncryption": "AES256"}) == {
        "atRestEncryption": "service_managed"
    }
    got = s3_object_facts(keys, {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": CUSTOMER_ARN})
    assert got["atRestEncryption"] == "customer_managed_key"
    dsse = {"ServerSideEncryption": "aws:kms:dsse", "SSEKMSKeyId": AWS_ARN}
    assert s3_object_facts(keys, dsse) == {"atRestEncryption": "service_managed"}
    assert s3_bucket_facts(keys, None) == {"atRestEncryption": "unknown"}
    assert s3_bucket_facts(keys, []) == {"atRestEncryption": "none"}
    kms_default = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
    assert s3_bucket_facts(keys, kms_default) == {"atRestEncryption": "service_managed"}
    assert dynamodb_facts(keys, None) == {"atRestEncryption": "service_managed"}
    kms_table = {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": CUSTOMER_ARN}
    assert dynamodb_facts(keys, kms_table)["atRestEncryption"] == "customer_managed_key"
    assert rds_facts(keys, {"StorageEncrypted": False}) == {"atRestEncryption": "none"}
    rds = {"StorageEncrypted": True, "KmsKeyId": AWS_ARN}
    assert rds_facts(keys, rds) == {"atRestEncryption": "service_managed"}
    assert log_group_facts(keys, {}) == {"atRestEncryption": "service_managed"}
    assert log_group_facts(keys, {"kmsKeyId": CUSTOMER_ARN})["atRestKeyHash"] == key_hash(CMK_ID)


# ------------------------------------------------------------------ the PCI DSS notes


@pytest.mark.parametrize(
    ("cls", "at_rest", "requirement"),
    [
        ("card", "service_managed", "3.5.1.2"),
        ("card", "customer_managed_key", "3.5.1.2"),
        ("card", "none", None),
        ("card", "unknown", None),
        ("card", None, None),
        ("cvv", "none", "3.3.1"),
        ("cvv", "customer_managed_key", "3.3.1"),
        ("cvv", None, "3.3.1"),
        ("us_ssn", "service_managed", None),
    ],
)
def test_pci_notes(cls: str, at_rest: str | None, requirement: str | None) -> None:
    note = pci_note(cls, at_rest)
    assert (note or {}).get("requirement") == requirement
    if note:
        assert "QSA" in note["guidance"]
    cf = ClassFinding(cls, count=1, occurrences=1, confidence="high")
    facts = encryption_facts(at_rest) if at_rest else None
    f = finding_json({"type": "x"}, None, "text", cf, "2026-09-29T00:00:00+00:00", facts=facts)
    assert (f.get("pciNote") or {}).get("requirement") == requirement
    assert f.get("atRestEncryption") == at_rest


def test_a_fact_is_never_a_value() -> None:
    with pytest.raises(ValueError, match="at-rest"):
        encryption_facts("aes")
    cf = ClassFinding("card", count=1, occurrences=1, confidence="high")
    with pytest.raises(ValueError, match="replace"):
        finding_json({"type": "x"}, None, "text", cf, "t", facts={"count": 2})


# ------------------------------------------------------------------ end to end


def test_s3_findings_carry_each_object_s_own_encryption(env: Env) -> None:
    s3 = env.clients.s3
    kms = boto3.client("kms", region_name="us-west-2")
    key = kms.create_key(Description="made-up customer key")["KeyMetadata"]
    env.clients.services["kms"] = kms
    # Stored before the bucket had default encryption: not encrypted, whatever the default now.
    s3.put_object(Bucket=DATA, Key="plain.txt", Body=f"card {CARDS['visa']}".encode())
    s3.put_bucket_encryption(
        Bucket=DATA,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_object(
        Bucket=DATA,
        Key="sse-s3.txt",
        Body=f"card {CARDS['amex']}".encode(),
        ServerSideEncryption="AES256",
    )
    s3.put_object(
        Bucket=DATA,
        Key="sse-kms.json",
        Body=json.dumps({"ssn": dashed(SSN_A), "cvv": "cvv 123", "card": CARDS["jcb"]}).encode(),
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=key["Arn"],
    )
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    by_key: dict[str, dict[str, Any]] = {}
    for f in doc["findings"]:
        by_key.setdefault(f["resource"]["key"], {})[f["class"]] = f
    plain, sse, cmk = by_key["plain.txt"], by_key["sse-s3.txt"], by_key["sse-kms.json"]
    # An object stored without encryption has no header: `none`, whatever the bucket's default.
    assert plain["card"]["atRestEncryption"] == "none"
    assert "pciNote" not in plain["card"]
    assert sse["card"]["atRestEncryption"] == "service_managed"
    assert sse["card"]["pciNote"]["requirement"] == "3.5.1.2"
    card = cmk["card"]
    assert card["atRestEncryption"] == "customer_managed_key"
    assert card["atRestKeyHash"] == key_hash(key["KeyId"])
    assert card["pciNote"]["requirement"] == "3.5.1.2"
    assert "pciNote" not in cmk["us_ssn"]
    if "cvv" in cmk:
        assert cmk["cvv"]["pciNote"]["requirement"] == "3.3.1"
    text = json.dumps(doc)
    assert key["KeyId"] not in text and key["Arn"] not in text
    # The run summary shows the bucket's default.
    bucket = next(s for s in doc["discovery"]["stores"] if s["name"] == DATA)
    assert bucket["atRestEncryption"] == "service_managed"


def test_a_stream_s_findings_carry_its_key(env: Env) -> None:
    s = stubs(env, "kinesis", "kms")
    k = s["kinesis"]
    s["kms"].add_response("list_aliases", {"Aliases": ALIASES, "Truncated": False})
    kinesis_estate(k)
    k.add_response(
        "describe_stream_summary",
        {
            "StreamDescriptionSummary": {
                "StreamName": "clicks",
                "StreamARN": "arn:aws:kinesis:us-west-2:123456789012:stream/clicks",
                "StreamStatus": "ACTIVE",
                "RetentionPeriodHours": 24,
                "StreamCreationTimestamp": "2026-09-01T00:00:00Z",
                "EnhancedMonitoring": [],
                "EncryptionType": "KMS",
                "KeyId": "alias/payments",
                "OpenShardCount": 1,
            }
        },
        {"StreamName": "clicks"},
    )
    k.add_response(
        "list_shards",
        {
            "Shards": [
                {
                    "ShardId": SHARD_A,
                    "HashKeyRange": {"StartingHashKey": "0", "EndingHashKey": "1"},
                    "SequenceNumberRange": {"StartingSequenceNumber": "1"},
                }
            ]
        },
        {"StreamName": "clicks"},
    )
    records(k, SHARD_A, [[json.dumps({"card": CARDS["visa"]}).encode()]])
    doc = env.run(config(s3_targets=[], discover=frozenset({"kinesis"})))
    assert doc is not None
    valid(doc)
    k.assert_no_pending_responses()
    (f,) = doc["findings"]
    assert f["atRestEncryption"] == "customer_managed_key"
    assert f["atRestKeyHash"] == key_hash(CMK_ID)
    assert f["pciNote"]["requirement"] == "3.5.1.2"
    assert "payments" not in json.dumps(doc)


def test_the_aliases_are_listed_once_per_run() -> None:
    kms = kms_stub(ALIASES)  # one response queued: a second listing would fail the stub
    keys = KeyClassifier(_Clients(kms))
    for _ in range(5):
        assert keys.facts(key=CUSTOMER_ARN)["atRestEncryption"] == "customer_managed_key"
        assert keys.facts(key=AWS_ARN)["atRestEncryption"] == "service_managed"
