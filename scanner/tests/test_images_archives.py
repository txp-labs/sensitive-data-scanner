"""Group 7, opt-in by size or cost, and reported archives (#35): ECR image layers, SageMaker
feature stores, Neptune Analytics by export, EventBridge archives by a replay to the
scanner's own queue, and Glacier vaults.

The AWS APIs answer through botocore's Stubber, S3 is moto's, and a layer download is a
fake. Every value is made up.
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import tarfile
from typing import IO, Any

from botocore.stub import ANY, Stubber

from aws_fixtures import DATA, RESULTS, Env, config
from synthetic import CARDS, SSN_A, SSN_B, dashed
from test_streams import stores, stubs, valid

ACCOUNT = "123456789012"
T0 = dt.datetime(2026, 9, 29, 8, 0, tzinfo=dt.UTC)


def run(env: Env, *kinds: str, **kw: Any) -> dict[str, Any]:
    doc = env.run(config(s3_targets=[], discover=frozenset(kinds), **kw))
    assert doc is not None
    valid(doc)
    return doc


# ------------------------------------------------------------------ ECR

REPO = f"arn:aws:ecr:us-west-2:{ACCOUNT}:repository/checkout"
IMAGE = "sha256:" + "a" * 64
PLATFORM = "sha256:" + "b" * 64
LAYERS = ["sha256:" + c * 64 for c in "cde"]


def layer(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def repositories(ecr: Stubber, encryption: dict[str, str] | None = None) -> None:
    ecr.add_response(
        "describe_repositories",
        {
            "repositories": [
                {
                    "repositoryArn": REPO,
                    "repositoryName": "checkout",
                    "encryptionConfiguration": encryption or {"encryptionType": "AES256"},
                }
            ]
        },
    )


def images(ecr: Stubber) -> None:
    ecr.add_response(
        "describe_images",
        {
            "imageDetails": [
                {"imageDigest": "sha256:" + "0" * 64, "imagePushedAt": T0 - dt.timedelta(days=9)},
                {"imageDigest": IMAGE, "imagePushedAt": T0},
            ]
        },
        {"repositoryName": "checkout"},
    )


def test_ecr_layers_are_sampled_from_the_latest_image(env: Env) -> None:
    s = stubs(env, "ecr")
    ecr = s["ecr"]
    repositories(ecr)
    images(ecr)
    index = {
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:" + "9" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": PLATFORM, "platform": {"os": "linux", "architecture": "amd64"}},
        ],
    }
    manifest = {
        "schemaVersion": 2,
        "layers": [
            {"digest": d, "size": 10, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}
            for d in LAYERS
        ],
    }
    for digest, body in ((IMAGE, index), (PLATFORM, manifest)):
        ecr.add_response(
            "batch_get_image",
            {"images": [{"imageManifest": json.dumps(body)}]},
            {
                "repositoryName": "checkout",
                "imageIds": [{"imageDigest": digest}],
                "acceptedMediaTypes": ANY,
            },
        )
    blobs = {
        LAYERS[2]: layer(
            {
                "app/config.json": json.dumps({"test_card": CARDS["visa"]}).encode(),
                "usr/share/doc/x.txt": f"card {CARDS['amex']}".encode(),
                "app/logo.png": b"\x89PNG....",
                "app/data.bin": b"\x00\x01\x02" * 10,
            }
        ),
        LAYERS[1]: layer({"srv/seed.csv": f"name,ssn\nA,{dashed(SSN_A)}\n".encode()}),
    }
    order = [LAYERS[2], LAYERS[1]]  # the top layers first; ECR_MAX_LAYERS=2
    for d in order:
        ecr.add_response(
            "get_download_url_for_layer",
            {"downloadUrl": f"https://layers.example/{d[7:15]}", "layerDigest": d},
            {"repositoryName": "checkout", "layerDigest": d},
        )
    fetched: list[str] = []

    def fetch(url: str, max_bytes: int) -> IO[bytes]:
        fetched.append(url)
        digest = next(d for d in order if d[7:15] in url)
        return io.BytesIO(blobs[digest])

    env.clients.services["layer-fetch"] = fetch
    doc = run(env, "ecr", ecr_read=True, ecr_max_layers=2)
    ecr.assert_no_pending_responses()
    assert len(fetched) == 2
    found = {(f["resource"]["field"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("app/config.json", "card"), ("srv/seed.csv", "us_ssn")}
    f = found[("app/config.json", "card")]
    assert f["resource"] == {
        "type": "store_field",
        "service": "ecr",
        "store": "checkout",
        "table": LAYERS[2][:19],
        "field": "app/config.json",
        "readBy": "layer_sample",
    }
    assert f["atRestEncryption"] == "service_managed"
    cov = next(c for c in doc["coverage"] if c["kind"] == "ecr")
    assert (cov["listed"], cov["scanned"], cov["skipped"]) == (2, 2, {"binary": 1, "image": 1})
    # The same image again: read in full, so nothing is downloaded.
    repositories(ecr)
    images(ecr)
    fetched.clear()
    run(env, "ecr", ecr_read=True, ecr_max_layers=2)
    ecr.assert_no_pending_responses()
    assert fetched == []


def test_ecr_is_reported_until_turned_on(env: Env) -> None:
    s = stubs(env, "ecr")
    repositories(s["ecr"], {"encryptionType": "KMS", "kmsKey": "alias/aws/ecr"})
    st = stores(run(env, "ecr"))[("ecr", "checkout")]
    assert (st["reason"], st["atRestEncryption"]) == ("read_not_configured", "service_managed")


# ------------------------------------------------------------------ SageMaker


def test_sagemaker_offline_stores_are_read_as_s3_and_the_rest_reported(env: Env) -> None:
    s = stubs(env, "sagemaker")
    sm = s["sagemaker"]
    sm.add_response(
        "list_feature_groups",
        {
            "FeatureGroupSummaries": [
                {
                    "FeatureGroupName": name,
                    "FeatureGroupArn": f"arn:aws:sagemaker:us-west-2:1:feature-group/{name}",
                    "CreationTime": T0,
                }
                for name in ("customers", "sessions")
            ]
        },
    )
    base = {
        "FeatureGroupArn": "arn:aws:sagemaker:us-west-2:1:feature-group/x",
        "RecordIdentifierFeatureName": "id",
        "EventTimeFeatureName": "t",
        "FeatureDefinitions": [{"FeatureName": "id", "FeatureType": "String"}],
        "CreationTime": T0,
        "NextToken": "",
    }
    sm.add_response(
        "describe_feature_group",
        {
            **base,
            "FeatureGroupName": "customers",
            "OfflineStoreConfig": {
                "S3StorageConfig": {
                    "S3Uri": f"s3://{DATA}/fs",
                    "ResolvedOutputS3Uri": f"s3://{DATA}/fs/{ACCOUNT}/sagemaker/customers/data",
                }
            },
        },
        {"FeatureGroupName": "customers"},
    )
    sm.add_response(
        "describe_feature_group",
        {**base, "FeatureGroupName": "sessions", "OnlineStoreConfig": {"EnableOnlineStore": True}},
        {"FeatureGroupName": "sessions"},
    )
    sm.add_response(
        "list_notebook_instances",
        {
            "NotebookInstances": [
                {
                    "NotebookInstanceName": "research",
                    "NotebookInstanceArn": "arn:aws:sagemaker:us-west-2:1:notebook-instance/r",
                }
            ]
        },
    )
    env.put(
        f"fs/{ACCOUNT}/sagemaker/customers/data/part-0.json", json.dumps({"ssn": dashed(SSN_B)})
    )
    env.put("elsewhere/x.txt", f"card {CARDS['jcb']}")  # not the feature group's
    doc = run(env, "sagemaker", sagemaker_read=True)
    sm.assert_no_pending_responses()
    (f,) = doc["findings"]
    assert (f["resource"]["type"], f["class"]) == ("s3_object", "us_ssn")
    st = stores(doc)
    assert st[("sagemaker", "feature-group/customers")]["status"] == "scanned"
    online = st[("sagemaker", "feature-group/sessions")]
    assert (online["reason"], online["resource"]) == ("no_read_path", "feature_group")
    nb = st[("sagemaker", "notebook-instance/research")]
    assert (nb["reason"], nb["resource"]) == ("no_read_path", "notebook_instance")


# ------------------------------------------------------------------ Neptune Analytics

GRAPH_KEY = f"arn:aws:kms:us-west-2:{ACCOUNT}:key/0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/graph-export"


def graphs(ng: Stubber) -> None:
    ng.add_response(
        "list_graphs",
        {
            "graphs": [
                {
                    "id": "g-0123456789",
                    "name": "customers-graph",
                    "arn": f"arn:aws:neptune-graph:us-west-2:{ACCOUNT}:graph/g-0123456789",
                    "status": "AVAILABLE",
                    "kmsKeyIdentifier": "AWS_OWNED_KEY",
                }
            ]
        },
    )


def test_neptune_analytics_is_read_by_export(env: Env) -> None:
    s = stubs(env, "neptune-graph")
    ng = s["neptune-graph"]
    cfg = {
        "neptune_analytics_export_role_arn": ROLE,
        "neptune_analytics_export_kms_key_arn": GRAPH_KEY,
    }
    graphs(ng)
    ng.add_response(
        "start_export_task",
        {
            "graphId": "g-0123456789",
            "roleArn": ROLE,
            "taskId": "t-0123456789",
            "status": "INITIALIZING",
            "format": "CSV",
            "destination": f"s3://{RESULTS}/exports/neptune-graph/",
            "kmsKeyIdentifier": GRAPH_KEY,
        },
        {
            "graphIdentifier": "g-0123456789",
            "roleArn": ROLE,
            "format": "CSV",
            "destination": f"s3://{RESULTS}/exports/neptune-graph/",
            "kmsKeyIdentifier": GRAPH_KEY,
        },
    )
    first = run(env, "neptune_analytics", **cfg)
    st = stores(first)[("neptune_analytics", "customers-graph")]
    assert (st["status"], st["reason"]) == ("deferred", "export_pending")
    base = "exports/neptune-graph/t-0123456789/"
    s3 = env.clients.s3
    s3.put_object(
        Bucket=RESULTS,
        Key=f"{base}Nodes/person.csv",
        Body=f"~id,~label,name:String,card:String\n1,Person,Ann,{CARDS['discover']}\n".encode(),
    )
    s3.put_object(Bucket=RESULTS, Key=f"{base}Edges/knows.csv", Body=b"~id,~from,~to,~label\n")
    graphs(ng)
    ng.add_response(
        "get_export_task",
        {
            "graphId": "g-0123456789",
            "roleArn": ROLE,
            "taskId": "t-0123456789",
            "status": "SUCCEEDED",
            "format": "CSV",
            "destination": f"s3://{RESULTS}/exports/neptune-graph/",
            "kmsKeyIdentifier": GRAPH_KEY,
        },
        {"taskIdentifier": "t-0123456789"},
    )
    second = run(env, "neptune_analytics", **cfg)
    ng.assert_no_pending_responses()
    (f,) = second["findings"]
    assert f["resource"] == {
        "type": "store_field",
        "service": "neptune_analytics",
        "store": "customers-graph",
        "table": "nodes",
        "field": "card",
        "readBy": "export",
    }
    assert f["atRestEncryption"] == "service_managed"
    left = s3.list_objects_v2(Bucket=RESULTS, Prefix=base).get("KeyCount", 0)
    assert left == 0  # the export is deleted once read
    graphs(ng)
    assert (
        stores(run(env, "neptune_analytics"))[("neptune_analytics", "customers-graph")]["reason"]
        == "export_not_configured"
    )


# ------------------------------------------------------------------ EventBridge archives

ARCHIVE = f"arn:aws:events:us-west-2:{ACCOUNT}:archive/orders-archive"
BUS = f"arn:aws:events:us-west-2:{ACCOUNT}:event-bus/orders"
QUEUE_URL = f"https://sqs.us-west-2.amazonaws.com/{ACCOUNT}/sensitive-data-scanner-replay"
QUEUE_ARN = f"arn:aws:sqs:us-west-2:{ACCOUNT}:sensitive-data-scanner-replay"


def archives(events: Stubber) -> None:
    events.add_response("list_archives", {"Archives": [{"ArchiveName": "orders-archive"}]})
    events.add_response(
        "describe_archive",
        {
            "ArchiveArn": ARCHIVE,
            "ArchiveName": "orders-archive",
            "EventSourceArn": BUS,
            "State": "ENABLED",
            "RetentionDays": 30,
            "SizeBytes": 123456,
            "EventCount": 789,
        },
        {"ArchiveName": "orders-archive"},
    )


def test_an_archive_is_reported_with_its_size_until_replay_is_on(env: Env) -> None:
    s = stubs(env, "events")
    archives(s["events"])
    st = stores(run(env, "eventbridge_archive"))[("eventbridge_archive", "orders-archive")]
    assert (st["reason"], st["sizeBytes"], st["eventCount"], st["retentionDays"]) == (
        "read_not_configured",
        123456,
        789,
        30,
    )


def test_a_replay_reaches_only_the_scanners_own_rule_and_queue(env: Env) -> None:
    s = stubs(env, "events", "sqs")
    ev, sqs = s["events"], s["sqs"]
    cfg = {
        "eventbridge_replay": True,
        "eventbridge_replay_queue_url": QUEUE_URL,
        "eventbridge_replay_queue_arn": QUEUE_ARN,
    }
    archives(ev)
    rule_arn = f"arn:aws:events:us-west-2:{ACCOUNT}:rule/orders/sensitive-data-scanner-replay-x"
    ev.add_response("put_rule", {"RuleArn": rule_arn})
    ev.add_response("put_targets", {"FailedEntryCount": 0, "FailedEntries": []})
    ev.add_response(
        "start_replay",
        {"State": "STARTING"},
        {
            "ReplayName": ANY,
            "EventSourceArn": ARCHIVE,
            "EventStartTime": ANY,
            "EventEndTime": ANY,
            "Destination": {"Arn": BUS, "FilterArns": [rule_arn]},
        },
    )
    first = run(env, "eventbridge_archive", **cfg)
    assert stores(first)[("eventbridge_archive", "orders-archive")]["reason"] == "export_pending"
    cursor = next(v for k, v in env.state()["cursors"].items() if k.startswith("ebarchive:"))
    replay = cursor["replay"]
    assert replay.startswith("sds-")
    archives(ev)
    ev.add_response("describe_replay", {"State": "COMPLETED"}, {"ReplayName": replay})
    ours = {"replay-name": replay, "detail": {"card": CARDS["mastercard"], "n": SSN_A}}
    stale = {"replay-name": "sds-other", "detail": {"card": CARDS["amex"]}}
    sqs.add_response(
        "receive_message",
        {
            "Messages": [
                {"MessageId": "1", "ReceiptHandle": "r1", "Body": json.dumps(ours)},
                {"MessageId": "2", "ReceiptHandle": "r2", "Body": json.dumps(stale)},
            ]
        },
        {"QueueUrl": QUEUE_URL, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1},
    )
    for handle in ("r1", "r2"):
        sqs.add_response("delete_message", {}, {"QueueUrl": QUEUE_URL, "ReceiptHandle": handle})
    sqs.add_response("receive_message", {"Messages": []})
    ev.add_response("remove_targets", {"FailedEntryCount": 0, "FailedEntries": []})
    ev.add_response("delete_rule", {})
    second = run(env, "eventbridge_archive", **cfg)
    ev.assert_no_pending_responses()
    sqs.assert_no_pending_responses()
    (f,) = second["findings"]
    assert (f["class"], f["resource"]["readBy"], f["resource"]["field"]) == (
        "card",
        "replay",
        "events",
    )
    assert stores(second)[("eventbridge_archive", "orders-archive")]["status"] == "scanned"


# ------------------------------------------------------------------ Glacier


def test_glacier_vaults_are_reported_as_archive_retrieval(env: Env) -> None:
    s = stubs(env, "glacier")
    s["glacier"].add_response(
        "list_vaults",
        {
            "VaultList": [
                {"VaultName": "old-statements", "NumberOfArchives": 42, "SizeInBytes": 9_000_000}
            ]
        },
        {"accountId": "-"},
    )
    st = stores(run(env, "glacier"))[("glacier", "old-statements")]
    assert (st["status"], st["reason"], st["archives"], st["sizeBytes"]) == (
        "skipped",
        "archive_retrieval",
        42,
        9_000_000,
    )
    assert st["atRestEncryption"] == "service_managed"


def test_a_gzip_layer_cut_by_its_byte_cap_counts_as_partial() -> None:
    from sensitive_data_scanner.sources.images import Capped

    data = gzip.compress(b"x" * 1000)
    capped = Capped(io.BytesIO(data), 10)
    assert capped.read(100) == data[:10]
    assert capped.read(100) == b""
    assert capped.cut is True
