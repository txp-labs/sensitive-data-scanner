"""Cloud Logging (read), Pub/Sub and disk snapshots (coverage only), Secret Manager (opt-in).

Every Google call goes to a stubbed session (gcp_fakes.py); every value is made up.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from aws_fixtures import shared_detector
from gcp_fakes import (
    KEY,
    NOW,
    OTHER,
    PROJECT,
    Cloud,
    Ops,
    asset,
    error,
    settings,
)
from sensitive_data_core.findings import key_hash
from sensitive_data_gcp.config import ConfigError, read_settings
from sensitive_data_gcp.runner import run_scan
from sensitive_data_gcp.sources.logging import entry_row, filter_for
from synthetic import CARDS, SSN_A, dashed
from test_gcp_gcs import valid

ACTIVITY = "cloudaudit.googleapis.com/activity"
DATA_ACCESS = "cloudaudit.googleapis.com/data_access"
TOPIC = "pubsub.googleapis.com/Topic"
SNAP = "compute.googleapis.com/Snapshot"
SECRET = "secretmanager.googleapis.com/Secret"  # noqa: S105 - an asset type


def cloud() -> tuple[Cloud, Ops]:
    c = Cloud()
    ops = Ops(c)
    ops.logs[PROJECT] = {
        "app": [
            {"textPayload": f"charged card {CARDS['visa']}", "timestamp": "2026-09-29T11:00:00Z"},
            {"jsonPayload": {"customer": {"ssn": dashed(SSN_A)}, "msg": "ok"}},
        ],
        ACTIVITY: [{"protoPayload": {"methodName": "SetIamPolicy"}}],
        DATA_ACCESS: [{"protoPayload": {"request": {"card": CARDS["amex"]}}}],
    }
    ops.logs[OTHER] = {}
    ops.log_keys[PROJECT] = KEY
    c.assets[TOPIC] = [
        asset(TOPIC, f"//pubsub.googleapis.com/projects/{PROJECT}/topics/orders"),
        asset(TOPIC, f"//pubsub.googleapis.com/projects/{PROJECT}/topics/orders-dlq"),
        asset(TOPIC, f"//pubsub.googleapis.com/projects/{OTHER}/topics/pay-dlq"),
    ]
    ops.subscriptions[PROJECT] = [
        {
            "name": f"projects/{PROJECT}/subscriptions/orders-worker",
            "topic": f"projects/{PROJECT}/topics/orders",
            "deadLetterPolicy": {"deadLetterTopic": f"projects/{PROJECT}/topics/orders-dlq"},
        }
    ]
    ops.subscriptions[OTHER] = error(403, "PERMISSION_DENIED", message="no subscriptions.list")
    c.assets[SNAP] = [
        asset(SNAP, f"//compute.googleapis.com/projects/{PROJECT}/global/snapshots/db-1"),
    ]
    disk = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/zones/us-central1-a/disks/db"
    ops.snapshots[PROJECT] = [
        {
            "name": "db-1",
            "sourceDisk": disk,
            "creationTimestamp": "2026-09-27T01:00:00.000-07:00",
            "storageBytes": "1024",
        },
        {
            "name": "db-2",
            "sourceDisk": disk,
            "creationTimestamp": "2026-09-28T01:00:00.000-07:00",
            "storageBytes": "2048",
            "snapshotEncryptionKey": {"kmsKeyName": KEY + "/cryptoKeyVersions/1"},
        },
        {
            "name": "orphan",
            "creationTimestamp": "2026-09-01T01:00:00.000-07:00",
            "diskSizeGb": "10",
            "snapshotEncryptionKey": {"sha256": "made-up"},
        },
    ]
    c.assets[SECRET] = [
        asset(SECRET, f"//secretmanager.googleapis.com/projects/{PROJECT}/secrets/api-key"),
        asset(SECRET, f"//secretmanager.googleapis.com/projects/{PROJECT}/secrets/card-vault"),
        asset(SECRET, f"//secretmanager.googleapis.com/projects/{PROJECT}/secrets/old"),
    ]
    ops.secrets[(PROJECT, "api-key")] = b"made-up-api-key"
    ops.secrets[(PROJECT, "card-vault")] = f"card {CARDS['mastercard']}".encode()
    ops.secrets[(PROJECT, "old")] = error(400, "FAILED_PRECONDITION", message="disabled")
    ops.secret_meta[(PROJECT, "card-vault")] = {
        "replication": {
            "userManaged": {"replicas": [{"customerManagedEncryption": {"kmsKeyName": KEY}}]}
        }
    }
    return c, ops


def run(c: Cloud, kinds: str, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(DISCOVER=kinds, **env), c.clients(), detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}


# ------------------------------------------------------------------ Cloud Logging


def test_logs_are_sampled_per_log_and_private_logs_are_opt_in() -> None:
    c, ops = cloud()
    doc = run(c, "logging")
    s = stores(doc)
    assert s[("cloud_logging", PROJECT)]["atRestKeyHash"] == key_hash(KEY)
    assert s[("cloud_logging", OTHER)]["status"] == "scanned"
    cov = next(x for x in doc["coverage"] if x["target"] == PROJECT)
    assert cov["skipped"] == {"private_log": 1} and cov["scanned"] == 2
    got = {(f["resource"]["table"], f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert ("app", "textPayload", "card") in got
    assert ("app", "jsonPayload.customer", "us_ssn") in got
    assert not any(t == DATA_ACCESS for t, _, _ in got)
    f = doc["findings"][0]
    assert (f["resource"]["service"], f["resource"]["readBy"], f["resource"]["store"]) == (
        "cloud_logging",
        "entries_list",
        PROJECT,
    )
    call = ops.entries_calls[0]
    assert call["orderBy"] == "timestamp desc" and call["pageSize"] == 500
    assert 'timestamp>="2026-09-28T12:00:00Z"' in call["filter"]
    # With Private Logs Viewer opted in, Data Access logs are read too.
    doc = run(c, "logging", LOGGING_PRIVATE_READ="on")
    assert any(f["resource"]["table"] == DATA_ACCESS for f in doc["findings"])


def test_the_read_quota_stops_the_pass_and_it_resumes_there() -> None:
    c, ops = cloud()
    ops.quota_after = 1
    doc = run(c, "logging")
    assert stores(doc)[("cloud_logging", PROJECT)].get("backlog") is True
    ops.quota_after = None
    first = len(ops.entries_calls)
    run(c, "logging")
    assert len(ops.entries_calls) == first + 1  # only the log the quota stopped at


def test_a_log_name_is_quoted_in_the_filter() -> None:
    since = dt.datetime(2026, 9, 28, tzinfo=dt.UTC)
    assert filter_for('projects/p/logs/a"b', since) == (
        'logName="projects/p/logs/a\\"b" AND timestamp>="2026-09-28T00:00:00Z"'
    )
    assert entry_row({"jsonPayload": {"@type": "x", "a": 1}, "labels": {"k": "v"}}) == {
        "jsonPayload.a": 1,
        "labels": {"k": "v"},
    }


# ------------------------------------------------------------------ Pub/Sub and snapshots


def test_topics_are_coverage_only_dead_letter_topics_named() -> None:
    c, _ = cloud()
    s = stores(run(c, "pubsub"))
    dlq = s[("pubsub", f"{PROJECT}/orders-dlq")]
    assert (dlq["status"], dlq["reason"], dlq["deadLetterQueue"]) == (
        "skipped",
        "needs_subscription",
        True,
    )
    assert s[("pubsub", f"{PROJECT}/orders")]["reason"] == "live_queue"
    # Subscriptions unreadable: whether a topic is a dead-letter topic is unknown.
    assert s[("pubsub", f"{OTHER}/pay-dlq")]["reason"] == "needs_subscription"
    assert not any(m == "POST" and "pubsub" in u for m, u, _ in c.requests)


def test_snapshots_are_coverage_only_grouped_by_disk() -> None:
    c, _ = cloud()
    s = stores(run(c, "snapshots"))
    db = s[("gce_snapshot", "db")]
    assert (db["reason"], db["olderSnapshots"], db["sizeBytes"]) == ("needs_disk_restore", 1, 2048)
    assert db["atRestKeyHash"] == key_hash(KEY)
    assert db["snapshotTime"] == "2026-09-28T01:00:00.000-07:00"
    orphan = s[("gce_snapshot", "orphan")]
    assert orphan["atRestEncryption"] == "customer_managed_key" and "atRestKeyHash" not in orphan
    assert orphan["sizeBytes"] == 10 * 1024**3
    assert all(m == "GET" for m, u, _q in c.requests if "compute" in u)


# ------------------------------------------------------------------ Secret Manager


def test_secrets_are_off_by_default() -> None:
    c, ops = cloud()
    s = stores(run(c, "secrets"))
    store = s[("secret_manager", PROJECT)]
    assert (store["reason"], store["items"]) == ("read_not_configured", 3)
    assert ops.accessed == []


def test_secrets_when_on_are_counts_only() -> None:
    c, ops = cloud()
    doc = run(c, "secrets", SECRET_MANAGER_READ="on")  # noqa: S106 - a setting
    store = stores(doc)[("secret_manager", PROJECT)]
    assert store["itemTypes"] == {"Disabled": 1, "Secret": 2}
    f = next(x for x in doc["findings"] if x["class"] == "card")
    r = f["resource"]
    assert (r["service"], r["table"], r["field"], r["readBy"]) == (
        "secret_manager",
        "card-vault",
        "value",
        "access",
    )
    assert f["offsets"] == [] and f["atRestKeyHash"] == key_hash(KEY)
    assert sorted(ops.accessed) == ["api-key", "card-vault", "old"]


def test_settings_for_opt_ins() -> None:
    base = {"SCANNER_SITE": "x", "GCP_ORGANIZATION": "1", "FINDINGS_FILE": "/f"}
    for env, code in [
        ({"LOGGING_PRIVATE_READ": "maybe"}, "logging_private_read"),
        ({"SECRET_MANAGER_READ": "maybe"}, "secret_manager_read"),
    ]:
        with pytest.raises(ConfigError) as err:
            read_settings({**base, **env})
        assert err.value.code == code
