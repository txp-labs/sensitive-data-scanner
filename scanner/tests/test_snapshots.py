"""Snapshots, backups and file systems: EBS (read by the EBS direct APIs, opt-in), AWS Backup,
DocumentDB, Neptune, EFS and FSx (discovered and reported with the reason they are not read).

Every AWS answer comes from botocore's Stubber; every value is made up.
"""

from __future__ import annotations

import datetime as dt
import io
import json
from typing import Any

import boto3
from botocore.response import StreamingBody
from botocore.stub import Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import Env, config
from conftest import REPO
from sensitive_data_core.scan.raw import printable_text
from sensitive_data_scanner.config import read_config, store_rules
from sensitive_data_scanner.sources.ebs import BLOCK
from synthetic import CARDS, SSN_A, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
T1 = dt.datetime(2026, 9, 28, 6, 0, tzinfo=dt.UTC)
T2 = dt.datetime(2026, 9, 29, 6, 0, tzinfo=dt.UTC)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    # Every finding the runner writes says what storage encryption it sat under (1.5).
    assert all("atRestEncryption" in f for f in doc["findings"])


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(s["kind"], s["name"]): s for s in doc["discovery"]["stores"]}


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


def stubs(env: Env, *services: str) -> dict[str, Stubber]:
    out = {}
    for s in services:
        c, stub = client(s)
        env.clients.services[s] = c
        out[s] = stub
    return out


def snapshot(sid: str, vid: str, at: dt.datetime, size: int = 1, tier: str = "standard") -> Any:
    return {
        "SnapshotId": sid,
        "VolumeId": vid,
        "State": "completed",
        "StartTime": at,
        "VolumeSize": size,
        "StorageTier": tier,
    }


def ebs_estate(ec2: Stubber) -> None:
    ec2.add_response(
        "describe_volumes",
        {
            "Volumes": [
                {"VolumeId": "vol-0a1", "Size": 1, "Tags": [{"Key": "team", "Value": "a"}]},
                {"VolumeId": "vol-0b2", "Size": 8},
                {"VolumeId": "vol-0c3", "Size": 8},
            ]
        },
    )
    ec2.add_response(
        "describe_snapshots",
        {
            "Snapshots": [
                snapshot("snap-old", "vol-0a1", T1),
                snapshot("snap-new", "vol-0a1", T2),
                snapshot("snap-arch", "vol-0c3", T2, tier="archive"),
                snapshot("snap-orphan", "vol-0gone", T1, size=1),
                {**snapshot("snap-pending", "vol-0b2", T2), "State": "pending"},
            ]
        },
        {"OwnerIds": ["self"]},
    )


def block_bytes(text: str) -> bytes:
    raw = b"\x00" * 1000 + text.encode() + b"\x00\x13" + "x".encode("utf-16-le") * 3
    return raw + b"\x00" * (BLOCK - len(raw))


def blocks(ebs: Stubber, sid: str, start: int, texts: list[str]) -> None:
    ebs.add_response(
        "list_snapshot_blocks",
        {
            "Blocks": [{"BlockIndex": start + i, "BlockToken": f"t{i}"} for i in range(len(texts))],
            "BlockSize": BLOCK,
            "VolumeSize": 1,
        },
        {"SnapshotId": sid, "StartingBlockIndex": start, "MaxResults": 100},
    )
    for i, text in enumerate(texts):
        data = block_bytes(text)
        ebs.add_response(
            "get_snapshot_block",
            {"BlockData": StreamingBody(io.BytesIO(data), len(data)), "DataLength": len(data)},
            {"SnapshotId": sid, "BlockIndex": start + i, "BlockToken": f"t{i}"},
        )


EBS = frozenset({"ebs"})


def test_ebs_off_discovers_and_reports_every_volume_and_snapshot(env: Env) -> None:
    s = stubs(env, "ec2")
    ebs_estate(s["ec2"])
    doc = env.run(config(s3_targets=[], discover=EBS))
    assert doc is not None
    valid(doc)
    st = stores(doc)
    a = st[("ebs", "vol-0a1")]
    assert (a["reason"], a["resource"], a["olderSnapshots"], a["snapshotTime"]) == (
        "read_not_configured",
        "volume",
        1,
        T2.isoformat(),
    )
    assert "snapshotId" not in a and "volumeGiB" not in a
    assert st[("ebs", "vol-0b2")]["reason"] == "no_snapshot"  # its only snapshot is pending
    assert st[("ebs", "vol-0c3")]["reason"] == "archived"
    assert (st[("ebs", "snap-orphan")]["resource"], st[("ebs", "snap-orphan")]["reason"]) == (
        "snapshot",
        "read_not_configured",
    )
    assert a["sizeBytes"] == 1024**3


def test_ebs_direct_read_samples_blocks_and_resumes(env: Env) -> None:
    s = stubs(env, "ec2", "ebs")
    # 1 GiB = 2048 blocks; 8 blocks per snapshot = 2 sampling points of 4 blocks.
    cfg = config(
        s3_targets=[],
        discover=EBS,
        ebs_direct_read=True,
        ebs_blocks_per_snapshot=8,
        max_bytes_per_run=4 * BLOCK,
        deny=store_rules("ebs:snap-orphan"),
    )
    ebs_estate(s["ec2"])
    blocks(s["ebs"], "snap-new", 0, [f"card {CARDS['visa']} on file", "nothing 1", "", "x"])
    first = env.run(cfg)
    assert first is not None
    valid(first)
    s["ebs"].assert_no_pending_responses()
    cov = next(c for c in first["coverage"] if c["kind"] == "ebs")
    assert (cov["scanned"], cov["formats"], cov["backlog"]) == (4, {"block": 4}, True)
    assert stores(first)[("ebs", "vol-0a1")]["backlog"] is True
    ebs_estate(s["ec2"])
    blocks(s["ebs"], "snap-new", 1024, [f"ssn {dashed(SSN_A)}", f"card {CARDS['visa']}"])
    second = env.run(cfg)
    assert second is not None
    valid(second)
    s["ebs"].assert_no_pending_responses()
    found = {(f["resource"]["store"], f["class"]): f for f in second["findings"]}
    assert set(found) == {("vol-0a1", "card"), ("vol-0a1", "us_ssn")}
    card = found[("vol-0a1", "card")]
    assert card["resource"] == {
        "type": "store_field",
        "service": "ebs",
        "store": "vol-0a1",
        "field": "blocks",
        "readBy": "ebs_direct",
        "snapshotTime": T2.isoformat(),
    }
    assert (card["format"], card["count"], card["offsets"]) == ("block", 2, [])
    cov = next(c for c in second["coverage"] if c["kind"] == "ebs")
    assert (cov["passComplete"], cov["partial"]) == (True, 1)
    # The same snapshot again: nothing to read, the findings stand.
    ebs_estate(s["ec2"])
    third = env.run(cfg)
    assert third is not None
    s["ebs"].assert_no_pending_responses()
    assert len(third["findings"]) == 2
    assert read_config({"RESULTS_BUCKET": "x"}).ebs_direct_read is False


def test_a_kms_denied_snapshot_is_reported(env: Env) -> None:
    s = stubs(env, "ec2", "ebs")
    s["ec2"].add_response("describe_volumes", {"Volumes": [{"VolumeId": "vol-0a1", "Size": 1}]})
    s["ec2"].add_response(
        "describe_snapshots", {"Snapshots": [snapshot("snap-new", "vol-0a1", T2)]}
    )
    s["ebs"].add_response(
        "list_snapshot_blocks",
        {"Blocks": [{"BlockIndex": 0, "BlockToken": "t0"}], "BlockSize": BLOCK},
    )
    s["ebs"].add_client_error(
        "get_snapshot_block",
        service_error_code="AccessDeniedException",
        http_status_code=403,
        service_message="not allowed to use the KMS key",
    )
    doc = env.run(config(s3_targets=[], discover=EBS, ebs_direct_read=True))
    assert doc is not None
    valid(doc)
    v = stores(doc)[("ebs", "vol-0a1")]
    assert (v["status"], v["reason"]) == ("error", "kms_access")


def test_backup_vaults_are_reported_with_their_recovery_points(env: Env) -> None:
    s = stubs(env, "backup")
    s["backup"].add_response(
        "list_backup_vaults",
        {
            "BackupVaultList": [
                {"BackupVaultName": "Default", "BackupVaultArn": "arn:v1"},
                {"BackupVaultName": "locked", "BackupVaultArn": "arn:v2"},
            ]
        },
    )
    s["backup"].add_response(
        "list_recovery_points_by_backup_vault",
        {
            "RecoveryPoints": [
                {"ResourceType": "EBS"},
                {"ResourceType": "EBS"},
                {"ResourceType": "RDS"},
                {"ResourceType": "S3"},
            ]
        },
        {"BackupVaultName": "Default"},
    )
    s["backup"].add_client_error(
        "list_recovery_points_by_backup_vault",
        service_error_code="AccessDeniedException",
        http_status_code=403,
    )
    doc = env.run(config(s3_targets=[], discover=frozenset({"backup"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)
    d = st[("backup", "Default")]
    assert (d["status"], d["reason"], d["recoveryPoints"]) == (
        "skipped",
        "backup_copy",
        {"EBS": 2, "RDS": 1, "S3": 1},
    )
    locked = st[("backup", "locked")]
    assert (locked["status"], locked["reason"]) == ("error", "access_denied")


def test_documentdb_and_neptune_have_no_snapshot_export(env: Env) -> None:
    s = stubs(env, "docdb", "neptune", "docdb-elastic", "rds")
    env.clients.rds = env.clients.services["rds"]
    s["rds"].add_response(
        "describe_db_clusters",
        {
            "DBClusters": [
                {"DBClusterIdentifier": "docs", "Engine": "docdb"},
                {"DBClusterIdentifier": "graph", "Engine": "neptune"},
            ]
        },
    )
    s["rds"].add_response("describe_db_instances", {"DBInstances": []})
    engine = {"Filters": [{"Name": "engine", "Values": ["docdb"]}]}
    s["docdb"].add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": "docs", "Engine": "docdb"}]},
        engine,
    )
    s["docdb-elastic"].add_response(
        "list_clusters",
        {"clusters": [{"clusterName": "elastic-docs", "clusterArn": "arn:e", "status": "ACTIVE"}]},
    )
    s["neptune"].add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": "graph", "Engine": "neptune"}]},
        {"Filters": [{"Name": "engine", "Values": ["neptune"]}]},
    )
    doc = env.run(config(s3_targets=[], discover=frozenset({"rds", "documentdb", "neptune"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)
    # Listed once, by their own kind: not again as unsupported RDS engines.
    assert ("rds", "docs") not in st and ("rds", "graph") not in st
    assert (st[("documentdb", "docs")]["reason"], st[("documentdb", "docs")]["engine"]) == (
        "no_snapshot_export",
        "docdb",
    )
    assert st[("documentdb", "elastic-docs")]["deployment"] == "elastic"
    assert st[("neptune", "graph")]["reason"] == "no_snapshot_export"


def test_efs_and_fsx_need_the_file_system_task(env: Env) -> None:
    s = stubs(env, "efs", "fsx")
    s["efs"].add_response(
        "describe_file_systems",
        {
            "FileSystems": [
                {
                    "OwnerId": "123456789012",
                    "CreationToken": "t",
                    "FileSystemId": "fs-0abc",
                    "CreationTime": T1,
                    "LifeCycleState": "available",
                    "NumberOfMountTargets": 1,
                    "SizeInBytes": {"Value": 4096},
                    "PerformanceMode": "generalPurpose",
                    "Tags": [],
                },
                {
                    "OwnerId": "123456789012",
                    "CreationToken": "u",
                    "FileSystemId": "fs-0def",
                    "CreationTime": T1,
                    "LifeCycleState": "deleting",
                    "NumberOfMountTargets": 0,
                    "SizeInBytes": {"Value": 0},
                    "PerformanceMode": "generalPurpose",
                    "Tags": [],
                },
            ]
        },
    )
    s["fsx"].add_response(
        "describe_file_systems",
        {
            "FileSystems": [
                {
                    "FileSystemId": "fs-0123456789abcdef0",
                    "FileSystemType": "WINDOWS",
                    "Lifecycle": "AVAILABLE",
                    "StorageCapacity": 32,
                }
            ]
        },
    )
    doc = env.run(config(s3_targets=[], discover=frozenset({"efs", "fsx"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)
    assert (st[("efs", "fs-0abc")]["reason"], st[("efs", "fs-0abc")]["sizeBytes"]) == (
        "needs_task",
        4096,
    )
    assert (st[("efs", "fs-0def")]["reason"], st[("efs", "fs-0def")]["state"]) == (
        "unsupported",
        "deleting",
    )
    fsx = st[("fsx", "fs-0123456789abcdef0")]
    assert (fsx["reason"], fsx["fileSystemType"], fsx["sizeBytes"]) == (
        "needs_task",
        "WINDOWS",
        32 * 1024**3,
    )


def test_printable_text_keeps_runs_that_could_hold_a_value() -> None:
    raw = (
        b"\x00\x01card 4539 on file\x00\xff"
        + "ssn 123".encode("utf-16-le")
        + b"\x00just words here\x00"
    )
    text = printable_text(raw)
    assert "card 4539 on file" in text and "ssn 123" in text
    assert "just words" not in text  # no digit: cannot hold a value


def test_the_file_system_task_is_a_hook_named_on_and_off(env: Env) -> None:
    """A5 (#105): EFS and FSx name FILESYSTEM_TASK_ENABLED, off by default; on, the task is not
    built, so each is `not_implemented`, never a silent pass."""
    fs = {
        "FileSystems": [
            {
                "OwnerId": "123456789012",
                "CreationToken": "t",
                "FileSystemId": "fs-0abc",
                "CreationTime": T1,
                "LifeCycleState": "available",
                "NumberOfMountTargets": 1,
                "SizeInBytes": {"Value": 4096},
                "PerformanceMode": "generalPurpose",
                "Tags": [],
            }
        ]
    }
    s = stubs(env, "efs")
    s["efs"].add_response("describe_file_systems", fs)
    doc = env.run(config(s3_targets=[], discover=frozenset({"efs"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)[("efs", "fs-0abc")]
    assert (st["reason"], st["toggle"]) == ("needs_task", "FILESYSTEM_TASK_ENABLED")
    s["efs"].add_response("describe_file_systems", fs)
    doc = env.run(config(s3_targets=[], discover=frozenset({"efs"}), filesystem_task=True))
    assert doc is not None
    valid(doc)
    st = stores(doc)[("efs", "fs-0abc")]
    assert (st["status"], st["reason"], st["toggle"]) == (
        "skipped",
        "not_implemented",
        "FILESYSTEM_TASK_ENABLED",
    )
    assert read_config({"RESULTS_BUCKET": "x"}).filesystem_task is False
