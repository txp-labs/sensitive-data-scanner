"""EBS volumes and snapshots, and AWS Backup vaults.

**Discovery** (`DISCOVER` includes `ebs`): `DescribeVolumes` and
`DescribeSnapshots` (owned by this account). Each volume is one store, read
through its latest completed snapshot; the latest snapshot of a volume that
no longer exists is a store of its own. Older snapshots of the same volume
are counted (`olderSnapshots`), not read: they are earlier copies of it. A
volume with no snapshot is `no_snapshot` (creating one would be a write),
and a snapshot in the archive tier is `archived` (the EBS direct APIs cannot
read it).

**Reading** (opt-in, `EBS_DIRECT_READ`): the EBS direct APIs read a
snapshot's blocks without creating or attaching a volume. `ListSnapshotBlocks`
from evenly spread starting points, then `GetSnapshotBlock` for a few
consecutive blocks at each, up to `EBS_BLOCKS_PER_SNAPSHOT` blocks (512 KiB
each) per snapshot, across as many runs as the budget needs. The runs of
printable text in the raw blocks (ASCII and UTF-16) are read as text: a file
system is not parsed, so compressed or encrypted files are not read and a
finding names the volume, not a file. The opt-in file-system task
(docs/ARCHITECTURE.md) is the design for reading files by path.

**AWS Backup** (`DISCOVER` includes `backup`): each vault is listed with its
recovery points counted by resource type (`recoveryPoints`). An EBS recovery
point is an EBS snapshot in this account, read as above; the rest are
copies of stores the other adapters read where they live. A vault is
reported as `backup_copy`: not read from the vault.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import secrets
import urllib.parse
from typing import Any

from ..detect.analyzer import Detector
from ..discovery import Discovery, Store, decide, needs_tags, reason_for
from ..findings import Coverage, console_link, store_field_resource
from ..safety import error_name, is_kms_denial, log_event
from ..scan.item import scan_item_text
from .base import Budget, Context, FindingStore, SourceRun, class_findings
from .exports import drop_other_passes, merge

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("ec2", "ebs", "backup")

BLOCK = 512 * 1024
RUN = 4  # consecutive blocks read at each sampling point
MAX_TEXT_PER_BLOCK = 64 * 1024
_ASCII = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_CANDIDATE = re.compile(r"[0-9]|\b(?:zero|one|two|three|four|five|six|seven|eight|nine)\b", re.I)


def printable_text(data: bytes) -> str:
    """The runs of printable text in raw bytes (ASCII, and UTF-16LE), one per line, that could
    hold a value; at most MAX_TEXT_PER_BLOCK characters."""
    runs = [m[0].decode("ascii") for m in _ASCII.finditer(data)]
    runs += [m[0].decode("utf-16-le") for m in _UTF16.finditer(data)]
    out: list[str] = []
    n = 0
    for r in runs:
        if not _CANDIDATE.search(r):
            continue
        out.append(r)
        n += len(r) + 1
        if n >= MAX_TEXT_PER_BLOCK:
            break
    return "\n".join(out)


def _tags(raw: list[dict[str, Any]] | None) -> dict[str, str]:
    return {str(t.get("Key")): str(t.get("Value", "")) for t in raw or [] if t.get("Key")}


class EbsAdapter:
    kind = "ebs"

    def discover(self, ctx: Context, out: Discovery) -> None:
        ec2 = ctx.clients.client("ec2")
        volumes: list[dict[str, Any]] = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            volumes.extend(page.get("Volumes", []))
        by_volume: dict[str, list[dict[str, Any]]] = {}
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []):
                if s.get("State") == "completed":
                    by_volume.setdefault(str(s.get("VolumeId") or s["SnapshotId"]), []).append(s)
        for snaps in by_volume.values():
            snaps.sort(key=lambda s: s.get("StartTime") or _dt.datetime.min, reverse=True)
        live = set()
        for v in volumes:
            vid = str(v["VolumeId"])
            live.add(vid)
            store = Store("ebs", vid, size_bytes=int(v.get("Size") or 0) * 1024**3)
            store.extra["resource"] = "volume"
            store.tags = _tags(v.get("Tags"))
            out.stores.append(store)
            self._decide(ctx, store, by_volume.get(vid, []))
        for vid, snaps in sorted(by_volume.items()):
            if vid in live:
                continue
            latest = snaps[0]
            store = Store("ebs", str(latest["SnapshotId"]))
            store.size_bytes = int(latest.get("VolumeSize") or 0) * 1024**3
            store.extra["resource"] = "snapshot"
            store.tags = _tags(latest.get("Tags"))
            out.stores.append(store)
            self._decide(ctx, store, snaps)

    def _decide(self, ctx: Context, store: Store, snaps: list[dict[str, Any]]) -> None:
        decide(store, ctx.config)
        if store.status != "pending":
            return
        if not snaps:
            store.skip("no_snapshot")  # creating one would be a write
            return
        latest = snaps[0]
        if len(snaps) > 1:
            store.extra["olderSnapshots"] = len(snaps) - 1
        if latest.get("StartTime"):
            store.extra["snapshotTime"] = latest["StartTime"].isoformat()
        if str(latest.get("StorageTier") or "standard") == "archive":
            store.skip("archived")
            return
        if not ctx.config.ebs_direct_read:
            store.skip("read_not_configured")
            return
        store.extra["snapshotId"] = str(latest["SnapshotId"])
        store.extra["volumeGiB"] = int(latest.get("VolumeSize") or 0)

    def source(self, ctx: Context, store: Store) -> EbsSnapshotSource | None:
        snapshot = store.extra.get("snapshotId")
        if not snapshot:
            return None
        return EbsSnapshotSource(
            ctx.clients.client("ebs"),
            name=store.name,
            snapshot_id=str(snapshot),
            snapshot_time=store.extra.get("snapshotTime"),
            volume_gib=int(store.extra.get("volumeGiB") or 0),
            region=ctx.region,
            max_blocks=ctx.config.ebs_blocks_per_snapshot,
        )


class EbsSnapshotSource:
    """One snapshot's blocks, sampled by the EBS direct APIs; resumes across runs."""

    kind = "ebs"

    def __init__(
        self,
        ebs: Any,
        *,
        name: str,
        snapshot_id: str,
        snapshot_time: str | None,
        volume_gib: int,
        region: str,
        max_blocks: int = 256,
    ) -> None:
        self.ebs = ebs
        self.name = name
        self.snapshot_id = snapshot_id
        self.snapshot_time = snapshot_time
        self.total_blocks = max(1, volume_gib * 1024**3 // BLOCK)
        self.region = region
        self.points = max(1, max_blocks // RUN)
        digest = hashlib.sha256(name.encode()).hexdigest()[:16]
        self.id = f"ebs:{digest}"
        self.target = name

    def link(self) -> str:
        what = (
            "VolumeDetails:volumeId"
            if self.name.startswith("vol-")
            else "SnapshotDetails:snapshotId"
        )
        q = urllib.parse.quote(self.name, safe="")
        return console_link(self.region, f"ec2/home?region={self.region}#{what}={q}")

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("ebs", self.target)
        extra: dict[str, Any] = {}
        if self.snapshot_time:
            extra["snapshotTime"] = self.snapshot_time
        if cursor.get("done") == self.snapshot_id:
            cov.pass_complete = True  # this snapshot is read; its findings stand
            return SourceRun(cov, cursor, None, extra)
        c = dict(cursor)
        if c.get("snapshot") != self.snapshot_id:
            c = {"snapshot": self.snapshot_id, "point": 0, "passId": secrets.token_hex(8)}
        resource = store_field_resource(
            service="ebs",
            store=self.name,
            field="blocks",
            read_by="ebs_direct",
            snapshot_time=self.snapshot_time,
        )
        link = self.link()
        seen_at = now.isoformat()
        cov.listed = self.points
        cov.eligible = self.points - int(c["point"])
        done = True
        try:
            for point in range(int(c["point"]), self.points):
                if not budget.has(BLOCK * RUN):
                    done = False
                    break
                start = point * self.total_blocks // self.points
                end = (point + 1) * self.total_blocks // self.points
                page = self.ebs.list_snapshot_blocks(
                    SnapshotId=self.snapshot_id, StartingBlockIndex=start, MaxResults=100
                )
                blocks = [b for b in page.get("Blocks", []) if int(b["BlockIndex"]) < end][:RUN]
                for b in blocks:
                    try:
                        r = self.ebs.get_snapshot_block(
                            SnapshotId=self.snapshot_id,
                            BlockIndex=int(b["BlockIndex"]),
                            BlockToken=str(b["BlockToken"]),
                        )
                        data = r["BlockData"].read(BLOCK)
                    except Exception as err:  # one block must not stop the pass
                        cov.unreadable += 1
                        if is_kms_denial(err):
                            raise
                        log_event("item.unreadable", source=self.target, error=error_name(err))
                        continue
                    budget.take(len(data))
                    cov.scanned += 1
                    cov.bytes_scanned += len(data)
                    cov.formats["block"] = cov.formats.get("block", 0) + 1
                    text = printable_text(data)
                    if not text:
                        continue
                    item = scan_item_text("block.txt", text, detector)
                    cov.test_values += item.test_values
                    cov.suppressed += item.suppressed
                    for f in class_findings(item.findings, resource, link, "block", seen_at):
                        merge(store, f"{self.id}\n{self.snapshot_id}", f, str(c["passId"]))
                c["point"] = point + 1
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, c, None, extra)
        if not done:
            cov.backlog = True
            return SourceRun(cov, c, None, extra)
        cov.pass_complete = True
        # The blocks were a sample: the whole volume was not read.
        cov.partial = int(self.points * RUN < self.total_blocks)
        gone = drop_other_passes(store, self.id, str(c["passId"]))
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return SourceRun(cov, {"done": self.snapshot_id}, None, extra)


class BackupAdapter:
    kind = "backup"

    def discover(self, ctx: Context, out: Discovery) -> None:
        backup = ctx.clients.client("backup")
        for page in backup.get_paginator("list_backup_vaults").paginate():
            for v in page.get("BackupVaultList", []):
                name = str(v["BackupVaultName"])
                store = Store("backup", name)
                out.stores.append(store)
                tag_error: str | None = None
                if needs_tags(ctx.config, "backup"):
                    try:
                        r = backup.list_tags(ResourceArn=str(v.get("BackupVaultArn")))
                        store.tags = {str(k): str(val) for k, val in (r.get("Tags") or {}).items()}
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status != "pending":
                    continue
                counts: dict[str, int] = {}
                try:
                    pages = backup.get_paginator("list_recovery_points_by_backup_vault").paginate(
                        BackupVaultName=name
                    )
                    for rp_page in pages:
                        for rp in rp_page.get("RecoveryPoints", []):
                            kind = re.sub(r"[^A-Za-z0-9]", "", str(rp.get("ResourceType") or ""))
                            counts[kind[:40] or "Unknown"] = (
                                counts.get(kind[:40] or "Unknown", 0) + 1
                            )
                except Exception as err:
                    store.status = "error"
                    store.error = error_name(err)
                    store.reason = reason_for(store.error)
                    continue
                store.extra["recoveryPoints"] = dict(sorted(counts.items()))
                store.skip("backup_copy")

    def source(self, ctx: Context, store: Store) -> None:
        return None
