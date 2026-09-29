"""What the export sources share: the export quota, the scanner-owned prefix, merging.

RDS and Aurora snapshots, and DynamoDB tables too large to Scan, are
exported by AWS to the results bucket's `exports/` prefix, which the scanner
owns. An export takes minutes to hours, so an export source is a small state
machine carried in its cursor from run to run: start an export (at most
`MAX_EXPORTS_PER_RUN` across all sources in a run, and no more often than
`EXPORT_MIN_INTERVAL_DAYS` per store), wait for it, scan what it wrote, then
delete it. Nothing outside `exports/` is written.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from ..findings import _CONF_RANK, MAX_OFFSETS_PER_FINDING
from .base import FindingStore

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


class ExportQuota:
    """How many exports this run may still start (shared by every export source)."""

    def __init__(self, allowed: int) -> None:
        self.left = allowed

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def due(last: str | None, now: _dt.datetime, min_interval_days: int) -> bool:
    """Whether a store's last complete export is old enough for a new one."""
    if not last:
        return True
    try:
        at = _dt.datetime.fromisoformat(last)
    except ValueError:
        return True
    return now - at >= _dt.timedelta(days=min_interval_days)


def list_keys(
    s3: S3Client, bucket: str, prefix: str, start_after: str | None = None
) -> Iterator[dict[str, Any]]:
    """Every object under `prefix` in key order, after `start_after`."""
    args: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
    if start_after:
        args["StartAfter"] = start_after
    while True:
        page = s3.list_objects_v2(**args)
        for obj in page.get("Contents", []):
            yield dict(obj)
        if not page.get("IsTruncated"):
            return
        args["ContinuationToken"] = page["NextContinuationToken"]
        args.pop("StartAfter", None)


def delete_prefix(s3: S3Client, bucket: str, prefix: str) -> int:
    """Delete an export the scanner has read. Only ever called under `exports/`."""
    if "/exports/" not in f"/{prefix}" or not prefix.endswith("/"):
        raise ValueError("refusing to delete outside the exports prefix")
    deleted = 0
    batch: list[dict[str, str]] = []
    for obj in list_keys(s3, bucket, prefix):
        batch.append({"Key": obj["Key"]})
        if len(batch) == 1000:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})  # type: ignore[typeddict-item]
            deleted += len(batch)
            batch = []
    if batch:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})  # type: ignore[typeddict-item]
        deleted += len(batch)
    return deleted


def merge(store: FindingStore, location: str, finding: dict[str, Any], pass_id: str) -> None:
    """Add a finding for one table and column from one more file of the same pass.

    An export splits a table across files; its findings for a column add up.
    `count` is then the sum of each file's distinct values (an upper bound).
    """
    finding["_pass"] = pass_id
    prev = store.items.get(finding["id"])
    if prev is None or prev.get("_pass") != pass_id:
        if prev is not None:
            finding["firstSeenAt"] = prev.get("firstSeenAt", finding["firstSeenAt"])
        store.put(location, finding)
        return
    prev["count"] += finding["count"]
    prev["occurrences"] += finding["occurrences"]
    for k, v in finding["confidenceCounts"].items():
        prev["confidenceCounts"][k] = prev["confidenceCounts"].get(k, 0) + v
    prev["confidenceCounts"] = dict(sorted(prev["confidenceCounts"].items()))
    prev["via"] = sorted(set(prev["via"]) | set(finding["via"]))
    if _CONF_RANK[finding["confidence"]] > _CONF_RANK[prev["confidence"]]:
        prev["confidence"] = finding["confidence"]
    offsets = prev["offsets"] + finding["offsets"]
    prev["offsetsTruncated"] = (
        prev["offsetsTruncated"]
        or finding["offsetsTruncated"]
        or len(offsets) > MAX_OFFSETS_PER_FINDING
    )
    prev["offsets"] = offsets[:MAX_OFFSETS_PER_FINDING]


def drop_other_passes(store: FindingStore, source_id: str, pass_id: str) -> int:
    """A pass is complete: findings it did not see again are gone."""
    gone = [
        k
        for k, v in store.items.items()
        if v.get("_location", "").startswith(f"{source_id}\n") and v.get("_pass") != pass_id
    ]
    for k in gone:
        del store.items[k]
    return len(gone)
