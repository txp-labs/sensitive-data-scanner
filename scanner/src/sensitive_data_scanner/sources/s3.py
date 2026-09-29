"""S3 source: one bucket, or one prefix of it.

Incremental: a pass lists the prefix in key order and reads only objects
modified since the previous COMPLETE pass started (less five minutes, for
clock skew). A pass that runs out of budget resumes after its last key on the
next run, so a large prefix is covered over several runs and nothing is read
twice in a pass.

Each object read is one version: the scanner records the VersionId that
GetObject returned, and a finding names that version.

Sampling: with `sample_percent` below 100, an object is read only if a hash
of its key falls in the sample (the same objects every pass), and the
coverage says how many were left out. An object larger than
`max_object_bytes` is read up to that size and counted as partial. Audio,
video, images, office documents and archives are not read; they are counted
by kind.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import zlib
from typing import TYPE_CHECKING, Any

from ..detect.analyzer import Detector
from ..findings import Coverage, finding_json, s3_link, s3_resource
from ..safety import error_name, log_event
from ..scan.item import classify_key, looks_binary, scan_item_text
from .base import Budget, FindingStore, SourceRun

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


def sample_point(key: str) -> int:
    """FNV-1a over the key's UTF-16 code units: a stable 0-99 bucket for sampling."""
    h = 0x811C9DC5
    data = key.encode("utf-16-le")
    for i in range(0, len(data), 2):
        h ^= data[i] | (data[i + 1] << 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h % 100


def _gunzip(data: bytes, limit: int) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, limit)
    if d.unconsumed_tail:
        return out  # cut at the limit: read in part
    return out


class S3Source:
    kind = "s3"

    def __init__(
        self,
        client: S3Client,
        *,
        bucket: str,
        prefix: str,
        region: str,
        sample_percent: int = 100,
        max_object_bytes: int = 20 * 1024**2,
        max_inflated_bytes: int = 100 * 1024**2,
        skew_seconds: int = 300,
    ) -> None:
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.region = region
        self.sample_percent = sample_percent
        self.max_object_bytes = max_object_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.skew = _dt.timedelta(seconds=skew_seconds)
        self.id = f"s3:{bucket}/{prefix}"
        self.target = f"{bucket}/{prefix}"

    def _read(self, key: str, size: int, cov: Coverage) -> tuple[str, int, str | None] | None:
        partial = size > self.max_object_bytes
        args: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
        if partial:
            args["Range"] = f"bytes=0-{self.max_object_bytes - 1}"
        r = self.client.get_object(**args)
        data = r["Body"].read()
        version = r.get("VersionId")
        if partial:
            cov.partial += 1
        read = len(data)
        _, gz, _ = classify_key(key)
        if gz:
            try:
                data = _gunzip(data, self.max_inflated_bytes)
            except (zlib.error, OSError, EOFError, gzip.BadGzipFile):
                cov.skipped["archive"] = cov.skipped.get("archive", 0) + 1
                return None
        if looks_binary(data):
            cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
            return None
        return (
            io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace").read(),
            read,
            version,
        )

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("s3", self.target, sample_percent=self.sample_percent)
        watermark = cursor.get("watermark")
        pass_started = cursor.get("passStartedAt") or now.isoformat()
        start_after = cursor.get("startAfter")
        since = (_dt.datetime.fromisoformat(watermark) - self.skew) if watermark else None
        seen_at = now.isoformat()
        done = False
        first_read_error: str | None = None
        try:
            while not done and budget.time_left():
                args: dict[str, Any] = {"Bucket": self.bucket, "MaxKeys": 1000}
                if self.prefix:
                    args["Prefix"] = self.prefix
                if start_after:
                    args["StartAfter"] = start_after
                page = self.client.list_objects_v2(**args)
                stop = False
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    cov.listed += 1
                    modified = obj.get("LastModified")
                    if since is not None and modified is not None and modified <= since:
                        start_after = key
                        continue
                    if key.endswith("/") or obj.get("Size", 0) == 0:
                        start_after = key
                        continue
                    cov.eligible += 1
                    if sample_point(key) >= self.sample_percent:
                        cov.sampled_out += 1
                        start_after = key
                        continue
                    read_it, _, kind = classify_key(key)
                    if not read_it:
                        cov.skipped[kind or "binary"] = cov.skipped.get(kind or "binary", 0) + 1
                        start_after = key
                        continue
                    size = min(obj.get("Size", 0), self.max_object_bytes)
                    if not budget.has(size):
                        cov.backlog = True
                        stop = True
                        break
                    budget.take(size)
                    try:
                        got = self._read(key, obj.get("Size", 0), cov)
                        if got is not None:
                            text, read, version = got
                            item = scan_item_text(key, text, detector)
                            cov.scanned += 1
                            cov.bytes_scanned += read
                            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                            cov.redaction_markers += item.redaction_markers
                            cov.test_values += item.test_values
                            cov.suppressed += item.suppressed
                            resource = s3_resource(self.bucket, key, version)
                            link = s3_link(self.region, self.bucket, key, version)
                            connect = (
                                {"contactId": item.contact_id, "instanceId": item.instance_id or ""}
                                if item.contact_id
                                else None
                            )
                            findings = [
                                finding_json(
                                    resource, link, item.format, cf, seen_at, connect=connect
                                )
                                for cf in item.findings.values()
                                if cf.count or cf.occurrences
                            ]
                            store.replace_location(f"{self.id}\n{key}", findings)
                    except Exception as err:  # one bad object must not stop the pass
                        cov.unreadable += 1
                        name = error_name(err)
                        first_read_error = first_read_error or name
                        log_event("item.unreadable", source=self.target, error=name)
                    start_after = key
                if stop:
                    break
                if not page.get("IsTruncated"):
                    done = True
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
        if done and cov.error is None:
            cov.pass_complete = True
            new_cursor: dict[str, Any] = {
                "watermark": pass_started,
                "passStartedAt": None,
                "startAfter": None,
            }
        else:
            if cov.error is None:
                cov.backlog = True
            new_cursor = {
                "watermark": watermark,
                "passStartedAt": pass_started,
                "startAfter": start_after,
            }
        if cov.error is None and cov.scanned == 0 and cov.unreadable > 0:
            cov.error = first_read_error
        return SourceRun(cov, new_cursor)

    def prune(self, store: FindingStore, budget: Budget, limit: int = 200) -> int:
        """Drop stored findings whose object is gone."""
        gone = 0
        for location in store.locations(f"{self.id}\n")[:limit]:
            if not budget.time_left():
                break
            key = location.split("\n", 1)[1]
            try:
                self.client.head_object(Bucket=self.bucket, Key=key)
            except Exception as err:  # unknown: keep the finding
                if error_name(err) in ("404", "NoSuchKey", "NotFound"):
                    gone += store.remove_location(location)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return gone
