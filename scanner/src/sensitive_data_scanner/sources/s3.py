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
coverage says how many were left out. With `max_per_prefix`, at most that
many objects are read per "directory" (the key up to its last `/`) in a
pass, and the rest are counted as sampled out: a data lake's thousand
partition files are represented by the first few of each. An object larger than
`max_object_bytes` is read up to that size and counted as partial.

Every object is read by the core's reader
(`sensitive_data_core.scan.objects.read_object`), the same one the Azure,
Google Cloud and SaaS scanners use, through ranged GETs of one object
version, up to `max_object_bytes` fetched and `max_inflated_bytes` inflated.
**What an object is comes from its first bytes, not its key** (#65): a
Word file named `.jpg` is read as Word and its findings say `disguised`.
Audio, video and images are counted by kind after one small ranged GET;
Word, Excel and PowerPoint as their text (a rights-managed one is
`encrypted`, an older binary one `document`); PDFs as their text layer
(`pdf_image_only` without one, `encrypted` behind a password); zip, tar,
gzip, bzip2 and xz archives entry by entry, in memory, nested up to three
levels, each entry routed like an object and named in its findings
(`archivePath`); 7z is `archive_unsupported`.

Columnar and data-lake files (Parquet, ORC, Avro, by magic bytes) are read by
column (scan/columnar.py): Parquet and ORC through ranged GETs, so a large
file's footer and first row groups are read without the rest, up to
`max_rows` rows and `max_object_bytes` bytes. A finding names the column.
Parquet, ORC, zstd, and Avro's snappy and zstandard codecs need pyarrow (the
container image); the Lambda zip counts them as skipped `columnar`.

A **catalog table** (a Glue table, `catalog` set) is this source over the
table's S3 location: its findings also name the database and table, and a
CSV or JSON table is read by the catalog's columns.

**Directory buckets** (S3 Express One Zone, `express`): the same reads through
a read-only S3 Express session. A directory bucket lists in no key order and
takes no `StartAfter`, so a pass resumes at its page's continuation token and
the objects of that page already read.

**Encryption (1.5).** With a key classifier (`keys`), each object's findings
carry the encryption it is stored under, from the `x-amz-server-side-encryption`
header of the GetObject that read it (`encryption.s3_object_facts`): the
object's own, which the bucket's default may postdate.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import UNINDEXED, Indexes, ObjectPass, Stale
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import (
    pyarrow_available,
)
from sensitive_data_core.scan.objects import (
    planned_bytes,
    sample_point,
)

from ..resources import s3_link, s3_resource
from . import inventory
from . import s3_read as _read_path
from .encryption import KeyClassifier, s3_object_facts
from .s3_read import object_fingerprint, object_marker

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


@dataclass
class _Walk:
    """One run's pass state, shared by a listing and an inventory report's rows."""

    cov: Coverage
    op: ObjectPass
    budget: Budget
    detector: Detector
    store: FindingStore
    seen_at: str
    since: _dt.datetime | None
    cur_dir: str | None
    cur_n: int
    first_error: str | None = None
    file: int = 0
    row: int = 0


class S3Source:
    kind = "s3"
    # #67: read a large bucket's objects from its S3 Inventory report (the runner sets these).
    use_inventory: bool = True
    inventory_min_objects: int = 1_000_000
    _recommend: bool = False
    _idle: bool = False
    # The run's object indexes (#67), set by the runner; None records nothing.
    # A change to how this kind is listed (`listing:<kind>`) drops these cursor keys: the next
    # pass lists the store again from the start and reads only what changed (#67).
    relist_keys: tuple[str, ...] = (
        "passStartedAt",
        "startAfter",
        "token",
        "skip",
        "passListed",
        "report",
        "prefixDir",
        "prefixCount",
    )
    indexes: Indexes | None = None

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
        max_per_prefix: int = 0,
        max_rows: int = 10_000,
        exclude_prefixes: tuple[str, ...] = (),
        catalog: tuple[str, str] | None = None,
        columns: tuple[str, ...] = (),
        serde: str | None = None,
        delimiter: str = ",",
        skip_header: int = 0,
        columnar: bool | None = None,
        keys: KeyClassifier | None = None,
        express: bool = False,
    ) -> None:
        self.client = client
        self.express = express
        self.keys = keys
        # Set per object from its headers when `keys` is given; else the store's (runner.plan).
        self.facts: dict[str, Any] | None = None
        self._object_facts: dict[str, Any] | None = None
        self.bucket = bucket
        self.prefix = prefix
        self.region = region
        self.sample_percent = sample_percent
        self.max_object_bytes = max_object_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.skew = _dt.timedelta(seconds=skew_seconds)
        self.max_per_prefix = max_per_prefix
        self.max_rows = max_rows
        self.exclude_prefixes = exclude_prefixes
        self.catalog = catalog
        self.columns = list(columns)
        self.serde = serde
        self.delimiter = delimiter
        self.skip_header = skip_header
        self.columnar = pyarrow_available() if columnar is None else columnar
        if catalog is not None:
            self.kind = "glue_table"
            self.id = f"glue:{catalog[0]}.{catalog[1]}"
            self.target = f"{catalog[0]}.{catalog[1]}"
        elif express:
            self.kind = "s3_directory"
            self.id = f"s3x:{bucket}/{prefix}"
            self.target = f"{bucket}/{prefix}"
        else:
            self.id = f"s3:{bucket}/{prefix}"
            self.target = f"{bucket}/{prefix}"

    # The read path (`s3_read.py`, the `adapter:<kind>` component, #67).
    _skip = _read_path._skip
    _read = _read_path._read
    _headers = _read_path._headers
    _facts = _read_path._facts
    _text = _read_path._text
    _read_one = _read_path._read_one
    _scan_object = _read_path._scan_object
    _catalog_text = _read_path._catalog_text
    _record_text = _read_path._record_text
    _record_item = _read_path._record_item
    _record_table = _read_path._record_table

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        watermark = cursor.get("watermark")
        pass_started = cursor.get("passStartedAt") or now.isoformat()
        start_after = cursor.get("startAfter")
        # A directory bucket resumes by its page's token and how much of that page was read.
        token: str | None = cursor.get("token")
        skip = int(cursor.get("skip") or 0)
        since = (_dt.datetime.fromisoformat(watermark) - self.skew) if watermark else None
        seen_at = now.isoformat()
        done = False
        first_read_error: str | None = None
        cur_dir: str | None = cursor.get("prefixDir")
        cur_n = int(cursor.get("prefixCount") or 0)
        # Each listing pass is a generation of the index: a complete pass drops the rows of
        # objects it did not list (gone from the bucket).
        generation = int(cursor.get("indexPass") or 0) + (0 if cursor.get("passStartedAt") else 1)
        op = ObjectPass(
            self.indexes,
            self.id,
            self.kind,
            generation=generation,
            columnar=self.columnar,
            budget=budget,
        )
        w = _Walk(cov, op, budget, detector, store, seen_at, since, cur_dir, cur_n)
        report = self._report(cursor, now)
        if self._idle:
            # The latest report was read in full: nothing is listed until the next one.
            cov.pass_complete = True
            op.settle(cov)
            return SourceRun(cov, dict(cursor), extra={"listedBy": "inventory"})
        try:
            if report is not None:
                # A large bucket's objects from its inventory report (#67), not a listing.
                done = self._walk_report(report, cursor, w)
            while report is None and not done and budget.time_left():
                args: dict[str, Any] = {"Bucket": self.bucket, "MaxKeys": 1000}
                if self.prefix:
                    args["Prefix"] = self.prefix
                if self.express:
                    if token:
                        args["ContinuationToken"] = token
                elif start_after:
                    args["StartAfter"] = start_after
                page = self.client.list_objects_v2(**args)
                stop = False
                contents = list(page.get("Contents", []))
                done_before, skip = (skip, 0) if self.express else (0, 0)
                start_after = None if self.express else start_after
                for obj in contents[done_before:]:
                    if not self._consider(obj, w):
                        cov.backlog = True
                        stop = True
                        break
                    start_after = obj["Key"]
                if stop:
                    if self.express:
                        keys = [o["Key"] for o in contents]
                        skip = keys.index(start_after) + 1 if start_after in keys else done_before
                    break
                if self.express:
                    token = page.get("NextContinuationToken")
                if not page.get("IsTruncated"):
                    done = True
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
        cur_dir, cur_n = w.cur_dir, w.cur_n
        first_read_error = w.first_error
        if cov.error is None:
            # Then the rescans this run met, within their capped share (#67).
            for obj, why in op.rescans.drain(
                budget, lambda o: planned_bytes(o["Key"], o.get("Size", 0), self.max_object_bytes)
            ):
                if self._duplicate(obj, cov, store, seen_at, op, why):
                    continue
                error = self._read_one(obj, cov, detector, store, seen_at, op, why)
                first_read_error = first_read_error or error
        listed = int(cursor.get("passListed") or 0) + cov.listed
        extra: dict[str, Any] = {}
        if done and cov.error is None:
            cov.pass_complete = True
            op.complete()
            new_cursor: dict[str, Any] = {
                # A report's pass starts at the report's own time: later objects are in the
                # next report.
                "watermark": report.created.isoformat() if report is not None else pass_started,
                "passStartedAt": None,
                "startAfter": None,
                "objects": listed,
            }
            cur_dir, cur_n = None, 0
        else:
            if cov.error is None:
                cov.backlog = True
            new_cursor = {
                "watermark": watermark,
                "passStartedAt": pass_started,
                "startAfter": None if self.express else start_after,
                "passListed": listed,
            }
            if cursor.get("objects"):
                new_cursor["objects"] = cursor["objects"]
            if self.express:
                new_cursor.update(token=token, skip=skip)
            if report is not None:
                new_cursor["report"] = {**report.cursor(), "file": w.file, "row": w.row}
        if report is not None:
            extra["listedBy"] = "inventory"
        if self._recommend or cursor.get("recommend"):
            extra["recommendation"] = "s3_inventory"
            new_cursor["recommend"] = True
        if self.max_per_prefix:
            new_cursor["prefixDir"] = cur_dir
            new_cursor["prefixCount"] = cur_n
        new_cursor["indexPass"] = generation
        op.settle(cov)
        if cov.error is None and cov.scanned == 0 and cov.unreadable > 0:
            cov.error = first_read_error
        return SourceRun(cov, new_cursor, extra=extra)

    def _report(self, cursor: dict[str, Any], now: _dt.datetime) -> inventory.Report | None:
        """The inventory report this pass reads, when the bucket is large enough and has one
        (#67): the one a pass in progress started with, or the latest for a new pass. When
        the latest was already read, the run is idle (`_idle`): no listing, no report."""
        self._recommend = False
        self._idle = False
        if isinstance(cursor.get("report"), dict):
            try:
                return inventory.Report.of(cursor["report"])
            except (KeyError, ValueError):
                return None
        big = int(cursor.get("objects") or 0) >= self.inventory_min_objects > 0
        plain = not (self.express or self.catalog or self.max_per_prefix)
        if cursor.get("passStartedAt") or not (big and plain and self.use_inventory):
            return None
        found = inventory.find(self.client, self.bucket, self.prefix, now, columnar=self.columnar)
        if found.report is None:
            # A bucket this large with no inventory to read: named, never configured here.
            self._recommend = found.reason == "none"
            return None
        watermark = cursor.get("watermark")
        if watermark and found.report.created <= _dt.datetime.fromisoformat(watermark):
            self._idle = True  # already read in full: the next report brings what changed
            return None
        return found.report

    def _walk_report(self, report: inventory.Report, cursor: dict[str, Any], w: _Walk) -> bool:
        """One pass over a report's rows from where the last run stopped; True when done."""
        at: dict[str, Any] = cursor["report"] if isinstance(cursor.get("report"), dict) else {}
        w.file, w.row = int(at.get("file") or 0), int(at.get("row") or 0)
        for i, n, obj in inventory.rows(self.client, report, start_file=w.file, start_row=w.row):
            w.file, w.row = i, n
            if not w.budget.time_left():
                return False
            if self.prefix and not obj["Key"].startswith(self.prefix):
                continue
            if not self._consider(obj, w):
                return False
            w.row = n + 1
        return True

    def _consider(self, obj: Mapping[str, Any], w: _Walk) -> bool:
        """One listed object: read now (a change), queued (a rescan), or passed over. False
        when the budget has no room for it (the pass stops before it)."""
        cov, op = w.cov, w.op
        key = obj["Key"]
        cov.listed += 1
        op.seen(key)
        if key.endswith("/") or obj.get("Size", 0) == 0:
            return True
        if self.exclude_prefixes and key.startswith(self.exclude_prefixes):
            return True  # a catalog table's own source reads it
        modified = obj.get("LastModified")
        changed = w.since is None or modified is None or modified > w.since
        decision = op.decide(key, changed=changed, marker=object_marker(obj))
        if not (decision.read or decision.rescan):
            return True  # unchanged, and read with what it would be now
        cov.eligible += int(decision.read)
        if sample_point(key) >= self.sample_percent:
            cov.sampled_out += int(decision.read)
            return True
        directory = key.rsplit("/", 1)[0] if "/" in key else ""
        # A rescan of an object read before was in its directory's sample; one the index
        # never saw takes its place in the sample like a new object.
        counted = decision.read or (decision.why is not None and decision.why.reason == UNINDEXED)
        if self.max_per_prefix and counted:
            if directory != w.cur_dir:
                w.cur_dir, w.cur_n = directory, 0
            if w.cur_n >= self.max_per_prefix:
                cov.sampled_out += int(decision.read)
                return True
        if decision.rescan:
            op.offer(obj, decision)  # read after this run's changes, if it fits
            w.cur_n += int(counted)
            return True
        if self._duplicate(obj, cov, w.store, w.seen_at, op):
            w.cur_n += 1  # in its directory's sample, as a read would be
            return True  # the same bytes as an object read with what it would be read with now
        size = planned_bytes(key, obj.get("Size", 0), self.max_object_bytes)
        if not w.budget.has(size):
            return False
        w.budget.take(size)
        w.cur_n += 1
        error = self._read_one(obj, cov, w.detector, w.store, w.seen_at, op)
        w.first_error = w.first_error or error
        return True

    def _duplicate(  # noqa: PLR0917 - one object of the pass
        self,
        obj: Mapping[str, Any],
        cov: Coverage,
        store: FindingStore,
        seen_at: str,
        op: ObjectPass,
        why: Stale | None = None,
    ) -> bool:
        """An object whose single-part ETag is an indexed object's, read with components that
        are still current, is not read (#67 part 5): its findings are the original's, as its
        own, each naming the original's (`duplicateOf`). Its version and its own encryption
        come from one HeadObject (no bytes). False when it is no duplicate, or the head fails
        (it is then read)."""
        key = obj["Key"]
        fingerprint = object_fingerprint(obj)
        original = op.duplicate(key, fingerprint)
        if original is None:
            return False
        try:
            head = dict(self.client.head_object(Bucket=self.bucket, Key=key))
        except Exception:  # read it instead
            return False
        version = str(head.get("VersionId") or "null")
        facts = s3_object_facts(self.keys, head) if self.keys is not None else self.facts
        findings = op.copy_findings(
            original,
            store,
            f"{self.id}\n",
            resource_for=lambda column: s3_resource(
                self.bucket, key, version, column=column, catalog=self.catalog
            ),
            link=s3_link(self.region, self.bucket, key, version, directory=self.express),
            seen_at=seen_at,
            facts=facts,
        )
        op.rescanned(findings, why)
        store.replace_location(f"{self.id}\n{key}", findings)
        op.record_duplicate(key, original, marker=object_marker(obj), fingerprint=fingerprint)
        return True

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
