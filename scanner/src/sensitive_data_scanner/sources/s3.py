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
`max_object_bytes` is read up to that size and counted as partial. Audio,
video, images, office documents and archives are not read; they are counted
by kind.

Columnar and data-lake files (Parquet, ORC, Avro, by extension or by magic
bytes) are read by column (scan/columnar.py): Parquet and ORC through
ranged GETs, so a large file's footer and first row groups are read without
the rest, up to `max_rows` rows and `max_object_bytes` bytes. A finding
names the column. Text compressed with gzip or zstd (`.gz`, `.zst`) is
inflated first. Parquet, ORC, zstd, and Avro's snappy and zstandard codecs
need pyarrow (the container image); the Lambda zip counts them as skipped
`columnar`.

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
import gzip
import io
import zlib
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.avro import UnsupportedCodec
from sensitive_data_core.scan.columnar import (
    TableResult,
    columnar_kind,
    csv_rows,
    json_rows,
    needs_pyarrow,
    pyarrow_available,
    scan_rows,
    scan_table,
    sniff,
    zstd_text,
)
from sensitive_data_core.scan.item import classify_key, looks_binary, scan_item_text
from sensitive_data_core.scan.objects import RangeCut, is_rdb, sample_point
from sensitive_data_core.scan.objects import compression as _compression
from sensitive_data_core.scan.objects import gunzip as _gunzip
from sensitive_data_core.scan.objects import inner_name as _inner_name
from sensitive_data_core.scan.raw import printable_text

from ..resources import s3_link, s3_resource
from .encryption import KeyClassifier, s3_object_facts

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


class S3RangeFile(io.RawIOBase):
    """A seekable read-only view of one object version, read with ranged GETs.

    Parquet and ORC keep their footer at the end, so a reader seeks there
    first; only the parts it asks for are fetched, up to `max_bytes`.
    """

    def __init__(
        self,
        client: S3Client,
        bucket: str,
        key: str,
        *,
        size: int,
        max_bytes: int,
        version_id: str | None = None,
    ) -> None:
        super().__init__()
        self.client = client
        self.bucket = bucket
        self.key = key
        self.size = size
        self.max_bytes = max_bytes
        self.version_id = version_id
        self.pos = 0
        self.bytes_read = 0
        self.cut = False
        self.headers: dict[str, Any] | None = None  # the first GET's encryption headers

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self.pos = offset
        elif whence == io.SEEK_CUR:
            self.pos += offset
        else:
            self.pos = self.size + offset
        self.pos = max(0, self.pos)
        return self.pos

    def readinto(self, b: Any) -> int:
        n = len(b)
        if n == 0 or self.pos >= self.size:
            return 0
        end = min(self.size, self.pos + n) - 1
        want = end - self.pos + 1
        if self.bytes_read + want > self.max_bytes:
            self.cut = True
            raise RangeCut("byte cap")
        args: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": self.key,
            "Range": f"bytes={self.pos}-{end}",
        }
        if self.version_id and self.version_id != "null":
            args["VersionId"] = self.version_id
        r = self.client.get_object(**args)
        if self.version_id is None:
            self.version_id = r.get("VersionId") or "null"
        if self.headers is None:
            self.headers = {k: r.get(k) for k in _SSE_HEADERS}
        data = r["Body"].read()
        b[: len(data)] = data
        self.pos += len(data)
        self.bytes_read += len(data)
        return len(data)


# GetObject's encryption headers (the object's own, 1.5).
_SSE_HEADERS = ("ServerSideEncryption", "SSEKMSKeyId")


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

    def _skip(self, cov: Coverage, kind: str) -> None:
        cov.skipped[kind] = cov.skipped.get(kind, 0) + 1

    def _read(self, key: str, size: int, cov: Coverage) -> tuple[bytes, int, str | None, bool]:
        """The object's first `max_object_bytes`, its bytes read, version, and whether cut."""
        partial = size > self.max_object_bytes
        args: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
        if partial:
            args["Range"] = f"bytes=0-{self.max_object_bytes - 1}"
        r = self.client.get_object(**args)
        self._headers(dict(r))
        data = r["Body"].read()
        return data, len(data), r.get("VersionId"), partial

    def _headers(self, response: dict[str, Any] | None) -> None:
        """The object's own encryption, from the headers of the GET that read it."""
        if self.keys is not None and response is not None:
            self._object_facts = s3_object_facts(self.keys, response)

    def _facts(self) -> dict[str, Any] | None:
        return self._object_facts if self._object_facts is not None else self.facts

    def _text(self, key: str, data: bytes, cov: Coverage) -> str | None:
        compression = _compression(key)
        if compression == "gzip":
            try:
                data = _gunzip(data, self.max_inflated_bytes)
            except (zlib.error, OSError, EOFError, gzip.BadGzipFile):
                self._skip(cov, "archive")
                return None
        elif compression == "zstd":
            if not self.columnar:
                self._skip(cov, "columnar")
                return None
            try:
                data = zstd_text(data, self.max_inflated_bytes)
            except Exception:  # a bad frame: not text we can read
                self._skip(cov, "archive")
                return None
        if looks_binary(data):
            self._skip(cov, "binary")
            return None
        return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace").read()

    def _table(
        self,
        kind: str,
        key: str,
        *,
        size: int,
        cov: Coverage,
        detector: Detector,
        head: bytes | None,
    ) -> tuple[TableResult, int, str | None] | None:
        """Read one columnar object by column. None when this build cannot read it."""
        if needs_pyarrow(kind) and not self.columnar:
            self._skip(cov, "columnar")
            return None
        if head is not None and len(head) >= size:
            f: Any = io.BytesIO(head)
            raw = None
        else:
            raw = S3RangeFile(
                self.client, self.bucket, key, size=size, max_bytes=self.max_object_bytes
            )
            f = io.BufferedReader(raw, buffer_size=256 * 1024)
        try:
            result = scan_table(kind, f, detector, self.max_rows, self.columnar)
        except UnsupportedCodec:
            self._skip(cov, "columnar")
            return None
        except Exception:
            if raw is not None and raw.cut:
                cov.partial += 1
                self._skip(cov, "columnar")  # the cap fell before a single batch
                return None
            raise
        if raw is not None:
            self._headers(raw.headers)
        if raw is not None and raw.cut:
            result.partial = True
        if result.partial:
            cov.partial += 1
        read = raw.bytes_read if raw is not None else len(head or b"")
        version = raw.version_id if raw is not None else None
        return result, read, version

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
        try:
            while not done and budget.time_left():
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
                    key = obj["Key"]
                    cov.listed += 1
                    modified = obj.get("LastModified")
                    if since is not None and modified is not None and modified <= since:
                        start_after = key
                        continue
                    if key.endswith("/") or obj.get("Size", 0) == 0:
                        start_after = key
                        continue
                    if self.exclude_prefixes and key.startswith(self.exclude_prefixes):
                        start_after = key  # a catalog table's own source reads it
                        continue
                    cov.eligible += 1
                    if sample_point(key) >= self.sample_percent:
                        cov.sampled_out += 1
                        start_after = key
                        continue
                    read_it, _, kind = classify_key(_inner_name(key))
                    if columnar_kind(key) is not None:
                        read_it = True
                    if not read_it:
                        cov.skipped[kind or "binary"] = cov.skipped.get(kind or "binary", 0) + 1
                        start_after = key
                        continue
                    directory = key.rsplit("/", 1)[0] if "/" in key else ""
                    if self.max_per_prefix:
                        if directory != cur_dir:
                            cur_dir, cur_n = directory, 0
                        if cur_n >= self.max_per_prefix:
                            cov.sampled_out += 1
                            start_after = key
                            continue
                    size = min(obj.get("Size", 0), self.max_object_bytes)
                    if not budget.has(size):
                        cov.backlog = True
                        stop = True
                        break
                    budget.take(size)
                    cur_n += 1
                    try:
                        self._scan_object(
                            key,
                            size=obj.get("Size", 0),
                            cov=cov,
                            detector=detector,
                            store=store,
                            seen_at=seen_at,
                        )
                    except Exception as err:  # one bad object must not stop the pass
                        cov.unreadable += 1
                        if is_kms_denial(err):
                            cov.kms_denied += 1
                        name = error_name(err)
                        first_read_error = first_read_error or name
                        log_event("item.unreadable", source=self.target, error=name)
                    start_after = key
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
        if done and cov.error is None:
            cov.pass_complete = True
            new_cursor: dict[str, Any] = {
                "watermark": pass_started,
                "passStartedAt": None,
                "startAfter": None,
            }
            cur_dir, cur_n = None, 0
        else:
            if cov.error is None:
                cov.backlog = True
            new_cursor = {
                "watermark": watermark,
                "passStartedAt": pass_started,
                "startAfter": None if self.express else start_after,
            }
            if self.express:
                new_cursor.update(token=token, skip=skip)
        if self.max_per_prefix:
            new_cursor["prefixDir"] = cur_dir
            new_cursor["prefixCount"] = cur_n
        if cov.error is None and cov.scanned == 0 and cov.unreadable > 0:
            cov.error = first_read_error
        return SourceRun(cov, new_cursor)

    def _scan_object(
        self,
        key: str,
        *,
        size: int,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
    ) -> None:
        kind = columnar_kind(key)
        head: bytes | None = None
        version: str | None = None
        self._object_facts = None
        if kind is None:
            head, read, version, partial = self._read(key, size, cov)
            kind = sniff(head) if _compression(key) is None else None
            if kind is None and is_rdb(key, head):
                # A Redis snapshot (an ElastiCache or MemoryDB export): its text runs.
                cov.partial += int(partial)
                self._record_text(
                    key,
                    printable_text(head),
                    read=read,
                    version=version,
                    cov=cov,
                    detector=detector,
                    store=store,
                    seen_at=seen_at,
                    fmt="rdb",
                )
                return
            if kind is None:
                if partial:
                    cov.partial += 1
                text = self._text(key, head, cov)
                if text is None:
                    return
                self._record_text(
                    key,
                    text,
                    read=read,
                    version=version,
                    cov=cov,
                    detector=detector,
                    store=store,
                    seen_at=seen_at,
                )
                return
        got = self._table(kind, key, size=size, cov=cov, detector=detector, head=head)
        if got is None:
            return
        table, read, range_version = got
        self._record_table(
            key,
            table,
            read=read,
            version=version or range_version,
            cov=cov,
            store=store,
            seen_at=seen_at,
        )

    def _record_text(
        self,
        key: str,
        text: str,
        *,
        read: int,
        version: str | None,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        fmt: str | None = None,
    ) -> None:
        name = _inner_name(key)
        if self.serde == "csv" and self.columns:
            rows = csv_rows(text, self.columns, self.delimiter, self.skip_header)
            table = scan_rows("csv", self.columns, rows, detector, self.max_rows)
            self._record_table(
                key, table, read=read, version=version, cov=cov, store=store, seen_at=seen_at
            )
            return
        if self.serde == "json":
            columns, records = json_rows(text)
            table = scan_rows("json", columns, records, detector, self.max_rows)
            self._record_table(
                key, table, read=read, version=version, cov=cov, store=store, seen_at=seen_at
            )
            return
        item = scan_item_text(name, text, detector)
        if fmt is not None:
            # Text pulled out of a binary file: offsets into it would point nowhere.
            item.format = fmt
            for cf in item.findings.values():
                cf.offsets = []
        cov.scanned += 1
        cov.bytes_scanned += read
        cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
        cov.redaction_markers += item.redaction_markers
        cov.test_values += item.test_values
        cov.suppressed += item.suppressed
        resource = s3_resource(self.bucket, key, version, catalog=self.catalog)
        link = s3_link(self.region, self.bucket, key, version, directory=self.express)
        connect = (
            {"contactId": item.contact_id, "instanceId": item.instance_id or ""}
            if item.contact_id
            else None
        )
        findings = [
            finding_json(
                resource, link, item.format, cf, seen_at, connect=connect, facts=self._facts()
            )
            for cf in item.findings.values()
            if cf.count or cf.occurrences
        ]
        store.replace_location(f"{self.id}\n{key}", findings)

    def _record_table(
        self,
        key: str,
        table: TableResult,
        *,
        read: int,
        version: str | None,
        cov: Coverage,
        store: FindingStore,
        seen_at: str,
    ) -> None:
        cov.scanned += 1
        cov.bytes_scanned += read
        cov.formats[table.format] = cov.formats.get(table.format, 0) + 1
        cov.redaction_markers += table.redaction_markers
        cov.test_values += table.test_values
        cov.suppressed += table.suppressed
        link = s3_link(self.region, self.bucket, key, version, directory=self.express)
        findings: list[dict[str, Any]] = []
        for column, item in sorted(table.by_column.items()):
            resource = s3_resource(self.bucket, key, version, column=column, catalog=self.catalog)
            findings.extend(
                finding_json(resource, link, table.format, cf, seen_at, facts=self._facts())
                for cf in item.findings.values()
                if cf.count or cf.occurrences
            )
        store.replace_location(f"{self.id}\n{key}", findings)

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
