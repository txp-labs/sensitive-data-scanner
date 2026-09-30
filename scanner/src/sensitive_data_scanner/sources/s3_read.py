"""S3's read path: one object version fetched by ranged GETs and read by the core's reader.

This module is `adapter:s3`, `adapter:glue_table`, `adapter:s3_directory`
(scripts/components.py): a change here rescans the objects it read. Listing, discovery and
configuration stay in `s3.py` (`listing:<kind>`), whose changes re-list and never re-read
(#67).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import zlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.index import ObjectPass, Stale
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import (
    TableResult,
    csv_rows,
    json_rows,
    scan_rows,
    zstd_text,
)
from sensitive_data_core.scan.item import ItemResult, looks_binary, scan_item_text
from sensitive_data_core.scan.objects import (
    RangeCut,
    read_object,
    record,
)
from sensitive_data_core.scan.objects import compression as _compression
from sensitive_data_core.scan.objects import gunzip as _gunzip
from sensitive_data_core.scan.objects import inner_name as _inner_name

from ..resources import s3_link, s3_resource
from .encryption import s3_object_facts

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

    from .s3 import S3Source as _Self

READS = ("s3", "glue_table", "s3_directory")


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


_MD5 = frozenset("0123456789abcdef")


def object_marker(obj: Mapping[str, Any]) -> str:
    """What changes when a listed object changes: its ETag, size and last-modified time."""
    modified = obj.get("LastModified")
    when = modified.isoformat() if isinstance(modified, _dt.datetime) else str(modified or "")
    return f"{obj.get('ETag') or ''}|{obj.get('Size') or 0}|{when}"


def object_fingerprint(obj: Mapping[str, Any]) -> str | None:
    """A single-part object's ETag is the MD5 of its bytes (#67): the same bytes under
    another key have the same one. A multipart ETag (`...-3`) says nothing of the bytes."""
    etag = str(obj.get("ETag") or "").strip('"').lower()
    if len(etag) == 32 and set(etag) <= _MD5:
        return f"md5:{etag}"
    return None


def _skip(src: _Self, cov: Coverage, kind: str) -> None:
    cov.skipped[kind] = cov.skipped.get(kind, 0) + 1


def _read(src: _Self, key: str, size: int, cov: Coverage) -> tuple[bytes, int, str | None, bool]:
    """The object's first `max_object_bytes`, its bytes read, version, and whether cut."""
    partial = size > src.max_object_bytes
    args: dict[str, Any] = {"Bucket": src.bucket, "Key": key}
    if partial:
        args["Range"] = f"bytes=0-{src.max_object_bytes - 1}"
    r = src.client.get_object(**args)
    src._headers(dict(r))
    data = r["Body"].read()
    return data, len(data), r.get("VersionId"), partial


def _headers(src: _Self, response: dict[str, Any] | None) -> None:
    """The object's own encryption, from the headers of the GET that read it."""
    if src.keys is not None and response is not None:
        src._object_facts = s3_object_facts(src.keys, response)


def _facts(src: _Self) -> dict[str, Any] | None:
    return src._object_facts if src._object_facts is not None else src.facts


def _text(src: _Self, key: str, data: bytes, cov: Coverage) -> str | None:
    compression = _compression(key)
    if compression == "gzip":
        try:
            data = _gunzip(data, src.max_inflated_bytes)
        except (zlib.error, OSError, EOFError, gzip.BadGzipFile):
            src._skip(cov, "archive")
            return None
    elif compression == "zstd":
        if not src.columnar:
            src._skip(cov, "columnar")
            return None
        try:
            data = zstd_text(data, src.max_inflated_bytes)
        except Exception:  # a bad frame: not text we can read
            src._skip(cov, "archive")
            return None
    if looks_binary(data):
        src._skip(cov, "binary")
        return None
    return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace").read()


def _read_one(  # noqa: PLR0917 - one object of the pass
    src: _Self,
    obj: Mapping[str, Any],
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    op: ObjectPass,
    why: Stale | None = None,
) -> str | None:
    """One listed object read (a change, or a rescan for `why`); the error's name when it
    could not be."""
    key = obj["Key"]
    try:
        src._scan_object(
            key,
            size=obj.get("Size", 0),
            cov=cov,
            detector=detector,
            store=store,
            seen_at=seen_at,
            op=op,
            listed=obj,
            why=why,
        )
    except Exception as err:  # one bad object must not stop the pass
        op.record(key, marker=object_marker(obj), unreadable=True)
        cov.unreadable += 1
        if is_kms_denial(err):
            cov.kms_denied += 1
        name = error_name(err)
        log_event("item.unreadable", source=src.target, error=name)
        return name
    return None


def _scan_object(
    src: _Self,
    key: str,
    *,
    size: int,
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    op: ObjectPass | None = None,
    listed: Mapping[str, Any] | None = None,
    why: Stale | None = None,
) -> None:
    """One object, read by the core's reader (`read_object`) through ranged GETs of one
    version: the first GET's version is pinned for the rest, and its encryption headers
    are the object's. A catalog table's CSV or JSON files are read by its columns. The
    read is recorded in the object index (`op`) with the listing's marker."""
    src._object_facts = None
    obj: Mapping[str, Any] = listed or {"Key": key, "Size": size}
    if src.serde == "json" or (src.serde == "csv" and src.columns):
        src._catalog_text(key, size=size, cov=cov, detector=detector, store=store,
                           seen_at=seen_at)  # fmt: skip
        if op is not None:
            op.record(key, marker=object_marker(obj), readers=("columnar",), text=True)
            location = f"{src.id}\n{key}"
            op.rescanned([f for f in store.items.values() if f["_location"] == location], why)
        return
    version: str | None = None
    headers: dict[str, Any] | None = None

    def fetch(start: int, end: int) -> bytes:
        nonlocal version, headers
        args: dict[str, Any] = {
            "Bucket": src.bucket,
            "Key": key,
            "Range": f"bytes={start}-{end}",
        }
        if version and version != "null":
            args["VersionId"] = version
        r = src.client.get_object(**args)
        if version is None:
            version = r.get("VersionId") or "null"
        if headers is None:
            headers = {k: r.get(k) for k in _SSE_HEADERS}
        data: bytes = r["Body"].read()
        return data

    got = read_object(
        key,
        size,
        fetch,
        detector,
        max_object_bytes=src.max_object_bytes,
        max_inflated_bytes=src.max_inflated_bytes,
        max_rows=src.max_rows,
        columnar=src.columnar,
    )
    src._headers(headers)
    if op is not None:
        op.record(key, marker=object_marker(obj), fingerprint=object_fingerprint(obj), got=got)
    findings = record(
        got,
        cov,
        resource_for=lambda column: s3_resource(
            src.bucket, key, version, column=column, catalog=src.catalog
        ),
        link=s3_link(src.region, src.bucket, key, version, directory=src.express),
        seen_at=seen_at,
        facts=src._facts(),
        connect=True,
    )
    if op is not None:
        op.rescanned(findings, why)
    if findings is None:
        return
    store.replace_location(f"{src.id}\n{key}", findings)


def _catalog_text(
    src: _Self,
    key: str,
    *,
    size: int,
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
) -> None:
    """A CSV or JSON file of a catalog table, read by the table's columns."""
    head, read, version, partial = src._read(key, size, cov)
    if partial:
        cov.partial += 1
    text = src._text(key, head, cov)
    if text is None:
        return
    src._record_text(
        key,
        text,
        read=read,
        version=version,
        cov=cov,
        detector=detector,
        store=store,
        seen_at=seen_at,
    )


def _record_text(
    src: _Self,
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
    if src.serde == "csv" and src.columns:
        rows = csv_rows(text, src.columns, src.delimiter, src.skip_header)
        table = scan_rows("csv", src.columns, rows, detector, src.max_rows)
        src._record_table(
            key, table, read=read, version=version, cov=cov, store=store, seen_at=seen_at
        )
        return
    if src.serde == "json":
        columns, records = json_rows(text)
        table = scan_rows("json", columns, records, detector, src.max_rows)
        src._record_table(
            key, table, read=read, version=version, cov=cov, store=store, seen_at=seen_at
        )
        return
    item = scan_item_text(name, text, detector)
    if fmt is not None:
        # Text pulled out of a binary file: offsets into it would point nowhere.
        item.format = fmt
        for cf in item.findings.values():
            cf.offsets = []
    src._record_item(key, item, read=read, version=version, cov=cov, store=store, seen_at=seen_at)


def _record_item(
    src: _Self,
    key: str,
    item: ItemResult,
    *,
    read: int,
    version: str | None,
    cov: Coverage,
    store: FindingStore,
    seen_at: str,
) -> None:
    cov.scanned += 1
    cov.bytes_scanned += read
    cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
    cov.redaction_markers += item.redaction_markers
    cov.test_values += item.test_values
    cov.suppressed += item.suppressed
    resource = s3_resource(src.bucket, key, version, catalog=src.catalog)
    link = s3_link(src.region, src.bucket, key, version, directory=src.express)
    connect = (
        {"contactId": item.contact_id, "instanceId": item.instance_id or ""}
        if item.contact_id
        else None
    )
    findings = [
        finding_json(resource, link, item.format, cf, seen_at, connect=connect, facts=src._facts())
        for cf in item.findings.values()
        if cf.count or cf.occurrences
    ]
    store.replace_location(f"{src.id}\n{key}", findings)


def _record_table(
    src: _Self,
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
    link = s3_link(src.region, src.bucket, key, version, directory=src.express)
    findings: list[dict[str, Any]] = []
    for column, item in sorted(table.by_column.items()):
        resource = s3_resource(src.bucket, key, version, column=column, catalog=src.catalog)
        findings.extend(
            finding_json(resource, link, table.format, cf, seen_at, facts=src._facts())
            for cf in item.findings.values()
            if cf.count or cf.occurrences
        )
    store.replace_location(f"{src.id}\n{key}", findings)
