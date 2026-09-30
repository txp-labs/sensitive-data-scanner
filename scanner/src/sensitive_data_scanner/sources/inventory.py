"""S3 Inventory: a large bucket's objects from its own inventory report, not a listing (#67).

A bucket with millions of objects costs a `ListObjectsV2` call per thousand keys
on every pass, whether or not anything changed. When the bucket already has an
S3 Inventory configuration, the scanner reads the latest report instead:

1. `ListBucketInventoryConfigurations` (`s3:GetInventoryConfiguration`, a read):
   an enabled configuration of current versions whose filter covers the
   source's prefix, with `Size` and `LastModifiedDate` among its fields;
2. the latest report under its destination
   (`<prefix>/<source bucket>/<configuration id>/<YYYY-MM-DDTHH-MMZ>/manifest.json`),
   no older than `MAX_AGE`;
3. the report's files, CSV (gzip, read as a stream), or ORC and Parquet (with
   pyarrow, the container image), row by row, each row taken as a listed
   object: its key, size, last-modified time and ETag.

The pass then decides what to read exactly as a listing pass does (the watermark,
the object index, sampling, rescans), and resumes at a file and row. Its
watermark is the report's own time, since a report says nothing of objects
written after it: they are in the next one.

The scanner **never creates or changes a configuration** (that is a write). A
bucket above the threshold with no usable configuration is named in the run
summary (`recommendation: s3_inventory`). The reports are read with the
scanner's `s3:GetObject`; a destination it may not read, a format this build
cannot read, or a report too old means the bucket is listed, as before.
"""

from __future__ import annotations

import csv
import datetime as _dt
import gzip
import io
import json
import re
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.safety import error_name

MAX_AGE = _dt.timedelta(days=8)  # a weekly report and a day's grace
MAX_MANIFEST_BYTES = 16 * 1024**2
_DATED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}Z")
NEEDED = frozenset({"Size", "LastModifiedDate"})


@dataclass
class Report:
    """One inventory report: where it is, when it was taken, and its files."""

    bucket: str  # the destination bucket
    manifest: str
    created: _dt.datetime
    fmt: str  # CSV | ORC | Parquet
    schema: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"Report({self.fmt}, files={len(self.files)})"

    def cursor(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "manifest": self.manifest,
            "created": self.created.isoformat(),
            "format": self.fmt,
            "schema": self.schema,
            "files": self.files,
        }

    @classmethod
    def of(cls, c: dict[str, Any]) -> Report:
        return cls(
            bucket=str(c["bucket"]),
            manifest=str(c["manifest"]),
            created=_dt.datetime.fromisoformat(str(c["created"])),
            fmt=str(c["format"]),
            schema=[str(x) for x in c.get("schema") or []],
            files=[str(x) for x in c.get("files") or []],
        )


@dataclass
class Found:
    """What a bucket's inventory configurations gave: a usable report, or why not."""

    report: Report | None = None
    configured: bool = False  # some configuration exists (usable or not)
    reason: str | None = None  # none | unreadable | stale | format | fields
    # The report's configuration runs weekly: up to a week before a change is seen. The run
    # summary recommends daily (#67).
    weekly: bool = False


def _configurations(s3: Any, bucket: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        args: dict[str, Any] = {"Bucket": bucket}
        if token:
            args["ContinuationToken"] = token
        r = s3.list_bucket_inventory_configurations(**args)
        out.extend(r.get("InventoryConfigurationList") or [])
        token = r.get("NextContinuationToken")
        if not r.get("IsTruncated") or not token:
            return out


def _covers(config: dict[str, Any], prefix: str) -> bool:
    filt = str((config.get("Filter") or {}).get("Prefix") or "")
    return prefix.startswith(filt)


def find(s3: Any, bucket: str, prefix: str, now: _dt.datetime, *, columnar: bool) -> Found:
    """The latest usable report for `bucket` (covering `prefix`), or why there is none."""
    try:
        configs = _configurations(s3, bucket)
    except Exception as err:  # denied, or no configuration API: unknown, so no recommendation
        name = error_name(err)
        return Found(configured=name != "NoSuchConfiguration", reason="unreadable")
    usable = [
        c
        for c in configs
        if c.get("IsEnabled")
        and c.get("IncludedObjectVersions") == "Current"
        and _covers(c, prefix)
        and set(c.get("OptionalFields") or []) >= NEEDED
    ]
    if not configs:
        return Found(reason="none")
    if not usable:
        return Found(configured=True, reason="fields")
    best: Found = Found(configured=True, reason="stale")
    for c in usable:
        dest = (c.get("Destination") or {}).get("S3BucketDestination") or {}
        fmt = str(dest.get("Format") or "")
        if fmt != "CSV" and not columnar:
            best = Found(configured=True, reason="format")
            continue
        target = str(dest.get("Bucket") or "").removeprefix("arn:aws:s3:::")
        base = str(dest.get("Prefix") or "").strip("/")
        root = f"{base}/{bucket}/{c.get('Id')}/" if base else f"{bucket}/{c.get('Id')}/"
        try:
            report = _latest(s3, target, root, fmt)
        except Exception:  # a destination the scanner may not read: listed, as before
            best = Found(configured=True, reason="unreadable")
            continue
        if report is None or now - report.created > MAX_AGE:
            continue
        weekly = str((c.get("Schedule") or {}).get("Frequency") or "") == "Weekly"
        return Found(report=report, configured=True, weekly=weekly)
    return best


def _latest(s3: Any, bucket: str, root: str, fmt: str) -> Report | None:
    dated: list[str] = []
    token: str | None = None
    while True:
        args: dict[str, Any] = {"Bucket": bucket, "Prefix": root, "Delimiter": "/"}
        if token:
            args["ContinuationToken"] = token
        r = s3.list_objects_v2(**args)
        for p in r.get("CommonPrefixes") or []:
            name = str(p.get("Prefix") or "")
            if _DATED.fullmatch(name.rstrip("/").rsplit("/", 1)[-1]):
                dated.append(name)
        token = r.get("NextContinuationToken")
        if not r.get("IsTruncated") or not token:
            break
    if not dated:
        return None
    key = f"{max(dated)}manifest.json"
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_MANIFEST_BYTES + 1)
    if len(body) > MAX_MANIFEST_BYTES:
        return None
    doc = json.loads(body)
    created = _dt.datetime.fromtimestamp(int(doc["creationTimestamp"]) / 1000, _dt.UTC)
    schema = [s.strip() for s in str(doc.get("fileSchema") or "").split(",") if s.strip()]
    files = [str(f["key"]) for f in doc.get("files") or [] if f.get("key")]
    return Report(bucket, key, created, str(doc.get("fileFormat") or fmt), schema, files)


def _when(v: Any) -> _dt.datetime | None:
    if isinstance(v, _dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=_dt.UTC)
    if v in (None, ""):
        return None
    try:
        return _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def _entry(row: dict[str, Any], *, encoded: bool) -> dict[str, Any] | None:
    """One report row as a listed object (`ListObjectsV2`'s shape)."""
    key = row.get("Key")
    if key is None:
        return None
    key = urllib.parse.unquote_plus(str(key)) if encoded else str(key)
    etag = row.get("ETag")
    return {
        "Key": key,
        "Size": int(row.get("Size") or 0),
        "LastModified": _when(row.get("LastModifiedDate")),
        "ETag": f'"{etag}"' if etag and not str(etag).startswith('"') else etag,
    }


def rows(
    s3: Any, report: Report, *, start_file: int = 0, start_row: int = 0
) -> Iterator[tuple[int, int, dict[str, Any]]]:
    """Every object in the report from (`start_file`, `start_row`): its position and the
    object as a listing gives it. CSV keys are URL-encoded; ORC and Parquet need pyarrow."""
    for i in range(start_file, len(report.files)):
        skip = start_row if i == start_file else 0
        body = s3.get_object(Bucket=report.bucket, Key=report.files[i])["Body"]
        if report.fmt == "CSV":
            text = io.TextIOWrapper(gzip.GzipFile(fileobj=body), encoding="utf-8", newline="")
            for n, values in enumerate(csv.reader(text)):
                if n < skip:
                    continue
                got = _entry(dict(zip(report.schema, values, strict=False)), encoded=True)
                if got is not None:
                    yield i, n, got
            continue
        yield from _columnar(i, skip, body.read(), report.fmt)


def _columnar(
    i: int, skip: int, data: bytes, fmt: str
) -> Iterator[tuple[int, int, dict[str, Any]]]:
    import pyarrow as pa  # noqa: PLC0415 - the container image's

    if fmt == "Parquet":
        import pyarrow.parquet as pq  # noqa: PLC0415

        table = pq.read_table(pa.BufferReader(data), columns=None)
    else:
        from pyarrow import orc  # noqa: PLC0415

        table = orc.ORCFile(pa.BufferReader(data)).read()
    names = {n.lower(): n for n in table.column_names}
    wanted = {
        "Key": names.get("key"),
        "Size": names.get("size"),
        "LastModifiedDate": names.get("last_modified_date") or names.get("lastmodifieddate"),
        "ETag": names.get("e_tag") or names.get("etag"),
    }
    columns = {k: table.column(v).to_pylist() for k, v in wanted.items() if v is not None}
    for n in range(skip, table.num_rows):
        got = _entry({k: col[n] for k, col in columns.items()}, encoded=False)
        if got is not None:
            yield i, n, got
