"""One stored object (a blob, a file in a bucket) read with the core's readers.

Nothing here knows which cloud holds the object. The caller lists the objects
and gives `read_object` a way to fetch a byte range of one (`fetch(start,
end)`, both inclusive); this module decides how to read what it gets, the same
way the AWS scanner reads an S3 object:

- a file whose name says it is audio, video, an image, a PDF or an older
  binary Office document, or an archive is not read, and is counted by kind
  (`skip_kind`);
- Word, Excel and PowerPoint's Open XML files (`.docx`, `.xlsx`, `.pptx`) are
  read as their text (`scan/office.py`) through ranged reads of the zip, and a
  rights-managed one (an OLE container) is counted as `encrypted`;
- Parquet and ORC (by extension or magic bytes) are read by column through
  ranged reads, so a large file's footer and first row groups are read
  without the rest (`RangeFile`), up to `max_rows` rows and `max_bytes` bytes;
  Avro is read by the core's own reader; pyarrow is needed for Parquet, ORC,
  zstd and Avro's snappy and zstandard codecs, and without it they are
  counted as `columnar`;
- text compressed with gzip or zstd (`.gz`, `.zst`) is inflated first;
- a Redis RDB snapshot is read as its runs of printable text;
- anything else is text: JSON, JSON lines, CSV, conversation transcripts
  and plain text (`scan/item.py`).

Sampling by key (`sample_point`) is the same on every platform, so the same
share of a store's objects is read wherever it lives. Values exist only in
memory while one object is read.
"""

from __future__ import annotations

import gzip
import io
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..detect.analyzer import Detector
from .avro import UnsupportedCodec
from .columnar import (
    TableResult,
    columnar_kind,
    needs_pyarrow,
    scan_table,
    sniff,
    zstd_text,
)
from .item import ItemResult, classify_key, looks_binary, scan_item_text
from .office import OfficeUnreadable, is_encrypted_office, office_kind, office_text
from .raw import printable_text

Fetch = Callable[[int, int], bytes]


def sample_point(key: str) -> int:
    """FNV-1a over the key's UTF-16 code units: a stable 0-99 bucket for sampling."""
    h = 0x811C9DC5
    data = key.encode("utf-16-le")
    for i in range(0, len(data), 2):
        h ^= data[i] | (data[i + 1] << 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h % 100


def is_rdb(key: str, head: bytes) -> bool:
    """A Redis RDB snapshot: `REDIS` and a version (`REDIS0011`), or an `.rdb` key."""
    return head[:5] == b"REDIS" or key.lower().endswith(".rdb")


def compression(key: str) -> str | None:
    lower = key.lower()
    if lower.endswith(".gz"):
        return "gzip"
    if lower.endswith((".zst", ".zstd")):
        return "zstd"
    return None


def inner_name(key: str) -> str:
    """The key without its compression suffix: `x.jsonl.zst` reads as `x.jsonl`."""
    lower = key.lower()
    for suffix in (".gz", ".zstd", ".zst"):
        if lower.endswith(suffix):
            return key[: -len(suffix)]
    return key


def gunzip(data: bytes, limit: int) -> bytes:
    """A gzip stream inflated up to `limit` bytes (cut there: read in part)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    return d.decompress(data, limit)


def skip_kind(key: str) -> str | None:
    """The kind of file a key names when it is not read (`audio`, `image`, ...), else None."""
    if columnar_kind(key) is not None or office_kind(key) is not None:
        return None
    read_it, _, kind = classify_key(inner_name(key))
    return None if read_it else (kind or "binary")


class RangeCut(Exception):
    """A columnar read reached its byte cap: what was read so far stands, as partial."""


class RangeFile(io.RawIOBase):
    """A seekable read-only view of one object, read with ranged fetches.

    Parquet and ORC keep their footer at the end, so a reader seeks there
    first; only the parts it asks for are fetched, up to `max_bytes`.
    """

    def __init__(self, fetch: Fetch, *, size: int, max_bytes: int) -> None:
        super().__init__()
        self.fetch = fetch
        self.size = size
        self.max_bytes = max_bytes
        self.pos = 0
        self.bytes_read = 0
        self.cut = False

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
        data = self.fetch(self.pos, end)
        b[: len(data)] = data
        self.pos += len(data)
        self.bytes_read += len(data)
        return len(data)


@dataclass
class ObjectResult:
    """What reading one object gave: an item's findings, or a table's by column, or neither
    (`skipped` names why). `read` is the bytes fetched; `partial` that it was read in part."""

    item: ItemResult | None = None
    table: TableResult | None = None
    read: int = 0
    partial: bool = False
    skipped: str | None = None

    def __repr__(self) -> str:
        return (
            f"ObjectResult(item={self.item is not None}, table={self.table is not None}, "
            f"read={self.read}, partial={self.partial}, skipped={self.skipped!r})"
        )


def _text(key: str, data: bytes, max_inflated_bytes: int, columnar: bool) -> str | ObjectResult:
    """The object's text, or an ObjectResult saying why it has none."""
    kind = compression(key)
    if kind == "gzip":
        try:
            data = gunzip(data, max_inflated_bytes)
        except (zlib.error, OSError, EOFError, gzip.BadGzipFile):
            return ObjectResult(skipped="archive")
    elif kind == "zstd":
        if not columnar:
            return ObjectResult(skipped="columnar")
        try:
            data = zstd_text(data, max_inflated_bytes)
        except Exception:  # a bad frame: not text we can read
            return ObjectResult(skipped="archive")
    if looks_binary(data):
        return ObjectResult(skipped="binary")
    return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace").read()


def read_object(
    key: str,
    size: int,
    fetch: Fetch,
    detector: Detector,
    *,
    max_object_bytes: int,
    max_inflated_bytes: int,
    max_rows: int,
    columnar: bool,
) -> ObjectResult:
    """Read one object of `size` bytes named `key`. A fetch that fails is raised to the
    caller (the object is then unreadable); a format this build cannot read is `skipped`."""
    office = office_kind(key)
    if office is not None:
        return _read_office(
            key,
            office,
            size,
            fetch,
            detector,
            max_object_bytes=max_object_bytes,
            max_inflated_bytes=max_inflated_bytes,
        )
    kind = columnar_kind(key)
    head: bytes | None = None
    partial = False
    if kind is None:
        want = min(size, max_object_bytes)
        head = fetch(0, want - 1) if want > 0 else b""
        partial = size > max_object_bytes
        kind = sniff(head) if compression(key) is None else None
        if kind is None and is_rdb(key, head):
            # A Redis snapshot: its text runs; offsets into them would point nowhere.
            item = scan_item_text(key, printable_text(head), detector)
            item.format = "rdb"
            for cf in item.findings.values():
                cf.offsets = []
            return ObjectResult(item=item, read=len(head), partial=partial)
        if kind is None:
            text = _text(key, head, max_inflated_bytes, columnar)
            if isinstance(text, ObjectResult):
                text.read, text.partial = len(head), partial
                return text
            item = scan_item_text(inner_name(key), text, detector)
            return ObjectResult(item=item, read=len(head), partial=partial)
    if needs_pyarrow(kind) and not columnar:
        return ObjectResult(skipped="columnar")
    raw: RangeFile | None = None
    if head is not None and len(head) >= size:
        f: Any = io.BytesIO(head)
    else:
        raw = RangeFile(fetch, size=size, max_bytes=max_object_bytes)
        f = io.BufferedReader(raw, buffer_size=256 * 1024)
    try:
        table = scan_table(kind, f, detector, max_rows, columnar)
    except UnsupportedCodec:
        return ObjectResult(skipped="columnar", read=raw.bytes_read if raw else 0)
    except Exception:
        if raw is not None and raw.cut:
            # The cap fell before a single batch.
            return ObjectResult(skipped="columnar", read=raw.bytes_read, partial=True)
        raise
    if raw is not None and raw.cut:
        table.partial = True
    read = raw.bytes_read if raw is not None else len(head or b"")
    return ObjectResult(table=table, read=read, partial=table.partial)


def _read_office(
    key: str,
    kind: str,
    size: int,
    fetch: Fetch,
    detector: Detector,
    *,
    max_object_bytes: int,
    max_inflated_bytes: int,
) -> ObjectResult:
    """A `.docx`, `.xlsx` or `.pptx` file: its zip read through ranged fetches (the central
    directory, then the parts with text), up to `max_object_bytes` fetched. A rights-managed
    file is `encrypted`; a file that is not a readable zip, or whose directory lies past the
    byte cap, is counted as a `document` not read."""
    if size <= 0:
        return ObjectResult(skipped="document")
    head = fetch(0, min(size, 8) - 1)
    if is_encrypted_office(head):
        return ObjectResult(skipped="encrypted", read=len(head))
    raw = RangeFile(fetch, size=size, max_bytes=max_object_bytes)
    f = io.BufferedReader(raw, buffer_size=64 * 1024)
    try:
        got = office_text(kind, f, max_inflated_bytes=max_inflated_bytes)
    except (OfficeUnreadable, RangeCut):
        return ObjectResult(skipped="document", read=raw.bytes_read + len(head), partial=raw.cut)
    name = inner_name(key) + (".csv" if kind == "xlsx" else ".txt")
    item = scan_item_text(name, got.text, detector)
    item.format = kind
    partial = got.partial or raw.cut
    return ObjectResult(item=item, read=raw.bytes_read + len(head), partial=partial)
