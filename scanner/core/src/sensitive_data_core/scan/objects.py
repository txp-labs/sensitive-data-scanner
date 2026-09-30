"""One stored object (a blob, a file in a bucket) read with the core's readers.

Nothing here knows which cloud holds the object. The caller lists the objects
and gives `read_object` a way to fetch a byte range of one (`fetch(start,
end)`, both inclusive); this module decides how to read what it gets, the same
way on every platform.

**Content, not name, decides the reader (#65).** The first bytes of every
object are sniffed (`scan/sniff.py`) from one small ranged read (a small
object's only read); the name is only a claim. When the two disagree the
object is read by what it is, and its findings carry `disguised: true` with
the `declaredType` and `detectedType` (kinds, never a value); the mismatch is
counted even when nothing is found. By content:

- audio, video and images are counted by kind, not read past the sniff;
- Word, Excel and PowerPoint's Open XML packages (a zip with
  `[Content_Types].xml` and `word/`, `xl/` or `ppt/`) are read as their text
  (`scan/office.py`) through ranged reads of the zip; an OLE container is a
  rights-managed Office file (`encrypted`) or an older binary Office file
  (`document`, not read);
- PDFs are read as their text layer (`scan/pdf.py`); a PDF with no text
  layer is `pdf_image_only`, one that needs a password `encrypted`;
- **archives** are read entry by entry, in memory, never extracted: zip,
  tar, and the gzip, bzip2, xz and zstd streams (a `.tar.gz` is one level).
  Each entry is sniffed and routed like an object, and nested archives are
  opened up to `MAX_DEPTH` levels. The caps: `max_inflated_bytes` for all
  that is inflated from one object, `MAX_ENTRIES` per archive, and a
  compression ratio of `MAX_RATIO` (past `RATIO_FLOOR`) per entry, the
  zip-bomb guard; the object is then `partial`. An encrypted entry is
  counted as `encrypted` (the archive too, when every entry is); 7z is
  counted as `archive_unsupported`;
- Parquet and ORC are read by column through ranged reads (`RangeFile`), up
  to `max_rows` rows and `max_object_bytes` bytes; Avro by the core's own
  reader; pyarrow is needed for Parquet, ORC, zstd and Avro's snappy and
  zstandard codecs, and without it they are counted as `columnar`;
- a Redis RDB snapshot is read as its runs of printable text;
- text (by a printable UTF-8 ratio): JSON, JSON lines, CSV, conversation
  transcripts and plain text (`scan/item.py`); other binary is `binary`.

A finding in an archive entry names the entry (`archive_fields`): its path
inside the archive, masked like a key, and where masking changed it, the
entry's position instead of anything derived from the name. `record` turns
a result into coverage and findings the same way for every platform.

Sampling by key (`sample_point`) is the same on every platform, so the same
share of a store's objects is read wherever it lives. Values exist only in
memory while one object is read.
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..detect.analyzer import Detector
from ..findings import Coverage, finding_json
from ..safety import redact_digits
from .avro import UnsupportedCodec
from .columnar import TableResult, needs_pyarrow, scan_table, zstd_text
from .item import CONVERSATION_FORMATS, ItemResult, scan_item_text
from .office import OfficeUnreadable, office_zip_text
from .pdf import ImageOnly, PdfEncrypted, PdfUnreadable, pdf_text
from .raw import printable_text
from .sniff import (
    MEDIA,
    OFFICE,
    SNIFF_BYTES,
    compatible,
    declared,
    office_layout,
    sniff,
)

Fetch = Callable[[int, int], bytes]

MAX_DEPTH = 3
MAX_ENTRIES = 1000
MAX_RATIO = 200
RATIO_FLOOR = 1024**2
WHOLE_BYTES = 256 * 1024  # an object this small is read in its one (sniffing) fetch

_OLE_MARK = "EncryptedPackage".encode("utf-16-le")
_SUFFIXES = (".gz", ".gzip", ".bz2", ".xz", ".zstd", ".zst")
_TAR_SUFFIXES = {".tgz": ".tar", ".tbz": ".tar", ".tbz2": ".tar", ".txz": ".tar", ".tzst": ".tar"}


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
    """The compression a key's name claims (a catalog table's text files, read by name)."""
    lower = key.lower()
    if lower.endswith(".gz"):
        return "gzip"
    if lower.endswith((".zst", ".zstd")):
        return "zstd"
    return None


def inner_name(key: str) -> str:
    """The key without its compression suffix: `x.jsonl.zst` reads as `x.jsonl`, `x.tgz`
    as `x.tar`."""
    lower = key.lower()
    for suffix, becomes in _TAR_SUFFIXES.items():
        if lower.endswith(suffix):
            return key[: -len(suffix)] + becomes
    for suffix in _SUFFIXES:
        if lower.endswith(suffix):
            return key[: -len(suffix)]
    return key


def gunzip(data: bytes, limit: int) -> bytes:
    """A gzip stream inflated up to `limit` bytes (cut there: read in part)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    return d.decompress(data, limit)


def planned_bytes(key: str, size: int, max_object_bytes: int) -> int:
    """What reading an object is expected to cost the budget: an object whose name says it
    is audio, video or an image is only sniffed unless its bytes say otherwise."""
    if declared(key) in MEDIA:
        return min(size, SNIFF_BYTES)
    return min(size, max_object_bytes)


class RangeCut(Exception):
    """A ranged read reached its byte cap: what was read so far stands, as partial."""


class RangeFile(io.RawIOBase):
    """A seekable read-only view of one object, read with ranged fetches.

    Parquet, ORC and zip keep their directory at the end, so a reader seeks
    there first; only the parts it asks for are fetched, up to `max_bytes`
    in all. The bytes already fetched to sniff the object (`head`) are served
    from memory and count toward the cap.
    """

    def __init__(self, fetch: Fetch, *, size: int, max_bytes: int, head: bytes = b"") -> None:
        super().__init__()
        self.fetch = fetch
        self.size = size
        self.max_bytes = max_bytes
        self.head = head
        self.pos = 0
        self.bytes_read = len(head)
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
        if self.pos < len(self.head):
            data = self.head[self.pos : self.pos + n]
            b[: len(data)] = data
            self.pos += len(data)
            return len(data)
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


class _Src:
    """One object (or one archive entry already in memory) and what has been fetched of it."""

    def __init__(self, size: int, fetch: Fetch, head: bytes, cap: int) -> None:
        self.size = size
        self.fetch = fetch
        self.head = head
        self.cap = cap
        self.fetched = len(head)
        self.cut = False
        self.raw: RangeFile | None = None

    @classmethod
    def of(cls, data: bytes, cut: bool = False) -> _Src:
        src = cls(len(data), lambda s, e: data[s : e + 1], data, len(data))
        src.cut = cut
        return src

    def all(self) -> bytes:
        """The object's bytes up to the cap, fetching what the sniff did not."""
        want = min(self.size, self.cap)
        if len(self.head) < want:
            rest = self.fetch(len(self.head), want - 1)
            self.fetched += len(rest)
            self.head += rest
        if self.size > self.cap:
            self.cut = True
        return self.head

    def file(self, buffer: int = 256 * 1024) -> Any:
        """A seekable reader: the bytes in hand, or ranged fetches of the rest."""
        if len(self.head) >= self.size:
            return io.BytesIO(self.head)
        self.raw = RangeFile(self.fetch, size=self.size, max_bytes=self.cap, head=self.head)
        return io.BufferedReader(self.raw, buffer_size=buffer)

    def settle(self) -> None:
        if self.raw is not None:
            self.fetched = max(self.fetched, self.raw.bytes_read)
            self.cut = self.cut or self.raw.cut


@dataclass(frozen=True)
class Disguise:
    """A name that claims one kind over bytes of another. Kinds only, never a name."""

    declared: str
    detected: str

    def facts(self) -> dict[str, Any]:
        return {"disguised": True, "declaredType": self.declared, "detectedType": self.detected}


@dataclass
class Entry:
    """One entry of an archive that was read: its path inside the archive (with `!/`
    between nested archives), its position (`3/0`), and what reading it gave."""

    path: str
    index: str
    item: ItemResult | None = None
    table: TableResult | None = None
    disguise: Disguise | None = None

    def __repr__(self) -> str:
        # The path comes from the archive and may hold a value: its position only.
        return f"Entry(index={self.index!r}, item={self.item is not None})"


@dataclass
class ObjectResult:
    """What reading one object gave: an item's findings, or a table's by column, or an
    archive's entries, or neither (`skipped` names why). `read` is the bytes fetched;
    `partial` that it was read in part; `disguised` how many names (the object's and its
    entries') claimed another kind; `inner_skipped` the entries counted, not read."""

    item: ItemResult | None = None
    table: TableResult | None = None
    read: int = 0
    partial: bool = False
    skipped: str | None = None
    format: str | None = None
    disguise: Disguise | None = None
    entries: list[Entry] = field(default_factory=list)
    inner_skipped: dict[str, int] = field(default_factory=dict)
    disguised: int = 0
    # For the object index (#67): what the bytes are, the readers that read them (the
    # object's and its entries'), the kinds met that no reader in this build reads, and
    # whether any part was a conversation. Names of kinds and readers only.
    detected: str | None = None
    readers: frozenset[str] = frozenset()
    unread: frozenset[str] = frozenset()
    conversation: bool = False

    def __repr__(self) -> str:
        return (
            f"ObjectResult(item={self.item is not None}, table={self.table is not None}, "
            f"entries={len(self.entries)}, read={self.read}, partial={self.partial}, "
            f"skipped={self.skipped!r}, disguised={self.disguised})"
        )

    @property
    def text_bearing(self) -> bool:
        """Some part of the object was read as text or a table (detection ran on it)."""
        return (
            self.item is not None
            or self.table is not None
            or any(e.item is not None or e.table is not None for e in self.entries)
        )


@dataclass
class _Out:
    item: ItemResult | None = None
    table: TableResult | None = None
    skipped: str | None = None
    format: str | None = None
    disguise: Disguise | None = None


class _Ctx:
    def __init__(
        self,
        detector: Detector,
        *,
        max_object_bytes: int,
        max_inflated_bytes: int,
        max_rows: int,
        columnar: bool,
    ) -> None:
        self.detector = detector
        self.max_object_bytes = max_object_bytes
        self.inflated_left = max_inflated_bytes
        self.max_rows = max_rows
        self.columnar = columnar
        self.partial = False
        self.entries: list[Entry] = []
        self.skipped: dict[str, int] = {}
        self.disguised = 0
        self.detected: str | None = None
        self.readers: set[str] = set()
        self.unread: set[str] = set()
        self.conversation = False

    def skip(self, kind: str) -> None:
        self.skipped[kind] = self.skipped.get(kind, 0) + 1

    def text_read(self, item: ItemResult, reader: str | None = None) -> None:
        """An item read as text: `transcript` when it was a conversation, else `reader`."""
        if item.format in CONVERSATION_FORMATS:
            self.readers.add("transcript")
            self.conversation = True
        else:
            self.readers.add(reader or "text")


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
    ctx = _Ctx(
        detector,
        max_object_bytes=max_object_bytes,
        max_inflated_bytes=max_inflated_bytes,
        max_rows=max_rows,
        columnar=columnar,
    )
    want = min(max(size, 0), max_object_bytes)
    first = want if want <= WHOLE_BYTES else min(want, SNIFF_BYTES)
    head = fetch(0, first - 1) if first > 0 else b""
    # A first read shorter than asked: the object is shorter than it was listed.
    src = _Src(len(head) if len(head) < first else max(size, 0), fetch, head, max_object_bytes)
    out = _read(key, src, ctx, depth=0, path="", index="", outer=None)
    src.settle()
    return ObjectResult(
        item=out.item,
        table=out.table,
        read=src.fetched,
        partial=ctx.partial or src.cut or bool(out.table and out.table.partial),
        skipped=out.skipped,
        format=out.format,
        disguise=out.disguise,
        entries=ctx.entries,
        inner_skipped=ctx.skipped,
        disguised=ctx.disguised,
        detected=ctx.detected,
        readers=frozenset(ctx.readers),
        unread=frozenset(ctx.unread),
        conversation=ctx.conversation,
    )


def _disguise(ctx: _Ctx, name: str, detected: str) -> Disguise | None:
    claim = declared(name)
    if compatible(claim, detected):
        return None
    ctx.disguised += 1
    return Disguise(claim or "none", detected)


def _read(
    name: str, src: _Src, ctx: _Ctx, *, depth: int, path: str, index: str, outer: Disguise | None
) -> _Out:
    """One object or entry, routed by what its first bytes are."""
    kind = sniff(src.head[:SNIFF_BYTES])
    if ctx.detected is None:
        ctx.detected = kind
    if kind == "zip":
        return _zip(name, src, ctx, depth=depth, path=path, index=index, outer=outer)
    disguise = _disguise(ctx, name, kind)
    if kind in ("gzip", "bzip2", "xz", "zstd"):
        out = _stream(kind, name, src, ctx, depth=depth, path=path, index=index,
                      outer=disguise or outer)  # fmt: skip
        out.disguise = out.disguise or disguise
        return out
    out = _leaf(kind, name, src, ctx, depth=depth, path=path, index=index, outer=disguise or outer)
    out.disguise = disguise
    return out


def _leaf(
    kind: str,
    name: str,
    src: _Src,
    ctx: _Ctx,
    *,
    depth: int,
    path: str,
    index: str,
    outer: Disguise | None,
) -> _Out:
    if kind in MEDIA or kind == "binary":
        ctx.unread.add(kind)
        return _Out(skipped=kind)
    if kind == "parquet_encrypted":
        return _Out(skipped="encrypted")
    if kind == "7z":
        ctx.unread.add(kind)
        return _Out(skipped="archive_unsupported")
    if kind == "ole":
        if _ole_encrypted(name, src):
            return _Out(skipped="encrypted")
        ctx.unread.add(kind)
        return _Out(skipped="document")
    if kind == "tar":
        ctx.readers.add("archive-tar")
        return _tar(src, ctx, depth=depth, path=path, index=index, outer=outer)
    if kind == "pdf":
        ctx.readers.add("pdf")
        return _pdf(name, src, ctx)
    if kind in ("parquet", "orc", "avro"):
        return _table(kind, src, ctx)
    data = src.all()
    if kind == "rdb":
        # A Redis snapshot: its text runs; offsets into them would point nowhere.
        ctx.readers.add("rdb")
        item = scan_item_text(name, printable_text(data), ctx.detector)
        item.format = "rdb"
        for cf in item.findings.values():
            cf.offsets = []
        return _Out(item=item, format="rdb")
    text = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace").read()
    item = scan_item_text(name, text, ctx.detector)
    ctx.text_read(item)
    return _Out(item=item, format=item.format)


def _ole_encrypted(name: str, src: _Src) -> bool:
    """An OLE container holding an `EncryptedPackage` stream: a rights-managed Office file.
    A Word, Excel or PowerPoint name over an OLE container is one by definition; otherwise
    the directory sector the header names is read (one ranged read) and looked in."""
    if declared(name) in OFFICE:
        return True
    head = src.head
    if _OLE_MARK in head:
        return True
    if len(head) < 0x34:
        return False
    sector = 1 << int.from_bytes(head[0x1E:0x20], "little")
    first = int.from_bytes(head[0x30:0x34], "little")
    if sector not in (512, 4096) or first >= 0xFFFFFFFA:
        return False
    start = (first + 1) * sector
    end = min(src.size, start + 4 * sector, src.cap) - 1
    if start > end:
        return False
    data = src.fetch(start, end)
    src.fetched += len(data)
    return _OLE_MARK in data


def _pdf(name: str, src: _Src, ctx: _Ctx) -> _Out:
    data = src.all()
    try:
        got = pdf_text(data, max_chars=max(0, ctx.inflated_left))
    except PdfEncrypted:
        return _Out(skipped="encrypted")
    except ImageOnly:
        return _Out(skipped="pdf_image_only")
    except PdfUnreadable:
        return _Out(skipped="document")
    ctx.inflated_left -= len(got.text)
    ctx.partial = ctx.partial or got.partial
    item = scan_item_text(inner_name(name) + ".txt", got.text, ctx.detector)
    item.format = "pdf"
    return _Out(item=item, format="pdf")


def _table(kind: str, src: _Src, ctx: _Ctx) -> _Out:
    if needs_pyarrow(kind) and not ctx.columnar:
        ctx.unread.add(kind)
        return _Out(skipped="columnar")
    ctx.readers.add("avro" if kind == "avro" else "columnar")
    f = src.file()
    try:
        table = scan_table(kind, f, ctx.detector, ctx.max_rows, ctx.columnar)
    except UnsupportedCodec:
        src.settle()
        ctx.unread.add(kind)
        return _Out(skipped="columnar")
    except Exception:
        src.settle()
        if src.raw is not None and src.raw.cut:
            ctx.partial = True  # the cap fell before a single batch
            return _Out(skipped="columnar")
        raise
    src.settle()
    if src.raw is not None and src.raw.cut:
        table.partial = True
    ctx.partial = ctx.partial or table.partial
    return _Out(table=table, format=table.format)


def _inflate(kind: str, data: bytes, limit: int, columnar: bool) -> tuple[bytes, bool]:
    """A compressed stream (every member of it), inflated up to `limit` bytes; and whether
    the limit cut it. Raises on a stream that is not what its magic said."""
    if kind == "zstd":
        out = zstd_text(data, limit + 1)
        return out[:limit], len(out) > limit
    buf = bytearray()
    rest = data
    while rest and len(buf) <= limit:
        d: Any
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            buf += d.decompress(rest, limit + 1 - len(buf))
            if d.unconsumed_tail or not d.eof:
                break
        else:
            d = bz2.BZ2Decompressor() if kind == "bzip2" else lzma.LZMADecompressor()
            buf += d.decompress(rest, limit + 1 - len(buf))
            if not d.eof:
                break
        rest = d.unused_data.lstrip(b"\x00")
    return bytes(buf[:limit]), len(buf) > limit


def _stream(
    kind: str,
    name: str,
    src: _Src,
    ctx: _Ctx,
    *,
    depth: int,
    path: str,
    index: str,
    outer: Disguise | None,
) -> _Out:
    """A gzip, bzip2, xz or zstd stream: inflated in memory and read as what it holds.
    It is transparent (the object, or the entry, is what it holds), and one level of
    nesting, except around a tar (`.tar.gz` is one archive)."""
    if kind == "zstd" and not ctx.columnar:
        ctx.unread.add(kind)
        return _Out(skipped="columnar")
    if depth >= MAX_DEPTH:
        ctx.partial = True
        return _Out(skipped="archive")
    ctx.readers.add("archive-stream")
    data = src.all()
    limit = min(max(0, ctx.inflated_left), max(len(data) * MAX_RATIO, RATIO_FLOOR))
    try:
        inner, cut = _inflate(kind, data, limit, ctx.columnar)
    except Exception:  # a bad stream (zlib, bz2, lzma or zstd error): not one we can read
        return _Out(skipped="archive")
    ctx.inflated_left -= len(inner)
    ctx.partial = ctx.partial or cut
    inside = inner_name(name)
    level = depth if sniff(inner[:SNIFF_BYTES]) == "tar" else depth + 1
    return _read(inside, _Src.of(inner, cut), ctx, depth=level, path=path, index=index,
                 outer=outer)  # fmt: skip


def _entry(
    name: str,
    data: bytes,
    ctx: _Ctx,
    *,
    cut: bool,
    depth: int,
    path: str,
    index: str,
    n: int,
    outer: Disguise | None,
) -> None:
    """One entry of an archive, routed like an object; read entries join `ctx.entries`."""
    entry_path = f"{path}!/{name}" if path else name
    entry_index = f"{index}/{n}" if index else str(n)
    try:
        out = _read(name, _Src.of(data, cut), ctx, depth=depth + 1, path=entry_path,
                    index=entry_index, outer=outer)  # fmt: skip
    except Exception:  # a damaged entry (a table that will not parse) must not cost the rest
        ctx.partial = True
        return
    if out.skipped is not None:
        ctx.skip(out.skipped)
    elif out.item is not None or out.table is not None:
        ctx.entries.append(
            Entry(entry_path, entry_index, out.item, out.table, out.disguise or outer)
        )


def _counted(name: str, head: bytes, ctx: _Ctx) -> bool:
    """An entry whose first bytes say it is audio, video, an image or binary: counted (and
    its name checked against them) without inflating the rest."""
    kind = sniff(head)
    if kind not in MEDIA and kind != "binary":
        return False
    _disguise(ctx, name, kind)
    ctx.skip(kind)
    ctx.unread.add(kind)
    return True


def _entry_limit(ctx: _Ctx, compressed: int) -> int:
    return min(ctx.inflated_left, ctx.max_object_bytes, max(compressed * MAX_RATIO, RATIO_FLOOR))


def _zip(
    name: str, src: _Src, ctx: _Ctx, *, depth: int, path: str, index: str, outer: Disguise | None
) -> _Out:
    """A zip: an Office Open XML package read as its text, or an archive read by entry.
    Nothing is extracted: an entry is inflated into memory and read there, so an entry
    named `../../x` (ZipSlip) is only a name."""
    claim = declared(name)
    not_read = "document" if claim in OFFICE else "archive"
    f = src.file(64 * 1024)  # a zip's directory and parts are small reads
    try:
        zf = zipfile.ZipFile(f)
    except RangeCut:
        src.settle()
        ctx.partial = True  # the directory lies past the byte cap
        return _Out(skipped=not_read, disguise=None)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        src.settle()
        return _Out(skipped=not_read)
    with zf:
        infos = zf.infolist()
        layout = office_layout(i.filename for i in infos)
        disguise = _disguise(ctx, name, layout or "zip")
        if layout is not None:
            try:
                got = office_zip_text(layout, zf, max_inflated_bytes=max(0, ctx.inflated_left))
            except (OfficeUnreadable, RangeCut):
                src.settle()
                return _Out(skipped="document", disguise=disguise)
            src.settle()
            ctx.inflated_left -= len(got.text)
            ctx.partial = ctx.partial or got.partial or src.cut
            text_name = inner_name(name) + (".csv" if layout == "xlsx" else ".txt")
            item = scan_item_text(text_name, got.text, ctx.detector)
            item.format = layout
            ctx.readers.add(layout)
            return _Out(item=item, format=layout, disguise=disguise)
        if depth >= MAX_DEPTH:
            ctx.partial = True
            return _Out(skipped="archive", disguise=disguise)
        ctx.readers.add("archive-zip")
        files = [i for i in infos if not i.is_dir()]
        if files and all(i.flag_bits & 0x1 for i in files):
            return _Out(skipped="encrypted", disguise=disguise)
        here = disguise or outer
        try:
            for n, info in enumerate(files):
                if n >= MAX_ENTRIES:
                    ctx.partial = True
                    break
                if info.flag_bits & 0x1:
                    ctx.skip("encrypted")
                    continue
                if ctx.inflated_left <= 0:
                    ctx.partial = True
                    break
                limit = _entry_limit(ctx, info.compress_size)
                try:
                    with zf.open(info) as member:
                        head = member.read(min(SNIFF_BYTES, limit + 1))
                        if _counted(info.filename, head, ctx):
                            continue  # media or binary: the rest is never inflated
                        data = head + member.read(limit + 1 - len(head))
                except NotImplementedError:
                    ctx.skip("archive_unsupported")  # a compression method zipfile lacks
                    continue
                except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, ValueError):
                    ctx.partial = True
                    continue
                cut = len(data) > limit
                if cut:
                    data = data[:limit]
                    ctx.partial = True  # the ratio or the inflate cap: read in part
                ctx.inflated_left -= len(data)
                _entry(info.filename, data, ctx, cut=cut, depth=depth, path=path, index=index,
                       n=n, outer=here)  # fmt: skip
        except RangeCut:
            ctx.partial = True  # the byte cap fell inside the archive
        src.settle()
    return _Out(format="zip", disguise=disguise)


def _tar(
    src: _Src, ctx: _Ctx, *, depth: int, path: str, index: str, outer: Disguise | None
) -> _Out:
    """A tar held in memory, read member by member; links and devices are not files."""
    if depth >= MAX_DEPTH:
        ctx.partial = True
        return _Out(skipped="archive")
    data = src.all()
    ctx.partial = ctx.partial or src.cut
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for m in tf:
                if not m.isreg():
                    continue
                if n >= MAX_ENTRIES:
                    ctx.partial = True
                    break
                if ctx.inflated_left <= 0:
                    ctx.partial = True
                    break
                f = tf.extractfile(m)
                if f is None:
                    continue
                limit = min(ctx.inflated_left, ctx.max_object_bytes)
                head = f.read(min(SNIFF_BYTES, limit + 1))
                if _counted(m.name, head, ctx):
                    continue
                body = head + f.read(limit + 1 - len(head))
                cut = len(body) > limit
                if cut:
                    body = body[:limit]
                    ctx.partial = True
                ctx.inflated_left -= len(body)
                _entry(m.name, body, ctx, cut=cut, depth=depth, path=path, index=index, n=n,
                       outer=outer)  # fmt: skip
                n += 1
    except (tarfile.TarError, EOFError, OSError):
        ctx.partial = True  # cut by the byte cap, or damaged: what was read stands
    return _Out(format="tar")


# ------------------------------------------------------------------ findings and coverage


def archive_fields(path: str, index: str) -> dict[str, Any]:
    """How a finding names an archive entry: `archivePath` masked like a key; when the mask
    changed it, `archivePathMasked` and the entry's position (`archiveEntry`, `3/0`) keep
    two entries that mask alike apart. Nothing derived from the name (no hash: a short
    number in a name is quickly guessed from its hash) is written."""
    masked = redact_digits(path)[:1024]
    out: dict[str, Any] = {"archivePath": masked}
    if masked != path:
        out["archivePathMasked"] = True
        out["archiveEntry"] = index
    return out


def record(
    got: ObjectResult,
    cov: Coverage,
    *,
    resource_for: Callable[[str | None], dict[str, Any]],
    link: str | None,
    seen_at: str,
    facts: Mapping[str, Any] | None = None,
    connect: bool = False,
    offsets: bool = True,
    table_offsets: bool = True,
) -> list[dict[str, Any]] | None:
    """One object's result into its source's coverage, and its findings: None when it was
    counted, not read (`skipped`). `resource_for(column)` is the object's resource (a
    table's column when not None); an entry's findings add `archive_fields`, and a
    disguised object's (or entry's) its `Disguise.facts`. With `connect`, a Connect
    transcript's findings name its contact (S3)."""
    cov.partial += int(got.partial)
    cov.disguised += got.disguised
    for kind, n in got.inner_skipped.items():
        cov.skipped[kind] = cov.skipped.get(kind, 0) + n
    if got.skipped is not None:
        cov.skipped[got.skipped] = cov.skipped.get(got.skipped, 0) + 1
        return None
    cov.scanned += 1
    cov.bytes_scanned += got.read
    fmt = got.format or (got.item.format if got.item else got.table.format if got.table else "")
    if fmt:
        cov.formats[fmt] = cov.formats.get(fmt, 0) + 1
    units: list[tuple[Entry | None, ItemResult | None, TableResult | None, Disguise | None]]
    units = [(None, got.item, got.table, got.disguise)]
    units += [(e, e.item, e.table, e.disguise) for e in got.entries]
    out: list[dict[str, Any]] = []
    for entry, item, table, disguise in units:
        extra = archive_fields(entry.path, entry.index) if entry is not None else {}
        unit_facts = {**(facts or {}), **(disguise.facts() if disguise else {})}
        if item is not None:
            cov.redaction_markers += item.redaction_markers
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            resource = {**resource_for(None), **extra}
            who = (
                {"contactId": item.contact_id, "instanceId": item.instance_id or ""}
                if connect and item.contact_id
                else None
            )
            for cf in item.findings.values():
                if not (cf.count or cf.occurrences):
                    continue
                if not offsets:
                    cf.offsets = []
                out.append(
                    finding_json(
                        resource, link, item.format, cf, seen_at, connect=who, facts=unit_facts
                    )
                )
        if table is not None:
            cov.redaction_markers += table.redaction_markers
            cov.test_values += table.test_values
            cov.suppressed += table.suppressed
            for column, col in sorted(table.by_column.items()):
                resource = {**resource_for(column), **extra}
                for cf in col.findings.values():
                    if not (cf.count or cf.occurrences):
                        continue
                    if not (offsets and table_offsets):
                        cf.offsets = []
                    out.append(
                        finding_json(resource, link, table.format, cf, seen_at, facts=unit_facts)
                    )
    return out
