"""A small reader for Avro object container files: records out, nothing written.

pyarrow does not read Avro, and one more dependency is not worth a format
this simple. The file is a header (magic, a metadata map holding the schema
and codec, a sync marker), then blocks of records, each block compressed with
the file's codec.

- Codecs: `null`, `deflate`, `bzip2` and `xz` from the standard library;
  `snappy` and `zstandard` through pyarrow when it is installed (the container
  image). Without it, such a file raises `UnsupportedCodec`.
- Types: every primitive and complex type, named-type references, and the
  logical types a value can hide in: `decimal` (as its decimal text),
  `date`, and `timestamp-*` (as ISO text).

Values exist only in memory while the file is read.
"""

from __future__ import annotations

import bz2
import datetime as _dt
import decimal
import json
import lzma
import struct
import zlib
from collections.abc import Iterator
from typing import IO, Any

MAGIC = b"Obj\x01"
MAX_BLOCK_BYTES = 64 * 1024**2
MAX_DEPTH = 64


class AvroError(Exception):
    """The file is not an Avro container this reader can read."""


class UnsupportedCodec(AvroError):
    pass


class _Buf:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise AvroError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def long(self) -> int:
        shift = 0
        acc = 0
        while True:
            if self.pos >= len(self.data):
                raise AvroError("truncated")
            b = self.data[self.pos]
            self.pos += 1
            acc |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
            if shift > 63:
                raise AvroError("bad varint")
        return (acc >> 1) ^ -(acc & 1)


def _stream_long(f: IO[bytes]) -> int | None:
    shift = 0
    acc = 0
    first = True
    while True:
        c = f.read(1)
        if not c:
            if first:
                return None
            raise AvroError("truncated")
        first = False
        b = c[0]
        acc |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        if shift > 63:
            raise AvroError("bad varint")
    return (acc >> 1) ^ -(acc & 1)


def _read_exact(f: IO[bytes], n: int) -> bytes:
    if n < 0 or n > MAX_BLOCK_BYTES:
        raise AvroError("block too large")
    data = f.read(n)
    if len(data) != n:
        raise AvroError("truncated")
    return data


def _snappy_length(data: bytes) -> int:
    shift = 0
    acc = 0
    for b in data[:10]:
        acc |= (b & 0x7F) << shift
        if not b & 0x80:
            return acc
        shift += 7
    raise AvroError("bad snappy header")


def _decompress(codec: str, data: bytes, limit: int, pyarrow_codecs: bool = True) -> bytes:
    if codec == "null":
        return data
    if codec == "deflate":
        d = zlib.decompressobj(-15)
        return d.decompress(data, limit)
    if codec == "bzip2":
        return bz2.decompress(data)[:limit]
    if codec == "xz":
        return lzma.decompress(data)[:limit]
    if not pyarrow_codecs:
        raise UnsupportedCodec("codec needs pyarrow")
    try:
        import pyarrow as pa  # noqa: PLC0415 - optional: the container image only
    except ImportError:
        raise UnsupportedCodec("codec needs pyarrow") from None
    if codec == "snappy":
        body = data[:-4]  # a CRC32 of the uncompressed data follows
        size = _snappy_length(body)
        if size > limit:
            raise AvroError("block too large")
        out: bytes = pa.Codec("snappy").decompress(body, decompressed_size=size, asbytes=True)
        return out
    if codec == "zstandard":
        stream = pa.CompressedInputStream(pa.BufferReader(data), "zstd")
        read: bytes = stream.read(limit)
        return read
    raise UnsupportedCodec("unknown codec")


class _Schema:
    """A parsed schema with its named types, for reading values."""

    def __init__(self, schema: Any) -> None:
        self.named: dict[str, Any] = {}
        self.root = self._register(schema, None)

    def _register(self, s: Any, ns: str | None) -> Any:
        if isinstance(s, dict):
            t = s.get("type")
            if t in ("record", "error", "enum", "fixed") and "name" in s:
                name = str(s["name"])
                space = s.get("namespace", ns)
                full = name if "." in name or not space else f"{space}.{name}"
                self.named[full] = s
                self.named.setdefault(name.rsplit(".", 1)[-1], s)
                ns = full.rsplit(".", 1)[0] if "." in full else space
            if t in ("record", "error"):
                for fld in s.get("fields", []):
                    fld["type"] = self._register(fld["type"], ns)
            elif t == "array":
                s["items"] = self._register(s["items"], ns)
            elif t == "map":
                s["values"] = self._register(s["values"], ns)
            elif isinstance(t, dict | list):
                s["type"] = self._register(t, ns)
            return s
        if isinstance(s, list):
            return [self._register(x, ns) for x in s]
        return s

    def fields(self) -> list[str]:
        root = self.root
        if isinstance(root, str) and root in self.named:
            root = self.named[root]
        if isinstance(root, dict) and root.get("type") in ("record", "error"):
            return [str(f["name"]) for f in root.get("fields", [])]
        return ["value"]

    def read(self, s: Any, b: _Buf, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise AvroError("too deep")
        if isinstance(s, list):
            return self.read(s[b.long()], b, depth + 1)
        if isinstance(s, str):
            return self._primitive(s, b, depth)
        t = s.get("type")
        logical = s.get("logicalType")
        if t in ("record", "error"):
            return {str(f["name"]): self.read(f["type"], b, depth + 1) for f in s["fields"]}
        if t == "enum":
            return str(s["symbols"][b.long()])
        if t == "array":
            out: list[Any] = []
            for _ in self._blocks(b):
                out.append(self.read(s["items"], b, depth + 1))
            return out
        if t == "map":
            m: dict[str, Any] = {}
            for _ in self._blocks(b):
                k = b.read(b.long()).decode("utf-8", "replace")
                m[k] = self.read(s["values"], b, depth + 1)
            return m
        if t == "fixed":
            raw = b.read(int(s["size"]))
            return _decimal(raw, s) if logical == "decimal" else raw
        if isinstance(t, dict | list):
            return self.read(t, b, depth + 1)
        value = self._primitive(str(t), b, depth)
        return _logical(value, s) if logical else value

    def _blocks(self, b: _Buf) -> Iterator[None]:
        while True:
            n = b.long()
            if n == 0:
                return
            if n < 0:
                b.long()  # the block's byte size
                n = -n
            for _ in range(n):
                yield None

    def _primitive(self, t: str, b: _Buf, depth: int) -> Any:
        if t == "null":
            return None
        if t == "boolean":
            return b.read(1) != b"\x00"
        if t in ("int", "long"):
            return b.long()
        if t == "float":
            return struct.unpack("<f", b.read(4))[0]
        if t == "double":
            return struct.unpack("<d", b.read(8))[0]
        if t == "bytes":
            return b.read(b.long())
        if t == "string":
            return b.read(b.long()).decode("utf-8", "replace")
        if t in self.named:
            return self.read(self.named[t], b, depth + 1)
        raise AvroError("unknown type")


def _decimal(raw: bytes, s: dict[str, Any]) -> str:
    n = int.from_bytes(raw, "big", signed=True)
    return str(decimal.Decimal(n).scaleb(-int(s.get("scale", 0))))


def _logical(value: Any, s: dict[str, Any]) -> Any:
    lt = s.get("logicalType")
    try:
        if lt == "decimal" and isinstance(value, bytes):
            return _decimal(value, s)
        if lt == "date" and isinstance(value, int):
            return (_dt.date(1970, 1, 1) + _dt.timedelta(days=value)).isoformat()
        if lt in ("timestamp-millis", "local-timestamp-millis") and isinstance(value, int):
            return (_dt.datetime(1970, 1, 1) + _dt.timedelta(milliseconds=value)).isoformat()
        if lt in ("timestamp-micros", "local-timestamp-micros") and isinstance(value, int):
            return (_dt.datetime(1970, 1, 1) + _dt.timedelta(microseconds=value)).isoformat()
    except (OverflowError, ValueError):
        return None
    return value


class AvroReader:
    """Records of an Avro object container file, read from a binary stream."""

    def __init__(
        self, f: IO[bytes], max_block_bytes: int = MAX_BLOCK_BYTES, pyarrow_codecs: bool = True
    ) -> None:
        self.f = f
        self.pyarrow_codecs = pyarrow_codecs
        self.max_block_bytes = max_block_bytes
        if f.read(4) != MAGIC:
            raise AvroError("not an Avro container")
        meta: dict[str, bytes] = {}
        while True:
            n = _stream_long(f)
            if n is None:
                raise AvroError("truncated")
            if n == 0:
                break
            if n < 0:
                _stream_long(f)
                n = -n
            for _ in range(n):
                k = _read_exact(f, _stream_long(f) or 0).decode("utf-8", "replace")
                meta[k] = _read_exact(f, _stream_long(f) or 0)
        self.sync = _read_exact(f, 16)
        self.codec = meta.get("avro.codec", b"null").decode() or "null"
        try:
            self.schema = _Schema(json.loads(meta["avro.schema"]))
        except (KeyError, ValueError):
            raise AvroError("no schema") from None
        if self.codec not in ("null", "deflate", "bzip2", "xz", "snappy", "zstandard"):
            raise UnsupportedCodec("unknown codec")
        if self.codec in ("snappy", "zstandard") and not pyarrow_codecs:
            raise UnsupportedCodec("codec needs pyarrow")

    @property
    def fields(self) -> list[str]:
        return self.schema.fields()

    def __iter__(self) -> Iterator[Any]:
        while True:
            count = _stream_long(self.f)
            if count is None:
                return
            size = _stream_long(self.f)
            if size is None or count < 0:
                raise AvroError("truncated")
            raw = _read_exact(self.f, size)
            if _read_exact(self.f, 16) != self.sync:
                raise AvroError("bad sync marker")
            b = _Buf(_decompress(self.codec, raw, self.max_block_bytes, self.pyarrow_codecs))
            for _ in range(count):
                yield self.schema.read(self.schema.root, b)
