"""The per-object index (#67): what each object was read with, so a run knows what to read.

For every object a source reads, the index keeps one row in the scanner's own
state location (the AWS results bucket, the Azure state container, the Google
Cloud state bucket, or a container runner's `STATE_LOCATION`), one index per
source:

- **key**: HMAC-SHA256 of the object's key (its name, path or item id), 12 bytes;
- **marker**: HMAC of the source's change marker (ETag, version, generation, mtime,
  content tag), 8 bytes;
- **fingerprint**: HMAC of the content fingerprint (an MD5 or SHA-1 the listing gives,
  or one of the bytes read), 12 bytes;
- **profile**: what the read met (the detected type, the readers used, the kinds no
  reader read, the skip reason) and the **component-version vector** it was read with
  (`components.json`);
- **flags**: disguised, conversation, text-bearing, duplicate, unreadable;
- **duplicate of**: the key hash of the object whose bytes this one repeats;
- **generation**: the listing pass that last saw it, so objects gone are swept.

**Never a value.** Keys, markers and fingerprints are HMACs under a random salt
(`index_salt`) kept in the runner's state document, never in the index file, the
same rule as the DynamoDB source's item keys: a short number in a name is quickly
guessed from a plain hash, not from a keyed one. The profile holds names of kinds,
readers and versions only. The no-leak suite plants values in keys and names and
looks for them in the index's bytes.

**Format.** SQLite (the standard library's), held in memory and stored gzipped,
one file per shard: `<source>/<shard>.db.gz` beside `<source>/meta.json`. A
source's index starts as one shard and splits by the key hash's first byte when
it passes `SHARD_ROWS` rows per shard, up to `MAX_SHARDS`; a run loads only the
shards it touches and writes only the ones it changed. About 35 bytes a row
gzipped, **about 35 MB per million objects** (docs/ARCHITECTURE.md; measured by
`tests/test_index.py`). A source
indexes at most `max_rows` objects (`INDEX_MAX_OBJECTS`); past that, objects are
read as before, by their change at the source only.

An index that cannot be read, was written under another salt, or is of another
format version is no index: the run starts a fresh one. Saving is best effort:
a failed save costs the next run its rescan decisions, never findings.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from functools import cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from .findings import finding_id, link_for, pci_note
from .push import SIGNATURE_HEADER, Revealable, sign
from .safety import error_name, log_event
from .scan.sniff import name_kind

if TYPE_CHECKING:
    from .adapter import Budget
    from .scan.objects import ObjectResult

FORMAT_VERSION = 1
SHARD_ROWS = 250_000
MAX_SHARDS = 256
DEFAULT_MAX_ROWS = 10_000_000
DEFAULT_RESCAN_PERCENT = 25
# A table whose change marker has not moved is still sampled after this many days: a
# marker that misses a change (a statistics setting, a restart) costs a week, not forever.
TABLE_RESAMPLE_DAYS = 7
KEY_BYTES = 12
MARKER_BYTES = 8
FINGERPRINT_BYTES = 12

# Row flags.
DISGUISED = 1
CONVERSATION = 2
TEXT = 4
DUPLICATE = 8
UNREADABLE = 16

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY, body TEXT NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS objects(k BLOB PRIMARY KEY, m BLOB, f BLOB,"
    " p INTEGER NOT NULL, fl INTEGER NOT NULL DEFAULT 0, d BLOB,"
    " g INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID",
)
# Built in memory when a run first looks up a fingerprint, and never stored: it would add
# about a third to the file.
_BY_FINGERPRINT = "CREATE INDEX IF NOT EXISTS objects_f ON objects(f) WHERE f IS NOT NULL"


# ------------------------------------------------------------------ the component manifest


# The manifest's scheme: 2 narrowed each adapter to its read path (`adapter:<kind>`), with
# `listing:<kind>` beside it. An adapter version recorded under an older scheme hashed a whole
# module, so it is not compared (`stale`); the row takes this scheme's version when a pass
# meets it unchanged (`ObjectPass.decide`), since the release that narrowed the adapters moved
# their code and changed nothing any of them reads.
MANIFEST_SCHEME = 2


@dataclass(frozen=True)
class Manifest:
    """The component versions this build was made from (`components.json`,
    scripts/components.py): what each object's vector is compared with."""

    components: Mapping[str, str]
    reader_kinds: Mapping[str, tuple[str, ...]]
    scheme: int = MANIFEST_SCHEME

    @classmethod
    def load(cls) -> Manifest:
        return _manifest()

    @classmethod
    def parse(cls, doc: Mapping[str, Any]) -> Manifest:
        kinds = doc.get("readerKinds") or {}
        return cls(
            dict(doc.get("components") or {}),
            {str(k): tuple(v) for k, v in kinds.items()},
            int(doc.get("manifestVersion") or 1),
        )

    def version(self, name: str) -> str | None:
        return self.components.get(name)

    def adapter(self, kind: str) -> str | None:
        return self.components.get(f"adapter:{kind}")

    def reader(self, name: str) -> str | None:
        return self.components.get(f"reader:{name}")

    def listing(self, kind: str) -> str | None:
        """`listing:<kind>`: how a split adapter finds its objects (a change re-lists)."""
        return self.components.get(f"listing:{kind}")

    @property
    def classes(self) -> dict[str, str]:
        """`spec-standalone/<class>`: each class's own rules' version."""
        prefix = "spec-standalone/"
        return {k[len(prefix) :]: v for k, v in self.components.items() if k.startswith(prefix)}

    def readers_for(self, kind: str) -> tuple[str, ...]:
        """The readers that read objects of a kind (`pdf` reads `pdf`)."""
        return tuple(sorted(r for r, kinds in self.reader_kinds.items() if kind in kinds))

    @property
    def digest(self) -> str:
        body = json.dumps(dict(sorted(self.components.items())), separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()[:12]


@cache
def _manifest() -> Manifest:
    raw = resources.files("sensitive_data_core").joinpath("components.json").read_text("utf-8")
    return Manifest.parse(json.loads(raw))


# ------------------------------------------------------------------ what an object was read with


@dataclass(frozen=True)
class Profile:
    """What one read met, and the component versions it was read with (the vector).

    Many objects share a profile (every PDF read by this build, every image counted), so a
    shard stores each once. Kinds, reader names, skip reasons and versions only."""

    adapter: str
    adapter_v: str | None = None
    detected: str | None = None
    readers: tuple[tuple[str, str | None], ...] = ()
    unread: tuple[str, ...] = ()
    skip: str | None = None
    sniffer_v: str | None = None
    standalone_v: str | None = None
    classes: tuple[tuple[str, str], ...] = ()
    conversation_v: str | None = None
    name_kind: str | None = None  # the name's known extensions (a duplicate must share them)
    scheme: int = 1  # the manifest scheme `adapter_v` was taken under (MANIFEST_SCHEME)

    def body(self) -> str:
        out: dict[str, Any] = {"a": self.adapter, "av": self.adapter_v}
        if self.scheme > 1:
            out["ms"] = self.scheme
        if self.detected is not None:
            out["t"] = self.detected
        if self.readers:
            out["r"] = dict(self.readers)
        if self.unread:
            out["u"] = list(self.unread)
        if self.skip is not None:
            out["s"] = self.skip
        if self.name_kind is not None:
            out["n"] = self.name_kind
        out |= {
            "sn": self.sniffer_v,
            "ss": self.standalone_v,
            "sc": dict(self.classes),
            "cv": self.conversation_v,
        }
        return json.dumps(out, sort_keys=True, separators=(",", ":"))

    @classmethod
    def parse(cls, body: str) -> Profile:
        d = json.loads(body)
        return cls(
            adapter=str(d.get("a") or ""),
            adapter_v=d.get("av"),
            detected=d.get("t"),
            readers=tuple(sorted((str(k), v) for k, v in (d.get("r") or {}).items())),
            unread=tuple(sorted(str(u) for u in d.get("u") or [])),
            skip=d.get("s"),
            sniffer_v=d.get("sn"),
            standalone_v=d.get("ss"),
            classes=tuple(sorted((str(k), str(v)) for k, v in (d.get("sc") or {}).items())),
            conversation_v=d.get("cv"),
            name_kind=d.get("n"),
            scheme=int(d.get("ms") or 1),
        )

    def reader_names(self) -> frozenset[str]:
        return frozenset(r for r, _ in self.readers)


def profile_for(
    manifest: Manifest,
    adapter: str,
    got: ObjectResult | None = None,
    *,
    readers: tuple[str, ...] = (),
    detected: str | None = None,
    skip: str | None = None,
    unread: tuple[str, ...] = (),
    name_kind: str | None = None,
) -> Profile:
    """The profile of one read: an object's (`got`), or a table's, an item's or a group of
    objects' (`readers`, `unread`)."""
    names = set(readers)
    unread_kinds = frozenset(unread)
    if got is not None:
        names |= got.readers
        unread_kinds |= got.unread
        detected = detected or got.detected
        skip = skip or got.skipped
    return Profile(
        adapter=adapter,
        adapter_v=manifest.adapter(adapter),
        detected=detected,
        readers=tuple(sorted((r, manifest.reader(r)) for r in names)),
        unread=tuple(sorted(unread_kinds)),
        skip=skip,
        sniffer_v=manifest.version("sniffer"),
        standalone_v=manifest.version("spec-standalone"),
        classes=tuple(sorted(manifest.classes.items())),
        conversation_v=manifest.version("spec-conversation"),
        name_kind=name_kind,
        scheme=manifest.scheme,
    )


def flags_for(got: ObjectResult | None, *, unreadable: bool = False, text: bool = False) -> int:
    fl = UNREADABLE if unreadable else 0
    if text:
        fl |= TEXT
    if got is not None:
        if got.disguised:
            fl |= DISGUISED
        if got.conversation:
            fl |= CONVERSATION
        if got.text_bearing:
            fl |= TEXT
    return fl


# ------------------------------------------------------------------ keyed hashes


def md5_fingerprint(raw: Any) -> str | None:
    """A listing's MD5 of an object's bytes as a fingerprint (`md5:<hex>`): raw bytes (Azure's
    `content_md5`), base64 (Cloud Storage's `md5Hash`) or hex (an ETag, Drive's
    `md5Checksum`). Anything else is no fingerprint."""
    if raw is None:
        return None
    if isinstance(raw, bytes | bytearray):
        return f"md5:{bytes(raw).hex()}" if len(raw) == 16 else None
    text = str(raw).strip().strip('"').lower()
    if len(text) == 32 and all(c in "0123456789abcdef" for c in text):
        return f"md5:{text}"
    try:
        data = base64.b64decode(str(raw).strip(), validate=True)
    except (ValueError, binascii.Error):
        return None
    return f"md5:{data.hex()}" if len(data) == 16 else None


def index_salt(state: Mapping[str, Any]) -> str:
    """The salt the index's HMACs are keyed with: the one in the runner's state document, or
    a new one (the runner writes it back with its state)."""
    salt = state.get("indexSalt")
    if isinstance(salt, str) and len(salt) >= 32:
        return salt
    return secrets.token_hex(16)


class Hasher:
    """HMAC-SHA256 under the index salt, one domain per field: a key's, a marker's and a
    fingerprint's hashes never compare equal to each other."""

    def __init__(self, salt: str) -> None:
        self._salt = salt.encode()

    def __repr__(self) -> str:
        return "Hasher(***)"

    def _mac(self, domain: bytes, text: str) -> bytes:
        data = domain + b"\0" + text.encode("utf-8", "surrogatepass")
        return hmac.new(self._salt, data, hashlib.sha256).digest()

    def key(self, text: str) -> bytes:
        return self._mac(b"key", text)[:KEY_BYTES]

    def marker(self, text: str) -> bytes:
        return self._mac(b"marker", text)[:MARKER_BYTES]

    def fingerprint(self, text: str) -> bytes:
        return self._mac(b"fingerprint", text)[:FINGERPRINT_BYTES]

    def name(self, text: str) -> str:
        return self._mac(b"source", text)[:12].hex()

    @property
    def check(self) -> str:
        """Says which salt an index was written under, and nothing about it."""
        return self._mac(b"check", "index")[:8].hex()


# ------------------------------------------------------------------ where the index lives


class IndexBackend(Protocol):
    """Bytes by name, in the scanner's own state location."""

    def get_bytes(self, name: str) -> bytes | None: ...

    def put_bytes(self, name: str, data: bytes) -> None: ...

    def delete(self, name: str) -> None: ...


class MemoryBackend:
    """In memory (tests, and a run with nowhere to keep state)."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}

    def __repr__(self) -> str:
        return f"MemoryBackend({len(self.files)})"

    def get_bytes(self, name: str) -> bytes | None:
        return self.files.get(name)

    def put_bytes(self, name: str, data: bytes) -> None:
        self.files[name] = bytes(data)

    def delete(self, name: str) -> None:
        self.files.pop(name, None)


def _safe(name: str) -> str:
    parts = [p for p in name.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise ValueError("index file name")
    return "/".join(parts)


class FileBackend:
    """A directory on a mounted volume; each file replaced atomically."""

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)

    def __repr__(self) -> str:
        return "FileBackend()"

    def get_bytes(self, name: str) -> bytes | None:
        try:
            return (self.dir / _safe(name)).read_bytes()
        except FileNotFoundError:
            return None

    def put_bytes(self, name: str, data: bytes) -> None:
        path = self.dir / _safe(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    def delete(self, name: str) -> None:
        (self.dir / _safe(name)).unlink(missing_ok=True)


class S3Backend:
    """Objects under a prefix of a bucket, through a client the platform's package makes."""

    def __init__(
        self,
        bucket: str,
        prefix: str,
        client: Any | None = None,
        *,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix
        self._client = client
        self._factory = client_factory

    def __repr__(self) -> str:
        return "S3Backend()"

    def _s3(self) -> Any:
        if self._client is None:
            if self._factory is None:
                raise RuntimeError("no s3 client")
            self._client = self._factory()
        return self._client

    def get_bytes(self, name: str) -> bytes | None:
        try:
            body = self._s3().get_object(Bucket=self.bucket, Key=self.prefix + _safe(name))
        except Exception as err:
            if error_name(err) in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
        data: bytes = body["Body"].read()
        return data

    def put_bytes(self, name: str, data: bytes) -> None:
        self._s3().put_object(Bucket=self.bucket, Key=self.prefix + _safe(name), Body=data)

    def delete(self, name: str) -> None:
        self._s3().delete_object(Bucket=self.bucket, Key=self.prefix + _safe(name))


class HttpsBackend:
    """URLs under the state URL the customer serves (`<state URL>.index/<name>`): GET to
    read, a signed PUT to write and a signed DELETE to remove, like the state itself."""

    def __init__(
        self,
        base: Revealable,
        key: Revealable,
        *,
        user_agent: str = "sensitive-data-scanner",
        opener: Callable[..., Any] = urllib.request.urlopen,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._base = base
        self._key = key
        self._agent = user_agent
        self._open = opener
        self._clock = clock

    def __repr__(self) -> str:
        return "HttpsBackend(***)"

    def _url(self, name: str) -> str:
        return self._base.reveal() + ".index/" + _safe(name)

    def _signed(self, method: str, name: str, body: bytes = b"") -> Any:
        ts = str(int(self._clock()))
        return urllib.request.Request(  # noqa: S310 - https only (each runner's settings)
            self._url(name),
            data=body if method == "PUT" else None,
            method=method,
            headers={
                "Content-Type": "application/octet-stream",
                "User-Agent": self._agent,
                SIGNATURE_HEADER: sign(self._key.reveal().encode(), ts, body),
            },
        )

    def get_bytes(self, name: str) -> bytes | None:
        req = urllib.request.Request(self._url(name), method="GET")  # noqa: S310 - https only
        try:
            with self._open(req, timeout=60) as resp:
                data: bytes = resp.read()
                return data
        except Exception as err:
            if getattr(err, "code", None) == 404:
                return None
            raise

    def put_bytes(self, name: str, data: bytes) -> None:
        with self._open(self._signed("PUT", name, data), timeout=60):
            return

    def delete(self, name: str) -> None:
        try:
            with self._open(self._signed("DELETE", name), timeout=60):
                return
        except Exception as err:
            if getattr(err, "code", None) != 404:
                raise


class PrefixBackend:
    """Another backend's names under a prefix (`state/index/` in a results bucket)."""

    def __init__(self, inner: Any, prefix: str) -> None:
        self.inner = inner
        self.prefix = prefix

    def __repr__(self) -> str:
        return f"PrefixBackend({self.inner!r})"

    def get_bytes(self, name: str) -> bytes | None:
        data: bytes | None = self.inner.get_bytes(self.prefix + _safe(name))
        return data

    def put_bytes(self, name: str, data: bytes) -> None:
        self.inner.put_bytes(self.prefix + _safe(name), data)

    def delete(self, name: str) -> None:
        self.inner.delete(self.prefix + _safe(name))


# ------------------------------------------------------------------ one source's index


@dataclass(frozen=True)
class Row:
    """One object's row. Hashes, a profile and flags: nothing that could be a value."""

    key: bytes
    marker: bytes | None
    fingerprint: bytes | None
    profile: Profile
    flags: int = 0
    duplicate_of: bytes | None = None
    generation: int = 0

    def __repr__(self) -> str:
        return f"Row(flags={self.flags}, generation={self.generation})"


@dataclass
class _Shard:
    conn: sqlite3.Connection
    profiles: dict[str, int] = field(default_factory=dict)
    by_id: dict[int, Profile] = field(default_factory=dict)
    dirty: bool = False


class ObjectIndex:
    """One source's index: rows by key hash, in shards loaded as they are touched."""

    def __init__(
        self,
        backend: IndexBackend,
        name: str,
        hasher: Hasher,
        *,
        max_rows: int = DEFAULT_MAX_ROWS,
        shard_rows: int = SHARD_ROWS,
    ) -> None:
        self.backend = backend
        self.name = name
        self.hasher = hasher
        self.max_rows = max_rows
        self.shard_rows = shard_rows
        self._shards: dict[int, _Shard] = {}
        self._meta: dict[str, Any] | None = None
        self.full = 0  # objects not indexed because the index was full
        self.fresh = False  # no usable index was found: every row is new this run

    def __repr__(self) -> str:
        return f"ObjectIndex(rows={self.rows})"

    # --- layout

    def _load_meta(self) -> dict[str, Any]:
        if self._meta is None:
            meta: dict[str, Any] | None = None
            try:
                raw = self.backend.get_bytes(f"{self.name}/meta.json")
                meta = json.loads(raw) if raw else None
            except Exception as err:  # unreadable: a fresh index
                log_event("index.failed", error=error_name(err))
            ok = (
                isinstance(meta, dict)
                and meta.get("version") == FORMAT_VERSION
                and meta.get("check") == self.hasher.check
                and isinstance(meta.get("shards"), int)
                and 1 <= meta["shards"] <= MAX_SHARDS
            )
            if ok and meta is not None:
                self._meta = {
                    "shards": int(meta["shards"]),
                    "rows": int(meta.get("rows") or 0),
                    "stored": int(meta["shards"]),
                }
            else:
                self.fresh = True
                old = int(meta.get("shards") or 0) if isinstance(meta, dict) else 0
                stored = old if isinstance(old, int) and 0 < old <= MAX_SHARDS else 0
                self._meta = {"shards": 1, "rows": 0, "stored": stored, "reset": True}
        return self._meta

    @property
    def shards(self) -> int:
        return int(self._load_meta()["shards"])

    @property
    def rows(self) -> int:
        return int(self._load_meta()["rows"])

    def _file(self, i: int) -> str:
        return f"{self.name}/{i:03d}.db.gz"

    def _shard_of(self, k: bytes) -> int:
        return k[0] % self.shards

    def _shard(self, i: int) -> _Shard:
        got = self._shards.get(i)
        if got is not None:
            return got
        conn = sqlite3.connect(":memory:")
        meta = self._load_meta()
        if not meta.get("reset"):
            try:
                data = self.backend.get_bytes(self._file(i))
                if data:
                    conn.deserialize(gzip.decompress(data))
            except Exception as err:  # a damaged shard: its rows are gone, the rest stand
                log_event("index.failed", error=error_name(err))
                conn.close()
                conn = sqlite3.connect(":memory:")
        for stmt in _SCHEMA:
            conn.execute(stmt)
        shard = _Shard(conn)
        for pid, body in conn.execute("SELECT id, body FROM profiles"):
            shard.profiles[body] = pid
            shard.by_id[pid] = Profile.parse(body)
        self._shards[i] = shard
        return shard

    def _all(self) -> Iterator[_Shard]:
        for i in range(self.shards):
            yield self._shard(i)

    def _profile_id(self, shard: _Shard, profile: Profile) -> int:
        body = profile.body()
        pid = shard.profiles.get(body)
        if pid is None:
            cur = shard.conn.execute("INSERT INTO profiles(body) VALUES (?)", (body,))
            pid = int(cur.lastrowid or 0)
            shard.profiles[body] = pid
            shard.by_id[pid] = profile
        return pid

    def _row(self, shard: _Shard, r: tuple[Any, ...]) -> Row:
        k, m, f, p, fl, d, g = r
        return Row(k, m, f, shard.by_id[p], fl, d, g)

    # --- rows

    def get(self, key: str) -> Row | None:
        return self.get_hashed(self.hasher.key(key))

    def get_hashed(self, k: bytes) -> Row | None:
        shard = self._shard(self._shard_of(k))
        r = shard.conn.execute(
            "SELECT k, m, f, p, fl, d, g FROM objects WHERE k = ?", (k,)
        ).fetchone()
        return self._row(shard, r) if r else None

    def put(
        self,
        key: str,
        *,
        profile: Profile,
        marker: str | None = None,
        fingerprint: str | None = None,
        flags: int = 0,
        duplicate_of: bytes | None = None,
        generation: int = 0,
    ) -> bool:
        """Write one object's row; False when the index is full and the object is new."""
        k = self.hasher.key(key)
        shard = self._shard(self._shard_of(k))
        exists = shard.conn.execute("SELECT 1 FROM objects WHERE k = ?", (k,)).fetchone()
        if not exists and self.rows >= self.max_rows:
            self.full += 1
            return False
        shard.conn.execute(
            "INSERT OR REPLACE INTO objects(k, m, f, p, fl, d, g) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                k,
                self.hasher.marker(marker) if marker is not None else None,
                self.hasher.fingerprint(fingerprint) if fingerprint is not None else None,
                self._profile_id(shard, profile),
                flags,
                duplicate_of,
                generation,
            ),
        )
        shard.dirty = True
        if not exists:
            self._load_meta()["rows"] += 1
        return True

    def reprofile(self, row: Row, profile: Profile) -> None:
        """Give a row another profile, nothing else changed (an adapter version carried to a
        newer manifest scheme)."""
        shard = self._shard(self._shard_of(row.key))
        shard.conn.execute(
            "UPDATE objects SET p = ? WHERE k = ?", (self._profile_id(shard, profile), row.key)
        )
        shard.dirty = True

    def touch(self, key: str, generation: int) -> None:
        """The listing saw the object in pass `generation` (so a sweep keeps its row)."""
        k = self.hasher.key(key)
        shard = self._shard(self._shard_of(k))
        cur = shard.conn.execute(
            "UPDATE objects SET g = ? WHERE k = ? AND g < ?", (generation, k, generation)
        )
        if cur.rowcount:
            shard.dirty = True

    def delete(self, key: str) -> None:
        k = self.hasher.key(key)
        shard = self._shard(self._shard_of(k))
        cur = shard.conn.execute("DELETE FROM objects WHERE k = ?", (k,))
        if cur.rowcount:
            shard.dirty = True
            self._load_meta()["rows"] -= cur.rowcount

    def sweep(self, generation: int) -> int:
        """Drop the rows a complete pass (`generation`) did not see: objects gone."""
        gone = 0
        for shard in self._all():
            cur = shard.conn.execute("DELETE FROM objects WHERE g < ?", (generation,))
            if cur.rowcount:
                shard.dirty = True
                gone += cur.rowcount
        self._load_meta()["rows"] -= gone
        return gone

    def by_fingerprint(self, fingerprint: str, *, exclude: str | None = None) -> Row | None:
        """A row whose content fingerprint is this one (another object with the same bytes)."""
        f = self.hasher.fingerprint(fingerprint)
        skip = self.hasher.key(exclude) if exclude is not None else None
        for shard in self._all():
            shard.conn.execute(_BY_FINGERPRINT)
            for r in shard.conn.execute(
                "SELECT k, m, f, p, fl, d, g FROM objects WHERE f = ? ORDER BY k", (f,)
            ):
                if r[0] != skip and not r[4] & (DUPLICATE | UNREADABLE):
                    return self._row(shard, r)
        return None

    def profile_counts(self) -> list[tuple[Profile, int, int]]:
        """Every profile in the index with its flags, and how many rows have them (what the
        rescan backlog is counted from)."""
        out: dict[tuple[str, int], tuple[Profile, int, int]] = {}
        for shard in self._all():
            for p, fl, n in shard.conn.execute(
                "SELECT p, fl, count(*) FROM objects GROUP BY p, fl"
            ):
                prof = shard.by_id[p]
                key = (prof.body(), int(fl))
                have = out.get(key)
                out[key] = (prof, int(fl), (have[2] if have else 0) + int(n))
        return list(out.values())

    # --- saving

    def dirty(self) -> bool:
        meta = self._load_meta()
        return any(s.dirty for s in self._shards.values()) or bool(meta.get("reset"))

    def _reshard(self) -> None:
        """Split into more shards when the rows outgrow them (never fewer)."""
        want = self.shards
        while want < MAX_SHARDS and self.rows > want * self.shard_rows:
            want *= 2
        if want == self.shards:
            return
        old = list(self._all())
        self._shards = {}
        self._load_meta()["shards"] = want
        new = [self._new_shard(i) for i in range(want)]
        for shard in old:
            bodies = {pid: prof for pid, prof in shard.by_id.items()}
            for r in shard.conn.execute("SELECT k, m, f, p, fl, d, g FROM objects"):
                target = new[r[0][0] % want]
                pid = self._profile_id(target, bodies[r[3]])
                target.conn.execute(
                    "INSERT OR REPLACE INTO objects(k, m, f, p, fl, d, g)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (r[0], r[1], r[2], pid, r[4], r[5], r[6]),
                )
            shard.conn.close()
        for i, shard in enumerate(new):
            shard.dirty = True
            self._shards[i] = shard

    def _new_shard(self, i: int) -> _Shard:
        conn = sqlite3.connect(":memory:")
        for stmt in _SCHEMA:
            conn.execute(stmt)
        return _Shard(conn)

    def save(self) -> int:
        """Write the shards this run changed, then the meta. Returns the bytes written."""
        if not self.dirty():
            return 0
        self._reshard()
        meta = self._load_meta()
        written = 0
        for i, shard in sorted(self._shards.items()):
            if not (shard.dirty or meta.get("reset")):
                continue
            shard.conn.execute("DROP INDEX IF EXISTS objects_f")
            shard.conn.commit()
            shard.conn.execute("VACUUM")
            data = gzip.compress(shard.conn.serialize(), compresslevel=6, mtime=0)
            self.backend.put_bytes(self._file(i), data)
            written += len(data)
            shard.dirty = False
        if meta.get("reset"):
            # Shards a reset index no longer has (written under another salt) are removed.
            for i in range(meta["shards"], int(meta.get("stored") or 0)):
                self.backend.delete(self._file(i))
            for i in range(meta["shards"]):
                if i not in self._shards:
                    self._shards[i] = self._new_shard(i)
                    data = gzip.compress(self._shards[i].conn.serialize(), mtime=0)
                    self.backend.put_bytes(self._file(i), data)
                    written += len(data)
        body = {
            "version": FORMAT_VERSION,
            "check": self.hasher.check,
            "shards": meta["shards"],
            "rows": meta["rows"],
        }
        self.backend.put_bytes(f"{self.name}/meta.json", json.dumps(body).encode())
        meta.pop("reset", None)
        meta["stored"] = meta["shards"]
        return written

    def close(self) -> None:
        for shard in self._shards.values():
            shard.conn.close()
        self._shards = {}


# ------------------------------------------------------------------ one run's indexes


class Indexes:
    """The indexes of one run: one per source, opened when a source first asks."""

    def __init__(
        self,
        backend: IndexBackend,
        salt: str,
        *,
        manifest: Manifest | None = None,
        max_rows: int = DEFAULT_MAX_ROWS,
        shard_rows: int = SHARD_ROWS,
        rescan_percent: int = DEFAULT_RESCAN_PERCENT,
    ) -> None:
        self.backend = backend
        self.salt = salt
        self.hasher = Hasher(salt)
        self.manifest = manifest or Manifest.load()
        self.max_rows = max_rows
        self.shard_rows = shard_rows
        self.rescan_percent = rescan_percent
        self._open: dict[str, ObjectIndex] = {}

    def __repr__(self) -> str:
        return f"Indexes({len(self._open)})"

    def open(self, source_id: str) -> ObjectIndex:
        got = self._open.get(source_id)
        if got is None:
            got = ObjectIndex(
                self.backend,
                "src-" + self.hasher.name(source_id),
                self.hasher,
                max_rows=self.max_rows,
                shard_rows=self.shard_rows,
            )
            self._open[source_id] = got
        return got

    def save(self) -> int:
        """Write every index this run changed; a failure is logged, never raised (the next
        run then decides from what was saved before). Returns how many failed."""
        failed = 0
        for index in self._open.values():
            try:
                written = index.save()
                if written:
                    log_event("index.saved", rows=index.rows, bytes=written)
            except Exception as err:
                failed += 1
                log_event("index.failed", error=error_name(err))
            finally:
                index.close()
        self._open = {}
        return failed


# ------------------------------------------------------------------ what a rescan is for


# Why an object that did not change at its source is read again (`rescanReason`, 1.10).
ADAPTER = "adapter"
READER = "reader"
NEW_READER = "new_reader"
SNIFFER = "sniffer"
SPEC_STANDALONE = "spec_standalone"
SPEC_CONVERSATION = "spec_conversation"
UNINDEXED = "unindexed"
RESCAN_REASONS = (
    ADAPTER,
    READER,
    NEW_READER,
    SNIFFER,
    SPEC_STANDALONE,
    SPEC_CONVERSATION,
    UNINDEXED,
)
# A duplicate's findings are its own: these of the original's are not carried over.
_NOT_COPIED = frozenset(
    {"rescanReason", "rescanClasses", "atRestEncryption", "atRestKeyHash", "pciNote", "linked"}
)
# What the sniffer could not name: a new sniffer may name it.
UNDETERMINED = frozenset({"binary"})
# Kinds only a build with pyarrow reads (the container images; not the Lambda zip).
NEEDS_PYARROW = frozenset({"parquet", "orc", "avro", "zstd"})


@dataclass(frozen=True)
class Stale:
    """Why an unchanged object is read again, and for a class-scoped spec change, which
    classes (a new class, or one class's rules)."""

    reason: str
    classes: tuple[str, ...] = ()

    def fields(self) -> dict[str, Any]:
        """What each of the object's findings says about it (1.10)."""
        out: dict[str, Any] = {"rescanReason": self.reason}
        if self.classes:
            out["rescanClasses"] = list(self.classes)
        return out


def readable(manifest: Manifest, kind: str, *, columnar: bool) -> bool:
    """A reader in this build reads objects of `kind`."""
    if not manifest.readers_for(kind):
        return False
    return columnar or kind not in NEEDS_PYARROW


def stale(profile: Profile, flags: int, manifest: Manifest, *, columnar: bool) -> Stale | None:
    """Whether a component the object was read with differs from this build's **and could
    change its result**, and which (the first that applies, in this order):

    - its adapter changed: that adapter's objects only;
    - a reader it was read with changed: that reader's objects, whatever the platform;
    - a reader now reads a kind it met unread (a new reader, or pyarrow in the build);
    - the sniffer changed, and what the object is was undetermined (`binary`) or disputed
      (`disguised`);
    - the standalone spec changed (the engine: every class; one class's rules or a new
      class: those classes), and the object was read as text or a table;
    - the conversation spec changed, and some part of it was a conversation.

    A component the manifest no longer names (a reader removed or renamed) counts as changed.
    An adapter version taken under an older manifest scheme is not compared: it hashed the
    whole module, listing included, where this scheme hashes the read path only.
    """
    current = manifest.adapter(profile.adapter)
    if current is not None and profile.adapter_v != current and profile.scheme == manifest.scheme:
        return Stale(ADAPTER)
    for name, version in profile.readers:
        if manifest.reader(name) != version:
            return Stale(READER)
    for kind in profile.unread:
        if readable(manifest, kind, columnar=columnar):
            return Stale(NEW_READER)
    if profile.sniffer_v != manifest.version("sniffer") and (
        profile.detected is None or profile.detected in UNDETERMINED or flags & DISGUISED
    ):
        return Stale(SNIFFER)
    if flags & TEXT:
        if profile.standalone_v != manifest.version("spec-standalone"):
            return Stale(SPEC_STANDALONE)
        had = dict(profile.classes)
        changed = tuple(sorted(c for c, v in manifest.classes.items() if had.get(c) != v))
        if changed:
            return Stale(SPEC_STANDALONE, changed)
    if flags & CONVERSATION and profile.conversation_v != manifest.version("spec-conversation"):
        return Stale(SPEC_CONVERSATION)
    return None


# ------------------------------------------------------------------ re-listing


# The cursor key that records the `listing:<kind>` version a source's position was reached with.
LISTING_KEY = "listing"


def relist(source: Any, cursor: Mapping[str, Any], indexes: Indexes | None) -> dict[str, Any]:
    """The cursor a source runs from. When how its kind is listed changed since the position
    was reached (`listing:<kind>` moved: discovery, listing, an inventory reader), the
    source's position keys (`relist_keys`: a resume key, a page token, a delta link) are
    dropped, so the pass lists the store again from the start. Nothing is read again for it:
    each object is decided by its row as always, and an unchanged one is skipped (#67).

    Only with an index: without one, a delta feed that lost its link would read every item.
    The first run after an upgrade records the version and re-lists nothing."""
    out = dict(cursor)
    if indexes is None:
        return out
    current = indexes.manifest.listing(str(getattr(source, "kind", "")))
    had = out.get(LISTING_KEY)
    if current is not None and had is not None and had != current:
        keys = tuple(getattr(source, "relist_keys", ()))
        for key in keys:
            out.pop(key, None)
        out[RELISTED] = True
        log_event("source.relist", source=getattr(source, "target", None))
    return out


RELISTED = "_relisted"


def listed_with(source: Any, run: Any, indexes: Indexes | None, cursor: Mapping[str, Any]) -> None:
    """After a source's run (`run`, its SourceRun): its cursor records the `listing:<kind>`
    version it listed with, and its coverage says when this run re-listed (`relisted`)."""
    if indexes is None or not isinstance(run.cursor, dict):
        return
    run.cursor.pop(RELISTED, None)
    current = indexes.manifest.listing(str(getattr(source, "kind", "")))
    if current is not None:
        run.cursor[LISTING_KEY] = current
    if cursor.get(RELISTED):
        run.coverage.relisted = True


@dataclass(frozen=True)
class Decision:
    """What a pass does with one listed object: `read` it (it changed at its source, or is
    new), `rescan` it (`why`), or `skip` it (unchanged, and read with what could change
    its result)."""

    action: str
    why: Stale | None = None

    @property
    def read(self) -> bool:
        return self.action == "read"

    @property
    def rescan(self) -> bool:
        return self.action == "rescan"


READ = Decision("read")
SKIP = Decision("skip")


class Rescans:
    """The rescan candidates of one source's run, read after its changes (#67).

    Rescans may use at most `percent` of the source's share of the run (items and bytes),
    and only what its changes left: an upgrade that makes a million objects stale reads a
    capped slice of them each run, in listing order, so the next run reaches the next slice
    (the rows read are current again). Candidates past the cap are the backlog."""

    def __init__(self, budget: Budget | None, percent: int) -> None:
        pct = max(0, min(100, percent))
        max_items = budget.max_items if budget is not None else 0
        max_bytes = budget.max_bytes if budget is not None else 0
        self.cap_items = max(1, max_items * pct // 100) if pct and max_items else 0
        self.cap_bytes = max_bytes * pct // 100
        self.items = 0
        self.bytes = 0
        self.queue: list[tuple[Any, Stale]] = []
        self.done: dict[str, int] = {}
        self.left: dict[str, int] = {}  # candidates met and not read, by reason

    def __repr__(self) -> str:
        return f"Rescans(queued={len(self.queue)}, left={sum(self.left.values())})"

    def _left(self, why: Stale) -> None:
        self.left[why.reason] = self.left.get(why.reason, 0) + 1

    def offer(self, candidate: Any, why: Stale) -> None:
        """A candidate met in the listing: queued while the cap could still read it."""
        if len(self.queue) < self.cap_items:
            self.queue.append((candidate, why))
        else:
            self._left(why)

    def room(self, size: int) -> bool:
        if self.items >= self.cap_items:
            return False
        return self.items == 0 or self.bytes + size <= self.cap_bytes

    def drain(self, budget: Budget, size_of: Callable[[Any], int]) -> Iterator[tuple[Any, Stale]]:
        """The queued candidates the cap and the budget have room for, each charged to both;
        the rest are backlog."""
        queue, self.queue = self.queue, []
        for n, (candidate, why) in enumerate(queue):
            size = size_of(candidate)
            if not (budget.has(size) and self.room(size)):
                for _, w in queue[n:]:
                    self._left(w)
                return
            budget.take(size)
            self.items += 1
            self.bytes += size
            yield candidate, why

    def take(self, size: int, budget: Budget) -> bool:
        """Room for one rescan of `size` now (a source that meets its candidates one by one,
        such as a delta feed's enumeration): charged to the cap and the budget."""
        if not (budget.has(size) and self.room(size)):
            return False
        budget.take(size)
        self.items += 1
        self.bytes += size
        return True

    def admit(self) -> bool:
        """Room for one more rescan whose bytes the source charges to the budget itself."""
        if self.items >= self.cap_items:
            return False
        self.items += 1
        return True

    def miss(self, why: Stale) -> None:
        """A candidate met with no room left: backlog."""
        self._left(why)

    def read(self, why: Stale) -> None:
        self.done[why.reason] = self.done.get(why.reason, 0) + 1


class ObjectPass:
    """One source's pass as the index sees it.

    - `decide`: read an object that changed at its source (or is new), rescan one whose
      recorded vector is stale, skip the rest;
    - `record`: each object read (or found unreadable), with its marker, fingerprint and
      profile;
    - `rescans`: the candidates, read after the changes within the capped share.

    With no index (`indexes` None: no state location, or `OBJECT_INDEX=off`) it decides as
    before, by the change at the source only, and records nothing."""

    def __init__(
        self,
        indexes: Indexes | None,
        source_id: str,
        adapter: str,
        *,
        generation: int = 0,
        columnar: bool = False,
        budget: Budget | None = None,
    ) -> None:
        self.indexes = indexes
        self.adapter = adapter
        self.generation = generation
        self.columnar = columnar
        self.index = indexes.open(source_id) if indexes is not None else None
        percent = indexes.rescan_percent if indexes is not None else 0
        self.rescans = Rescans(budget, percent if self.index is not None else 0)
        self.duplicates = 0
        self._locations: dict[bytes, str] | None = None

    @property
    def bootstrap(self) -> bool:
        """An object with no row that did not change is read once (`unindexed`): it was read
        before the index knew it, or with a build whose vector is unknown. Not when the index
        is full (those objects will never have a row) or rescans are off."""
        return (
            self.index is not None
            and self.rescans.cap_items > 0
            and self.index.rows < self.index.max_rows
        )

    def decide(self, key: str, *, changed: bool, marker: str | None = None) -> Decision:
        """`changed`: the source says it changed (a time past the watermark, less its skew).
        With a row, the marker decides instead when there is one: the same marker is the
        same object, whatever its time (an object inside the skew window is not read twice);
        another marker is a change. Then a stale vector is a rescan; no row is `unindexed`."""
        if self.index is None:
            return READ if changed else SKIP
        row = self.index.get(key)
        if row is None:
            if changed:
                return READ
            return Decision("rescan", Stale(UNINDEXED)) if self.bootstrap else SKIP
        if marker is not None and row.marker is not None:
            if row.marker != self.index.hasher.marker(marker):
                return READ
        elif changed:
            return READ
        if row.flags & UNREADABLE:
            return SKIP  # retried when it changes, as before the index
        return self._verdict(row)

    def _verdict(self, row: Row) -> Decision:
        """An unchanged row: a rescan when a component it was read with is stale, else skip.
        A row whose adapter version predates this manifest scheme takes this build's version
        on the way (`MANIFEST_SCHEME`): the read path it was read with is this one."""
        why = stale(row.profile, row.flags, self.manifest, columnar=self.columnar)
        if why is not None:
            return Decision("rescan", why)
        m = self.manifest
        if self.index is not None and row.profile.scheme != m.scheme:
            self.index.reprofile(
                row,
                replace(row.profile, adapter_v=m.adapter(row.profile.adapter), scheme=m.scheme),
            )
        return SKIP

    def table(self, key: str, marker: str, *, resample_days: int = TABLE_RESAMPLE_DAYS) -> Decision:
        """A table with an engine's change marker (#67 part 3): skipped when the marker is the
        one recorded, it was read in the last `resample_days` (this pass's generation is the
        day), and read with what could still give the same result; a rescan when a component
        is stale; else read."""
        if self.index is None:
            return READ
        row = self.index.get(key)
        if row is None or row.flags & UNREADABLE or row.marker != self.index.hasher.marker(marker):
            return READ
        if self.generation - row.generation >= resample_days:
            return READ
        return self._verdict(row)

    def offer(self, candidate: Any, decision: Decision) -> None:
        """A rescan candidate (`decide` said `rescan`), read after the changes if it fits."""
        if decision.why is not None:
            self.rescans.offer(candidate, decision.why)

    # --- duplicates (#67 part 5)

    def duplicate(self, key: str, fingerprint: str | None, name: str | None = None) -> Row | None:
        """Another object of this source already read whose bytes are this one's (the same
        content fingerprint) under a name of the same kind (`.csv` for `.csv`), read with
        components that are still current: this one need not be read. None when there is
        none, or it is stale (both are then read)."""
        if self.index is None or fingerprint is None:
            return None
        row = self.index.by_fingerprint(fingerprint, exclude=key)
        if row is None or row.profile.name_kind != name_kind(name if name is not None else key):
            return None
        if stale(row.profile, row.flags, self.manifest, columnar=self.columnar) is not None:
            return None
        return row

    def copy_findings(
        self,
        original: Row,
        store: Any,
        prefix: str,
        *,
        resource_for: Callable[[str | None], dict[str, Any]],
        link: str | None,
        seen_at: str,
        facts: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """The original's findings as this object's own: its resource, id and link, its own
        storage facts, and `duplicateOf` naming the original's finding (1.10). `prefix` is the
        source's location prefix (`<source id>\n`); the original is found by its key hash."""
        location = self._location_of(original.key, store, prefix)
        if location is None:
            return []  # the original holds nothing
        out = []
        for f in store.items.values():
            if f.get("_location") != location:
                continue
            old = dict(f.get("resource") or {})
            resource = {**resource_for(old.get("column"))}
            for k in ("archivePath", "archivePathMasked", "archiveEntry"):
                if k in old:
                    resource[k] = old[k]
            copy = {k: v for k, v in f.items() if not k.startswith("_") and k not in _NOT_COPIED}
            copy.update(
                id=finding_id(resource, str(f["class"])),
                resource=resource,
                link=link_for(resource, link),
                firstSeenAt=seen_at,
                lastSeenAt=seen_at,
                duplicateOf=f["id"],
            )
            for k, v in (facts or {}).items():
                copy[k] = v
            note = pci_note(str(f["class"]), copy.get("atRestEncryption"))
            if note is not None:
                copy["pciNote"] = note
            out.append(copy)
        return out

    def _location_of(self, k: bytes, store: Any, prefix: str) -> str | None:
        """The finding store's location of the object whose key hash is `k` (a map of the
        source's locations by hash, rebuilt when an original read this run is not in it)."""
        if self.index is None:
            return None
        if self._locations is None or k not in self._locations:
            self._locations = {
                self.index.hasher.key(loc[len(prefix) :]): loc for loc in store.locations(prefix)
            }
        return self._locations.get(k)

    def record_duplicate(
        self, key: str, original: Row, *, marker: str | None, fingerprint: str | None
    ) -> None:
        """A duplicate's row: the original's profile (its bytes were read with it)."""
        if self.index is None:
            return
        self.index.put(
            key,
            profile=original.profile,
            marker=marker,
            fingerprint=fingerprint,
            flags=original.flags | DUPLICATE,
            duplicate_of=original.key,
            generation=self.generation,
        )
        self.duplicates += 1

    def rescanned(self, findings: list[dict[str, Any]] | None, why: Stale | None) -> None:
        """An object read for `why` (a rescan): its findings say so (`rescanReason`, 1.10),
        and it is counted. A read for a change at the source is not a rescan."""
        if why is None:
            return
        self.rescans.read(why)
        for f in findings or []:
            f.update(why.fields())

    def needs_enumeration(self, *, indexed: bool) -> bool:
        """A delta feed lists only what changed, so a stale row never shows up in it: a pass
        over every item is needed when the index has stale rows, or when items were read
        before the index knew them (`indexed` False)."""
        if self.index is None or self.rescans.cap_items == 0:
            return False
        return not indexed or self.stale_rows() > 0

    def stale_rows(self) -> int:
        """Rows whose vector is stale: the rescan backlog the index knows of."""
        if self.index is None:
            return 0
        m = self.manifest
        return sum(
            n
            for prof, fl, n in self.index.profile_counts()
            if not fl & UNREADABLE and stale(prof, fl, m, columnar=self.columnar) is not None
        )

    def settle(self, cov: Any) -> None:
        """What the run rescanned, by reason, and the backlog left (1.10), into coverage."""
        if self.index is None:
            return
        cov.indexed = (cov.indexed or 0) + self.index.rows
        cov.duplicates += self.duplicates
        for reason, n in self.rescans.done.items():
            cov.rescanned[reason] = cov.rescanned.get(reason, 0) + n
        # Rows still stale, and candidates with no row met and not read.
        cov.rescan_backlog += self.stale_rows() + self.rescans.left.get(UNINDEXED, 0)

    def __repr__(self) -> str:
        return f"ObjectPass({self.adapter!r})"

    @property
    def manifest(self) -> Manifest:
        return self.indexes.manifest if self.indexes is not None else Manifest.load()

    def record(
        self,
        key: str,
        *,
        marker: str | None = None,
        fingerprint: str | None = None,
        got: ObjectResult | None = None,
        unreadable: bool = False,
        readers: tuple[str, ...] = (),
        skip: str | None = None,
        text: bool = False,
        unread: tuple[str, ...] = (),
        flags: int = 0,
        name: str | None = None,
    ) -> None:
        """One read: an object's (`got`), or what a group of reads met (`readers`, `unread`,
        `flags`, such as an image layer's files). `name`: the object's name when its key is
        not (a drive item's id), for the name kind a duplicate must share."""
        if self.index is None:
            return
        profile = profile_for(
            self.manifest,
            self.adapter,
            got,
            readers=readers,
            skip="unreadable" if unreadable else skip,
            unread=unread,
            name_kind=name_kind(name if name is not None else key),
        )
        self.index.put(
            key,
            profile=profile,
            marker=marker,
            # The listing's fingerprint, else one of the bytes when the whole object was read.
            fingerprint=fingerprint or (got.fingerprint if got is not None else None),
            flags=flags | flags_for(got, unreadable=unreadable, text=text),
            generation=self.generation,
        )

    def carry(self, store: Any, location: str, pass_id: str) -> None:
        """A pass that skips an unchanged, current location (a file whose blob is the same,
        a layer already read) keeps its findings: they join this pass (`_pass`), so the end
        of the pass does not drop them. A `location` ending in a line break is a prefix."""
        prefix = location.endswith("\n")
        for f in store.items.values():
            at = str(f.get("_location", ""))
            if at == location or (prefix and at.startswith(location)):
                f["_pass"] = pass_id

    def seen(self, key: str) -> None:
        """A listed object this pass did not read (unchanged, sampled out): keep its row."""
        if self.index is not None and self.generation:
            self.index.touch(key, self.generation)

    def forget(self, key: str) -> None:
        """An object the source says is gone (a delta feed's deletion)."""
        if self.index is not None:
            self.index.delete(key)

    def complete(self) -> int:
        """A listing pass saw every object: rows it did not see are gone. Returns how many."""
        if self.index is None or not self.generation:
            return 0
        return self.index.sweep(self.generation)
