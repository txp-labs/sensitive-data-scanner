"""The per-object index (#67): rows keyed by HMACs, profiles with the component vector,
shards, bounds, backends, and what `read_object` reports for it. Made-up values only."""

from __future__ import annotations

import gzip
import io
import json
import sqlite3
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from archive_fixtures import JPEG, SEVEN_Z, pdf, tar_of, zip_of
from aws_fixtures import RESULTS, Env, config, shared_detector
from office_fixtures import docx
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.index import (
    CONVERSATION,
    DISGUISED,
    TEXT,
    UNREADABLE,
    FileBackend,
    Hasher,
    HttpsBackend,
    Indexes,
    Manifest,
    MemoryBackend,
    ObjectIndex,
    ObjectPass,
    PrefixBackend,
    Profile,
    S3Backend,
    index_salt,
    md5_fingerprint,
    profile_for,
)
from sensitive_data_core.safety import Secret
from sensitive_data_core.scan.objects import ObjectResult, read_object
from sensitive_data_core.state import FileState, HttpsState, S3State, index_backend
from synthetic import CARDS, SSN_A, dashed

SALT = "0" * 32
MANIFEST = Manifest.load()


@pytest.fixture
def detector() -> Detector:
    return shared_detector()


def read(name: str, data: bytes, detector: Detector) -> ObjectResult:
    return read_object(
        name,
        len(data),
        lambda s, e: data[s : e + 1],
        detector,
        max_object_bytes=1024**2,
        max_inflated_bytes=4 * 1024**2,
        max_rows=100,
        columnar=False,
    )


def test_read_object_reports_what_the_index_needs(detector: Detector) -> None:
    got = read("a.txt", f"card {CARDS['visa']}".encode(), detector)
    assert (got.detected, set(got.readers), set(got.unread)) == ("text", {"text"}, set())
    assert got.text_bearing and not got.conversation

    got = read("report.pdf", pdf([f"ssn {dashed(SSN_A)}"]), detector)
    assert (got.detected, set(got.readers)) == ("pdf", {"pdf"})

    got = read("photo.jpg", docx(["hello"]), detector)
    assert (got.detected, set(got.readers), got.disguised) == ("zip", {"docx"}, 1)

    got = read("bundle.zip", zip_of({"a.pdf": pdf(["x"]), "b.jpg": JPEG}), detector)
    assert got.detected == "zip"
    assert got.readers == {"archive-zip", "pdf"}
    assert got.unread == {"image"}

    got = read("x.7z", SEVEN_Z, detector)
    assert (got.detected, set(got.readers), set(got.unread), got.skipped) == (
        "7z",
        set(),
        {"7z"},
        "archive_unsupported",
    )
    assert not got.text_bearing

    got = read("t.tar", tar_of({"notes.txt": b"hello"}), detector)
    assert got.readers == {"archive-tar", "text"}

    chat = {
        "Version": "2019-08-26",
        "ContactId": "c",
        "Participants": [{"ParticipantId": "a", "ParticipantRole": "AGENT"}],
        "Transcript": [
            {"ParticipantId": "a", "ParticipantRole": "AGENT", "Content": "hi", "Type": "MESSAGE"}
        ],
    }
    got = read("chat.json", json.dumps(chat).encode(), detector)
    assert got.conversation and got.readers == {"transcript"}


def test_a_profile_carries_the_vector_and_round_trips() -> None:
    p = profile_for(MANIFEST, "s3", readers=("pdf", "text"), detected="pdf")
    assert p.adapter_v == MANIFEST.adapter("s3")
    assert dict(p.readers) == {"pdf": MANIFEST.reader("pdf"), "text": MANIFEST.reader("text")}
    assert p.sniffer_v == MANIFEST.version("sniffer")
    assert dict(p.classes) == MANIFEST.classes
    assert Profile.parse(p.body()) == p


def test_rows_are_keyed_hashes_and_survive_a_save(detector: Detector) -> None:
    backend = MemoryBackend()
    idx = ObjectIndex(backend, "src-x", Hasher(SALT))
    prof = profile_for(MANIFEST, "s3", read("a.txt", b"hello", detector))
    assert idx.put("dir/a.txt", profile=prof, marker="etag|5", fingerprint="md5:" + "a" * 32)
    assert idx.put("dir/b.txt", profile=prof, marker="etag|6", flags=TEXT)
    assert idx.rows == 2
    idx.save()
    idx.close()

    again = ObjectIndex(backend, "src-x", Hasher(SALT))
    row = again.get("dir/a.txt")
    assert row is not None and row.profile == prof
    assert row.marker == Hasher(SALT).marker("etag|5")
    assert again.get("dir/c.txt") is None
    assert again.rows == 2
    found = again.by_fingerprint("md5:" + "a" * 32, exclude="dir/b.txt")
    assert found is not None and found.key == Hasher(SALT).key("dir/a.txt")
    assert again.by_fingerprint("md5:" + "a" * 32, exclude="dir/a.txt") is None
    # One profile stored once, however many rows share it.
    conn = sqlite3.connect(":memory:")
    conn.deserialize(gzip.decompress(backend.files["src-x/000.db.gz"]))
    assert conn.execute("SELECT count(*) FROM profiles").fetchone() == (1,)


def test_another_salt_is_a_fresh_index() -> None:
    backend = MemoryBackend()
    idx = ObjectIndex(backend, "src-x", Hasher(SALT))
    idx.put("k", profile=profile_for(MANIFEST, "s3"))
    idx.save()
    other = ObjectIndex(backend, "src-x", Hasher("1" * 32))
    assert other.get("k") is None and other.rows == 0 and other.fresh
    other.put("k2", profile=profile_for(MANIFEST, "s3"))
    other.save()
    assert ObjectIndex(backend, "src-x", Hasher("1" * 32)).rows == 1


def test_a_damaged_index_is_no_index() -> None:
    backend = MemoryBackend()
    backend.files["src-x/meta.json"] = b"{not json"
    idx = ObjectIndex(backend, "src-x", Hasher(SALT))
    assert idx.rows == 0 and idx.get("k") is None


def test_shards_split_as_rows_grow_and_keep_every_row() -> None:
    backend = MemoryBackend()
    idx = ObjectIndex(backend, "src-x", Hasher(SALT), shard_rows=50)
    prof = profile_for(MANIFEST, "s3")
    for i in range(300):
        idx.put(f"k/{i}", profile=prof, marker=str(i))
    idx.save()
    assert idx.shards == 8
    again = ObjectIndex(backend, "src-x", Hasher(SALT), shard_rows=50)
    assert again.shards == 8 and again.rows == 300
    assert all(again.get(f"k/{i}") is not None for i in range(300))
    # A later run touching one key loads and writes one shard only.
    before = dict(backend.files)
    again.put("k/7", profile=prof, marker="changed")
    again.save()
    rewritten = {n for n in backend.files if backend.files[n] != before.get(n)}
    assert rewritten <= {"src-x/meta.json", f"src-x/{Hasher(SALT).key('k/7')[0] % 8:03d}.db.gz"}


def test_a_full_index_takes_no_new_objects() -> None:
    idx = ObjectIndex(MemoryBackend(), "src-x", Hasher(SALT), max_rows=3)
    prof = profile_for(MANIFEST, "s3")
    for i in range(5):
        idx.put(f"k/{i}", profile=prof)
    assert idx.rows == 3 and idx.full == 2
    assert idx.put("k/0", profile=prof, marker="updated")  # an indexed object still updates


def test_a_complete_pass_sweeps_objects_it_did_not_see() -> None:
    backend = MemoryBackend()
    indexes = Indexes(backend, SALT)
    op = ObjectPass(indexes, "s3:b/", "s3", generation=1)
    for k in ("a", "b", "c"):
        op.record(k, marker=k)
    indexes.save()
    indexes = Indexes(backend, SALT)
    op = ObjectPass(indexes, "s3:b/", "s3", generation=2)
    op.seen("a")
    op.record("c", marker="c2")
    assert op.complete() == 1  # b is gone
    assert op.index is not None
    assert op.index.get("b") is None and op.index.get("a") is not None


def test_object_pass_records_flags_and_forgets(detector: Detector) -> None:
    indexes = Indexes(MemoryBackend(), SALT)
    op = ObjectPass(indexes, "drive:1", "m365_sharepoint")
    op.record("item-1", got=read("photo.jpg", docx([f"card {CARDS['visa']}"]), detector))
    op.record("item-2", unreadable=True)
    assert op.index is not None
    one, two = op.index.get("item-1"), op.index.get("item-2")
    assert one is not None and one.flags & DISGUISED and one.flags & TEXT
    assert not one.flags & CONVERSATION
    assert two is not None and two.flags & UNREADABLE and two.profile.skip == "unreadable"
    op.forget("item-1")
    assert op.index.get("item-1") is None
    assert ObjectPass(None, "x", "s3").index is None  # no state: nothing recorded


def test_md5_fingerprints_from_every_platforms_listing() -> None:
    raw = bytes(range(16))
    hexed = raw.hex()
    import base64

    assert md5_fingerprint(raw) == f"md5:{hexed}"
    assert md5_fingerprint(bytearray(raw)) == f"md5:{hexed}"
    assert md5_fingerprint(base64.b64encode(raw).decode()) == f"md5:{hexed}"
    assert md5_fingerprint(f'"{hexed.upper()}"') == f"md5:{hexed}"
    assert md5_fingerprint("abc-3") is None
    assert md5_fingerprint(None) is None
    assert md5_fingerprint(b"short") is None


def test_the_salt_comes_from_the_state_or_is_new() -> None:
    assert index_salt({"indexSalt": "a" * 32}) == "a" * 32
    fresh = index_salt({})
    assert len(fresh) == 32 and fresh != index_salt({})


def test_backends_round_trip(tmp_path: Path, env: Env) -> None:
    for backend in (
        FileBackend(str(tmp_path / "idx")),
        S3Backend(RESULTS, "state/index/", env.clients.s3),
        PrefixBackend(MemoryBackend(), "state/index/"),
    ):
        assert backend.get_bytes("src-a/meta.json") is None
        backend.put_bytes("src-a/meta.json", b"{}")
        assert backend.get_bytes("src-a/meta.json") == b"{}"
        backend.delete("src-a/meta.json")
        assert backend.get_bytes("src-a/meta.json") is None
    with pytest.raises(ValueError):
        FileBackend(str(tmp_path)).put_bytes("../escape", b"x")


def test_the_https_backend_signs_its_writes() -> None:
    calls: list[tuple[str, str, dict[str, str]]] = []
    store: dict[str, bytes] = {}

    class Resp(io.BytesIO):
        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    def opener(req: Any, timeout: int) -> Resp:
        calls.append((req.get_method(), req.full_url, dict(req.header_items())))
        if req.get_method() == "PUT":
            store[req.full_url] = req.data
            return Resp(b"")
        if req.get_method() == "DELETE":
            store.pop(req.full_url, None)
            return Resp(b"")
        if req.full_url not in store:
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)  # type: ignore[arg-type]
        return Resp(store[req.full_url])

    b = HttpsBackend(
        Secret("https://state.example/sds/state.json"), Secret("k" * 32), opener=opener
    )
    assert b.get_bytes("src-a/meta.json") is None
    b.put_bytes("src-a/meta.json", b"{}")
    assert b.get_bytes("src-a/meta.json") == b"{}"
    put = next(c for c in calls if c[0] == "PUT")
    assert put[1] == "https://state.example/sds/state.json.index/src-a/meta.json"
    assert any(h.lower() == "x-sds-signature" for h in put[2])
    b.delete("src-a/meta.json")
    assert b.get_bytes("src-a/meta.json") is None
    assert "k" * 32 not in repr(b)


def test_each_state_location_has_an_index_beside_it(tmp_path: Path) -> None:
    f = index_backend(FileState(str(tmp_path / "state.json")))
    assert isinstance(f, FileBackend) and f.dir == tmp_path / "state.json.index"
    s = index_backend(S3State("bucket", "sds/state.json", client=object()))
    assert isinstance(s, S3Backend) and (s.bucket, s.prefix) == ("bucket", "sds/state.json.index/")
    h = index_backend(HttpsState(Secret("https://x.example/s.json"), Secret("k" * 32)))
    assert isinstance(h, HttpsBackend)

    class Plain:
        def load(self) -> None:
            return None

        def save(self, state: dict[str, Any]) -> None:
            return None

    assert index_backend(Plain()) is None


def test_the_aws_run_keeps_an_index_beside_its_state(env: Env) -> None:
    env.put("a/one.txt", f"card {CARDS['visa']}")
    env.put("a/two.pdf", pdf(["nothing here"]))
    env.put("a/three.jpg", JPEG)
    assert env.run(config()) is not None
    state = env.state()
    salt = state["indexSalt"]
    listed = env.clients.s3.list_objects_v2(Bucket=RESULTS, Prefix="state/index/")
    names = sorted(o["Key"] for o in listed.get("Contents", []))
    assert names and all(n.startswith("state/index/src-") for n in names)
    indexes = Indexes(S3Backend(RESULTS, "state/index/", env.clients.s3), salt)
    idx = indexes.open("s3:example-connect-data/")
    assert idx.rows == 3
    row = idx.get("a/two.pdf")
    assert row is not None and row.profile.reader_names() == {"pdf"}
    jpg = idx.get("a/three.jpg")
    assert jpg is not None and jpg.profile.unread == ("image",) and jpg.profile.skip == "image"
    # A second run keeps the salt and the rows.
    assert env.run(config()) is not None
    assert env.state()["indexSalt"] == salt
    assert (
        Indexes(S3Backend(RESULTS, "state/index/", env.clients.s3), salt)
        .open("s3:example-connect-data/")
        .rows
        == 3
    )


def test_object_index_off_writes_no_index(env: Env) -> None:
    env.put("a/one.txt", "hello")
    assert env.run(config(object_index=False)) is not None
    listed = env.clients.s3.list_objects_v2(Bucket=RESULTS, Prefix="state/index/")
    assert not listed.get("Contents")
    assert "indexSalt" not in env.state()


def test_size_per_million_objects_is_bounded() -> None:
    """The documented size: bytes a row, gzipped, measured on 20,000 made-up keys with
    listing fingerprints; the million-object figure in docs/ARCHITECTURE.md is this times
    a million."""
    backend = MemoryBackend()
    idx = ObjectIndex(backend, "src-x", Hasher(SALT))
    profiles = [
        profile_for(MANIFEST, "s3", readers=(r,), detected=t)
        for r, t in (("text", "text"), ("pdf", "pdf"), ("docx", "docx"), ("columnar", "parquet"))
    ]
    n = 20_000
    for i in range(n):
        idx.put(
            f"exports/2026/09/{i:08d}/part-{i:05d}.csv",
            profile=profiles[i % len(profiles)],
            marker=f'"{i:032x}"|{i}|2026-09-29T00:00:00+00:00',
            fingerprint=f"md5:{i:032x}",
            flags=TEXT,
            generation=1,
        )
    idx.save()
    size = sum(len(v) for v in backend.files.values())
    per_row = size / n
    assert per_row < 40, per_row
