"""Smart rescans (#67 part 2): an unchanged object is read again only when a component it
was read with changed and could change its result, within a capped share, and says why.

A changed component is a manifest with that component's version moved (`bumped`), as a
build with a changed reader, adapter, sniffer or spec would have. Every value is made up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from archive_fixtures import JPEG, SEVEN_Z, pdf, zip_of
from aws_fixtures import DATA, Env, config
from office_fixtures import docx
from sensitive_data_core.adapter import Budget
from sensitive_data_core.index import (
    ADAPTER,
    CONVERSATION,
    DISGUISED,
    NEW_READER,
    READER,
    SNIFFER,
    SPEC_CONVERSATION,
    SPEC_STANDALONE,
    TEXT,
    UNINDEXED,
    Indexes,
    Manifest,
    MemoryBackend,
    ObjectPass,
    Rescans,
    Stale,
    profile_for,
    stale,
)
from sensitive_data_core.scan.objects import ObjectResult, read_object
from synthetic import CARDS, SSN_A, dashed, printed

BASE = Manifest.load()
SALT = "0" * 32
BUMP = "f" * 12


def bumped(
    *names: str, add: dict[str, str] | None = None, kinds: dict[str, list[str]] | None = None
) -> Manifest:
    """This build's manifest with the named components' versions moved (a changed reader,
    adapter, sniffer or spec), components added (a new class, a new reader)."""
    for n in names:
        assert n in BASE.components, n
    comps = {**BASE.components, **dict.fromkeys(names, BUMP), **(add or {})}
    rk = {**BASE.reader_kinds, **{k: tuple(v) for k, v in (kinds or {}).items()}}
    return Manifest(comps, rk)


def use(monkeypatch: pytest.MonkeyPatch, manifest: Manifest) -> None:
    """Every run from here on is a build with `manifest`."""
    monkeypatch.setattr(Manifest, "load", classmethod(lambda cls: manifest))


def read(name: str, data: bytes) -> ObjectResult:
    from aws_fixtures import shared_detector

    return read_object(
        name,
        len(data),
        lambda s, e: data[s : e + 1],
        shared_detector(),
        max_object_bytes=1024**2,
        max_inflated_bytes=4 * 1024**2,
        max_rows=100,
        columnar=False,
    )


CHAT = json.dumps(
    {
        "Version": "2019-08-26",
        "ContactId": "c-1",
        "Participants": [
            {"ParticipantId": "a", "ParticipantRole": "AGENT"},
            {"ParticipantId": "c", "ParticipantRole": "CUSTOMER"},
        ],
        "Transcript": [
            {
                "ParticipantId": "a",
                "ParticipantRole": "AGENT",
                "Content": "What is your card number?",
                "Type": "MESSAGE",
            },
            {
                "ParticipantId": "c",
                "ParticipantRole": "CUSTOMER",
                "Content": printed(CARDS["visa"]),
                "Type": "MESSAGE",
            },
        ],
    }
).encode()

OBJECTS: dict[str, bytes] = {
    "a/notes.txt": f"card {printed(CARDS['visa'])}".encode(),
    "a/report.pdf": pdf([f"ssn {dashed(SSN_A)}"]),
    "a/letter.docx": docx([f"card {printed(CARDS['amex'])}"]),
    "a/photo.jpg": JPEG,
    "a/bundle.7z": SEVEN_Z,
    "a/chat.json": CHAT,
    "a/disguised.jpg": docx(["nothing here"]),
    "a/blob.bin": bytes(range(256)) * 4,
}


# ------------------------------------------------------------------ the rules


def _profiles() -> dict[str, tuple[Any, int]]:
    out = {}
    for name, data in OBJECTS.items():
        got = read(name, data)
        from sensitive_data_core.index import flags_for

        out[name] = (profile_for(BASE, "s3", got), flags_for(got))
    return out


PROFILES = _profiles()


def verdicts(manifest: Manifest, *, columnar: bool = False) -> dict[str, Stale | None]:
    return {
        name: stale(prof, fl, manifest, columnar=columnar) for name, (prof, fl) in PROFILES.items()
    }


def reasons(manifest: Manifest, **kw: Any) -> dict[str, str]:
    return {k: v.reason for k, v in verdicts(manifest, **kw).items() if v is not None}


def test_nothing_is_stale_under_the_build_it_was_read_with() -> None:
    assert reasons(BASE) == {}


def test_an_adapter_change_touches_only_that_adapters_objects() -> None:
    assert set(reasons(bumped("adapter:s3"))) == set(OBJECTS)
    assert reasons(bumped("adapter:s3"))["a/notes.txt"] == ADAPTER
    assert reasons(bumped("adapter:azure_blob", "adapter:m365_sharepoint", "adapter:gcs")) == {}


def test_a_reader_change_touches_only_what_it_read() -> None:
    assert reasons(bumped("reader:pdf")) == {"a/report.pdf": READER}
    assert reasons(bumped("reader:docx")) == {"a/letter.docx": READER, "a/disguised.jpg": READER}
    assert reasons(bumped("reader:transcript")) == {"a/chat.json": READER}
    # An archive is read by its own reader and its entries' readers.
    got = read("pack.zip", zip_of({"r.pdf": pdf(["x"]), "n.txt": b"hello"}))
    prof = profile_for(BASE, "s3", got)
    assert stale(prof, TEXT, bumped("reader:pdf"), columnar=False) == Stale(READER)
    assert stale(prof, TEXT, bumped("reader:archive-zip"), columnar=False) == Stale(READER)
    assert stale(prof, TEXT, bumped("reader:docx"), columnar=False) is None


def test_a_new_reader_touches_what_had_no_reader_for_its_kind() -> None:
    seven = bumped(add={"reader:archive-7z": "a" * 12}, kinds={"archive-7z": ["7z"]})
    assert reasons(seven) == {"a/bundle.7z": NEW_READER}
    ocr = bumped(add={"reader:ocr": "b" * 12}, kinds={"ocr": ["image"]})
    assert reasons(ocr) == {"a/photo.jpg": NEW_READER}
    # Parquet read by a build without pyarrow (the Lambda zip) is read when pyarrow is there.
    import io

    import pyarrow as pa
    import pyarrow.parquet as pq

    buf = io.BytesIO()
    pq.write_table(pa.table({"card_number": [CARDS["visa"]]}), buf)
    got = read("t.parquet", buf.getvalue())
    assert got.unread == {"parquet"} and got.skipped == "columnar"
    prof = profile_for(BASE, "s3", got)
    assert stale(prof, 0, BASE, columnar=False) is None
    assert stale(prof, 0, BASE, columnar=True) == Stale(NEW_READER)


def test_a_sniffer_change_touches_undetermined_or_disputed_objects() -> None:
    assert reasons(bumped("sniffer")) == {"a/blob.bin": SNIFFER, "a/disguised.jpg": SNIFFER}
    assert PROFILES["a/disguised.jpg"][1] & DISGUISED


def test_a_standalone_spec_change_touches_text_bearing_objects() -> None:
    engine = reasons(bumped("spec-standalone"))
    text_bearing = {"a/notes.txt", "a/report.pdf", "a/letter.docx", "a/chat.json"}
    assert set(engine) == text_bearing | {"a/disguised.jpg"}
    assert set(engine.values()) == {SPEC_STANDALONE}
    one = verdicts(bumped("spec-standalone/card"))
    assert one["a/notes.txt"] == Stale(SPEC_STANDALONE, ("card",))
    assert one["a/photo.jpg"] is None and one["a/bundle.7z"] is None


def test_a_new_class_touches_text_bearing_objects_and_is_named() -> None:
    new = verdicts(bumped(add={"spec-standalone/passport": "c" * 12}))
    assert new["a/report.pdf"] == Stale(SPEC_STANDALONE, ("passport",))
    assert new["a/notes.txt"] == Stale(SPEC_STANDALONE, ("passport",))
    assert new["a/photo.jpg"] is None and new["a/blob.bin"] is None


def test_a_conversation_spec_change_touches_transcripts_only() -> None:
    assert reasons(bumped("spec-conversation")) == {"a/chat.json": SPEC_CONVERSATION}
    assert PROFILES["a/chat.json"][1] & CONVERSATION


def test_the_first_rule_that_applies_is_the_reason() -> None:
    both = bumped("adapter:s3", "reader:pdf", "spec-standalone")
    assert reasons(both)["a/report.pdf"] == ADAPTER
    assert reasons(bumped("reader:pdf", "spec-standalone"))["a/report.pdf"] == READER


def test_rescans_take_a_capped_share_and_leave_the_rest_as_backlog() -> None:
    budget = Budget(100, 10_000, float("inf"))
    r = Rescans(budget, 10)
    assert r.cap_items == 10
    for i in range(25):
        r.offer(i, Stale(READER))
    assert len(r.queue) == 10 and r.left == {READER: 15}
    got = [c for c, _ in r.drain(budget, lambda _: 100)]
    assert got == list(range(10)) and budget.items == 10
    assert Rescans(budget, 0).cap_items == 0
    # A byte cap stops the drain too; what it did not reach is backlog.
    small = Rescans(Budget(100, 1000, float("inf")), 50)
    for i in range(5):
        small.offer(i, Stale(UNINDEXED))
    # 500 bytes for rescans: the first always fits, the second would pass the cap.
    assert len(list(small.drain(Budget(100, 1000, float("inf")), lambda _: 300))) == 1
    assert small.left == {UNINDEXED: 4}


def test_decisions_by_the_index() -> None:
    backend = MemoryBackend()
    idx = Indexes(backend, SALT)
    op = ObjectPass(idx, "s3:b/", "s3", budget=Budget(100, 10**9, float("inf")))
    op.record("k", marker="m1", got=read("k.pdf", OBJECTS["a/report.pdf"]))
    assert op.decide("k", changed=True).read
    assert op.decide("k", changed=False, marker="m1").action == "skip"
    assert op.decide("k", changed=False, marker="m2").read  # the marker says it changed
    assert op.decide("new", changed=False).why == Stale(UNINDEXED)
    op.record("bad", marker="m", unreadable=True)
    assert op.decide("bad", changed=False, marker="m").action == "skip"
    idx.save()
    later = Indexes(backend, SALT, manifest=bumped("reader:pdf"))
    op2 = ObjectPass(later, "s3:b/", "s3", budget=Budget(100, 10**9, float("inf")))
    assert op2.decide("k", changed=False, marker="m1").why == Stale(READER)
    assert op2.stale_rows() == 1
    # Without an index, a pass decides as before: by the change at the source only.
    plain = ObjectPass(None, "s3:b/", "s3")
    assert plain.decide("k", changed=False).action == "skip"
    assert plain.decide("k", changed=True).read


# ------------------------------------------------------------------ S3, end to end


def gets(env: Env) -> list[str]:
    """Every GetObject on the data bucket, by key, from here on."""
    keys: list[str] = []

    def count(params: dict[str, Any], **_: Any) -> None:
        if params.get("Bucket") == DATA:
            keys.append(params["Key"])

    env.clients.s3.meta.events.register("provide-client-params.s3.GetObject", count)
    return keys


def s3_coverage(doc: dict[str, Any]) -> dict[str, Any]:
    return next(c for c in doc["coverage"] if c["kind"] == "s3")


def seeded(env: Env) -> dict[str, Any]:
    for k, v in OBJECTS.items():
        env.put(k, v)
    doc = env.run(config())
    assert doc is not None
    return doc


def test_unchanged_objects_are_not_read_again(env: Env) -> None:
    first = seeded(env)
    assert s3_coverage(first)["indexed"] == len(OBJECTS)
    read_keys = gets(env)
    again = env.run(config())
    assert again is not None
    assert read_keys == []
    cov = s3_coverage(again)
    assert (cov["scanned"], cov["rescanned"], cov["rescanBacklog"]) == (0, {}, 0)
    assert {f["id"] for f in again["findings"]} == {f["id"] for f in first["findings"]}
    assert not any("rescanReason" in f for f in again["findings"])


def test_a_pdf_reader_change_rescans_only_pdfs(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    seeded(env)
    use(monkeypatch, bumped("reader:pdf"))
    read_keys = gets(env)
    doc = env.run(config())
    assert doc is not None
    assert set(read_keys) == {"a/report.pdf"}
    cov = s3_coverage(doc)
    assert cov["rescanned"] == {READER: 1} and cov["rescanBacklog"] == 0
    pdf_findings = [f for f in doc["findings"] if f["resource"]["key"] == "a/report.pdf"]
    assert pdf_findings and all(f["rescanReason"] == READER for f in pdf_findings)
    assert not any(
        "rescanReason" in f for f in doc["findings"] if f["resource"]["key"] != "a/report.pdf"
    )
    # Read with the new reader, it is current: the next run reads nothing.
    read_keys.clear()
    assert env.run(config()) is not None and read_keys == []


def test_an_adapter_change_rescans_that_adapters_objects_only(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeded(env)
    use(monkeypatch, bumped("adapter:azure_blob", "adapter:gcs", "adapter:dynamodb"))
    read_keys = gets(env)
    assert env.run(config()) is not None
    assert read_keys == []
    use(monkeypatch, bumped("adapter:s3"))
    doc = env.run(config())
    assert doc is not None
    assert set(read_keys) == set(OBJECTS)
    assert s3_coverage(doc)["rescanned"] == {ADAPTER: len(OBJECTS)}


def test_a_new_class_rescans_text_bearing_objects(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeded(env)
    use(monkeypatch, bumped(add={"spec-standalone/passport": "c" * 12}))
    read_keys = gets(env)
    doc = env.run(config())
    assert doc is not None
    text_bearing = {"a/notes.txt", "a/report.pdf", "a/letter.docx", "a/chat.json"}
    assert set(read_keys) == text_bearing | {"a/disguised.jpg"}
    assert s3_coverage(doc)["rescanned"] == {SPEC_STANDALONE: 5}
    for f in doc["findings"]:
        assert f["rescanReason"] == SPEC_STANDALONE and f["rescanClasses"] == ["passport"]


def test_a_conversation_spec_change_rescans_transcripts_only(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeded(env)
    use(monkeypatch, bumped("spec-conversation"))
    read_keys = gets(env)
    doc = env.run(config())
    assert doc is not None
    assert read_keys and set(read_keys) == {"a/chat.json"}
    assert s3_coverage(doc)["rescanned"] == {SPEC_CONVERSATION: 1}
    chat = [f for f in doc["findings"] if f["resource"]["key"] == "a/chat.json"]
    assert chat and all(f["rescanReason"] == SPEC_CONVERSATION for f in chat)


def test_a_new_reader_reads_what_was_counted_unread(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io

    import pyarrow as pa
    import pyarrow.parquet as pq

    import sensitive_data_scanner.sources.s3 as s3mod

    buf = io.BytesIO()
    pq.write_table(pa.table({"card_number": [CARDS["visa"]]}), buf)
    env.put("lake/t.parquet", buf.getvalue())
    env.put("lake/n.txt", b"hello")
    monkeypatch.setattr(s3mod, "pyarrow_available", lambda: False)  # the Lambda zip
    first = env.run(config())
    assert first is not None and s3_coverage(first)["skipped"] == {"columnar": 1}
    read_keys = gets(env)
    assert env.run(config()) is not None and read_keys == []  # still no reader for it
    monkeypatch.setattr(s3mod, "pyarrow_available", lambda: True)  # the container image
    doc = env.run(config())
    assert doc is not None
    assert read_keys == ["lake/t.parquet"] or set(read_keys) == {"lake/t.parquet"}
    assert s3_coverage(doc)["rescanned"] == {NEW_READER: 1}
    assert any(f["resource"].get("column") == "card_number" for f in doc["findings"])


def test_objects_read_before_the_index_are_read_once_more(env: Env) -> None:
    import datetime as dt

    for k in ("x/1.txt", "x/2.txt"):
        env.put(k, b"hello")
    hour = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    assert env.run(config(object_index=False), now=lambda: hour) is not None
    read_keys = gets(env)
    # Past the watermark and its skew: unchanged, but never recorded in an index.
    later = hour + dt.timedelta(hours=1)
    doc = env.run(config(), now=lambda: later)
    assert doc is not None
    assert sorted(read_keys) == ["x/1.txt", "x/2.txt"]
    assert s3_coverage(doc)["rescanned"] == {UNINDEXED: 2}
    read_keys.clear()
    assert env.run(config(), now=lambda: later) is not None and read_keys == []


def test_rescans_are_spread_across_runs_and_changes_come_first(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(20):
        env.put(f"p/{i:02d}.pdf", pdf([f"page {i}"]))
    assert env.run(config()) is not None
    use(monkeypatch, bumped("reader:pdf"))
    env.put("p/new.txt", f"card {printed(CARDS['visa'])}".encode())  # a change at the source
    read_keys = gets(env)
    # 20 items a run, a quarter of them for rescans: 5 a run.
    doc = env.run(config(max_items_per_run=20))
    assert doc is not None
    cov = s3_coverage(doc)
    assert "p/new.txt" in read_keys
    assert cov["rescanned"] == {READER: 5} and cov["rescanBacklog"] == 15
    left = [15]
    for _ in range(3):
        doc = env.run(config(max_items_per_run=20))
        assert doc is not None
        cov = s3_coverage(doc)
        assert cov["rescanned"] == {READER: 5}
        left.append(cov["rescanBacklog"])
    assert left == [15, 10, 5, 0]
    read_keys.clear()
    assert env.run(config(max_items_per_run=20)) is not None and read_keys == []


def test_rescans_off_reads_only_changes(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    seeded(env)
    use(monkeypatch, bumped("reader:pdf"))
    read_keys = gets(env)
    doc = env.run(config(rescan_percent=0))
    assert doc is not None and read_keys == []
    assert s3_coverage(doc)["rescanBacklog"] == 1


# ------------------------------------------------------------------ other platforms


def test_a_pdf_reader_change_rescans_only_pdfs_on_azure_gcs_and_sharepoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The same reader change, on every platform's object store: only the PDFs."""
    from azure_fakes import Blob
    from gcp_fakes import Obj
    from saas_fakes import HOST, Item
    from saas_fakes import settings as m365_settings
    from sensitive_data_core.state import FileState
    from test_azure_blob import run as azure_run
    from test_azure_blob import tenant
    from test_gcp_gcs import cloud
    from test_gcp_gcs import run as gcp_run
    from test_saas_m365 import files_tenant, scan

    report = pdf([f"ssn {dashed(SSN_A)}"])
    t = tenant()
    t.container("contosolake", "raw").blobs["docs/report.pdf"] = Blob(report)
    c = cloud()
    c.bucket("acme-lake").objects["docs/report.pdf"] = Obj(report)
    m = files_tenant()
    m.drives["d-lib"].add(Item("p1", "report.pdf", report))
    state = FileState(str(tmp_path / "state.json"))
    s = m365_settings(tmp_path, M365_SITES=f"{HOST}:/sites/finance", DISCOVER="sharepoint")

    def runs() -> list[dict[str, Any]]:
        return [azure_run(t), gcp_run(c), scan(m, s, state=state)]

    runs()
    unchanged = runs()
    for doc in unchanged:
        assert all(not c_.get("rescanned") for c_ in doc["coverage"])
    use(monkeypatch, bumped("reader:pdf"))
    for doc in runs():
        rescanned = [f for f in doc["findings"] if f.get("rescanReason")]
        assert rescanned, doc.get("platform")
        for f in rescanned:
            where = (
                f["resource"].get("blob") or f["resource"].get("object") or f["resource"]["name"]
            )
            assert where.endswith("report.pdf") and f["rescanReason"] == READER
        total = sum(sum(c_.get("rescanned", {}).values()) for c_ in doc["coverage"])
        assert total == 1, doc.get("platform")


def test_a_sharepoint_drive_enumerates_for_stale_files_and_resumes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A delta feed never lists an unchanged file: a stale one is found by listing every item
    again, within the cap, from where the last run stopped."""
    from saas_fakes import HOST, Item
    from saas_fakes import settings as m365_settings
    from sensitive_data_core.state import FileState
    from test_saas_m365 import files_tenant, scan

    m = files_tenant()
    for i in range(8):
        m.drives["d-lib"].add(Item(f"p{i}", f"r{i}.pdf", pdf([f"page {i}"])))
    state = FileState(str(tmp_path / "state.json"))
    s = m365_settings(
        tmp_path, M365_SITES=f"{HOST}:/sites/finance", DISCOVER="sharepoint", MAX_ITEMS_PER_RUN="8"
    )
    for _ in range(3):
        scan(m, s, state=state)  # the first pass, then the changes feed
    use(monkeypatch, bumped("reader:pdf"))
    done: list[int] = []
    for _ in range(6):
        doc = scan(m, s, state=state)
        cov = next(c for c in doc["coverage"] if c["kind"] == "m365_sharepoint")
        done.append(cov.get("rescanned", {}).get(READER, 0))
        if cov["rescanBacklog"] == 0:
            break
    assert sum(done) == 8
    assert len([d for d in done if d]) >= 2  # spread over runs, 2 a run (a quarter of 8)
    saved = json.loads((tmp_path / "state.json").read_text())
    assert all("rescan" not in c for c in saved["cursors"].values())


# ------------------------------------------------------------------ CodeCommit


def test_codecommit_reads_only_changed_blobs_and_rescans_by_file(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new head whose files have the same blobs reads nothing and keeps its findings; a
    reader change reads, at the same head, only the files that reader read."""
    from sensitive_data_core.scan.objects import sample_point
    from test_default_on import blob, repo, run, tree
    from test_streams import stubs

    cc = stubs(env, "codecommit")["codecommit"]
    files = {
        "README.md": b"Run the tests with the sample data.",
        "logo.png": b"\x89PNG\r\n\x1a\n made up",
        "fixtures/users.csv": f"name,ssn\nA,{dashed(SSN_A)}\n".encode(),
    }
    order = sorted(files, key=lambda p: (sample_point(p), p))
    repo(cc)
    tree(cc, "c1")
    for path in order:
        blob(cc, "c1", path, files[path])
    first = run(env, "codecommit")
    cc.assert_no_pending_responses()
    # A new head, the same blobs: listed, nothing fetched, the findings stay.
    repo(cc)
    tree(cc, "c2")
    second = run(env, "codecommit")
    cc.assert_no_pending_responses()
    assert {f["id"] for f in second["findings"]} == {f["id"] for f in first["findings"]}
    assert second["findings"]
    # The text reader changed: the same head is read again for its text files only.
    use(monkeypatch, bumped("reader:text"))
    repo(cc)
    tree(cc, "c2")
    for path in order:
        if path != "logo.png":
            blob(cc, "c2", path, files[path])
    third = run(env, "codecommit")
    cc.assert_no_pending_responses()
    cov = next(c for c in third["coverage"] if c["kind"] == "codecommit")
    assert cov["rescanned"] == {READER: 2} and cov["rescanBacklog"] == 0
    assert all(f["rescanReason"] == READER for f in third["findings"])


# ------------------------------------------------------------------ ECR


def test_ecr_reads_a_shared_layer_once_and_rescans_it_for_a_reader_change(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A newer image that shares a layer already read (its digest is its content's hash)
    does not download it again; a reader change downloads it once more."""
    import io

    from botocore.stub import ANY

    from test_images_archives import layer
    from test_streams import stubs

    ecr = stubs(env, "ecr")["ecr"]
    shared = "sha256:" + "a" * 64
    blob = layer({"app/config.txt": f"card {printed(CARDS['visa'])}".encode()})
    fetched: list[str] = []

    def fetch(url: str, n: int) -> Any:
        fetched.append(url)
        return io.BytesIO(blob)

    env.clients.services["layer-fetch"] = fetch

    def image(digest: str, *, download: bool) -> None:
        ecr.add_response(
            "describe_repositories",
            {"repositories": [{"repositoryName": "web", "repositoryArn": "arn:aws:ecr:x:1:r"}]},
        )
        ecr.add_response("describe_images", {"imageDetails": [{"imageDigest": digest}]})
        manifest = {
            "layers": [
                {"digest": shared, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}
            ]
        }
        ecr.add_response(
            "batch_get_image",
            {"images": [{"imageManifest": json.dumps(manifest)}]},
            {"repositoryName": ANY, "imageIds": ANY, "acceptedMediaTypes": ANY},
        )
        if download:
            ecr.add_response("get_download_url_for_layer", {"downloadUrl": "https://l.example/x"})

    def run_ecr() -> dict[str, Any]:
        doc = env.run(config(s3_targets=[], discover=frozenset({"ecr"}), ecr_read=True))
        assert doc is not None
        ecr.assert_no_pending_responses()
        return doc

    image("sha256:" + "1" * 64, download=True)
    first = run_ecr()
    assert len(fetched) == 1 and first["findings"]
    image("sha256:" + "2" * 64, download=False)  # a newer push, the same layer
    second = run_ecr()
    assert len(fetched) == 1
    assert {f["id"] for f in second["findings"]} == {f["id"] for f in first["findings"]}
    use(monkeypatch, bumped("reader:text"))
    image("sha256:" + "2" * 64, download=True)
    third = run_ecr()
    assert len(fetched) == 2
    cov = next(c for c in third["coverage"] if c["kind"] == "ecr")
    assert cov["rescanned"] == {READER: 1}
    assert all(f["rescanReason"] == READER for f in third["findings"])
