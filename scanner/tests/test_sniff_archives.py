"""Content, not name, decides the reader; archives and PDFs are read (#65).

The core's reader (`scan/objects.py`) on its own, then end to end through S3 (moto),
with the findings document checked against the schema. Every value is made up.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from archive_fixtures import (
    JPEG,
    PNG,
    SEVEN_Z,
    encrypted,
    locked_pdf,
    pdf,
    tar_bz2,
    tar_gz,
    tar_of,
    xz,
    zip_of,
)
from aws_fixtures import DATA, Env, config, shared_detector
from office_fixtures import OLE, docx, xlsx
from sensitive_data_core.findings import Coverage
from sensitive_data_core.scan import objects
from sensitive_data_core.scan.objects import ObjectResult, archive_fields, read_object, record
from sensitive_data_core.scan.sniff import SNIFF_BYTES, compatible, declared, looks_text, sniff
from synthetic import CARDS, SSN_A, SSN_B, dashed, printed
from test_streams import valid

DETECTOR = shared_detector()
CSV = f"name,ssn\nA,{dashed(SSN_A)}\n".encode()


def read(name: str, data: bytes, **kw: Any) -> ObjectResult:
    calls: list[tuple[int, int]] = []

    def fetch(start: int, end: int) -> bytes:
        calls.append((start, end))
        return data[start : end + 1]

    got = read_object(
        name,
        len(data),
        fetch,
        DETECTOR,
        max_object_bytes=kw.get("max_object_bytes", 20 * 1024**2),
        max_inflated_bytes=kw.get("max_inflated_bytes", 100 * 1024**2),
        max_rows=100,
        columnar=kw.get("columnar", False),
    )
    got.calls = calls  # type: ignore[attr-defined]
    return got


def classes(got: ObjectResult) -> set[str]:
    out = set(got.item.findings) if got.item else set()
    for e in got.entries:
        if e.item:
            out |= set(e.item.findings)
    return out


def by_path(got: ObjectResult) -> dict[str, set[str]]:
    return {e.path: set(e.item.findings) if e.item else set() for e in got.entries}


# ------------------------------------------------------------------ sniffing


def test_the_first_bytes_name_the_kind() -> None:
    assert sniff(docx(["x"])) == "zip"
    assert sniff(OLE) == "ole"
    assert sniff(pdf(["x"])) == "pdf"
    assert sniff(tar_gz({"a": b"x"})) == "gzip"
    assert sniff(tar_of({"a": b"x"})) == "tar"
    assert sniff(tar_bz2({"a": b"x"})) == "bzip2"
    assert sniff(xz(b"x")) == "xz"
    assert sniff(b"(\xb5/\xfd\x00") == "zstd"
    assert sniff(SEVEN_Z) == "7z"
    assert sniff(b"PAR1\x00\x00") == "parquet"
    assert sniff(b"PARE\x00\x00") == "parquet_encrypted"
    assert sniff(JPEG) == "image" and sniff(PNG) == "image"
    assert sniff(b"RIFF\x24\x00\x00\x00WAVEfmt ") == "audio"
    assert sniff(b"\x00\x00\x00\x18ftypmp42\x00\x00") == "video"
    assert sniff(b"\x7fELF\x02\x01\x01\x00") == "binary"
    assert sniff("Grüße, name,ssn\n".encode()) == "text"
    assert sniff(b"BZh9 is how the note starts, not a bzip2 stream") == "text"
    assert sniff(b"BMW notes: nothing else") == "text"
    assert not looks_text(bytes(range(128, 256)) * 4)


def test_what_a_name_claims_and_when_it_is_a_disguise() -> None:
    assert declared("a/b.DOCX") == "docx" and declared("x.fff") == "unknown"
    assert declared("part-00000") is None and declared("x.tar.gz") == "gzip"
    assert compatible("zip", "docx") and compatible("docx", "ole")
    assert compatible(None, "parquet") and compatible("unknown", "text")
    assert compatible("audio", "video") and compatible("text", "binary")
    assert not compatible("unknown", "docx") and not compatible("image", "docx")
    assert not compatible("text", "zip") and not compatible("docx", "text")


# ------------------------------------------------------------------ disguised


@pytest.mark.parametrize(("name", "claim"), [("notes.fff", "unknown"), ("photo.jpg", "image")])
def test_a_renamed_word_document_is_read_and_marked_disguised(name: str, claim: str) -> None:
    got = read(name, docx([f"Please charge card {printed(CARDS['visa'])}"]))
    assert got.skipped is None and got.item is not None
    assert got.item.format == "docx"
    assert "card" in classes(got)
    assert got.disguise is not None
    assert got.disguise.facts() == {
        "disguised": True,
        "declaredType": claim,
        "detectedType": "docx",
    }
    assert got.disguised == 1


def test_a_disguise_is_counted_even_when_nothing_is_found() -> None:
    got = read("readme.txt", PNG)  # an image named as text: counted by what it is
    assert (got.skipped, got.disguised) == ("image", 1)
    cov = Coverage("s3", "b")
    assert record(got, cov, resource_for=lambda _c: {}, link=None, seen_at="t") is None
    assert (cov.disguised, cov.skipped, cov.as_json()["disguised"]) == (1, {"image": 1}, 1)


def test_a_genuine_jpeg_is_not_read_past_its_sniff() -> None:
    big = JPEG + bytes(2 * 1024 * 1024)
    got = read("photo.jpg", big)
    assert (got.skipped, got.disguised, got.partial) == ("image", 0, False)
    assert got.calls == [(0, SNIFF_BYTES - 1)]  # type: ignore[attr-defined]
    assert got.read == SNIFF_BYTES
    assert objects.planned_bytes("photo.jpg", len(big), 20 * 1024**2) == SNIFF_BYTES


def test_a_gzip_named_as_text_and_text_named_gzip_are_read_by_content() -> None:
    import gzip as gz

    got = read("app.log", gz.compress(CSV))
    assert "us_ssn" in classes(got) and got.disguise is not None
    plain = read("export.csv.gz", CSV)
    assert "us_ssn" in classes(plain)
    assert plain.disguise is not None and plain.disguise.detected == "text"


# ------------------------------------------------------------------ archives


def test_a_zip_a_zip_in_a_zip_and_a_tar_gz_are_read_by_entry() -> None:
    inner = zip_of({"deep/cards.txt": f"card {CARDS['mastercard']}".encode()})
    outer = zip_of({"people.csv": CSV, "nested/inner.zip": inner, "logo.png": PNG})
    got = read("bundle.zip", outer)
    assert got.format == "zip" and got.skipped is None
    assert by_path(got) == {
        "people.csv": {"us_ssn"},
        "nested/inner.zip!/deep/cards.txt": {"card"},
    }
    assert got.inner_skipped == {"image": 1}
    tgz = read("backup.tar.gz", tar_gz({"etc/app.env": f"CARD={CARDS['amex']}\n".encode()}))
    assert by_path(tgz) == {"etc/app.env": {"card"}}
    tbz = read("backup.tbz2", tar_bz2({"x.json": f'{{"ssn": "{dashed(SSN_B)}"}}'.encode()}))
    assert by_path(tbz) == {"x.json": {"us_ssn"}}
    one = read("export.csv.xz", xz(CSV))
    assert one.item is not None and "us_ssn" in classes(one) and not one.entries


def test_entries_are_routed_like_objects_disguises_included() -> None:
    got = read(
        "docs.zip",
        zip_of({"scan.jpg": docx([f"ssn {dashed(SSN_A)}"]), "report.pdf": pdf(["no values"])}),
    )
    (entry,) = [e for e in got.entries if e.path == "scan.jpg"]
    assert entry.item is not None and entry.item.format == "docx"
    assert entry.disguise is not None and entry.disguise.declared == "image"
    assert got.disguised == 1
    assert {e.path for e in got.entries} == {"scan.jpg", "report.pdf"}


def test_an_archive_nested_past_the_depth_is_counted_and_partial() -> None:
    level = zip_of({"leaf.txt": f"ssn {dashed(SSN_A)}".encode()})
    for n in range(4):
        level = zip_of({f"level{n}.zip": level})
    got = read("deep.zip", level)
    assert got.partial and not got.entries
    assert got.inner_skipped == {"archive": 1}
    three = zip_of({"a.zip": zip_of({"b.zip": zip_of({"leaf.txt": CSV})})})
    assert by_path(read("ok.zip", three)) == {"a.zip!/b.zip!/leaf.txt": {"us_ssn"}}


def test_the_zip_bomb_guard_and_the_caps_make_a_read_partial() -> None:
    # 40 MiB of text that deflates about a thousand to one: cut at the ratio, partial.
    bomb = zip_of({"a.txt": b"A" * (40 * 1024 * 1024), "people.csv": CSV})
    assert len(bomb) < 100 * 1024
    got = read("bomb.zip", bomb)
    assert got.partial
    (a,) = [e for e in got.entries if e.path == "a.txt"]
    assert a.item is not None  # read up to the ratio: 200 times its compressed size
    # Binary of the same size is sniffed and counted without inflating it.
    zeros = read("zeros.zip", zip_of({"zeros.bin": bytes(40 * 1024 * 1024)}))
    assert (zeros.inner_skipped, zeros.partial) == ({"binary": 1}, False)
    assert by_path(got) == {"a.txt": set(), "people.csv": {"us_ssn"}}  # past the bomb, still read
    # The inflated total across the object is capped.
    capped = read("bomb.zip", bomb, max_inflated_bytes=64 * 1024)
    assert capped.partial and "people.csv" not in by_path(capped)
    # Entries per archive.
    many = zip_of({f"f{i}.txt": b"hello" for i in range(8)} | {"z.csv": CSV})
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(objects, "MAX_ENTRIES", 3)
        few = read("many.zip", many)
    assert few.partial and len(few.entries) == 3


def test_encrypted_zips_and_7z_are_counted() -> None:
    plain = zip_of({"a.csv": CSV, "b.txt": f"card {CARDS['jcb']}".encode()})
    whole = read("locked.zip", encrypted(plain))
    assert (whole.skipped, whole.entries) == ("encrypted", [])
    part = read("half.zip", encrypted(plain, only="a.csv"))
    assert part.inner_skipped == {"encrypted": 1}
    assert by_path(part) == {"b.txt": {"card"}}
    assert read("x.7z", SEVEN_Z).skipped == "archive_unsupported"


def test_nothing_is_ever_extracted_zipslip_included(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("extracted to disk")

    for cls, names in ((zipfile.ZipFile, ("extract", "extractall")),
                       (tarfile.TarFile, ("extract", "extractall"))):  # fmt: skip
        for n in names:
            monkeypatch.setattr(cls, n, refuse)
    monkeypatch.chdir(tmp_path)
    evil = zip_of({"../../escape.csv": CSV, "/abs/root.txt": f"card {CARDS['visa']}".encode()})
    got = read("evil.zip", evil)
    assert by_path(got) == {"../../escape.csv": {"us_ssn"}, "/abs/root.txt": {"card"}}
    tgot = read("evil.tar", tar_of({"../escape.csv": CSV}))
    assert by_path(tgot) == {"../escape.csv": {"us_ssn"}}
    assert os.listdir(tmp_path) == []
    assert not (tmp_path.parent.parent / "escape.csv").exists()


def test_a_large_zip_is_read_through_ranged_fetches() -> None:
    import random

    noise = random.Random(3).randbytes(600 * 1024)  # noqa: S311 - incompressible padding
    big = zip_of({"noise.bin": noise, "people.csv": CSV})
    got = read("big.zip", big)
    assert by_path(got) == {"people.csv": {"us_ssn"}}
    calls = got.calls  # type: ignore[attr-defined]
    assert calls[0] == (0, SNIFF_BYTES - 1)
    # The binary entry is sniffed, not inflated: most of the object is never fetched.
    assert got.read < len(big) // 4
    assert got.inner_skipped == {"binary": 1}
    # The byte cap falls before the directory: counted as an archive not read, partial.
    cut = read("big.zip", big, max_object_bytes=16 * 1024)
    assert (cut.skipped, cut.partial) == ("archive", True)


# ------------------------------------------------------------------ PDF


def test_pdf_text_is_read_and_scans_encryption_are_counted() -> None:
    doc = pdf(["Statement", f"Card on file {printed(CARDS['discover'])}"])
    got = read("statement.pdf", doc)
    assert got.item is not None and got.item.format == "pdf" and "card" in classes(got)
    assert read("scan.pdf", pdf([], text=False)).skipped == "pdf_image_only"
    assert read("locked.pdf", locked_pdf(doc, user="made-up-pw")).skipped == "encrypted"
    # A PDF encrypted only for its permissions (an empty user password) opens: it is read.
    open_ = read("perms.pdf", locked_pdf(doc, user=""))
    assert "card" in classes(open_)
    assert read("broken.pdf", b"%PDF-1.7 made up").skipped == "document"
    # Renamed, and inside an archive.
    named = read("statement.txt", doc)
    assert "card" in classes(named) and named.disguise is not None
    assert by_path(read("docs.zip", zip_of({"s.pdf": doc}))) == {"s.pdf": {"card"}}


def test_pdf_document_information_is_read() -> None:
    got = read("x.pdf", pdf(["nothing here"], info={"Subject": f"ssn {dashed(SSN_B)}"}))
    assert "us_ssn" in classes(got)


# ------------------------------------------------------------------ findings


def test_entry_findings_name_the_entry_masked_and_carry_the_disguise() -> None:
    assert archive_fields("a/b.csv", "3") == {"archivePath": "a/b.csv"}
    masked = archive_fields(f"x/{SSN_A}.csv", "3/1")
    assert masked == {
        "archivePath": "x/#########.csv",
        "archivePathMasked": True,
        "archiveEntry": "3/1",
    }
    got = read("pack.jpg", zip_of({f"hr/{SSN_B}.csv": CSV, "ok.csv": CSV}))
    cov = Coverage("s3", "b")
    findings = record(
        got,
        cov,
        resource_for=lambda c: {"type": "s3_object", "key": "pack.jpg", "column": c},
        link=None,
        seen_at="2026-09-30T00:00:00+00:00",
    )
    assert findings is not None and len(findings) == 2
    paths = sorted(f["resource"]["archivePath"] for f in findings)
    assert paths == ["hr/#########.csv", "ok.csv"]
    assert all(f["disguised"] and f["detectedType"] == "zip" for f in findings)
    assert all(f["declaredType"] == "image" for f in findings)
    assert len({f["id"] for f in findings}) == 2
    assert (cov.scanned, cov.formats, cov.disguised) == (1, {"zip": 1}, 1)


def test_s3_reads_disguised_files_archives_and_pdfs(env: Env) -> None:
    env.put("drop/notes.fff", docx([f"card {printed(CARDS['visa'])}"]))
    env.put("drop/holiday.jpg", xlsx([["name", "ssn"], ["A", dashed(SSN_A)]]))
    env.put("drop/real.jpg", JPEG)
    env.put(
        "backups/site.tar.gz", tar_gz({"app/config.json": f'{{"card":"{CARDS["jcb"]}"}}'.encode()})
    )
    env.put("backups/bundle.zip", zip_of({"in/inner.zip": zip_of({"s.csv": CSV})}))
    env.put("backups/locked.zip", encrypted(zip_of({"a.csv": CSV})))
    env.put("docs/statement.pdf", pdf([f"Card {printed(CARDS['amex'])}"]))
    env.put("docs/scan.pdf", pdf([], text=False))
    env.put("docs/locked.pdf", locked_pdf(pdf(["x"]), user="made-up-pw"))
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    found = {(f["resource"]["key"], f["resource"].get("archivePath"), f["class"]): f
             for f in doc["findings"]}  # fmt: skip
    assert set(found) == {
        ("drop/notes.fff", None, "card"),
        ("drop/holiday.jpg", None, "us_ssn"),
        ("backups/site.tar.gz", "app/config.json", "card"),
        ("backups/bundle.zip", "in/inner.zip!/s.csv", "us_ssn"),
        ("docs/statement.pdf", None, "card"),
    }
    fff = found[("drop/notes.fff", None, "card")]
    assert (fff["disguised"], fff["declaredType"], fff["detectedType"]) == (True, "unknown", "docx")
    jpg = found[("drop/holiday.jpg", None, "us_ssn")]
    assert (jpg["format"], jpg["declaredType"], jpg["detectedType"]) == ("xlsx", "image", "xlsx")
    assert "disguised" not in found[("docs/statement.pdf", None, "card")]
    cov = doc["coverage"][0]
    assert cov["disguised"] == 2
    assert cov["skipped"] == {"image": 1, "encrypted": 2, "pdf_image_only": 1}
    assert cov["formats"] == {"docx": 1, "xlsx": 1, "tar": 1, "zip": 1, "pdf": 1}
    assert "discovery" not in doc  # a configured target: no run summary here


def test_the_run_summary_counts_disguised_objects(env: Env) -> None:
    from test_discovery import stores

    env.put("a/readme.txt", PNG)  # an image named as text: nothing found, still counted
    env.put("a/notes.fff", docx(["nothing here"]))
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    s = stores(doc)[("s3", DATA)]
    assert s["gaps"] == {"disguised": 2, "unsupportedFormat": 1}


def test_the_new_skip_kinds_and_fields_are_in_the_schema() -> None:
    import json

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schema/findings.schema.json").read_text()
    )
    skipped = schema["$defs"]["coverage"]["properties"]["skipped"]["propertyNames"]["enum"]
    assert {"archive_unsupported", "pdf_image_only", "encrypted"} <= set(skipped)
    assert "pdf" in schema["$defs"]["finding"]["properties"]["format"]["enum"]
    kinds = set(schema["$defs"]["contentKind"]["enum"])
    from sensitive_data_core.scan.sniff import KINDS, UNKNOWN

    assert kinds == KINDS | {UNKNOWN}


def test_reprs_hold_no_entry_path() -> None:
    got = read("a.zip", zip_of({f"{SSN_A}.csv": CSV}))
    assert SSN_A not in repr(got) and SSN_A not in repr(got.entries)


def test_a_damaged_entry_costs_only_itself() -> None:
    got = read("mixed.zip", zip_of({"bad.avro": b"Obj\x01" + b"\xff" * 64, "people.csv": CSV}))
    assert got.partial
    assert by_path(got) == {"people.csv": {"us_ssn"}}
