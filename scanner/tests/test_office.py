"""The core's Office Open XML reader (#21 step 6): Word, Excel and PowerPoint as text.

Every value is made up.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from aws_fixtures import shared_detector
from office_fixtures import OLE, docx, pptx, with_dtd, xlsx
from sensitive_data_core.scan.objects import read_object, skip_kind
from sensitive_data_core.scan.office import OfficeUnreadable, office_kind, office_text
from synthetic import CARDS, SSN_A, dashed, printed

DETECTOR = shared_detector()


def read(name: str, data: bytes, **kw: int) -> object:
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
        columnar=False,
    )
    got.calls = calls  # type: ignore[attr-defined]
    return got


def classes(got: object) -> set[str]:
    item = got.item  # type: ignore[attr-defined]
    assert item is not None
    return set(item.findings)


def test_office_files_are_read_not_skipped() -> None:
    for name in ("a.docx", "b.XLSX", "c.pptx", "d.docm", "e.xlsm"):
        assert office_kind(name) is not None
        assert skip_kind(name) is None
    for name in ("a.doc", "b.xls", "c.ppt", "d.pdf"):
        assert office_kind(name) is None
        assert skip_kind(name) == "document"


def test_word_excel_and_powerpoint_give_their_text() -> None:
    got = read(
        "memo.docx",
        docx(
            [f"Please charge card {printed(CARDS['visa'])}", "thanks"],
            comments=[f"SSN on file: {dashed(SSN_A)}"],
        ),
    )
    assert got.item.format == "docx"  # type: ignore[attr-defined]
    assert {"card", "us_ssn"} <= classes(got)
    sheet = read("roster.xlsx", xlsx([["name", "card_number"], ["A", CARDS["mastercard"]]]))
    assert sheet.item.format == "xlsx"  # type: ignore[attr-defined]
    assert "card" in classes(sheet)
    inline = read("inline.xlsx", xlsx([["ssn"], [dashed(SSN_A)]], shared=False))
    assert "us_ssn" in classes(inline)
    deck = read("deck.pptx", pptx(["Q3", f"test card {printed(CARDS['amex'])}"]))
    assert deck.item.format == "pptx"  # type: ignore[attr-defined]
    assert "card" in classes(deck)


def test_a_dtd_is_never_expanded_and_encryption_is_counted() -> None:
    got = read("x.docx", with_dtd())
    assert got.item is not None and got.item.findings == {}  # type: ignore[attr-defined]
    enc = read("locked.docx", OLE)
    assert enc.skipped == "encrypted"  # type: ignore[attr-defined]
    bad = read("not-a-zip.xlsx", b"just some text, not a zip at all")
    assert bad.skipped == "document"  # type: ignore[attr-defined]


def test_the_zip_is_read_through_ranged_fetches_within_the_caps() -> None:
    big = docx([f"line {i}" for i in range(2000)] + [f"card {printed(CARDS['visa'])}"])
    got = read("big.docx", big)
    assert all(end - start < len(big) for start, end in got.calls)  # type: ignore[attr-defined]
    # The inflated text is capped: the part cut short is not parsed, and the file is partial.
    capped = read("big.docx", big, max_inflated_bytes=1024)
    assert capped.partial  # type: ignore[attr-defined]
    # A byte cap below the central directory: counted as a document not read.
    cut = read("big.docx", big, max_object_bytes=64)
    assert cut.skipped == "document"  # type: ignore[attr-defined]


def test_office_text_refuses_what_is_not_office() -> None:
    with pytest.raises(OfficeUnreadable):
        office_text("docx", io.BytesIO(b"nope"), max_inflated_bytes=1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<not-closed")
    got = office_text("docx", io.BytesIO(buf.getvalue()), max_inflated_bytes=1024)
    assert got.text == "" and "chars=0" in repr(got)
