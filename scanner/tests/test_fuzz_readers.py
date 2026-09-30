"""Property-based fuzzing of the readers (#77): every object is untrusted input.

For any bytes, and for valid files of every kind with their bytes damaged (flipped,
set, inserted, deleted, cut, repeated):

- **no crash beyond the declared exceptions**. `sniff`, `csv_cells` and `scan_item_text`
  never raise. `office_text` raises only `OfficeUnreadable`. `pdf_text` raises only
  `PdfUnreadable`, `PdfEncrypted` or `ImageOnly`. `read_object` with a working fetch raises
  only for a damaged table at the top level (a Parquet, ORC or Avro file), which its
  caller counts as unreadable by the exception's name;
- **the caps hold**: bytes fetched, text inflated, rows read, a PDF's characters;
- **no value in an exception, a log line, a warning, stdout, a repr or the findings**:
  the made-up card number and SSN planted in every seed never appear there.

Runs derandomized with a few dozen examples per property in the normal test run. CI
also runs `--hypothesis-profile=fuzz` (randomized, more examples, time-capped). For a
long local run, use `--hypothesis-profile=fuzz-long`. The profiles are in `conftest.py`.
Every value is made up.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import json
import logging
import lzma
import warnings
from collections.abc import Callable, Iterator
from typing import Any
from unittest import mock

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from archive_fixtures import pdf as make_pdf
from archive_fixtures import tar_gz, zip_of
from office_fixtures import docx, pptx, xlsx
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.scan import objects
from sensitive_data_core.scan.item import csv_cells, scan_item_text
from sensitive_data_core.scan.objects import read_object, record
from sensitive_data_core.scan.office import OfficeUnreadable, office_text
from sensitive_data_core.scan.pdf import ImageOnly, PdfEncrypted, PdfUnreadable, pdf_text
from sensitive_data_core.scan.sniff import SNIFF_BYTES, looks_text, sniff
from synthetic import CARDS, SSN_A, dashed, printed

DET = Detector()
CARD = CARDS["visa"]
PLANTED = (CARD, printed(CARD), SSN_A, dashed(SSN_A))
MAX_OBJECT = 64 * 1024
MAX_INFLATED = 256 * 1024
MAX_ROWS = 200
KINDS = {
    "zip", "ole", "pdf", "gzip", "zstd", "7z", "xz", "bzip2", "tar", "parquet",
    "parquet_encrypted", "avro", "orc", "rdb", "image", "audio", "video", "text", "binary",
}  # fmt: skip
TABLES = {"parquet", "orc", "avro"}


# ---------------------------------------------------------------- seeds


def _text() -> str:
    return (
        f"Customer Testy McTestface paid with card {printed(CARD)} on 09/28/2026.\n"
        f"SSN on file: {dashed(SSN_A)}. Order 112-3456789-1234567.\n"
    )


def _transcript() -> str:
    turns = [
        ("AGENT", "What's the card number?"),
        ("CUSTOMER", printed(CARD)),
        ("AGENT", "And your social security number?"),
        ("CUSTOMER", " ".join(SSN_A)),
    ]
    return json.dumps(
        {
            "Version": "2019-08-26",
            "ContactId": "11111111-2222-3333-4444-555555555555",
            "Transcript": [
                {"Type": "MESSAGE", "Content": t, "ParticipantId": r.lower(), "ParticipantRole": r}
                for r, t in turns
            ],
        }
    )


def _parquet() -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    buf = io.BytesIO()
    table = pa.table({"name": ["Sample Notreal"] * 3, "card_number": [CARD, None, CARD]})
    pq.write_table(table, buf, row_group_size=2)
    return buf.getvalue()


def _orc() -> bytes:
    import pyarrow as pa
    from pyarrow import orc

    buf = io.BytesIO()
    orc.write_table(pa.table({"ssn": [dashed(SSN_A), "none"]}), buf)
    return buf.getvalue()


def _avro() -> bytes:
    import fastavro

    schema = {
        "type": "record",
        "name": "Row",
        "fields": [{"name": "card", "type": "string"}, {"name": "n", "type": "long"}],
    }
    buf = io.BytesIO()
    fastavro.writer(buf, fastavro.parse_schema(schema), [{"card": CARD, "n": 1}] * 3)
    return buf.getvalue()


def _seeds() -> list[tuple[str, bytes]]:
    text = _text().encode()
    inner_zip = zip_of({f"{CARD}.csv": b"card_number\n" + CARD.encode() + b"\n"})
    return [
        ("notes.txt", text),
        ("export.csv", f"name,card_number,ssn\nTesty,{CARD},{SSN_A}\n".encode()),
        (
            "doc.json",
            json.dumps({"a": {"cardNumber": CARD, "b": [SSN_A, {"ssn": SSN_A}]}}).encode(),
        ),
        ("events.jsonl", (json.dumps({"ssn": SSN_A}) + "\n" + json.dumps({"c": CARD})).encode()),
        ("chat.json", _transcript().encode()),
        ("bundle.zip", zip_of({f"hr/{SSN_A}.txt": text, "nested.zip": inner_zip})),
        ("logs.tar.gz", tar_gz({f"{CARD}.log": text, "b.txt": b"nothing here"})),
        ("app.log.gz", gzip.compress(text, mtime=0)),
        ("app.log.bz2", bz2.compress(text)),
        ("app.log.xz", lzma.compress(text)),
        ("letter.docx", docx([_text(), "Signed, Placeholder Person"])),
        ("sheet.xlsx", xlsx([["card", "ssn"], [CARD, dashed(SSN_A)]])),
        ("deck.pptx", pptx([_text()])),
        ("statement.pdf", make_pdf(_text().splitlines(), info={"Title": f"card {CARD}"})),
        ("part-0.parquet", _parquet()),
        ("part-0.orc", _orc()),
        ("part-0.avro", _avro()),
        ("dump.rdb", b"REDIS0011\xfa\x09redis-ver" + text),
    ]


SEEDS = _seeds()
_SEED = dict(SEEDS)


def _cut_before_second_part(data: bytes) -> bytes:
    """The file from just inside its second part's local header: the central directory's
    offsets then point before the start of the file."""
    return data[data.index(b"PK\x03\x04", 1) + 1 :]


def _bad_deflate(data: bytes, part: bytes = b"word/document.xml") -> bytes:
    """The file with the first byte of one part's deflate stream set to an invalid block."""
    out = bytearray(data)
    head = data.index(part) - 30
    assert data[head : head + 4] == b"PK\x03\x04"
    name_len = int.from_bytes(data[head + 26 : head + 28], "little")
    extra_len = int.from_bytes(data[head + 28 : head + 30], "little")
    out[head + 30 + name_len + extra_len] = 0xFF
    return bytes(out)


NAMES = [name for name, _ in SEEDS] + ["noext", "photo.jpg", "x.docx", f"{CARD}.txt"]


@st.composite
def damaged(draw: st.DrawFn, seeds: list[tuple[str, bytes]] | None = None) -> tuple[str, bytes]:
    """A seed file with its bytes damaged, sometimes under another file's name."""
    name, seed = draw(st.sampled_from(seeds or SEEDS))
    if draw(st.booleans()):
        name = draw(st.sampled_from(NAMES))
    data = bytearray(seed)
    for _ in range(draw(st.integers(0, 6))):
        if not data:
            break
        op = draw(st.sampled_from(["flip", "set", "insert", "delete", "cut", "repeat"]))
        pos = draw(st.integers(0, len(data) - 1))
        if op == "flip":
            data[pos] ^= 1 << draw(st.integers(0, 7))
        elif op == "set":
            data[pos] = draw(st.sampled_from([0, 0xFF, 0x7F, 0x80, ord("{"), ord('"')]))
        elif op == "insert":
            data[pos:pos] = draw(st.binary(min_size=1, max_size=64))
        elif op == "delete":
            del data[pos : pos + draw(st.integers(1, 64))]
        elif op == "cut":
            del data[pos:]
        else:
            n = draw(st.integers(1, 256))
            data[pos:pos] = data[pos : pos + n] * draw(st.integers(1, 8))
    return name, bytes(data)


# ---------------------------------------------------------------- what must never show


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


@contextlib.contextmanager
def watched() -> Iterator[list[str]]:
    """Everything the code under test logs, warns or prints, as lines."""
    out: list[str] = []
    handler = _Capture()
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        with (
            warnings.catch_warnings(record=True) as caught,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            warnings.simplefilter("always")
            yield out
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
    out += handler.lines + [str(w.message) for w in caught]
    out += [stdout.getvalue(), stderr.getvalue()]


def assert_no_value(*blobs: object) -> None:
    for blob in blobs:
        text = blob if isinstance(blob, str) else repr(blob)
        for value in PLANTED:
            assert value not in text, "a planted value reached an output"


def _error_text(err: BaseException) -> str:
    return f"{err!s} {err!r} {err.args!r}"


# ---------------------------------------------------------------- sniff and text


@given(st.binary(max_size=2 * SNIFF_BYTES))
def test_sniff_names_a_known_kind_for_any_bytes(head: bytes) -> None:
    kind = sniff(head)
    assert kind in KINDS
    if kind == "text":
        assert looks_text(head[:SNIFF_BYTES]) or looks_text(head)


@given(st.text(max_size=2000), st.sampled_from(["x.txt", "x.csv", "x.tsv", "x.jsonl", "x.json"]))
def test_scan_item_text_never_raises(text: str, name: str) -> None:
    with watched() as out:
        item = scan_item_text(name, text, DET)
    assert item.format
    assert_no_value(*out)


@given(st.integers(1, 200_000), st.sampled_from(["[", '{"a":', '{"a":[']))
# Found by this fuzz (#77): json.loads raised RecursionError, which is not a ValueError, so a
# deeply nested document was an unreadable object instead of text.
@example(100_000, "[")
def test_deeply_nested_json_is_read_or_left_as_text(depth: int, opener: str) -> None:
    closer = {"[": "]", '{"a":': "}", '{"a":[': "]}"}[opener]
    text = opener * depth + f'"{CARD}"' + closer * depth
    for name in ("x.json", "x.jsonl", "x.txt"):
        scan_item_text(name, text, DET)


@given(
    st.text(alphabet=st.sampled_from('ab1,"\n\r\t'), max_size=300),
    st.sampled_from([",", "\t"]),
)
def test_csv_cells_are_in_order_and_in_bounds(text: str, delimiter: str) -> None:
    last = (-1, -1)
    for row, col, start, end in csv_cells(text, delimiter):
        assert 0 <= start <= end <= len(text)
        assert (row, col) > last
        last = (row, col)
    if '"' not in text and "\r" not in text:
        rows: dict[int, list[str]] = {}
        for row, _, start, end in csv_cells(text, delimiter):
            rows.setdefault(row, []).append(text[start:end])
        assert [delimiter.join(c) for _, c in sorted(rows.items())] == text.split("\n")


# ---------------------------------------------------------------- the readers


OFFICE_SEEDS = [(n, d) for n, d in SEEDS if n.endswith((".docx", ".xlsx", ".pptx"))]
PDF_SEEDS = [(n, d) for n, d in SEEDS if n.endswith(".pdf")]


@given(damaged(OFFICE_SEEDS), st.integers(0, 4096))
# Found by this fuzz (#77): a part whose deflate stream will not inflate raised zlib.error,
# and a zip whose offsets point before its start raised ValueError; both escaped read_object.
@example(("letter.docx", _bad_deflate(_SEED["letter.docx"])), 1)
@example(("letter.docx", _cut_before_second_part(_SEED["letter.docx"])), 1)
def test_office_raises_only_office_unreadable_within_its_cap(
    file: tuple[str, bytes], cap: int
) -> None:
    name, data = file
    kind = name.rsplit(".", 1)[-1] if name.endswith((".docx", ".xlsx", ".pptx")) else "docx"
    with watched() as out:
        try:
            got = office_text(kind, io.BytesIO(data), max_inflated_bytes=cap)
        except OfficeUnreadable as err:
            assert_no_value(_error_text(err))
        else:
            assert len(got.text.encode()) <= cap + 4096
    assert_no_value(*out)


@given(damaged(PDF_SEEDS), st.integers(0, 2000))
# Found by this fuzz (#77): the document information was added past max_chars.
@example(("statement.pdf", _SEED["statement.pdf"]), 0)
def test_pdf_raises_only_its_three_exceptions_within_its_cap(
    file: tuple[str, bytes], cap: int
) -> None:
    _, data = file
    with watched() as out:
        try:
            got = pdf_text(data, max_chars=cap)
        except (PdfUnreadable, PdfEncrypted, ImageOnly) as err:
            assert_no_value(_error_text(err))
        else:
            assert len(got.text) <= cap
    assert_no_value(*out)


def _fetcher(data: bytes, seen: list[int]) -> Callable[[int, int], bytes]:
    def fetch(start: int, end: int) -> bytes:
        seen.append(end - start + 1)
        return data[start : end + 1]

    return fetch


def _read(name: str, data: bytes) -> tuple[Any, int, list[str]]:
    """read_object under the fuzz caps, with the text it hands the detector counted."""
    fetched: list[int] = []
    read_text: list[int] = []
    real = objects.__dict__["scan_item_text"]

    def counting(n: str, text: str, detector: Detector) -> Any:
        read_text.append(len(text))
        return real(n, text, detector)

    with watched() as out, mock.patch.object(objects, "scan_item_text", counting):
        try:
            got: Any = read_object(
                name,
                len(data),
                _fetcher(data, fetched),
                DET,
                max_object_bytes=MAX_OBJECT,
                max_inflated_bytes=MAX_INFLATED,
                max_rows=MAX_ROWS,
                columnar=True,
            )
        except Exception as err:  # only a damaged table at the top level may raise
            assert sniff(data[:SNIFF_BYTES]) in TABLES, type(err).__name__
            got = err
    assert sum(fetched) <= MAX_OBJECT
    assert sum(read_text) <= MAX_OBJECT + MAX_INFLATED
    return got, sum(fetched), out


def _check(name: str, data: bytes) -> None:
    got, _, out = _read(name, data)
    if isinstance(got, Exception):
        assert_no_value(_error_text(got), *out)
        return
    assert got.read <= MAX_OBJECT
    tables = [got.table] + [e.table for e in got.entries]
    for t in tables:
        if t is not None:
            assert t.rows <= MAX_ROWS
    findings = record(
        got,
        Coverage("s3", "fuzz"),
        resource_for=lambda col: {"key": "masked", "column": col or ""},
        link=None,
        seen_at="2026-09-30T00:00:00Z",
    )
    assert_no_value(repr(got), json.dumps(findings), *[repr(e) for e in got.entries], *out)


@given(damaged())
@example(("letter.docx", _bad_deflate(_SEED["letter.docx"])))
@example(("letter.docx", _cut_before_second_part(_SEED["letter.docx"])))
def test_read_object_survives_damaged_files_of_every_kind(file: tuple[str, bytes]) -> None:
    _check(*file)


@given(st.binary(max_size=4096), st.sampled_from(NAMES))
def test_read_object_survives_any_bytes(data: bytes, name: str) -> None:
    _check(name, data)


@pytest.mark.parametrize(("name", "data"), SEEDS, ids=[n for n, _ in SEEDS])
def test_every_seed_is_read_and_finds_what_was_planted(name: str, data: bytes) -> None:
    """The fuzz starts from files the readers read: each seed finds its planted values."""
    got, _, _ = _read(name, data)
    assert not isinstance(got, Exception)
    classes = set(got.item.findings if got.item else {})
    for e in got.entries:
        classes |= set(e.item.findings if e.item else {})
        classes |= {c for r in (e.table.by_column.values() if e.table else []) for c in r.findings}
    if got.table:
        classes |= {c for r in got.table.by_column.values() for c in r.findings}
    assert classes & {"card", "us_ssn"}, name


# ---------------------------------------------------------------- JSON shapes and masking

_KEYS = st.sampled_from(
    ["Transcript", "Content", "ParticipantId", "ParticipantRole", "Participants", "Type",
     "BeginOffsetMillis", "inputTranscript", "messages", "content", "sessionId", "bot",
     "sessionState", "ContactFlowModuleType", "ContactFlowId", "ContactId", "Parameters",
     "Text", "Results", "cardNumber", "ssn", "label", "value", CARD]
)  # fmt: skip
_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False),
    st.text(max_size=40),
    st.sampled_from([CARD, printed(CARD), SSN_A, dashed(SSN_A), "MESSAGE", "AGENT", "SSN"]),
)
JSON = st.recursive(
    _LEAVES,
    lambda inner: st.one_of(st.lists(inner, max_size=6), st.dictionaries(_KEYS, inner, max_size=6)),
    max_leaves=40,
)


@given(JSON, st.sampled_from(["x.json", "x.jsonl", "x.txt"]))
# Found by this fuzz (#77): an item's repr showed an offset's pointer, built from its keys.
@example({CARD: printed(CARDS["amex"])}, "x.json")
def test_any_json_shape_is_read_and_no_value_leaves(doc: Any, name: str) -> None:
    from sensitive_data_core.scan.item import scan_log_event

    text = json.dumps(doc)
    with watched() as out:
        item = scan_item_text(name, text, DET)
        event = scan_log_event(text, DET)
        lambda_line = scan_log_event("2026-09-28T03:00:00.000Z INFO " + text, DET)
    for got in (item, event, lambda_line):
        assert_no_value(repr(got), *[repr(f) for f in got.findings.values()])
        for f in got.findings.values():
            for o in f.offsets:
                assert_no_value(o.as_json())
    assert_no_value(*out)


@given(st.text(alphabet=st.sampled_from("0123456789 -/.a_"), max_size=80))
def test_redact_digits_leaves_no_card_or_ssn_shaped_run(text: str) -> None:
    import re

    from sensitive_data_core.engine.rules import luhn_valid
    from sensitive_data_core.safety import redact_digits

    masked = redact_digits(text + " " + CARD + " " + dashed(SSN_A))
    assert_no_value(masked)
    for m in re.finditer(r"[0-9]{13,19}", masked):
        assert not luhn_valid(m[0]) or len(m[0]) < 13
    assert not re.search(r"(?<![0-9])[0-9]{3}([ -]?)[0-9]{2}\1[0-9]{4}(?![0-9])", masked)
