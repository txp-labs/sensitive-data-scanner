"""Office Open XML documents to text: `.docx`, `.xlsx` and `.pptx` (#21 step 6).

A Word, Excel or PowerPoint file is a zip of XML parts. This module reads the
parts that hold what a person typed, with the standard library only (`zipfile`
and `xml.etree`), and gives the caller text that `scan/item.py` reads:

- **Word** (`.docx`): the body, headers, footers, footnotes, endnotes and
  comments; one paragraph (`w:p`) per line, a table cell ended by a tab.
- **Excel** (`.xlsx`): every worksheet as CSV rows, each cell's shared string,
  inline string or number, so a sheet's first row is the header context of the
  rows under it, as a CSV file's is. Sheets are separated by a blank line.
- **PowerPoint** (`.pptx`): every slide's and every note's text runs (`a:t`),
  one paragraph per line.

The limits keep a hostile file from costing more than a large one:

- the zip is opened through the caller's seekable reader (a ranged read of a
  blob or a Graph download), so only the central directory and the parts read
  are fetched;
- at most `MAX_PARTS` parts are read, and the text inflated from them stops at
  `max_inflated_bytes` (the result is then partial);
- a part that declares a DTD (`<!DOCTYPE`) is not parsed, so no entity is
  ever expanded; a part that is not well-formed XML is skipped.

A rights-managed (encrypted) Office file is not a zip but an OLE container
(`D0 CF 11 E0`): the caller (`scan/objects.py`) knows one by its first bytes
and counts it as `encrypted`. Whether a zip is Word, Excel or PowerPoint is
decided by its parts, whatever the file is named (`sniff.office_layout`), and
`office_zip_text` reads the zip the caller opened. Values exist only in memory
while one file is read.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass
from typing import IO
from xml.etree import ElementTree as ET

OFFICE_EXT = {"docx": "docx", "docm": "docx", "xlsx": "xlsx", "xlsm": "xlsx", "pptx": "pptx"}
MAX_PARTS = 400
MAX_CELLS = 200_000

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_WORD_PARTS = re.compile(
    r"^word/(document|header[0-9]*|footer[0-9]*|footnotes|endnotes|comments)\.xml$"
)
_SHEET = re.compile(r"^xl/worksheets/sheet([0-9]+)\.xml$")
_SLIDE = re.compile(r"^ppt/(slides/slide|notesSlides/notesSlide)([0-9]+)\.xml$")
_COL = re.compile(r"^([A-Z]{1,3})")


class OfficeUnreadable(Exception):
    """The file is not an Office Open XML document this module can read."""


def office_kind(key: str) -> str | None:
    """`docx`, `xlsx` or `pptx` by the name's extension, else None."""
    base = key.rsplit("/", 1)[-1].lower()
    ext = base.rsplit(".", 1)[1] if "." in base else ""
    return OFFICE_EXT.get(ext)


@dataclass
class OfficeText:
    """What one document gave: its text, and whether a limit cut it short."""

    format: str
    text: str
    partial: bool = False

    def __repr__(self) -> str:
        return f"OfficeText({self.format!r}, chars={len(self.text)}, partial={self.partial})"


class _Budget:
    def __init__(self, limit: int) -> None:
        self.left = limit
        self.cut = False

    def read(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
        """One part, inflated up to what is left of the limit (None when nothing is)."""
        if self.left <= 0:
            self.cut = True
            return None
        with zf.open(info) as f:
            data = f.read(self.left + 1)
        if len(data) > self.left:
            self.cut = True
            return None  # a part cut mid-way is not well-formed XML: not read
        self.left -= len(data)
        return data


def _xml(data: bytes | None) -> ET.Element | None:
    """A part's root element; None for a DTD (never expanded) or XML that is not well formed."""
    if data is None or b"<!DOCTYPE" in data[:4096].upper() or b"<!ENTITY" in data:
        return None
    try:
        return ET.fromstring(data)  # noqa: S314 - no DTD, so no entity expansion
    except ET.ParseError:
        return None


def _paragraphs(root: ET.Element, para: str, text: str, tab: str | None = None) -> list[str]:
    lines: list[str] = []
    for p in root.iter(para):
        parts: list[str] = []
        for el in p.iter():
            if el.tag == text and el.text:
                parts.append(el.text)
            elif tab is not None and el.tag == tab:
                parts.append("\t")
        if parts:
            lines.append("".join(parts))
    return lines


def _docx(zf: zipfile.ZipFile, names: list[zipfile.ZipInfo], budget: _Budget) -> str:
    out: list[str] = []
    for info in names:
        if not _WORD_PARTS.match(info.filename):
            continue
        root = _xml(budget.read(zf, info))
        if root is not None:
            out.extend(_paragraphs(root, f"{_W}p", f"{_W}t", f"{_W}tab"))
    return "\n".join(out)


def _pptx(zf: zipfile.ZipFile, names: list[zipfile.ZipInfo], budget: _Budget) -> str:
    slides = sorted(
        (int(m[2]), m[1], info) for info in names if (m := _SLIDE.match(info.filename)) is not None
    )
    out: list[str] = []
    for _, _, info in slides:
        root = _xml(budget.read(zf, info))
        if root is not None:
            out.extend(_paragraphs(root, f"{_A}p", f"{_A}t"))
    return "\n".join(out)


def _col_index(ref: str) -> int:
    m = _COL.match(ref or "")
    if not m:
        return -1
    n = 0
    for ch in m[1]:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _xlsx(zf: zipfile.ZipFile, names: list[zipfile.ZipInfo], budget: _Budget) -> str:
    by_name = {i.filename: i for i in names}
    shared: list[str] = []
    if "xl/sharedStrings.xml" in by_name:
        root = _xml(budget.read(zf, by_name["xl/sharedStrings.xml"]))
        if root is not None:
            for si in root.iter(f"{_S}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{_S}t")))
    sheets = sorted(
        (int(m[1]), info) for info in names if (m := _SHEET.match(info.filename)) is not None
    )
    out = io.StringIO()
    cells = 0
    for n, (_, info) in enumerate(sheets):
        root = _xml(budget.read(zf, info))
        if root is None:
            continue
        if n:
            out.write("\n")
        writer = csv.writer(out, lineterminator="\n")
        for row in root.iter(f"{_S}row"):
            values: dict[int, str] = {}
            for c in row.iter(f"{_S}c"):
                cells += 1
                if cells > MAX_CELLS:
                    budget.cut = True
                    break
                kind = c.get("t")
                text: str | None = None
                if kind == "s":
                    v = c.find(f"{_S}v")
                    try:
                        text = shared[int(v.text or "")] if v is not None else None
                    except (ValueError, IndexError):
                        text = None
                elif kind == "inlineStr":
                    text = "".join(t.text or "" for t in c.iter(f"{_S}t"))
                else:
                    v = c.find(f"{_S}v")
                    text = v.text if v is not None else None
                if text:
                    col = _col_index(c.get("r") or "")
                    values[col if col >= 0 else len(values)] = text
            if values:
                width = max(values) + 1
                writer.writerow([values.get(i, "") for i in range(width)])
            if cells > MAX_CELLS:
                break
    return out.getvalue()


def office_text(kind: str, f: IO[bytes], *, max_inflated_bytes: int) -> OfficeText:
    """The text of one `.docx`, `.xlsx` or `.pptx` file, read from a seekable file."""
    try:
        zf = zipfile.ZipFile(f)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        raise OfficeUnreadable("not a zip") from None
    with zf:
        return office_zip_text(kind, zf, max_inflated_bytes=max_inflated_bytes)


def office_zip_text(kind: str, zf: zipfile.ZipFile, *, max_inflated_bytes: int) -> OfficeText:
    """The text of an Office Open XML package already opened as a zip (the readers open it
    once, see it is Word, Excel or PowerPoint by its parts, and read it here)."""
    budget = _Budget(max_inflated_bytes)
    names = zf.infolist()
    partial = len(names) > MAX_PARTS
    names = names[:MAX_PARTS]
    try:
        if kind == "docx":
            text = _docx(zf, names, budget)
        elif kind == "xlsx":
            text = _xlsx(zf, names, budget)
        elif kind == "pptx":
            text = _pptx(zf, names, budget)
        else:
            raise OfficeUnreadable("not an office kind")
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError):
        raise OfficeUnreadable("unreadable part") from None
    return OfficeText(kind, text, partial or budget.cut)
