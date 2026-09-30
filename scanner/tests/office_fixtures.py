"""Minimal Office Open XML files for the tests, made with the standard library. Every value
is made up."""

from __future__ import annotations

import io
import zipfile
from xml.sax.saxutils import escape

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"


def _zip(parts: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        for name, body in parts.items():
            z.writestr(name, body)
    return buf.getvalue()


def docx(paragraphs: list[str], *, comments: list[str] | None = None) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs)
    parts = {"word/document.xml": f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'}
    if comments:
        c = "".join(
            f"<w:comment><w:p><w:r><w:t>{escape(t)}</w:t></w:r></w:p></w:comment>" for t in comments
        )
        parts["word/comments.xml"] = f'<w:comments xmlns:w="{W}">{c}</w:comments>'
    return _zip(parts)


def xlsx(rows: list[list[str]], *, shared: bool = True) -> bytes:
    strings: list[str] = []
    cells = []
    for r, row in enumerate(rows, start=1):
        out = []
        for c, value in enumerate(row):
            ref = f"{chr(65 + c)}{r}"
            if shared:
                strings.append(value)
                out.append(f'<c r="{ref}" t="s"><v>{len(strings) - 1}</v></c>')
            else:
                out.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>')
        cells.append(f'<row r="{r}">{"".join(out)}</row>')
    sheet = f'<worksheet xmlns="{S}"><sheetData>{"".join(cells)}</sheetData></worksheet>'
    parts = {"xl/worksheets/sheet1.xml": sheet}
    if shared:
        si = "".join(f"<si><t>{escape(s)}</t></si>" for s in strings)
        parts["xl/sharedStrings.xml"] = f'<sst xmlns="{S}">{si}</sst>'
    return _zip(parts)


def pptx(slides: list[str]) -> bytes:
    parts = {}
    for i, text in enumerate(slides, start=1):
        parts[f"ppt/slides/slide{i}.xml"] = (
            f'<p:sld xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree><p:sp><p:txBody>'
            f"<a:p><a:r><a:t>{escape(text)}</a:t></a:r></a:p>"
            "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
        )
    return _zip(parts)


def with_dtd() -> bytes:
    """A document whose body declares an entity: never parsed."""
    return _zip(
        {
            "word/document.xml": (
                '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "card 4111">]>'
                f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p>'
                "</w:body></w:document>"
            )
        }
    )


OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
