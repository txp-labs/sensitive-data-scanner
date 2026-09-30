"""PDF documents to text (#65), with pypdf: pure Python, no dependencies of its own.

- The text layer of each page, in order, one page after another, up to
  `MAX_PAGES` pages and `max_chars` characters (the result is then partial);
  the document information (title, author, subject, keywords) is read too,
  after the pages, since a value typed there is stored like any other.
- A PDF with pages but no text layer at all (a scan) is `ImageOnly`: counted,
  not read (no OCR).
- A PDF that needs a password is `PdfEncrypted`. One encrypted with an empty
  user password (permissions only) opens for anyone, so it is read.
- A PDF pypdf cannot parse is `PdfUnreadable`.

pypdf's own log and warnings are silenced: a message about a malformed object
could quote the object. Values exist only in memory while one file is read.
"""

from __future__ import annotations

import io
import logging
import warnings
from dataclasses import dataclass
from typing import Any

MAX_PAGES = 500

logging.getLogger("pypdf").addHandler(logging.NullHandler())
logging.getLogger("pypdf").propagate = False


class PdfUnreadable(Exception):
    """Not a PDF pypdf can read."""


class PdfEncrypted(Exception):
    """A PDF that needs a password (or a cipher this build cannot run)."""


class ImageOnly(Exception):
    """A PDF with pages and no text layer."""


@dataclass
class PdfText:
    text: str
    pages: int
    partial: bool = False

    def __repr__(self) -> str:
        return f"PdfText(chars={len(self.text)}, pages={self.pages}, partial={self.partial})"


_INFO_KEYS = ("/Title", "/Author", "/Subject", "/Keywords")


def pdf_text(data: bytes, *, max_chars: int) -> PdfText:
    """The text of one PDF held in memory (a file's first bytes, up to the object cap)."""
    try:
        from pypdf import PdfReader  # noqa: PLC0415 - loaded with the first PDF
        from pypdf.errors import DependencyError, FileNotDecryptedError  # noqa: PLC0415
    except ImportError:  # pragma: no cover - a core dependency
        raise PdfUnreadable("pypdf missing") from None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                try:
                    if not reader.decrypt(""):
                        raise PdfEncrypted("password")
                except (DependencyError, NotImplementedError, FileNotDecryptedError):
                    raise PdfEncrypted("cipher") from None
            pages = reader.pages
            n = len(pages)
        except (PdfEncrypted, ImageOnly):
            raise
        except Exception:  # pypdf raises many kinds for a malformed file
            raise PdfUnreadable("unreadable") from None
        out: list[str] = []
        size = 0
        partial = n > MAX_PAGES
        any_text = False
        for i in range(min(n, MAX_PAGES)):
            try:
                text = pages[i].extract_text() or ""
            except FileNotDecryptedError:
                raise PdfEncrypted("page") from None
            except Exception:  # one bad page must not cost the rest
                partial = True
                continue
            if text.strip():
                any_text = True
            if size + len(text) > max_chars:
                out.append(text[: max(0, max_chars - size)])
                partial = True
                size = max_chars
                break
            out.append(text)
            size += len(text) + 1
        info: list[str] = []
        try:
            meta: Any = reader.metadata or {}
            for k in _INFO_KEYS:
                v = meta.get(k)
                if isinstance(v, str) and v.strip():
                    # Within the same cap as the pages (#77): the text never passes max_chars.
                    room = max_chars - size - 1
                    if room <= 0:
                        partial = True
                        break
                    info.append(str(v)[: min(4096, room)])
                    size += len(info[-1]) + 1
        except Exception:  # noqa: S110 - document information is optional
            pass
    if n and not any_text:
        raise ImageOnly("no text layer")
    return PdfText("\n".join(out + info), n, partial)
