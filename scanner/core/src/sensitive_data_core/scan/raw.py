"""Text in raw bytes: the runs of printable characters that could hold a value.

For data with no format the scanner parses (EBS snapshot blocks, Redis RDB
snapshot files), the runs of printable ASCII and UTF-16LE text are read as
text. A run with no digit or digit word cannot hold a card number or an SSN,
so it is left out.
"""

from __future__ import annotations

import re

MAX_TEXT_PER_BLOCK = 64 * 1024
_ASCII = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_CANDIDATE = re.compile(r"[0-9]|\b(?:zero|one|two|three|four|five|six|seven|eight|nine)\b", re.I)


def printable_text(data: bytes) -> str:
    """The runs of printable text in raw bytes (ASCII, and UTF-16LE), one per line, that could
    hold a value; at most MAX_TEXT_PER_BLOCK characters."""
    runs = [m[0].decode("ascii") for m in _ASCII.finditer(data)]
    runs += [m[0].decode("utf-16-le") for m in _UTF16.finditer(data)]
    out: list[str] = []
    n = 0
    for r in runs:
        if not _CANDIDATE.search(r):
            continue
        out.append(r)
        n += len(r) + 1
        if n >= MAX_TEXT_PER_BLOCK:
            break
    return "\n".join(out)
