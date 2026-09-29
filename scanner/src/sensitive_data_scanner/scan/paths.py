"""Attribute paths for DynamoDB items: `.` between map keys, `[]` for every list element.

`stepResults[].observedDtmf` is ("stepResults", "[]", "observedDtmf"). A path
covers everything under it: `steps` covers `steps[].digits`.
"""

from __future__ import annotations

import re

_NAME = re.compile(r"[^.\[\]]+")

Path = tuple[str, ...]  # "[]" stands for every list index


def parse_path(text: str) -> Path:
    """`stepResults[].observedDtmf` -> ("stepResults", "[]", "observedDtmf")."""
    out: list[str] = []
    rest = text.strip()
    if not rest:
        raise ValueError("empty attribute path")
    first = True
    while rest:
        if rest.startswith("[]"):
            if first:
                raise ValueError("invalid attribute path")
            out.append("[]")
            rest = rest[2:]
        elif rest.startswith(".") and not first:
            rest = rest[1:]
            m = _NAME.match(rest)
            if not m:
                raise ValueError("invalid attribute path")
            out.append(m[0])
            rest = rest[m.end() :]
        elif first:
            m = _NAME.match(rest)
            if not m:
                raise ValueError("invalid attribute path")
            out.append(m[0])
            rest = rest[m.end() :]
        else:
            raise ValueError("invalid attribute path")
        first = False
    return tuple(out)


def render_path(path: Path) -> str:
    out = ""
    for seg in path:
        out += "[]" if seg == "[]" else (f".{seg}" if out else seg)
    return out


def covers(prefix: Path, path: Path) -> bool:
    return path[: len(prefix)] == prefix


def pointer_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")
