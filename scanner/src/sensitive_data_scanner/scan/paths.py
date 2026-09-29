"""Attribute paths for DynamoDB items.

- `.` goes between map keys: `result.status`.
- `[]` stands for every element of a list (or set): `stepResults[].observedDtmf`.
- `[name=value]` stands for the list elements that are maps whose attribute
  `name` is the string (or number) `value`: `stepResults[kind=sendDtmf].observedDtmf`.
  Several conditions, all of which must hold, are separated by commas:
  `[kind=sendDtmf,status=passed]`.

A path covers everything under it: `steps` covers `steps[kind=sendDtmf].digits`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_NAME = re.compile(r"[^.\[\]]+")
_CONDITION = re.compile(r"^([^=,\[\]]+)=([^,\[\]]*)$")


@dataclass(frozen=True)
class Elements:
    """A list step in a path: every element, or the elements that meet all the conditions."""

    where: tuple[tuple[str, str], ...] = ()

    def __str__(self) -> str:
        return "[" + ",".join(f"{k}={v}" for k, v in self.where) + "]"


Segment = str | Elements
Path = tuple[Segment, ...]
EVERY = Elements()


@dataclass(frozen=True)
class Step:
    """One step of a leaf's concrete path: a map key, or a list index with that element's
    scalar attributes (what a condition is tested against)."""

    key: str | None = None
    index: int | None = None
    fields: tuple[tuple[str, str], ...] = ()


def _condition(text: str) -> tuple[tuple[str, str], ...]:
    out = []
    for part in text.split(","):
        m = _CONDITION.match(part.strip())
        if not m or not m[1].strip():
            raise ValueError("invalid attribute path")
        out.append((m[1].strip(), m[2].strip()))
    return tuple(out)


def parse_path(text: str) -> Path:
    """`steps[kind=sendDtmf].digits` -> ("steps", Elements((("kind", "sendDtmf"),)), "digits")."""
    out: list[Segment] = []
    rest = text.strip()
    if not rest:
        raise ValueError("empty attribute path")
    first = True
    while rest:
        if rest.startswith("["):
            end = rest.find("]")
            if first or end < 0:
                raise ValueError("invalid attribute path")
            inner = rest[1:end]
            out.append(Elements(_condition(inner)) if inner else EVERY)
            rest = rest[end + 1 :]
        elif first or rest.startswith("."):
            if not first:
                rest = rest[1:]
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
        if isinstance(seg, Elements):
            out += str(seg)
        else:
            out += f".{seg}" if out else seg
    return out


def _step_matches(seg: Segment, step: Step) -> bool:
    if isinstance(seg, Elements):
        if step.index is None:
            return False
        fields = dict(step.fields)
        return all(fields.get(k) == v for k, v in seg.where)
    return step.key == seg


def covers(prefix: Path, steps: tuple[Step, ...]) -> bool:
    """Whether the configured path `prefix` covers the leaf at `steps`."""
    if len(prefix) > len(steps):
        return False
    return all(_step_matches(seg, step) for seg, step in zip(prefix, steps, strict=False))


def generic(steps: tuple[Step, ...]) -> Path:
    """The leaf's path with `[]` for every list index: what a finding names."""
    return tuple(EVERY if s.index is not None else (s.key or "") for s in steps)


def pointer_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")
