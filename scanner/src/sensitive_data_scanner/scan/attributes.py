"""One DynamoDB item to per-attribute-path findings.

An item is read attribute by attribute. Each string (or number) leaf is its
own text; a finding names the leaf's attribute path, with `[]` for every list
index (`stepResults[].observedDtmf`), and its offsets carry the exact leaf as
an RFC 6901 pointer (`/stepResults/1/observedDtmf`).

The table's configuration may name three kinds of path:

- **keypad** leaves are keypad (DTMF) entries: a customer turn on the `dtmf`
  channel, normalized like every other source (`123456789#` loses its
  terminator) and never joined to another turn;
- **prompt** leaves are what the IVR said: a bot turn. A prompt classes the
  keypad entry that follows it, exactly as in a Connect flow log. Prompt and
  keypad leaves under one top-level attribute form one conversation, in list
  order, a prompt before the keypad entry of the same list element;
- **planted** paths hold test inputs a test put there on purpose (a test
  script's `steps`). Their findings are marked `planted`, so a reviewer can
  tell planted data from a leak.

A keypad leaf with no prompt paths configured takes its own map's other short
strings and key names as the prompt (a step labeled "Enter SSN").

Every other leaf is read as stored text, with its path and its map's short
strings as context. Values exist only in memory while the item is scanned.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..detect.analyzer import Analysis, Detection, Detector
from ..detect.enhancer import humanize
from ..engine.conversation import Turn, utf16_index
from ..findings import Offset
from .item import _HAS_CANDIDATE, MAX_LEAVES, REDACTION_MARKER, ItemResult, _Collector
from .paths import Path, covers, pointer_escape, render_path

FORMAT = "dynamodb_item"
MAX_DEPTH = 32
MAX_LOCAL_CONTEXT = 2_000


@dataclass(frozen=True)
class AttributeRules:
    """Which attribute paths to read, and which are keypad entries, prompts or planted."""

    include: tuple[Path, ...] = ()
    exclude: tuple[Path, ...] = ()
    keypad: tuple[Path, ...] = ()
    prompts: tuple[Path, ...] = ()
    planted: tuple[Path, ...] = ()

    def read(self, path: Path) -> bool:
        if self.include and not any(covers(p, path) for p in self.include):
            return False
        return not any(covers(p, path) for p in self.exclude)

    def role(self, path: Path) -> str:
        if any(covers(p, path) for p in self.keypad):
            return "keypad"
        if any(covers(p, path) for p in self.prompts):
            return "prompt"
        return "text"

    def is_planted(self, path: Path) -> bool:
        return any(covers(p, path) for p in self.planted)

    def top_level_names(self) -> list[str]:
        """The top-level attributes a projection must return (empty: all of them)."""
        return list(dict.fromkeys(p[0] for p in self.include))


@dataclass
class Leaf:
    concrete: tuple[str | int, ...]
    text: str
    context: str  # the enclosing map's short strings and key names

    @property
    def path(self) -> Path:
        return tuple("[]" if isinstance(s, int) else s for s in self.concrete)

    @property
    def pointer(self) -> str:
        return "".join("/" + pointer_escape(str(s)) for s in self.concrete)

    @property
    def indices(self) -> tuple[int, ...]:
        return tuple(s for s in self.concrete if isinstance(s, int))


def _local_context(m: dict[str, Any]) -> str:
    parts: list[str] = []
    size = 0
    for k, v in m.items():
        parts.append(str(k))
        size += len(str(k))
        if isinstance(v, dict) and "S" in v:
            s = v["S"]
            if isinstance(s, str) and len(s) <= 80 and not re.search(r"[0-9]{4}", s):
                parts.append(s)
                size += len(s)
        if size > MAX_LOCAL_CONTEXT:
            break
    return humanize(" ".join(parts))


def iter_leaves(item: dict[str, Any], rules: AttributeRules) -> Iterator[Leaf]:
    """Every string and number leaf the rules read, from DynamoDB-JSON attribute values.

    Binary values, booleans and nulls are not text and are not read.
    """
    count = 0

    def visit(av: Any, concrete: tuple[str | int, ...], context: str, depth: int) -> Iterator[Leaf]:
        nonlocal count
        if count > MAX_LEAVES or depth > MAX_DEPTH or not isinstance(av, dict):
            return
        path = tuple("[]" if isinstance(s, int) else s for s in concrete)
        if "S" in av or "N" in av:
            if not rules.read(path):
                return
            count += 1
            yield Leaf(concrete, str(av.get("S", av.get("N"))), context)
        elif "M" in av and isinstance(av["M"], dict):
            local = _local_context(av["M"])
            for k, v in av["M"].items():
                yield from visit(v, (*concrete, str(k)), local, depth + 1)
        elif "L" in av and isinstance(av["L"], list):
            for i, v in enumerate(av["L"]):
                yield from visit(v, (*concrete, i), context, depth + 1)
        elif "SS" in av or "NS" in av:
            values = av.get("SS", av.get("NS")) or []
            if not rules.read((*path, "[]")):
                return
            for i, v in enumerate(values):
                count += 1
                yield Leaf((*concrete, i), str(v), context)

    top = _local_context(item)
    for name, av in item.items():
        yield from visit(av, (str(name),), top, 1)


@dataclass
class AttributeResult:
    """Findings for one item, per attribute path (rendered with `[]`)."""

    by_path: dict[str, ItemResult] = field(default_factory=dict)
    planted: set[str] = field(default_factory=set)
    redaction_markers: int = 0
    test_values: int = 0
    suppressed: int = 0
    leaves: int = 0


def key_value(av: Any) -> str:
    """A key attribute's value as text: a string or a number as it is, a binary as base64."""
    if isinstance(av, dict):
        if "S" in av:
            return str(av["S"])
        if "N" in av:
            return str(av["N"])
        if "B" in av:
            b = av["B"]
            return base64.b64encode(b if isinstance(b, bytes) else str(b).encode()).decode()
    return ""


def _turn_offsets(det: Detection, owners: list[Leaf | None]) -> list[Offset]:
    """A conversation detection's spans, each in the leaf its turn came from."""
    spans = []
    for sp in det.spans:
        owner = owners[sp.turn] if sp.turn is not None else None
        if owner is None:
            continue
        t = owner.text
        spans.append(Offset(utf16_index(t, sp.start), utf16_index(t, sp.end), owner.pointer))
    return spans


def scan_attributes(
    item: dict[str, Any], detector: Detector, rules: AttributeRules
) -> AttributeResult:
    out = AttributeResult()
    collectors: dict[str, _Collector] = {}

    def collector(path: Path) -> _Collector:
        name = render_path(path)
        if rules.is_planted(path):
            out.planted.add(name)
        return collectors.setdefault(name, _Collector(FORMAT))

    conversations: dict[str, list[tuple[int, Leaf, str]]] = {}
    for n, leaf in enumerate(iter_leaves(item, rules)):
        out.leaves += 1
        out.redaction_markers += len(REDACTION_MARKER.findall(leaf.text))
        role = rules.role(leaf.path)
        if role != "text":
            conversations.setdefault(str(leaf.concrete[0]), []).append((n, leaf, role))
            continue
        if not _HAS_CANDIDATE.search(leaf.text):
            continue
        analysis = detector.analyze_text(leaf.text, [humanize(" ".join(leaf.path)), leaf.context])
        out.test_values += analysis.test_values
        out.suppressed += analysis.suppressed
        text, pointer = leaf.text, leaf.pointer
        collector(leaf.path).add(
            Analysis(analysis.detections),
            lambda d, text=text, pointer=pointer: [
                Offset(utf16_index(text, sp.start), utf16_index(text, sp.end), pointer)
                for sp in d.spans
            ],
        )

    for leaves in conversations.values():
        # List order; within one list element, the prompt comes before the keypad entry.
        ordered = sorted(leaves, key=lambda x: (x[1].indices, 0 if x[2] == "prompt" else 1, x[0]))
        turns: list[Turn] = []
        owners: list[Leaf | None] = []
        for _, leaf, role in ordered:
            if role == "prompt":
                turns.append(Turn("bot", leaf.text, "speech"))
            else:
                if not rules.prompts and leaf.context:
                    turns.append(Turn("bot", leaf.context, "speech"))
                    owners.append(None)
                turns.append(Turn("customer", leaf.text, "dtmf"))
            owners.append(leaf)
        analysis = detector.analyze_conversation(turns)
        out.test_values += analysis.test_values
        out.suppressed += analysis.suppressed
        for d in analysis.detections:
            owned = [owners[sp.turn] for sp in d.spans if sp.turn is not None]
            first = next((o for o in owned if o is not None), None)
            if first is None:
                continue  # found only in a key-name prompt: nothing stored there

            collector(first.path).add(
                Analysis([d]), lambda det, owners=owners: _turn_offsets(det, owners)
            )

    for name, col in collectors.items():
        if col.result.findings:
            out.by_path[name] = col.result
    return out
