"""One DynamoDB item to per-attribute-path findings.

An item is read attribute by attribute. Each string (or number) leaf is its
own text; a finding names the leaf's attribute path, with `[]` for every list
index (`stepResults[].observedDtmf`), and its offsets carry the exact leaf as
an RFC 6901 pointer (`/stepResults/3/observedDtmf`). Configured paths may
select list elements by attribute (`stepResults[kind=sendDtmf].observedDtmf`;
see paths.py).

The table's configuration may name three kinds of path:

- **keypad** leaves are keypad (DTMF) entries: a customer turn on the `dtmf`
  channel, normalized like every other source (`123456789#` loses its
  terminator) and never joined to another turn;
- **prompt** leaves are what the IVR said. Each keypad entry is paired with
  the **nearest preceding prompt in the same list**, ordered by the
  configured `orderBy` attribute of the list elements (`stepIndex`) when an
  element has it, else by position; a prompt in the same element counts as
  preceding. The pair is read as a bot turn then a customer turn, so the
  prompt classes the entry, as in a Connect flow log. Only a configured
  prompt path is ever a prompt: other text (an expected-prompt regex in a
  test script) is never used to class an entry;
- **planted** paths hold test inputs a test put there on purpose (a test
  script's `steps`). Their findings are marked `planted`, so a reviewer can
  tell planted data from a leak.

A keypad leaf, when no prompt path is configured at all, takes its own map's
other short strings and key names as the prompt (a step labeled "Enter SSN").

Every leaf that is not a keypad entry (prompts included) is also read as
stored text, with its path and its map's short strings as context. Values
exist only in memory while the item is scanned.
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
from .paths import Path, Step, covers, generic, pointer_escape, render_path

FORMAT = "dynamodb_item"
MAX_DEPTH = 32
MAX_LOCAL_CONTEXT = 2_000


@dataclass(frozen=True)
class AttributeRules:
    """Which attribute paths to read, which are keypad entries, prompts or planted, and
    which list-element attribute orders a list (`orderBy`)."""

    include: tuple[Path, ...] = ()
    exclude: tuple[Path, ...] = ()
    keypad: tuple[Path, ...] = ()
    prompts: tuple[Path, ...] = ()
    planted: tuple[Path, ...] = ()
    order_by: str | None = None

    def read(self, steps: tuple[Step, ...]) -> bool:
        if self.include and not any(covers(p, steps) for p in self.include):
            return False
        return not any(covers(p, steps) for p in self.exclude)

    def role(self, steps: tuple[Step, ...]) -> str:
        if any(covers(p, steps) for p in self.keypad):
            return "keypad"
        if any(covers(p, steps) for p in self.prompts):
            return "prompt"
        return "text"

    def is_planted(self, steps: tuple[Step, ...]) -> bool:
        return any(covers(p, steps) for p in self.planted)

    def top_level_names(self) -> list[str]:
        """The top-level attributes a projection must return (empty: all of them)."""
        return list(dict.fromkeys(str(p[0]) for p in self.include))


@dataclass
class Leaf:
    steps: tuple[Step, ...]
    text: str
    context: str  # the enclosing map's short strings and key names
    list_pointer: str | None = None  # the innermost list the leaf is in
    order: tuple[float, int] = (0.0, 0)  # its element's place in that list

    @property
    def path(self) -> Path:
        return generic(self.steps)

    @property
    def pointer(self) -> str:
        return "".join(
            "/" + pointer_escape(str(s.index if s.index is not None else s.key)) for s in self.steps
        )


def _scalars(m: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    out = []
    for k, v in m.items():
        if isinstance(v, dict) and ("S" in v or "N" in v):
            out.append((str(k), str(v.get("S", v.get("N")))))
    return tuple(out)


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


def _order(
    fields: tuple[tuple[str, str], ...], index: int, order_by: str | None
) -> tuple[float, int]:
    if order_by:
        value = dict(fields).get(order_by)
        if value is not None:
            try:
                return (float(value), index)
            except ValueError:
                pass
    return (float(index), index)


def iter_leaves(item: dict[str, Any], rules: AttributeRules) -> Iterator[Leaf]:
    """Every string and number leaf the rules read, from DynamoDB-JSON attribute values.

    Binary values, booleans and nulls are not text and are not read.
    """
    count = 0

    def visit(
        av: Any,
        steps: tuple[Step, ...],
        context: str,
        where: tuple[str | None, tuple[float, int]],
        depth: int,
    ) -> Iterator[Leaf]:
        nonlocal count
        if count > MAX_LEAVES or depth > MAX_DEPTH or not isinstance(av, dict):
            return
        if "S" in av or "N" in av:
            if not rules.read(steps):
                return
            count += 1
            yield Leaf(steps, str(av.get("S", av.get("N"))), context, where[0], where[1])
        elif "M" in av and isinstance(av["M"], dict):
            local = _local_context(av["M"])
            for k, v in av["M"].items():
                yield from visit(v, (*steps, Step(key=str(k))), local, where, depth + 1)
        elif "L" in av and isinstance(av["L"], list):
            here = Leaf(steps, "", "").pointer
            for i, v in enumerate(av["L"]):
                fields = (
                    _scalars(v["M"]) if isinstance(v, dict) and isinstance(v.get("M"), dict) else ()
                )
                step = Step(index=i, fields=fields)
                yield from visit(
                    v, (*steps, step), context, (here, _order(fields, i, rules.order_by)), depth + 1
                )
        elif "SS" in av or "NS" in av:
            here = Leaf(steps, "", "").pointer
            for i, v in enumerate(av.get("SS", av.get("NS")) or []):
                leaf_steps = (*steps, Step(index=i))
                if not rules.read(leaf_steps):
                    continue
                count += 1
                yield Leaf(leaf_steps, str(v), context, here, (float(i), i))

    top = _local_context(item)
    for name, av in item.items():
        yield from visit(av, (Step(key=str(name)),), top, (None, (0.0, 0)), 1)


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


def pair_prompts(leaves: list[tuple[int, Leaf, str]]) -> list[tuple[Leaf, Leaf | None]]:
    """Each keypad leaf with the nearest preceding prompt leaf in its list (or None).

    `leaves` are (document position, leaf, role) for one list. Order: the element's
    order key, a prompt before a keypad entry of the same element, then position.
    """
    ordered = sorted(leaves, key=lambda x: (x[1].order, 0 if x[2] == "prompt" else 1, x[0]))
    out: list[tuple[Leaf, Leaf | None]] = []
    last: Leaf | None = None
    for _, leaf, role in ordered:
        if role == "prompt":
            last = leaf
        else:
            out.append((leaf, last))
    return out


def scan_attributes(
    item: dict[str, Any], detector: Detector, rules: AttributeRules
) -> AttributeResult:
    out = AttributeResult()
    collectors: dict[str, _Collector] = {}

    def collector(leaf: Leaf) -> _Collector:
        name = render_path(leaf.path)
        if rules.is_planted(leaf.steps):
            out.planted.add(name)
        return collectors.setdefault(name, _Collector(FORMAT))

    lists: dict[str | None, list[tuple[int, Leaf, str]]] = {}
    for n, leaf in enumerate(iter_leaves(item, rules)):
        out.leaves += 1
        out.redaction_markers += len(REDACTION_MARKER.findall(leaf.text))
        role = rules.role(leaf.steps)
        if role != "text":
            lists.setdefault(leaf.list_pointer, []).append((n, leaf, role))
        if role == "keypad" or not _HAS_CANDIDATE.search(leaf.text):
            continue
        words = " ".join(str(s.key) for s in leaf.steps if s.key is not None)
        analysis = detector.analyze_text(leaf.text, [humanize(words), leaf.context])
        out.test_values += analysis.test_values
        out.suppressed += analysis.suppressed
        text, pointer = leaf.text, leaf.pointer
        collector(leaf).add(
            Analysis(analysis.detections),
            lambda d, text=text, pointer=pointer: [
                Offset(utf16_index(text, sp.start), utf16_index(text, sp.end), pointer)
                for sp in d.spans
            ],
        )

    for leaves in lists.values():
        for keypad, prompt in pair_prompts(leaves):
            turns: list[Turn] = []
            owners: list[Leaf | None] = []
            if prompt is not None:
                turns.append(Turn("bot", prompt.text, "speech"))
                owners.append(None)  # the prompt is read as text on its own
            elif not rules.prompts and keypad.context:
                turns.append(Turn("bot", keypad.context, "speech"))
                owners.append(None)
            turns.append(Turn("customer", keypad.text, "dtmf"))
            owners.append(keypad)
            analysis = detector.analyze_conversation(turns)
            found = [
                d for d in analysis.detections if any(sp.turn == len(turns) - 1 for sp in d.spans)
            ]
            out.test_values += analysis.test_values
            out.suppressed += analysis.suppressed
            if found:
                collector(keypad).add(
                    Analysis(found), lambda det, owners=owners: _turn_offsets(det, owners)
                )

    for name, col in collectors.items():
        if col.result.findings:
            out.by_path[name] = col.result
    return out
