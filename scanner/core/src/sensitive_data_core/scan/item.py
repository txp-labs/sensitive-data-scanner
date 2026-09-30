"""One item (an S3 object, a log event) to per-class findings.

Works out what the item is and reads it the right way:

- Connect chat and Contact Lens transcripts, Lex V2 conversation logs and
  Connect flow log events are conversations: prompt carryover, split turns,
  spoken forms (ConversationalPromptRecognizer).
- Any other JSON (Lambda logs, exports): each string or number is read with
  its key path and the labels of the objects that hold it as context.
- CSV: each column's cells with the column's name as context, as a table's.
  Plain text and log lines as they are.
- What an object is (binary, an archive, a document) is decided by its bytes
  before it gets here (`scan/sniff.py`, `scan/objects.py`).

The result is counts and offsets per class. Values exist only in memory for
the item being scanned; distinct values are counted by keyed hash.
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..detect.analyzer import Analysis, Detector
from ..detect.enhancer import humanize
from ..engine.conversation import utf16_index
from ..findings import ClassFinding, Offset
from ..parsers import (
    Conversation,
    is_flow_log,
    is_lex_record,
    parse_connect_transcript,
    parse_flow_log,
    parse_lex_records,
)

REDACTION_MARKER = re.compile(
    r"\[(?:PII|SSN|CREDIT_DEBIT_NUMBER|CREDIT_DEBIT_CVV|CREDIT_DEBIT_EXPIRY|PIN"
    r"|BANK_ACCOUNT_NUMBER|BANK_ROUTING|NAME|ADDRESS|EMAIL|PHONE|DATE_TIME|AGE|USERNAME"
    r"|PASSWORD|US_SOCIAL_SECURITY_NUMBER|REDACTED(?::[^\]\n]{1,120})?)\]"
)
_HAS_CANDIDATE = re.compile(
    r"[0-9]|\b(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)\b", re.I
)
MAX_LEAVES = 20_000
MAX_DOC_CONTEXT = 2_000
CSV_BATCH_ROWS = 500
MAX_LABELS = 64
_LONG_DIGITS = re.compile(r"[0-9]{4}")
# The formats read as a conversation (prompt carryover, split turns, spoken digits): what a
# change to the conversation spec can change (#67).
CONVERSATION_FORMATS = frozenset({"connect_chat", "contact_lens", "lex_v2_log", "connect_flow_log"})


def looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


@dataclass
class ItemResult:
    format: str
    findings: dict[str, ClassFinding] = field(default_factory=dict)
    redaction_markers: int = 0
    test_values: int = 0
    suppressed: int = 0
    contact_id: str | None = None
    instance_id: str | None = None

    @property
    def total(self) -> int:
        return sum(f.count for f in self.findings.values())

    def __repr__(self) -> str:
        # Counts by class only: an offset's pointer comes from the item's keys (#77).
        counts = {c: f.occurrences for c, f in sorted(self.findings.items())}
        return f"ItemResult(format={self.format!r}, findings={counts!r})"


class _Collector:
    def __init__(self, fmt: str) -> None:
        self.result = ItemResult(fmt)
        self._seen: dict[str, set[str]] = {}

    def add(self, analysis: Analysis, offsets_for: Any) -> None:
        self.result.test_values += analysis.test_values
        self.result.suppressed += analysis.suppressed
        for d in analysis.detections:
            cf = self.result.findings.setdefault(d.cls, ClassFinding(d.cls))
            seen = self._seen.setdefault(d.cls, set())
            key = d.value_key or f"span:{len(seen)}:{cf.occurrences}"
            new = key not in seen
            seen.add(key)
            cf.add(d.via, d.confidence, offsets_for(d), new)


def _conversation(collector: _Collector, detector: Detector, conv: Conversation, base: str) -> None:
    analysis = detector.analyze_conversation(conv.turns)

    def offsets(d: Any) -> list[Offset]:
        out = []
        for sp in d.spans:
            text = conv.turns[sp.turn].text
            out.append(
                Offset(
                    utf16_index(text, sp.start),
                    utf16_index(text, sp.end),
                    base + conv.pointers[sp.turn],
                )
            )
        return out

    collector.add(analysis, offsets)
    for t in conv.turns:
        collector.result.redaction_markers += len(REDACTION_MARKER.findall(t.text))
    if conv.contact_id and not collector.result.contact_id:
        collector.result.contact_id = conv.contact_id
        collector.result.instance_id = conv.instance_id


def _pointer_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def _labels(obj: dict[Any, Any]) -> list[str]:
    """An object's labels: its short string values with no run of four digits ("SSN" in
    `{"label": "SSN", "value": ...}`). Never its keys: a key names its own value only."""
    return [
        v
        for v in obj.values()
        if isinstance(v, str) and len(v) <= 80 and not _LONG_DIGITS.search(v)
    ]


def _json_leaves(collector: _Collector, detector: Detector, doc: Any, base: str) -> None:
    """Each string and number in a JSON document, read with its own key path and the labels
    of the objects that hold it as context (#75). Not the document's other keys: one
    `dateOfBirth` key in a log record must not make the record's `timestamp` a birth
    date, nor an `ssn` key the routing number beside it an SSN."""
    leaves = 0

    def visit(v: Any, path: list[str], labels: tuple[str, ...], depth: int) -> None:
        nonlocal leaves
        if leaves > MAX_LEAVES or depth > 32:
            return
        if isinstance(v, bool) or v is None:
            return
        if isinstance(v, int | float | str):
            leaves += 1
            text = v if isinstance(v, str) else json.dumps(v)
            if not _HAS_CANDIDATE.search(text):
                return
            pointer = base + "".join("/" + _pointer_escape(p) for p in path)
            context = [humanize(" ".join(path)), humanize(" ".join(labels))[:MAX_DOC_CONTEXT]]
            analysis = detector.analyze_text(text, context)
            collector.add(
                analysis,
                lambda d: [
                    Offset(utf16_index(text, sp.start), utf16_index(text, sp.end), pointer)
                    for sp in d.spans
                ],
            )
            if isinstance(v, str):
                collector.result.redaction_markers += len(REDACTION_MARKER.findall(v))
            return
        if isinstance(v, list):
            for i, x in enumerate(v):
                visit(x, [*path, str(i)], labels, depth + 1)
        elif isinstance(v, dict):
            inner = labels if len(labels) > MAX_LABELS else (*labels, *_labels(v))
            for k, x in v.items():
                visit(x, [*path, str(k)], inner, depth + 1)

    visit(doc, [], (), 0)


def _json_format(doc: Any) -> str:
    if is_lex_record(doc):
        return "lex_v2_log"
    if is_flow_log(doc):
        return "connect_flow_log"
    return "json"


def _scan_json(collector: _Collector, detector: Detector, doc: Any, base: str = "") -> None:
    conv = parse_connect_transcript(doc)
    if conv is not None:
        collector.result.format = conv.format
        _conversation(collector, detector, conv, base)
        return
    if is_lex_record(doc):
        collector.result.format = "lex_v2_log"
        for c in parse_lex_records([doc]):
            # One record: its pointers are "/0/..."; the record is the document itself.
            fixed = [p.removeprefix("/0") for p in c.pointers]
            _conversation(collector, detector, Conversation(c.format, c.turns, fixed), base)
        return
    flow = parse_flow_log(doc)
    if flow is not None:
        collector.result.format = "connect_flow_log"
        _conversation(collector, detector, flow, base)
        return
    if collector.result.format == "text":
        collector.result.format = _json_format(doc)
    _json_leaves(collector, detector, doc, base)


def _parse_json(text: str) -> Any:
    t = text.strip()
    if not t or t[0] not in "{[":
        return None
    try:
        return json.loads(t)
    except (ValueError, RecursionError):  # not JSON, or nested past the parser's stack (#77)
        return None


def scan_item_text(name: str, text: str, detector: Detector) -> ItemResult:
    """Read one item's text. `name` (key or log group) only decides CSV and JSON Lines."""
    lower = name.lower().removesuffix(".gz")
    doc = _parse_json(text)
    if doc is not None:
        collector = _Collector("text")
        if isinstance(doc, list) and doc and all(is_lex_record(r) for r in doc):
            collector.result.format = "lex_v2_log"
            for c in parse_lex_records(doc):
                _conversation(collector, detector, c, "")
        else:
            _scan_json(collector, detector, doc)
        if collector.result.format == "text":
            collector.result.format = "json"
        return collector.result
    lines = text.split("\n")
    if lower.endswith((".jsonl", ".ndjson")) or re.match(r"^\s*\{.*\}\s*\n\s*\{", text, re.S):
        records = [(i, _parse_json(line)) for i, line in enumerate(lines)]
        parsed = [(i, r) for i, r in records if r is not None]
        if parsed:
            collector = _Collector("json")
            lex = [(i, r) for i, r in parsed if is_lex_record(r)]
            if lex:
                collector.result.format = "lex_v2_log"
                by_line = [r for _, r in lex]
                line_of = [i for i, _ in lex]
                for c in parse_lex_records(by_line):
                    # Pointers are "/<n>/..." over the Lex records; make them "/<line>/...".
                    fixed = [
                        re.sub(r"^/([0-9]+)/", lambda m: f"/{line_of[int(m[1])]}/", p)
                        for p in c.pointers
                    ]
                    _conversation(collector, detector, Conversation(c.format, c.turns, fixed), "")
            for i, r in parsed:
                if not is_lex_record(r):
                    _scan_json(collector, detector, r, f"/{i}")
            if collector.result.format == "text":
                collector.result.format = "json"
            return collector.result
    if lower.endswith((".csv", ".tsv")):
        return _scan_csv(text, "\t" if lower.endswith(".tsv") else ",", detector)
    collector = _Collector("text")
    analysis = detector.analyze_text(text)
    collector.add(
        analysis,
        lambda d: [
            Offset(utf16_index(text, sp.start), utf16_index(text, sp.end)) for sp in d.spans
        ],
    )
    collector.result.redaction_markers += len(REDACTION_MARKER.findall(text))
    return collector.result


def csv_cells(text: str, delimiter: str) -> Iterator[tuple[int, int, int, int]]:
    """Every cell of a CSV text as `(row, column, start, end)`: where its content sits in
    `text`. A quoted cell's content is what is between its quotes (a doubled quote stays
    doubled; it cannot be part of a value). A row ends at a line feed outside quotes."""
    n = len(text)
    row = col = 0
    i = 0
    while True:
        if i < n and text[i] == '"':
            start = j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            end = j
            k = min(j + 1, n)
            while k < n and text[k] != delimiter and text[k] != "\n":
                k += 1
        else:
            start = k = i
            while k < n and text[k] != delimiter and text[k] != "\n":
                k += 1
            end = k - 1 if k > start and text[k - 1] == "\r" else k
        yield row, col, start, end
        if k >= n:
            return
        if text[k] == delimiter:
            col += 1
        else:
            row += 1
            col = 0
        i = k + 1


def _scan_csv(text: str, delimiter: str, detector: Detector) -> ItemResult:
    """A CSV object, read as a table is (`columnar.py`): each column's cells, in batches of
    rows, with the column's own name (the first row's cell) as context. Not the whole
    header: an `ssn` column must not make the routing numbers beside it SSNs (#75)."""
    collector = _Collector("csv")
    collector.result.redaction_markers += len(REDACTION_MARKER.findall(text))
    header: list[str] = []
    batch: dict[int, list[tuple[int, int]]] = {}
    rows = 0

    def flush() -> None:
        for col, cells in sorted(batch.items()):
            _csv_column(collector, detector, text, cells, header[col] if col < len(header) else "")
        batch.clear()

    last_row = -1
    for row, col, start, end in csv_cells(text, delimiter):
        if row != last_row:
            last_row = row
            rows += 1
            if rows % CSV_BATCH_ROWS == 0:
                flush()
        if row == 0:
            header.append(humanize(text[start:end][:MAX_DOC_CONTEXT]))
        if end > start:
            batch.setdefault(col, []).append((start, end))
    flush()
    return collector.result


def _csv_column(
    collector: _Collector,
    detector: Detector,
    text: str,
    cells: list[tuple[int, int]],
    name: str,
) -> None:
    kept = [(s, e) for s, e in cells if _HAS_CANDIDATE.search(text, s, e)]
    if not kept:
        return
    starts: list[int] = []
    pos = 0
    for s, e in kept:
        starts.append(pos)
        pos += e - s + 1
    chunk = "\n".join(text[s:e] for s, e in kept)
    analysis = detector.analyze_text(chunk, [name])
    detections = []
    where: dict[int, int] = {}
    for d in analysis.detections:
        cells_of = {bisect.bisect_right(starts, sp.start) - 1 for sp in d.spans}
        if len(cells_of) != 1:
            continue  # a detection across two cells is none
        k = cells_of.pop()
        if all(sp.end <= starts[k] + kept[k][1] - kept[k][0] for sp in d.spans):
            detections.append(d)
            where[id(d)] = k

    def offsets(d: Any) -> list[Offset]:
        k = where[id(d)]
        base = kept[k][0] - starts[k]
        return [
            Offset(utf16_index(text, base + sp.start), utf16_index(text, base + sp.end))
            for sp in d.spans
        ]

    collector.add(
        Analysis(detections, analysis.test_values, analysis.suppressed),
        offsets,
    )


def scan_log_event(message: str, detector: Detector) -> ItemResult:
    """One CloudWatch Logs event: JSON (a flow log, a Lex record, a structured line), a
    Lambda line ending in JSON (`2026-09-28T... INFO {...}`), or plain text."""
    doc = _parse_json(message)
    if doc is not None:
        collector = _Collector("text")
        _scan_json(collector, detector, doc)
        if collector.result.format == "text":
            collector.result.format = "json"
        return collector.result
    brace = message.find("{")
    if brace > 0:
        tail = _parse_json(message[brace:])
        if tail is not None:
            collector = _Collector("lambda_log")
            head = message[:brace]
            analysis = detector.analyze_text(head)
            collector.add(
                analysis,
                lambda d: [
                    Offset(utf16_index(head, sp.start), utf16_index(head, sp.end)) for sp in d.spans
                ],
            )
            _scan_json(collector, detector, tail, "")
            collector.result.format = "lambda_log"
            return collector.result
    return scan_item_text("event.log", message, detector)
