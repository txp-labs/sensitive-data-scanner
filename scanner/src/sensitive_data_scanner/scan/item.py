"""One item (an S3 object, a log event) to per-class findings.

Works out what the item is and reads it the right way:

- Connect chat and Contact Lens transcripts, Lex V2 conversation logs and
  Connect flow log events are conversations: prompt carryover, split turns,
  spoken forms (ConversationalPromptRecognizer).
- Any other JSON (Lambda logs, exports): each string or number is read with
  its key path and the document's own labels as context.
- CSV: the header row is context for every row. Plain text and log lines as
  they are.
- Binary formats are not read; the caller counts them by kind.

The result is counts and offsets per class. Values exist only in memory for
the item being scanned; distinct values are counted by keyed hash.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..detect.analyzer import Analysis, Detector
from ..detect.enhancer import humanize
from ..engine.conversation import utf16_index
from ..findings import ClassFinding, Offset
from ..sources.parsers import (
    Conversation,
    is_flow_log,
    is_lex_record,
    parse_connect_transcript,
    parse_flow_log,
    parse_lex_records,
)

SKIP_BY_EXT = {
    **dict.fromkeys(["wav", "mp3", "ogg", "opus", "flac", "m4a", "aac"], "audio"),
    **dict.fromkeys(["webm", "mp4", "mov", "mkv"], "video"),
    **dict.fromkeys(["png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp"], "image"),
    **dict.fromkeys(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"], "document"),
    **dict.fromkeys(["zip", "tar", "tgz", "7z", "bz2"], "archive"),
    **dict.fromkeys(["parquet", "avro", "orc", "bin", "exe", "so", "class", "jar"], "binary"),
}

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


def classify_key(key: str) -> tuple[bool, bool, str | None]:
    """(read it, gunzip it, else the kind of file it is)."""
    lower = key.lower()
    gz = lower.endswith(".gz")
    base = lower[:-3] if gz else lower
    ext = base.rsplit(".", 1)[1] if "." in base.rsplit("/", 1)[-1] else ""
    kind = SKIP_BY_EXT.get(ext)
    if kind:
        return False, False, kind
    return True, gz, None


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


def _document_context(doc: Any) -> str:
    parts: list[str] = []
    size = 0

    def visit(v: Any, depth: int) -> None:
        nonlocal size
        if size > MAX_DOC_CONTEXT or depth > 12:
            return
        if isinstance(v, str):
            if len(v) <= 80 and not re.search(r"[0-9]{4}", v):
                parts.append(v)
                size += len(v)
        elif isinstance(v, list):
            for x in v:
                visit(x, depth + 1)
        elif isinstance(v, dict):
            for k, x in v.items():
                parts.append(str(k))
                size += len(str(k))
                visit(x, depth + 1)

    visit(doc, 0)
    return humanize(" ".join(parts))


def _json_leaves(collector: _Collector, detector: Detector, doc: Any, base: str) -> None:
    doc_context = _document_context(doc)
    leaves = 0

    def visit(v: Any, path: list[str], depth: int) -> None:
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
            context = [humanize(" ".join(path)), doc_context]
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
                visit(x, [*path, str(i)], depth + 1)
        elif isinstance(v, dict):
            for k, x in v.items():
                visit(x, [*path, str(k)], depth + 1)

    visit(doc, [], 0)


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
    except ValueError:
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
        collector = _Collector("csv")
        header = humanize(lines[0]) if lines else ""
        analysis = detector.analyze_text(text, [header])
        collector.add(
            analysis,
            lambda d: [
                Offset(utf16_index(text, sp.start), utf16_index(text, sp.end)) for sp in d.spans
            ],
        )
        collector.result.redaction_markers += len(REDACTION_MARKER.findall(text))
        return collector.result
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
