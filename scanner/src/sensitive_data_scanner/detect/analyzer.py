"""The Presidio AnalyzerEngine this scanner runs, with no NLP model.

`Detector.analyze_text` reads stored text (an S3 object, a log event, a JSON
field); `Detector.analyze_conversation` reads a transcript's turns. Both
return `Detection`s: a class, how it was found, how confident, and where.
Never the value.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NoOpNlpEngine

from ..engine.conversation import Turn
from ..engine.spec import Spec, load_spec
from .enhancer import SpecContextEnhancer
from .entities import (
    ENTITY_TO_CLASS,
    META_CONFIDENCE,
    META_EXCLUDED,
    META_MATCH_ID,
    META_SUPPRESSED,
    META_TURN,
    META_VALUE_KEY,
    META_VIA,
    confidence_of,
)
from .recognizers import (
    ConversationalPromptRecognizer,
    DateOfBirthRecognizer,
    SpecCreditCardRecognizer,
    SpecUsItinRecognizer,
    SpecUsSsnRecognizer,
    SpokenDigitsRecognizer,
    render_transcript,
)


@dataclass(frozen=True)
class Span:
    start: int  # code points, in the analyzed text (or in the turn's text)
    end: int
    turn: int | None = None


@dataclass(frozen=True)
class Detection:
    """One value found. Its location, never its content."""

    cls: str
    via: str
    confidence: str
    spans: tuple[Span, ...]
    value_key: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"Detection(cls={self.cls!r}, via={self.via!r}, confidence={self.confidence!r})"


@dataclass
class Analysis:
    detections: list[Detection] = field(default_factory=list)
    test_values: int = 0  # published test or sample numbers, set aside
    suppressed: int = 0  # numbers next to "order", "phone"... with no card word


def build_engine(spec: Spec, now: _dt.date | None) -> AnalyzerEngine:
    registry = RecognizerRegistry(supported_languages=["en"])
    for rec in (
        SpecCreditCardRecognizer(spec),
        SpecUsSsnRecognizer(spec),
        SpecUsItinRecognizer(spec),
        DateOfBirthRecognizer(now),
        SpokenDigitsRecognizer(spec, now),
    ):
        registry.add_recognizer(rec)
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=NoOpNlpEngine(models=[{"lang_code": "en", "model_name": "none"}]),
        supported_languages=["en"],
        context_aware_enhancer=SpecContextEnhancer(spec),
    )


def build_conversation_engine(spec: Spec, now: _dt.date | None) -> AnalyzerEngine:
    registry = RecognizerRegistry(supported_languages=["en"])
    registry.add_recognizer(ConversationalPromptRecognizer(spec, now))
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=NoOpNlpEngine(models=[{"lang_code": "en", "model_name": "none"}]),
        supported_languages=["en"],
        context_aware_enhancer=SpecContextEnhancer(spec),
    )


def _analysis(results: list[RecognizerResult], turn_offsets: list[int] | None) -> Analysis:
    out = Analysis()
    grouped: dict[int, list[RecognizerResult]] = {}
    singles: list[RecognizerResult] = []
    for r in sorted(results, key=lambda x: (x.start, x.end)):
        meta = r.recognition_metadata or {}
        if meta.get(META_EXCLUDED):
            out.test_values += 1
            continue
        if meta.get(META_SUPPRESSED):
            out.suppressed += 1
            continue
        if meta.get(META_MATCH_ID) is not None:
            grouped.setdefault(int(meta[META_MATCH_ID]), []).append(r)
        else:
            singles.append(r)

    def span(r: RecognizerResult) -> Span:
        meta = r.recognition_metadata or {}
        turn = meta.get(META_TURN)
        if turn_offsets is not None and turn is not None:
            base = turn_offsets[int(turn)]
            return Span(r.start - base, r.end - base, int(turn))
        return Span(r.start, r.end)

    def detection(parts: list[RecognizerResult]) -> Detection:
        meta = parts[0].recognition_metadata or {}
        return Detection(
            cls=ENTITY_TO_CLASS.get(parts[0].entity_type, parts[0].entity_type.lower()),
            via=str(meta.get(META_VIA, "shape")),
            confidence=str(meta.get(META_CONFIDENCE) or confidence_of(parts[0].score)),
            spans=tuple(span(p) for p in parts),
            value_key=meta.get(META_VALUE_KEY),
        )

    for parts in grouped.values():
        out.detections.append(detection(parts))
    for r in singles:
        out.detections.append(detection([r]))
    out.detections.sort(key=lambda d: (d.spans[0].turn or 0, d.spans[0].start))
    return out


class Detector:
    """The scanner's detection: Presidio with the spec's recognizers, no NLP model."""

    def __init__(self, spec: Spec | None = None, now: _dt.date | None = None) -> None:
        self.spec = spec or load_spec()
        self.now = now
        self._text = build_engine(self.spec, now)
        self._conversation = build_conversation_engine(self.spec, now)

    def analyze_text(self, text: str, context: list[str] | None = None) -> Analysis:
        """Stored text: card, SSN and ITIN patterns and checksums, dates of birth, spoken digits."""
        results = self._text.analyze(text=text, language="en", context=context or [])
        return _analysis(results, None)

    def analyze_conversation(self, turns: list[Turn]) -> Analysis:
        """A transcript: prompt carryover, split turns, spoken forms, shape and context."""
        if not turns:
            return Analysis()
        rendered = render_transcript(turns)
        results = self._conversation.analyze(text=rendered.text, language="en")
        return _analysis(results, rendered.offsets)
