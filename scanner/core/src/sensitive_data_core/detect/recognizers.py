"""Presidio recognizers for the spec's classes.

- `SpecCreditCardRecognizer`, `SpecUsSsnRecognizer` and
  `SpecUsItinRecognizer` extend Presidio's own card, SSN and ITIN
  recognizers (pattern and checksum) with the spec's rules: the IIN table,
  published test numbers, SSN and ITIN structure and sample numbers.
- `DateOfBirthRecognizer` finds dates; `SpecContextEnhancer` keeps one only
  next to a DOB word.
- `SpokenDigitsRecognizer` finds card numbers and SSNs read aloud in one
  text ("four five three nine ..."), through the spec's normalization.
- `ConversationalPromptRecognizer` reads a whole transcript, one turn per
  line, and applies the spec's prompt carryover: a bot or agent turn asking
  for class X classes the next customer turn as X, whatever its shape. It
  also joins a value split across the same speaker's turns.

None of them records the text it matched: a result is an entity type, a
span, a score and metadata about how it was found.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any, ClassVar

from presidio_analyzer import EntityRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    UsItinRecognizer,
    UsSsnRecognizer,
)

from ..engine.conversation import SPEAKERS, Turn, classify
from ..engine.normalize import normalize
from ..engine.rules import (
    card_brand,
    is_test_card,
    itin_structure_valid,
    luhn_valid,
    plausible_birth_date,
    ssn_structure_valid,
)
from ..engine.spec import Spec, load_spec
from .entities import (
    CLASS_TO_ENTITY,
    COUNT_ONLY_SCORE,
    META_CONFIDENCE,
    META_ENGINE,
    META_EXCLUDED,
    META_MATCH_ID,
    META_NEEDS_CONTEXT,
    META_TURN,
    META_VALUE_KEY,
    META_VIA,
    SCORE,
)

# A per-process random key: distinct values can be counted without keeping them.
_VALUE_KEY = secrets.token_bytes(32)


def value_key(digits: str) -> str:
    """A keyed hash of a value, for counting distinct values within one run. Not reversible."""
    return hmac.new(_VALUE_KEY, digits.encode(), hashlib.sha256).hexdigest()[:24]


def _digits(s: str) -> str:
    return "".join(c for c in s if "0" <= c <= "9")


def _result(entity: str, start: int, end: int, score: float, **meta: Any) -> RecognizerResult:
    return RecognizerResult(entity, start, end, score, recognition_metadata=dict(meta))


# ------------------------------------------------------------ card


def card_grouping(raw: str) -> str:
    """plain, printed (4-4-4-4, 4-6-5, ...), spaced_digits or odd."""
    seps = re.findall(r"[ -]", raw)
    if not seps:
        return "plain"
    if len(set(seps)) > 1:
        return "odd"
    groups = [len(g) for g in re.split(r"[ -]", raw)]
    if all(g == 1 for g in groups):
        return "spaced_digits"
    key = "-".join(str(g) for g in groups)
    if re.fullmatch(r"4-4-4-[1-4]|4-4-4-4-[1-3]|4-6-5|4-6-4", key):
        return "printed"
    return "odd"


class SpecCreditCardRecognizer(CreditCardRecognizer):
    """Presidio's card recognizer, plus the 2-series and 19-digit ranges and the spec's rules."""

    CARD_PATTERNS: ClassVar[list[Pattern]] = [
        *CreditCardRecognizer.PATTERNS,
        Pattern(
            "Card, 13-19 digits (weak)",
            r"(?<![\w])(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)(?![\w])",
            0.3,
        ),
    ]

    def __init__(self, spec: Spec | None = None, **kwargs: Any) -> None:
        self.spec = spec or load_spec()
        super().__init__(patterns=self.CARD_PATTERNS, **kwargs)

    def validate_result(self, pattern_text: str) -> bool:
        # Judged in analyze(), which sees the span; None keeps the pattern's score.
        return None  # type: ignore[return-value]

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        card = self.spec.classes["card"]
        out: list[RecognizerResult] = []
        for r in super().analyze(text, entities, nlp_artifacts, regex_flags):
            raw = text[r.start : r.end]
            grouping = card_grouping(raw)
            if grouping == "odd":
                continue
            digits = _digits(raw)
            if not (luhn_valid(digits) and card_brand(digits, self.spec.brands)):
                continue
            key = value_key(digits)
            if is_test_card(digits, card):
                out.append(
                    _result(
                        r.entity_type,
                        r.start,
                        r.end,
                        COUNT_ONLY_SCORE,
                        **{
                            META_EXCLUDED: "test",
                            META_VALUE_KEY: key,
                        },
                    )
                )
                continue
            out.append(
                _result(
                    r.entity_type,
                    r.start,
                    r.end,
                    SCORE["medium"],
                    **{
                        META_VIA: "shape",
                        META_CONFIDENCE: "medium",
                        META_NEEDS_CONTEXT: grouping == "spaced_digits",
                        META_VALUE_KEY: key,
                    },
                )
            )
        return out


# ------------------------------------------------------------ SSN


class SpecUsSsnRecognizer(UsSsnRecognizer):
    """Presidio's SSN recognizer with the spec's structure rules and sample numbers.

    The dashed or spaced form counts alone (medium); nine bare digits only
    with an SSN word nearby, which the context enhancer decides.
    """

    SSN_PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("SSN formatted (medium)", r"\b([0-9]{3})([- ])([0-9]{2})\2([0-9]{4})\b", 0.5),
        Pattern("SSN nine digits (very weak)", r"\b[0-9]{9}\b", 0.05),
    ]

    def __init__(self, spec: Spec | None = None, **kwargs: Any) -> None:
        self.spec = spec or load_spec()
        super().__init__(patterns=self.SSN_PATTERNS, **kwargs)

    def invalidate_result(self, pattern_text: str) -> bool:
        return not ssn_structure_valid(_digits(pattern_text))

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        ssn = self.spec.classes["us_ssn"]
        out: list[RecognizerResult] = []
        for r in super().analyze(text, entities, nlp_artifacts, regex_flags):
            raw = text[r.start : r.end]
            digits = _digits(raw)
            key = value_key(digits)
            if digits in ssn.dummy_values:
                out.append(
                    _result(
                        r.entity_type,
                        r.start,
                        r.end,
                        COUNT_ONLY_SCORE,
                        **{
                            META_EXCLUDED: "test",
                            META_VALUE_KEY: key,
                        },
                    )
                )
                continue
            formatted = len(raw) == 11
            out.append(
                _result(
                    r.entity_type,
                    r.start,
                    r.end,
                    SCORE["medium"] if formatted else 0.05,
                    **{
                        META_VIA: "shape",
                        META_CONFIDENCE: "medium",
                        META_NEEDS_CONTEXT: not formatted,
                        META_VALUE_KEY: key,
                    },
                )
            )
        return out


# ------------------------------------------------------------ ITIN


class SpecUsItinRecognizer(UsItinRecognizer):
    """Presidio's ITIN recognizer with the spec's structure rules and advertising numbers.

    Like an SSN: the dashed or spaced form counts alone (medium); nine bare
    digits only with an ITIN or SSN word nearby, which the context enhancer
    decides. The IRS advertising range is counted apart as test data.
    """

    ITIN_PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("ITIN formatted (medium)", r"\b(9[0-9]{2})([- ])([0-9]{2})\2([0-9]{4})\b", 0.5),
        Pattern("ITIN nine digits (very weak)", r"\b9[0-9]{8}\b", 0.05),
    ]

    def __init__(self, spec: Spec | None = None, **kwargs: Any) -> None:
        self.spec = spec or load_spec()
        super().__init__(patterns=self.ITIN_PATTERNS, **kwargs)

    def invalidate_result(self, pattern_text: str) -> bool:
        return not itin_structure_valid(_digits(pattern_text))

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        itin = self.spec.classes["us_itin"]
        out: list[RecognizerResult] = []
        for r in super().analyze(text, entities, nlp_artifacts, regex_flags):
            raw = text[r.start : r.end]
            digits = _digits(raw)
            if not itin_structure_valid(digits):
                continue
            key = value_key(digits)
            if digits in itin.test_numbers:
                out.append(
                    _result(
                        r.entity_type,
                        r.start,
                        r.end,
                        COUNT_ONLY_SCORE,
                        **{
                            META_EXCLUDED: "test",
                            META_VALUE_KEY: key,
                        },
                    )
                )
                continue
            formatted = len(raw) == 11
            out.append(
                _result(
                    r.entity_type,
                    r.start,
                    r.end,
                    SCORE["medium"] if formatted else 0.05,
                    **{
                        META_VIA: "shape",
                        META_CONFIDENCE: "medium",
                        META_NEEDS_CONTEXT: not formatted,
                        META_VALUE_KEY: key,
                    },
                )
            )
        return out


# ------------------------------------------------------------ date of birth

_MONTHS = (
    "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    "|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)
_MONTH_NUM = {
    m: i + 1
    for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
    )
}


class DateOfBirthRecognizer(EntityRecognizer):
    """Dates that could be a birth date; kept only next to a DOB word (see SpecContextEnhancer)."""

    _PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"(?<![0-9])([0-9]{1,2})[/.-]([0-9]{1,2})[/.-]([0-9]{4}|[0-9]{2})(?![0-9])"),
        re.compile(r"(?<![0-9])([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?![0-9])"),
        re.compile(rf"\b({_MONTHS})\.?\s+([0-9]{{1,2}})(?:st|nd|rd|th)?,?\s+([0-9]{{4}})\b", re.I),
        re.compile(
            rf"\b([0-9]{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?({_MONTHS})\.?,?\s+([0-9]{{4}})\b",
            re.I,
        ),
    ]

    def __init__(self, now: _dt.date | None = None) -> None:
        self.now = now
        super().__init__(supported_entities=[CLASS_TO_ENTITY["dob"]], name="DateOfBirthRecognizer")

    def load(self) -> None:
        return None

    def _plausible(self, idx: int, m: re.Match[str]) -> bool:
        now_year = (self.now or _dt.datetime.now(_dt.UTC).date()).year
        g = m.groups()
        if idx == 0:
            a, b, y = int(g[0]), int(g[1]), int(g[2])
            if len(g[2]) == 2:
                y = 2000 + y if 2000 + y <= now_year else 1900 + y
            return plausible_birth_date(y, a, b, now_year) or plausible_birth_date(
                y, b, a, now_year
            )
        if idx == 1:
            return plausible_birth_date(int(g[0]), int(g[1]), int(g[2]), now_year)
        if idx == 2:
            month, day, year = _MONTH_NUM[g[0][:3].lower()], int(g[1]), int(g[2])
        else:
            day, month, year = int(g[0]), _MONTH_NUM[g[1][:3].lower()], int(g[2])
        return plausible_birth_date(year, month, day, now_year)

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts | None = None
    ) -> list[RecognizerResult]:
        out: list[RecognizerResult] = []
        for idx, rx in enumerate(self._PATTERNS):
            for m in rx.finditer(text):
                if self._plausible(idx, m):
                    out.append(
                        _result(
                            self.supported_entities[0],
                            m.start(),
                            m.end(),
                            0.05,
                            **{
                                META_VIA: "context",
                                META_CONFIDENCE: "high",
                                META_NEEDS_CONTEXT: True,
                            },
                        )
                    )
        return out


# ------------------------------------------------------------ the conversation engine


def _engine_results(
    spec: Spec,
    turns: list[Turn],
    offsets: list[int],
    now: _dt.date | None,
    entities: list[str],
    *,
    spoken_only: bool = False,
) -> list[RecognizerResult]:
    """The engine's matches as Presidio results: one result per part of each value."""
    r = classify(spec, turns, now)
    out: list[RecognizerResult] = []
    for n, m in enumerate(r.matches):
        entity = CLASS_TO_ENTITY.get(m.cls, m.cls.upper())
        if entities and entity not in entities:
            continue
        if spoken_only and not any(
            re.search(r"[A-Za-z]", turns[p.turn].text[p.orig_start : p.orig_end]) for p in m.parts
        ):
            continue  # digits as digits: the pattern recognizers handle them
        # The value's digits, for counting distinct values (hashed, never kept).
        digits = "".join(
            _digits_from_norm(spec, turns[p.turn].text, p.start, p.end) for p in m.parts
        )
        for p in m.parts:
            out.append(
                _result(
                    entity,
                    offsets[p.turn] + p.orig_start,
                    offsets[p.turn] + p.orig_end,
                    SCORE[m.confidence],
                    **{
                        META_VIA: m.via,
                        META_CONFIDENCE: m.confidence,
                        META_ENGINE: True,
                        META_MATCH_ID: n,
                        META_TURN: p.turn,
                        META_VALUE_KEY: value_key(digits),
                    },
                )
            )
    for i, x in enumerate(r.excluded):
        entity = CLASS_TO_ENTITY.get(x.cls, x.cls.upper())
        # A distinct one-character span per exclusion, so Presidio's de-duplication keeps each.
        start = offsets[x.turn] + i
        out.append(
            _result(
                entity,
                start,
                start + 1,
                COUNT_ONLY_SCORE,
                **{
                    META_EXCLUDED: "test",
                    META_ENGINE: True,
                    META_TURN: x.turn,
                },
            )
        )
    return out


def _digits_from_norm(spec: Spec, text: str, start: int, end: int) -> str:
    return _digits(normalize(text, spec.normalize).text[start:end])


class SpokenDigitsRecognizer(EntityRecognizer):
    """Card numbers, SSNs and ITINs read aloud in one text, after the spec's normalization.

    Only values that were at least partly spoken as words are reported;
    values written as digits are the pattern recognizers' job.
    """

    def __init__(self, spec: Spec | None = None, now: _dt.date | None = None) -> None:
        self.spec = spec or load_spec()
        self.now = now
        super().__init__(
            supported_entities=[CLASS_TO_ENTITY[c] for c in ("card", "us_ssn", "us_itin", "dob")],
            name="SpokenDigitsRecognizer",
        )

    def load(self) -> None:
        return None

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts | None = None
    ) -> list[RecognizerResult]:
        if not re.search(
            r"\b(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)\b", text, re.I
        ):
            return []
        turns = [Turn("customer", text)]
        results = _engine_results(self.spec, turns, [0], self.now, entities, spoken_only=True)
        return [r for r in results if not (r.recognition_metadata or {}).get(META_EXCLUDED)]


# ------------------------------------------------------------ transcripts

_LINE = re.compile(
    r"^(bot|agent|customer)(?:/(speech|dtmf|chat))?(?:@([0-9]+)(?:-([0-9]+))?)?: (.*)$"
)


@dataclass(frozen=True)
class RenderedTranscript:
    text: str
    turns: list[Turn]
    offsets: list[int]  # where each turn's text starts in `text`


def render_transcript(turns: list[Turn]) -> RenderedTranscript:
    """Turns as the text ConversationalPromptRecognizer reads.

    One line per turn: `speaker[/channel][@begin[-end]]: text`.
    """
    lines: list[str] = []
    offsets: list[int] = []
    pos = 0
    clean: list[Turn] = []
    for t in turns:
        if t.speaker not in SPEAKERS:
            raise ValueError("speaker must be bot, agent or customer")
        head = t.speaker
        if t.channel:
            head += f"/{t.channel}"
        if t.begin_ms is not None:
            head += f"@{t.begin_ms}" + (f"-{t.end_ms}" if t.end_ms is not None else "")
        body = t.text.replace("\r", " ").replace("\n", " ")
        prefix = f"{head}: "
        offsets.append(pos + len(prefix))
        lines.append(prefix + body)
        pos += len(prefix) + len(body) + 1
        clean.append(Turn(t.speaker, body, t.channel, t.begin_ms, t.end_ms))
    return RenderedTranscript("\n".join(lines), clean, offsets)


def parse_transcript(text: str) -> RenderedTranscript | None:
    """The turns in a rendered transcript, or None if `text` is not one."""
    turns: list[Turn] = []
    offsets: list[int] = []
    pos = 0
    for line in text.split("\n"):
        m = _LINE.match(line)
        if not m:
            return None
        begin = int(m[3]) if m[3] else None
        end = int(m[4]) if m[4] else None
        turns.append(Turn(m[1], m[5], m[2], begin, end))
        offsets.append(pos + m.start(5))
        pos += len(line) + 1
    return RenderedTranscript(text, turns, offsets) if turns else None


class ConversationalPromptRecognizer(EntityRecognizer):
    """Question-then-answer recognition over a transcript (one turn per line).

    A bot or agent turn that asks for a class of data ("Please enter your
    nine digit Social Security number") marks the next customer turn as that
    class, whatever its shape: `123456789#` is an SSN there, and a
    Luhn-failing `5555666677778888#` after a card prompt is a card with low
    confidence. The context word sits in the previous speaker's turn, where
    Presidio's same-text context enhancement cannot see it.
    """

    def __init__(self, spec: Spec | None = None, now: _dt.date | None = None) -> None:
        self.spec = spec or load_spec()
        self.now = now
        super().__init__(
            supported_entities=list(CLASS_TO_ENTITY.values()),
            name="ConversationalPromptRecognizer",
        )

    def load(self) -> None:
        return None

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts | None = None
    ) -> list[RecognizerResult]:
        rendered = parse_transcript(text)
        if rendered is None:
            return []
        return _engine_results(self.spec, rendered.turns, rendered.offsets, self.now, entities)
