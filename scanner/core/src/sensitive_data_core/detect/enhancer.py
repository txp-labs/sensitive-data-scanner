"""Context enhancement without an NLP model.

Presidio's default enhancer finds context words through the NLP engine's
lemmas. This scanner runs Presidio with no NLP model, so this enhancer does
it with the spec's context words over a character window around each match,
plus any context the caller passes (a JSON key path, a CSV header, the
document's own labels):

- a context word raises a match to high confidence, via `context`;
- a card number next to a word like "order" or "phone", and no card word, is
  suppressed;
- a match that needs context (nine bare digits, a date, single spaced
  digits) and has none is dropped;
- a date's window stops at the nearest other date on each side, so a DOB
  word gives its context to the date it labels, not to every date after it.

Results from the conversation engine already had their context judged; the
enhancer only raises a `shape` result to `context` when the caller's
context names its class.
"""

from __future__ import annotations

import bisect
import re

from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.context_aware_enhancers import ContextAwareEnhancer
from presidio_analyzer.nlp_engine import NlpArtifacts

from ..engine.conversation import has_context
from ..engine.spec import Spec, load_spec
from .entities import (
    CLASS_TO_ENTITY,
    COUNT_ONLY_SCORE,
    ENTITY_TO_CLASS,
    META_CONFIDENCE,
    META_ENGINE,
    META_EXCLUDED,
    META_NEEDS_CONTEXT,
    META_SUPPRESSED,
    META_VIA,
    SCORE,
)

WINDOW_BEFORE = 64
WINDOW_AFTER = 32


def humanize(s: str) -> str:
    """ "cardNumber", "card_number" -> "card Number", "card number": key names become words."""
    return re.sub(r"([a-z])([A-Z])", r"\1 \2", s).replace("_", " ")


DOB_ENTITY = CLASS_TO_ENTITY["dob"]

# A field whose name ends in one of these words holds a time, never a date of birth (#101):
# `createdAt`, `updated_at`, `startTime`, `eventTimestamp`, `created`, `hire_date`.
_TIMESTAMP_LAST_WORDS = frozenset({"at", "time", "timestamp", "created", "updated", "date"})
# ... unless the name is a birth name: `birthDate`, `birth_date`, `dob_date`.
_BIRTH_NAME = re.compile(r"birth|dob|born", re.I)


def timestamp_name(name: str | None) -> bool:
    """Whether a field (a key, an attribute, a column) is named like a timestamp, which makes
    it negative context for `dob`: its value is never a date of birth."""
    if not name or _BIRTH_NAME.search(name):
        return False
    words = re.split(r"[^a-z0-9]+", humanize(name).lower())
    words = [w for w in words if w]
    return bool(words) and words[-1] in _TIMESTAMP_LAST_WORDS


def _between_dates(
    dates: list[tuple[int, int]], start: int, end: int, lo: int, hi: int
) -> tuple[int, int]:
    """The window around the date at `start`-`end`, cut at the nearest other date on each
    side: in "date of birth 03/14/1985, charged on 09/03/2026" the DOB words belong to the
    first date, not the second (#75)."""
    i = bisect.bisect_left(dates, (start, end))
    for _s, e in reversed(dates[:i]):
        if e <= start:
            lo = max(lo, e)
            break
    for s, _e in dates[i:]:
        if s >= end:
            hi = min(hi, s)
            break
    return lo, hi


class SpecContextEnhancer(ContextAwareEnhancer):
    def __init__(self, spec: Spec | None = None) -> None:
        super().__init__(
            context_similarity_factor=0.35,
            min_score_with_context_similarity=SCORE["high"],
            context_prefix_count=0,
            context_suffix_count=0,
        )
        self.spec = spec or load_spec()

    def enhance_using_context(
        self,
        text: str,
        raw_results: list[RecognizerResult],
        nlp_artifacts: NlpArtifacts,
        recognizers: list[EntityRecognizer],
        context: list[str] | None = None,
    ) -> list[RecognizerResult]:
        extra = humanize(" ".join(context or []))
        # Where each date sits: a date's context window stops at the next date on each side.
        dates = sorted(
            (r.start, r.end)
            for r in raw_results
            if r.entity_type == DOB_ENTITY and not (r.recognition_metadata or {}).get(META_ENGINE)
        )
        out: list[RecognizerResult] = []
        for r in raw_results:
            meta = r.recognition_metadata or {}
            cls_name = ENTITY_TO_CLASS.get(r.entity_type)
            if cls_name is None or meta.get(META_EXCLUDED):
                out.append(r)
                continue
            cls = self.spec.classes[cls_name]
            if meta.get(META_ENGINE):
                if meta.get(META_VIA) == "shape" and extra and has_context(cls, extra):
                    self._raise(r)
                out.append(r)
                continue
            lo, hi = max(0, r.start - WINDOW_BEFORE), r.end + WINDOW_AFTER
            if r.entity_type == DOB_ENTITY:
                lo, hi = _between_dates(dates, r.start, r.end, lo, hi)
            window = humanize(text[lo:hi])
            around = f"{extra}\n{window}"
            if has_context(cls, around):
                self._raise(r)
                out.append(r)
                continue
            if cls.suppress_re is not None and cls.suppress_re.search(around):
                r.score = COUNT_ONLY_SCORE
                meta[META_SUPPRESSED] = True
                r.recognition_metadata = meta
                out.append(r)
                continue
            if meta.get(META_NEEDS_CONTEXT):
                continue
            out.append(r)
        return out

    @staticmethod
    def _raise(r: RecognizerResult) -> None:
        meta = r.recognition_metadata or {}
        meta[META_VIA] = "context"
        meta[META_CONFIDENCE] = "high"
        meta[META_NEEDS_CONTEXT] = False
        r.recognition_metadata = meta
        r.score = max(r.score, SCORE["high"])
