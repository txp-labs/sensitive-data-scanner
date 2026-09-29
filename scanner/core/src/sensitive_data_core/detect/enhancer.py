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
  digits) and has none is dropped.

Results from the conversation engine already had their context judged; the
enhancer only raises a `shape` result to `context` when the caller's
context names its class.
"""

from __future__ import annotations

import re

from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.context_aware_enhancers import ContextAwareEnhancer
from presidio_analyzer.nlp_engine import NlpArtifacts

from ..engine.conversation import has_context
from ..engine.spec import Spec, load_spec
from .entities import (
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
            window = humanize(text[max(0, r.start - WINDOW_BEFORE) : r.end + WINDOW_AFTER])
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
