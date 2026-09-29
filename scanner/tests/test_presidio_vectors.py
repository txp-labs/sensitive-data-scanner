"""The Presidio path (ConversationalPromptRecognizer in an AnalyzerEngine with
no NLP model) gives the same answer as the vectors for every case."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import all_conversation_vectors, turns_of, vector_now
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import utf16_index
from sensitive_data_core.engine.normalize import normalize
from sensitive_data_core.engine.spec import load_spec

SPEC = load_spec()
CONVERSATIONS = all_conversation_vectors()
DETECTORS: dict[Any, Detector] = {}


def detector(now: Any) -> Detector:
    if now not in DETECTORS:
        DETECTORS[now] = Detector(SPEC, now)
    return DETECTORS[now]


@pytest.mark.parametrize("case", CONVERSATIONS, ids=lambda c: c["id"])
def test_presidio_matches_vector(case: dict[str, Any]) -> None:
    turns = turns_of(case)
    analysis = detector(vector_now(case)).analyze_conversation(turns)
    got = []
    for d in analysis.detections:
        first, last = d.spans[0], d.spans[-1]
        assert first.turn is not None and last.turn is not None
        got.append(
            (
                d.cls,
                d.via,
                d.confidence,
                first.turn,
                utf16_index(turns[first.turn].text, first.start),
                last.turn,
                utf16_index(turns[last.turn].text, last.end),
            )
        )
    want = []
    for e in case["expect"]:
        end_turn = e.get("endTurn", e["turn"])
        n_first = normalize(turns[e["turn"]].text, SPEC.normalize)
        n_last = normalize(turns[end_turn].text, SPEC.normalize)
        # Vector spans are UTF-16 over normalized text; map them to code points first.
        cp_start = _cp(n_first.text, e["start"])
        cp_end = _cp(n_last.text, e["end"])
        o_start = n_first.to_original(cp_start, cp_start + 1)[0]
        o_end = n_last.to_original(cp_end - 1, cp_end)[1]
        want.append(
            (
                e["class"],
                e["via"],
                e["confidence"],
                e["turn"],
                utf16_index(turns[e["turn"]].text, o_start),
                end_turn,
                utf16_index(turns[end_turn].text, o_end),
            )
        )
    assert sorted(got) == sorted(want)


def _cp(text: str, utf16: int) -> int:
    units = 0
    for i, c in enumerate(text):
        if units >= utf16:
            return i
        units += 2 if ord(c) > 0xFFFF else 1
    return len(text)
