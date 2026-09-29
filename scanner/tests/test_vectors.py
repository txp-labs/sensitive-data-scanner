"""The spec engine passes every vector: normalization pairs and conversation cases."""

from __future__ import annotations

import re
from typing import Any

import pytest

from conftest import VECTORS_DIR, all_conversation_vectors, load_jsonl, turns_of, vector_now
from sensitive_data_core.engine.conversation import classify, utf16_index
from sensitive_data_core.engine.normalize import normalize
from sensitive_data_core.engine.spec import load_spec

SPEC = load_spec()
NORMALIZE = load_jsonl(VECTORS_DIR / "normalize.jsonl")
CONVERSATIONS = all_conversation_vectors()


@pytest.mark.parametrize("case", NORMALIZE, ids=lambda c: c["id"])
def test_normalize_vector(case: dict[str, Any]) -> None:
    n = normalize(case["text"], SPEC.normalize)
    assert n.text == case["normalized"]
    runs = []
    for m in re.finditer(r"[0-9]+", n.text):
        o_s, o_e = n.to_original(m.start(), m.end())
        runs.append(
            [
                utf16_index(n.text, m.start()),
                utf16_index(n.text, m.end()),
                utf16_index(case["text"], o_s),
                utf16_index(case["text"], o_e),
            ]
        )
    assert runs == case["digitRuns"]


def expectation(e: dict[str, Any]) -> dict[str, Any]:
    out = {k: e[k] for k in ("turn", "class", "start", "end", "via", "confidence")}
    out["endTurn"] = e.get("endTurn", e["turn"])
    return out


@pytest.mark.parametrize("case", CONVERSATIONS, ids=lambda c: c["id"])
def test_conversation_vector(case: dict[str, Any]) -> None:
    result = classify(SPEC, turns_of(case), vector_now(case), utf16=True)
    got = [
        {
            "turn": m.turn,
            "class": m.cls,
            "start": m.start,
            "end": m.end,
            "via": m.via,
            "confidence": m.confidence,
            "endTurn": m.end_turn,
        }
        for m in result.matches
    ]
    assert got == [expectation(e) for e in case["expect"]]


def test_there_are_enough_vectors() -> None:
    assert len(CONVERSATIONS) >= 60
    assert len(NORMALIZE) >= 30
