"""The TypeScript package and the Python engine agree on every vector.

Runs packages/spec-ts/scripts/parity.ts with Node and compares everything it
prints with the Python results: normalized text and digit-run offsets, and for
each conversation the matches with their original offsets and parts, the
exclusions and the suppression count. Any difference fails the test.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any

import pytest

from conftest import REPO, VECTORS_DIR, all_conversation_vectors, load_jsonl, turns_of, vector_now
from sensitive_data_core.engine.conversation import classify, utf16_index
from sensitive_data_core.engine.normalize import normalize
from sensitive_data_core.engine.spec import load_spec

SPEC = load_spec()
PARITY_SCRIPT = REPO / "packages" / "spec-ts" / "scripts" / "parity.ts"


@pytest.fixture(scope="module")
def ts_results() -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("SDS_REQUIRE_PARITY") == "1":
            pytest.fail("Node is required for the parity test (SDS_REQUIRE_PARITY=1)")
        pytest.skip("Node is not installed")
    proc = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [node, str(PARITY_SCRIPT), str(VECTORS_DIR)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    data: dict[str, Any] = json.loads(proc.stdout)
    return data


def test_normalization_parity(ts_results: dict[str, Any]) -> None:
    cases = load_jsonl(VECTORS_DIR / "normalize.jsonl")
    assert set(ts_results["normalize"]) == {c["id"] for c in cases}
    for case in cases:
        n = normalize(case["text"], SPEC.normalize)
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
        assert ts_results["normalize"][case["id"]] == {"normalized": n.text, "digitRuns": runs}, (
            case["id"]
        )


def python_result(case: dict[str, Any]) -> dict[str, Any]:
    turns = turns_of(case)
    r = classify(SPEC, turns, vector_now(case), utf16=True)
    return {
        "normalized": [normalize(t.text, SPEC.normalize).text for t in turns],
        "matches": [
            {
                "class": m.cls,
                "via": m.via,
                "confidence": m.confidence,
                "turn": m.turn,
                "start": m.start,
                "endTurn": m.end_turn,
                "end": m.end,
                "origStart": m.orig_start,
                "origEnd": m.orig_end,
                "parts": [
                    {
                        "turn": p.turn,
                        "start": p.start,
                        "end": p.end,
                        "origStart": p.orig_start,
                        "origEnd": p.orig_end,
                    }
                    for p in m.parts
                ],
            }
            for m in r.matches
        ],
        "excluded": [{"class": x.cls, "turn": x.turn} for x in r.excluded],
        "suppressed": r.suppressed,
    }


def test_conversation_parity(ts_results: dict[str, Any]) -> None:
    cases = all_conversation_vectors()
    assert set(ts_results["conversations"]) == {c["id"] for c in cases}
    disagreements = [
        c["id"] for c in cases if ts_results["conversations"][c["id"]] != python_result(c)
    ]
    assert disagreements == []
