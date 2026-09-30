"""Shared paths for the tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_fixtures import env  # noqa: F401 - the moto-backed AWS fixture, for every test module

REPO = Path(__file__).resolve().parents[2]
SPEC_DIR = REPO / "spec"
VECTORS_DIR = REPO / "vectors"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def conversation_vector_files() -> list[Path]:
    return sorted(p for p in VECTORS_DIR.glob("*.jsonl") if p.name != "normalize.jsonl")


def all_conversation_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in conversation_vector_files():
        out.extend(load_jsonl(path))
    return out


VECTOR_DATE = __import__("datetime").date(2026, 9, 29)


def vector_now(case: dict[str, Any]) -> Any:
    import datetime as dt

    return dt.date.fromisoformat(case["now"]) if case.get("now") else VECTOR_DATE


def turns_of(case: dict[str, Any]) -> list[Any]:
    from sensitive_data_core.engine.conversation import Turn

    return [
        Turn(t["speaker"], t["text"], t.get("channel"), t.get("beginMs"), t.get("endMs"))
        for t in case["turns"]
    ]


# Hypothesis profiles for the reader fuzz tests (tests/test_fuzz_readers.py, #77). The
# normal run is derandomized and short, so a failure is reproducible and CI is quick;
# `--hypothesis-profile=fuzz` is CI's time-capped fuzz step, and `fuzz-long` a local run.
def _hypothesis_profiles() -> None:
    from hypothesis import HealthCheck, settings

    common: dict[str, Any] = {
        "deadline": None,
        "suppress_health_check": [HealthCheck.too_slow, HealthCheck.data_too_large],
    }
    settings.register_profile("default", max_examples=40, derandomize=True, database=None, **common)
    settings.register_profile("fuzz", max_examples=600, **common)
    settings.register_profile("fuzz-long", max_examples=50_000, **common)
    settings.load_profile("default")


_hypothesis_profiles()
