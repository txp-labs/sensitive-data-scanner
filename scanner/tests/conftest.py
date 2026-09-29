"""Shared paths for the tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
    from sensitive_data_scanner.engine.conversation import Turn

    return [
        Turn(t["speaker"], t["text"], t.get("channel"), t.get("beginMs"), t.get("endMs"))
        for t in case["turns"]
    ]
