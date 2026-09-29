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
