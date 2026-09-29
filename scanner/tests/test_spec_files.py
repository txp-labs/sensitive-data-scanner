"""The spec files and vectors are well formed and follow their JSON Schemas."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from conftest import (
    SPEC_DIR,
    VECTORS_DIR,
    all_conversation_vectors,
    conversation_vector_files,
    load_jsonl,
)


def schema(name: str) -> Draft202012Validator:
    with (SPEC_DIR / "schema" / name).open(encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)
    Draft202012Validator.check_schema(raw)
    return Draft202012Validator(raw, format_checker=Draft202012Validator.FORMAT_CHECKER)


def load_yaml(name: str) -> dict[str, Any]:
    with (SPEC_DIR / name).open(encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return data


@pytest.mark.parametrize(
    ("yaml_name", "schema_name"),
    [("classes.yaml", "classes.schema.json"), ("normalize.yaml", "normalize.schema.json")],
)
def test_spec_file_follows_schema(yaml_name: str, schema_name: str) -> None:
    errors = list(schema(schema_name).iter_errors(load_yaml(yaml_name)))
    assert errors == []


def test_spec_version_is_0_1() -> None:
    assert load_yaml("classes.yaml")["specVersion"] == "0.1"
    assert load_yaml("normalize.yaml")["specVersion"] == "0.1"


def test_prompt_phrases_and_exclusions_compile() -> None:
    for cls in load_yaml("classes.yaml")["classes"].values():
        for phrase in cls["promptPhrases"] + cls.get("contextExclusions", []):
            re.compile(phrase, re.I | re.A)
            # The portable subset: no lookbehind, no named groups, no inline flags.
            assert "(?<" not in phrase
            assert "(?P" not in phrase
            assert not re.search(r"\(\?[aiLmsux]", phrase)


def test_v0_stugum_prompts_and_classes_are_present() -> None:
    classes = load_yaml("classes.yaml")["classes"]
    assert set(classes) >= {
        "us_ssn",
        "card",
        "dob",
        "cvv",
        "pin",
        "account_number",
        "us_ssn_last4",
    }
    assert "last four of your social" not in classes["us_ssn"]["promptPhrases"]
    assert "last four of your social" in classes["us_ssn_last4"]["promptPhrases"]


@pytest.mark.parametrize("path", conversation_vector_files(), ids=lambda p: p.name)
def test_conversation_vectors_follow_schema(path: Any) -> None:
    validator = schema("vector.schema.json")
    for case in load_jsonl(path):
        errors = [e.message for e in validator.iter_errors(case)]
        assert errors == [], case.get("id")


def test_normalize_vectors_follow_schema() -> None:
    validator = schema("normalize-vector.schema.json")
    for case in load_jsonl(VECTORS_DIR / "normalize.jsonl"):
        assert [e.message for e in validator.iter_errors(case)] == [], case["id"]
        for start, end, o_start, o_end in case["digitRuns"]:
            assert case["normalized"][start:end].isdigit()
            assert 0 <= o_start < o_end <= len(case["text"])


def test_vector_ids_are_unique() -> None:
    ids = [c["id"] for c in all_conversation_vectors()]
    ids += [c["id"] for c in load_jsonl(VECTORS_DIR / "normalize.jsonl")]
    assert len(ids) == len(set(ids))


def test_expectations_point_at_real_turns() -> None:
    for case in all_conversation_vectors():
        n = len(case["turns"])
        for e in case["expect"]:
            assert 0 <= e["turn"] < n, case["id"]
            end_turn = e.get("endTurn", e["turn"])
            assert e["turn"] <= end_turn < n, case["id"]
            if end_turn == e["turn"]:
                assert e["start"] < e["end"], case["id"]


def test_every_stugum_live_case_is_present() -> None:
    """The Stugum live-run cases listed in txp-labs/mermera-attestation-app#1059."""
    cases = load_jsonl(VECTORS_DIR / "stugum-live.jsonl")
    texts = {t["text"] for c in cases for t in c["turns"]}
    for keyed in [
        "010180#",
        "0230#",
        "123456789#",
        "12345678#",
        "1111222233334444#",
        "5555666677778888#",
    ]:
        assert keyed in texts, keyed
    for spoken in [
        "January first, nineteen eighty",
        "one two three four five six seven eight nine",
        "one one one one two two two two three three three three four four four four",
    ]:
        assert spoken in texts, spoken
    assert any(t.startswith("Sorry. I didn't get that.") for t in texts)
    prompts = " ".join(texts).lower()
    for prompt in ["date of birth", "nine digit social security number", "credit card number"]:
        assert prompt in prompts
