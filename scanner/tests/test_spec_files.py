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
from sensitive_data_core.engine.conversation import has_context, prompt_classes
from sensitive_data_core.engine.spec import load_spec


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


def test_spec_version_is_0_6() -> None:
    assert load_yaml("classes.yaml")["specVersion"] == "0.6"
    assert load_yaml("normalize.yaml")["specVersion"] == "0.6"


def test_the_last_four_exclusion_is_one_shared_string() -> None:
    """Spec 0.6: us_ssn and us_itin hold the same last-four exclusion, so a consumer (Stugum)
    can take the shared set; and us_ssn_last4 arms on every possessive it excludes."""
    classes = load_yaml("classes.yaml")["classes"]
    last4 = [
        [e for e in classes[c]["contextExclusions"] if e.startswith("last ")]
        for c in ("us_ssn", "us_itin")
    ]
    assert len(last4[0]) == 1 and last4[0] == last4[1]
    exclusion = re.compile(last4[0][0], re.IGNORECASE)
    (prompt,) = classes["us_ssn_last4"]["promptPhrases"]
    phrase = re.compile(prompt, re.IGNORECASE)
    for text in (
        "last four of my social",
        "last 4 digits of your social security number",
        "last four of the ssn",
        "last four my social",
    ):
        assert exclusion.fullmatch(text), text
        assert phrase.fullmatch(text), text
    assert exclusion.fullmatch("last four of my itin")
    assert phrase.fullmatch("last four of my itin") is None  # an ITIN's last four: not a class


def test_prompt_phrases_leave_boundaries_to_the_implementation() -> None:
    # Spec 0.3: implementations apply the boundary, so no phrase carries \b.
    for cls in load_yaml("classes.yaml")["classes"].values():
        for phrase in cls["promptPhrases"]:
            assert "\\b" not in phrase, phrase


def test_prompted_without_shape_is_gone() -> None:
    # Spec 0.3: every class is low when a prompted value passes no shape.
    for cls in load_yaml("classes.yaml")["classes"].values():
        assert "promptedWithoutShape" not in cls


def test_retry_prefixes_are_words_without_punctuation() -> None:
    for prefix in load_yaml("classes.yaml")["retryPrefixes"]:
        assert not re.search(r"[.,!?;:A-Z]", prefix), prefix


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
    spec = load_spec()
    assert prompt_classes(spec, "What's the last four of your social?")[0] == ("us_ssn_last4",)
    assert prompt_classes(spec, "last 4 of your ssn")[0] == ("us_ssn_last4",)


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


@pytest.mark.parametrize(
    ("text", "classes"),
    [
        ("I'm being stubborn about it.", ()),
        ("When were you born?", ("dob",)),
        ("Enter the 14 digit code.", ()),
        ("Enter the 4 digit code.", ("cvv",)),
        ("SSN:", ("us_ssn", "us_itin")),
        # Spec 0.4: "nine digit social" with "number" dropped; never "social media".
        ("Please say your nine digit social.", ("us_ssn", "us_itin")),
        ("Enter your 9-digit Social Security.", ("us_ssn", "us_itin")),
        ("Please read me your nine digit social media account number.", ("account_number",)),
        ("Which social media do you use?", ()),
        ("Say your social.", ()),
        ("Enter the 19 digit social code.", ()),
    ],
)
def test_prompt_phrases_match_on_boundaries(text: str, classes: tuple[str, ...]) -> None:
    # Spec 0.3: no letter or digit on either side of a prompt phrase.
    assert prompt_classes(load_spec(), text)[0] == classes


@pytest.mark.parametrize(
    ("text", "retry"),
    [
        ("Sorry, I didn't get that!", True),
        ("Sorry. I didn\u2019t get that.", True),
        ("  sorry; i didn't   catch that?", True),
        ("I'm sorry I didn't catch that.", True),
        ("Okay. Sorry, I didn't get that.", False),
        ("Sorry I didn't get thatcher's file.", False),
        ("Sorry, I missed that.", False),
    ],
)
def test_retry_prefixes_ignore_punctuation(text: str, retry: bool) -> None:
    # Spec 0.3: . , ! ? ; : and whitespace runs between the words; only at the start.
    assert prompt_classes(load_spec(), text)[1] is retry


@pytest.mark.parametrize(
    ("context", "cls", "found"),
    [
        # Spec 0.5 (#75): "social media" is not an SSN or ITIN word; "social" still is.
        ("Shared on social media, post", "us_ssn", False),
        ("found you on Social-Media", "us_itin", False),
        ("my social is", "us_ssn", True),
        ("my social, not my social media", "us_ssn", True),
        ("social security", "us_itin", True),
    ],
)
def test_social_media_is_not_ssn_context(context: str, cls: str, found: bool) -> None:
    assert has_context(load_spec().classes[cls], context) is found
