"""The accuracy benchmark (tests/bench_corpus.py, tests/bench_score.py).

The corpus is the same bytes on every build, every conversation it hands the engine's
runner is what the document's own parser reads, no output holds a planted value, and
accuracy has not fallen past `benchmark/baseline.json`. CI also runs
`python tests/bench_score.py --check`, which prints the whole report.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from bench_corpus import SPEC, Doc, build_corpus
from bench_score import BASELINE, baseline_json, regressions, run
from sensitive_data_core.parsers import parse_document

FORMATS = {
    "transcript_voice": "contact_lens",
    "transcript_chat": "connect_chat",
    "ivr_lex_log": "lex_v2_log",
}


@pytest.fixture(scope="module")
def corpus() -> list[Doc]:
    return build_corpus()


def test_the_corpus_is_the_same_on_every_build(corpus: list[Doc]) -> None:
    again = build_corpus()
    assert [(d.name, hashlib.sha256(d.data).hexdigest(), d.truth) for d in corpus] == [
        (d.name, hashlib.sha256(d.data).hexdigest(), d.truth) for d in again
    ]
    assert len({d.name for d in corpus}) == len(corpus)


def test_every_class_and_every_kind_of_document_is_there(corpus: list[Doc]) -> None:
    classes = {c for d in corpus for c in d.truth}
    assert classes == {
        "card", "us_ssn", "us_itin", "dob", "cvv", "pin", "account_number", "us_ssn_last4",
    }  # fmt: skip
    categories = {d.category for d in corpus}
    for want in ("bank_statement", "card_statement", "crm_csv", "hr_csv", "ticket_json",
                 "email", "transcript_voice", "transcript_chat", "ivr_dtmf_flow_log",
                 "ivr_lex_log", "pdf", "office_docx", "office_xlsx", "office_pptx", "app_log",
                 "access_log", "lambda_log", "parquet", "archive"):  # fmt: skip
        assert want in categories, want
    negatives = [d for d in corpus if d.category.startswith("neg:")]
    assert negatives and all(not d.truth for d in negatives)


def test_no_value_is_a_published_test_or_sample_number(corpus: list[Doc]) -> None:
    card = SPEC.classes["card"]
    for d in corpus:
        if d.category in ("neg:test_cards", "neg:ssa_irs_samples", "office_pptx"):
            continue
        assert not (d.values & set(card.test_numbers)), d.name
        assert not (d.values & set(SPEC.classes["us_ssn"].dummy_values)), d.name


def test_names_are_obviously_made_up(corpus: list[Doc]) -> None:
    from bench_corpus import FIRST, LAST

    names = re.compile(r"(?:Account holder: |From: |this is |Offer letter for )(\w+) (\w+)")
    seen = 0
    for d in corpus:
        if d.name.endswith((".txt", ".eml", ".json")):
            for m in names.finditer(d.data.decode()):
                seen += 1
                assert m[1] in FIRST and m[2] in LAST, d.name
    assert seen > 50


def test_the_engine_runner_reads_what_the_parser_reads(corpus: list[Doc]) -> None:
    for d in corpus:
        if d.category in FORMATS:
            parsed = [c.turns for c in parse_document(FORMATS[d.category], d.data.decode())]
            assert parsed == d.conversations, d.name
        elif d.category == "ivr_dtmf_flow_log":
            lines = d.data.decode().splitlines()
            parsed = [parse_document("connect_flow_log", line)[0].turns for line in lines]
            assert parsed == d.conversations, d.name
        else:
            assert not d.conversations, d.name


def test_no_regression_and_no_leak() -> None:
    results = run()
    assert not [x for r in results.values() for x in r.leaks]
    base = json.loads(BASELINE.read_text())
    assert base["specVersion"] == SPEC.spec_version
    assert regressions(baseline_json(results), base) == []
