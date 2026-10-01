"""Timestamps are never dates of birth, and a DOB prompt's context stays local (#101).

A real-account run classed about 590 ISO-8601 timestamps in Stugum's run items as `dob`
at high confidence: `createdAt`, `updatedAt`, `stepResults[].startedAt` and the like,
beside a step whose `observedText` was a bot's "please enter your date of birth".

- A full timestamp (a date with a time of day and/or a zone, epoch seconds or
  milliseconds, RFC 2822) is never `dob`, in stored text or in a conversation (spec 0.7).
- A field named like a timestamp (`createdAt`, `updated_at`, `startTime`, `hire_date`)
  holds no `dob`, unless the name is a birth name (`birthDate`).
- A DOB prompt in one attribute lends no context to its siblings: a configured prompt
  reaches only its paired keypad entry, and a sentence is not a label.

Every value is made up.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from aws_fixtures import shared_detector
from ddb_fixtures import target
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import Turn, classify
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.scan.attributes import AttributeRules, scan_attributes
from sensitive_data_core.scan.item import scan_item_text
from sensitive_data_core.scan.paths import parse_path
from sensitive_data_scanner.config import DynamoTarget
from sensitive_data_scanner.sources.dynamodb import DynamoDBSource

DET = Detector(now=dt.date(2026, 9, 29))
SPEC = load_spec()
NOW = dt.date(2026, 9, 29)
DOB_PROMPT = "Please enter your date of birth as m m d d y y y y, then press pound."
TIMESTAMPS = (
    "2026-09-29T14:36:01.123Z",
    "2026-09-29T14:36:01Z",
    "2026-09-29T14:36:01.123-05:00",
    "2026-09-29T14:36:01+00:00",
    "2026-09-29 14:36:01",
    "2026-09-29 14:36",
    "09/29/2026 14:36",
    "Tue, 29 Sep 2026 14:36:01 +0000",
    "29 Sep 2026 14:36:01 GMT",
)
EPOCHS = ("1759156561123", "1759156561")


def S(v: str) -> dict[str, str]:
    return {"S": v}


def N(v: str) -> dict[str, str]:
    return {"N": v}


def run_item(dtmf: str | None = None, **top: Any) -> dict[str, Any]:
    """A Stugum-shaped run item: timestamps everywhere, a DOB prompt in one step."""

    def step(index: int, kind: str, **attrs: dict[str, str]) -> dict[str, Any]:
        return {
            "M": {
                "kind": S(kind),
                "stepIndex": N(str(index)),
                "startedAt": S(f"2026-09-29T14:36:0{index}.000Z"),
                "endedAt": S(f"2026-09-29T14:36:0{index}.900Z"),
                **attrs,
            }
        }

    steps = [step(0, "waitForPrompt", observedText=S(DOB_PROMPT))]
    if dtmf is not None:
        steps.append(step(1, "sendDtmf", observedDtmf=S(dtmf)))
    item: dict[str, Any] = {
        "pk": S("T#t_0000example"),
        "sk": S("RUN#r_0000example"),
        "createdAt": S("2026-09-29T14:36:00.123Z"),
        "updatedAt": S("2026-09-29T14:38:12.456Z"),
        "estimatedCostUpdatedAt": S("2026-09-29T14:38:12Z"),
        "lastHeardText": S(DOB_PROMPT),
        "stepResults": {"L": steps},
        "assertions": {
            "L": [
                {
                    "M": {
                        "name": S("date of birth prompt heard"),
                        "evaluatedAt": S("2026-09-29T14:38:11.000Z"),
                    }
                }
            ]
        },
    }
    item.update(top)
    return item


def rules_of(t: DynamoTarget) -> AttributeRules:
    from ddb_fixtures import Ddb

    return DynamoDBSource(Ddb().client, target=t, region="us-west-2").rules


def found(item: dict[str, Any], rules: AttributeRules) -> dict[str, dict[str, str]]:
    result = scan_attributes(item, shared_detector(), rules)
    return {p: {c: f.confidence for c, f in r.findings.items()} for p, r in result.by_path.items()}


# ---------------------------------------------------------------- the report, reproduced


def test_timestamps_beside_a_dob_prompt_are_not_dobs_with_no_configuration() -> None:
    """The reported shape: every attribute read, nothing configured."""
    assert found(run_item(), AttributeRules()) == {}


def test_timestamps_beside_a_dob_prompt_are_not_dobs_with_stugums_configuration() -> None:
    every = rules_of(target(include=()))
    assert found(run_item(), every) == {}


def test_the_paired_keypad_entry_is_still_the_dob() -> None:
    every = rules_of(target(include=()))
    assert found(run_item("03141985#"), every) == {"stepResults[].observedDtmf": {"dob": "high"}}
    # With no prompt path configured, a keypad entry still takes its own step's strings as
    # the prompt (a step labeled "Enter date of birth").
    keypad_only = AttributeRules(keypad=(parse_path("stepResults[].observedDtmf"),))
    item = run_item("03141985#")
    item["stepResults"]["L"][1]["M"]["label"] = S("Enter date of birth")
    assert found(item, keypad_only) == {"stepResults[].observedDtmf": {"dob": "high"}}


# ---------------------------------------------------------------- context stays local


def test_a_configured_prompt_lends_no_context_to_a_sibling() -> None:
    """A date in a sibling attribute is not a birth date because a prompt sits beside it."""
    item = run_item()
    item["stepResults"]["L"][0]["M"]["note"] = S("rescheduled to 10/04/2026")
    item["stepResults"]["L"][0]["M"]["scheduled"] = S("2026-10-04")
    every = rules_of(target(include=()))
    assert found(item, every) == {}


def test_a_prompt_sentence_is_not_a_label_for_its_siblings() -> None:
    item = {
        "pk": S("T#1"),
        "step": {"M": {"observedText": S(DOB_PROMPT), "scheduled": S("2026-10-04")}},
    }
    assert found(item, AttributeRules()) == {}
    doc = {"observedText": DOB_PROMPT, "scheduled": "2026-10-04"}
    assert classes("item.json", json.dumps(doc)) == {}


def test_a_sibling_key_name_is_not_context() -> None:
    """#84's rule for JSON, now for DynamoDB too: a key names its own value only."""
    item = {"pk": S("T#1"), "person": {"M": {"dob": S("[REDACTED]"), "seen": S("2026-09-01")}}}
    assert found(item, AttributeRules()) == {}


def test_a_label_still_names_its_value() -> None:
    item = {"pk": S("T#1"), "field": {"M": {"label": S("Date of birth"), "value": S("1985-03-14")}}}
    assert found(item, AttributeRules()) == {"field.value": {"dob": "high"}}
    item = {"pk": S("T#1"), "dateOfBirth": S("03/14/1985")}
    assert found(item, AttributeRules()) == {"dateOfBirth": {"dob": "high"}}


# ---------------------------------------------------------------- timestamp names


@pytest.mark.parametrize(
    "name",
    [
        "createdAt",
        "updatedAt",
        "estimatedCostUpdatedAt",
        "evaluated_at",
        "startTime",
        "timestamp",
        "eventTimestamp",
        "created",
        "last_updated",
        "hire_date",
        "date",
        "invoiceDate",
    ],
)
def test_a_timestamp_name_holds_no_dob(name: str) -> None:
    item = {"pk": S("T#1"), "m": {"M": {"label": S("Date of birth"), name: S("1985-03-14")}}}
    assert found(item, AttributeRules()) == {}
    doc = {"label": "Date of birth", name: "1985-03-14"}
    assert classes("item.json", json.dumps(doc)) == {}
    assert classes("x.csv", f"date_of_birth,{name}\n03/14/1985,03/15/1985\n") == {"dob": 1}


@pytest.mark.parametrize("name", ["birthDate", "birth_date", "dateOfBirth", "dob", "DOB_date"])
def test_a_birth_name_is_not_a_timestamp_name(name: str) -> None:
    item = {"pk": S("T#1"), name: S("1985-03-14")}
    assert found(item, AttributeRules()) == {name: {"dob": "high"}}


# ---------------------------------------------------------------- timestamps in text


@pytest.mark.parametrize("ts", TIMESTAMPS)
def test_a_timestamp_beside_a_dob_word_is_not_a_dob(ts: str) -> None:
    assert classes("t.txt", f"Date of birth confirmed {ts}") == {}
    assert classes("t.txt", f"DOB: {ts}") == {}
    item = {"pk": S("T#1"), "dob_checked": S(ts)}
    assert found(item, AttributeRules()) == {}


def test_a_bare_date_beside_a_timestamp_is_still_a_dob() -> None:
    text = "2026-09-29T14:36:01Z customer date of birth 1985-03-14 verified"
    item = scan_item_text("t.log", text, DET)
    assert {c: f.occurrences for c, f in item.findings.items()} == {"dob": 1}
    o = item.findings["dob"].offsets[0]
    assert text[o.start : o.end] == "1985-03-14"


@pytest.mark.parametrize("epoch", EPOCHS)
def test_epoch_times_are_not_dobs(epoch: str) -> None:
    assert classes("t.txt", f"date of birth checked at {epoch}") == {}
    item = {"pk": S("T#1"), "m": {"M": {"label": S("Date of birth"), "at": N(epoch)}}}
    assert found(item, AttributeRules()) == {}


# ---------------------------------------------------------------- conversations (spec 0.7)


@pytest.mark.parametrize("value", TIMESTAMPS + EPOCHS)
def test_a_timestamp_after_a_dob_prompt_is_not_a_dob(value: str) -> None:
    turns = [Turn("bot", "What is your date of birth?"), Turn("customer", value, "chat")]
    assert [m.cls for m in classify(SPEC, turns, NOW).matches] == []


@pytest.mark.parametrize("value", ["03/14/1985", "1985-03-14", "03141985", "031485"])
def test_a_bare_date_after_a_dob_prompt_is_still_a_dob(value: str) -> None:
    turns = [Turn("bot", "What is your date of birth?"), Turn("customer", value, "chat")]
    got = [(m.cls, m.confidence) for m in classify(SPEC, turns, NOW).matches]
    assert got == [("dob", "high")]


def classes(name: str, text: str) -> dict[str, int]:
    return {c: f.occurrences for c, f in scan_item_text(name, text, DET).findings.items()}
