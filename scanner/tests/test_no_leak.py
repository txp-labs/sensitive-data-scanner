"""No value leaves: not in findings, events, logs, exception messages or reprs.

Every vector is scanned end to end (as an S3 object and as log events),
along with #1067's synthetic values in every stored form, and the DynamoDB
fixtures (positive and negative controls, and items whose key holds a
value) through the DynamoDB source. Every output is searched for every
candidate value. A second set of tests audits the source:
the only log call is `safety.log_event` with a fixed event name, and no
exception carries a message from below.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from aws_fixtures import RESULTS, Env, config, epoch_ms
from conftest import all_conversation_vectors, turns_of
from ddb_fixtures import FIXTURES, Ddb, load_item, page, target
from sensitive_data_scanner import safety
from sensitive_data_scanner.detect.analyzer import Detector
from sensitive_data_scanner.engine.conversation import classify
from sensitive_data_scanner.engine.normalize import normalize
from sensitive_data_scanner.engine.spec import load_spec
from sensitive_data_scanner.safety import ScanError, redact_digits
from sensitive_data_scanner.scan.attributes import AttributeRules, scan_attributes
from sensitive_data_scanner.scan.item import scan_item_text
from sensitive_data_scanner.scan.paths import parse_path
from synthetic import CARDS, SSN_A, SSN_B, all_values, dashed, printed, spaced, spoken_groups

SPEC = load_spec()
VECTORS = all_conversation_vectors()
PACKAGE = Path(__file__).resolve().parents[1] / "src" / "sensitive_data_scanner"
DIGIT_WORD = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"


def candidates() -> set[str]:
    """Every value a vector or fixture holds: digit runs of 6 or more, raw and normalized."""
    out = set(all_values())
    for case in VECTORS:
        for t in case["turns"]:
            for text in (t["text"], normalize(t["text"], SPEC.normalize).text):
                out.update(m[0] for m in re.finditer(r"[0-9]{6,}", text))
                for m in re.finditer(r"[0-9](?:[ -]?[0-9]){5,}", text):
                    out.add(m[0])
                    out.add(re.sub(r"[ -]", "", m[0]))
    for path in FIXTURES.glob("*.json"):
        out.update(m[0] for m in re.finditer(r"[0-9]{6,}", path.read_text()))
    return out


CANDIDATES = candidates()


def leaks(blob: str) -> list[str]:
    found = [c for c in CANDIDATES if re.search(rf"(?<![0-9]){re.escape(c)}(?![0-9])", blob)]
    if re.search(rf"\b{DIGIT_WORD}(?:[ ,]+{DIGIT_WORD}){{3,}}\b", blob, re.I):
        found.append("<spoken digits>")
    return found


def chat_document(case: dict[str, Any]) -> str:
    """A vector without a source document, as a Connect chat transcript."""
    role = {"agent": "AGENT", "customer": "CUSTOMER", "bot": "SYSTEM"}
    return json.dumps(
        {
            "Version": "2019-08-26",
            "ContactId": "11111111-2222-3333-4444-555555555555",
            "Transcript": [
                {
                    "Type": "MESSAGE",
                    "Content": t["text"],
                    "ParticipantId": t["speaker"],
                    "ParticipantRole": role[t["speaker"]],
                    "AbsoluteTime": "2026-09-28T15:00:00.000Z",
                }
                for t in case["turns"]
            ],
        }
    )


STORED = [
    ("stored/printed.txt", f"card {printed(CARDS['visa'])}"),
    ("stored/plain.log", f"value={CARDS['jcb']} ssn {dashed(SSN_A)} social {SSN_B}"),
    ("stored/export.csv", "name,card_number\n" + "\n".join(CARDS.values())),
    ("stored/spaced.txt", f"card: {spaced(CARDS['amex'])}"),
    ("stored/spoken.txt", f"my visa is {spoken_groups(CARDS['visa'])}"),
    (
        "stored/lambda.json",
        json.dumps({"cardNumber": CARDS["mir"], "ssn": dashed(SSN_B), "dob": "DOB 7/4/1981"}),
    ),
]


def test_candidates_cover_every_class_of_value() -> None:
    assert {CARDS["visa"], SSN_A, "010180", "123456789", "5555666677778888"} <= CANDIDATES


def test_no_value_in_findings_events_or_logs(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    for case in VECTORS:
        doc = case.get("document")
        if doc and doc["format"] == "lex_v2_log":
            env.put(f"vectors/{case['id']}.jsonl", doc["content"])
        elif doc:
            env.put(f"vectors/{case['id']}.json", doc["content"])
        else:
            env.put(f"vectors/{case['id']}.json", chat_document(case))
    for key, body in STORED:
        env.put(key, body)
    t = epoch_ms(__import__("datetime").datetime.now(__import__("datetime").UTC)) - 3_600_000
    messages = [(t + i, t_["text"]) for i, case in enumerate(VECTORS) for t_ in case["turns"][:1]]
    messages += [(t + 1000 + i, body) for i, (_, body) in enumerate(STORED)]
    env.log("/aws/lambda/everything", "stream", sorted(messages))

    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(log_groups=["/aws/lambda/everything"], event_bus_arn="arn:aws:events:x:1:b/c")
    )
    assert doc is not None
    assert doc["findingsTotal"] > 40  # the scan did find things
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for obj in env.clients.s3.list_objects_v2(Bucket=RESULTS)["Contents"]:
        if obj["Key"].startswith("findings/"):
            data = env.clients.s3.get_object(Bucket=RESULTS, Key=obj["Key"])["Body"].read()
            outputs[obj["Key"]] = data.decode()
    for name, blob in outputs.items():
        assert leaks(blob) == [], name


def ddb_items() -> list[dict[str, Any]]:
    """The positive and negative controls, and the positive one keyed by a card and an SSN."""
    keyed = load_item("stugum-positive")
    keyed["pk"] = {"S": f"CUST#{SSN_B}"}
    keyed["sk"] = {"S": f"CARD#{CARDS['mastercard']}"}
    return [load_item("stugum-positive"), load_item("stugum-negative"), keyed]


def test_no_value_leaves_the_dynamodb_source(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    ddb = Ddb()
    ddb.describe()
    ddb.error("query", "ProvisionedThroughputExceededException")  # a throttle is logged
    ddb.query(page(ddb_items()))
    env.clients.dynamodb = ddb.client
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(s3_targets=[], dynamodb_targets=[target()], event_bus_arn="arn:aws:events:x:1:b/c")
    )
    assert doc is not None
    assert doc["findingsTotal"] >= 12  # both keyed items, steps and stepResults, three classes
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for name, blob in outputs.items():
        assert leaks(blob) == [], name
    detector = __import__("aws_fixtures").shared_detector()
    rules = AttributeRules(
        keypad=(parse_path("stepResults[].observedDtmf"), parse_path("steps[].digits")),
        prompts=(parse_path("stepResults[].heard"), parse_path("steps[].text")),
    )
    results = [scan_attributes(item, detector, rules) for item in ddb_items()]
    assert results[0].by_path  # the positive control was found
    blobs = [repr(r) + repr(list(r.by_path.values())) for r in results]
    assert leaks("\n".join(blobs)) == []


def test_ddb_candidates_hold_the_fixture_values() -> None:
    assert {"010180", "123456789", "5555666677778888", SSN_B, CARDS["mastercard"]} <= CANDIDATES


def test_a_value_in_an_object_key_is_masked(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.put(f"receipts/{CARDS['visa']}.txt", f"card {CARDS['visa']}")
    doc = env.run(config())
    assert doc is not None
    f = doc["findings"][0]
    assert f["resource"]["key"] == "receipts/################.txt"
    assert f["resource"]["keyMasked"] is True
    assert f["link"] is None
    assert leaks(json.dumps(doc) + "".join(capsys.readouterr())) == []


def test_exceptions_quote_nothing(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.put("stored/a.txt", f"card {CARDS['visa']}")

    class Boom(Detector):
        def analyze_text(self, text: str, context: list[str] | None = None) -> Any:
            raise ValueError(f"cannot read {text}")

    env.detector = Boom.__new__(Boom)
    doc = env.run(config())
    assert doc is not None
    assert doc["coverage"][0]["unreadable"] == 1
    assert doc["coverage"][0]["error"] == "ValueError"
    assert leaks(json.dumps(doc) + "".join(capsys.readouterr())) == []

    def refuse(**kwargs: Any) -> Any:
        raise RuntimeError(f"denied writing {CARDS['visa']}")

    env.detector = __import__("aws_fixtures").shared_detector()
    env.clients.s3.put_object = refuse  # type: ignore[method-assign]
    with pytest.raises(ScanError) as info:
        env.run(config(results_prefix="elsewhere/"))
    assert leaks(str(info.value) + repr(info.value) + "".join(capsys.readouterr())) == []


def test_reprs_hold_no_values() -> None:
    detector = __import__("aws_fixtures").shared_detector()
    blobs = []
    for case in VECTORS:
        turns = turns_of(case)
        r = classify(SPEC, turns)
        blobs.append(repr(r.matches) + repr(r.excluded))
        a = detector.analyze_conversation(turns)
        blobs.append(repr(a) + repr(a.detections))
    for _, body in STORED:
        item = scan_item_text("x.txt", body, detector)
        blobs.append(repr(item) + repr(detector.analyze_text(body)))
    assert leaks("\n".join(blobs)) == []


def test_redact_digits_masks_numbers_and_keeps_dates_and_ids() -> None:
    assert redact_digits(f"receipts/{CARDS['visa']}.txt") == "receipts/################.txt"
    assert redact_digits(f"x/{printed(CARDS['visa'])}") == "x/#### #### #### ####"
    assert redact_digits(f"ssn-{dashed(SSN_A)}.csv") == "ssn-###-##-####.csv"
    for kept in [
        "connect/i/ChatTranscripts/2026/09/28/abc_20260928T15:00_UTC.json",
        "2026/09/28/[$LATEST]0123456789abcdef",
    ]:
        assert redact_digits(kept) == kept
    assert redact_digits("ts 1727500000000123") == "ts ################"


def test_log_event_masks_and_refuses_unknown_events(capsys: pytest.CaptureFixture[str]) -> None:
    safety.log_event("source.failed", source=f"bucket/{CARDS['visa']}", error="AccessDenied")
    out = capsys.readouterr().out
    assert CARDS["visa"] not in out
    assert "################" in out
    with pytest.raises(ValueError, match="unknown log event"):
        safety.log_event("anything.goes")


# ------------------------------------------------------------ source audit


def _modules() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text())) for p in sorted(PACKAGE.rglob("*.py"))]


def test_only_safety_writes_output() -> None:
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = ast.unparse(f)
                assert name != "print", f"{path.name}: print()"
                if path.name != "safety.py":
                    assert not name.startswith(("sys.stdout", "sys.stderr")), f"{path.name}: {name}"
                    assert not re.match(
                        r"(logging|logger|log)\.(debug|info|warning|error|exception|critical|log)$",
                        name,
                    ), f"{path.name}: {name}"
                    if name.endswith((".debug", ".info", ".warning", ".exception")):
                        raise AssertionError(f"{path.name}: {name}")


def test_every_log_event_uses_a_fixed_name_and_safe_fields() -> None:
    calls = 0
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "log_event":
                calls += 1
                first = node.args[0]
                assert isinstance(first, ast.Constant), f"{path.name}: event name not literal"
                assert first.value in safety.EVENTS, f"{path.name}: {first.value!r}"
                for kw in node.keywords:
                    value = ast.unparse(kw.value)
                    assert not isinstance(kw.value, ast.JoinedStr), f"{path.name}: f-string field"
                    assert not re.search(r"\b(str|repr|format)\(|\.args\b|\.message\b", value), (
                        f"{path.name}: {value}"
                    )
                    if kw.arg == "error":
                        assert re.fullmatch(r"error_name\(\w+\)|\w+(\.\w+)*|'[A-Za-z]+'", value), (
                            f"{path.name}: error={value}"
                        )
    assert calls >= 10


def test_raised_exceptions_carry_no_message_from_below() -> None:
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                for arg in node.exc.args:
                    ok = isinstance(arg, ast.Constant) or (
                        isinstance(arg, ast.Name) and arg.id in ("name",)
                    )
                    assert ok, f"{path.name}: raise {ast.unparse(node.exc)}"
