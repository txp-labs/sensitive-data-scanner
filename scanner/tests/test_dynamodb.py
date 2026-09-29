"""The DynamoDB source against a stubbed client (botocore Stubber): Query and Scan,
projection, attribute paths, keypad entries after prompts, planted paths, key
hashing and masking, backoff, page cap, budget, and the proof pair (the positive
control has findings, the negative control has none)."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from botocore.stub import ANY
from jsonschema import Draft202012Validator

from aws_fixtures import NOW, Env, config, shared_detector
from conftest import REPO
from ddb_fixtures import KEYPAD, PARTITION, PROMPT, TABLE, Ddb, key_of, load_item, page, target
from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.findings import findings_document
from sensitive_data_core.scan.attributes import AttributeRules, iter_leaves, scan_attributes
from sensitive_data_core.scan.paths import EVERY, Elements, parse_path, render_path
from sensitive_data_scanner.config import DynamoTarget, dynamodb_targets, read_config
from sensitive_data_scanner.sources.dynamodb import DynamoDBSource
from synthetic import CARDS, SSN_A

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def budget(items: int = 1000, nbytes: int = 10**9) -> Budget:
    return Budget(items, nbytes, time.monotonic() + 600)


def source(ddb: Ddb, t: DynamoTarget | None = None, **kw: Any) -> DynamoDBSource:
    kw.setdefault("sleep", lambda s: None)
    return DynamoDBSource(ddb.client, target=t or target(), region="us-west-2", **kw)


def run(
    src: DynamoDBSource,
    store: FindingStore | None = None,
    cursor: dict[str, Any] | None = None,
    b: Budget | None = None,
) -> tuple[SourceRun, FindingStore]:
    store = store or FindingStore(NOW.isoformat())
    result = src.run(cursor or {}, b or budget(), shared_detector(), store, NOW)
    return result, store


def document(store: FindingStore, result: SourceRun) -> dict[str, Any]:
    doc = findings_document(
        run_id="20260929T120000Z-0a1b2c3d",
        account="123456789012",
        region="us-west-2",
        started_at=NOW.isoformat(),
        finished_at=NOW.isoformat(),
        classes=["us_ssn", "card", "dob"],
        coverage=[result.coverage],
        findings=store.public(),
    )
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    return doc


def by_path(doc: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for f in doc["findings"]:
        out.setdefault(f["resource"]["attributePath"], {})[f["class"]] = f
    return out


# ------------------------------------------------------------------ the proof pair


def test_positive_control_has_findings_on_each_keypad_entry() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(
        page([load_item("stugum-positive")]),
        {
            "TableName": TABLE,
            "Limit": 100,
            "KeyConditionExpression": "#pk = :pk AND begins_with(#sk, :sk)",
            "ExpressionAttributeNames": {
                "#p0": "pk",
                "#p1": "sk",
                "#p2": "stepResults",
                "#p3": "steps",
                "#p4": "lastHeardText",
                "#p5": "errorMessage",
                "#pk": "pk",
                "#sk": "sk",
            },
            "ExpressionAttributeValues": {":pk": {"S": PARTITION}, ":sk": {"S": "RUN#"}},
            "ProjectionExpression": "#p0, #p1, #p2, #p3, #p4, #p5",
        },
    )
    result, store = run(source(ddb))
    ddb.stub.assert_no_pending_responses()
    doc = document(store, result)
    found = by_path(doc)

    leak = found["stepResults[].observedDtmf"]
    assert set(leak) == {"dob", "us_ssn", "card"}
    assert (leak["dob"]["confidence"], leak["dob"]["via"]) == ("high", ["prompt"])
    assert (leak["us_ssn"]["confidence"], leak["us_ssn"]["via"]) == ("high", ["prompt"])
    assert (leak["card"]["confidence"], leak["card"]["via"]) == ("low", ["prompt"])
    # The terminator is not part of the value: offsets end before "#".
    assert leak["us_ssn"]["offsets"] == [
        {"pointer": "/stepResults/5/observedDtmf", "start": 0, "end": 9}
    ]
    assert leak["dob"]["offsets"][0]["pointer"] == "/stepResults/2/observedDtmf"
    assert leak["card"]["offsets"][0]["pointer"] == "/stepResults/8/observedDtmf"
    assert "planted" not in leak["dob"]["resource"]
    # The planted digits in `steps` have no prompt paired with them (the test script's
    # expected-prompt regexes are not prompts), and none of them has a card's or an
    # SSN's standalone shape: nothing is reported there.
    assert set(found) == {"stepResults[].observedDtmf"}

    f = leak["dob"]
    assert f["format"] == "dynamodb_item"
    assert f["resource"]["type"] == "dynamodb_item"
    assert f["resource"]["table"] == TABLE
    assert f["resource"]["key"] == {
        "pk": PARTITION,
        "sk": "RUN#2026-09-29T15:00:00Z#r_0000positive",
    }
    assert len(f["resource"]["keyHash"]) == 64
    assert f["link"].startswith("https://us-west-2.console.aws.amazon.com/dynamodbv2/")
    cov = doc["coverage"][0]
    assert (cov["kind"], cov["scanned"], cov["passComplete"]) == ("dynamodb", 1, True)
    assert cov["formats"] == {"dynamodb_item": 1}


def test_negative_control_has_no_findings() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-negative")]))
    result, store = run(source(ddb))
    doc = document(store, result)
    assert doc["findings"] == []
    assert doc["findingsTotal"] == 0
    cov = doc["coverage"][0]
    assert cov["scanned"] == 1
    # "[REDACTED:ssn · asked for SSN]" and the others: markers, not findings.
    assert cov["redactionMarkers"] == 3
    assert cov["passComplete"] is True


def test_the_same_item_redacted_on_a_later_pass_drops_its_findings() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    first, store = run(source(ddb))
    assert store.public()
    redacted = load_item("stugum-negative")
    redacted["sk"] = load_item("stugum-positive")["sk"]
    ddb.describe()
    ddb.query(page([redacted]))
    run(source(ddb), store, first.cursor)
    assert store.public() == []


def test_a_deleted_item_drops_out_when_the_pass_completes() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    first, store = run(source(ddb))
    assert store.public()
    ddb.describe()
    ddb.query(page([]))
    second, _ = run(source(ddb), store, first.cursor)
    assert second.coverage.pass_complete
    assert store.public() == []


# ------------------------------------------------------------------ reading


def test_scan_without_a_partition_and_without_a_projection() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.scan(page([load_item("stugum-positive")]), {"TableName": TABLE, "Limit": 100})
    t = DynamoTarget(
        table=TABLE, keypad=("stepResults[].observedDtmf",), prompts=("stepResults[].observedText",)
    )
    result, store = run(source(ddb, t))
    ddb.stub.assert_no_pending_responses()
    found = by_path(document(store, result))
    assert set(found) == {"stepResults[].observedDtmf"}


def test_exclude_drops_a_path() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    result, store = run(source(ddb, target(exclude=("steps",))))
    assert set(by_path(document(store, result))) == {"stepResults[].observedDtmf"}


def test_pages_follow_last_evaluated_key() -> None:
    a = load_item("stugum-positive")
    b = load_item("stugum-negative")
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([a], last=key_of(a)))
    ddb.query(
        page([b]),
        {
            "TableName": ANY,
            "Limit": ANY,
            "KeyConditionExpression": ANY,
            "ExpressionAttributeNames": ANY,
            "ExpressionAttributeValues": ANY,
            "ProjectionExpression": ANY,
            "ExclusiveStartKey": key_of(a),
        },
    )
    result, _ = run(source(ddb))
    ddb.stub.assert_no_pending_responses()
    assert result.coverage.scanned == 2
    assert result.coverage.pass_complete
    assert result.cursor["startKey"] is None


def test_page_cap_stops_and_the_next_run_resumes() -> None:
    a = load_item("stugum-positive")
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([a], last=key_of(a)))
    first, store = run(source(ddb, max_pages=1))
    ddb.stub.assert_no_pending_responses()
    assert first.coverage.backlog and not first.coverage.pass_complete
    assert first.cursor["startKey"] == key_of(a)

    b = load_item("stugum-negative")
    ddb.describe()
    ddb.query(page([b]))
    second, store = run(source(ddb, max_pages=1), store, first.cursor)
    assert second.coverage.pass_complete
    # The first run's findings belong to the same pass, so they stay.
    assert store.public()


def test_budget_cut_resumes_after_the_last_item_read() -> None:
    a = load_item("stugum-positive")
    b = load_item("stugum-negative")
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([a, b]))
    result, _ = run(source(ddb), b=budget(items=1))
    assert result.coverage.scanned == 1
    assert result.coverage.backlog
    assert result.cursor["startKey"] == key_of(a)


def test_throttling_backs_off_and_retries() -> None:
    ddb = Ddb()
    slept: list[float] = []
    ddb.describe()
    ddb.error("query", "ProvisionedThroughputExceededException")
    ddb.error("query", "ThrottlingException")
    ddb.query(page([load_item("stugum-positive")]))
    result, _ = run(source(ddb, sleep=slept.append))
    ddb.stub.assert_no_pending_responses()
    assert result.coverage.error is None
    assert result.coverage.scanned == 1
    assert len(slept) == 2
    assert 0.125 <= slept[0] <= 0.25 and 0.25 <= slept[1] <= 0.5


def test_throttling_past_the_retries_names_the_error_and_keeps_the_cursor() -> None:
    a = load_item("stugum-positive")
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([a], last=key_of(a)))
    for _ in range(6):
        ddb.error("query", "ProvisionedThroughputExceededException")
    result, _ = run(source(ddb))
    assert result.coverage.error == "ProvisionedThroughputExceededException"
    assert result.cursor["startKey"] == key_of(a)
    assert not result.coverage.pass_complete


def test_access_denied_is_named_and_not_retried() -> None:
    ddb = Ddb()
    ddb.error("describe_table", "AccessDeniedException")
    result, _ = run(source(ddb))
    ddb.stub.assert_no_pending_responses()
    assert result.coverage.error == "AccessDeniedException"


def test_a_sort_prefix_on_a_table_without_a_sort_key_is_an_error() -> None:
    ddb = Ddb()
    ddb.describe(sort_key=False)
    result, _ = run(source(ddb))
    assert result.coverage.error == "ValueError"


# ------------------------------------------------------------------ keys


def test_a_key_that_could_be_sensitive_is_masked_and_hashed() -> None:
    item = load_item("stugum-positive")
    item["pk"] = {"S": f"CUST#{SSN_A}"}
    item["sk"] = {"S": f"CARD#{CARDS['visa']}"}
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([item]))
    result, store = run(source(ddb))
    doc = document(store, result)
    f = doc["findings"][0]
    assert f["resource"]["key"] == {"pk": "CUST##########", "sk": "CARD#################"}
    assert f["resource"]["keyMasked"] is True
    # The link names the table only, so a masked key keeps it (#24).
    assert f["link"] == (
        "https://us-west-2.console.aws.amazon.com/dynamodbv2/home?region=us-west-2"
        "#item-explorer?table=example-call-tests"
    )
    blob = json.dumps(doc)
    assert SSN_A not in blob and CARDS["visa"] not in blob


def test_key_hash_is_salted_and_stable_across_runs() -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    first, store = run(source(ddb))
    h1 = store.public()[0]["resource"]["keyHash"]
    ids1 = {f["id"] for f in store.public()}
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    run(source(ddb), store, first.cursor)
    assert store.public()[0]["resource"]["keyHash"] == h1
    assert {f["id"] for f in store.public()} == ids1
    # Another salt, another hash: the hash cannot be recomputed from a guessed key.
    ddb.describe()
    ddb.query(page([load_item("stugum-positive")]))
    _, other = run(source(ddb))
    assert other.public()[0]["resource"]["keyHash"] != h1


# ------------------------------------------------------------------ attributes


def test_paths_parse_and_render() -> None:
    assert parse_path("stepResults[].observedDtmf") == ("stepResults", EVERY, "observedDtmf")
    assert parse_path("a[][].b.c") == ("a", EVERY, EVERY, "b", "c")
    assert render_path(("a", EVERY, EVERY, "b", "c")) == "a[][].b.c"
    where = parse_path("stepResults[kind=sendDtmf, status=passed].observedDtmf")
    assert where == (
        "stepResults",
        Elements((("kind", "sendDtmf"), ("status", "passed"))),
        "observedDtmf",
    )
    assert render_path(where) == "stepResults[kind=sendDtmf,status=passed].observedDtmf"
    for bad in ["", "[]a", "a..b", "a[1]", ".a", "a.", "a[]b", "a[kind]", "a[=x]", "a[k=v"]:
        with pytest.raises(ValueError, match="attribute path"):
            parse_path(bad)


def test_every_leaf_kind_is_read_or_skipped() -> None:
    item = {
        "s": {"S": "x"},
        "n": {"N": "12"},
        "b": {"B": b"\x00"},
        "ok": {"BOOL": True},
        "nothing": {"NULL": True},
        "tags": {"SS": ["a", "b"]},
        "m": {"M": {"l": {"L": [{"M": {"v": {"S": "y"}}}]}}},
    }
    got = {leaf.pointer: leaf.text for leaf in iter_leaves(item, AttributeRules())}
    assert got == {"/s": "x", "/n": "12", "/tags/0": "a", "/tags/1": "b", "/m/l/0/v": "y"}


def test_a_keypad_entry_without_prompt_paths_takes_its_step_label_as_the_prompt() -> None:
    item = {
        "pk": {"S": "T#1"},
        "results": {
            "L": [
                {"M": {"label": {"S": "Enter SSN"}, "dtmf": {"S": "512437788#"}}},
                {"M": {"label": {"S": "Enter card number"}, "dtmf": {"S": "5555666677778888#"}}},
                {"M": {"label": {"S": "Choose a menu option"}, "dtmf": {"S": "2#"}}},
            ]
        },
    }
    rules = AttributeRules(keypad=(parse_path("results[].dtmf"),))
    result = scan_attributes(item, shared_detector(), rules)
    found = result.by_path["results[].dtmf"].findings
    assert set(found) == {"us_ssn", "card"}
    assert found["us_ssn"].offsets[0].pointer == "/results/0/dtmf"
    assert found["card"].offsets[0].pointer == "/results/1/dtmf"


def test_a_plain_attribute_is_read_as_text_with_its_path_as_context() -> None:
    item = {
        "pk": {"S": "T#1"},
        "notes": {"M": {"ssn": {"S": "512-43-7788"}, "cardNumber": {"S": CARDS["visa"]}}},
    }
    result = scan_attributes(item, shared_detector(), AttributeRules())
    assert set(result.by_path) == {"notes.ssn", "notes.cardNumber"}
    assert set(result.by_path["notes.cardNumber"].findings) == {"card"}


# ------------------------------------------------------------------ config and runner


def test_config_reads_scan_dynamodb() -> None:
    raw = json.dumps(
        [
            {
                "table": "stugum",
                "partition": "T#t_0000example",
                "sortPrefix": "RUN#",
                "include": [KEYPAD, PROMPT, "steps", "lastHeardText", "errorMessage"],
                "keypad": [KEYPAD, "steps[kind=sendDtmf].digits"],
                "prompts": [PROMPT],
                "planted": ["steps"],
                "orderBy": "stepIndex",
            },
            {"table": "other_table"},
        ]
    )
    c = read_config({"RESULTS_BUCKET": "r", "SCAN_DYNAMODB": raw, "DYNAMODB_MAX_PAGES": "5"})
    assert c.dynamodb_max_pages == 5
    assert c.dynamodb_page_size == 100
    first, second = c.dynamodb_targets
    assert (first.table, first.partition) == ("stugum", "T#t_0000example")
    assert first.sort_prefix == "RUN#"
    assert (first.planted, first.order_by) == (("steps",), "stepIndex")
    assert (second.table, second.partition, second.include) == ("other_table", None, ())


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        '[{"table": "x"}]',
        '[{"table": "ok_table", "surprise": 1}]',
        '[{"table": "ok_table", "sortPrefix": "R#"}]',
        '[{"table": "ok_table", "include": ["a[1]"]}]',
        '[{"table": "ok_table", "include": "steps"}]',
        '[{"table": "ok_table", "include": ["steps[kind]"]}]',
        '[{"table": "ok_table", "orderBy": 3}]',
    ],
)
def test_config_refuses_a_bad_scan_dynamodb(raw: str) -> None:
    with pytest.raises(ValueError, match=r"SCAN_DYNAMODB|attribute path"):
        dynamodb_targets(raw)


def test_runner_writes_dynamodb_findings(env: Env) -> None:
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([load_item("stugum-positive"), load_item("stugum-negative")]))
    env.clients.dynamodb = ddb.client
    doc = env.run(config(s3_targets=[], dynamodb_targets=[target()]))
    assert doc is not None
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    assert [c["kind"] for c in doc["coverage"]] == ["dynamodb"]
    assert doc["totals"] == {"card": 1, "dob": 1, "us_ssn": 1}
    runs = {f["resource"]["key"]["sk"].rsplit("#", 1)[1] for f in doc["findings"]}
    assert runs == {"r_0000positive"}
    state = env.state()
    (cursor,) = [v for k, v in state["cursors"].items() if k.startswith("dynamodb:")]
    assert cursor["startKey"] is None and len(cursor["keySalt"]) == 32


def test_runner_refuses_dynamodb_targets_without_a_client(env: Env) -> None:
    from sensitive_data_core.safety import ScanError

    with pytest.raises(ScanError):
        env.run(config(s3_targets=[], dynamodb_targets=[target()]))


# ------------------------------------------------------------------ Stugum's shape


def rules_of(t: DynamoTarget) -> AttributeRules:
    return DynamoDBSource(Ddb().client, target=t, region="us-west-2").rules


def test_an_expected_prompt_regex_is_never_a_prompt() -> None:
    """The test script's assertPromptContains regex names the SSN; the IVR asked for a menu
    choice. The nine digits are not classed as an SSN."""
    item = load_item("stugum-regex-not-prompt")
    result = scan_attributes(item, shared_detector(), rules_of(target()))
    assert result.by_path == {}
    # The same regex, wrongly configured as a prompt, would class the planted entry:
    # the fixture really does hold what the rule keeps out.
    wrong = rules_of(target(prompts=(PROMPT, "steps[kind=assertPromptContains].text")))
    found = scan_attributes(item, shared_detector(), wrong).by_path
    assert set(found["steps[].digits"].findings) == {"us_ssn"}


def test_a_redacted_label_that_names_the_class_gives_no_finding() -> None:
    item = load_item("stugum-negative")
    result = scan_attributes(item, shared_detector(), rules_of(target()))
    assert result.by_path == {}
    assert result.redaction_markers == 3


def test_each_entry_pairs_with_the_nearest_preceding_prompt_by_order_by() -> None:
    def entry(kind: str, index: int, **attrs: str) -> dict[str, Any]:
        m: dict[str, Any] = {"kind": {"S": kind}, "stepIndex": {"N": str(index)}}
        m.update({k: {"S": v} for k, v in attrs.items()})
        return {"M": m}

    dob = "Please enter your date of birth as m m d d y y, then press pound."
    ssn = "Please enter or say your nine digit Social Security number."
    # Stored out of order: stepIndex, not the array, is the order of the call.
    item = {
        "pk": {"S": "T#t_1"},
        "stepResults": {
            "L": [
                entry("waitForPrompt", 3, observedText=ssn),
                entry("sendDtmf", 2, observedDtmf="010180#"),
                entry("waitForPrompt", 0, observedText=dob),
                entry("assertPromptContains", 1, observedText=dob),
                entry("sendDtmf", 5, observedDtmf=f"{SSN_A}#"),
                entry("assertPromptContains", 4, observedText=ssn),
            ]
        },
    }
    by_index = scan_attributes(item, shared_detector(), rules_of(target()))
    found = by_index.by_path["stepResults[].observedDtmf"].findings
    assert {c: (f.confidence, [o.pointer for o in f.offsets]) for c, f in found.items()} == {
        "dob": ("high", ["/stepResults/1/observedDtmf"]),
        "us_ssn": ("high", ["/stepResults/4/observedDtmf"]),
    }
    # By array order instead, each entry would take the other prompt.
    by_array = scan_attributes(item, shared_detector(), rules_of(target(order_by=None)))
    found = by_array.by_path["stepResults[].observedDtmf"].findings
    assert found["us_ssn"].offsets[0].pointer == "/stepResults/1/observedDtmf"


def test_a_failed_run_has_its_free_text_read() -> None:
    item = load_item("stugum-failed")
    result = scan_attributes(item, shared_detector(), rules_of(target()))
    assert set(result.by_path) == {"lastHeardText", "stepResults[].observedDtmf"}
    assert set(result.by_path["lastHeardText"].findings) == {"card"}


def test_planted_steps_are_marked() -> None:
    item = load_item("stugum-positive")
    item["steps"]["L"][8]["M"]["digits"] = {"S": f"{CARDS['visa']}#"}
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([item]))
    result, store = run(source(ddb))
    found = by_path(document(store, result))
    planted = found["steps[].digits"]["card"]
    assert planted["resource"]["planted"] is True
    assert planted["offsets"][0]["pointer"] == "/steps/8/digits"
    assert "planted" not in found["stepResults[].observedDtmf"]["card"]["resource"]
