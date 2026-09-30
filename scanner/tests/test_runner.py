"""The batch runner end to end against moto: S3 and CloudWatch Logs sources,
findings document, incremental passes, budgets, sampling, lock, events."""

from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, RESULTS, Env, config, epoch_ms
from conftest import REPO, all_conversation_vectors
from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import event_details
from sensitive_data_scanner.events import put_findings_events
from synthetic import CARDS, SSN_A, dashed, printed, spoken_groups

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
DOCS = {c["id"]: c["document"] for c in all_conversation_vectors() if c.get("document")}


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    # Every finding the runner writes says what storage encryption it sat under (1.5).
    assert all("atRestEncryption" in f for f in doc["findings"])


def by_key(doc: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for f in doc["findings"]:
        r = f["resource"]
        loc = r.get("key") or f"{r.get('logGroup')}|{r.get('logStream')}|{r.get('timestamp')}"
        out.setdefault(loc, {})[f["class"]] = f
    return out


def seed(env: Env) -> None:
    env.put(
        "connect/x/Analysis/Voice/2026/09/28/lens.json",
        DOCS["contact-lens-ssn-split-backchannel"]["content"],
    )
    env.put(
        "connect/x/ChatTranscripts/2026/09/28/chat.json",
        DOCS["connect-chat-card-ssn-dob"]["content"],
    )
    env.put("lex/PaymentBot/2026/09/28/log.jsonl", DOCS["lex-v2-card-spoken"]["content"])
    env.put("export/customers.csv", "name,card_number\n" + "\n".join(CARDS.values()))
    env.put("notes/clean.txt", "Nothing sensitive here. Order 12345 shipped.")
    env.put("recordings/call.wav", b"RIFF\x24\x00\x00\x00WAVEfmt fake-audio")


def recent(minutes: int) -> int:
    return epoch_ms(dt.datetime.now(dt.UTC) - dt.timedelta(minutes=minutes))


def test_first_run_finds_each_location_and_states_coverage(env: Env) -> None:
    seed(env)
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    found = by_key(doc)
    assert set(found["connect/x/Analysis/Voice/2026/09/28/lens.json"]) == {"us_ssn"}
    assert set(found["connect/x/ChatTranscripts/2026/09/28/chat.json"]) == {"card", "us_ssn", "dob"}
    assert found["lex/PaymentBot/2026/09/28/log.jsonl"]["card"]["via"] == ["prompt"]
    assert found["export/customers.csv"]["card"]["count"] == len(CARDS)
    assert "notes/clean.txt" not in found

    lens = found["connect/x/Analysis/Voice/2026/09/28/lens.json"]["us_ssn"]
    assert lens["format"] == "contact_lens"
    assert lens["confidence"] == "high"
    assert [o["pointer"] for o in lens["offsets"]] == [
        "/Transcript/1/Content",
        "/Transcript/3/Content",
        "/Transcript/4/Content",
    ]
    assert lens["connect"]["contactId"] == "11111111-2222-3333-4444-555555555555"
    # One object version per finding, and a deep link to it.
    version = env.clients.s3.head_object(
        Bucket=DATA, Key="connect/x/Analysis/Voice/2026/09/28/lens.json"
    )["VersionId"]
    assert lens["resource"]["versionId"] == version
    assert lens["link"].startswith("https://us-west-2.console.aws.amazon.com/s3/object/")
    assert f"versionId={version}" in lens["link"]

    cov = doc["coverage"][0]
    assert cov["kind"] == "s3"
    assert cov["scanned"] == 5
    assert cov["skipped"] == {"audio": 1}
    assert cov["passComplete"] is True
    assert cov["formats"]["contact_lens"] == 1
    assert doc["account"] == "123456789012"
    assert doc["totals"]["card"] >= len(CARDS)


def test_incremental_passes(env: Env) -> None:
    # No clock-skew allowance here, so a pass boundary is exact; a second apart,
    # because S3 LastModified has one-second resolution.
    cfg = config(s3_skew_seconds=0)
    seed(env)
    time.sleep(1.1)
    env.run(cfg)
    again = env.run(cfg)
    assert again is not None
    assert again["coverage"][0]["scanned"] == 0
    assert again["coverage"][0]["passComplete"] is True
    assert "export/customers.csv" in by_key(again)
    # A new version of an object is read again; its findings replace the old ones.
    time.sleep(1.1)
    env.put("export/customers.csv", "name,note\nnobody,nothing")
    env.put("notes/new.txt", f"SSN {dashed(SSN_A)}")
    third = env.run(cfg)
    assert third is not None
    assert third["coverage"][0]["scanned"] == 2
    found = by_key(third)
    assert "export/customers.csv" not in found
    assert set(found["notes/new.txt"]) == {"us_ssn"}
    # A deleted object drops out.
    env.clients.s3.delete_object(Bucket=DATA, Key="notes/new.txt")
    fourth = env.run(cfg)
    assert fourth is not None
    assert "notes/new.txt" not in by_key(fourth)


def test_budget_resumes_where_it_stopped_and_reads_nothing_twice(env: Env) -> None:
    for i in range(7):
        env.put(f"batch/{i:02d}.txt", f"card {printed(CARDS['visa'])} #{i}")
    first = env.run(config(max_items_per_run=3))
    assert first is not None
    assert first["coverage"][0]["scanned"] == 3
    assert first["coverage"][0]["backlog"] is True
    second = env.run(config(max_items_per_run=3))
    third = env.run(config(max_items_per_run=3))
    assert second is not None and third is not None
    assert second["coverage"][0]["scanned"] == 3
    assert third["coverage"][0]["scanned"] == 1
    assert third["coverage"][0]["passComplete"] is True
    assert len(by_key(third)) == 7


def test_sampling_is_stated(env: Env) -> None:
    for i in range(20):
        env.put(f"sample/{i:02d}.txt", f"hello {i}")  # distinct: copies would be duplicates
    doc = env.run(config(sample_percent=30))
    assert doc is not None
    cov = doc["coverage"][0]
    assert cov["samplePercent"] == 30
    assert cov["sampledOut"] > 0
    assert cov["scanned"] + cov["sampledOut"] == 20


def test_large_object_is_read_in_part(env: Env) -> None:
    env.put("big/log.txt", f"card {printed(CARDS['visa'])}\n" + "x" * 5000)
    doc = env.run(config(max_object_bytes=1024))
    assert doc is not None
    assert doc["coverage"][0]["partial"] == 1
    assert set(by_key(doc)["big/log.txt"]) == {"card"}


def test_a_source_that_cannot_be_read_is_named_and_the_others_run(env: Env) -> None:
    seed(env)
    doc = env.run(config(s3_targets=[("no-such-bucket-here", ""), (DATA, "export/")]))
    assert doc is not None
    assert doc["coverage"][0]["error"] == "NoSuchBucket"
    assert doc["coverage"][1]["scanned"] == 1


def test_cloudwatch_logs_flow_lex_and_lambda(env: Env) -> None:
    t = recent(60)
    flow = DOCS["connect-flow-log-card-dtmf"]["content"]
    env.log("/aws/connect/example", "flows", [(t, flow)])
    lex_lines = DOCS["lex-v2-card-spoken"]["content"].splitlines()
    env.log("/aws/lex/PaymentBot", "session-1", [(t + 1, lex_lines[0]), (t + 2, lex_lines[1])])
    lam = (
        "2026-09-28T15:00:07.000Z\t11111111-aaaa\tINFO\tfulfillment "
        f'{{"cardNumber":"{CARDS["visa"]}","ssn":"{dashed(SSN_A)}"}}'
    )
    env.log("/aws/lambda/fulfill", "2026/09/28/[$LATEST]abc", [(t + 3, lam), (t + 4, "START")])
    doc = env.run(
        config(
            s3_targets=[],
            log_groups=["/aws/connect/example", "/aws/lex/PaymentBot", "/aws/lambda/fulfill"],
        )
    )
    assert doc is not None
    valid(doc)
    found = by_key(doc)
    assert found[f"/aws/connect/example|flows|{t}"]["card"]["via"] == ["prompt"]
    # The prompt in the first Lex record classes the answer in the second.
    lex = found[f"/aws/lex/PaymentBot|session-1|{t + 2}"]["card"]
    assert (lex["via"], lex["confidence"]) == (["prompt"], "high")
    assert lex["offsets"][0]["pointer"] == "/inputTranscript"
    assert set(found[f"/aws/lambda/fulfill|2026/09/28/[$LATEST]abc|{t + 3}"]) == {"card", "us_ssn"}
    assert all(c["passComplete"] for c in doc["coverage"])
    # Read once: a quiet second run adds nothing.
    again = env.run(config(s3_targets=[], log_groups=["/aws/connect/example"]))
    assert again is not None
    assert again["coverage"][0]["scanned"] == 0


def test_one_run_at_a_time(env: Env) -> None:
    env.clients.s3.put_object(Bucket=RESULTS, Key="state/lock.json", Body=b"{}")
    assert env.run(config()) is None


def test_events_go_to_the_configured_bus(env: Env) -> None:
    seed(env)
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0, "Entries": [{} for _ in Entries]}

    env.clients.events = Bus()  # type: ignore[assignment]
    bus = "arn:aws:events:us-west-2:210987654321:event-bus/findings"
    doc = env.run(config(event_bus_arn=bus))
    assert doc is not None
    assert len(sent) == 1
    entry = sent[0]
    assert (entry["Source"], entry["DetailType"], entry["EventBusName"]) == (
        EVENT_SOURCE,
        EVENT_DETAIL_TYPE,
        bus,
    )
    detail = json.loads(entry["Detail"])
    valid(detail)
    assert (detail["part"], detail["parts"]) == (1, 1)
    assert detail["findings"] == doc["findings"]


def test_events_split_under_the_size_limit() -> None:
    finding = {"id": "0" * 32, "pad": "x" * 1000}
    doc = {"schema": "s", "findings": [dict(finding, id=f"{i:032d}") for i in range(500)]}
    details = event_details(doc)
    assert len(details) > 1
    assert all(len(json.dumps(d)) < 256_000 for d in details)
    assert sum(len(d["findings"]) for d in details) == 500
    assert {d["parts"] for d in details} == {len(details)}


def test_a_failing_bus_does_not_fail_the_run(capsys: pytest.CaptureFixture[str]) -> None:
    class Down:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            raise ConnectionError("down")

    sent = put_findings_events(Down(), "arn:x", {"findings": [], "schema": "s"})  # type: ignore[arg-type]
    assert sent == 0
    assert '"event":"events.failed"' in capsys.readouterr().out


def test_spoken_card_in_a_plain_transcript_file(env: Env) -> None:
    env.put("transcribe/call.txt", f"customer: my visa is {spoken_groups(CARDS['visa'])}")
    doc = env.run(config())
    assert doc is not None
    assert by_key(doc)["transcribe/call.txt"]["card"]["confidence"] == "high"


def test_a_large_store_among_many_small_ones_gets_the_budget_they_leave(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    """#94: an even share per source gave a large store a few items a run when hundreds of
    small stores were waiting. Now the small ones finish, and the large one gets the rest."""
    for i in range(800):
        env.put(f"bulk/{i:03d}.txt", f"line {i}")
    t = recent(30)
    groups = [f"/aws/lambda/fn-{i:02d}" for i in range(60)]
    for g in groups:
        env.log(g, "s", [(t, "START")])
    doc = env.run(config(s3_targets=[(DATA, "bulk/")], log_groups=groups, max_items_per_run=500))
    assert doc is not None
    valid(doc)
    by_target = {c["target"]: c for c in doc["coverage"]}
    assert all(by_target[g]["passComplete"] for g in groups)
    bulk = by_target[f"{DATA}/bulk/"]
    # One coverage for the bucket, however many rounds it was served in.
    assert [c["target"] for c in doc["coverage"]].count(f"{DATA}/bulk/") == 1
    # The even share was 500 / 61, about 8 objects; now all that the groups left.
    assert bulk["scanned"] >= 500 - len(groups) - 1
    assert bulk["backlog"] and not bulk["passComplete"]
    scheduled = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if '"run.scheduled"' in line
    ]
    assert scheduled and scheduled[0]["rounds"] >= 2
    # The next run starts with the bucket, still behind, and finishes it.
    again = env.run(config(s3_targets=[(DATA, "bulk/")], log_groups=groups, max_items_per_run=500))
    assert again is not None
    assert {c["target"]: c for c in again["coverage"]}[f"{DATA}/bulk/"]["passComplete"]
