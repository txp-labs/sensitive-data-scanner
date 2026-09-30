"""The SaaS scanner with Slack: channels, threads, files, Discovery, and Slack's errors.

Every Slack call goes to a stubbed session (slack_fakes.py); every value is made up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from office_fixtures import xlsx
from sensitive_data_core.findings import key_hash
from sensitive_data_core.state import FileState
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.resources import tenant_hash
from sensitive_data_saas.runner import run_scan
from slack_fakes import NOW, ORG, Chan, SlackOrg, settings, ts
from synthetic import CARDS, SSN_A, dashed, printed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
DETECTOR = shared_detector()


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def scan(o: SlackOrg, s: Any, **kw: Any) -> dict[str, Any]:
    doc, failed = run_scan(s, o.clients(s), detector=DETECTOR, now=lambda: NOW, **kw)
    assert failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(x["kind"], x["name"]): x for x in doc["discovery"]["stores"]}


def org() -> SlackOrg:
    o = SlackOrg()
    support = Chan("C0SUPPORT1", "support")
    support.messages = [
        {
            "ts": ts(5),
            "text": f"my card is {printed(CARDS['visa'])}",
            "reply_count": 1,
            "thread_ts": ts(5),
        },
        {"ts": ts(4), "text": "nothing here"},
        {
            "ts": ts(3),
            "text": "roster attached",
            "files": [
                {
                    "id": "F0ROSTER1",
                    "name": "roster.xlsx",
                    "size": 2000,
                    "url_private_download": "https://files.slack.com/files-pri/T0-F0ROSTER1/roster.xlsx",
                },
                {
                    "id": "F0GDOC",
                    "name": "doc",
                    "is_external": True,
                    "url_private": "https://docs.example/x",
                },
            ],
        },
        {
            "ts": ts(2),
            "text": "",
            "attachments": [{"fallback": f"ssn {dashed(SSN_A)}", "text": "unfurled"}],
        },
        {"ts": ts(24 * 400), "text": f"{CARDS['jcb']}"},
    ]
    support.replies[ts(5)] = [{"ts": ts(4.5), "text": f"and my ssn is {dashed(SSN_A)}"}]
    o.files["/files-pri/T0-F0ROSTER1/roster.xlsx"] = xlsx([["name", "card"], ["A", CARDS["amex"]]])
    o.channels[support.id] = support
    o.channels["G0SECRET1"] = Chan("G0SECRET1", "hr-private", private=True, member=False)
    o.dms["D0DM00001"] = [{"ts": ts(1), "text": f"my card is {printed(CARDS['mastercard'])}"}]
    o.dms["G0MPIM001"] = [{"ts": ts(1), "text": "lunch?"}]
    return o


def test_settings_take_the_token_from_a_file(tmp_path: Path) -> None:
    s = settings(tmp_path)
    assert s.slack is not None and "xoxb" not in repr(s) and "xoxb" not in repr(s.slack)
    assert s.discover == ("slack_channel",)
    for bad, code in (
        ({"SLACK_TOKEN": "xoxb-made-up"}, "slack_token_in_env"),
        ({"SLACK_TOKEN_FILE": "relative"}, "slack_token_file"),
    ):
        with pytest.raises(ConfigError) as err:
            read_settings({"SCANNER_SITE": "x", "FINDINGS_FILE": "/tmp/x", **bad})  # noqa: S108
        assert err.value.code == code
    bad_token = tmp_path / "t"
    bad_token.write_text("not-a-slack-token")
    with pytest.raises(ConfigError) as err:
        read_settings(
            {"SCANNER_SITE": "x", "FINDINGS_FILE": "/tmp/x", "SLACK_TOKEN_FILE": str(bad_token)}  # noqa: S108
        )
    assert err.value.code == "slack_token"
    with pytest.raises(ConfigError):
        settings(tmp_path, SLACK_CHANNELS="general")


def test_channels_threads_files_and_gaps(tmp_path: Path) -> None:
    o = org()
    doc = scan(o, settings(tmp_path))
    by = stores(doc)
    support = by[("slack_channel", "#support")]
    assert support["status"] == "scanned" and support["vendor"] == "slack"
    assert support["tenantHash"] == tenant_hash(ORG)
    assert by[("slack_channel", "#hr-private")]["reason"] == "not_a_member"
    assert by[("slack_dm", "*")]["reason"] == "read_not_configured"
    found = {
        (f["resource"]["part"], f["class"], f["resource"].get("name")) for f in doc["findings"]
    }
    assert ("message", "card", None) in found
    assert ("reply", "us_ssn", None) in found
    assert ("message", "us_ssn", None) in found  # a legacy attachment's text
    assert ("attachment", "card", "roster.xlsx") in found
    cov = next(c for c in doc["coverage"] if c["kind"] == "slack_channel")
    assert cov["skipped"] == {"linked_item": 1}
    assert all(not f["resource"]["itemId"].endswith(ts(24 * 400)) for f in doc["findings"])
    f = next(f for f in doc["findings"] if f["resource"]["part"] == "message")
    assert f["link"] == "https://app.slack.com/client/T0ACMEHQ1/C0SUPPORT1"
    assert f["resource"]["channel"] == "C0SUPPORT1" and f["resource"]["container"] == "#support"
    assert f["atRestEncryption"] == "service_managed"
    # No write method, and the private channel was never asked for its history.
    assert not any("G0SECRET1" in str(c[2]) for c in o.calls if c[1].endswith("history"))


def test_a_capped_channel_goes_on_below_where_it_stopped(tmp_path: Path) -> None:
    o = org()
    state = FileState(str(tmp_path / "state.json"))
    s = settings(tmp_path, MESSAGES_MAX_PER_CHANNEL="2")
    runs = [scan(o, s, state=state) for _ in range(4)]
    assert runs[0]["coverage"][0]["backlog"]
    assert runs[-1]["coverage"][0]["passComplete"]
    classes = {(f["resource"]["part"], f["class"]) for f in runs[-1]["findings"]}
    assert {("message", "card"), ("reply", "us_ssn"), ("attachment", "card")} <= classes
    # Then only what is new.
    o.channels["C0SUPPORT1"].messages.append({"ts": ts(0.5), "text": f"card {CARDS['discover']}"})
    after = scan(o, s, state=state)
    assert after["coverage"][0]["scanned"] == 1


def test_direct_messages_through_discovery_and_ekm(tmp_path: Path) -> None:
    o = org()
    s = settings(tmp_path, DISCOVER="slack_channel,slack_dm", SLACK_EKM_KEY_ID="ekm-key-1")
    doc = scan(o, s)
    dm = [f for f in doc["findings"] if f["resource"]["service"] == "dm"]
    assert [x["class"] for x in dm] == ["card"]
    assert dm[0]["link"] is None and dm[0]["resource"]["channel"] == "D0DM00001"
    assert dm[0]["atRestEncryption"] == "customer_managed_key"
    assert dm[0]["atRestKeyHash"] == key_hash("ekm-key-1")
    o2 = org()
    o2.grid = False
    doc2 = scan(o2, s)
    store = stores(doc2)[("slack_dm", "direct-messages")]
    assert (store["status"], store["reason"], store["error"]) == (
        "error",
        "access_denied",
        "not_allowed_token_type",
    )


def test_slack_errors_by_code_and_rate_limits(tmp_path: Path) -> None:
    o = org()
    o.throttle["conversations.history"] = 2
    doc = scan(o, settings(tmp_path))
    assert stores(doc)[("slack_channel", "#support")]["status"] == "scanned"
    o.fail["conversations.list"] = "missing_scope"
    bad = scan(o, settings(tmp_path))
    assert bad["discovery"]["listErrors"] == {"slack_channel": "missing_scope"}
