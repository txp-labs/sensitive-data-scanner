"""The SaaS scanner with Slack: channels, threads, files, Discovery, and Slack's errors.

Every Slack call goes to a stubbed session (slack_fakes.py); every value is made up.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from office_fixtures import xlsx
from sensitive_data_core.findings import key_hash
from sensitive_data_core.report import report_html
from sensitive_data_core.state import FileState
from sensitive_data_saas.clients import Clients
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.resources import tenant_hash
from sensitive_data_saas.runner import run_scan
from sensitive_data_saas.sources.slack import message_link, shared_link
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
                    "permalink": "https://acme.slack.com/files/U0ALICE01/F0ROSTER1/roster.xlsx",
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
    f = next(
        f for f in doc["findings"] if f["resource"]["part"] == "message" and f["class"] == "card"
    )
    # The exact message: its thread pane, by its own ts, with the dot.
    assert f["link"] == (
        f"https://app.slack.com/client/T0ACMEHQ1/C0SUPPORT1/thread/C0SUPPORT1-{ts(5)}"
    )
    reply = next(f for f in doc["findings"] if f["resource"]["part"] == "reply")
    assert reply["link"] == (
        f"https://app.slack.com/client/T0ACMEHQ1/C0SUPPORT1/thread/C0SUPPORT1-{ts(5)}"
    )
    unfurl = next(
        f for f in doc["findings"] if f["resource"]["part"] == "message" and f["class"] == "us_ssn"
    )
    assert unfurl["link"].endswith(f"/thread/C0SUPPORT1-{ts(2)}")
    roster = next(f for f in doc["findings"] if f["resource"]["part"] == "attachment")
    # A file takes the message that shared it.
    assert roster["link"] == (
        f"https://app.slack.com/client/T0ACMEHQ1/C0SUPPORT1/thread/C0SUPPORT1-{ts(3)}"
    )
    # No link carries a run of 13 digits or more (the documented p<ts> permalink would).
    assert not any(re.search(r"[0-9]{13,}", f["link"] or "") for f in doc["findings"])
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


def test_message_and_file_links() -> None:
    team, chan = "T0ACMEHQ1", "C0SUPPORT1"
    base = f"https://app.slack.com/client/{team}/{chan}"
    one = "1759147200.000100"
    assert message_link(team, chan, {"ts": one}) == f"{base}/thread/{chan}-{one}"
    # A reply opens its thread, by the first message's ts.
    reply = {"ts": "1759147300.000200", "thread_ts": one}
    assert message_link(team, chan, reply) == f"{base}/thread/{chan}-{one}"
    # No ts: the channel.
    assert message_link(team, chan, {}) == base
    # A listed file: the message that shared it in this channel, from its shares.
    shared = {"shares": {"private": {chan: [{"ts": "1759147300.000200", "thread_ts": one}]}}}
    assert shared_link(team, chan, shared) == f"{base}/thread/{chan}-{one}"
    elsewhere = {"shares": {"public": {"C0OTHER001": [{"ts": one}]}}}
    unlinked: list[dict[str, Any]] = [
        {},
        {"shares": None},
        elsewhere,
        {"shares": {"public": {chan: [{}]}}},
    ]
    for f in unlinked:
        assert shared_link(team, chan, f) == base
    # Its permalink is never the link: another host, and it names the file and a person.
    permalink = {"permalink": "https://acme.slack.com/files/U0ALICE01/F0X/a.pdf"}
    assert shared_link(team, chan, permalink) == base


# ------------------------------------------------------------------ the opt-in join (#139)


def joining_org() -> SlackOrg:
    """The org, plus a public channel of each kind the bot is not in."""
    o = org()
    lobby = Chan("C0LOBBY01", "lobby", member=False)
    lobby.messages = [{"ts": ts(2), "text": f"my card is {printed(CARDS['visa'])}"}]
    o.channels[lobby.id] = lobby
    o.channels["C0OLDNEWS"] = Chan("C0OLDNEWS", "old-news", member=False, archived=True)
    o.channels["C0PARTNER"] = Chan("C0PARTNER", "partner-acme", member=False, ext_shared=True)
    o.channels["C0PENDING"] = Chan(
        "C0PENDING", "pending-share", member=False, pending_ext_shared=True
    )
    o.channels["C0FINANCE"] = Chan("C0FINANCE", "finance", member=False)
    return o


def joins_posted(o: SlackOrg) -> list[Any]:
    return [c for c in o.calls if c[0] != "GET" or c[1].endswith("conversations.join")]


@pytest.mark.parametrize("value", [None, "off", ""])
def test_join_off_never_calls_join(tmp_path: Path, value: str | None) -> None:
    """Off (the default): the scanner never calls conversations.join, and every public
    channel the bot is not in is `not_a_member`, exactly as before #139."""
    o = joining_org()
    o.scopes = "channels:read,groups:read,channels:history,groups:history,files:read,channels:join"
    extra = {} if value is None else {"SLACK_JOIN_PUBLIC_CHANNELS": value}
    s = settings(tmp_path, **extra)
    assert s.slack is not None and s.slack.join_public is False
    doc = scan(o, s)
    assert joins_posted(o) == [] and o.joins == []
    by = stores(doc)
    for name in ("#lobby", "#old-news", "#partner-acme", "#pending-share", "#finance"):
        store = by[("slack_channel", name)]
        assert store == {k: v for k, v in store.items() if k != "toggle"}, name
        assert (store["status"], store["reason"]) == ("skipped", "not_a_member"), name
        assert "error" not in store and "joinedByScanner" not in store, name
    assert "What the scanner changed" not in report_html(doc)


def test_join_off_reports_exactly_what_unset_reports(tmp_path: Path) -> None:
    a, b = joining_org(), joining_org()
    unset = scan(a, settings(tmp_path))
    off = scan(b, settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="off"))
    for doc in (unset, off):
        doc.pop("runId"), doc.pop("startedAt"), doc.pop("finishedAt")
    assert json.dumps(unset, sort_keys=True) == json.dumps(off, sort_keys=True)
    assert a.calls == b.calls


def test_join_on_joins_public_channels_only_and_records_each(tmp_path: Path) -> None:
    o = joining_org()
    o.scopes = "channels:read,groups:read,channels:history,groups:history,files:read,channels:join"
    s = settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="on", DISCOVER_DENY="slack_channel:#finance")
    doc = scan(o, s)
    # Only the public, live, unshared channel the rules allow; never private, archived,
    # Slack Connect (shared or pending), or denied.
    assert o.joins == ["C0LOBBY01"]
    (post,) = joins_posted(o)
    assert post[0] == "POST"
    by = stores(doc)
    lobby = by[("slack_channel", "#lobby")]
    assert lobby["status"] == "scanned"
    assert lobby["joinedByScanner"] == {
        "action": "joined_by_scanner",
        "channelId": "C0LOBBY01",
        "joinedAt": "2026-09-21T14:13:20Z",  # the fake clients' wall clock, 1_790_000_000
    }
    # Read this run.
    assert any(
        f["resource"]["channel"] == "C0LOBBY01" and f["class"] == "card" for f in doc["findings"]
    )
    for name in ("#hr-private", "#old-news", "#partner-acme", "#pending-share"):
        store = by[("slack_channel", name)]
        assert (store["status"], store["reason"]) == ("skipped", "not_a_member"), name
        assert "joinedByScanner" not in store, name
    assert by[("slack_channel", "#finance")]["reason"] == "denied"
    assert "joinedByScanner" not in by[("slack_channel", "#support")]  # already a member
    # The next run reads it as a member, and records no new join.
    again = scan(o, s)
    assert o.joins == ["C0LOBBY01"]
    assert "joinedByScanner" not in stores(again)[("slack_channel", "#lobby")]


def test_join_honors_slack_channels(tmp_path: Path) -> None:
    o = joining_org()
    s = settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="on", SLACK_CHANNELS="C0SUPPORT1")
    scan(o, s)
    assert o.joins == []


def test_join_without_the_scope_named_by_slack_falls_back_to_invite_only(tmp_path: Path) -> None:
    """Slack names the token's scopes and channels:join is not one: nothing is tried."""
    o = joining_org()
    o.scopes = "channels:read,groups:read,channels:history,groups:history,files:read"
    o.can_join = False
    doc = scan(o, settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="on"))
    assert joins_posted(o) == []
    lobby = stores(doc)[("slack_channel", "#lobby")]
    assert (lobby["status"], lobby["reason"], lobby["error"], lobby["toggle"]) == (
        "skipped",
        "not_a_member",
        "missing_scope:channels:join",
        "SLACK_JOIN_PUBLIC_CHANNELS",
    )
    assert stores(doc)[("slack_channel", "#support")]["status"] == "scanned"


def test_join_without_the_scope_unnamed_stops_at_the_first_refusal(tmp_path: Path) -> None:
    """No `x-oauth-scopes` header: the first join's missing_scope stops every other try."""
    o = joining_org()
    o.channels["C0SECOND1"] = Chan("C0SECOND1", "second", member=False)
    o.can_join = False
    doc = scan(o, settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="on"))
    assert len(joins_posted(o)) == 1
    by = stores(doc)
    for name in ("#lobby", "#second"):
        assert by[("slack_channel", name)]["error"] == "missing_scope:channels:join", name
    assert by[("slack_channel", "#support")]["status"] == "scanned"


def test_join_is_paced_to_slacks_tier(tmp_path: Path) -> None:
    o = joining_org()
    o.channels["C0SECOND1"] = Chan("C0SECOND1", "second", member=False)
    waits: list[float] = []
    s = settings(tmp_path, SLACK_JOIN_PUBLIC_CHANNELS="on")
    clock = iter(float(n) / 10 for n in range(10_000))
    clients = Clients(
        s, session=o, sleep=waits.append, clock=lambda: next(clock), wall=lambda: 1.79e9
    )
    doc, failed = run_scan(s, clients, detector=DETECTOR, now=lambda: NOW)
    assert failed == 0
    valid(doc)
    assert sorted(o.joins) == ["C0FINANCE", "C0LOBBY01", "C0SECOND1"]
    # One join every 1.2 seconds at most (Tier 3): each wait tops the gap up to it.
    assert len(waits) == 2 and all(0 < w <= 1.2 for w in waits)
    # report.html says what the scanner changed; a run that joined nothing says nothing.
    page = report_html(doc)
    assert "What the scanner changed" in page and "C0LOBBY01" in page
    assert "What the scanner changed" not in report_html(scan(org(), settings(tmp_path)))
