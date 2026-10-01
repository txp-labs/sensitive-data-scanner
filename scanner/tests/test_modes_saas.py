"""Vendor detection imported for SaaS (#55): Purview DLP, the Workspace Alert Center, Slack DLP.

Every vendor call goes to the stubbed sessions (saas_fakes, gws_fakes, slack_fakes); every
value is made up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from gws_fakes import ADMIN, DFile, Workspace
from gws_fakes import settings as gws_settings
from saas_fakes import M365, NOW, Item
from saas_fakes import settings as m365_settings
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.resources import owner_hash
from sensitive_data_saas.runner import run_scan
from slack_fakes import AUDIT, Chan, SlackOrg, ts
from slack_fakes import settings as slack_settings
from synthetic import CARDS, printed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
ALICE = "alice@contoso.example"
ANA = "ana@acme.example"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def scan(session: Any, s: Any) -> dict[str, Any]:
    doc, failed = run_scan(s, session.clients(s), detector=shared_detector(), now=lambda: NOW)
    assert failed == 0
    valid(doc)
    return doc


def purview_alert(aid: str) -> dict[str, Any]:
    """A Purview DLP alert as Graph returns it: title, description and evidence may quote
    anything."""
    return {
        "id": aid,
        "title": f"DLP policy 'Cards' matched {CARDS['visa']}",
        "description": f"subject: my card {printed(CARDS['visa'])}",
        "serviceSource": "microsoftDataLossPrevention",
        "severity": "high",
        "lastUpdateDateTime": "2026-09-28T10:00:00Z",
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
                "subject": f"card {CARDS['visa']}",
                "recipientEmailAddress": "someone@contoso.example",
                "p1Sender": {"emailAddress": ALICE},
            },
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {"userPrincipalName": ALICE, "displayName": "Alice"},
            },
        ],
    }


def test_modes_per_vendor_and_atlassian_is_scanner_only(tmp_path: Path) -> None:
    s = m365_settings(tmp_path, M365_USERS=ALICE, SCAN_MODE="both")
    assert dict(s.modes) == {"m365": "both"}
    s = m365_settings(tmp_path, M365_USERS=ALICE, SCAN_MODE_M365="vendor")
    assert dict(s.modes) == {"m365": "vendor"}
    with pytest.raises(ConfigError) as err:
        m365_settings(tmp_path, SCAN_MODE_M365="sometimes")
    assert err.value.code == "scan_mode"
    token = tmp_path / "atl"
    token.write_text("made-up")
    base = {
        "SCANNER_SITE": "x",
        "FINDINGS_FILE": "/tmp/x",  # noqa: S108
        "ATLASSIAN_SITE": "acme.atlassian.net",
        "ATLASSIAN_EMAIL": "sds@acme.example",
        "ATLASSIAN_API_TOKEN_FILE": str(token),
    }
    assert dict(read_settings({**base, "SCAN_MODE": "both"}).modes) == {"atlassian": "scanner"}
    with pytest.raises(ConfigError) as err:
        read_settings({**base, "SCAN_MODE_ATLASSIAN": "vendor"})
    assert err.value.code == "scan_mode_atlassian"
    with pytest.raises(ConfigError) as err:
        slack_settings(tmp_path, SCAN_MODE_SLACK="both")
    assert err.value.code == "slack_audit_token_file"


def test_purview_alerts_in_vendor_mode(tmp_path: Path) -> None:
    m = M365()
    m.user(ALICE, "u-alice", drive="d-alice")
    m.drives["d-alice"].add(
        Item("f1", "notes.txt", f"my card is {printed(CARDS['visa'])}".encode())
    )
    m.alerts = [purview_alert("a-1"), purview_alert("a-2")]
    doc = scan(
        m, m365_settings(tmp_path, M365_USERS=ALICE, DISCOVER="onedrive", SCAN_MODE_M365="vendor")
    )
    assert doc["scanMode"] == {"m365": "vendor"} and doc["coverage"] == []
    (cov,) = doc["vendorCoverage"]
    assert (cov["vendor"], cov["status"], cov["findings"]) == ("purview", "read", 2)
    assert "item_not_linkable" in cov["limits"] and "m365_mail" in cov["covers"]
    stores = {s["kind"]: s for s in doc["discovery"]["stores"] if s["name"] != "*"}
    assert stores["m365_onedrive"]["reason"] == "vendor_mode"
    f = doc["findings"][0]
    assert f["source"] == "vendor:purview" and f["class"] == "other"
    assert f["vendorType"] == "DLP_POLICY_MATCH"
    assert f["resource"]["service"] == "exchange" and f["resource"]["ownerHash"] == owner_hash(
        ALICE
    )
    blob = json.dumps(doc)
    assert CARDS["visa"] not in blob and ALICE not in blob and "DLP policy" not in blob


def test_workspace_alerts_link_to_the_scanners_drive_findings(tmp_path: Path) -> None:
    w = Workspace()
    w.user(ANA)
    w.file(
        "my",
        DFile("f1", "notes.txt", data=f"my card is {printed(CARDS['visa'])}".encode(), owner=ANA),
    )
    w.alerts = [
        {
            "alertId": "al-1",
            "createTime": "2026-09-28T10:00:00Z",
            "type": "DlpRuleViolation",
            "data": {
                "@type": "type.googleapis.com/google.apps.alertcenter.type.DlpRuleViolation",
                "ruleViolationInfo": {
                    "dataSource": "DRIVE",
                    "resourceInfo": {"documentId": "f1", "resourceTitle": f"card {CARDS['visa']}"},
                    "matchInfo": [
                        {"predefinedDetector": {"detectorName": "CREDIT_CARD_NUMBER"}},
                        {
                            "userDefinedDetector": {
                                "displayName": "Employee ID",
                                "resourceName": "x",
                            }
                        },
                    ],
                    "triggeringUserEmail": ANA,
                    "recipients": ["friend@acme.example"],
                    "ruleInfo": {"displayName": "Block cards", "resourceName": "rules/1"},
                },
            },
        }
    ]
    doc = scan(w, gws_settings(tmp_path, GWS_USERS=ANA, DISCOVER="drive", SCAN_MODE="both"))
    (cov,) = doc["vendorCoverage"]
    assert (cov["vendor"], cov["findings"]) == ("google_workspace_dlp", 1)
    vendor = [f for f in doc["findings"] if f["source"] == "vendor:google_workspace_dlp"]
    card = next(f for f in vendor if f["class"] == "card")
    ours = next(f for f in doc["findings"] if f["source"] == "scanner" and f["class"] == "card")
    assert card["linked"] == [ours["id"]] and ours["linked"] == [card["id"]]
    assert {f["vendorType"] for f in vendor} == {"CREDIT_CARD_NUMBER", "custom:Employee ID"}
    blob = json.dumps(doc)
    assert ANA not in blob and "friend@" not in blob and "Block cards" not in blob
    assert ADMIN not in blob


def test_the_alert_center_off_imports_nothing_and_says_so(tmp_path: Path) -> None:
    """D1 (#105): GWS_ALERT_CENTER off (on by default): in both mode nothing is imported, the
    importer says `not_enabled` naming the setting, and the scanner still reads Drive."""
    w = Workspace()
    w.user(ANA)
    w.file(
        "my",
        DFile("f1", "notes.txt", data=f"my card is {printed(CARDS['visa'])}".encode(), owner=ANA),
    )
    w.alerts = [{"alertId": "al-1", "createTime": "2026-09-28T10:00:00Z"}]
    doc = scan(
        w,
        gws_settings(
            tmp_path, GWS_USERS=ANA, DISCOVER="drive", SCAN_MODE="both", GWS_ALERT_CENTER="off"
        ),
    )
    (cov,) = doc["vendorCoverage"]
    assert (cov["vendor"], cov["status"], cov["findings"], cov["toggle"]) == (
        "google_workspace_dlp",
        "not_enabled",
        0,
        "GWS_ALERT_CENTER",
    )
    assert {f["source"] for f in doc["findings"]} == {"scanner"}
    # In vendor mode, nothing reads Workspace: its stores say so.
    doc = scan(
        w,
        gws_settings(
            tmp_path, GWS_USERS=ANA, DISCOVER="drive", SCAN_MODE="vendor", GWS_ALERT_CENTER="off"
        ),
    )
    assert {x["reason"] for x in doc["discovery"]["stores"]} == {"vendor_not_covered"}
    assert doc["findings"] == []


def test_slack_dlp_audit_events_link_to_the_scanners_messages(tmp_path: Path) -> None:
    o = SlackOrg()
    c = Chan("C0SUPPORT1", "support")
    c.messages = [{"ts": ts(5), "text": f"my card is {printed(CARDS['visa'])}"}]
    o.channels[c.id] = c
    o.audit = [
        {
            "id": "ev-1",
            "date_create": int(NOW.timestamp()) - 3600,
            "action": "native_dlp_rule_matched",
            "actor": {"type": "user", "user": {"id": "U1", "email": "bob@acme.example"}},
            "entity": {"type": "message", "message": {"channel": "C0SUPPORT1", "timestamp": ts(5)}},
            "details": {"rule_name": f"cards {CARDS['visa']}", "text": printed(CARDS["visa"])},
        },
        {
            "id": "ev-2",
            "date_create": int(NOW.timestamp()) - 1800,
            "action": "native_dlp_rule_matched",
            "entity": {"type": "file", "file": {"id": "F0FILE1", "name": f"{CARDS['visa']}.csv"}},
        },
    ]
    audit = tmp_path / "audit-token"
    audit.write_text(AUDIT)
    doc = scan(
        o, slack_settings(tmp_path, SCAN_MODE_SLACK="both", SLACK_AUDIT_TOKEN_FILE=str(audit))
    )
    (cov,) = doc["vendorCoverage"]
    assert (cov["vendor"], cov["status"], cov["findings"]) == ("slack_dlp", "read", 2)
    vendor = [f for f in doc["findings"] if f["source"] == "vendor:slack_dlp"]
    msg = next(f for f in vendor if f["resource"]["part"] == "message")
    ours = next(f for f in doc["findings"] if f["source"] == "scanner")
    # The same message, by its hash. The event names no class of data: linked by location
    # only (#105, LINK_VENDOR_ALERTS_BY_LOCATION on by default), and both sides say so.
    assert msg["resource"]["itemHash"] == ours["resource"]["itemHash"]
    assert msg["linked"] == [ours["id"]] and ours["linked"] == [msg["id"]]
    assert msg["linkedBy"] == ours["linkedBy"] == "location"
    assert "no_data_class" in cov["limits"]
    assert msg["vendorType"] == "native_dlp_rule_matched"
    blob = json.dumps(doc)
    assert CARDS["visa"] not in blob and "bob@" not in blob and AUDIT not in blob
    assert o.audit_queries and o.audit_queries[0]["action"] == "native_dlp_rule_matched"


def test_linking_by_location_can_be_turned_off(tmp_path: Path) -> None:
    """D2 (#105): LINK_VENDOR_ALERTS_BY_LOCATION off: an alert that names no kind of data is
    never linked, as before 1.12."""
    o = SlackOrg()
    c = Chan("C0SUPPORT1", "support")
    c.messages = [{"ts": ts(5), "text": f"my card is {printed(CARDS['visa'])}"}]
    o.channels[c.id] = c
    o.audit = [
        {
            "id": "ev-1",
            "date_create": int(NOW.timestamp()) - 3600,
            "action": "native_dlp_rule_matched",
            "entity": {"type": "message", "message": {"channel": "C0SUPPORT1", "timestamp": ts(5)}},
        }
    ]
    audit = tmp_path / "audit-token"
    audit.write_text(AUDIT)
    doc = scan(
        o,
        slack_settings(
            tmp_path,
            SCAN_MODE_SLACK="both",
            SLACK_AUDIT_TOKEN_FILE=str(audit),
            LINK_VENDOR_ALERTS_BY_LOCATION="off",
        ),
    )
    assert not any("linked" in f or "linkedBy" in f for f in doc["findings"])
    assert len(doc["findings"]) == 2
