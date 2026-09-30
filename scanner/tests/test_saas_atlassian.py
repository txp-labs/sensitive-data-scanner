"""The SaaS scanner with Atlassian: Jira issues and Confluence pages, API token and 3LO.

Every Atlassian call goes to a stubbed session (atlassian_fakes.py); every value is made up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from atlassian_fakes import CLOUD, EMAIL, NOW, SITE, Issue, Page, Site, settings
from aws_fixtures import shared_detector
from office_fixtures import docx
from sensitive_data_core.findings import key_hash
from sensitive_data_core.state import FileState
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.resources import tenant_hash
from sensitive_data_saas.runner import run_scan
from sensitive_data_saas.sources.atlassian import adf_text
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


def scan(site: Site, s: Any, **kw: Any) -> dict[str, Any]:
    doc, failed = run_scan(s, site.clients(s), detector=DETECTOR, now=lambda: NOW, **kw)
    assert failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(x["kind"], x["name"]): x for x in doc["discovery"]["stores"]}


def site() -> Site:
    s = Site()
    s.projects["PAY"] = [
        Issue("PAY-1", "refund", f"my card is {printed(CARDS['visa'])}"),
        Issue(
            "PAY-2",
            "hr",
            "",
            comments=[f"ssn {dashed(SSN_A)}"],
            updated="2026-09-28T11:00:00.000+0000",
        ),
        Issue(
            "PAY-3",
            "file",
            "see attached",
            attachments=[("10001", "memo.docx", docx([f"card {printed(CARDS['amex'])}"]))],
            updated="2026-09-28T12:00:00.000+0000",
        ),
    ]
    s.projects["HR"] = [Issue("HR-1", "x", "y")]
    s.forbidden_projects.add("HR")
    s.spaces["ENG"] = [
        Page("20001", "Runbook", f"<p>test card <b>{printed(CARDS['mastercard'])}</b></p>"),
        Page(
            "20002",
            "Notes",
            "<p>nothing</p>",
            comments=[f"<p>ssn {dashed(SSN_A)}</p>"],
            attachments=[("att1", "export.csv", f"card\n{CARDS['jcb']}\n".encode())],
            when="2026-09-28T11:00:00.000Z",
        ),
    ]
    return s


def test_settings(tmp_path: Path) -> None:
    s = settings(tmp_path)
    assert s.atlassian is not None and s.discover == ("jira_project", "confluence_space")
    assert EMAIL not in repr(s) and "made-up" not in repr(s.atlassian)
    base = {"SCANNER_SITE": "x", "FINDINGS_FILE": "/tmp/x", "ATLASSIAN_SITE": SITE}  # noqa: S108
    for bad, code in (
        ({"ATLASSIAN_SITE": "acme.example.com"}, "atlassian_site"),
        ({}, "atlassian_credential"),
        ({"ATLASSIAN_API_TOKEN": "made-up"}, "atlassian_secret_in_env"),
        ({"ATLASSIAN_API_TOKEN_FILE": "/t", "ATLASSIAN_EMAIL": "nope"}, "atlassian_email"),
        ({"ATLASSIAN_OAUTH_CLIENT_ID": "abcdefgh12"}, "atlassian_credential"),
    ):
        with pytest.raises(ConfigError) as err:
            read_settings({**base, **bad})
        assert err.value.code == code
    assert (
        adf_text(
            {
                "type": "doc",
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": "a"}]}],
            }
        )
        == "a\n"
    )


def test_jira_and_confluence(tmp_path: Path) -> None:
    st = site()
    doc = scan(st, settings(tmp_path))
    by = stores(doc)
    pay = by[("jira_project", "PAY")]
    assert pay["status"] == "scanned" and pay["vendor"] == "atlassian"
    assert pay["tenantHash"] == tenant_hash(CLOUD)
    hr = by[("jira_project", "HR")]
    assert (hr["status"], hr["reason"], hr["error"]) == ("error", "access_denied", "Http403")
    found = {
        (f["resource"]["service"], f["resource"]["part"], f["class"], f["resource"].get("name"))
        for f in doc["findings"]
    }
    assert ("jira", "issue", "card", None) in found
    assert ("jira", "issue", "us_ssn", None) in found  # a comment
    assert ("jira", "attachment", "card", "memo.docx") in found
    assert ("confluence", "page", "card", None) in found
    assert ("confluence", "page", "us_ssn", None) in found  # a footer comment
    assert ("confluence", "attachment", "card", "export.csv") in found
    issue = next(f for f in doc["findings"] if f["resource"].get("itemId") == "PAY-1")
    assert issue["link"] == f"https://{SITE}/browse/PAY-1"
    page = next(f for f in doc["findings"] if f["resource"].get("itemId") == "20001")
    assert page["link"] == f"https://{SITE}/wiki/pages/viewpage.action?pageId=20001"
    assert EMAIL not in json.dumps(doc)
    ranged = [c for c in st.calls if "attachment/content" in c[1] or c[1].endswith("/download")]
    assert ranged and all("Range" in c[3] for c in ranged)


def test_incremental_runs_skip_what_was_read_and_drop_what_is_gone(tmp_path: Path) -> None:
    st = site()
    state = FileState(str(tmp_path / "state.json"))
    s = settings(tmp_path, ISSUES_MAX_PER_PROJECT="2", DISCOVER="jira", JIRA_PROJECTS="PAY")
    first = scan(st, s, state=state)
    assert first["coverage"][0]["scanned"] == 2 and first["coverage"][0]["backlog"]
    second = scan(st, s, state=state)
    assert second["coverage"][0]["passComplete"]
    assert {f["resource"]["itemId"] for f in second["findings"]} >= {"PAY-1", "PAY-2"}
    third = scan(st, s, state=state)
    assert third["coverage"][0]["scanned"] == 0  # nothing changed
    st.projects["PAY"].append(
        Issue("PAY-4", "new", f"ssn {dashed(SSN_A)}", updated="2026-09-29T09:00:00.000+0000")
    )
    st.projects["PAY"] = [i for i in st.projects["PAY"] if i.key != "PAY-1"]
    fourth = scan(st, s, state=state)
    ids = {f["resource"]["itemId"].split("/")[0] for f in fourth["findings"]}
    assert "PAY-4" in ids and "PAY-1" not in ids
    assert fourth["coverage"][0]["scanned"] == 1


def test_oauth_rotates_its_refresh_token_and_byok(tmp_path: Path) -> None:
    st = site()
    secret = tmp_path / "client-secret"
    secret.write_text("made-up-client-secret")
    refresh = tmp_path / "refresh"
    refresh.write_text("made-up-refresh-0")
    s = settings(
        tmp_path,
        ATLASSIAN_OAUTH_CLIENT_ID="abcdefgh12",
        ATLASSIAN_OAUTH_CLIENT_SECRET_FILE=str(secret),
        ATLASSIAN_OAUTH_REFRESH_TOKEN_FILE=str(refresh),
        ATLASSIAN_BYOK_KEY_ID="byok-1",
        DISCOVER="confluence",
    )
    doc = scan(st, s)
    assert st.oauth_posts[0]["refresh_token"] == "made-up-refresh-0"  # noqa: S105
    assert refresh.read_text() == "made-up-refresh-1"
    assert all("api.atlassian.com" in c[1] for c in st.calls if "/wiki/" in c[1])
    f = doc["findings"][0]
    assert f["atRestEncryption"] == "customer_managed_key" and f["atRestKeyHash"] == key_hash(
        "byok-1"
    )
    refresh.chmod(0o400)
    tmp_path.chmod(0o500)
    try:
        bad = scan(st, s)
        assert bad["discovery"]["listErrors"] == {"confluence_space": "RefreshTokenNotSaved"}
    finally:
        tmp_path.chmod(0o700)
        refresh.chmod(0o600)
