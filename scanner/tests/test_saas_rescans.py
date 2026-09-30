"""SaaS attachments and shared files rescanned when a reader that read them changed (#67).

Each attachment (M365 mail, Gmail, Jira, Confluence) and each Slack file is recorded in its
source's object index by its stable id. After a component changes, a pass lists the items
that have attachments, metadata only, and downloads just the stale ones within the rescan
share. Message bodies are not read again. Every value is made up.
"""

from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from sensitive_data_core.index import READER
from sensitive_data_core.state import FileState
from synthetic import CARDS, SSN_A, dashed, printed
from test_rescans import bumped, use


def rescanned(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in doc["findings"] if f.get("rescanReason")]


# ------------------------------------------------------------------ M365 mail


def test_mail_attachments_are_rescanned_for_their_reader_and_bodies_are_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from saas_fakes import settings as m365_settings
    from test_saas_m365 import ALICE, OUTSIDE, mailbox_tenant, scan

    m = mailbox_tenant()
    state = FileState(str(tmp_path / "state.json"))
    s = m365_settings(tmp_path, M365_USERS=ALICE, DISCOVER="mail", M365_MAIL_SCOPE_CHECK=OUTSIDE)
    first = scan(m, s, state=state)
    assert first["coverage"][0]["indexed"] == 2  # the two file attachments read, by their ids
    m.calls.clear()
    again = scan(m, s, state=state)
    # A full first pass recorded every attachment: nothing is enumerated or downloaded.
    assert not [u for _, u, _, _ in m.calls if "/attachments" in u]
    assert again["coverage"][0]["rescanned"] == {}
    # The Word reader changed: only the Word attachment is downloaded again.
    use(monkeypatch, bumped("reader:docx"))
    m.calls.clear()
    doc = scan(m, s, state=state)
    downloads = [u for _, u, _, _ in m.calls if u.endswith("/$value")]
    assert len(downloads) == 1 and "/attachments/a2/" in downloads[0]
    assert not any("/messages/delta" in u and "deltatoken" not in u for _, u, _, _ in m.calls)
    cov = doc["coverage"][0]
    assert cov["rescanned"] == {READER: 1} and cov["rescanBacklog"] == 0
    again_ = rescanned(doc)
    assert again_ and {f["resource"]["itemId"] for f in again_} == {"m3/a2"}
    assert all(f["rescanReason"] == READER for f in again_)
    # The message's own findings and its other attachment's stand, unchanged.
    ids = {f["resource"]["itemId"] for f in doc["findings"]}
    assert {"m1", "m3/a1", "m3/a2"} <= ids
    assert {f["id"] for f in doc["findings"]} == {f["id"] for f in first["findings"]}
    # Read with the new reader, it is current: nothing more.
    m.calls.clear()
    scan(m, s, state=state)
    assert not [u for _, u, _, _ in m.calls if u.endswith("/$value")]
    assert printed(CARDS["amex"]) not in str(doc) and dashed(SSN_A) not in str(doc)


# ------------------------------------------------------------------ Gmail


def test_gmail_attachments_are_rescanned_by_their_stable_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from gws_fakes import settings as gws_settings
    from test_saas_gws import ANA, BEN, scan, workspace

    w = workspace()
    state = FileState(str(tmp_path / "state.json"))
    s = gws_settings(tmp_path, GWS_USERS=f"{ANA},{BEN}", DISCOVER="gmail")
    first = scan(w, s, state=state)
    scan(w, s, state=state)
    use(monkeypatch, bumped("reader:docx"))
    w.calls.clear()
    doc = scan(w, s, state=state)
    fetched = [u for _, u, _, _ in w.calls if "/attachments/" in u]
    assert len(fetched) == 1 and "/messages/m3/" in fetched[0]
    listed = [p for _, u, p, _ in w.calls if u.endswith("/messages") and p]
    assert any("has:attachment" in str(p.get("q")) for p in listed)
    again = rescanned(doc)
    assert again and {f["resource"]["itemId"] for f in again} == {"m3/2"}
    assert {f["rescanReason"] for f in again} == {READER}
    assert {f["id"] for f in doc["findings"]} == {f["id"] for f in first["findings"]}
    # The bodies were not read again: no message's text was scanned this run.
    assert sum(c["scanned"] for c in doc["coverage"]) == 1


# ------------------------------------------------------------------ Slack


def test_slack_files_are_rescanned_by_their_file_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from slack_fakes import settings as slack_settings
    from test_saas_slack import org, scan

    o = org()
    state = FileState(str(tmp_path / "state.json"))
    s = slack_settings(tmp_path)
    first = scan(o, s, state=state)
    scan(o, s, state=state)
    use(monkeypatch, bumped("reader:xlsx"))
    o.calls.clear()
    doc = scan(o, s, state=state)
    names = [urllib.parse.urlsplit(u).path for _, u, _, _ in o.calls]
    assert "/api/files.list" in names
    assert names.count("/files-pri/T0-F0ROSTER1/roster.xlsx") >= 1
    assert not any(n.endswith(("conversations.replies",)) for n in names)
    again = rescanned(doc)
    assert again and {f["resource"]["itemId"] for f in again} == {"F0ROSTER1"}
    assert {f["rescanReason"] for f in again} == {READER}
    assert {f["id"] for f in doc["findings"]} == {f["id"] for f in first["findings"]}
    channel = next(c for c in doc["coverage"] if c["kind"] == "slack_channel" and c["indexed"])
    assert channel["rescanned"] == {READER: 1}


# ------------------------------------------------------------------ Jira and Confluence


def test_jira_and_confluence_attachments_are_rescanned_and_text_is_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from atlassian_fakes import settings as atlassian_settings
    from test_saas_atlassian import scan, site

    s_ = site()
    state = FileState(str(tmp_path / "state.json"))
    s = atlassian_settings(tmp_path)
    first = scan(s_, s, state=state)
    scan(s_, s, state=state)
    # A new class: every text-bearing attachment is read again; issue and page text is not.
    use(monkeypatch, bumped(add={"spec-standalone/passport": "c" * 12}))
    s_.calls.clear()
    doc = scan(s_, s, state=state)
    paths = [urllib.parse.urlsplit(u).path for _, u, _, _ in s_.calls]
    assert "/rest/api/3/attachment/content/10001" in paths
    assert "/wiki/rest/api/content/20002/child/attachment/att1/download" in paths
    again = rescanned(doc)
    assert {f["resource"]["itemId"] for f in again} == {"PAY-3/10001", "20002/att1"}
    assert {f["rescanClasses"][0] for f in again} == {"passport"}
    assert {f["resource"]["part"] for f in again} == {"attachment"}
    # The issues' and pages' own findings are the same, and were not read again.
    assert sum(c["scanned"] for c in doc["coverage"]) == 2
    assert {f["id"] for f in doc["findings"]} == {f["id"] for f in first["findings"]}
    s_.calls.clear()
    scan(s_, s, state=state)
    assert not any(
        "/attachment/" in u for _, u, _, _ in s_.calls if "download" in u or "content/1" in u
    )


def test_no_value_in_a_saas_index(tmp_path: Path) -> None:
    """Attachments are keyed by their ids, as HMACs: a file named for a value, holding it,
    leaves neither in the index (#67)."""
    import gzip

    from slack_fakes import settings as slack_settings
    from test_saas_slack import org, scan

    o = org()
    msg = next(m for c in o.channels.values() for m in c.messages if m.get("files"))
    f = msg["files"][0]
    f["name"] = f"card-{CARDS['visa']}.xlsx"
    state = FileState(str(tmp_path / "state.json"))
    scan(o, slack_settings(tmp_path), state=state)
    files = [p for p in tmp_path.rglob("*") if p.is_file() and ".index" in str(p)]
    assert any(p.name.endswith(".db.gz") for p in files)
    text = "\n".join(
        (gzip.decompress(p.read_bytes()) if p.name.endswith(".gz") else p.read_bytes()).decode(
            "latin-1"
        )
        for p in files
    )
    for value in (CARDS["visa"], CARDS["amex"], "F0ROSTER1", "C0SUPPORT1"):
        assert value not in text
