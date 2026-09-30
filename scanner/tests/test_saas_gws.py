"""The SaaS scanner with Google Workspace: delegation, people, Gmail, Drive, shared drives.

Every Google call goes to a stubbed session (gws_fakes.py); every value is made up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from gws_fakes import (
    ADMIN,
    CUSTOMER,
    NOW,
    PROVIDER,
    SA,
    DFile,
    GMsg,
    Workspace,
    gerror,
    settings,
)
from office_fixtures import docx
from sensitive_data_core.state import FileState
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.resources import owner_hash, tenant_hash
from sensitive_data_saas.runner import run_scan
from sensitive_data_saas.scopes import GWS_GMAIL
from synthetic import CARDS, SSN_A, dashed, printed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
DETECTOR = shared_detector()
ANA = "ana@acme.example"
BEN = "ben@acme.example"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def scan(w: Workspace, s: Any, **kw: Any) -> dict[str, Any]:
    doc, failed = run_scan(s, w.clients(s), detector=DETECTOR, now=lambda: NOW, **kw)
    assert failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(x["kind"], x["name"]): x for x in doc["discovery"]["stores"]}


def user_store(email: str) -> str:
    return f"user-{owner_hash(email)[:16]}"


def workspace() -> Workspace:
    w = Workspace()
    w.user(ANA)
    w.user(BEN, gmail=False)
    w.mail(ANA, GMsg("m1", "Order", text=f"my card is {printed(CARDS['visa'])}"))
    w.mail(ANA, GMsg("m2", "HR", html=f"<p>ssn <b>{dashed(SSN_A)}</b></p>"))
    w.mail(
        ANA,
        GMsg(
            "m3",
            "files",
            text="see attached",
            attachments=[("memo.docx", docx([f"card {printed(CARDS['amex'])}"]))],
        ),
    )
    w.mail(ANA, GMsg("old", "old", text=f"{CARDS['jcb']}", days_old=400))
    w.file(
        "my",
        DFile("f1", "notes.txt", data=f"my card is {printed(CARDS['visa'])}".encode(), owner=ANA),
    )
    w.file(
        "my",
        DFile(
            "f2",
            "Roster",
            mime="application/vnd.google-apps.spreadsheet",
            data=f"name,ssn\nA,{dashed(SSN_A)}\n".encode(),
            owner=ANA,
        ),
    )
    w.file(
        "my",
        DFile("f3", "photo.png", mime="image/png", data=b"\x89PNG\r\n\x1a\n made up", owner=ANA),
    )
    w.file("my", DFile("f4", "form", mime="application/vnd.google-apps.form", owner=ANA))
    w.file("my", DFile("f5", "link", mime="application/vnd.google-apps.shortcut", owner=ANA))
    w.file("my", DFile("b1", "bens.txt", data=f"ssn {dashed(SSN_A)}".encode(), owner=BEN))
    w.drive_names["0AshareFIN1"] = "Finance"
    w.drive_members["0AshareFIN1"] = {ADMIN}
    w.file("0AshareFIN1", DFile("s1", "ledger.csv", data=f"card\n{CARDS['mastercard']}\n".encode()))
    w.drive_names["0AshareLEG2"] = "Legal"
    return w


def test_settings_need_a_signer_and_a_provider_for_federation(tmp_path: Path) -> None:
    s = settings(tmp_path, GWS_USERS=ANA)
    assert s.gws is not None and s.discover == ("gws_gmail", "gws_drive", "gws_shared_drive")
    assert ADMIN not in repr(s) and ANA not in repr(s.gws)
    base = {
        "SCANNER_SITE": "x",
        "GWS_CUSTOMER_ID": CUSTOMER,
        "GWS_SERVICE_ACCOUNT": SA,
        "GWS_ADMIN_USER": ADMIN,
        "FINDINGS_FILE": "/tmp/x",  # noqa: S108
    }
    for bad, code in (
        ({"GWS_CUSTOMER_ID": "acme"}, "gws_customer_id"),
        ({"GWS_SERVICE_ACCOUNT": "sds@gmail.com"}, "gws_service_account"),
        ({}, "gws_credential"),
        ({"GWS_CREDENTIAL": "aws"}, "gws_workload_provider"),
        ({"GWS_CREDENTIAL": "gcp", "GWS_KEY_FILE": "/k.json"}, "gws_credential"),
        ({"GWS_CREDENTIAL": "gcp", "GWS_ORG_UNITS": "/Sales'x"}, "gws_org_units"),
        ({"GWS_CREDENTIAL": "gcp", "GWS_SHARED_DRIVES": "a b"}, "gws_shared_drives"),
    ):
        with pytest.raises(ConfigError) as err:
            read_settings({**base, **bad})
        assert err.value.code == code
    ok = read_settings({**base, "GWS_CREDENTIAL": "aws", "GWS_WORKLOAD_PROVIDER": PROVIDER})
    assert ok.gws is not None and ok.gws.provider == PROVIDER


def test_delegation_signs_as_each_person_for_read_only_scopes(tmp_path: Path) -> None:
    w = workspace()
    s = settings(tmp_path, GWS_USERS=ANA, DISCOVER="gmail")
    scan(w, s)
    subjects = {(c["sub"], c["scope"]) for c in w.token_posts}
    assert (ANA, " ".join(GWS_GMAIL)) in subjects
    assert all(
        c["iss"] == SA and c["aud"] == "https://oauth2.googleapis.com/token" for c in w.token_posts
    )
    # The key file signed them (RS256), and no call went through IAM Credentials.
    assert not any("iamcredentials" in c[1] for c in w.calls)
    # Keyless on Google Cloud: the metadata server's token calls signJwt.
    w2 = workspace()
    scan(w2, settings(tmp_path, GWS_USERS=ANA, DISCOVER="gmail", GWS_CREDENTIAL="gcp"))
    assert any(c[1].endswith(f"{SA}:signJwt") for c in w2.calls)
    assert any("metadata.google.internal" in c[1] for c in w2.calls)
    # Keyless elsewhere: a workload token exchanged at Google's STS.
    token = tmp_path / "token"
    token.write_text("made-up-k8s-token")
    w3 = workspace()
    scan(
        w3,
        settings(
            tmp_path,
            GWS_USERS=ANA,
            DISCOVER="gmail",
            GWS_CREDENTIAL=f"file:{token}",
            GWS_WORKLOAD_PROVIDER=PROVIDER,
        ),
    )
    sts = [p for p in w3.token_posts if "subject_token" in p]
    assert sts and sts[0]["subject_token"] == "made-up-k8s-token"  # noqa: S105


def test_a_scope_the_delegation_lacks_is_access_denied(tmp_path: Path) -> None:
    w = workspace()
    w.delegated.discard(GWS_GMAIL[0])
    doc = scan(w, settings(tmp_path, GWS_USERS=ANA, DISCOVER="gmail"))
    ana = stores(doc)[("gws_gmail", user_store(ANA))]
    assert (ana["status"], ana["reason"], ana["error"]) == (
        "error",
        "access_denied",
        "unauthorized_client",
    )


def test_gmail_messages_and_attachments_then_only_history(tmp_path: Path) -> None:
    w = workspace()
    w.per_page = 2
    state = FileState(str(tmp_path / "state.json"))
    s = settings(
        tmp_path, GWS_USERS=f"{ANA},{BEN}", DISCOVER="gmail", MAIL_MAX_MESSAGES_PER_MAILBOX="2"
    )
    first = scan(w, s, state=state)
    by = stores(first)
    assert by[("gws_gmail", user_store(BEN))]["reason"] == "not_provisioned"
    ana = by[("gws_gmail", user_store(ANA))]
    assert ana["vendor"] == "google_workspace" and ana["tenantHash"] == tenant_hash(CUSTOMER)
    assert ana["backlog"]
    second = scan(w, s, state=state)
    found = {
        (f["resource"]["part"], f["class"], f["resource"].get("name")) for f in second["findings"]
    }
    assert ("message", "card", None) in found
    assert ("message", "us_ssn", None) in found  # the HTML-only body's text
    assert ("attachment", "card", "memo.docx") in found
    assert all(f["resource"]["itemId"] != "old" for f in second["findings"])
    assert all(f["link"] is None for f in second["findings"])
    # Later runs read only the history: a new message, and a deleted one drops its findings.
    w.mail(ANA, GMsg("m9", "new", text=f"ssn {dashed(SSN_A)}"))
    w.unmail(ANA, "m1")
    third = scan(w, s, state=state)
    ids = {f["resource"]["itemId"] for f in third["findings"]}
    assert "m9" in ids and "m1" not in ids and "m2" in ids
    assert next(c for c in third["coverage"] if c["scanned"])["eligible"] == 1
    # A history Gmail no longer keeps starts a new pass.
    w.history_floor = 10**9
    fourth = scan(w, s, state=state)
    assert any(c["scanned"] for c in fourth["coverage"])
    blob = json.dumps(third) + (tmp_path / "state.json").read_text()
    assert ANA not in blob and CARDS["visa"] not in blob


def test_my_drive_and_shared_drives(tmp_path: Path) -> None:
    w = workspace()
    s = settings(
        tmp_path,
        GWS_GROUPS="team@acme.example",
        GWS_SHARED_DRIVES="0AshareFIN1,0AshareLEG2,0AshareGONE3",
        DISCOVER="drive,shared_drive",
    )
    w.groups["team@acme.example"] = [ANA, BEN]
    doc = scan(w, s)
    by = stores(doc)
    assert by[("gws_drive", user_store(ANA))]["status"] == "scanned"
    assert by[("gws_shared_drive", "Finance")]["status"] == "scanned"
    legal = by[("gws_shared_drive", "Legal")]
    assert (legal["status"], legal["reason"], legal["error"]) == (
        "error",
        "access_denied",
        "NOT_FOUND",
    )
    assert by[("gws_shared_drive", "0AshareGONE3")]["reason"] == "not_provisioned"
    found = {
        (f["resource"]["service"], f["resource"].get("name"), f["class"]) for f in doc["findings"]
    }
    assert ("drive", "notes.txt", "card") in found
    assert ("drive", "Roster", "us_ssn") in found  # a Google Sheet, exported as CSV
    assert ("shared_drive", "ledger.csv", "card") in found
    # Ben's file is read in Ben's store, once.
    bens = [f for f in doc["findings"] if f["resource"].get("name") == "bens.txt"]
    assert len(bens) == 1 and bens[0]["resource"]["ownerHash"] == owner_hash(BEN)
    ana_cov = next(c for c in doc["coverage"] if c["kind"] == "gws_drive" and c["scanned"] == 2)
    assert ana_cov["skipped"] == {"document": 1, "image": 1, "linked_item": 1}
    f1 = next(f for f in doc["findings"] if f["resource"].get("name") == "notes.txt")
    assert f1["link"] == "https://drive.google.com/open?id=f1"
    assert f1["atRestEncryption"] == "service_managed"
    ranged = [c for c in w.calls if c[1].endswith("/files/f1")]
    assert ranged and all("Range" in c[3] for c in ranged)


def test_drive_changes_after_the_first_pass(tmp_path: Path) -> None:
    w = workspace()
    state = FileState(str(tmp_path / "state.json"))
    s = settings(tmp_path, GWS_USERS=ANA, DISCOVER="drive", FILES_MAX_PER_DRIVE="1")
    runs = [scan(w, s, state=state) for _ in range(4)]
    assert runs[0]["coverage"][0]["backlog"] and runs[-1]["coverage"][0]["passComplete"]
    assert {f["resource"]["itemId"] for f in runs[-1]["findings"]} == {"f1", "f2"}
    w.file(
        "my",
        DFile("f6", "new.txt", data=f"my card is {printed(CARDS['amex'])}".encode(), owner=ANA),
    )
    w.trash("my", "f1")
    after = scan(w, s, state=state)
    assert {f["resource"]["itemId"] for f in after["findings"]} == {"f2", "f6"}
    assert after["coverage"][0]["scanned"] == 1


def test_org_units_rate_limits_and_all_shared_drives(tmp_path: Path) -> None:
    w = workspace()
    w.org_units["/Sales"] = [ANA]
    w.rate_limit["/gmail/v1/users/me/messages"] = 2
    s = settings(
        tmp_path, GWS_ORG_UNITS="/Sales", GWS_SHARED_DRIVES="all", DISCOVER="gmail,shared_drive"
    )
    doc = scan(w, s)
    by = stores(doc)
    assert by[("gws_gmail", user_store(ANA))]["status"] == "scanned"
    assert {("gws_shared_drive", "Finance"), ("gws_shared_drive", "Legal")} <= set(by)
    assert any(f["resource"]["service"] == "gmail" for f in doc["findings"])
    w.fail["/admin/directory/v1/users"] = gerror(
        403, "PERMISSION_DENIED", f"{ADMIN} is not an admin"
    )
    bad = scan(w, s)
    assert bad["discovery"]["listErrors"] == {"gws_gmail": "PERMISSION_DENIED"}
