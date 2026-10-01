"""The SaaS scanner with Microsoft 365: settings, sign-in, mail, files, Teams, state, sinks.

Every Graph call goes to a stubbed session (saas_fakes.py); every value is made up.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from office_fixtures import OLE, docx, xlsx
from saas_fakes import (
    CLIENT,
    HOST,
    M365,
    NOW,
    TENANT,
    ChannelMsg,
    Item,
    Message,
    Resp,
    env,
    graph_error,
    settings,
)
from sensitive_data_core.findings import key_hash
from sensitive_data_core.push import verify
from sensitive_data_core.state import FileState
from sensitive_data_saas import __main__ as entry
from sensitive_data_saas.config import ConfigError, read_settings
from sensitive_data_saas.entra import Certificate, EntraApp
from sensitive_data_saas.federation import AwsToken, AzureToken, FileToken, GcpToken
from sensitive_data_saas.graph import Graph
from sensitive_data_saas.http import Http, SaasError, Throttled, retry_after
from sensitive_data_saas.resources import owner_hash, tenant_hash
from sensitive_data_saas.runner import run_scan
from sensitive_data_saas.sinks import FileSink, sinks_for
from synthetic import CARDS, SSN_A, dashed, printed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
DETECTOR = shared_detector()
ALICE = "alice@contoso.example"
BOB = "bob@contoso.example"
OUTSIDE = "ceo@contoso.example"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def scan(m: M365, s: Any, **kw: Any) -> dict[str, Any]:
    doc, failed = run_scan(s, m.clients(s), detector=DETECTOR, now=lambda: NOW, **kw)
    assert failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(x["kind"], x["name"]): x for x in doc["discovery"]["stores"]}


def mailbox_tenant() -> M365:
    m = M365()
    alice = m.user(ALICE, "u-alice", drive="d-alice")
    m.user(BOB, "u-bob")
    inbox = m.folder(alice.id)
    inbox.add(Message("m1", "Order", f"please charge my card {printed(CARDS['visa'])} today"))
    inbox.add(Message("m2", "hello", "nothing to see here"))
    inbox.add(
        Message(
            "m3",
            "HR",
            "see attached",
            attachments=[
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "id": "a1",
                    "name": "roster.csv",
                    "size": 40,
                    "data": f"name,ssn\nA,{dashed(SSN_A)}\n".encode(),
                },
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "id": "a2",
                    "name": "memo.docx",
                    "size": 900,
                    "data": docx([f"card {printed(CARDS['amex'])}"]),
                },
                {"@odata.type": "#microsoft.graph.itemAttachment", "id": "a3", "name": "fwd"},
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "id": "a4",
                    "name": "huge.csv",
                    "size": 10**9,
                    "data": b"",
                },
            ],
        )
    )
    inbox.add(Message("old", "old", f"{CARDS['jcb']}", received="2020-01-01T00:00:00Z"))
    return m


# ------------------------------------------------------------------ settings


def test_settings_need_one_credential_and_never_a_secret_in_the_environment(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "s"
    secret.write_text("made-up-client-secret-value")
    base = env(M365_CLIENT_SECRET_FILE=str(secret))
    s = read_settings(base)
    assert s.m365 is not None and s.m365.secret is not None
    assert "made-up" not in repr(s) and "made-up" not in repr(s.m365)
    assert s.discover == ("m365_mail", "m365_onedrive", "m365_sharepoint")
    for bad, code in (
        ({"M365_TENANT_ID": "contoso"}, "m365_tenant_id"),
        ({"M365_CLIENT_ID": "x"}, "m365_client_id"),
        ({"M365_FEDERATED_TOKEN": "aws"}, "m365_credential"),
        ({"M365_CLIENT_SECRET": "made-up"}, "m365_client_secret_in_env"),
        ({"M365_CLIENT_SECRET_FILE": "relative"}, "m365_client_secret_file"),
        ({"M365_USERS": "not an address"}, "m365_users"),
        ({"M365_GROUPS": "finance"}, "m365_groups"),
        ({"M365_SITES": "https://contoso.sharepoint.com/sites/x"}, "m365_sites"),
        ({"DISCOVER": "slack"}, "discover_vendor_not_configured"),
        ({"DISCOVER": "salesforce"}, "discover_kind"),
        ({"FINDINGS_HTTPS_URL": "http://collector.example/x"}, "findings_url_not_https"),
        ({"STATE_LOCATION": "relative/state.json"}, "state_location"),
        ({"STATE_LOCATION": "https://state.example/x"}, "state_hmac_key"),
    ):
        with pytest.raises(ConfigError) as err:
            read_settings({**base, **bad})
        assert err.value.code == code
    with pytest.raises(ConfigError) as err:
        read_settings({"SCANNER_SITE": "x", "FINDINGS_FILE": "/tmp/x"})  # noqa: S108
    assert err.value.code == "no_vendor"
    fed = read_settings(env(M365_FEDERATED_TOKEN="file:/var/run/secrets/token"))  # noqa: S106
    assert fed.m365 is not None and fed.m365.federated == "file:/var/run/secrets/token"
    teams = read_settings({**base, "DISCOVER": "all"})
    assert "m365_teams_chat" in teams.discover


SITE_ID = f"{HOST},11111111-2222-3333-4444-555555555555,66666666-7777-8888-9999-000000000000"


@pytest.mark.parametrize(
    ("raw", "sites"),
    [
        # #83: every form on its own.
        (f"{HOST}:/sites/finance", (f"{HOST}:/sites/finance",)),
        (SITE_ID, (SITE_ID,)),
        ("root", ("root",)),
        (f"{HOST}:/", (f"{HOST}:/",)),
        # Separators: whitespace, newlines, `;`, and commas outside an id.
        (f"{HOST}:/sites/a {HOST}:/sites/b", (f"{HOST}:/sites/a", f"{HOST}:/sites/b")),
        (f"{HOST}:/sites/a\n{HOST}:/sites/b\n", (f"{HOST}:/sites/a", f"{HOST}:/sites/b")),
        (f"{HOST}:/sites/a; {HOST}:/sites/b", (f"{HOST}:/sites/a", f"{HOST}:/sites/b")),
        (f"{HOST}:/sites/a,{HOST}:/sites/b", (f"{HOST}:/sites/a", f"{HOST}:/sites/b")),
        # Mixed lists, the id kept whole even among commas.
        (
            f"root;{SITE_ID}\n{HOST}:/ {HOST}:/sites/a",
            ("root", SITE_ID, f"{HOST}:/", f"{HOST}:/sites/a"),
        ),
        (
            f"{HOST}:/sites/a,{SITE_ID},root,{HOST}:/",
            (f"{HOST}:/sites/a", SITE_ID, "root", f"{HOST}:/"),
        ),
    ],
)
def test_m365_sites_every_form_and_separator(
    tmp_path: Path, raw: str, sites: tuple[str, ...]
) -> None:
    s = settings(tmp_path, M365_SITES=raw)
    assert s.m365 is not None and s.m365.sites == sites and not s.m365.all_sites


@pytest.mark.parametrize(
    "raw",
    [
        f"{HOST},11111111-2222-3333-4444-555555555555",  # an id missing its web guid
        f"{HOST}:/sites/a root extra",
        "Root",
        f"{HOST}:/ all",
        "contoso.example.com:/",
    ],
)
def test_m365_sites_refuses_what_is_not_a_site(tmp_path: Path, raw: str) -> None:
    with pytest.raises(ConfigError) as err:
        settings(tmp_path, M365_SITES=raw)
    assert err.value.code == "m365_sites"


# ------------------------------------------------------------------ sign-in


def _pem(tmp_path: Path) -> tuple[Path, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sds-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.UTC))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "app.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    return path, cert


def _b64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def test_a_certificate_signs_a_client_assertion(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    path, cert = _pem(tmp_path)
    m = M365()
    http = Http(m)
    app = EntraApp(http, TENANT, CLIENT, certificate=Certificate(str(path)), clock=lambda: 1000.0)
    assert app.token() == app.token()  # cached: one request
    assert len(m.token_forms) == 1
    form = m.token_forms[0]
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "https://graph.microsoft.com/.default"
    assert "client_secret" not in form
    head, claims, sig = form["client_assertion"].split(".")
    header = json.loads(_b64(head))
    body = json.loads(_b64(claims))
    assert header["alg"] == "PS256"
    import hashlib

    der = cert.public_bytes(serialization.Encoding.DER)
    assert _b64(header["x5t#S256"]) == hashlib.sha256(der).digest()
    assert body["iss"] == body["sub"] == CLIENT
    assert body["aud"] == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert body["exp"] - body["iat"] == 600
    cert.public_key().verify(
        _b64(sig),
        f"{head}.{claims}".encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    assert "PRIVATE" not in repr(app) and repr(Certificate(str(path))) == "Certificate(***)"
    with pytest.raises(SaasError) as err:
        Certificate(str(tmp_path / "missing.pem"))
    assert err.value.error_code == "CertificateUnreadable"


def test_a_federated_token_or_a_secret_file_and_errors_by_code(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("made-up.federated.jwt\n")
    m = M365()
    app = EntraApp(Http(m), TENANT, CLIENT, federated=FileToken(str(token_file)))
    app.token()
    assert m.token_forms[-1]["client_assertion"] == "made-up.federated.jwt"
    assert m.token_forms[-1]["client_assertion_type"].endswith("jwt-bearer")
    m.token_error = Resp(
        401, {"error": "invalid_client", "error_description": f"AADSTS7000215 {ALICE}"}
    )
    from sensitive_data_core.safety import Secret

    bad = EntraApp(Http(m), TENANT, CLIENT, secret=Secret("made-up-secret"))
    with pytest.raises(SaasError) as err:
        bad.token()
    assert err.value.error_code == "invalid_client"
    assert ALICE not in repr(err.value) and "made-up" not in repr(bad)
    with pytest.raises(SaasError):
        FileToken(str(tmp_path / "none")).token()


def test_workload_tokens_from_aws_gcp_and_azure() -> None:
    class Sts:
        def get_web_identity_token(self, **kw: Any) -> dict[str, Any]:
            assert kw == {
                "Audience": ["api://AzureADTokenExchange"],
                "SigningAlgorithm": "RS256",
                "DurationSeconds": 300,
            }
            return {"WebIdentityToken": "made-up-aws-jwt"}

    assert AwsToken("api://AzureADTokenExchange", Sts).token() == "made-up-aws-jwt"
    seen: list[tuple[str, dict[str, str]]] = []

    class Meta:
        def request(self, method: str, url: str, **kw: Any) -> Resp:
            seen.append((url, kw["headers"]))
            if "metadata.google.internal" in url:
                return Resp(200, content=b"made-up-gcp-jwt")
            return Resp(200, {"access_token": "made-up-azure-jwt"})

    http = Http(Meta())
    assert GcpToken("api://AzureADTokenExchange", http).token() == "made-up-gcp-jwt"
    assert seen[-1][1]["Metadata-Flavor"] == "Google"
    az = AzureToken("api://AzureADTokenExchange", http, env={})
    assert az.token() == "made-up-azure-jwt" and seen[-1][1]["Metadata"] == "true"
    aca = AzureToken(
        "api://AzureADTokenExchange",
        http,
        env={"IDENTITY_ENDPOINT": "http://localhost:42356/msi/token", "IDENTITY_HEADER": "h"},
    )
    aca.token()
    assert seen[-1][0].startswith("http://localhost:42356") and seen[-1][1]["X-IDENTITY-HEADER"]


def test_rate_limits_are_honored_and_a_long_wait_defers() -> None:
    slept: list[float] = []

    class Busy:
        def __init__(self, answers: list[Resp]) -> None:
            self.answers = answers

        def request(self, *a: Any, **kw: Any) -> Resp:
            return self.answers.pop(0)

    ok = Resp(200, {"value": []})
    http = Http(Busy([Resp(429, headers={"Retry-After": "7"}), ok]), sleep=slept.append)
    assert http.call("GET", "https://graph.microsoft.com/v1.0/x") is ok
    assert slept == [7.0] and http.throttled == 1
    long = Http(Busy([Resp(503, headers={"Retry-After": "900"})]), sleep=slept.append)
    with pytest.raises(Throttled):
        long.call("GET", "https://graph.microsoft.com/v1.0/x")
    near = Http(Busy([Resp(429, headers={"Retry-After": "30"})]), clock=lambda: 100.0)
    near.deadline = 110.0
    with pytest.raises(Throttled):
        near.call("GET", "https://graph.microsoft.com/v1.0/x")
    assert (
        retry_after(Resp(429, headers={"retry-after": "Wed, 30 Sep 2026 12:00:10 GMT"}), 0) or 0
    ) > 0
    assert retry_after(Resp(429), 0) is None


def test_the_token_goes_to_graph_only() -> None:
    m = M365()

    class App:
        def token(self) -> str:
            return "made-up-graph-token"

    g = Graph(Http(m), App())
    with pytest.raises(SaasError) as err:
        g.get("https://evil.example/v1.0/users")
    assert err.value.error_code == "NotGraph"


# ------------------------------------------------------------------ mail


def test_mail_is_read_only_when_the_grant_is_proved_scoped(tmp_path: Path) -> None:
    m = mailbox_tenant()
    s = settings(tmp_path, M365_USERS=f"{ALICE},{BOB}", DISCOVER="mail")
    doc = scan(m, s)
    by = stores(doc)
    alice = by[("m365_mail", f"user-{owner_hash(ALICE)[:16]}")]
    assert alice["reason"] == "scope_unverified" and doc["findings"] == []
    m.scope_check_readable = True
    s = settings(tmp_path, M365_USERS=ALICE, DISCOVER="mail", M365_MAIL_SCOPE_CHECK=OUTSIDE)
    doc = scan(m, s)
    reasons = {x["reason"] for x in doc["discovery"]["stores"] if x["name"] != "*"}
    assert reasons == {"unscoped_grant"}
    # The opt-in kinds left out are named, not silent.
    off = {x["kind"] for x in doc["discovery"]["stores"] if x["name"] == "*"}
    assert off == {"m365_teams_channel", "m365_teams_chat"}
    assert not any("/mailFolders" in c[1] for c in m.calls)


def test_mail_bodies_and_attachments(tmp_path: Path) -> None:
    m = mailbox_tenant()
    s = settings(
        tmp_path,
        M365_USERS=f"{ALICE},{BOB}",
        DISCOVER="mail",
        M365_MAIL_SCOPE_CHECK=OUTSIDE,
    )
    doc = scan(m, s)
    by = stores(doc)
    alice = by[("m365_mail", f"user-{owner_hash(ALICE)[:16]}")]
    assert alice["status"] == "scanned"
    assert alice["vendor"] == "m365" and alice["tenantHash"] == tenant_hash(TENANT)
    assert alice["ownerHash"] == owner_hash(ALICE)
    bob = by[("m365_mail", f"user-{owner_hash(BOB)[:16]}")]
    assert bob["reason"] == "not_provisioned"
    found = {
        (f["resource"]["part"], f["class"], f["resource"].get("name")) for f in doc["findings"]
    }
    assert ("message", "card", None) in found
    assert ("attachment", "us_ssn", "roster.csv") in found
    assert ("attachment", "card", "memo.docx") in found
    # The old message is outside the first run's window.
    assert all(f["resource"]["itemId"] != "old" for f in doc["findings"])
    cov = next(c for c in doc["coverage"] if c["kind"] == "m365_mail" and c["scanned"])
    assert cov["skipped"] == {"linked_item": 1, "too_large": 1}
    assert cov["formats"]["docx"] == 1
    body = next(f for f in doc["findings"] if f["resource"]["part"] == "message")
    assert body["resource"]["service"] == "exchange"
    assert body["link"].startswith("https://outlook.office365.com/owa/?ItemID=m1")
    assert body["atRestEncryption"] == "service_managed"
    blob = json.dumps(doc)
    assert ALICE not in blob and "alice" not in blob and CARDS["visa"] not in blob
    # Bodies were asked for as text, and every call was a GET to Graph with the token.
    prefer = [c[3].get("Prefer", "") for c in m.calls if "/messages/delta" in c[1]]
    assert prefer and all('outlook.body-content-type="text"' in p for p in prefer)


def test_mail_resumes_at_its_cap_then_reads_only_changes(tmp_path: Path) -> None:
    m = mailbox_tenant()
    m.per_page = 2
    state = FileState(str(tmp_path / "state.json"))
    s = settings(
        tmp_path,
        M365_USERS=ALICE,
        DISCOVER="mail",
        M365_MAIL_SCOPE_CHECK=OUTSIDE,
        MAIL_MAX_MESSAGES_PER_MAILBOX="1",
    )
    first = scan(m, s, state=state)
    cov = first["coverage"][0]
    assert cov["scanned"] == 1 and cov["backlog"] and not cov["passComplete"]
    second = scan(m, s, state=state)
    third = scan(m, s, state=state)
    assert third["coverage"][0]["passComplete"]
    ids = {f["resource"]["itemId"] for f in third["findings"]}
    assert {"m1", "m3/a1", "m3/a2"} <= ids
    assert second["coverage"][0]["scanned"] >= 1
    saved = json.loads((tmp_path / "state.json").read_text())
    assert ALICE not in json.dumps(saved) and "deltatoken" in json.dumps(saved)
    # Only what changed is read next: a new message, and a deleted one drops its findings.
    inbox = m.users["u-alice"].folders["inbox"]
    inbox.add(Message("m9", "new", f"ssn {dashed(SSN_A)}"))
    inbox.remove("m1")
    fourth = scan(m, s, state=state)
    ids = {f["resource"]["itemId"] for f in fourth["findings"]}
    assert "m9" in ids and "m1" not in ids and "m3/a1" in ids
    assert fourth["coverage"][0]["eligible"] == 1


# ------------------------------------------------------------------ files


def files_tenant() -> M365:
    m = M365()
    alice = m.user(ALICE, "u-alice", drive="d-alice")
    m.user(BOB, "u-bob")
    m.drives[alice.drive or ""].add(
        Item("f1", "notes.txt", f"my card is {printed(CARDS['visa'])}".encode())
    )
    m.site(f"{HOST}:/sites/finance", f"{HOST},s1,w1", "Finance", {"d-lib": "Documents"})
    lib = m.drives["d-lib"]
    lib.add(Item("x1", "roster.xlsx", xlsx([["name", "ssn"], ["A", dashed(SSN_A)]])))
    lib.add(Item("x2", "locked.docx", OLE))
    lib.add(Item("x3", "photo.png", b"\x89PNG\r\n\x1a\n made up"))
    lib.add(Item("dir", "folder", folder=True))
    lib.add(Item("x4", f"card-{CARDS['mir']}.txt", f"{CARDS['mir']}".encode(), unique_id="u-4"))
    return m


def test_onedrive_and_sharepoint_files(tmp_path: Path) -> None:
    m = files_tenant()
    s = settings(
        tmp_path,
        M365_USERS=f"{ALICE},{BOB}",
        M365_SITES=f"{HOST}:/sites/finance,{HOST}:/sites/legal",
        DISCOVER="onedrive,sharepoint",
    )
    doc = scan(m, s)
    by = stores(doc)
    assert by[("m365_onedrive", f"user-{owner_hash(ALICE)[:16]}")]["status"] == "scanned"
    assert by[("m365_onedrive", f"user-{owner_hash(BOB)[:16]}")]["reason"] == "not_provisioned"
    assert by[("m365_sharepoint", "Finance")]["status"] == "scanned"
    legal = by[("m365_sharepoint", "/sites/legal")]
    assert (legal["status"], legal["reason"], legal["error"]) == (
        "error",
        "access_denied",
        "accessDenied",
    )
    found = {
        (f["resource"]["service"], f["resource"].get("name"), f["class"]) for f in doc["findings"]
    }
    assert ("onedrive", "notes.txt", "card") in found
    assert ("sharepoint", "roster.xlsx", "us_ssn") in found
    lib = next(c for c in doc["coverage"] if c["kind"] == "m365_sharepoint")
    assert lib["skipped"] == {"encrypted": 1, "image": 1}
    xl = next(f for f in doc["findings"] if f["resource"].get("name") == "roster.xlsx")
    assert xl["resource"]["container"] == "Finance" and xl["resource"]["channel"] == "Documents"
    assert xl["link"] == (
        f"https://{HOST}/_layouts/15/Doc.aspx?"
        "sourcedoc=%7B11111111-2222-4333-8444-555555555555%7D&action=default"
    )
    masked = next(f for f in doc["findings"] if f["resource"]["itemId"] == "x4")
    assert masked["resource"]["name"] == "card-################.txt"
    assert masked["resource"]["keyMasked"] is True
    # Content was fetched in ranges, through Graph, never without the token.
    ranged = [c for c in m.calls if c[1].endswith("/content")]
    assert ranged and all("Range" in c[3] for c in ranged)


def test_root_site_forms_are_read_from_graph(tmp_path: Path) -> None:
    # #83: `root` is Graph's /sites/root and `host:/` is /sites/{host}:/.
    m = files_tenant()
    m.site("root", f"{HOST},r1,w1", "Root", {"d-lib": "Documents"})
    m.site(f"{HOST}:/", f"{HOST},r1,w1", "Root", {"d-lib": "Documents"})
    for ref in ("root", f"{HOST}:/"):
        doc = scan(
            m,
            settings(
                tmp_path,
                M365_SITES=ref,
                DISCOVER="sharepoint",
            ),
        )
        assert stores(doc)[("m365_sharepoint", "Root")]["status"] == "scanned"
        assert any(c[1].endswith(f"/v1.0/sites/{ref}") for c in m.calls)


def test_files_resume_and_drop_deleted_files(tmp_path: Path) -> None:
    m = files_tenant()
    m.per_page = 2
    state = FileState(str(tmp_path / "state.json"))
    s = settings(
        tmp_path,
        M365_SITES=f"{HOST}:/sites/finance",
        DISCOVER="sharepoint",
        FILES_MAX_PER_DRIVE="1",
    )
    runs = [scan(m, s, state=state) for _ in range(6)]
    assert runs[0]["coverage"][0]["backlog"]
    assert runs[-1]["coverage"][0]["passComplete"]
    assert {f["resource"]["itemId"] for f in runs[-1]["findings"]} == {"x1", "x4"}
    m.drives["d-lib"].remove("x1")
    after = scan(m, s, state=state)
    assert {f["resource"]["itemId"] for f in after["findings"]} == {"x4"}


def test_a_customer_key_is_named_by_its_hash(tmp_path: Path) -> None:
    m = files_tenant()
    s = settings(
        tmp_path,
        M365_USERS=ALICE,
        DISCOVER="onedrive",
        M365_CUSTOMER_KEY_ID="dep-contoso-2026",
    )
    doc = scan(m, s)
    f = doc["findings"][0]
    assert f["atRestEncryption"] == "customer_managed_key"
    assert f["atRestKeyHash"] == key_hash("dep-contoso-2026")
    assert f["pciNote"]["requirement"] == "3.5.1.2"
    assert "dep-contoso-2026" not in json.dumps(doc)


# ------------------------------------------------------------------ Teams


def teams_tenant() -> M365:
    m = M365()
    alice = m.user(ALICE, "u-alice")
    bob = m.user(BOB, "u-bob")
    m.teams["t1"] = "Support"
    m.channels["t1"] = {"19:c1@thread.tacv2": "General"}
    box = m.channel_msgs.setdefault("t1/19:c1@thread.tacv2", __import__("saas_fakes").Versioned())
    box.add(
        ChannelMsg(
            "1727000000001",
            f"<p>customer card <b>{printed(CARDS['visa'])}</b></p>",
            replies=[
                {
                    "id": "1727000000002",
                    "body": {"contentType": "html", "content": f"<div>ssn {dashed(SSN_A)}</div>"},
                    "lastModifiedDateTime": "2026-09-28T10:01:00.000Z",
                }
            ],
            attachments=[{"id": "f", "contentType": "reference"}],
        )
    )
    alice.chats = ["19:chat-ab"]
    bob.chats = ["19:chat-ab"]
    m.chats["19:chat-ab"] = [
        {
            "id": f"17270000000{i:02d}",
            "body": {
                "contentType": "text",
                "content": f"msg {i} " + (f"my card is {printed(CARDS['amex'])}" if i == 3 else ""),
            },
            "lastModifiedDateTime": f"2026-09-28T10:{i:02d}:00.000Z",
        }
        for i in range(1, 6)
    ]
    return m


def test_teams_is_opt_in_and_a_protected_api_is_a_gap(tmp_path: Path) -> None:
    m = teams_tenant()
    s = settings(tmp_path, M365_USERS=ALICE, M365_TEAMS="00000000-0000-4000-8000-000000000001")
    assert "m365_teams_channel" not in s.discover and "m365_teams_chat" not in s.discover
    m.teams["00000000-0000-4000-8000-000000000001"] = "Support"
    m.channels["00000000-0000-4000-8000-000000000001"] = {"19:c1@thread.tacv2": "General"}
    m.fail["/teams/00000000-0000-4000-8000-000000000001/channels/"] = graph_error(
        403, "Forbidden", "Invoked API requires Protected API access in application-only context"
    )
    m.fail["/chats/"] = graph_error(
        403, "Forbidden", "Invoked API requires Protected API access in application-only context"
    )
    s = settings(
        tmp_path,
        M365_USERS=ALICE,
        M365_TEAMS="00000000-0000-4000-8000-000000000001",
        DISCOVER="m365_teams_channel,m365_teams_chat",
    )
    m.users["u-alice"].chats = ["19:chat-ab"]
    doc = scan(m, s)
    assert {x["reason"] for x in doc["discovery"]["stores"]} == {"protected_api"}


def test_channel_messages_replies_and_chats(tmp_path: Path) -> None:
    m = teams_tenant()
    team = "00000000-0000-4000-8000-000000000001"
    m.teams[team] = m.teams.pop("t1")
    m.channels[team] = m.channels.pop("t1")
    m.channel_msgs[f"{team}/19:c1@thread.tacv2"] = m.channel_msgs.pop("t1/19:c1@thread.tacv2")
    state = FileState(str(tmp_path / "state.json"))
    s = settings(
        tmp_path,
        M365_USERS=f"{ALICE},{BOB}",
        M365_TEAMS=team,
        DISCOVER="m365_teams_channel,m365_teams_chat",
        MESSAGES_MAX_PER_CHANNEL="2",
    )
    doc = scan(m, s, state=state)
    chan = [f for f in doc["findings"] if f["resource"]["service"] == "teams_channel"]
    assert {(f["resource"]["part"], f["class"]) for f in chan} == {
        ("message", "card"),
        ("reply", "us_ssn"),
    }
    root = next(f for f in chan if f["resource"]["part"] == "message")
    # A 13-digit message id is masked; its hash keeps the finding apart.
    assert root["resource"]["itemId"] == "#############" and root["resource"]["keyMasked"]
    assert root["link"].startswith("https://teams.microsoft.com/l/channel/19%3Ac1%40thread.tacv2/")
    assert root["resource"]["container"] == "Support"
    cov = next(c for c in doc["coverage"] if c["kind"] == "m365_teams_channel")
    assert cov["skipped"] == {"linked_item": 1}
    # The chat both people share is read once a run, two messages at a time.
    chats = [c for c in doc["coverage"] if c["kind"] == "m365_teams_chat"]
    assert sum(c["scanned"] for c in chats) == 2
    for _ in range(3):
        doc = scan(m, s, state=state)
    chat = [f for f in doc["findings"] if f["resource"]["service"] == "teams_chat"]
    assert [f["class"] for f in chat] == ["card"]
    reads = [c for c in m.calls if c[1].endswith("/chats/19:chat-ab/messages")]
    assert reads


# ------------------------------------------------------------------ the run


def test_sinks_signed_push_and_the_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = "k" * 40
    s = settings(
        tmp_path,
        M365_USERS=ALICE,
        FINDINGS_HTTPS_URL="https://collector.example/sds?t=made-up",
        FINDINGS_HMAC_KEY=key,
        FINDINGS_FILE=str(tmp_path / "out.json"),
        DISCOVER="onedrive",
    )
    sinks = sinks_for(s)
    assert [type(x).__name__ for x in sinks] == ["HttpsSink", "FileSink"]
    sent: list[Any] = []

    class Ok:
        status = 200

        def __enter__(self) -> Ok:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    def opener(req: Any, timeout: int) -> Ok:
        sent.append(req)
        return Ok()

    sinks[0]._open = opener  # type: ignore[attr-defined]
    m = files_tenant()
    doc, failed = run_scan(s, m.clients(s), sinks=sinks, detector=DETECTOR, now=lambda: NOW)
    assert failed == 0 and sent
    req = sent[0]
    assert verify(
        key.encode(), req.get_header("X-sds-signature"), req.data, __import__("time").time()
    )
    assert json.loads((tmp_path / "out.json").read_text())["platform"] == "saas"
    assert FileSink(str(tmp_path / "o.json")).push(doc) == 1
    # The entry point: a wrong setting by its code, and nothing else printed.
    monkeypatch.setenv("SCANNER_SITE", "x")
    monkeypatch.setenv("M365_TENANT_ID", "made-up-tenant")
    capsys.readouterr()
    assert entry.main(["scan"]) == 1
    out = capsys.readouterr().out
    assert '"error":"m365_tenant_id"' in out and "made-up" not in out
    assert entry.main(["nope"]) == 1
    secret = tmp_path / "sec"
    secret.write_text("made-up-client-secret-value")
    for k, v in env(M365_CLIENT_SECRET_FILE=str(secret), M365_USERS=ALICE).items():
        monkeypatch.setenv(k, v)
    m2 = files_tenant()
    clients = m2.clients(read_settings())
    assert entry.main(["check"], clients) == 0
    assert not any(c[1].endswith("/content") for c in m2.calls)
    m3 = files_tenant()
    m3.token_error = Resp(401, {"error": "invalid_client"})
    assert entry.main(["check"], m3.clients(read_settings())) == 2
    assert '"error":"invalid_client"' in capsys.readouterr().out


def test_a_group_expands_to_its_members_and_throttling_defers(tmp_path: Path) -> None:
    m = files_tenant()
    m.groups["9d1f0000-0000-4000-8000-00000000000a"] = [ALICE, BOB]
    s = settings(
        tmp_path,
        M365_GROUPS="9d1f0000-0000-4000-8000-00000000000a,9d1f0000-0000-4000-8000-00000000000b",
        DISCOVER="onedrive",
        MAX_THROTTLE_WAIT_SECONDS="5",
    )
    m.retry_after = "60"
    m.throttle["/drives/d-alice/"] = 1
    doc = scan(m, s)
    by = stores(doc)
    assert by[("m365_onedrive", f"user-{owner_hash(ALICE)[:16]}")]["reason"] == "throttled"
    missing = by[
        ("m365_onedrive", f"user-{owner_hash('9d1f0000-0000-4000-8000-00000000000b')[:16]}")
    ]
    assert missing["reason"] == "not_provisioned"
    again = scan(m, s)
    assert stores(again)[("m365_onedrive", f"user-{owner_hash(ALICE)[:16]}")]["status"] == "scanned"
