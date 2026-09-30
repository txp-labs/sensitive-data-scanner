"""A stubbed Google Workspace for the SaaS scanner's tests. Every value is made up.

One HTTPS session answers what the scanner calls: Google's token endpoint
(domain-wide delegation: the JWT's `sub` and `scope` are checked against what
the Admin console delegated), IAM Credentials' `signJwt`, the metadata server,
Google's STS, the Directory API, Gmail and Drive. **It has no method that
writes**: any request that is not a GET to a Google API (or one of the token
POSTs) fails the test.

- Gmail keeps a history counter: each added or deleted message is one history
  record, and `users.history.list` returns those after `startHistoryId`.
- Drive keeps a change counter per drive: `changes.list` returns the files
  changed after the page token.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from saas_fakes import Resp
from sensitive_data_saas.clients import Clients
from sensitive_data_saas.config import Settings, read_settings
from sensitive_data_saas.scopes import GWS_ALERTS, GWS_DIRECTORY, GWS_DRIVE, GWS_GMAIL

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
CUSTOMER = "C01abc234"
SA = "sds-reader@acme-sec.iam.gserviceaccount.com"
ADMIN = "admin@acme.example"
PROVIDER = "projects/123456/locations/global/workloadIdentityPools/sds-pool/providers/sds-aws"


def gerror(status: int, code: str, message: str = "", reason: str | None = None) -> Resp:
    err: dict[str, Any] = {"code": status, "message": message or f"failed {status}", "status": code}
    if reason:
        err["errors"] = [{"reason": reason, "message": message}]
    return Resp(status, {"error": err})


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class GMsg:
    id: str
    subject: str = ""
    text: str = ""
    html: str = ""
    attachments: list[tuple[str, bytes]] = field(default_factory=list)
    days_old: int = 3


@dataclass
class DFile:
    id: str
    name: str
    mime: str = "text/plain"
    data: bytes = b""
    owner: str = ""
    trashed: bool = False
    v: int = 0


@dataclass
class GUser:
    email: str
    gmail: bool = True
    messages: dict[str, GMsg] = field(default_factory=dict)
    history: list[tuple[int, str, str]] = field(default_factory=list)
    suspended: bool = False


class Workspace:
    """The session: Google's token endpoints and APIs, read-only."""

    def __init__(self) -> None:
        self.users: dict[str, GUser] = {}
        self.groups: dict[str, list[str]] = {}
        self.org_units: dict[str, list[str]] = {}
        self.delegated: set[str] = {*GWS_DIRECTORY, *GWS_GMAIL, *GWS_DRIVE, *GWS_ALERTS}
        # #55: the Alert Center's DLP alerts.
        self.alerts: list[dict[str, Any]] = []
        self.history_id = 1000
        self.drives: dict[str, list[DFile]] = {"my": []}
        self.drive_names: dict[str, str] = {}
        self.drive_members: dict[str, set[str]] = {}
        self.change = 1
        self.per_page = 50
        self.history_floor = 0
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.token_posts: list[dict[str, Any]] = []
        self.fail: dict[str, Resp] = {}
        self.rate_limit: dict[str, int] = {}

    def __repr__(self) -> str:
        return "Workspace()"

    # -------------------------------------------------------------- setup

    def user(self, email: str, *, gmail: bool = True) -> GUser:
        u = GUser(email, gmail)
        self.users[email] = u
        return u

    def mail(self, email: str, msg: GMsg) -> None:
        self.history_id += 1
        self.users[email].messages[msg.id] = msg
        self.users[email].history.append((self.history_id, "add", msg.id))

    def unmail(self, email: str, mid: str) -> None:
        self.history_id += 1
        del self.users[email].messages[mid]
        self.users[email].history.append((self.history_id, "del", mid))

    def file(self, drive: str, f: DFile) -> None:
        self.change += 1
        f.v = self.change
        files = self.drives.setdefault(drive, [])
        self.drives[drive] = [x for x in files if x.id != f.id] + [f]

    def trash(self, drive: str, fid: str) -> None:
        self.change += 1
        for f in self.drives[drive]:
            if f.id == fid:
                f.trashed = True
                f.v = self.change

    def clients(self, settings: Settings) -> Clients:
        return Clients(settings, session=self, sleep=lambda s: None, wall=lambda: 1_790_000_000.0)

    # -------------------------------------------------------------- the session

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        timeout: float = 0,
        allow_redirects: bool = True,
    ) -> Resp:
        headers = headers or {}
        self.calls.append((method, url, params, headers))
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        query: dict[str, Any] = dict(urllib.parse.parse_qsl(parts.query))
        if isinstance(params, dict):
            query.update(params)
        if host == "oauth2.googleapis.com":
            return self._token(method, data)
        if host == "iamcredentials.googleapis.com":
            assert method == "POST" and parts.path.endswith(f"{SA}:signJwt")
            assert headers.get("Authorization", "").startswith("Bearer made-up-")
            claims = json_loads(json["payload"])
            head = b64u(b'{"alg":"RS256"}')
            return Resp(200, {"signedJwt": f"{head}.{b64u(dumps(claims))}.made-up-signature"})
        if host == "metadata.google.internal":
            assert headers.get("Metadata-Flavor") == "Google"
            return Resp(200, {"access_token": "made-up-metadata-token", "expires_in": 3599})
        if host == "sts.googleapis.com":
            assert method == "POST" and data["audience"] == f"//iam.googleapis.com/{PROVIDER}"
            self.token_posts.append(dict(data))
            return Resp(200, {"access_token": "made-up-federated-token", "expires_in": 3599})
        assert method == "GET", "the scanner never writes"
        auth = headers.get("Authorization", "")
        m = re.fullmatch(r"Bearer made-up-tok:([^:]+):(.+)", auth)
        if not m:
            return gerror(401, "UNAUTHENTICATED")
        who, scope = m[1], set(m[2].split(" "))
        path = parts.path
        for prefix, n in list(self.rate_limit.items()):
            if path.startswith(prefix) and n > 0:
                self.rate_limit[prefix] = n - 1
                return gerror(403, "PERMISSION_DENIED", "slow down", reason="userRateLimitExceeded")
        for prefix, resp in self.fail.items():
            if path.startswith(prefix):
                return resp
        if host == "alertcenter.googleapis.com":
            assert scope == set(GWS_ALERTS) and who == ADMIN
            assert path == "/v1beta1/alerts" and 'type="DlpRuleViolation"' in query["filter"]
            floor = re.search(r'createTime >= "([^"]+)"', query["filter"])
            rows = [a for a in self.alerts if not floor or a["createTime"] >= floor[1]]
            return self._page("alerts", rows, query)
        if host == "admin.googleapis.com":
            assert scope <= set(GWS_DIRECTORY) and who == ADMIN
            return self._directory(path, query)
        if host == "gmail.googleapis.com":
            assert scope == set(GWS_GMAIL)
            return self._gmail(who, path, query)
        if host == "www.googleapis.com":
            assert scope == set(GWS_DRIVE)
            return self._drive(who, path, query, headers)
        raise AssertionError(f"unexpected call {url}")

    def _token(self, method: str, data: Any) -> Resp:
        assert (
            method == "POST" and data["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        )
        claims = json_loads(b64d(data["assertion"].split(".")[1]))
        self.token_posts.append(claims)
        scopes = set(str(claims["scope"]).split(" "))
        if claims["iss"] != SA or not scopes <= self.delegated:
            return Resp(
                401, {"error": "unauthorized_client", "error_description": f"{claims['sub']} no"}
            )
        sub = claims["sub"]
        if sub != ADMIN and sub not in self.users:
            return Resp(400, {"error": "invalid_grant", "error_description": f"{sub} unknown"})
        return Resp(
            200, {"access_token": f"made-up-tok:{sub}:{claims['scope']}", "expires_in": 3599}
        )

    def _page(
        self, key: str, items: list[Any], query: dict[str, Any], extra: dict[str, Any] | None = None
    ) -> Resp:
        start = int(query.get("pageToken") or 0)
        body: dict[str, Any] = {key: items[start : start + self.per_page], **(extra or {})}
        if start + self.per_page < len(items):
            body["nextPageToken"] = str(start + self.per_page)
        return Resp(200, body)

    def _directory(self, path: str, query: dict[str, Any]) -> Resp:
        base = "/admin/directory/v1"
        m = re.fullmatch(rf"{base}/users/([^/]+)", path)
        if m:
            u = self.users.get(urllib.parse.unquote(m[1]))
            if u is None:
                return gerror(404, "NOT_FOUND", f"Resource Not Found: {m[1]}")
            return Resp(200, {"primaryEmail": u.email, "suspended": u.suspended})
        if path == f"{base}/users":
            q = str(query.get("query") or "")
            ou = re.fullmatch(r"orgUnitPath='(.+)'", q)
            emails = self.org_units.get(ou[1], []) if ou else list(self.users)
            rows = [{"primaryEmail": e, "suspended": self.users[e].suspended} for e in emails]
            return self._page("users", rows, query)
        m = re.fullmatch(rf"{base}/groups/([^/]+)/members", path)
        if m:
            g = urllib.parse.unquote(m[1])
            if g not in self.groups:
                return gerror(404, "NOT_FOUND", f"group {g}")
            rows = [{"type": "USER", "email": e, "status": "ACTIVE"} for e in self.groups[g]]
            return self._page("members", rows, query)
        raise AssertionError(path)

    def _gmail(self, who: str, path: str, query: dict[str, Any]) -> Resp:
        u = self.users[who]
        if not u.gmail:
            return gerror(400, "FAILED_PRECONDITION", f"Mail service not enabled for {who}")
        base = "/gmail/v1/users/me"
        if path == f"{base}/profile":
            return Resp(200, {"emailAddress": who, "historyId": str(self.history_id)})
        if path == f"{base}/messages":
            days = int(re.fullmatch(r"newer_than:(\d+)d", str(query["q"]))[1])  # type: ignore[index]
            ids = [
                {"id": x.id}
                for x in sorted(u.messages.values(), key=lambda x: x.id)
                if x.days_old <= days
            ]
            return self._page("messages", ids, query)
        m = re.fullmatch(rf"{base}/messages/([^/]+)", path)
        if m:
            msg = u.messages.get(m[1])
            if msg is None:
                return gerror(404, "NOT_FOUND")
            parts: list[dict[str, Any]] = []
            if msg.text:
                parts.append({"mimeType": "text/plain", "body": {"data": b64u(msg.text.encode())}})
            if msg.html:
                parts.append({"mimeType": "text/html", "body": {"data": b64u(msg.html.encode())}})
            for i, (name, data) in enumerate(msg.attachments):
                parts.append(
                    {
                        "partId": str(i + 2),
                        "filename": name,
                        "mimeType": "application/octet-stream",
                        "body": {"attachmentId": f"att-{i}", "size": len(data)},
                    }
                )
            return Resp(
                200,
                {
                    "id": msg.id,
                    "payload": {
                        "mimeType": "multipart/mixed",
                        "headers": [{"name": "Subject", "value": msg.subject}],
                        "parts": parts,
                    },
                },
            )
        m = re.fullmatch(rf"{base}/messages/([^/]+)/attachments/att-(\d+)", path)
        if m:
            name, data = u.messages[m[1]].attachments[int(m[2])]
            return Resp(200, {"size": len(data), "data": b64u(data)})
        if path == f"{base}/history":
            start = int(query["startHistoryId"])
            if start < self.history_floor:
                return gerror(404, "NOT_FOUND", "history too old")
            rows = []
            for hid, what, mid in u.history:
                if hid > start:
                    key = "messagesAdded" if what == "add" else "messagesDeleted"
                    rows.append({"id": str(hid), key: [{"message": {"id": mid}}]})
            return self._page("history", rows, query, {"historyId": str(self.history_id)})
        raise AssertionError(path)

    def _visible(self, who: str, drive: str) -> bool:
        return who in self.drive_members.get(drive, set())

    def _drive(self, who: str, path: str, query: dict[str, Any], headers: dict[str, str]) -> Resp:
        base = "/drive/v3"
        drive = str(query.get("driveId") or "")
        if path == f"{base}/drives":
            assert query.get("useDomainAdminAccess") == "true"
            listed = [{"id": d, "name": n} for d, n in self.drive_names.items()]
            return self._page("drives", listed, query)
        m = re.fullmatch(rf"{base}/drives/([^/]+)", path)
        if m:
            if m[1] not in self.drive_names:
                return gerror(404, "NOT_FOUND", f"Shared drive not found: {m[1]}")
            return Resp(200, {"id": m[1], "name": self.drive_names[m[1]]})
        if drive and not self._visible(who, drive):
            return gerror(404, "NOT_FOUND", f"Shared drive not found: {drive}")
        if path == f"{base}/changes/startPageToken":
            return Resp(200, {"startPageToken": str(self.change)})
        files = self.drives.get(drive or "my", [])
        if not drive:
            files = [f for f in files if f.owner == who]

        def shape(f: DFile) -> dict[str, Any]:
            return {
                "id": f.id,
                "name": f.name,
                "mimeType": f.mime,
                "size": str(len(f.data)),
                "trashed": f.trashed,
                "ownedByMe": f.owner == who or bool(drive),
            }

        if path == f"{base}/files":
            rows = [shape(f) for f in files if not f.trashed]
            return self._page("files", rows, query)
        if path == f"{base}/changes":
            since = int(query["pageToken"]) if str(query.get("pageToken", "")).isdigit() else 0
            changed = sorted((f for f in files if f.v > since), key=lambda f: f.v)
            changed_rows: list[dict[str, Any]] = [
                {"fileId": f.id, "removed": False, "file": shape(f)}
                for f in changed[: self.per_page]
            ]
            body: dict[str, Any] = {"changes": changed_rows}
            if len(changed) > self.per_page:
                body["nextPageToken"] = str(changed[self.per_page - 1].v)
            else:
                body["newStartPageToken"] = str(self.change)
            return Resp(200, body)
        m = re.fullmatch(rf"{base}/files/([^/]+)(/export)?", path)
        if m:
            everything = [f for d in self.drives.values() for f in d]
            f = next(x for x in everything if x.id == m[1])
            if m[2]:
                return Resp(200, content=f.data)
            assert query.get("alt") == "media"
            rng = re.fullmatch(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
            if rng:
                return Resp(206, content=f.data[int(rng[1]) : int(rng[2]) + 1])
            return Resp(200, content=f.data)
        raise AssertionError(path)


def dumps(v: Any) -> bytes:
    return json.dumps(v).encode()


def json_loads(v: str | bytes) -> Any:
    return json.loads(v)


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def settings(tmp_path: Any, **extra: str) -> Settings:
    """A Google Workspace configuration signing with a key file (tests write it)."""
    e = {
        "SCANNER_SITE": "acme-gws",
        "GWS_CUSTOMER_ID": CUSTOMER,
        "GWS_SERVICE_ACCOUNT": SA,
        "GWS_ADMIN_USER": ADMIN,
        "FINDINGS_FILE": str(tmp_path / "findings.json"),
    }
    e.update(extra)
    if "GWS_CREDENTIAL" not in e:
        e.setdefault("GWS_KEY_FILE", str(key_file(tmp_path)))
    return read_settings(e)


def key_file(tmp_path: Any) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = tmp_path / "sa-key.json"
    if not path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        path.write_text(
            json.dumps({"type": "service_account", "client_email": SA, "private_key": pem})
        )
    return path
