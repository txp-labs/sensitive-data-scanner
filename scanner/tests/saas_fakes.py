"""A stubbed Microsoft 365 for the SaaS scanner's tests. Every value is made up.

The scanner calls Entra's token endpoint and Microsoft Graph through one HTTPS
session; `M365` is that session. It answers the calls the scanner makes, and
nothing more, and **it has no method that writes**: any request that is not a
GET to Graph (or the token POST) fails the test.

- Delta queries: each mailbox folder, drive and channel keeps a version
  counter; a page holds `per_page` items and links to the next with a
  `$skiptoken`, and the last page's delta link carries the version, so the next
  query returns only what changed since (deletions as `@removed`).
- `throttle[path_prefix] = n` answers the first n calls there with 429 and a
  `Retry-After`; `fail[path_prefix]` answers with an error.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_saas.clients import Clients
from sensitive_data_saas.config import Settings, read_settings

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
TENANT = "0f0e0d0c-0b0a-4909-8807-060504030201"
CLIENT = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
TOKEN = "made-up-graph-token"  # noqa: S105 - a made-up access token
GRAPH = "https://graph.microsoft.com/v1.0"
HOST = "contoso.sharepoint.com"


class Resp:
    def __init__(
        self,
        status: int = 200,
        body: Any = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status
        if content is not None:
            self.content = content
        elif body is None:
            self.content = b""
        else:
            self.content = json.dumps(body).encode()
        self.headers = headers or {}

    @property
    def text(self) -> str:
        return self.content.decode()

    def json(self) -> Any:
        return json.loads(self.content)


def graph_error(status: int, code: str, message: str = "") -> Resp:
    return Resp(status, {"error": {"code": code, "message": message or f"failed {status}"}})


@dataclass
class Message:
    id: str
    subject: str = ""
    body: str = ""
    received: str = "2026-09-20T10:00:00Z"
    attachments: list[dict[str, Any]] = field(default_factory=list)
    v: int = 1
    removed: bool = False


@dataclass
class Item:
    id: str
    name: str
    data: bytes = b""
    v: int = 1
    removed: bool = False
    folder: bool = False
    unique_id: str = "11111111-2222-4333-8444-555555555555"
    sha1: bool = False  # the listing gives the file's SHA-1 (#67 part 5)


@dataclass
class ChannelMsg:
    id: str
    html: str = ""
    modified: str = "2026-09-28T10:00:00.000Z"
    replies: list[dict[str, Any]] = field(default_factory=list)
    v: int = 1
    removed: bool = False
    attachments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Versioned:
    """Items with versions, for delta queries."""

    items: list[Any] = field(default_factory=list)
    version: int = 1

    def add(self, item: Any) -> None:
        self.version += 1
        item.v = self.version
        self.items = [i for i in self.items if i.id != item.id] + [item]

    def remove(self, item_id: str) -> None:
        self.version += 1
        for i in self.items:
            if i.id == item_id:
                i.removed = True
                i.v = self.version


@dataclass
class User:
    id: str
    upn: str
    folders: dict[str, Versioned] = field(default_factory=dict)
    drive: str | None = None
    chats: list[str] = field(default_factory=list)


class M365:
    """The session: Entra's token endpoint and Microsoft Graph, read-only."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.groups: dict[str, list[str]] = {}
        self.scope_check_readable = False
        self.drives: dict[str, Versioned] = {}
        self.drive_names: dict[str, str] = {}
        self.sites: dict[str, tuple[str, str]] = {}
        self.site_drives: dict[str, list[str]] = {}
        self.teams: dict[str, str] = {}
        self.channels: dict[str, dict[str, str]] = {}
        self.channel_msgs: dict[str, Versioned] = {}
        self.chats: dict[str, list[dict[str, Any]]] = {}
        self.per_page = 50
        self.fail: dict[str, Resp] = {}
        self.throttle: dict[str, int] = {}
        self.retry_after = "1"
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.token_forms: list[dict[str, str]] = []
        self.token_error: Resp | None = None
        # #55: Purview DLP's alerts, as Graph's security API returns them.
        self.alerts: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return "M365()"

    # -------------------------------------------------------------- setup helpers

    def user(self, upn: str, uid: str, *, drive: str | None = None) -> User:
        u = User(uid, upn, drive=drive)
        self.users[uid] = u
        if drive is not None:
            self.drives.setdefault(drive, Versioned())
            self.drive_names.setdefault(drive, "OneDrive")
        return u

    def folder(self, uid: str, fid: str = "inbox") -> Versioned:
        return self.users[uid].folders.setdefault(fid, Versioned())

    def site(self, ref: str, site_id: str, name: str, drives: dict[str, str]) -> None:
        self.sites[ref] = (site_id, name)
        self.site_drives[site_id] = list(drives)
        for did, dname in drives.items():
            self.drives.setdefault(did, Versioned())
            self.drive_names[did] = dname

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
        query = dict(urllib.parse.parse_qsl(parts.query))
        if isinstance(params, dict):
            query.update({k: str(v) for k, v in params.items()})
        if parts.hostname == "login.microsoftonline.com":
            assert method == "POST" and parts.path == f"/{TENANT}/oauth2/v2.0/token"
            self.token_forms.append(dict(data))
            if self.token_error is not None:
                return self.token_error
            return Resp(200, {"access_token": TOKEN, "expires_in": 3599, "token_type": "Bearer"})
        assert parts.hostname == "graph.microsoft.com", "only Graph is called"
        assert method == "GET", "the scanner never writes"
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return graph_error(401, "InvalidAuthenticationToken")
        path = parts.path.removeprefix("/v1.0")
        for prefix, left in list(self.throttle.items()):
            if path.startswith(prefix) and left > 0:
                self.throttle[prefix] = left - 1
                return Resp(
                    429,
                    {"error": {"code": "TooManyRequests"}},
                    headers={"Retry-After": self.retry_after},
                )
        for prefix, resp in self.fail.items():
            if path.startswith(prefix):
                return resp
        return self._route(path, query, headers)

    def _page(
        self, items: list[dict[str, Any]], base: str, query: dict[str, str], version: int | None
    ) -> Resp:
        start = int(query.get("$skiptoken") or 0)
        chunk = items[start : start + self.per_page]
        body: dict[str, Any] = {"value": chunk}
        rest = {k: v for k, v in query.items() if k not in ("$skiptoken", "$deltatoken")}
        if start + self.per_page < len(items):
            q = urllib.parse.urlencode({**rest, "$skiptoken": str(start + self.per_page)})
            body["@odata.nextLink"] = f"{GRAPH}{base}?{q}"
        elif version is not None:
            q = urllib.parse.urlencode({"$deltatoken": str(version)})
            body["@odata.deltaLink"] = f"{GRAPH}{base}?{q}"
        return Resp(200, body)

    def _delta(self, box: Versioned, base: str, query: dict[str, str], shape: Any) -> Resp:
        since = int(query.get("$deltatoken") or 0)
        items = []
        for i in sorted(box.items, key=lambda x: x.id):
            if i.v <= since:
                continue
            if i.removed:
                if since:
                    items.append({"id": i.id, "@removed": {"reason": "deleted"}})
                continue
            got = shape(i)
            if got is not None:
                items.append(got)
        return self._page(items, base, query, box.version)

    def _route(self, path: str, query: dict[str, str], headers: dict[str, str]) -> Resp:
        if path == "/security/alerts_v2":
            flt = query.get("$filter", "")
            assert "serviceSource eq 'microsoftDataLossPrevention'" in flt
            since_alert = re.search(r"lastUpdateDateTime ge (\S+)", flt)
            rows = [
                a
                for a in self.alerts
                if not since_alert or a["lastUpdateDateTime"] >= since_alert[1]
            ]
            return self._page(rows, path, query, None)
        m = re.fullmatch(r"/users/([^/]+)", path)
        if m:
            key = urllib.parse.unquote(m[1])
            for u in self.users.values():
                if key in (u.id, u.upn):
                    return Resp(200, {"id": u.id, "userPrincipalName": u.upn})
            return graph_error(404, "Request_ResourceNotFound", f"user {key} not found")
        m = re.fullmatch(r"/groups/([^/]+)/transitiveMembers/microsoft\.graph\.user", path)
        if m:
            if m[1] not in self.groups:
                return graph_error(404, "Request_ResourceNotFound")
            members = [
                {"id": u.id, "userPrincipalName": u.upn}
                for u in self.users.values()
                if u.upn in self.groups[m[1]]
            ]
            return self._page(members, path, query, None)
        m = re.fullmatch(r"/users/([^/]+)/messages", path)
        if m:
            if self.scope_check_readable:
                return Resp(200, {"value": [{"id": "outside-1"}]})
            return graph_error(403, "ErrorAccessDenied", "Access is denied. Check credentials.")
        m = re.fullmatch(r"/users/([^/]+)/mailFolders/delta", path)
        if m:
            box_user = self.users.get(m[1])
            if box_user is None or not box_user.folders:
                return graph_error(404, "MailboxNotEnabledForRESTAPI", "no mailbox")
            return self._page([{"id": f} for f in sorted(box_user.folders)], path, query, 1)
        m = re.fullmatch(r"/users/([^/]+)/mailFolders/([^/]+)/messages/delta", path)
        if m:
            box = self.users[m[1]].folders[m[2]]
            since = query.get("$filter", "")
            floor = since.removeprefix("receivedDateTime ge ") if since else ""

            def shape(msg: Message) -> dict[str, Any] | None:
                if floor and msg.received < floor:
                    return None
                return {
                    "id": msg.id,
                    "subject": msg.subject,
                    "body": {"contentType": "text", "content": msg.body},
                    "hasAttachments": bool(msg.attachments),
                    "receivedDateTime": msg.received,
                }

            return self._delta(box, path, query, shape)
        m = re.fullmatch(r"/users/([^/]+)/messages/([^/]+)/attachments(?:/([^/]+)/\$value)?", path)
        if m:
            msg = next(
                x for f in self.users[m[1]].folders.values() for x in f.items if x.id == m[2]
            )
            if m[3] is None:
                meta = [{k: v for k, v in a.items() if k != "data"} for a in msg.attachments]
                return self._page(meta, path, query, None)
            att = next(a for a in msg.attachments if a["id"] == m[3])
            return Resp(200, content=att["data"])
        m = re.fullmatch(r"/users/([^/]+)/drive", path)
        if m:
            u = self.users[m[1]]
            if u.drive is None:
                return graph_error(404, "ResourceNotFound", "no drive for this user")
            return Resp(
                200,
                {"id": u.drive, "webUrl": f"https://contoso-my.sharepoint.com/personal/{u.upn}"},
            )
        m = re.fullmatch(r"/sites/(.+)", path)
        if m and "/drives" not in path:
            ref = urllib.parse.unquote(m[1])
            if ref not in self.sites:
                return graph_error(403, "accessDenied", f"site {ref} is not granted")
            sid, name = self.sites[ref]
            return Resp(200, {"id": sid, "displayName": name})
        m = re.fullmatch(r"/sites/([^/]+)/drives", path)
        if m:
            drives = [
                {
                    "id": d,
                    "name": self.drive_names[d],
                    "webUrl": f"https://{HOST}/sites/x/{self.drive_names[d]}",
                    "driveType": "documentLibrary",
                }
                for d in self.site_drives.get(urllib.parse.unquote(m[1]), [])
            ]
            return self._page(drives, path, query, None)
        m = re.fullmatch(r"/drives/([^/]+)/root/delta", path)
        if m:

            def item_shape(i: Item) -> dict[str, Any]:
                out: dict[str, Any] = {
                    "id": i.id,
                    "name": i.name,
                    "size": len(i.data),
                    "sharepointIds": {"listItemUniqueId": i.unique_id},
                }
                out["folder" if i.folder else "file"] = {}
                if i.sha1 and not i.folder:
                    digest = hashlib.sha1(i.data, usedforsecurity=False).hexdigest()
                    out["file"] = {"hashes": {"sha1Hash": digest.upper()}}
                return out

            return self._delta(self.drives[m[1]], path, query, item_shape)
        m = re.fullmatch(r"/drives/([^/]+)/items/([^/]+)/content", path)
        if m:
            item = next(i for i in self.drives[m[1]].items if i.id == m[2])
            rng = re.fullmatch(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
            if rng:
                return Resp(206, content=item.data[int(rng[1]) : int(rng[2]) + 1])
            return Resp(200, content=item.data)
        m = re.fullmatch(r"/teams/([^/]+)", path)
        if m:
            if m[1] not in self.teams:
                return graph_error(404, "NotFound")
            return Resp(200, {"id": m[1], "displayName": self.teams[m[1]]})
        m = re.fullmatch(r"/teams/([^/]+)/channels", path)
        if m:
            chans = [{"id": c, "displayName": n} for c, n in self.channels.get(m[1], {}).items()]
            return self._page(chans, path, query, None)
        m = re.fullmatch(r"/teams/([^/]+)/channels/([^/]+)/messages/delta", path)
        if m:

            def msg_shape(x: ChannelMsg) -> dict[str, Any]:
                return {
                    "id": x.id,
                    "body": {"contentType": "html", "content": x.html},
                    "lastModifiedDateTime": x.modified,
                    "attachments": x.attachments,
                }

            return self._delta(self.channel_msgs[f"{m[1]}/{m[2]}"], path, query, msg_shape)
        m = re.fullmatch(r"/teams/([^/]+)/channels/([^/]+)/messages/([^/]+)/replies", path)
        if m:
            root = next(x for x in self.channel_msgs[f"{m[1]}/{m[2]}"].items if x.id == m[3])
            return self._page(root.replies, path, query, None)
        m = re.fullmatch(r"/users/([^/]+)/chats", path)
        if m:
            return self._page([{"id": c} for c in self.users[m[1]].chats], path, query, None)
        m = re.fullmatch(r"/chats/([^/]+)/messages", path)
        if m:
            msgs = sorted(
                self.chats.get(m[1], []), key=lambda x: x["lastModifiedDateTime"], reverse=True
            )
            flt = query.get("$filter", "")
            gt = re.search(r"gt (\S+)", flt)
            lt = re.search(r"lt (\S+)", flt)
            if gt:
                msgs = [x for x in msgs if x["lastModifiedDateTime"] > gt[1]]
            if lt:
                msgs = [x for x in msgs if x["lastModifiedDateTime"] < lt[1]]
            return self._page(msgs, path, query, None)
        raise AssertionError(f"unexpected Graph call {path}")


def env(**extra: str) -> dict[str, str]:
    """A Microsoft 365 configuration with a client secret file (tests write it)."""
    base = {
        "SCANNER_SITE": "acme-m365",
        "M365_TENANT_ID": TENANT,
        "M365_CLIENT_ID": CLIENT,
        "FINDINGS_FILE": "/tmp/sds-saas-findings.json",  # noqa: S108 - a made-up path
    }
    base.update(extra)
    return base


def settings(tmp_path: Any, **extra: str) -> Settings:
    secret = tmp_path / "client-secret"
    secret.write_text("made-up-client-secret-value")
    e = env(**extra)
    if not any(k in e for k in ("M365_CERTIFICATE_FILE", "M365_FEDERATED_TOKEN")):
        e.setdefault("M365_CLIENT_SECRET_FILE", str(secret))
    return read_settings(e)
