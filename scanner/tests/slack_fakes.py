"""A stubbed Slack for the SaaS scanner's tests. Every value is made up.

One HTTPS session answers Slack's read methods (`auth.test`,
`conversations.list`, `conversations.history`, `conversations.replies`, the
Discovery API's list and history) and file downloads from `files.slack.com`.
Like Slack, a failure is HTTP 200 with `{"ok": false, "error": ...}`. **It has
no method that writes**: any other method, or any request that is not a GET,
fails the test.
"""

from __future__ import annotations

import datetime as dt
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from saas_fakes import Resp
from sensitive_data_saas.clients import Clients
from sensitive_data_saas.config import Settings, read_settings

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
TEAM = "T0ACMEHQ1"
ORG = "E0ACMEORG"
BOT = "xoxb-made-up-bot-token-0000000000"
AUDIT = "xoxp-made-up-audit-token-000000000"
READ_METHODS = frozenset(
    {
        "auth.test",
        "conversations.list",
        "conversations.history",
        "conversations.replies",
        "files.list",
        "discovery.conversations.list",
        "discovery.conversations.history",
    }
)


def ts(hours_ago: float, n: int = 0) -> str:
    return f"{(NOW - dt.timedelta(hours=hours_ago)).timestamp():.0f}.{n:06d}"


@dataclass
class Chan:
    id: str
    name: str
    private: bool = False
    member: bool = True
    messages: list[dict[str, Any]] = field(default_factory=list)
    replies: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


class SlackOrg:
    """The session: Slack's Web API and file host, read-only."""

    def __init__(self) -> None:
        self.channels: dict[str, Chan] = {}
        self.files: dict[str, bytes] = {}
        self.dms: dict[str, list[dict[str, Any]]] = {}
        self.grid = True
        self.per_page = 50
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.fail: dict[str, str] = {}
        self.throttle: dict[str, int] = {}
        # #55: the Audit Logs API's entries.
        self.audit: list[dict[str, Any]] = []
        self.audit_queries: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return "SlackOrg()"

    def clients(self, settings: Settings) -> Clients:
        return Clients(settings, session=self, sleep=lambda s: None, wall=lambda: 1_790_000_000.0)

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
        assert method == "GET", "the scanner never writes"
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "api.slack.com":
            assert headers.get("Authorization") == f"Bearer {AUDIT}"
            assert parts.path == "/audit/v1/logs"
            q = dict(params or {})
            self.audit_queries.append(q)
            rows = [
                e
                for e in self.audit
                if e["action"] == q["action"] and e["date_create"] >= int(q["oldest"])
            ]
            return Resp(200, {"entries": rows, "response_metadata": {"next_cursor": ""}})
        assert headers.get("Authorization") == f"Bearer {BOT}"
        if parts.hostname == "files.slack.com":
            data_ = self.files[parts.path]
            rng = re.fullmatch(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
            if rng:
                return Resp(206, content=data_[int(rng[1]) : int(rng[2]) + 1])
            return Resp(200, content=data_)
        assert parts.hostname == "slack.com" and parts.path.startswith("/api/")
        name = parts.path.removeprefix("/api/")
        assert name in READ_METHODS, name
        q = dict(params or {})
        if self.throttle.get(name, 0) > 0:
            self.throttle[name] -= 1
            return Resp(429, {"ok": False, "error": "ratelimited"}, headers={"Retry-After": "2"})
        if name in self.fail:
            return Resp(200, {"ok": False, "error": self.fail[name], "warning": "details for you"})
        return self._route(name, q)

    def _page(self, key: str, rows: list[Any], q: dict[str, Any], **extra: Any) -> Resp:
        start = int(q.get("cursor") or 0)
        body: dict[str, Any] = {"ok": True, key: rows[start : start + self.per_page], **extra}
        if start + self.per_page < len(rows):
            body["response_metadata"] = {"next_cursor": str(start + self.per_page)}
        return Resp(200, body)

    @staticmethod
    def _window(msgs: list[dict[str, Any]], q: dict[str, Any]) -> list[dict[str, Any]]:
        oldest = float(q.get("oldest") or 0)
        latest = float(q["latest"]) if q.get("latest") else float("inf")
        out = [m for m in msgs if oldest < float(m["ts"]) < latest]
        return sorted(out, key=lambda m: float(m["ts"]), reverse=True)

    def _route(self, name: str, q: dict[str, Any]) -> Resp:
        if name == "auth.test":
            return Resp(200, {"ok": True, "team_id": TEAM, "enterprise_id": ORG, "team": "Acme"})
        if name == "conversations.list":
            rows = [
                {"id": c.id, "name": c.name, "is_private": c.private, "is_member": c.member}
                for c in self.channels.values()
            ]
            return self._page("channels", rows, q)
        if name == "conversations.history":
            c = self.channels.get(q["channel"])
            if c is None:
                return Resp(200, {"ok": False, "error": "channel_not_found"})
            if not c.member:
                return Resp(200, {"ok": False, "error": "not_in_channel"})
            return self._page("messages", self._window(c.messages, q), q)
        if name == "conversations.replies":
            c = self.channels[q["channel"]]
            parent = next(m for m in c.messages if m["ts"] == q["ts"])
            return self._page("messages", [parent, *c.replies.get(q["ts"], [])], q)
        if name == "files.list":
            # A channel's files shared since `ts_from` (#67 rescans), from its messages.
            c = self.channels[q["channel"]]
            floor = float(q.get("ts_from") or 0)
            seen: dict[str, dict[str, Any]] = {}
            for m in c.messages:
                if float(m["ts"]) >= floor:
                    for f in m.get("files") or []:
                        # Like Slack, each file says where it was shared: the channel and
                        # the message's ts (and its thread's, for a reply).
                        share = {
                            "ts": m["ts"],
                            **({"thread_ts": m["thread_ts"]} if "thread_ts" in m else {}),
                        }
                        scope = "private" if c.private else "public"
                        seen.setdefault(str(f["id"]), {**f, "shares": {scope: {c.id: [share]}}})
            return self._page("files", [seen[k] for k in sorted(seen)], q)
        if name == "discovery.conversations.list":
            if not self.grid:
                return Resp(200, {"ok": False, "error": "not_allowed_token_type"})
            want = "D" if q.get("only_im") else "G"
            rows = [{"id": d, "team_id": TEAM} for d in sorted(self.dms) if d.startswith(want)]
            return self._page("channels", rows, q)
        if name == "discovery.conversations.history":
            return self._page("messages", self._window(self.dms[q["channel"]], q), q)
        raise AssertionError(name)


def settings(tmp_path: Any, **extra: str) -> Settings:
    token = tmp_path / "slack-token"
    token.write_text(BOT)
    e = {
        "SCANNER_SITE": "acme-slack",
        "SLACK_TOKEN_FILE": str(token),
        "FINDINGS_FILE": str(tmp_path / "findings.json"),
    }
    e.update(extra)
    return read_settings(e)
