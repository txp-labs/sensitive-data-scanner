"""A stubbed Atlassian Cloud site (Jira and Confluence) for the SaaS scanner's tests.

Every value is made up. One HTTPS session answers the site's tenant info,
Jira's project search, JQL search, issue and attachment content, Confluence's
space list, CQL search, content, attachments and downloads, and Atlassian's
OAuth token endpoint (rotating refresh tokens). **It has no method that
writes**: anything but a GET to the site or the gateway (or the token POST)
fails the test.
"""

from __future__ import annotations

import base64
import datetime as dt
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from saas_fakes import Resp
from sensitive_data_saas.clients import Clients
from sensitive_data_saas.config import Settings, read_settings

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
SITE = "acme.atlassian.net"
CLOUD = "11112222-3333-4444-5555-666677778888"
EMAIL = "sds-reader@acme.example"
API_TOKEN = "made-up-atlassian-api-token"  # noqa: S105


def adf(*paragraphs: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": p}]} for p in paragraphs
        ],
    }


@dataclass
class Issue:
    key: str
    summary: str = ""
    description: str = ""
    comments: list[str] = field(default_factory=list)
    attachments: list[tuple[str, str, bytes]] = field(default_factory=list)
    updated: str = "2026-09-28T10:00:00.000+0000"


@dataclass
class Page:
    id: str
    title: str = ""
    body: str = ""
    comments: list[str] = field(default_factory=list)
    attachments: list[tuple[str, str, bytes]] = field(default_factory=list)
    when: str = "2026-09-28T10:00:00.000Z"
    version: int = 1


class Site:
    """The session: one Atlassian Cloud site, read-only."""

    def __init__(self) -> None:
        self.projects: dict[str, list[Issue]] = {}
        self.forbidden_projects: set[str] = set()
        self.spaces: dict[str, list[Page]] = {}
        self.per_page = 50
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.oauth_posts: list[dict[str, Any]] = []
        self.refresh_counter = 0
        self.throttle: dict[str, int] = {}

    def __repr__(self) -> str:
        return "Site()"

    def clients(self, settings: Settings) -> Clients:
        return Clients(settings, session=self, sleep=lambda s: None, wall=lambda: 1_790_000_000.0)

    def _auth_ok(self, headers: dict[str, str]) -> bool:
        basic = "Basic " + base64.b64encode(f"{EMAIL}:{API_TOKEN}".encode()).decode()
        return headers.get("Authorization") in (basic, "Bearer made-up-3lo-access")

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
        q: dict[str, Any] = dict(urllib.parse.parse_qsl(parts.query))
        q.update(params or {})
        if parts.hostname == "auth.atlassian.com":
            assert method == "POST"
            self.oauth_posts.append(dict(json))
            self.refresh_counter += 1
            return Resp(
                200,
                {
                    "access_token": "made-up-3lo-access",
                    "refresh_token": f"made-up-refresh-{self.refresh_counter}",
                    "expires_in": 3600,
                },
            )
        assert method == "GET", "the scanner never writes"
        if parts.path == "/_edge/tenant_info":
            return Resp(200, {"cloudId": CLOUD})
        if not self._auth_ok(headers):
            return Resp(401, {"message": f"Client must be authenticated {EMAIL}"})
        path = parts.path
        if parts.hostname == "api.atlassian.com":
            path = re.sub(rf"^/ex/(jira|confluence)/{CLOUD}", "", path)
        else:
            assert parts.hostname == SITE
        for prefix, n in list(self.throttle.items()):
            if path.startswith(prefix) and n > 0:
                self.throttle[prefix] = n - 1
                return Resp(429, {"message": "slow"}, headers={"Retry-After": "1"})
        return self._route(path, q, headers)

    def _range(self, data: bytes, headers: dict[str, str]) -> Resp:
        rng = re.fullmatch(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
        if rng:
            return Resp(206, content=data[int(rng[1]) : int(rng[2]) + 1])
        return Resp(200, content=data)

    def _route(self, path: str, q: dict[str, Any], headers: dict[str, str]) -> Resp:
        if path == "/rest/api/3/project/search":
            rows = [
                {"id": f"1{i:04d}", "key": k, "name": k}
                for i, k in enumerate(sorted(self.projects))
            ]
            return Resp(200, {"values": rows, "isLast": True})
        if path == "/rest/api/3/search/jql":
            m = re.match(r'project = "([^"]+)"(?: AND updated >= "([^"]+)")?', q["jql"])
            assert m
            if m[1] in self.forbidden_projects:
                return Resp(403, {"errorMessages": [f"no access to {m[1]}"]})
            issues = sorted(self.projects[m[1]], key=lambda i: (i.updated, i.key))
            if m[2]:
                floor = dt.datetime.strptime(m[2], "%Y-%m-%d %H:%M").replace(tzinfo=dt.UTC)
                issues = [
                    i
                    for i in issues
                    if dt.datetime.strptime(i.updated, "%Y-%m-%dT%H:%M:%S.%f%z") >= floor
                ]
            start = int(q.get("nextPageToken") or 0)
            chunk = issues[start : start + self.per_page]
            body: dict[str, Any] = {
                "issues": [
                    {
                        "key": i.key,
                        "fields": {
                            "summary": i.summary,
                            "description": adf(i.description) if i.description else None,
                            "comment": {"comments": [{"body": adf(c)} for c in i.comments]},
                            "attachment": [
                                {"id": aid, "filename": name, "size": len(data)}
                                for aid, name, data in i.attachments
                            ],
                            "updated": i.updated,
                        },
                    }
                    for i in chunk
                ]
            }
            if start + self.per_page < len(issues):
                body["nextPageToken"] = str(start + self.per_page)
            else:
                body["isLast"] = True
            return Resp(200, body)
        m = re.fullmatch(r"/rest/api/3/attachment/content/([^/]+)", path)
        if m:
            data = next(
                d
                for p in self.projects.values()
                for i in p
                for a, _, d in i.attachments
                if a == m[1]
            )
            return self._range(data, headers)
        m = re.fullmatch(r"/rest/api/3/issue/([^/]+)", path)
        if m:
            key = urllib.parse.unquote(m[1])
            if any(i.key == key for p in self.projects.values() for i in p):
                return Resp(200, {"key": key})
            return Resp(404, {"errorMessages": [f"Issue {key} does not exist"]})
        if path == "/wiki/api/v2/spaces":
            rows = [
                {"id": f"9{i:04d}", "key": k, "name": k} for i, k in enumerate(sorted(self.spaces))
            ]
            return Resp(200, {"results": rows, "_links": {}})
        if path == "/wiki/rest/api/content/search":
            m = re.match(
                r'space = "([^"]+)" and type in \(page, blogpost\)'
                r'(?: and lastmodified >= "([^"]+)")?',
                q["cql"],
            )
            assert m
            pages: list[Page] = sorted(self.spaces[m[1]], key=lambda p: (p.when, p.id))
            if m[2]:
                floor = dt.datetime.strptime(m[2], "%Y-%m-%d %H:%M").replace(tzinfo=dt.UTC)
                pages = [
                    p
                    for p in pages
                    if dt.datetime.fromisoformat(p.when.replace("Z", "+00:00")) >= floor
                ]
            start = int(q.get("start") or 0)
            page_chunk = pages[start : start + self.per_page]
            page_body: dict[str, Any] = {
                "results": [
                    {
                        "id": p.id,
                        "type": "page",
                        "title": p.title,
                        "body": {"storage": {"value": p.body}},
                        "version": {"when": p.when, "number": p.version},
                        "children": {
                            "comment": {
                                "results": [{"body": {"storage": {"value": c}}} for c in p.comments]
                            }
                        },
                    }
                    for p in page_chunk
                ],
                "_links": {},
            }
            if start + self.per_page < len(pages):
                cql = urllib.parse.quote(q["cql"])
                page_body["_links"]["next"] = (
                    f"/rest/api/content/search?cql={cql}&limit=50&start={start + self.per_page}"
                )
            return Resp(200, page_body)
        m = re.fullmatch(r"/wiki/rest/api/content/([^/]+)/child/attachment", path)
        if m:
            page = next(p for s in self.spaces.values() for p in s if p.id == m[1])
            atts = [
                {"id": aid, "title": name, "extensions": {"fileSize": len(data)}}
                for aid, name, data in page.attachments
            ]
            return Resp(200, {"results": atts})
        m = re.fullmatch(r"/wiki/rest/api/content/([^/]+)/child/attachment/([^/]+)/download", path)
        if m:
            page = next(p for s in self.spaces.values() for p in s if p.id == m[1])
            data = next(d for a, _, d in page.attachments if a == m[2])
            return self._range(data, headers)
        m = re.fullmatch(r"/wiki/rest/api/content/([^/]+)", path)
        if m:
            if any(p.id == m[1] for s in self.spaces.values() for p in s):
                return Resp(200, {"id": m[1]})
            return Resp(404, {"statusCode": 404, "message": f"No content {m[1]}"})
        raise AssertionError(path)


def settings(tmp_path: Any, **extra: str) -> Settings:
    token = tmp_path / "atlassian-token"
    token.write_text(API_TOKEN)
    e = {
        "SCANNER_SITE": "acme-atlassian",
        "ATLASSIAN_SITE": SITE,
        "FINDINGS_FILE": str(tmp_path / "findings.json"),
    }
    e.update(extra)
    if "ATLASSIAN_OAUTH_CLIENT_ID" not in e:
        e.setdefault("ATLASSIAN_EMAIL", EMAIL)
        e.setdefault("ATLASSIAN_API_TOKEN_FILE", str(token))
    return read_settings(e)
