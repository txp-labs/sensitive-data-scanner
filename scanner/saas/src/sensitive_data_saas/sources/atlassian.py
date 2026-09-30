"""Jira issues and Confluence pages: their text, comments and attachments, read-only.

**Stores.** `jira_project` per project (its key, masked), `confluence_space`
per space (its key, masked): every one the sign-in can browse, or those named
in `JIRA_PROJECTS` and `CONFLUENCE_SPACES`.

**Jira.** Issues come from `GET /rest/api/3/search/jql`, in order of their
last update. An issue's summary, description and comments (Atlassian Document
Format, read as text) are read together (part `issue`), and each attachment
with the core's readers (part `attachment`, `/rest/api/3/attachment/content/<id>`
with ranged GETs). The first pass reads every issue; later runs only those
updated since (less a day: JQL dates are in the sign-in's time zone), skipping
an issue whose `updated` was read already.

**Confluence.** Pages and blog posts come from a CQL search
(`/rest/api/content/search`, `lastmodified` order), each read with its body
(storage format, read as text) and footer comments (part `page`), and its
attachments (`/rest/api/content/<page>/child/attachment/<id>/download`). The
same incremental rule, by page version.

At most `ISSUES_MAX_PER_PROJECT` issues or `PAGES_MAX_PER_SPACE` pages a run;
the next run goes on from there. Sampling is stable, by issue key or page id.
Each run checks up to 50 of the items it holds findings for, and drops the
findings of one that is gone. Nothing is changed: no watch, no view, no
transition.

**Attachments are rescanned** (#67): each is recorded in the project's or
space's object index by its stable id (`<issue key or page id>/<attachment
id>`). When a reader that read one changed, a pass lists the attachments
(Jira: the issues with attachments, `attachments IS NOT EMPTY`, their
`attachment` field only; Confluence: a CQL search for `type = attachment`) and
downloads only the stale ones, within `RESCAN_PERCENT`. Issue and page text is
not read again.

**Gaps.** A project or space the sign-in may not browse is `access_denied`
(401, 403); one that is gone, `not_provisioned` (404).

**Encryption.** Atlassian's own keys (`service_managed`); with Atlassian Cloud
BYOK, `ATLASSIAN_BYOK_KEY_ID` makes findings `customer_managed_key`, hashed.
"""

from __future__ import annotations

import datetime as _dt
import functools
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, Link
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.objects import sample_point

from ..atlassian import Atlassian
from ..resources import saas_item, store_fields, tenant_hash
from . import atlassian_read as _read_path
from .atlassian_read import VENDOR, download_url
from .base import (
    Attachment,
    AttachmentPage,
    AttachmentRescans,
    Context,
    ItemReader,
    call_gap,
    html_text,
    parse_time,
    vendor_facts,
)

SKEW = _dt.timedelta(days=1)
PRUNE_LIMIT = 50
ISSUE_FIELDS = "summary,description,comment,attachment,updated"


def adf_text(node: Any) -> str:
    """The text of an Atlassian Document Format node: its text nodes, a line per block."""
    out: list[str] = []

    def visit(n: Any, depth: int) -> None:
        if depth > 64:
            return
        if isinstance(n, dict):
            if isinstance(n.get("text"), str):
                out.append(n["text"])
            for child in n.get("content") or []:
                visit(child, depth + 1)
            if n.get("type") in ("paragraph", "heading", "listItem", "tableCell", "codeBlock"):
                out.append("\n")
        elif isinstance(n, list):
            for child in n:
                visit(child, depth + 1)
        elif isinstance(n, str):
            out.append(n)

    visit(node, 0)
    return "".join(out)


def gap_of(err: BaseException) -> str | None:
    name = error_name(err)
    if name in ("Http401", "Http403", "FORBIDDEN", "UNAUTHORIZED"):
        return "access_denied"
    if name in ("Http404", "NOT_FOUND"):
        return "not_provisioned"
    return call_gap(err)


def next_url(api: Atlassian, nxt: str) -> str:
    """Confluence's `_links.next`: relative to the site (v2, `/wiki/...`) or to the API root
    (v1, `/rest/...`)."""
    return api.base("confluence") + nxt.removeprefix("/wiki")


def _stamp(t: _dt.datetime) -> str:
    """A time as JQL and CQL take it (minutes)."""
    return t.astimezone(_dt.UTC).strftime("%Y-%m-%d %H:%M")


@dataclass
class Container:
    """A Jira project or a Confluence space: its id, its key, its name."""

    ident: str
    key: str

    def __repr__(self) -> str:
        return f"Container({redact_digits(self.key)!r})"


def _tenant(ctx: Context) -> str:
    return tenant_hash(ctx.clients.atlassian.cloud_id())


def _store(ctx: Context, out: Discovery, kind: str, c: Container) -> None:
    a = ctx.settings.atlassian
    store = Store(kind, c.key)
    store.extra.update(store_fields(VENDOR, _tenant(ctx)))
    store.facts = vendor_facts(a.byok_key_id if a is not None else None)
    store.table = c
    out.stores.append(store)
    if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
        return
    pct, _ = ctx.settings.sampling_for(kind, store.name, None)
    store.sample_percent = pct if pct is not None else ctx.settings.sample_percent


class JiraAdapter:
    kind = "jira_project"

    def discover(self, ctx: Context, out: Discovery) -> None:
        a = ctx.settings.atlassian
        if a is None:  # pragma: no cover - only when configured
            return
        api = ctx.clients.atlassian
        base = api.base("jira")
        wanted = {p.upper() for p in a.projects}
        start = 0
        seen: set[str] = set()
        while True:
            page = api.get(
                f"{base}/rest/api/3/project/search", {"startAt": str(start), "maxResults": "50"}
            )
            values = [v for v in page.get("values") or [] if isinstance(v, dict)]
            for p in values:
                key = str(p.get("key") or "")
                if key and (not wanted or key.upper() in wanted):
                    seen.add(key.upper())
                    _store(ctx, out, self.kind, Container(str(p.get("id") or key), key))
            start += len(values)
            if page.get("isLast", True) or not values:
                break
        for key in sorted(wanted - seen):  # named, but not browsable
            store = Store(self.kind, key)
            store.extra.update(store_fields(VENDOR, _tenant(ctx)))
            store.skip("not_provisioned")
            out.stores.append(store)

    def source(self, ctx: Context, store: Store) -> JiraSource | None:
        t = store.table
        if not isinstance(t, Container):
            return None
        return JiraSource(ctx, t, store.name, store.sample_percent or 100)


class _Atlassian:
    kind = ""
    service = ""
    id = ""
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(self, ctx: Context, c: Container, store_name: str, sample_percent: int) -> None:
        self.ctx = ctx
        self.api: Atlassian = ctx.clients.atlassian
        self.c = c
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.tenant = _tenant(ctx)
        self.target = store_name
        self.id = f"{self.kind}:{c.ident}"
        self.read = 0

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.c!r})"

    def cap(self) -> int:
        return 500

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        self.read = 0
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        r = ItemReader(
            detector, self.ctx.settings, cov, now.isoformat(), dict(self.facts or {}), store, budget
        )
        op = r.index = ObjectPass(
            self.indexes, self.id, self.kind, columnar=r.columnar, budget=budget
        )
        rescans = AttachmentRescans(r, cursor, prefix=f"{self.id}\n")
        mine = ("indexPass", "indexed", "rescan", "full")
        st: dict[str, Any] = {k: v for k, v in cursor.items() if k not in mine}
        # The first pass reads every item, and every attachment of it.
        first = not st.get("mark") or bool(cursor.get("full"))
        note: str | None = None
        done = False
        try:
            done = self.scan(st, r)
            if done and first and op.index is not None:
                rescans.indexed = True
            if done and rescans.due():
                # Then the attachments a changed component read, within the share (#67).
                rescans.run(
                    lambda at: self.attachment_pages(at, r), sample_percent=self.sample_percent
                )
        except Exception as err:  # recorded by name on the source
            gap = gap_of(err)
            cov.error = None if gap == "throttled" else error_name(err)
            if cov.scanned == 0 and gap is not None:
                note = gap
            log_event("source.failed", source=self.target, error=error_name(err))
        cov.pass_complete = done and cov.error is None
        if not done and cov.error is None:
            cov.backlog = True
        if first and not done:
            st["full"] = True
        rescans.save(st)
        op.settle(cov)
        return SourceRun(cov, st, note=note)

    def scan(self, st: dict[str, Any], r: ItemReader) -> bool:
        raise NotImplementedError

    def attachment_pages(self, at: Any, r: ItemReader) -> Iterator[AttachmentPage]:
        """The store's attachments, a page at a time, for a rescan pass (#67)."""
        raise NotImplementedError

    def room(self, r: ItemReader) -> bool:
        return self.read < self.cap() and r.room()

    def window(self, st: dict[str, Any]) -> tuple[str | None, dict[str, str]]:
        """The query's lower bound (None on the first pass) and what was read at its edge."""
        mark = parse_time(st.get("mark"))
        seen = {str(k): str(v) for k, v in (st.get("seen") or {}).items()}
        return (_stamp(mark - SKEW) if mark is not None else None), seen

    def advance(
        self, st: dict[str, Any], seen: dict[str, str], newest: _dt.datetime | None
    ) -> None:
        """Keep the newest time read, and the versions read within a skew of it."""
        mark = newest or parse_time(st.get("mark"))
        if mark is None:
            return
        floor = mark - SKEW * 2
        st["mark"] = mark.isoformat()
        st["seen"] = {
            k: v for k, v in seen.items() if (parse_time(v.split("|", 1)[0]) or mark) >= floor
        }

    # The read path (`atlassian_read.py`, the `adapter:<kind>` component, #67).
    attachments = _read_path.attachments
    attachment = _read_path.attachment

    def rescan_entry(
        self,
        att: dict[str, Any],
        r: ItemReader,
        *,
        url_of: Callable[[str], str],
        container_item: str,
        link: str | None,
    ) -> Attachment:
        """An attachment met by a rescan pass (#67): sampled by its item, as it was read."""
        return Attachment(
            key=f"{container_item}/{att.get('id')}",
            size=int(att.get("size") or att.get("fileSize") or 0),
            sample=container_item,
            location=f"{self.id}\n{container_item}",
            read=functools.partial(
                self.attachment, att, r, url_of=url_of, container_item=container_item, link=link
            ),
        )

    def prune(self, store: FindingStore, budget: Budget) -> int:
        """Drop the findings of items that are gone (a few a run)."""
        gone = 0
        for location in store.locations(f"{self.id}\n")[:PRUNE_LIMIT]:
            if not budget.time_left():
                break
            item = location.split("\n", 1)[1]
            try:
                self.api.get(self.item_url(item), {"fields": "updated"})
            except Exception as err:  # unknown: keep the findings
                if error_name(err) in ("Http404", "NOT_FOUND"):
                    gone += store.remove_location(location)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return gone

    def item_url(self, item: str) -> str:
        raise NotImplementedError


class JiraSource(_Atlassian):
    kind = "jira_project"
    service = "jira"

    def cap(self) -> int:
        a = self.ctx.settings.atlassian
        return a.issues_max if a is not None else 500

    def item_url(self, item: str) -> str:
        return f"{self.api.base('jira')}/rest/api/3/issue/{urllib.parse.quote(item)}"

    def scan(self, st: dict[str, Any], r: ItemReader) -> bool:
        base = self.api.base("jira")
        since, seen = self.window(st)
        jql = f'project = "{self.c.key}"'
        if since is not None:
            jql += f' AND updated >= "{since}"'
        jql += " ORDER BY updated ASC, key ASC"
        token: str | None = None
        newest: _dt.datetime | None = None
        while True:
            params: dict[str, Any] = {"jql": jql, "fields": ISSUE_FIELDS, "maxResults": "50"}
            if token:
                params["nextPageToken"] = token
            page = self.api.get(f"{base}/rest/api/3/search/jql", params)
            for issue in page.get("issues") or []:
                if not isinstance(issue, dict):
                    continue
                key = str(issue.get("key") or "")
                fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
                updated = str((fields or {}).get("updated") or "")
                if not key or seen.get(key) == updated:
                    continue
                if not self.room(r):
                    self.advance(st, seen, newest)
                    return False
                self.issue(key, fields or {}, r)
                seen[key] = updated
                when = parse_time(updated.replace("+0000", "+00:00"))
                if when is not None and (newest is None or when > newest):
                    newest = when
            token = str(page.get("nextPageToken") or "") or None
            if not token or page.get("isLast"):
                break
        self.advance(st, seen, newest)
        return True

    def issue(self, key: str, fields: dict[str, Any], r: ItemReader) -> None:
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(key) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        self.read += 1
        comments = (fields.get("comment") or {}).get("comments") or []
        text = "\n\n".join(
            [
                str(fields.get("summary") or ""),
                adf_text(fields.get("description")),
                *(adf_text(c.get("body")) for c in comments if isinstance(c, dict)),
            ]
        )
        r.budget.take(len(text))
        link = self.issue_link(key)
        resource = saas_item(VENDOR, self.service, self.tenant, key, "issue", container=self.c.key)
        findings = r.text(text, resource, link)
        base = self.api.base("jira")
        findings.extend(
            self.attachments(
                [a for a in fields.get("attachment") or [] if isinstance(a, dict)],
                r,
                url_of=lambda aid: f"{base}/rest/api/3/attachment/content/{aid}",
                container_item=key,
                link=link,
            )
        )
        r.store.replace_location(f"{self.id}\n{key}", findings)

    def issue_link(self, key: str) -> Link:
        return Link(
            f"https://{self.api.site}/browse/{urllib.parse.quote(key)}", (self.api.site, key)
        )

    def attachment_pages(self, at: Any, r: ItemReader) -> Iterator[AttachmentPage]:
        """The project's issues with attachments, their `attachment` field only (#67); `at`
        is the page token where a pass stopped."""
        base = self.api.base("jira")
        jql = f'project = "{self.c.key}" AND attachments IS NOT EMPTY ORDER BY key ASC'
        token = str(at) if isinstance(at, str) and at else None
        while True:
            params: dict[str, Any] = {"jql": jql, "fields": "attachment", "maxResults": "50"}
            if token:
                params["nextPageToken"] = token
            page = self.api.get(f"{base}/rest/api/3/search/jql", params)
            items: list[Attachment] = []
            for issue in page.get("issues") or []:
                key = str(issue.get("key") or "") if isinstance(issue, dict) else ""
                fields = (
                    issue.get("fields") if key and isinstance(issue.get("fields"), dict) else {}
                )
                for a in (fields or {}).get("attachment") or []:
                    if isinstance(a, dict) and a.get("id"):
                        items.append(
                            self.rescan_entry(
                                a,
                                r,
                                url_of=lambda aid: f"{base}/rest/api/3/attachment/content/{aid}",
                                container_item=key,
                                link=self.issue_link(key),
                            )
                        )
            yield items, token
            nxt = str(page.get("nextPageToken") or "") or None
            if not nxt or page.get("isLast"):
                return
            token = nxt


class ConfluenceAdapter:
    kind = "confluence_space"

    def discover(self, ctx: Context, out: Discovery) -> None:
        a = ctx.settings.atlassian
        if a is None:  # pragma: no cover - only when configured
            return
        api = ctx.clients.atlassian
        base = api.base("confluence")
        wanted = {s.upper() for s in a.spaces}
        seen: set[str] = set()
        url: str | None = f"{base}/api/v2/spaces"
        params: dict[str, Any] | None = {"limit": "250"}
        while url:
            page = api.get(url, params)
            params = None
            for sp in page.get("results") or []:
                key = str(sp.get("key") or "")
                if key and (not wanted or key.upper() in wanted):
                    seen.add(key.upper())
                    _store(ctx, out, self.kind, Container(str(sp.get("id") or key), key))
            nxt = (page.get("_links") or {}).get("next")
            url = next_url(api, str(nxt)) if nxt else None
        for key in sorted(wanted - seen):
            store = Store(self.kind, key)
            store.extra.update(store_fields(VENDOR, _tenant(ctx)))
            store.skip("not_provisioned")
            out.stores.append(store)

    def source(self, ctx: Context, store: Store) -> ConfluenceSource | None:
        t = store.table
        if not isinstance(t, Container):
            return None
        return ConfluenceSource(ctx, t, store.name, store.sample_percent or 100)


class ConfluenceSource(_Atlassian):
    kind = "confluence_space"
    service = "confluence"

    def cap(self) -> int:
        a = self.ctx.settings.atlassian
        return a.pages_max if a is not None else 500

    def item_url(self, item: str) -> str:
        return f"{self.api.base('confluence')}/rest/api/content/{urllib.parse.quote(item)}"

    def scan(self, st: dict[str, Any], r: ItemReader) -> bool:
        base = self.api.base("confluence")
        since, seen = self.window(st)
        cql = f'space = "{self.c.key}" and type in (page, blogpost)'
        if since is not None:
            cql += f' and lastmodified >= "{since}"'
        cql += " order by lastmodified asc"
        url: str | None = f"{base}/rest/api/content/search"
        params: dict[str, Any] | None = {
            "cql": cql,
            "limit": "50",
            "expand": "body.storage,version,children.comment.body.storage",
        }
        newest: _dt.datetime | None = None
        while url:
            page = self.api.get(url, params)
            params = None
            for item in page.get("results") or []:
                if not isinstance(item, dict):
                    continue
                pid = str(item.get("id") or "")
                version = item.get("version") if isinstance(item.get("version"), dict) else {}
                when_raw = str((version or {}).get("when") or "")
                mark = f"{when_raw}|{(version or {}).get('number') or ''}"
                if not pid or seen.get(pid) == mark:
                    continue
                if not self.room(r):
                    self.advance(st, seen, newest)
                    return False
                self.page(pid, item, r)
                seen[pid] = mark
                when = parse_time(when_raw)
                if when is not None and (newest is None or when > newest):
                    newest = when
            nxt = (page.get("_links") or {}).get("next")
            url = next_url(self.api, str(nxt)) if nxt else None
        self.advance(st, seen, newest)
        return True

    def page(self, pid: str, item: dict[str, Any], r: ItemReader) -> None:
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(pid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        self.read += 1
        body = ((item.get("body") or {}).get("storage") or {}).get("value") or ""
        comments = (((item.get("children") or {}).get("comment") or {}).get("results")) or []
        parts = [str(item.get("title") or ""), html_text(str(body))]
        for c in comments:
            if isinstance(c, dict):
                parts.append(
                    html_text(str(((c.get("body") or {}).get("storage") or {}).get("value") or ""))
                )
        text = "\n\n".join(parts)
        r.budget.take(len(text))
        q = urllib.parse.urlencode({"pageId": pid})
        link = Link(f"https://{self.api.site}/wiki/pages/viewpage.action?{q}", (self.api.site, pid))
        resource = saas_item(VENDOR, self.service, self.tenant, pid, "page", container=self.c.key)
        findings = r.text(text, resource, link)
        base = self.api.base("confluence")
        atts = self.api.get(
            f"{base}/rest/api/content/{pid}/child/attachment",
            {"limit": "100", "expand": "extensions"},
        )
        items = []
        for a in atts.get("results") or []:
            if isinstance(a, dict):
                ext = a.get("extensions") if isinstance(a.get("extensions"), dict) else {}
                items.append(
                    {
                        "id": a.get("id"),
                        "title": a.get("title"),
                        "size": (ext or {}).get("fileSize"),
                    }
                )
        findings.extend(
            self.attachments(
                items,
                r,
                url_of=lambda aid: f"{base}/rest/api/content/{pid}/child/attachment/{aid}/download",
                container_item=pid,
                link=link,
            )
        )
        r.store.replace_location(f"{self.id}\n{pid}", findings)

    def attachment_pages(self, at: Any, r: ItemReader) -> Iterator[AttachmentPage]:
        """The space's attachments, from a CQL search (#67), each with its page; `at` is the
        URL of the page of results where a pass stopped."""
        base = self.api.base("confluence")
        resume = str(at) if isinstance(at, str) and at else None
        url: str | None = resume or f"{base}/rest/api/content/search"
        params: dict[str, Any] | None = (
            None
            if resume
            else {
                "cql": f'space = "{self.c.key}" and type = attachment',
                "limit": "100",
                "expand": "container,extensions",
            }
        )
        while url:
            here = url if params is None else None  # the first page is asked for by its query
            page = self.api.get(url, params)
            items: list[Attachment] = []
            for a in page.get("results") or []:
                if not isinstance(a, dict) or not a.get("id"):
                    continue
                pid = str((a.get("container") or {}).get("id") or "")
                if not pid:
                    continue
                ext = a.get("extensions") if isinstance(a.get("extensions"), dict) else {}
                att = {
                    "id": a.get("id"),
                    "title": a.get("title"),
                    "size": (ext or {}).get("fileSize"),
                }
                q = urllib.parse.urlencode({"pageId": pid})
                link = Link(
                    f"https://{self.api.site}/wiki/pages/viewpage.action?{q}", (self.api.site, pid)
                )
                items.append(
                    self.rescan_entry(
                        att,
                        r,
                        url_of=functools.partial(download_url, base, pid),
                        container_item=pid,
                        link=link,
                    )
                )
            yield items, here
            nxt = (page.get("_links") or {}).get("next")
            url = next_url(self.api, str(nxt)) if nxt else None
            params = None
