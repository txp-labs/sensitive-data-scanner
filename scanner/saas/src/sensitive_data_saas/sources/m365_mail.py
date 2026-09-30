"""Exchange Online mail: each mailbox in scope, read incrementally with delta queries.

**Grant.** Graph's `Mail.Read` application permission, limited by Exchange to
the mailboxes in scope (RBAC for Applications, or an application access
policy; docs/SAAS.md), and proved limited before any mail is read (the scope
check in `m365.py`). One store per mailbox (`m365_mail`, `user-<hash>`).

**Reading.** Each folder's messages are read with a delta query
(`/users/{id}/mailFolders/{folder}/messages/delta`), the first pass limited to
`LOOKBACK_DAYS` (`receivedDateTime ge`), bodies as text
(`Prefer: outlook.body-content-type="text"`). A message's subject and body are
read together (part `message`), and each file attachment with the core's
readers (part `attachment`): Office files, CSV, JSON, text, and table files by
column; a larger attachment than `MAX_OBJECT_BYTES` is counted as `too_large`,
an attached item or a link to a cloud file as `linked_item`.

- At most `MAIL_MAX_MESSAGES_PER_MAILBOX` messages a run; the pass resumes at
  the page and message it stopped at, then at the delta link, which returns
  only what changed. A deleted message drops its findings.
- **Attachments are rescanned** (#67): each is recorded in the mailbox's object
  index by its stable id (`<message id>/<attachment id>`). When a reader that
  read one changed, a pass lists the messages with attachments
  (`hasAttachments eq true`, within `LOOKBACK_DAYS`, ids only) and their
  attachments' metadata, and downloads only the stale ones, within
  `RESCAN_PERCENT`. Message bodies are not read again.
- Sampling is stable, by the message's id (`SAMPLE_PERCENT`).
- Nothing is marked read, moved or changed: every call is a GET.

**Gaps.** A mailbox the grant does not cover is `access_denied`; a user with no
Exchange Online mailbox is `not_provisioned`; `scope_unverified` and
`unscoped_grant` as above.
"""

from __future__ import annotations

import datetime as _dt
import functools
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.objects import sample_point

from ..graph import Graph
from ..resources import outlook_link, saas_item
from . import m365_mail_read as _read_path
from .base import (
    Attachment,
    AttachmentPage,
    AttachmentRescans,
    Context,
    ItemReader,
    call_gap,
)
from .m365 import Person, facts_of, fields_of, mail_scope, people, tenant_of
from .m365_mail_read import ATTACHMENT_FIELDS, FILE_ATTACHMENT, SERVICE

KIND = "m365_mail"
MESSAGE_FIELDS = "subject,body,hasAttachments,receivedDateTime"
PREFER = 'odata.maxpagesize=50, outlook.body-content-type="text"'


@dataclass
class Mailbox:
    person: Person

    def __repr__(self) -> str:
        return f"Mailbox({self.person!r})"


class MailAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        scope = mail_scope(ctx)
        for p in people(ctx):
            store = Store(KIND, p.store_name)
            store.extra.update(fields_of(ctx, p.principal_hash))
            store.facts = facts_of(ctx)
            store.table = Mailbox(p)
            out.stores.append(store)
            if p.gap is not None:
                if p.gap in ("access_denied", "error"):
                    store.status, store.reason, store.error = "error", p.gap, p.error
                else:
                    store.skip(p.gap)
                continue
            if scope is not None:
                store.skip(scope)
                continue
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, _ = ctx.settings.sampling_for(KIND, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> MailSource | None:
        t = store.table
        if not isinstance(t, Mailbox) or t.person.user_id is None:
            return None
        return MailSource(ctx, t.person, store, sample_percent=store.sample_percent or 100)


class MailSource:
    kind = KIND
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(self, ctx: Context, person: Person, store: Store, *, sample_percent: int) -> None:
        self.ctx = ctx
        self.graph: Graph = ctx.clients.graph
        self.person = person
        self.user_id = str(person.user_id)
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.id = f"{KIND}:{person.principal_hash}"
        self.target = store.name
        self.tenant = tenant_of(ctx)

    def __repr__(self) -> str:
        return f"MailSource({self.target!r})"

    def _folders(self) -> list[str]:
        out: list[str] = []
        for page, _, _ in self.graph.pages(
            f"/users/{self.user_id}/mailFolders/delta", {"$select": "id"}
        ):
            out.extend(str(f["id"]) for f in page if f.get("id") and "@removed" not in f)
        return sorted(set(out))

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        s = self.ctx.settings
        cov = Coverage(KIND, self.target, sample_percent=self.sample_percent)
        r = ItemReader(detector, s, cov, now.isoformat(), dict(self.facts or {}), store, budget)
        op = r.index = ObjectPass(
            self.indexes, self.id, self.kind, columnar=r.columnar, budget=budget
        )
        rescans = AttachmentRescans(r, cursor, prefix=f"{self.id}\n")
        # A pass from no delta links reads every message in the look-back: once it completes
        # with the index on, every attachment has a row (`indexed`).
        full = bool(cursor.get("full")) or not cursor.get("folders")
        folders_state: dict[str, Any] = dict(cursor.get("folders") or {})
        since = (now - _dt.timedelta(days=s.lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        read = 0
        note: str | None = None
        complete = True
        try:
            folders = self._folders()
            # A folder that is gone takes its cursor with it.
            folders_state = {k: v for k, v in folders_state.items() if k in folders}
            for folder in folders:
                st = dict(folders_state.get(folder) or {})
                done, read = self._folder(folder, st, r, read=read, since=since, cap=s.mail_max)
                folders_state[folder] = st
                if not done:
                    complete = False
                    break
            if complete and full and op.index is not None:
                rescans.indexed = True
            if complete and rescans.due():
                # Then the attachments a changed component read, within the share (#67).
                rescans.run(
                    lambda at: self._attachment_pages(folders, at, since, r),
                    sample_percent=self.sample_percent,
                )
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            gap = call_gap(err)
            if cov.scanned == 0 and gap is not None:
                note = gap
            if gap == "throttled":
                cov.error = None
                cov.backlog = True
            complete = False
            log_event("source.failed", source=self.target, error=error_name(err))
        cov.pass_complete = complete and cov.error is None
        if not complete and cov.error is None:
            cov.backlog = True
        out: dict[str, Any] = {"folders": folders_state}
        if full and not complete:
            out["full"] = True
        rescans.save(out)
        op.settle(cov)
        return SourceRun(cov, out, note=note)

    def _folder(
        self, folder: str, st: dict[str, Any], r: ItemReader, *, read: int, since: str, cap: int
    ) -> tuple[bool, int]:
        """Read one folder from its cursor. (Whether it reached its delta link, messages read.)"""
        url = st.get("page") or st.get("delta")
        if url is None:
            query = urllib.parse.urlencode(
                {"$select": MESSAGE_FIELDS, "$filter": f"receivedDateTime ge {since}"}
            )
            url = f"/users/{self.user_id}/mailFolders/{folder}/messages/delta?{query}"
        skip = int(st.get("skip") or 0)
        headers = {"Prefer": PREFER}
        while True:
            page = self.graph.get(url, headers=headers)
            items = [i for i in page.get("value") or [] if isinstance(i, dict)]
            for i, msg in enumerate(items):
                if i < skip:
                    continue
                if read >= cap or not r.room():
                    st.update(page=url, skip=i)
                    return False, read
                read += self._message(msg, r)
            skip = 0
            nxt = page.get("@odata.nextLink")
            if nxt:
                url = str(nxt)
                st.update(page=url, skip=0)
                continue
            delta = page.get("@odata.deltaLink")
            st.clear()
            if delta:
                st["delta"] = str(delta)
            return True, read

    def _message(self, msg: dict[str, Any], r: ItemReader) -> int:
        """One message from a delta page. 1 when it was read (counted against the cap)."""
        mid = str(msg.get("id") or "")
        if not mid:
            return 0
        location = f"{self.id}\n{mid}"
        if "@removed" in msg:
            r.store.remove_location(location)
            return 0  # its attachments' rows go when a rescan pass no longer meets them
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(mid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return 0
        body = msg.get("body") if isinstance(msg.get("body"), dict) else {}
        text = f"{msg.get('subject') or ''}\n\n{(body or {}).get('content') or ''}"
        r.budget.take(len(text))
        link = outlook_link(mid)
        resource = saas_item(
            "m365", SERVICE, self.tenant, mid, "message", owner=self.person.principal_hash
        )
        findings = r.text(text, resource, link)
        if msg.get("hasAttachments"):
            try:
                findings.extend(self._attachments(mid, r))
            except Exception as err:  # the message's text still counts
                r.cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
        r.store.replace_location(location, findings)
        return 1

    # The read path (`m365_mail_read.py`, the `adapter:<kind>` component, #67).
    _attachments = _read_path._attachments
    _attachment = _read_path._attachment

    def _attachment_pages(
        self, folders: list[str], at: Any, since: str, r: ItemReader
    ) -> Iterator[AttachmentPage]:
        """The mailbox's file attachments, a page of messages at a time (#67): the messages
        with attachments in the look-back, by id, and their attachments' metadata. `at` is
        where a pass stopped: a folder and the page it was on."""
        start = at if isinstance(at, dict) else {}
        first = str(start.get("folder") or "")
        for folder in folders:
            if first and folder < first:
                continue
            query = urllib.parse.urlencode(
                {
                    "$select": "id",
                    "$filter": f"hasAttachments eq true and receivedDateTime ge {since}",
                    "$top": "50",
                }
            )
            url: str | None = (
                str(start["page"])
                if folder == first and start.get("page")
                else f"/users/{self.user_id}/mailFolders/{folder}/messages?{query}"
            )
            while url is not None:
                page = self.graph.get(url)
                items: list[Attachment] = []
                for msg in page.get("value") or []:
                    mid = str(msg.get("id") or "") if isinstance(msg, dict) else ""
                    if not mid or sample_point(mid) >= self.sample_percent:
                        continue
                    for meta, _, _ in self.graph.pages(
                        f"/users/{self.user_id}/messages/{mid}/attachments",
                        {"$select": ATTACHMENT_FIELDS},
                    ):
                        for att in meta:
                            if att.get("@odata.type") != FILE_ATTACHMENT or not att.get("id"):
                                continue
                            items.append(
                                Attachment(
                                    key=f"{mid}/{att['id']}",
                                    size=int(att.get("size") or 0),
                                    sample=mid,
                                    location=f"{self.id}\n{mid}",
                                    read=functools.partial(self._attachment, mid, att, r),
                                )
                            )
                yield items, {"folder": folder, "page": url}
                nxt = page.get("@odata.nextLink")
                url = str(nxt) if nxt else None
