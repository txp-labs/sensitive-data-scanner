"""Gmail: each person's mailbox, read as that person with `gmail.readonly` only.

**Grant.** Domain-wide delegation of `https://www.googleapis.com/auth/gmail.readonly`
to the service account's client id. The scanner acts as each person in scope
(`GWS_USERS`, `GWS_GROUPS`, `GWS_ORG_UNITS`), and as no one else. One store
per mailbox (`gws_gmail`, `user-<hash>`).

**Reading.** The first pass lists the last `LOOKBACK_DAYS` of messages
(`users.messages.list`, `q=newer_than:<n>d`, spam and trash left out) and reads
each (`format=full`): its subject and its text parts (an HTML-only body as its
text) together, part `message`, and each attachment with the core's readers,
part `attachment`. The mailbox's `historyId` at the start of the pass is kept;
later runs read only the messages added since (`users.history.list`), and a
deleted message drops its findings. A history too old for Gmail to keep
starts a new pass.

- At most `MAIL_MAX_MESSAGES_PER_MAILBOX` messages a run; the pass resumes at
  the page and message it stopped at.
- Sampling is stable, by message id.
- Nothing is modified: no label, no read mark. `gmail.readonly` could not.

**Gaps.** A person without Gmail is `not_provisioned`; a delegation that does
not cover the scope (`unauthorized_client`) is `access_denied`.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.objects import sample_point

from ..google import GoogleApi
from ..resources import saas_item
from ..scopes import GWS_GMAIL
from .base import Context, ItemReader, bytes_fetch, call_gap, html_text
from .gws import VENDOR, GwsPerson, facts_of, fields_of, people, tenant_of

KIND = "gws_gmail"
SERVICE = "gmail"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"


def b64(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError):
        return b""


def _parts(part: dict[str, Any]) -> list[dict[str, Any]]:
    out = [part]
    for p in part.get("parts") or []:
        if isinstance(p, dict):
            out.extend(_parts(p))
    return out


def message_text(msg: dict[str, Any]) -> str:
    """A message's subject and text: its text/plain parts, else its HTML parts' text."""
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    headers = (payload or {}).get("headers") or []
    subject = next(
        (str(h.get("value") or "") for h in headers if str(h.get("name")).lower() == "subject"),
        "",
    )
    plain: list[str] = []
    html: list[str] = []
    for p in _parts(payload or {}):
        if p.get("filename"):
            continue
        data = (p.get("body") or {}).get("data")
        if not data:
            continue
        text = b64(str(data)).decode("utf-8", "replace")
        mime = str(p.get("mimeType") or "")
        if mime == "text/plain":
            plain.append(text)
        elif mime == "text/html":
            html.append(html_text(text))
    body = "\n".join(plain) if plain else "\n".join(html)
    return f"{subject}\n\n{body}"


@dataclass
class Mailbox:
    person: GwsPerson

    def __repr__(self) -> str:
        return f"Mailbox({self.person!r})"


def person_stores(ctx: Context, out: Discovery, kind: str, target: type) -> None:
    """One store per person in scope, decided; `target` wraps the person for the source."""
    for p in people(ctx):
        store = Store(kind, p.store_name)
        store.extra.update(fields_of(ctx, p.principal_hash))
        store.facts = facts_of(ctx)
        store.table = target(p)
        out.stores.append(store)
        if p.gap is not None:
            if p.gap in ("access_denied", "error"):
                store.status, store.reason, store.error = "error", p.gap, p.error
            else:
                store.skip(p.gap)
            continue
        if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
            continue
        pct, _ = ctx.settings.sampling_for(kind, store.name, None)
        store.sample_percent = pct if pct is not None else ctx.settings.sample_percent


def gap_of(err: BaseException, not_provisioned: frozenset[str] = frozenset()) -> str | None:
    name = error_name(err)
    if name in not_provisioned:
        return "not_provisioned"
    return call_gap(err)


class GmailAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        person_stores(ctx, out, KIND, Mailbox)

    def source(self, ctx: Context, store: Store) -> GmailSource | None:
        t = store.table
        if not isinstance(t, Mailbox) or t.person.email is None:
            return None
        return GmailSource(ctx, t.person, store.name, store.sample_percent or 100)


class GmailSource:
    kind = KIND

    def __init__(
        self, ctx: Context, person: GwsPerson, store_name: str, sample_percent: int
    ) -> None:
        self.ctx = ctx
        self.person = person
        self.api: GoogleApi = ctx.clients.google(str(person.email), GWS_GMAIL)
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.tenant = tenant_of(ctx)
        self.id = f"{KIND}:{person.principal_hash}"
        self.target = store_name
        self.read = 0

    def __repr__(self) -> str:
        return f"GmailSource({self.person!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        s = self.ctx.settings
        self.read = 0
        cov = Coverage(KIND, self.target, sample_percent=self.sample_percent)
        r = ItemReader(detector, s, cov, now.isoformat(), dict(self.facts or {}), store, budget)
        st: dict[str, Any] = dict(cursor)
        note: str | None = None
        done = False
        try:
            if st.get("mode") == "history":
                done = self._history(st, r)
                if st.get("mode") != "history":  # the history was too old: a new pass
                    done = self._list(st, r)
            else:
                done = self._list(st, r)
        except Exception as err:  # recorded by name on the source
            gap = gap_of(err, frozenset({"FAILED_PRECONDITION"}))
            cov.error = None if gap == "throttled" else error_name(err)
            if cov.scanned == 0 and gap is not None:
                note = gap
            log_event("source.failed", source=self.target, error=error_name(err))
        cov.pass_complete = done and cov.error is None
        if not done and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, st, note=note)

    def _room(self, r: ItemReader) -> bool:
        return self.read < self.ctx.settings.mail_max and r.room()

    def _list(self, st: dict[str, Any], r: ItemReader) -> bool:
        if st.get("mode") != "list":
            profile = self.api.get(f"{GMAIL}/profile")
            st.clear()
            st.update(mode="list", start=str(profile.get("historyId") or ""), page=None, skip=0)
        skip = int(st.get("skip") or 0)
        params = {"q": f"newer_than:{self.ctx.settings.lookback_days}d", "maxResults": "100"}
        token = st.get("page")
        for page, nxt, _ in self.api.pages(f"{GMAIL}/messages", "messages", params, token=token):
            for i, ref in enumerate(page):
                if i < skip:
                    continue
                if not self._room(r):
                    st.update(page=token, skip=i)
                    return False
                self._message(str(ref.get("id") or ""), r)
            skip = 0
            token = nxt
            st.update(page=token, skip=0)
        start = str(st.get("start") or "")
        st.clear()
        st.update(mode="history", history=start)
        return True

    def _history(self, st: dict[str, Any], r: ItemReader) -> bool:
        start = str(st.get("history") or "")
        params: dict[str, Any] = {
            "startHistoryId": start,
            "historyTypes": ["messageAdded", "messageDeleted"],
            "maxResults": "500",
        }
        token = st.get("page")
        skip = int(st.get("skip") or 0)
        latest = start
        try:
            pages = list(self.api.pages(f"{GMAIL}/history", "history", params, token=token))
        except Exception as err:
            if error_name(err) == "NOT_FOUND":  # Gmail no longer keeps that history
                st.clear()
                return False
            raise
        for page, nxt, whole in pages:
            latest = str(whole.get("historyId") or latest)
            events: list[tuple[str, str]] = []
            for h in page:
                for added in h.get("messagesAdded") or []:
                    events.append(("add", str((added.get("message") or {}).get("id") or "")))
                for gone in h.get("messagesDeleted") or []:
                    events.append(("del", str((gone.get("message") or {}).get("id") or "")))
            for i, (what, mid) in enumerate(events):
                if i < skip or not mid:
                    continue
                if what == "del":
                    r.store.remove_location(f"{self.id}\n{mid}")
                    continue
                if not self._room(r):
                    st.update(page=token, skip=i)
                    return False
                self._message(mid, r)
            skip = 0
            token = nxt
            st.update(page=token, skip=0)
        st.clear()
        st.update(mode="history", history=latest)
        return True

    def _message(self, mid: str, r: ItemReader) -> None:
        if not mid:
            return
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(mid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        try:
            msg = self.api.get(f"{GMAIL}/messages/{mid}", {"format": "full"})
        except Exception as err:
            if error_name(err) == "NOT_FOUND":  # deleted since it was listed
                r.store.remove_location(f"{self.id}\n{mid}")
                return
            raise
        text = message_text(msg)
        r.budget.take(len(text))
        self.read += 1
        resource = saas_item(
            VENDOR, SERVICE, self.tenant, mid, "message", owner=self.person.principal_hash
        )
        findings = r.text(text, resource, None)
        try:
            findings.extend(self._attachments(mid, msg, r))
        except Exception as err:  # the message's text still counts
            r.cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))
        r.store.replace_location(f"{self.id}\n{mid}", findings)

    def _attachments(self, mid: str, msg: dict[str, Any], r: ItemReader) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
        max_bytes = self.ctx.settings.max_object_bytes
        for n, p in enumerate(_parts(payload or {})):
            name = str(p.get("filename") or "")
            if not name:
                continue
            body = p.get("body") or {}
            size = int(body.get("size") or 0)
            if size > max_bytes:
                r.skip("too_large")
                continue
            if body.get("attachmentId"):
                got = self.api.get(f"{GMAIL}/messages/{mid}/attachments/{body['attachmentId']}")
                data = b64(str(got.get("data") or ""))
            else:
                data = b64(str(body.get("data") or ""))
            item_id = f"{mid}/{p.get('partId') or n}"

            def resource_for(column: str | None, item_id: str = item_id, name: str = name) -> Any:
                return saas_item(
                    VENDOR,
                    SERVICE,
                    self.tenant,
                    item_id,
                    "attachment",
                    owner=self.person.principal_hash,
                    name=name,
                    column=column,
                )

            out.extend(
                r.file(name, len(data), bytes_fetch(data), resource_for=resource_for, link=None)
            )
            r.budget.bytes += len(data)
        return out
