"""Microsoft Teams messages, opt-in: channel messages per team, and chats per person.

**Grants.** `ChannelMessage.Read.All` (channels) and `Chat.Read.All` (chats),
with `Team.ReadBasic.All` and `Channel.ReadBasic.All` to list them. Both
message permissions are **protected APIs**: Microsoft must approve the app
for them (a request form) before Graph returns any message, whatever the
admin consented to. Until then every team or chat store is `protected_api`,
a gap the run summary names. So both kinds are off unless named in `DISCOVER`
(`m365_teams_channel`, `m365_teams_chat`).

**Channels** (`m365_teams_channel`, one store per team in `M365_TEAMS`, its
name masked): each channel's messages from a delta query
(`/teams/{team}/channels/{channel}/messages/delta`, the first pass limited to
`LOOKBACK_DAYS`), with each root message's replies. Bodies are HTML; their text
is read. A file shared in a channel lives in the team's SharePoint site and is
counted as `linked_item` here (the site's own store reads it).

**Chats** (`m365_teams_chat`, one store per person in scope,
`user-<hash>`): the person's chats (`/users/{id}/chats`), each read from
newest to oldest (`/chats/{id}/messages`) down to what the last complete read
saw. A chat two people in scope share is read once a run.

At most `MESSAGES_MAX_PER_CHANNEL` messages per team, or per person's chats, a
run; the next run goes on from there. Sampling is stable, by message id.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.objects import sample_point

from ..graph import Graph
from ..resources import saas_item, teams_channel_link
from .base import Context, ItemReader, call_gap, html_text, parse_time
from .m365 import Person, facts_of, fields_of, people, settings_of, tenant_of

_CHATS_READ = "m365.chats_read"


def _stamp(t: _dt.datetime) -> str:
    """A time as Graph's filters take it: UTC, milliseconds, `Z`."""
    return t.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def message_text(msg: dict[str, Any]) -> str:
    body = msg.get("body") if isinstance(msg.get("body"), dict) else {}
    content = str((body or {}).get("content") or "")
    if str((body or {}).get("contentType") or "").lower() == "html":
        content = html_text(content)
    subject = str(msg.get("subject") or "")
    return f"{subject}\n\n{content}" if subject else content


@dataclass
class Team:
    team_id: str
    name: str

    def __repr__(self) -> str:
        return f"Team({redact_digits(self.name)!r})"


@dataclass
class Chats:
    person: Person

    def __repr__(self) -> str:
        return f"Chats({self.person!r})"


class _Messages:
    """What channel and chat sources share: a message's findings, a budget, a cap."""

    kind = ""
    service = ""

    def __init__(self, ctx: Context, store_name: str, sample_percent: int) -> None:
        self.ctx = ctx
        self.graph: Graph = ctx.clients.graph
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.tenant = tenant_of(ctx)
        self.target = store_name
        self.read = 0

    def room(self, r: ItemReader) -> bool:
        return self.read < self.ctx.settings.messages_max and r.room()

    def message(
        self,
        msg: dict[str, Any],
        location: str,
        r: ItemReader,
        *,
        resource: dict[str, Any],
        link: str | None,
    ) -> None:
        mid = str(msg.get("id") or "")
        if msg.get("deletedDateTime") or "@removed" in msg:
            r.store.remove_location(location)
            return
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(mid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        text = message_text(msg)
        r.budget.take(len(text))
        self.read += 1
        findings = r.text(text, resource, link)
        for att in msg.get("attachments") or []:
            if isinstance(att, dict):
                r.skip("linked_item")
        r.store.replace_location(location, findings)

    def failed(self, err: BaseException, cov: Coverage) -> str | None:
        gap = call_gap(err)
        cov.error = None if gap == "throttled" else error_name(err)
        log_event("source.failed", source=self.target, error=error_name(err))
        if cov.scanned == 0 and gap is not None:
            return gap
        return None


class ChannelsAdapter:
    kind = "m365_teams_channel"

    def discover(self, ctx: Context, out: Discovery) -> None:
        graph = ctx.clients.graph
        for team_id in settings_of(ctx).teams:
            try:
                got = graph.get(f"/teams/{team_id}", {"$select": "id,displayName"})
                name = str(got.get("displayName") or team_id)
            except Exception as err:
                store = Store(self.kind, team_id)
                store.extra.update(fields_of(ctx))
                gap = call_gap(err) or "error"
                if gap in ("not_provisioned", "protected_api"):
                    store.skip(gap)
                else:
                    store.status, store.reason, store.error = "error", gap, error_name(err)
                out.stores.append(store)
                continue
            store = Store(self.kind, name)
            store.extra.update(fields_of(ctx))
            store.facts = facts_of(ctx)
            store.table = Team(team_id, name)
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> ChannelsSource | None:
        t = store.table
        if not isinstance(t, Team):
            return None
        return ChannelsSource(ctx, t, store.name, store.sample_percent or 100)


class ChannelsSource(_Messages):
    kind = "m365_teams_channel"
    service = "teams_channel"

    def __init__(self, ctx: Context, team: Team, store_name: str, sample_percent: int) -> None:
        super().__init__(ctx, store_name, sample_percent)
        self.team = team
        self.id = f"{self.kind}:{team.team_id}"

    def __repr__(self) -> str:
        return f"ChannelsSource({self.team!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        self.read = 0
        s = self.ctx.settings
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        r = ItemReader(detector, s, cov, now.isoformat(), dict(self.facts or {}), store, budget)
        state: dict[str, Any] = dict(cursor.get("channels") or {})
        since = (now - _dt.timedelta(days=s.lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        note: str | None = None
        complete = True
        try:
            channels: list[tuple[str, str]] = []
            for page, _, _ in self.graph.pages(
                f"/teams/{self.team.team_id}/channels", {"$select": "id,displayName"}
            ):
                channels.extend((str(c["id"]), str(c.get("displayName") or "")) for c in page)
            state = {k: v for k, v in state.items() if k in {c for c, _ in channels}}
            for cid, cname in sorted(channels):
                st = dict(state.get(cid) or {})
                done = self._channel(cid, cname, st, r, since=since)
                state[cid] = st
                if not done:
                    complete = False
                    break
        except Exception as err:  # recorded by name on the source
            note = self.failed(err, cov)
            complete = False
        cov.pass_complete = complete and cov.error is None
        if not complete and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"channels": state}, note=note)

    def _channel(
        self, cid: str, cname: str, st: dict[str, Any], r: ItemReader, *, since: str
    ) -> bool:
        base = f"/teams/{self.team.team_id}/channels/{cid}/messages"
        url = st.get("page") or st.get("delta")
        if url is None:
            query = urllib.parse.urlencode({"$filter": f"lastModifiedDateTime gt {since}"})
            url = f"{base}/delta?{query}"
        skip = int(st.get("skip") or 0)
        link = teams_channel_link(cid, self.team.team_id)
        while True:
            page = self.graph.get(url)
            items = [i for i in page.get("value") or [] if isinstance(i, dict)]
            for i, msg in enumerate(items):
                if i < skip:
                    continue
                if not self.room(r):
                    st.clear()
                    st.update(page=url, skip=i)
                    return False
                self._root(base, msg, r, cname=cname, link=link)
            skip = 0
            nxt = page.get("@odata.nextLink")
            if nxt:
                url = str(nxt)
                st.clear()
                st.update(page=url, skip=0)
                continue
            delta = page.get("@odata.deltaLink")
            st.clear()
            if delta:
                st["delta"] = str(delta)
            return True

    def _resource(self, mid: str, cname: str, part: str) -> dict[str, Any]:
        return saas_item(
            "m365",
            self.service,
            self.tenant,
            mid,
            part,
            container=self.team.name,
            channel=cname,
        )

    def _root(
        self, base: str, msg: dict[str, Any], r: ItemReader, *, cname: str, link: str | None
    ) -> None:
        mid = str(msg.get("id") or "")
        if not mid:
            return
        location = f"{self.id}\n{mid}"
        self.message(msg, location, r, resource=self._resource(mid, cname, "message"), link=link)
        if msg.get("deletedDateTime") or "@removed" in msg:
            return
        try:
            for page, _, _ in self.graph.pages(f"{base}/{mid}/replies", {"$top": "50"}):
                for reply in page:
                    rid = str(reply.get("id") or "")
                    if not rid or not self.room(r):
                        return
                    self.message(
                        reply,
                        f"{location}/{rid}",
                        r,
                        resource=self._resource(f"{mid}/{rid}", cname, "reply"),
                        link=link,
                    )
        except Exception as err:  # the root message still counts
            r.cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))


class ChatsAdapter:
    kind = "m365_teams_chat"

    def discover(self, ctx: Context, out: Discovery) -> None:
        for p in people(ctx):
            store = Store(self.kind, p.store_name)
            store.extra.update(fields_of(ctx, p.principal_hash))
            store.facts = facts_of(ctx)
            store.table = Chats(p)
            out.stores.append(store)
            if p.gap is not None:
                if p.gap in ("access_denied", "error"):
                    store.status, store.reason, store.error = "error", p.gap, p.error
                else:
                    store.skip(p.gap)
                continue
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> ChatsSource | None:
        t = store.table
        if not isinstance(t, Chats) or t.person.user_id is None:
            return None
        return ChatsSource(ctx, t.person, store.name, store.sample_percent or 100)


class ChatsSource(_Messages):
    kind = "m365_teams_chat"
    service = "teams_chat"

    def __init__(self, ctx: Context, person: Person, store_name: str, sample_percent: int) -> None:
        super().__init__(ctx, store_name, sample_percent)
        self.person = person
        self.id = f"{self.kind}:{person.principal_hash}"

    def __repr__(self) -> str:
        return f"ChatsSource({self.person!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        self.read = 0
        s = self.ctx.settings
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        r = ItemReader(detector, s, cov, now.isoformat(), dict(self.facts or {}), store, budget)
        seen: set[str] = self.ctx.memo.setdefault(_CHATS_READ, set())
        marks: dict[str, Any] = dict(cursor.get("chats") or {})
        floor = _stamp(now - _dt.timedelta(days=s.lookback_days))
        note: str | None = None
        complete = True
        try:
            chats: list[str] = []
            for page, _, _ in self.graph.pages(
                f"/users/{self.person.user_id}/chats", {"$select": "id", "$top": "50"}
            ):
                chats.extend(str(c["id"]) for c in page if c.get("id"))
            for chat in sorted(set(chats)):
                if chat in seen:
                    continue
                if not self.room(r):
                    complete = False
                    break
                seen.add(chat)
                got = marks.get(chat)
                entry = dict(got) if isinstance(got, dict) else {"mark": floor}
                done = self._chat(chat, entry, r)
                marks[chat] = entry
                if not done:
                    complete = False
                    break
        except Exception as err:  # recorded by name on the source
            note = self.failed(err, cov)
            complete = False
        cov.pass_complete = complete and cov.error is None
        if not complete and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"chats": marks}, note=note)

    def _chat(self, chat: str, entry: dict[str, Any], r: ItemReader) -> bool:
        """Read one chat newest first, from `before` (where the last run stopped) down to
        `mark` (the newest message of the last complete read). False when the cap or the
        budget stopped it: `entry` then says where the next run goes on."""
        epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
        mark = parse_time(entry.get("mark")) or epoch
        before = parse_time(entry.get("before"))
        newest = parse_time(entry.get("newest")) or mark
        window = f"lastModifiedDateTime gt {_stamp(mark)}"
        if before is not None:
            window += f" and lastModifiedDateTime lt {_stamp(before)}"
        params = {"$top": "50", "$orderby": "lastModifiedDateTime desc", "$filter": window}
        for page, _, _ in self.graph.pages(f"/chats/{chat}/messages", params):
            for msg in page:
                mid = str(msg.get("id") or "")
                if not mid:
                    continue
                when = parse_time(msg.get("lastModifiedDateTime"))
                if not self.room(r):
                    entry.update(mark=_stamp(mark), newest=_stamp(newest))
                    if before is not None:
                        entry["before"] = _stamp(before)
                    return False
                if when is not None:
                    newest = max(newest, when)
                    before = when
                resource = saas_item(
                    "m365",
                    self.service,
                    self.tenant,
                    f"{chat}/{mid}",
                    "message",
                    owner=self.person.principal_hash,
                )
                self.message(msg, f"{self.id}\n{chat}/{mid}", r, resource=resource, link=None)
        entry.clear()
        entry["mark"] = _stamp(newest)
        return True
