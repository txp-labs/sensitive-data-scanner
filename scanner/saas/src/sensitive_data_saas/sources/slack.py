"""Slack: channel messages, their threads and files; direct messages through Discovery.

**Grant.** A Slack app the customer creates and installs, with read scopes
only: `channels:read` and `groups:read` (to list channels), `channels:history`
and `groups:history` (messages), `files:read` (files). A bot reads only the
channels it is a member of: a bot token in a channel it was not invited to is
`not_a_member`.

**Auto-join, opt-in** (#139): with `SLACK_JOIN_PUBLIC_CHANNELS` on and the app's
`channels:join` scope (the auto-join manifest), discovery joins each public
channel the bot is not in, before it is read: never a private channel (a bot
cannot join one), an archived one, or a Slack Connect channel (shared with
another organization, or pending), and never one `SLACK_CHANNELS` or the allow
and deny rules leave out. Each join is recorded on its store
(`joinedByScanner`: `joined_by_scanner`, the channel id and the time). Without
the scope, nothing is joined: the channels stay `not_a_member` with the error
`missing_scope:channels:join` and the setting named in `toggle`. Off (the
default), the scanner never calls `conversations.join`.

**Channels** (`slack_channel`, one store per channel, `#name` masked):
`conversations.history` from the newest message down to what the last
complete read saw (the first run: `LOOKBACK_DAYS`), with each thread's replies
read along with its first message (`conversations.replies`; a reply added
later to a thread already read is not seen) and each message's files, read by the core's readers
from `files.slack.com` (a file hosted elsewhere is `linked_item`). A message's
text and its legacy attachments' text are read together. At most
`MESSAGES_MAX_PER_CHANNEL` messages a channel a run; the next run goes on
below where this one stopped.

**Files are rescanned** (#67): each file read is recorded in the channel's
object index by its file id. When a reader that read one changed, a pass lists
the channel's files (`files.list`, `files:read`, within `LOOKBACK_DAYS`) and
downloads only the stale ones, within `RESCAN_PERCENT`. Messages are not read
again. Files met through the Discovery API are read with their messages only.

**Direct and group messages** (`slack_dm`, opt-in, one store per organization):
only the **Discovery API** reads them, on **Enterprise Grid**, with an
org-level app Slack has approved for `discovery:read`
(`discovery.conversations.list` with `only_im` and `only_mpim`, then
`discovery.conversations.history`). Not named in `DISCOVER`, the store is
`read_not_configured`; without the Discovery API, `access_denied`
(`missing_scope`, `not_allowed_token_type`).

**Encryption.** Slack's own keys (`service_managed`); with Slack Enterprise Key
Management, `SLACK_EKM_KEY_ID` makes findings `customer_managed_key`, hashed.
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
from sensitive_data_core.findings import Coverage, Link
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.objects import sample_point

from ..resources import saas_item, store_fields, tenant_hash
from ..slack import Slack
from . import slack_read as _read_path
from .base import (
    Attachment,
    AttachmentPage,
    AttachmentRescans,
    Context,
    ItemReader,
    call_gap,
    vendor_facts,
)
from .slack_read import VENDOR

_TEAM = "slack.team"
JOIN_SETTING = "SLACK_JOIN_PUBLIC_CHANNELS"
JOIN_SCOPE = "channels:join"
JOINED = "joined_by_scanner"
NOT_MEMBER = frozenset({"not_in_channel"})
SLACK_DENIED = frozenset(
    {"missing_scope", "not_allowed_token_type", "invalid_auth", "not_authed", "account_inactive"}
)


def channel_link(team: str, channel: str) -> Link:
    """The channel in Slack's web app: the fallback when a message or file has no link."""
    q = urllib.parse.quote
    return Link(f"https://app.slack.com/client/{q(team)}/{q(channel)}", (team, channel))


def message_link(team: str, channel: str, msg: dict[str, Any]) -> Link:
    """A message in Slack's web app, opened in its thread pane.

    `https://app.slack.com/client/<team>/<channel>/thread/<channel>-<ts>`: a thread
    reply opens its thread (by `thread_ts`, the first message's ts), and any other
    message opens on its own. The ts keeps its dot. Slack's documented permalink
    (`https://<workspace>.slack.com/archives/<channel>/p<ts without the dot>`,
    `chat.getPermalink`) is a 16-digit run: a 13+ digit run is masked here
    (`redact_digits`), and a reader's leak guard may take one for a card number, so
    that form is never written. Built from ids only; without a ts, the channel.
    """
    root = str(msg.get("thread_ts") or msg.get("ts") or "")
    if not root:
        return channel_link(team, channel)
    q = urllib.parse.quote
    return Link(
        f"https://app.slack.com/client/{q(team)}/{q(channel)}/thread/{q(channel)}-{q(root)}",
        (team, channel, root),
    )


def shared_link(team: str, channel: str, f: dict[str, Any]) -> Link:
    """A file listed by `files.list` (the rescans, #67): the message that shared it in this
    channel, from the file's own `shares` (already in the listing, no other call), else the
    channel.

    The file's `permalink` (`https://<workspace>.slack.com/files/<user>/<file>/<name>`) is
    not used: the schema holds a Slack link to `app.slack.com`, and it would name the file
    and the person who shared it. A file read with its message takes that message's link.
    """
    shares = f.get("shares")
    for scope in ("public", "private"):
        group = shares.get(scope) if isinstance(shares, dict) else None
        found = group.get(channel) if isinstance(group, dict) else None
        if isinstance(found, list):
            for share in found:
                if isinstance(share, dict) and share.get("ts"):
                    return message_link(team, channel, share)
    return channel_link(team, channel)


def message_text(msg: dict[str, Any]) -> str:
    """A message's text, with its legacy attachments' text."""
    parts = [str(msg.get("text") or "")]
    for att in msg.get("attachments") or []:
        if isinstance(att, dict):
            parts.extend(str(att.get(k) or "") for k in ("pretext", "title", "text", "fallback"))
    return "\n".join(p for p in parts if p)


def _ts(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def team_of(ctx: Context) -> tuple[str, str]:
    """(the team id, the tenant: the organization's id on Enterprise Grid, else the team's)."""
    if _TEAM not in ctx.memo:
        got = ctx.clients.slack.get("auth.test")
        team = str(got.get("team_id") or "")
        ctx.memo[_TEAM] = (team, str(got.get("enterprise_id") or team))
    found: tuple[str, str] = ctx.memo[_TEAM]
    return found


def gap_of(err: BaseException) -> str | None:
    name = error_name(err)
    if name in NOT_MEMBER:
        return "not_a_member"
    if name in SLACK_DENIED:
        return "access_denied"
    if name in ("channel_not_found", "team_not_found"):
        return "not_provisioned"
    return call_gap(err)


@dataclass
class Channel:
    channel_id: str
    name: str

    def __repr__(self) -> str:
        return f"Channel({redact_digits(self.name)!r})"


class _Messages:
    """Reading one conversation newest first, from `before` down to `mark`."""

    kind = ""
    service = ""
    id = ""

    def __init__(self, ctx: Context, store_name: str, sample_percent: int) -> None:
        self.ctx = ctx
        self.api: Slack = ctx.clients.slack
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.target = store_name
        self.read = 0
        self.team, tenant = team_of(ctx)
        self.tenant = tenant_hash(tenant)

    def room(self, r: ItemReader) -> bool:
        return self.read < self.ctx.settings.messages_max and r.room()

    def conversation(
        self,
        method: str,
        base: dict[str, Any],
        entry: dict[str, Any],
        r: ItemReader,
        *,
        channel: str,
        container: str,
        link: str | None,
        threads: bool,
    ) -> bool:
        """Read one conversation's messages newest first. False when the cap or the budget
        stopped it: `entry` then says where the next run goes on."""
        mark = _ts(entry.get("mark"))
        before = entry.get("before")
        newest = _ts(entry.get("newest")) or mark
        params = {**base, "oldest": f"{mark:.6f}", "limit": "200"}
        if before:
            params["latest"] = str(before)
        for page, _, _ in self.api.pages(method, "messages", params):
            for msg in page:
                ts = str(msg.get("ts") or "")
                if not ts:
                    continue
                if not self.room(r):
                    entry.update(mark=f"{mark:.6f}", newest=f"{newest:.6f}")
                    if before:
                        entry["before"] = str(before)
                    return False
                newest = max(newest, _ts(ts))
                before = ts
                self.message(msg, r, channel=channel, container=container, link=link)
                if threads and msg.get("reply_count") and msg.get("thread_ts") == ts:
                    self.replies(ts, r, channel=channel, container=container, link=link)
        entry.clear()
        entry["mark"] = f"{newest:.6f}"
        return True

    def replies(
        self, thread: str, r: ItemReader, *, channel: str, container: str, link: str | None
    ) -> None:
        try:
            for page, _, _ in self.api.pages(
                "conversations.replies",
                "messages",
                {"channel": channel, "ts": thread, "limit": "200"},
            ):
                for reply in page:
                    if str(reply.get("ts")) == thread:
                        continue  # the thread's first message, read already
                    # A thread is read with its first message: past the channel's cap, never
                    # past the budget (a thread cut here is not read again).
                    if not r.room():
                        return
                    # Its link opens the thread it was read from.
                    self.message(
                        {"thread_ts": thread, **reply},
                        r,
                        channel=channel,
                        container=container,
                        link=link,
                        part="reply",
                    )
        except Exception as err:  # the thread's first message still counts
            r.cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))

    def message(
        self,
        msg: dict[str, Any],
        r: ItemReader,
        *,
        channel: str,
        container: str,
        link: str | None,
        part: str = "message",
    ) -> None:
        ts = str(msg.get("ts") or "")
        item_id = f"{channel}/{ts}"
        location = f"{self.id}\n{item_id}"
        r.cov.listed += 1
        r.cov.eligible += 1
        if sample_point(item_id) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        text = message_text(msg)
        r.budget.take(len(text))
        self.read += 1
        resource = saas_item(
            VENDOR, self.service, self.tenant, item_id, part, container=container, channel=channel
        )
        # The exact message, or its thread, and its files with it; a conversation with no
        # link (direct messages) gives its messages none.
        here = None if link is None else message_link(self.team, channel, msg)
        findings = r.text(text, resource, here) if text else []
        for f in msg.get("files") or []:
            if isinstance(f, dict):
                findings.extend(self.file(f, r, channel=channel, container=container, link=here))
        r.store.replace_location(location, findings)

    # The read path (`slack_read.py`, the `adapter:<kind>` component, #67).
    file = _read_path.file

    def failed(self, err: BaseException, cov: Coverage) -> str | None:
        gap = gap_of(err)
        cov.error = None if gap == "throttled" else error_name(err)
        log_event("source.failed", source=self.target, error=error_name(err))
        return gap if cov.scanned == 0 else None


def joinable(c: dict[str, Any]) -> bool:
    """A channel the opt-in join may enter: public, not archived, not Slack Connect (#139).

    Private channels (a bot must be invited), archived ones (Slack refuses), direct
    messages, and channels shared with another organization or pending such a share
    (`is_ext_shared`, `is_pending_ext_shared`) are never joined: they stay `not_a_member`.
    """
    return not any(
        c.get(k)
        for k in ("is_private", "is_group", "is_im", "is_mpim", "is_archived", "is_ext_shared")
    ) and not c.get("is_pending_ext_shared")


class Joiner:
    """The opt-in join (#139): one per discovery, on only with `SLACK_JOIN_PUBLIC_CHANNELS`."""

    def __init__(self, ctx: Context) -> None:
        self.api: Slack = ctx.clients.slack
        self.clients = ctx.clients
        granted = self.api.granted
        # Slack named the token's scopes (auth.test's header) and channels:join is not one:
        # nothing is tried. Not named: the first join's `missing_scope` says so.
        self.missing = granted is not None and JOIN_SCOPE not in granted
        self.stopped = False  # Slack throttled the joins past the run: the rest wait
        self.joined = 0

    def join(self, store: Store, channel: str) -> bool:
        """Join `channel` for `store`. True when the bot is now a member; False leaves the
        store `not_a_member`, with why in `error` (and the setting in `toggle`)."""
        if self.missing:
            store.skip("not_a_member", f"missing_scope:{JOIN_SCOPE}", toggle=JOIN_SETTING)
            return False
        if self.stopped:
            store.skip("not_a_member", "Throttled", toggle=JOIN_SETTING)
            return False
        try:
            self.api.join(channel)
        except Exception as err:  # Slack's code only, never its message
            name = error_name(err)
            if name == "missing_scope":
                self.missing = True
                name = f"missing_scope:{JOIN_SCOPE}"
                log_event("slack.join_scope_missing", setting=JOIN_SETTING)
            elif name == "Throttled":
                self.stopped = True
            store.skip("not_a_member", name, toggle=JOIN_SETTING)
            return False
        at = _dt.datetime.fromtimestamp(self.clients.now(), _dt.UTC)
        store.extra["joinedByScanner"] = {
            "action": JOINED,
            "channelId": channel,
            "joinedAt": at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        self.joined += 1
        log_event("slack.joined", kind="slack_channel")
        return True


class ChannelAdapter:
    kind = "slack_channel"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sl = ctx.settings.slack
        if sl is None:  # pragma: no cover - only when configured
            return
        _, tenant = team_of(ctx)
        bot = sl.token.reveal().startswith("xoxb-")
        wanted = set(sl.channels)
        # #139: off (the default), there is no joiner and nothing below calls a join.
        joiner = Joiner(ctx) if sl.join_public and bot else None
        for page, _, _ in ctx.clients.slack.pages(
            "conversations.list",
            "channels",
            {
                "types": "public_channel,private_channel",
                "exclude_archived": "false",
                "limit": "200",
            },
        ):
            for c in page:
                cid = str(c.get("id") or "")
                if not cid or (wanted and cid not in wanted):
                    continue
                name = "#" + str(c.get("name") or cid)
                store = Store(self.kind, name)
                store.extra.update(store_fields(VENDOR, tenant_hash(tenant)))
                store.facts = vendor_facts(sl.ekm_key_id)
                store.table = Channel(cid, name)
                out.stores.append(store)
                if bot and not c.get("is_member"):
                    if joiner is None or not joinable(c):
                        store.skip("not_a_member")
                        continue
                    # The rules first: a channel they leave out is never joined.
                    if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                        continue
                    if not joiner.join(store, cid):
                        continue
                elif not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                    continue
                pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
                store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> ChannelSource | None:
        t = store.table
        if not isinstance(t, Channel):
            return None
        return ChannelSource(ctx, t, store.name, store.sample_percent or 100)


class ChannelSource(_Messages):
    kind = "slack_channel"
    service = "channel"
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(
        self, ctx: Context, channel: Channel, store_name: str, sample_percent: int
    ) -> None:
        self.channel = channel
        self.id = f"{self.kind}:{channel.channel_id}"
        super().__init__(ctx, store_name, sample_percent)

    def __repr__(self) -> str:
        return f"ChannelSource({self.channel!r})"

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
        op = r.index = ObjectPass(
            self.indexes, self.id, self.kind, columnar=r.columnar, budget=budget
        )
        rescans = AttachmentRescans(r, cursor, prefix=f"{self.id}\n")
        floor = (now - _dt.timedelta(days=s.lookback_days)).timestamp()
        mine = ("indexPass", "indexed", "rescan", "full")
        entry = {k: v for k, v in cursor.items() if k not in mine}
        # The first read of the channel reads every message in the look-back, and its files.
        first = not entry or bool(cursor.get("full"))
        entry = entry or {"mark": f"{floor:.6f}"}
        note: str | None = None
        done = False
        try:
            done = self.conversation(
                "conversations.history",
                {"channel": self.channel.channel_id},
                entry,
                r,
                channel=self.channel.channel_id,
                container=self.channel.name,
                link=channel_link(self.team, self.channel.channel_id),
                threads=True,
            )
            if done and first and op.index is not None:
                rescans.indexed = True
            if done and rescans.due():
                # Then the files a changed component read, within the share (#67).
                rescans.run(
                    lambda at: self._file_pages(at, floor, r), sample_percent=self.sample_percent
                )
        except Exception as err:  # recorded by name on the source
            note = self.failed(err, cov)
        cov.pass_complete = done and cov.error is None
        if not done and cov.error is None:
            cov.backlog = True
        out = dict(entry)
        if first and not done:
            out["full"] = True
        rescans.save(out)
        op.settle(cov)
        return SourceRun(cov, out, note=note)

    def _file_pages(self, at: Any, floor: float, r: ItemReader) -> Iterator[AttachmentPage]:
        """The channel's files in the look-back (#67), a page at a time; `at` is the cursor of
        the page where a pass stopped."""
        channel = self.channel.channel_id
        params = {"channel": channel, "ts_from": f"{floor:.0f}", "limit": "200"}
        cursor = str(at) if isinstance(at, str) and at else None
        for page, nxt, _ in self.api.pages("files.list", "files", params, cursor=cursor):
            items: list[Attachment] = []
            for f in page:
                fid = str(f.get("id") or "")
                url = str(f.get("url_private_download") or f.get("url_private") or "")
                if (
                    not fid
                    or f.get("mode") in ("tombstone", "hidden_by_limit")
                    or f.get("is_external")
                    or urllib.parse.urlsplit(url).hostname != "files.slack.com"
                ):
                    continue
                items.append(
                    Attachment(
                        key=fid,
                        size=int(f.get("size") or 0),
                        sample=fid,
                        location=f"{self.id}\n{channel}/{fid}",
                        read=functools.partial(
                            self.file,
                            f,
                            r,
                            channel=channel,
                            container=self.channel.name,
                            link=shared_link(self.team, channel, f),
                        ),
                    )
                )
            yield items, cursor
            cursor = nxt


class DiscoveryAdapter:
    """Direct and group messages, through the Discovery API (Enterprise Grid), opt-in."""

    kind = "slack_dm"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sl = ctx.settings.slack
        if sl is None:  # pragma: no cover - only when configured
            return
        _, tenant = team_of(ctx)
        store = Store(self.kind, "direct-messages")
        store.extra.update(store_fields(VENDOR, tenant_hash(tenant)))
        store.facts = vendor_facts(sl.ekm_key_id)
        out.stores.append(store)
        if apply_rules(store, ctx.settings.allow, ctx.settings.deny):
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent
            store.table = "discovery"

    def source(self, ctx: Context, store: Store) -> DirectSource | None:
        if store.table != "discovery":
            return None
        return DirectSource(ctx, store.name, store.sample_percent or 100)


class DirectSource(_Messages):
    kind = "slack_dm"
    service = "dm"

    def __init__(self, ctx: Context, store_name: str, sample_percent: int) -> None:
        self.id = f"{self.kind}:org"
        super().__init__(ctx, store_name, sample_percent)

    def __repr__(self) -> str:
        return "DirectSource()"

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
        floor = (now - _dt.timedelta(days=s.lookback_days)).timestamp()
        marks: dict[str, Any] = dict(cursor.get("conversations") or {})
        note: str | None = None
        complete = True
        try:
            found: list[tuple[str, str]] = []
            for kind in ("only_im", "only_mpim"):
                for page, _, _ in self.api.pages(
                    "discovery.conversations.list", "channels", {kind: "true", "limit": "1000"}
                ):
                    found.extend(
                        (str(c["id"]), str(c.get("team_id") or "")) for c in page if c.get("id")
                    )
            for conv, team in sorted(set(found)):
                if not self.room(r):
                    complete = False
                    break
                got = marks.get(conv)
                entry = dict(got) if isinstance(got, dict) else {"mark": f"{floor:.6f}"}
                base = {"channel": conv, **({"team": team} if team else {})}
                done = self.conversation(
                    "discovery.conversations.history",
                    base,
                    entry,
                    r,
                    channel=conv,
                    container="direct-messages",
                    link=None,
                    threads=False,
                )
                marks[conv] = entry
                if not done:
                    complete = False
                    break
        except Exception as err:  # recorded by name on the source
            note = self.failed(err, cov)
            complete = False
        cov.pass_complete = complete and cov.error is None
        if not complete and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"conversations": marks}, note=note)
