"""Archives: EventBridge archives and S3 Glacier vaults, reported by default (#35).

**EventBridge archives** (`DISCOVER` includes `eventbridge`): `ListArchives`,
`DescribeArchive`: each archive is reported with its size (`sizeBytes`), its
events (`eventCount`) and how long it keeps them (`retentionDays`). An archive
has no read API; its events come back only by a **replay**, which sends them to
the bus the archive belongs to. That is opt-in (`EVENTBRIDGE_REPLAY`), and it
reaches **only the scanner's own target**:

1. On the archive's bus, the scanner puts its own rule for that archive,
   `sensitive-data-scanner-replay-<hash>`, whose pattern matches only events
   the scanner replays from that archive (`replay-name` starting
   `sds-<hash>-`), targeting the scanner's own SQS queue
   (`EVENTBRIDGE_REPLAY_QUEUE_URL`, created by the template).
2. `StartReplay` of the last `EVENTBRIDGE_REPLAY_HOURS` of the archive, with
   `FilterArns` naming only that rule: none of the bus's other rules (the
   customer's) receives a replayed event.
3. Later runs wait for the replay (`DescribeReplay`), then receive the events
   from the scanner's queue (up to `EVENTBRIDGE_REPLAY_MAX_EVENTS`), read each
   event's `detail`, and delete them from that queue: it is the scanner's own.
4. When the queue is empty, the rule's target and the rule are removed.

A run starts at most `MAX_EXPORTS_PER_RUN` replays (shared with the exports),
and replays an archive again no sooner than `EXPORT_MIN_INTERVAL_DAYS`.

**S3 Glacier vaults** (`glacier`, the legacy vault API): `ListVaults`, each
reported as `archive_retrieval` with its archives (`archives`) and size. Reading
an archive needs a retrieval job (hours, and billed); the scanner starts none,
and the role denies `InitiateJob`.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
import urllib.parse
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.item import scan_item_text

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import ExportQuota, drop_other_passes, due, merge

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("events", "sqs", "glacier")

REPLAY_RULE = "sensitive-data-scanner-replay-"  # and the archive's hash: one rule per archive
REPLAY_PREFIX = "sds-"
REPLAYING = frozenset({"STARTING", "RUNNING"})


# ------------------------------------------------------------------ EventBridge archives


class EventBridgeArchiveAdapter:
    kind = "eventbridge_archive"

    def discover(self, ctx: Context, out: Discovery) -> None:
        events = ctx.clients.client("events")
        keys = classifier(ctx.clients)
        names: list[str] = []
        token: str | None = None
        while True:
            r = events.list_archives(**({"NextToken": token} if token else {}))
            names.extend(str(a["ArchiveName"]) for a in r.get("Archives", []))
            token = r.get("NextToken")
            if not token:
                break
        for name in names:
            store = Store(self.kind, name)
            out.stores.append(store)
            try:
                d = events.describe_archive(ArchiveName=name)
            except Exception as err:
                store.status, store.error = "error", error_name(err)
                store.reason = reason_for(store.error)
                continue
            store.size_bytes = int(d.get("SizeBytes") or 0)
            store.extra.update(
                eventCount=int(d.get("EventCount") or 0),
                retentionDays=int(d.get("RetentionDays") or 0),
            )
            key = d.get("KmsKeyIdentifier")
            store.facts = keys.facts(key=key, aws_owned=not key)
            state = str(d.get("State") or "")
            if state != "ENABLED":
                store.skip("unsupported")
                store.extra["state"] = state[:60]
                continue
            decide(store, ctx.config)
            if store.status != "pending":
                continue
            c = ctx.config
            if not (c.eventbridge_replay and c.eventbridge_replay_queue_url):
                store.skip("read_not_configured")  # an archive is read only by a replay
                continue
            store.extra["arn"] = str(d.get("ArchiveArn"))
            store.extra["bus"] = str(d.get("EventSourceArn"))

    def source(self, ctx: Context, store: Store) -> EventBridgeReplaySource | None:
        c = ctx.config
        if not store.extra.get("arn") or ctx.quota is None:
            return None
        return EventBridgeReplaySource(
            ctx.clients.client("events"),
            ctx.clients.client("sqs"),
            name=store.name,
            archive_arn=str(store.extra["arn"]),
            bus_arn=str(store.extra["bus"]),
            queue_url=str(c.eventbridge_replay_queue_url),
            queue_arn=str(c.eventbridge_replay_queue_arn),
            region=ctx.region,
            quota=ctx.quota,
            hours=c.eventbridge_replay_hours,
            max_events=c.eventbridge_replay_max_events,
            min_interval_days=c.export_min_interval_days,
        )


class EventBridgeReplaySource:
    """One archive, read by a replay to the scanner's own rule and queue (opt-in)."""

    kind = "eventbridge_archive"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        events: Any,
        sqs: Any,
        *,
        name: str,
        archive_arn: str,
        bus_arn: str,
        queue_url: str,
        queue_arn: str,
        region: str,
        quota: ExportQuota,
        hours: int = 24,
        max_events: int = 1000,
        min_interval_days: int = 7,
    ) -> None:
        self.events = events
        self.sqs = sqs
        self.name = name
        self.archive_arn = archive_arn
        self.bus_arn = bus_arn
        self.queue_url = queue_url
        self.queue_arn = queue_arn
        self.region = region
        self.quota = quota
        self.hours = hours
        self.max_events = max_events
        self.min_interval_days = min_interval_days
        digest = hashlib.sha256(archive_arn.encode()).hexdigest()
        self.id = f"ebarchive:{digest[:16]}"
        self.target = name
        self.rule = f"{REPLAY_RULE}{digest[:12]}"
        self.replay_prefix = f"{REPLAY_PREFIX}{digest[:12]}-"

    def link(self) -> str:
        q = urllib.parse.quote(self.name, safe="")
        return console_link(self.region, f"events/home?region={self.region}#/archive/{q}")

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        c = dict(cursor)
        try:
            if not c.get("replay"):
                return self._start(c, cov, now)
            if c.get("phase") == "replaying":
                r = self.events.describe_replay(ReplayName=c["replay"])
                state = str(r.get("State") or "").upper()
                if state in REPLAYING:
                    cov.backlog = True
                    return SourceRun(cov, c, "export_pending", {})
                if state != "COMPLETED":
                    self._clean_up()
                    cov.error = "ReplayFailed"
                    log_event("source.failed", source=self.target, error=cov.error)
                    return SourceRun(cov, {"lastReplayAt": c.get("lastReplayAt")}, None, {})
                c["phase"] = "reading"
            return self._read(c, cov, budget, detector, store, now)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, cursor, None, {})

    def _rule_arn(self) -> str:
        r = self.events.put_rule(
            Name=self.rule,
            EventBusName=self.bus_arn,
            EventPattern=json.dumps({"replay-name": [{"prefix": self.replay_prefix}]}),
            State="ENABLED",
            Description="sensitive-data-scanner: replayed events to its own queue only",
        )
        self.events.put_targets(
            Rule=self.rule,
            EventBusName=self.bus_arn,
            Targets=[{"Id": "sensitive-data-scanner", "Arn": self.queue_arn}],
        )
        return str(r["RuleArn"])

    def _clean_up(self) -> None:
        self.events.remove_targets(
            Rule=self.rule, EventBusName=self.bus_arn, Ids=["sensitive-data-scanner"]
        )
        self.events.delete_rule(Name=self.rule, EventBusName=self.bus_arn)

    def _start(self, c: dict[str, Any], cov: Coverage, now: _dt.datetime) -> SourceRun:
        if not due(c.get("lastReplayAt"), now, self.min_interval_days):
            cov.pass_complete = True
            return SourceRun(cov, c, None, {})
        if not self.quota.take():
            cov.backlog = True
            return SourceRun(cov, c, "budget", {})
        rule_arn = self._rule_arn()
        name = f"{self.replay_prefix}{now.strftime('%Y%m%d%H%M%S')}"
        end = now - _dt.timedelta(minutes=5)
        self.events.start_replay(
            ReplayName=name,
            EventSourceArn=self.archive_arn,
            EventStartTime=end - _dt.timedelta(hours=self.hours),
            EventEndTime=end,
            Destination={"Arn": self.bus_arn, "FilterArns": [rule_arn]},
        )
        started = {
            "lastReplayAt": c.get("lastReplayAt"),
            "replay": name,
            "phase": "replaying",
            "passId": secrets.token_hex(8),
            "read": 0,
        }
        cov.backlog = True
        return SourceRun(cov, started, "export_pending", {})

    def _read(  # noqa: PLR0917 - the reading phase of one replay
        self,
        c: dict[str, Any],
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        seen_at, link = now.isoformat(), self.link()
        pass_id = str(c["passId"])
        resource = store_field_resource(
            service="eventbridge", store=self.name, field="events", read_by="replay"
        )
        empty = False
        while int(c.get("read") or 0) < self.max_events and budget.has(0):
            r = self.sqs.receive_message(
                QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            )
            messages = r.get("Messages", [])
            if not messages:
                empty = True
                break
            for m in messages:
                body = str(m.get("Body") or "")
                try:
                    event = json.loads(body)
                except ValueError:
                    event = {}
                if isinstance(event, dict) and event.get("replay-name") == c["replay"]:
                    c["read"] = int(c.get("read") or 0) + 1
                    text = json.dumps(event.get("detail"), default=str)
                    budget.take(len(text))
                    item = scan_item_text("event.json", text, detector)
                    cov.scanned += 1
                    cov.bytes_scanned += len(text)
                    cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                    cov.test_values += item.test_values
                    cov.suppressed += item.suppressed
                    for f in class_findings(
                        item.findings, resource, link, item.format, seen_at, facts=self.facts
                    ):
                        merge(store, f"{self.id}\n{self.name}", f, pass_id)
                # The scanner's own queue: every message is taken off once seen.
                self.sqs.delete_message(
                    QueueUrl=self.queue_url, ReceiptHandle=str(m["ReceiptHandle"])
                )
        cov.listed = cov.eligible = int(c.get("read") or 0)
        cov.partial = int(int(c.get("read") or 0) >= self.max_events)
        if not (empty or cov.partial):
            cov.backlog = True
            return SourceRun(cov, c, None, {})
        self._clean_up()
        cov.pass_complete = True
        drop_other_passes(store, self.id, pass_id)
        return SourceRun(cov, {"lastReplayAt": now.isoformat()}, None, {})


# ------------------------------------------------------------------ S3 Glacier vaults


class GlacierAdapter:
    kind = "glacier"

    def discover(self, ctx: Context, out: Discovery) -> None:
        glacier = ctx.clients.client("glacier")
        keys = classifier(ctx.clients)
        for page in glacier.get_paginator("list_vaults").paginate(accountId="-"):
            for v in page.get("VaultList", []):
                store = Store(self.kind, str(v.get("VaultName")))
                out.stores.append(store)
                store.size_bytes = int(v.get("SizeInBytes") or 0)
                store.extra["archives"] = int(v.get("NumberOfArchives") or 0)
                store.facts = keys.facts(aws_owned=True)  # Glacier always encrypts (AES-256)
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        t = glacier.list_tags_for_vault(accountId="-", vaultName=store.name)
                        store.tags = {str(k): str(x) for k, x in (t.get("Tags") or {}).items()}
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status == "pending":
                    store.skip("archive_retrieval")  # a retrieval job would be needed

    def source(self, ctx: Context, store: Store) -> None:
        return None
