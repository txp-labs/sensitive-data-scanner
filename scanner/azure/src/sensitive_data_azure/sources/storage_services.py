"""Table Storage and Queue Storage: sampled entities, and peeked messages. Read by default.

**Discovery** is the storage accounts' Resource Graph listing that blobs use,
then each account's tables and queues from Resource Manager (Reader), so a
table or queue the job cannot reach is still in the run summary.

**Tables** (`azure_table`, `account/table`) are read with Storage Table Data
Reader: the first `TABLE_MAX_ENTITIES` entities of each table (Query
Entities), read by property, so a finding names the property (`field`), as a
column. Nothing is inserted, updated or deleted.

**Queues** (`azure_queue`, `account/queue`) are read with Storage Queue Data
Reader, by **Peek Messages only**: up to 32 messages at the front of the queue,
which stay where they are, visible to their consumers, with their dequeue
count unchanged. The scanner never gets, dequeues, updates or deletes a
message. Base64-encoded messages (the Storage SDKs' default for binary) are
decoded when that gives text.

**Encryption (1.5).** A table's or queue's key is the account's key when the
account's encryption covers that service with its own key (`keyType:
Account`), else a key Microsoft manages (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import itertools
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import (
    Budget,
    FindingStore,
    SourceRun,
    class_findings,
    column_findings,
)
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows
from sensitive_data_core.scan.item import scan_item_text

from ..resources import ResourceId, azure_fields, portal_link
from .base import Context, key_facts
from .blob import STORAGE_ACCOUNTS, STORAGE_API, _account_key_uri, _tags
from .common import http_gap, merge_items, message_text, plain

MAX_PEEK = 32  # what Peek Messages returns at most


@dataclass
class ServiceTarget:
    """One table or queue of a storage account, and where its service is."""

    rid: ResourceId  # the storage account
    account: str
    name: str
    endpoint: str

    def __repr__(self) -> str:
        return f"ServiceTarget({redact_digits(self.account)!r}, {redact_digits(self.name)!r})"


class _StorageServiceAdapter:
    kind = ""
    service = ""  # table | queue
    children = ""  # tableServices/default/tables | queueServices/default/queues

    def discover(self, ctx: Context, out: Discovery) -> None:
        arm = ctx.clients.client("arm")
        for row in ctx.graph(STORAGE_ACCOUNTS):
            endpoint = str(row.get(f"{self.service}Endpoint") or "")
            if not endpoint:
                continue
            rid = ResourceId.parse(str(row.get("id") or ""))
            account = str(row.get("name") or rid.name)
            if str(row.get(f"{self.service}KeyType") or "").lower() == "account":
                facts = key_facts(str(row.get("keySource") or ""), _account_key_uri(row))
            else:
                facts = key_facts("Microsoft.Storage")
            restricted = (
                str(row.get("publicNetworkAccess") or "").lower() == "disabled"
                or str(row.get("defaultAction") or "").lower() == "deny"
            )
            try:
                names = [
                    str(x.get("name") or "")
                    for x in arm.list(f"{rid.value}/{self.children}", STORAGE_API)
                ]
            except Exception as err:  # the account is reported, its tables or queues unknown
                store = Store(self.kind, f"{account}/*", tags=_tags(row.get("tags")))
                store.extra.update(azure_fields(rid))
                store.status, store.error = "error", error_name(err)
                store.reason = reason_for(store.error)
                out.stores.append(store)
                continue
            for name in names:
                if not name:
                    continue
                store = Store(self.kind, f"{account}/{name}", tags=_tags(row.get("tags")))
                store.extra.update(azure_fields(rid))
                if restricted:
                    store.extra["networkRestricted"] = True
                store.facts = dict(facts)
                store.table = ServiceTarget(rid, account, name, endpoint)
                out.stores.append(store)
                apply_rules(store, ctx.settings.allow, ctx.settings.deny)


class TableAdapter(_StorageServiceAdapter):
    kind = "azure_table"
    service = "table"
    children = "tableServices/default/tables"

    def source(self, ctx: Context, store: Store) -> TableSource | None:
        t = store.table
        if not isinstance(t, ServiceTarget):
            return None
        client = ctx.clients.client("table", t.endpoint).get_table_client(t.name)
        return TableSource(client, t, max_entities=ctx.settings.table_max_entities)


class QueueAdapter(_StorageServiceAdapter):
    kind = "azure_queue"
    service = "queue"
    children = "queueServices/default/queues"

    def source(self, ctx: Context, store: Store) -> QueueSource | None:
        t = store.table
        if not isinstance(t, ServiceTarget):
            return None
        return QueueSource(ctx.clients.client("queue", t.endpoint).get_queue_client(t.name), t)


class TableSource:
    """One table: its first entities, read by property."""

    kind = "azure_table"

    def __init__(self, client: Any, target: ServiceTarget, *, max_entities: int = 1000) -> None:
        self.client = client
        self.t = target
        self.max_entities = max_entities
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"table:{target.account}/{target.name}"
        self.target = f"{target.account}/{target.name}"

    def __repr__(self) -> str:
        return f"TableSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target, listed=1, eligible=1)
        if not budget.has():
            cov.backlog = True
            return SourceRun(cov, cursor, note="budget")
        try:
            pages = self.client.list_entities(results_per_page=min(self.max_entities, 1000))
            rows = [plain(dict(e)) for e in itertools.islice(pages, self.max_entities)]
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        size = len(json.dumps(rows, default=str))
        budget.take(size)
        columns = list(dict.fromkeys(k for r in rows for k in r))
        result = scan_rows("json", columns, rows, detector, self.max_entities)
        cov.scanned, cov.bytes_scanned, cov.pass_complete = 1, size, True
        cov.partial = int(len(rows) >= self.max_entities)
        cov.formats["json"] = 1
        cov.test_values, cov.suppressed = result.test_values, result.suppressed
        cov.redaction_markers = result.redaction_markers
        t = self.t

        def resource(column: str) -> dict[str, Any]:
            out = store_field_resource(
                service=self.kind, store=t.account, table=t.name, field=column, read_by="sample"
            )
            out.update(azure_fields(t.rid))
            return out

        link = portal_link(t.rid, "storagebrowser")
        store.replace_location(
            f"{self.id}\n",
            column_findings(result, resource, link, now.isoformat(), facts=self.facts),
        )
        return SourceRun(cov, {})


class QueueSource:
    """One queue: the messages at its front, peeked (never dequeued)."""

    kind = "azure_queue"

    def __init__(self, client: Any, target: ServiceTarget) -> None:
        self.client = client
        self.t = target
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"queue:{target.account}/{target.name}"
        self.target = f"{target.account}/{target.name}"

    def __repr__(self) -> str:
        return f"QueueSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        if not budget.has():
            cov.backlog = True
            return SourceRun(cov, cursor, note="budget")
        try:
            messages = list(self.client.peek_messages(max_messages=MAX_PEEK))
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        cov.listed = cov.eligible = len(messages)
        items = []
        for m in messages:
            text = message_text(getattr(m, "content", None))
            if text is None:
                cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                continue
            budget.take(len(text))
            item = scan_item_text("message.json", text, detector)
            items.append(item)
            cov.scanned += 1
            cov.bytes_scanned += len(text)
            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            cov.redaction_markers += item.redaction_markers
        cov.pass_complete = True
        t = self.t
        resource = store_field_resource(
            service=self.kind, store=t.account, table=t.name, field="messages", read_by="peek"
        )
        resource.update(azure_fields(t.rid))
        fmt = Counter(i.format for i in items).most_common(1)[0][0] if items else "text"
        found = class_findings(
            merge_items(items),
            resource,
            portal_link(t.rid, "storagebrowser"),
            fmt,
            now.isoformat(),
            facts=self.facts,
        )
        store.replace_location(f"{self.id}\n", found)
        return SourceRun(cov, {})
