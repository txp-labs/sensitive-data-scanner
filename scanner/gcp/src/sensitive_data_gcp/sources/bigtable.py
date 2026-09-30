"""Bigtable: every table, sampled with one `readRows`. Read by default.

**Discovery** (`DISCOVER` includes `bigtable`): Cloud Asset Inventory lists
every Bigtable table in scope (`bigtableadmin.googleapis.com/Table`); each
instance's clusters (`bigtable.clusters.list`) say which key encrypts it. A
store is one table, `instance/table`.

**Reading** is one `readRows` per table with `bigtable.tables.readRows`
(Bigtable Reader): the first `BIGTABLE_MAX_ROWS` rows, only the latest cell
of each column (`cellsPerColumnLimitFilter: 1`). A row is read by column,
`family:qualifier`, and its row key as the column `rowKey`, since a key can
hold a value too. Cells that are not text are not read. `readRows` cannot
write.

**Encryption (1.5):** a cluster's Cloud KMS key (`encryptionConfig`), hashed,
else Google's own keys (`service_managed`).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows
from sensitive_data_core.scan.item import looks_binary

from ..clients import Rest
from ..resources import Located, console_link
from .base import Context, kms_facts, labels
from .common import call_gap

KIND = "bigtable"
ADMIN = "https://bigtableadmin.googleapis.com/v2"
DATA = "https://bigtable.googleapis.com/v2"
ASSET_TYPE = "bigtableadmin.googleapis.com/Table"
ROW_KEY = "rowKey"
MAX_CELL_BYTES = 64 * 1024


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def text(raw: Any) -> str | None:
    """A base64 cell, key or qualifier as text; None when it is not text."""
    try:
        data = base64.b64decode(str(raw or ""), validate=True)[:MAX_CELL_BYTES]
    except (binascii.Error, ValueError):
        return None
    if not data or looks_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def _family(v: Any) -> str:
    return str(v.get("value") if isinstance(v, dict) else v or "")


def decode_rows(messages: Any) -> list[dict[str, Any]]:
    """The rows of a `readRows` response (its messages' chunks), by `family:qualifier`."""
    msgs = messages if isinstance(messages, list) else [messages]
    rows: list[dict[str, Any]] = []
    key: str | None = None
    family = qualifier = ""
    current: dict[str, Any] = {}
    buf = b""
    for msg in msgs:
        chunks = msg.get("chunks") if isinstance(msg, dict) else None
        for ch in chunks or []:
            if ch.get("resetRow"):
                current, buf = {}, b""
                continue
            if ch.get("rowKey"):
                key = text(ch["rowKey"])
            if "familyName" in ch:
                family = _family(ch["familyName"])
            if "qualifier" in ch:
                q = ch["qualifier"]
                qualifier = text(q.get("value") if isinstance(q, dict) else q) or "?"
            try:
                buf += base64.b64decode(str(ch.get("value") or ""), validate=True)
            except (binascii.Error, ValueError):
                buf = b""
            if int(ch.get("valueSize") or 0) == 0:
                column = f"{family}:{qualifier}"
                if column not in current and buf and not looks_binary(buf[:MAX_CELL_BYTES]):
                    current[column] = buf[:MAX_CELL_BYTES].decode("utf-8", errors="replace")
                buf = b""
            if ch.get("commitRow"):
                rows.append({ROW_KEY: key, **current})
                current = {}
    return rows


@dataclass
class TableTarget:
    project: str
    instance: str
    table: str
    where: Located

    def __repr__(self) -> str:
        return f"BigtableTarget({redact_digits(self.instance)!r}, {redact_digits(self.table)!r})"


class BigtableAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        keys: dict[tuple[str, str], dict[str, str]] = {}
        for row in ctx.search(ASSET_TYPE):
            parts = str(row.get("name") or "").split("/")
            try:
                project = parts[parts.index("projects") + 1]
                instance = parts[parts.index("instances") + 1]
                table = parts[parts.index("tables") + 1]
            except (ValueError, IndexError):
                continue
            where = Located(project, str(row.get("name") or ""))
            store = Store(KIND, f"{instance}/{table}", tags=labels(row))
            store.extra.update(where.fields())
            if (project, instance) not in keys:
                keys[(project, instance)] = self._key(ctx, project, instance)
            store.facts = dict(keys[(project, instance)])
            store.table = TableTarget(project, instance, table, where)
            out.stores.append(store)
            apply_rules(store, ctx.settings.allow, ctx.settings.deny)

    def _key(self, ctx: Context, project: str, instance: str) -> dict[str, str]:
        url = f"{ADMIN}/projects/{_q(project)}/instances/{_q(instance)}/clusters"
        try:
            clusters = ctx.rest.get(url).get("clusters") or []
        except Exception as err:  # the key stays Google's; the tables are still listed
            log_event("discovery.failed", kind=KIND, error=error_name(err))
            return kms_facts(None)
        key = next(
            (
                str((c.get("encryptionConfig") or {}).get("kmsKeyName"))
                for c in clusters
                if isinstance(c, dict) and (c.get("encryptionConfig") or {}).get("kmsKeyName")
            ),
            None,
        )
        return kms_facts(key)

    def source(self, ctx: Context, store: Store) -> BigtableSource | None:
        t = store.table
        if not isinstance(t, TableTarget):
            return None
        return BigtableSource(ctx.rest, t, max_rows=ctx.settings.bigtable_max_rows)


class BigtableSource:
    """One table: its first rows, the latest cell of each column."""

    kind = KIND

    def __init__(self, rest: Rest, target: TableTarget, *, max_rows: int = 1000) -> None:
        self.rest = rest
        self.t = target
        self.max_rows = max_rows
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"bigtable:{target.instance}/{target.table}"
        self.target = f"{target.instance}/{target.table}"

    def __repr__(self) -> str:
        return f"BigtableSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target, listed=1, eligible=1)
        if not budget.has():
            cov.backlog = True
            return SourceRun(cov, cursor, note="budget")
        t = self.t
        path = f"projects/{_q(t.project)}/instances/{_q(t.instance)}/tables/{_q(t.table)}"
        body = {"rowsLimit": str(self.max_rows), "filter": {"cellsPerColumnLimitFilter": 1}}
        try:
            rows = decode_rows(self.rest.post(f"{DATA}/{path}:readRows", body))
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            gap = call_gap(err)
            return SourceRun(cov, cursor, note=gap if gap == "network" else None)
        size = len(json.dumps(rows, default=str))
        budget.take(size)
        columns = list(dict.fromkeys(k for r in rows for k in r))
        result = scan_rows("json", columns, rows, detector, self.max_rows)
        cov.scanned, cov.bytes_scanned, cov.pass_complete = 1, size, True
        cov.partial = int(len(rows) >= self.max_rows)
        cov.formats["json"] = 1
        cov.test_values, cov.suppressed = result.test_values, result.suppressed
        cov.redaction_markers = result.redaction_markers

        def resource(column: str) -> dict[str, Any]:
            out = store_field_resource(
                service=KIND, store=t.instance, table=t.table, field=column, read_by="read_rows"
            )
            out.update(t.where.fields())
            return out

        link = console_link(
            f"bigtable/instances/{_q(t.instance)}/tables/{_q(t.table)}/overview",
            {"project": t.project},
            t.instance,
            t.table,
        )
        store.replace_location(
            f"{self.id}\n",
            column_findings(result, resource, link, now.isoformat(), facts=self.facts),
        )
        return SourceRun(cov, {})
