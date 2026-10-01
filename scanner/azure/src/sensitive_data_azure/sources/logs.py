"""Azure Monitor logs: Log Analytics workspaces, sampled with KQL. Read by default.

**Discovery** (Resource Graph, Reader) lists every Log Analytics workspace in
scope, with its query network access and its dedicated cluster's customer key
(Azure Monitor's customer-managed keys live on a cluster). A workspace-based
Application Insights resource writes to its workspace and is read there;
diagnostic settings that archive to a storage account are read as blobs.

**Reading** is the Log Analytics query API with **Log Analytics Reader**, as
the job's identity. For each workspace:

1. `Usage` says which tables took data in the lookback window
   (`LOGS_LOOKBACK_DAYS`, 1), so empty tables cost nothing;
2. each such table is sampled with `['<table>'] | where TimeGenerated > ago(Nd)
   | take n` (`LOGS_MAX_ROWS_PER_TABLE`, 500), the table name quoted so that
   nothing in it is KQL, and read by column, so a finding names the column;
3. a table on the Basic or Auxiliary plan is billed per query, so it is not
   read: it is counted as skipped `billed_plan` (the plans come from Resource
   Manager, Reader);
4. a workspace the budget does not finish resumes at its next table.

Only queries are sent: KQL cannot write, and the role cannot either.

**Encryption (1.5):** a workspace linked to a dedicated cluster with a Key
Vault key is `customer_managed_key` (hashed); otherwise Azure Monitor's own
keys (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows

from ..resources import ResourceId, azure_fields, portal_link
from .base import Context, key_facts
from .common import http_gap, plain

KIND = "log_analytics"
TABLES_API = "2022-10-01"
BILLED_PLANS = frozenset({"basic", "auxiliary"})
MAX_TABLES = 500

WORKSPACES = """resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project id, name, tags,
    customerId = tostring(properties.customerId),
    queryAccess = tostring(properties.publicNetworkAccessForQuery),
    cluster = tolower(tostring(properties.features.clusterResourceId))
| order by id asc"""
CLUSTERS = """resources
| where type =~ 'microsoft.operationalinsights/clusters'
| project id = tolower(id),
    vault = tostring(properties.keyVaultProperties.keyVaultUri),
    keyName = tostring(properties.keyVaultProperties.keyName)
| order by id asc"""


def kql_table(name: str) -> str:
    """A table name as KQL: `['name']`, so that nothing in it is a statement."""
    return "['" + name.replace("\\", "\\\\").replace("'", "\\'") + "']"


def sample_kql(table: str, lookback_days: int, rows: int) -> str:
    return (
        f"{kql_table(table)} | where TimeGenerated > ago({int(lookback_days)}d) | take {int(rows)}"
    )


def usage_kql(lookback_days: int) -> str:
    return (
        f"Usage | where TimeGenerated > ago({int(lookback_days)}d) "
        "| summarize by DataType | order by DataType asc"
    )


@dataclass
class WorkspaceTarget:
    rid: ResourceId
    name: str
    workspace_id: str  # the customer id (a GUID) the query API takes

    def __repr__(self) -> str:
        return f"WorkspaceTarget({redact_digits(self.name)!r})"


class LogAnalyticsAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        keys: dict[str, dict[str, str]] = {}
        for c in ctx.graph(CLUSTERS):
            vault, name = str(c.get("vault") or "").rstrip("/"), str(c.get("keyName") or "")
            if vault and name:
                keys[str(c.get("id") or "")] = key_facts(
                    "Microsoft.Keyvault", f"{vault}/keys/{name}"
                )
        for row in ctx.graph(WORKSPACES):
            rid = ResourceId.parse(str(row.get("id") or ""))
            name = str(row.get("name") or rid.name)
            store = Store(
                KIND, name, tags={str(k): str(v) for k, v in (row.get("tags") or {}).items()}
            )
            store.extra.update(azure_fields(rid))
            if str(row.get("queryAccess") or "").lower() == "disabled":
                store.extra["networkRestricted"] = True
            store.facts = dict(
                keys.get(str(row.get("cluster") or "")) or key_facts("Microsoft.Storage")
            )
            store.table = WorkspaceTarget(rid, name, str(row.get("customerId") or ""))
            out.stores.append(store)
            if apply_rules(store, ctx.settings.allow, ctx.settings.deny) and not (
                ctx.settings.log_analytics_read
            ):
                store.toggle_off("AZURE_LOG_ANALYTICS")  # #105: listed, not read

    def source(self, ctx: Context, store: Store) -> LogAnalyticsSource | None:
        t = store.table
        if not isinstance(t, WorkspaceTarget) or not t.workspace_id:
            return None
        return LogAnalyticsSource(
            ctx.clients.client("logs"),
            ctx.clients.client("arm"),
            t,
            lookback_days=ctx.settings.logs_lookback_days,
            max_rows=ctx.settings.logs_max_rows,
            statement_seconds=ctx.settings.db_statement_seconds,
        )


def _tables(result: Any) -> list[Any]:
    """The tables of a query's result, complete or partial."""
    got = getattr(result, "tables", None)
    if got is None:
        got = getattr(result, "partial_data", None) or []
    return list(got)


def _rows(result: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for table in _tables(result):
        columns = [str(c) for c in getattr(table, "columns", [])]
        for row in getattr(table, "rows", []):
            out.append({c: plain(v) for c, v in zip(columns, list(row), strict=False)})
    return out


class LogAnalyticsSource:
    """One workspace: its tables with data, each sampled with one KQL query."""

    kind = KIND

    def __init__(
        self,
        logs: Any,
        arm: Any,
        target: WorkspaceTarget,
        *,
        lookback_days: int = 1,
        max_rows: int = 500,
        statement_seconds: int = 60,
    ) -> None:
        self.logs = logs
        self.arm = arm
        self.t = target
        self.lookback_days = lookback_days
        self.max_rows = max_rows
        self.statement_seconds = statement_seconds
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"logs:{target.name}"
        self.target = target.name

    def __repr__(self) -> str:
        return f"LogAnalyticsSource({self.t!r})"

    def _query(self, kql: str) -> Any:
        return self.logs.query_workspace(
            self.t.workspace_id,
            kql,
            timespan=_dt.timedelta(days=self.lookback_days),
            server_timeout=self.statement_seconds,
        )

    def _billed(self) -> set[str]:
        """Tables on a plan billed per query (Basic, Auxiliary), from Resource Manager."""
        try:
            listed = self.arm.list(f"{self.t.rid.value}/tables", TABLES_API)
            return {
                str(t.get("name") or "")
                for t in listed
                if str((t.get("properties") or {}).get("plan") or "").lower() in BILLED_PLANS
            }
        except Exception as err:  # plans unknown: every table with data is still read
            log_event("discovery.failed", kind=KIND, error=error_name(err))
            return set()

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target)
        try:
            usage = _rows(self._query(usage_kql(self.lookback_days)))
            tables = sorted({str(r.get("DataType") or "") for r in usage} - {""})[:MAX_TABLES]
        except Exception as err:  # the workspace could not be queried
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        billed = self._billed()
        after = cursor.get("after")
        cov.listed = len(tables)
        todo = [t for t in tables if after is None or t > after]
        cov.eligible = len(todo)
        seen_at = now.isoformat()
        link = portal_link(self.t.rid, "logs")
        done = True
        for table in todo:
            if table in billed:
                cov.skipped["billed_plan"] = cov.skipped.get("billed_plan", 0) + 1
                after = table
                continue
            if not budget.has():
                done = False
                break
            try:
                rows = _rows(self._query(sample_kql(table, self.lookback_days, self.max_rows)))
            except Exception as err:  # one table must not stop the pass
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
                after = table
                continue
            size = len(json.dumps(rows, default=str))
            budget.take(size)
            columns = list(dict.fromkeys(k for r in rows for k in r))
            result = scan_rows("kql", columns, rows, detector, self.max_rows)
            cov.scanned += 1
            cov.bytes_scanned += size
            cov.partial += int(len(rows) >= self.max_rows)
            cov.test_values += result.test_values
            cov.suppressed += result.suppressed
            cov.redaction_markers += result.redaction_markers
            cov.formats["kql"] = cov.formats.get("kql", 0) + 1

            def resource(
                column: str, table: str = table, t: WorkspaceTarget = self.t
            ) -> dict[str, Any]:
                out = store_field_resource(
                    service=KIND, store=t.name, table=table, field=column, read_by="kql"
                )
                out.update(azure_fields(t.rid))
                return out

            store.replace_location(
                f"{self.id}\n{table}",
                column_findings(result, resource, link, seen_at, facts=self.facts),
            )
            after = table
        cov.pass_complete = done
        cov.backlog = not done
        return SourceRun(cov, {"after": None if done else after})
