"""BigQuery: every table of every dataset, sampled with `tabledata.list`. Read by default.

**Discovery** (`DISCOVER` includes `bigquery`): Cloud Asset Inventory lists
every dataset in scope; each dataset's own record (`datasets.get`: its access
list and default key) and its tables (`tables.list`) come from the BigQuery
API with `bigquery.datasets.get` and `bigquery.tables.list`. A store is one
table, `project.dataset.table`, so each one's gap has its own reason:

- a view or materialized view is never read: it is a query, which bills bytes
  and needs a job (`bigquery.jobs.create`, a write the scanner does not hold).
  A plain view is `unsupported` (`tableType: VIEW`); a view that a dataset's
  access list authorizes is `authorized_view`: it may read tables the
  scanner's service account cannot, and the scanner never reads through it
  (never escalating). The tables it reads are stores of their own, read
  directly when the service account may;
- an external table (Cloud Storage, Drive, Bigtable, a BigLake connection) is
  `unsupported` (`tableType: EXTERNAL`): its data is read where it lives;
- a table with **row-level access policies** is `row_level_policy`: reading it
  would return only the rows the service account is granted, a sample that
  says nothing of the rest, and granting more would be an escalation;
- columns under **policy tags** (column-level security) are left out of the
  read (`selectedFields`) and counted as `protectedColumns`: the service
  account is never given Fine-Grained Reader.

**Reading** is `tabledata.list` with `bigquery.tables.getData` (BigQuery Data
Viewer, or the custom read-only role): the first `BIGQUERY_MAX_ROWS` rows,
read by column, so a finding names the column (nested `RECORD` fields are read
inside it). `tabledata.list` runs no query and bills no bytes, which is why it
is preferred over `TABLESAMPLE`: a `TABLESAMPLE` query would bill the bytes of
the blocks it samples, and would need `bigquery.jobs.create`. A table
unchanged since its last complete read (`lastModifiedTime`) is not read again;
its findings stay.

**Encryption (1.5):** the table's own Cloud KMS key, else its dataset's default
key (`customer_managed_key`, hashed), else Google's own keys (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows

from ..clients import Rest
from ..resources import Located, console_link
from .base import Context, kms_facts, labels
from .common import call_gap

KIND = "bigquery"
ASSET_TYPE = "bigquery.googleapis.com/Dataset"
API = "https://bigquery.googleapis.com/bigquery/v2"
READ_TYPES = frozenset({"TABLE", "SNAPSHOT"})
VIEW_TYPES = frozenset({"VIEW", "MATERIALIZED_VIEW"})
MAX_TABLES_PER_DATASET = 5000
MAX_COLUMNS = 1000


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def table_url(project: str, dataset: str, table: str) -> str:
    return f"{API}/projects/{_q(project)}/datasets/{_q(dataset)}/tables/{_q(table)}"


def full_name(project: str, dataset: str, table: str | None = None) -> str:
    """The table's (or the dataset's) full resource name, as Cloud Asset Inventory gives it."""
    name = f"//bigquery.googleapis.com/projects/{project}/datasets/{dataset}"
    return f"{name}/tables/{table}" if table is not None else name


@dataclass
class TableTarget:
    """One BigQuery table: where it is, and its dataset's default key."""

    project: str
    dataset: str
    table: str
    dataset_facts: dict[str, Any] = field(default_factory=dict)

    @property
    def where(self) -> Located:
        return Located(self.project, full_name(self.project, self.dataset, self.table))

    def __repr__(self) -> str:
        return f"TableTarget({redact_digits(self.dataset)!r}, {redact_digits(self.table)!r})"


def _dataset_of(row: dict[str, Any]) -> tuple[str, str] | None:
    parts = str(row.get("name") or "").split("/")
    try:
        return parts[parts.index("projects") + 1], parts[parts.index("datasets") + 1]
    except (ValueError, IndexError):
        return None


def authorized_views(access: list[Any]) -> set[tuple[str, str, str]]:
    """The views a dataset's access list authorizes: (project, dataset, table)."""
    out: set[tuple[str, str, str]] = set()
    for entry in access:
        view = entry.get("view") if isinstance(entry, dict) else None
        if isinstance(view, dict):
            out.add(
                (
                    str(view.get("projectId") or ""),
                    str(view.get("datasetId") or ""),
                    str(view.get("tableId") or ""),
                )
            )
    return out


class BigQueryAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        rest = ctx.rest
        authorized: set[tuple[str, str, str]] = set()
        views: list[tuple[Store, tuple[str, str, str]]] = []
        for row in ctx.search(ASSET_TYPE):
            got = _dataset_of(row)
            if got is None:
                continue
            project, dataset = got
            base = f"{API}/projects/{_q(project)}/datasets/{_q(dataset)}"
            try:
                meta = rest.get(base)
                listed: list[dict[str, Any]] = []
                for page, _ in rest.pages(f"{base}/tables", "tables", {"maxResults": "1000"}):
                    listed.extend(t for t in page if isinstance(t, dict))
                    if len(listed) >= MAX_TABLES_PER_DATASET:
                        break
            except Exception as err:  # the dataset is reported, its tables unknown
                store = Store(KIND, f"{project}.{dataset}.*", tags=labels(row))
                store.extra.update(Located(project, full_name(project, dataset)).fields())
                store.status, store.error = "error", error_name(err)
                gap = call_gap(err)
                store.reason = gap if gap in ("network",) else reason_for(store.error)
                out.stores.append(store)
                continue
            authorized |= authorized_views(list(meta.get("access") or []))
            key = (meta.get("defaultEncryptionConfiguration") or {}).get("kmsKeyName")
            dataset_facts = kms_facts(str(key) if key else None)
            tags = {**labels(row), **labels(meta)}
            for t in listed[:MAX_TABLES_PER_DATASET]:
                ref = t.get("tableReference") or {}
                table = str(ref.get("tableId") or "")
                if not table:
                    continue
                kind = str(t.get("type") or "TABLE").upper()
                target = TableTarget(project, dataset, table, dict(dataset_facts))
                store = Store(KIND, f"{project}.{dataset}.{table}", tags={**tags, **labels(t)})
                store.extra.update(target.where.fields())
                store.extra["tableType"] = kind
                store.facts = dict(dataset_facts)
                store.table = target
                out.stores.append(store)
                if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                    continue
                if kind in VIEW_TYPES:
                    views.append((store, (project, dataset, table)))
                    store.skip("unsupported")  # a query: bytes billed, and a job to create
                elif kind not in READ_TYPES:
                    store.skip("unsupported")  # external: read where its data lives
        for store, ref in views:
            if ref in authorized:
                store.skip("authorized_view")  # never read through: that would escalate

    def source(self, ctx: Context, store: Store) -> BigQuerySource | None:
        t = store.table
        if not isinstance(t, TableTarget):
            return None
        return BigQuerySource(ctx.rest, t, max_rows=ctx.settings.bigquery_max_rows)


def _fields(schema: Any) -> list[dict[str, Any]]:
    got = schema.get("fields") if isinstance(schema, dict) else None
    return [f for f in got or [] if isinstance(f, dict)]


def _protected(f: dict[str, Any]) -> bool:
    """A field under a policy tag (column-level security), or holding one."""
    tags = (f.get("policyTags") or {}).get("names") if isinstance(f, dict) else None
    return bool(tags) or any(_protected(x) for x in _fields(f))


def cell(f: dict[str, Any], v: Any, depth: int = 0) -> Any:
    """One `tabledata.list` cell as a plain value, by its schema field. Bytes are dropped."""
    if depth > 15 or v is None:
        return None
    if str(f.get("mode") or "").upper() == "REPEATED":
        inner = {**f, "mode": "NULLABLE"}
        return [cell(inner, x.get("v") if isinstance(x, dict) else x, depth + 1) for x in v]
    kind = str(f.get("type") or "").upper()
    if kind in ("RECORD", "STRUCT"):
        values = v.get("f") if isinstance(v, dict) else None
        return row_of(_fields(f), values or [], depth + 1)
    if kind == "BYTES":
        return None
    return v if isinstance(v, str | int | float | bool) else json.dumps(v)


def row_of(fields: list[dict[str, Any]], cells: list[Any], depth: int = 0) -> dict[str, Any]:
    return {
        str(f.get("name") or ""): cell(f, c.get("v") if isinstance(c, dict) else None, depth)
        for f, c in zip(fields, cells, strict=False)
    }


class BigQuerySource:
    """One table: its first rows, read by column with `tabledata.list`."""

    kind = KIND

    def __init__(self, rest: Rest, target: TableTarget, *, max_rows: int = 1000) -> None:
        self.rest = rest
        self.t = target
        self.max_rows = max_rows
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"bigquery:{target.project}.{target.dataset}.{target.table}"
        self.target = f"{target.project}.{target.dataset}.{target.table}"

    def __repr__(self) -> str:
        return f"BigQuerySource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target, listed=1)
        t = self.t
        url = table_url(t.project, t.dataset, t.table)
        try:
            meta = self.rest.get(url)
            policies = self.rest.get(f"{url}/rowAccessPolicies").get("rowAccessPolicies") or []
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            gap = call_gap(err)
            return SourceRun(cov, cursor, note=gap if gap == "network" else None)
        extra: dict[str, Any] = {}
        if meta.get("numBytes") is not None:
            extra["sizeBytes"] = int(meta["numBytes"])
        if policies:
            log_event("source.refused", source=self.target, kind=KIND, reason="row_level_policy")
            return SourceRun(cov, cursor, note="row_level_policy", extra=extra)
        modified = str(meta.get("lastModifiedTime") or "")
        if modified and cursor.get("modified") == modified:
            cov.pass_complete = True  # unchanged since its last complete read: findings stay
            return SourceRun(cov, cursor, extra=extra)
        cov.eligible = 1
        if not budget.has():
            cov.backlog = True
            return SourceRun(cov, cursor, note="budget", extra=extra)
        fields = _fields(meta.get("schema"))[:MAX_COLUMNS]
        readable = [f for f in fields if not _protected(f)]
        protected = len(fields) - len(readable)
        if protected:
            extra["protectedColumns"] = protected
        rows: list[dict[str, Any]] = []
        if readable:
            params: dict[str, str] = {
                "maxResults": str(self.max_rows),
                "formatOptions.useInt64Timestamp": "true",
            }
            if protected:
                params["selectedFields"] = ",".join(str(f.get("name")) for f in readable)
            try:
                page = self.rest.get(f"{url}/data", params)
            except Exception as err:  # reported by name
                cov.error = error_name(err)
                log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
                return SourceRun(cov, cursor, extra=extra)
            rows = [row_of(readable, list(r.get("f") or [])) for r in page.get("rows") or []]
        size = len(json.dumps(rows, default=str))
        budget.take(size)
        columns = [str(f.get("name") or "") for f in readable]
        result = scan_rows("json", columns, rows, detector, self.max_rows)
        cov.scanned, cov.bytes_scanned, cov.pass_complete = 1, size, True
        cov.partial = int(len(rows) >= self.max_rows)
        cov.formats["json"] = 1
        cov.test_values, cov.suppressed = result.test_values, result.suppressed
        cov.redaction_markers = result.redaction_markers
        key = (meta.get("encryptionConfiguration") or {}).get("kmsKeyName")
        facts = kms_facts(str(key)) if key else (self.facts or t.dataset_facts)
        where = t.where

        def resource(column: str) -> dict[str, Any]:
            out = store_field_resource(
                service=KIND,
                store=t.dataset,
                table=t.table,
                field=column,
                read_by="tabledata_list",
            )
            out.update(where.fields())
            return out

        link = console_link(
            "bigquery",
            {"project": t.project, "p": t.project, "d": t.dataset, "t": t.table, "page": "table"},
        )
        store.replace_location(
            f"{self.id}\n",
            column_findings(result, resource, link, now.isoformat(), facts=facts),
        )
        return SourceRun(cov, {"modified": modified or None}, extra=extra)
