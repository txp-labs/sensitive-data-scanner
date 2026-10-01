"""Spanner: every database, sampled with the core's SQL pass in read-only transactions.

**Discovery** (`DISCOVER` includes `spanner`): Cloud Asset Inventory lists every
Spanner database in scope (`spanner.googleapis.com/Database`); its record
(`databases.get`: its dialect, state and Cloud KMS key) comes from the Spanner
API. A store is one database, `instance/database`.

**Reading** needs `spanner.databases.select` and the session permissions of
Cloud Spanner Database Reader: one session (`sessions.create`, deleted after),
then the core's sampled pass (`scan/sql.py`) through `executeSql`, every
statement in a **single-use read-only transaction** (`readOnly: {strong:
true}`), which cannot write. GoogleSQL and PostgreSQL-dialect databases are
both read: the base tables from `information_schema.tables`, then `SELECT *
FROM <table> LIMIT n` with quoted identifiers, read by column. The service
account's access is its IAM role (Database Reader), which the deployment's
strict test holds to reads; there is no SQL user to check.

**Encryption (1.5):** the database's Cloud KMS key (`encryptionConfig`), hashed,
else Google's own keys (`service_managed`).
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import TableResult
from sensitive_data_core.scan.sql import SPANNER, SPANNER_PG, Params, sample_tables

from ..clients import Rest
from ..config import Settings
from ..resources import Located, console_link
from .base import Context, kms_facts, labels
from .common import call_gap

KIND = "spanner"
API = "https://spanner.googleapis.com/v1"
ASSET_TYPE = "spanner.googleapis.com/Database"
READ_ONLY = {"singleUse": {"readOnly": {"strong": True}}}


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


@dataclass
class SpannerTarget:
    project: str
    instance: str
    database: str
    postgres: bool
    where: Located
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> str:
        t = self
        return f"projects/{_q(t.project)}/instances/{_q(t.instance)}/databases/{_q(t.database)}"

    def __repr__(self) -> str:
        return f"SpannerTarget({redact_digits(self.instance)!r}, {redact_digits(self.database)!r})"


def cell(kind: dict[str, Any], v: Any, depth: int = 0) -> Any:
    """One `executeSql` value as a plain value, by its type. Bytes are dropped."""
    if v is None or depth > 15:
        return None
    code = str(kind.get("code") or "")
    if code in ("BYTES", "PROTO"):
        return None
    if code == "ARRAY" and isinstance(v, list):
        inner = kind.get("arrayElementType") or {}
        return [cell(inner, x, depth + 1) for x in v]
    if code == "STRUCT" and isinstance(v, list):
        fields = (kind.get("structType") or {}).get("fields") or []
        return {
            str(f.get("name") or i): cell(f.get("type") or {}, x, depth + 1)
            for i, (f, x) in enumerate(zip(fields, v, strict=False))
        }
    return v if isinstance(v, str | int | float | bool) else None


class SpannerAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        for row in ctx.search(ASSET_TYPE):
            parts = str(row.get("name") or "").split("/")
            try:
                project = parts[parts.index("projects") + 1]
                instance = parts[parts.index("instances") + 1]
                database = parts[parts.index("databases") + 1]
            except (ValueError, IndexError):
                continue
            where = Located(project, str(row.get("name") or ""))
            store = Store(KIND, f"{instance}/{database}", tags=labels(row))
            store.extra.update(where.fields())
            store.extra["database"] = database
            out.stores.append(store)
            path = f"projects/{_q(project)}/instances/{_q(instance)}/databases/{_q(database)}"
            try:
                meta = ctx.rest.get(f"{API}/{path}")
            except Exception as err:  # the database is reported with its error
                store.status, store.error = "error", error_name(err)
                gap = call_gap(err)
                store.reason = "network" if gap == "network" else reason_for(store.error)
                continue
            key = (meta.get("encryptionConfig") or {}).get("kmsKeyName")
            store.facts = kms_facts(str(key) if key else None)
            postgres = str(meta.get("databaseDialect") or "").upper() == "POSTGRESQL"
            store.table = SpannerTarget(project, instance, database, postgres, where, store.facts)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            if str(meta.get("state") or "READY").upper() not in ("READY", "READY_OPTIMIZING"):
                store.skip("paused")  # still being created or restored
            elif not ctx.settings.spanner_read:
                store.toggle_off("GCP_SPANNER")  # #105: listed, not read

    def source(self, ctx: Context, store: Store) -> SpannerSource | None:
        t = store.table
        if not isinstance(t, SpannerTarget):
            return None
        return SpannerSource(ctx.rest, t, ctx.settings)


class SpannerSource:
    """One database: a session, then the sampled pass, statement by read-only statement."""

    kind = KIND

    def __init__(self, rest: Rest, target: SpannerTarget, settings: Settings) -> None:
        self.rest = rest
        self.t = target
        self.settings = settings
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"spanner:{target.instance}/{target.database}"
        self.target = f"{target.instance}/{target.database}"

    def __repr__(self) -> str:
        return f"SpannerSource({self.t!r})"

    def _execute(self, session: str, sql: str, params: Params) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"sql": sql, "transaction": READ_ONLY}
        if params:
            body["params"] = dict(params)
            body["paramTypes"] = {k: {"code": "STRING"} for k, _ in params}
        got = self.rest.post(f"{API}/{session}:executeSql", body)
        fields = ((got.get("metadata") or {}).get("rowType") or {}).get("fields") or []
        names = [str(f.get("name") or "") for f in fields]
        return [
            {n: cell(f.get("type") or {}, v) for n, f, v in zip(names, fields, row, strict=False)}
            for row in got.get("rows") or []
        ]

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target)
        t = self.t
        try:
            session = str(self.rest.post(f"{API}/{t.path}/sessions", {}).get("name") or "")
            if not session:
                raise ValueError("no session")
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            gap = call_gap(err)
            return SourceRun(cov, cursor, note=gap if gap == "network" else None)
        try:
            return self._read(
                session, cov, cursor=cursor, budget=budget, detector=detector, store=store, now=now
            )
        finally:
            with contextlib.suppress(Exception):  # an idle session expires by itself
                self.rest.call("DELETE", f"{API}/{session}")

    def _read(
        self,
        session: str,
        cov: Coverage,
        *,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        t = self.t
        s = self.settings
        link = console_link(
            f"spanner/instances/{_q(t.instance)}/databases/{_q(t.database)}/details/tables",
            {"project": t.project},
            t.instance,
            t.database,
        )
        seen_at = now.isoformat()

        def on_table(schema: str, table: str, result: TableResult) -> None:
            name = f"{schema}.{table}" if schema else table

            def resource(column: str) -> dict[str, Any]:
                out = store_field_resource(
                    service=KIND,
                    store=t.instance,
                    database=t.database,
                    table=name,
                    field=column,
                    read_by="sample",
                )
                out.update(t.where.fields())
                return out

            store.replace_location(
                f"{self.id}\n{schema}\n{table}",
                column_findings(result, resource, link, seen_at, facts=self.facts),
            )

        try:
            sp = sample_tables(
                lambda sql, params: self._execute(session, sql, params),
                SPANNER_PG if t.postgres else SPANNER,
                detector=detector,
                has_room=budget.has,
                take=budget.take,
                on_table=on_table,
                after=cursor.get("after"),
                schemas=() if t.postgres else s.db_schemas,
                max_rows=s.db_max_rows,
                max_tables=s.db_max_tables,
                source=self.target,
            )
        except Exception as err:  # the listing itself failed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            return SourceRun(cov, cursor)
        cov.listed, cov.eligible, cov.scanned = sp.listed, sp.eligible, sp.scanned
        cov.unreadable, cov.partial, cov.bytes_scanned = sp.unreadable, sp.partial, sp.bytes
        cov.test_values, cov.suppressed = sp.test_values, sp.suppressed
        cov.redaction_markers = sp.redaction_markers
        cov.pass_complete, cov.backlog = sp.done, not sp.done
        if sp.scanned:
            cov.formats["sql"] = sp.scanned
        note = "no_grant" if sp.listed == 0 else None
        return SourceRun(cov, {"after": None if sp.done else sp.after}, note=note)
