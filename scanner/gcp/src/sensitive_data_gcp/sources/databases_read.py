"""Cloud SQL's and AlloyDB's read path: a connected session's tables sampled with read-only SQL
by the core's SQL reader, and the findings they give.

This module is `adapter:cloudsql_postgresql`, `adapter:cloudsql_mysql`,
`adapter:cloudsql_sqlserver`, `adapter:alloydb` (scripts/components.py): a change here
rescans the objects it read. Listing, discovery and configuration stay in `databases.py`
(`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import datetime as _dt
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.index import ObjectPass
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import TableResult
from sensitive_data_core.scan.sql import sample_tables
from sensitive_data_db.engines import SqlSession

if TYPE_CHECKING:
    from .databases import DatabaseSource as _Self

MAX_WRITE_GRANTS = 30
READS = ("cloudsql_postgresql", "cloudsql_mysql", "cloudsql_sqlserver", "alloydb")


def _read(
    src: _Self,
    session: SqlSession,
    database: str,
    *,
    begin: tuple[str, ...],
    cov: Coverage,
    cursor: dict[str, Any],
    budget: Budget,
    detector: Detector,
    store: FindingStore,
    now: _dt.datetime,
) -> SourceRun:
    grants = session.grants()
    if not grants.verified:
        log_event("source.refused", source=src.target, kind=src.kind, reason="grants_unverifiable")
        return SourceRun(cov, cursor, note="grants_unverifiable")
    if grants.write:
        log_event("source.refused", source=src.target, kind=src.kind, reason="db_user_can_write")
        write = sorted(grants.write)[:MAX_WRITE_GRANTS]
        return SourceRun(cov, cursor, note="db_user_can_write", extra={"writeGrants": write})
    seen_at = now.isoformat()
    facts = src.facts
    t = src.t
    today = (now.date() - _dt.date(1970, 1, 1)).days
    op = ObjectPass(src.indexes, f"{src.id}\n{database}", src.kind, generation=today, budget=budget)

    def on_table(schema: str, table: str, result: TableResult) -> None:
        def resource(column: str) -> dict[str, Any]:
            out = store_field_resource(
                service=t.kind,
                store=t.server,
                database=database,
                table=f"{schema}.{table}",
                field=column,
                read_by="sample",
            )
            out.update(t.where.fields())
            return out

        location = f"{src.id}\n{database}\n{schema}\n{table}"
        store.replace_location(
            location, column_findings(result, resource, t.link, seen_at, facts=facts)
        )

    session.rollback()
    for statement in begin:
        session.execute(statement, [])
    s = src.settings
    try:
        sp = sample_tables(
            session.execute,
            session.dialect,
            detector=detector,
            has_room=budget.has,
            take=budget.take,
            on_table=on_table,
            after=cursor.get("after"),
            schemas=s.db_schemas,
            max_rows=s.db_max_rows,
            max_tables=s.db_max_tables,
            source=src.target,
            index=op,
        )
    except Exception as err:  # the listing itself failed
        cov.error = error_name(err)
        log_event("source.failed", source=src.target, kind=src.kind, error=cov.error)
        return SourceRun(cov, cursor)
    cov.listed += sp.listed
    cov.eligible += sp.eligible
    cov.scanned += sp.scanned
    cov.unreadable += sp.unreadable
    cov.partial += sp.partial
    cov.bytes_scanned += sp.bytes
    cov.test_values += sp.test_values
    cov.suppressed += sp.suppressed
    cov.redaction_markers += sp.redaction_markers
    cov.pass_complete = sp.done
    cov.backlog = not sp.done
    op.settle(cov)
    if sp.scanned:
        cov.formats["sql"] = cov.formats.get("sql", 0) + sp.scanned
    note = "no_grant" if sp.listed == 0 and src.t.database is not None else None
    return SourceRun(cov, {"after": None if sp.done else sp.after}, note=note)
