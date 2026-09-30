"""RDS and Aurora's read path: a snapshot export's Parquet files read column by column, a table
sampled with read-only SQL through the Data API, and the findings they give.

This module is `adapter:rds` (scripts/components.py): a change here rescans the objects it
read. Listing, discovery and configuration stay in `rds.py` (`listing:<kind>`), whose
changes re-list and never re-read (#67).
"""

from __future__ import annotations

import datetime as _dt
import io
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import (
    Coverage,
    finding_json,
)
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import TableResult, scan_parquet
from sensitive_data_core.scan.sql import (
    MYSQL,
    POSTGRESQL,
    Dialect,
    sample_sql,
)

from ..resources import rds_link, rds_resource
from .exports import delete_prefix, drop_other_passes, list_keys, merge
from .s3_read import S3RangeFile

if TYPE_CHECKING:
    from .rds import RdsExportSource as _Self

READS = ("rds",)


def _findings(
    table: TableResult,
    *,
    engine: str,
    identifier: str,
    db_type: str,
    database: str,
    name: str,
    read_by: str,
    snapshot_time: str | None,
    link: str,
    seen_at: str,
    facts: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    out = []
    for column, item in sorted(table.by_column.items()):
        resource = rds_resource(
            engine=engine,
            identifier=identifier,
            db_type=db_type,
            database=database,
            table=name,
            column=column,
            read_by=read_by,
            snapshot_time=snapshot_time,
        )
        for cf in item.findings.values():
            cf.offsets = []  # the rows are gone with the export: counts only
            out.append(finding_json(resource, link, table.format, cf, seen_at, facts=facts))
    return out


def export_table_of(relative: str) -> tuple[str, str] | None:
    """`<db>/<schema.table>/<partition>/part-….parquet` to (db, schema.table)."""
    parts = relative.split("/")
    if len(parts) < 3 or not parts[-1].endswith(".parquet"):
        return None
    return parts[0], parts[1]


def _dialect(engine: str) -> Dialect:
    return MYSQL if engine == "mysql" else POSTGRESQL


def quote_identifier(name: str, engine: str) -> str:
    """A SQL identifier, quoted so that nothing in it is SQL (the core's scan/sql.py)."""
    return _dialect(engine).ident(name)


def select_sql(engine: str, schema: str, table: str, limit: int) -> str:
    return sample_sql(_dialect(engine), schema, table, limit)


def _scan(
    src: _Self,
    c: dict[str, Any],
    cov: Coverage,
    *,
    budget: Budget,
    detector: Detector,
    store: FindingStore,
    now: _dt.datetime,
) -> SourceRun:
    base = f"{src.prefix}{c['task']}/"
    seen_at = now.isoformat()
    link = rds_link(src.region, src.identifier, src.db_type)
    done = True
    for obj in list_keys(src.s3, src.bucket, base, c.get("after")):
        key = obj["Key"]
        cov.listed += 1
        where = export_table_of(key[len(base) :])
        if where is None:  # export_info_*.json and the like
            c["after"] = key
            continue
        cov.eligible += 1
        size = int(obj.get("Size", 0))
        if not budget.has(min(size, src.max_object_bytes)):
            done = False
            break
        budget.take(min(size, src.max_object_bytes))
        raw = S3RangeFile(src.s3, src.bucket, key, size=size, max_bytes=src.max_object_bytes)
        try:
            table = scan_parquet(io.BufferedReader(raw, 256 * 1024), detector, src.max_rows)
        except Exception as err:  # one bad file must not stop the pass
            cov.unreadable += 1
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("item.unreadable", source=src.target, error=error_name(err))
            c["after"] = key
            continue
        cov.scanned += 1
        cov.bytes_scanned += raw.bytes_read
        cov.formats["parquet"] = cov.formats.get("parquet", 0) + 1
        cov.partial += int(table.partial or raw.cut)
        cov.test_values += table.test_values
        cov.suppressed += table.suppressed
        cov.redaction_markers += table.redaction_markers
        database, name = where
        for f in _findings(
            table,
            engine=src.engine,
            identifier=src.identifier,
            db_type=src.db_type,
            database=database,
            name=name,
            read_by="snapshot_export",
            snapshot_time=c.get("snapshotAt"),
            link=link,
            seen_at=seen_at,
            facts=src.facts,
        ):
            merge(store, f"{src.id}\n{database}/{name}", f, c["passId"])
        c["after"] = key
    if not done:
        cov.backlog = True
        return SourceRun(cov, c, None, src._extra(c, "COMPLETE"))
    gone = drop_other_passes(store, src.id, c["passId"])
    if gone:
        log_event("finding.gone", source=src.target, count=gone)
    delete_prefix(src.s3, src.bucket, base)
    cov.pass_complete = True
    finished = {
        "lastSnapshot": c.get("snapshot"),
        "lastSnapshotAt": c.get("snapshotAt"),
        "lastExportAt": now.isoformat(),
    }
    return SourceRun(cov, finished, None, src._extra(c, "COMPLETE"))
