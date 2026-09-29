"""Sampled, read-only SQL over any database: the statements, and the pass over its tables.

Nothing here knows which cloud or which driver runs the SQL. A caller gives
an `execute(sql, params)` that returns rows as dicts, and a dialect; this
module builds the only statements the scanner ever sends and walks the
tables with a resumable cursor:

1. list base tables from `information_schema` (or the dialect's own view),
   with schemas as bound parameters, never inlined;
2. for each table, `SELECT * FROM "schema"."table" LIMIT n`, with quoted
   identifiers, so a table named `x"; DROP TABLE y; --` stays a name;
3. read the rows by column (scan/columnar.py), so a finding names the
   column.

The read-only guarantee is the database user's grants (SELECT only). The
statements are only SELECTs, and where the dialect allows it the caller runs
them in a read-only transaction that is rolled back.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..detect.analyzer import Detector
from ..safety import error_name, log_event
from .columnar import TableResult, scan_rows

Params = list[tuple[str, str]]
Execute = Callable[[str, Params], list[dict[str, Any]]]

# Schemas that hold the database's own catalog, never user data.
SYSTEM_SCHEMAS = {
    "postgresql": ("pg_catalog", "information_schema"),
    "redshift": ("pg_catalog", "information_schema", "pg_internal", "pg_automv", "pg_auto_copy"),
    "mysql": (),
}


@dataclass(frozen=True)
class Dialect:
    """How one SQL engine quotes names and lists its tables."""

    name: str  # postgresql | mysql | redshift
    quote: str  # the identifier quote character
    placeholder: str  # ":{name}" (RDS and Redshift Data API)

    def ident(self, name: str) -> str:
        """A SQL identifier, quoted so that nothing in it is SQL."""
        q = self.quote
        return q + name.replace(q, q + q) + q

    def param(self, name: str) -> str:
        return self.placeholder.format(name=name)


POSTGRESQL = Dialect("postgresql", '"', ":{name}")
MYSQL = Dialect("mysql", "`", ":{name}")
REDSHIFT = Dialect("redshift", '"', ":{name}")
DIALECTS = {d.name: d for d in (POSTGRESQL, MYSQL, REDSHIFT)}


def tables_sql(dialect: Dialect, schemas: tuple[str, ...]) -> tuple[str, Params]:
    """The statement that lists base tables, and its parameters (never inlined values)."""
    if dialect.name == "mysql":
        return (
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' AND table_schema = DATABASE() "
            "ORDER BY table_schema, table_name",
            [],
        )
    params = [(f"s{i}", s) for i, s in enumerate(schemas)]
    if schemas:
        where = "table_schema IN (" + ", ".join(dialect.param(n) for n, _ in params) + ")"
    else:
        system = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS[dialect.name])
        where = f"table_schema NOT IN ({system})"
    view = "svv_tables" if dialect.name == "redshift" else "information_schema.tables"
    # svv_tables also lists external (Spectrum) tables, which are S3 data read by the
    # Glue and S3 sources; only local base tables are read here.
    sql = (
        f"SELECT table_schema, table_name FROM {view} "  # noqa: S608 - placeholders only
        f"WHERE table_type = 'BASE TABLE' AND {where} ORDER BY table_schema, table_name"
    )
    return sql, params


def sample_sql(dialect: Dialect, schema: str, table: str, limit: int) -> str:
    """The one statement that reads data: a sample of rows, by quoted identifiers."""
    return f"SELECT * FROM {dialect.ident(schema)}.{dialect.ident(table)} LIMIT {int(limit)}"  # noqa: S608 - quoted identifiers


@dataclass
class SqlPass:
    """What one run of a sampled pass over a database's tables did."""

    listed: int = 0
    eligible: int = 0
    scanned: int = 0
    unreadable: int = 0
    partial: int = 0
    bytes: int = 0
    test_values: int = 0
    suppressed: int = 0
    redaction_markers: int = 0
    done: bool = False
    after: list[str] | None = None
    errors: dict[str, int] = field(default_factory=dict)


def sample_tables(
    execute: Execute,
    dialect: Dialect,
    *,
    detector: Detector,
    has_room: Callable[[], bool],
    take: Callable[[int], None],
    on_table: Callable[[str, str, TableResult], None],
    after: list[str] | None,
    schemas: tuple[str, ...] = (),
    max_rows: int = 1000,
    max_tables: int = 500,
    source: str = "",
) -> SqlPass:
    """List the tables, then sample each after `after`, while the budget has room.

    `on_table(schema, table, result)` receives each table's per-column result.
    A table that cannot be read is counted and the pass goes on. The listing's
    own failure is raised to the caller.
    """
    out = SqlPass(after=after)
    sql, params = tables_sql(dialect, schemas)
    listed = execute(sql, params)
    # Sorted here, not by the database's collation, so resuming is exact.
    tables = sorted(
        {
            (
                str(r.get("table_schema") or r.get("TABLE_SCHEMA") or ""),
                str(r.get("table_name") or r.get("TABLE_NAME") or ""),
            )
            for r in listed
        }
    )[:max_tables]
    out.listed = len(tables)
    todo = [t for t in tables if after is None or list(t) > list(after)]
    out.eligible = len(todo)
    out.done = True
    for schema, name in todo:
        if not has_room():
            out.done = False
            break
        try:
            rows = execute(sample_sql(dialect, schema, name, max_rows), [])
        except Exception as err:  # one table must not stop the pass
            out.unreadable += 1
            e = error_name(err)
            out.errors[e] = out.errors.get(e, 0) + 1
            log_event("item.unreadable", source=source, error=e)
            out.after = [schema, name]
            continue
        size = len(json.dumps(rows, default=str))
        take(size)
        columns = list(dict.fromkeys(k for row in rows for k in row))
        result = scan_rows("sql", columns, rows, detector, max_rows)
        out.scanned += 1
        out.bytes += size
        out.partial += int(len(rows) >= max_rows)
        out.test_values += result.test_values
        out.suppressed += result.suppressed
        out.redaction_markers += result.redaction_markers
        on_table(schema, name, result)
        out.after = [schema, name]
    return out
