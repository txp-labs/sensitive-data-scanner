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

**A table unchanged since its last read is not read again** (#67). With an
object index, the pass first asks the engine what it keeps about each table's
changes (`markers_sql`), one catalog query and no data:

- PostgreSQL: `pg_stat_user_tables`, rows inserted, updated, deleted and live,
  and the last analyze (on a primary only: a replica's counters do not move);
- MySQL and MariaDB: `information_schema.tables.UPDATE_TIME` (InnoDB keeps it in
  memory: after a restart it is unknown until the table changes);
- SQL Server: the latest `sys.dm_db_index_usage_stats.last_user_update` of the
  table's indexes (reset by a restart);
- Oracle: `ALL_TAB_MODIFICATIONS` (inserts, updates, deletes, truncation, time)
  and `ALL_TABLES.LAST_ANALYZED`;
- Snowflake and Databricks: `information_schema.tables.last_altered`;
- Redshift and Spanner: none, so every table is sampled on every pass.

A table whose marker is the one recorded, read with components that are still
current, is skipped (its findings stay); a marker that is unknown or differs
means a read, and so does a table not read for `TABLE_RESAMPLE_DAYS` (7), in
case a marker misses a change. A table read with a stale component is read
again within the rescan share (`rescanReason`). A marker query the user may
not run is no marker: every table is sampled, as before.

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
from ..index import ObjectPass
from ..safety import error_name, log_event
from .columnar import TableResult, scan_rows

Params = list[tuple[str, str]]
Execute = Callable[[str, Params], list[dict[str, Any]]]

# Schemas that hold the database's own catalog, never user data.
SYSTEM_SCHEMAS = {
    "postgresql": ("pg_catalog", "information_schema"),
    "redshift": ("pg_catalog", "information_schema", "pg_internal", "pg_automv", "pg_auto_copy"),
    "mysql": (),
    "sqlserver": ("sys", "INFORMATION_SCHEMA"),
    "snowflake": ("INFORMATION_SCHEMA",),
    "databricks": ("information_schema",),
    # Spanner: GoogleSQL's default schema is the empty name; its catalogs are these.
    "spanner": ("INFORMATION_SCHEMA", "SPANNER_SYS"),
    "spanner_pg": ("information_schema", "spanner_sys", "pg_catalog"),
}


@dataclass(frozen=True)
class Dialect:
    """How one SQL engine quotes names and lists its tables."""

    name: str  # postgresql | mysql | redshift | sqlserver | oracle | snowflake | databricks
    quote: str  # the identifier quote character
    placeholder: str  # ":{name}" (RDS and Redshift Data API), or a driver's ("%({name})s", "?")
    quote_end: str = ""  # the closing quote when it differs ("]" for SQL Server)
    limit: str = "limit"  # how a sample is capped: limit | top (SQL Server) | fetch (Oracle)

    def ident(self, name: str) -> str:
        """A SQL identifier, quoted so that nothing in it is SQL."""
        q = self.quote
        end = self.quote_end or q
        return q + name.replace(end, end + end) + end

    def param(self, name: str) -> str:
        return self.placeholder.format(name=name)


POSTGRESQL = Dialect("postgresql", '"', ":{name}")
MYSQL = Dialect("mysql", "`", ":{name}")
REDSHIFT = Dialect("redshift", '"', ":{name}")
DIALECTS = {d.name: d for d in (POSTGRESQL, MYSQL, REDSHIFT)}
# The engines a database runner reads (sensitive_data_db) take their drivers'
# placeholders; the statements are the same.
SQLSERVER = Dialect("sqlserver", "[", "%({name})s", quote_end="]", limit="top")
ORACLE = Dialect("oracle", '"', ":{name}", limit="fetch")
SNOWFLAKE = Dialect("snowflake", '"', "%({name})s")
DATABRICKS = Dialect("databricks", "`", ":{name}")
# Spanner, over its REST API (a caller's `execute` binds the named parameters). A
# PostgreSQL-dialect database takes no named parameters: its schemas are never bound.
SPANNER = Dialect("spanner", "`", "@{name}")
SPANNER_PG = Dialect("spanner_pg", '"', "@{name}")


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
    if dialect.name == "oracle":
        # Oracle has no information_schema: the tables of every schema Oracle does not maintain.
        where = (
            "t.owner IN (" + ", ".join(dialect.param(n) for n, _ in params) + ")"
            if schemas
            else "u.oracle_maintained = 'N'"
        )
        return (
            "SELECT t.owner AS table_schema, t.table_name AS table_name FROM all_tables t "  # noqa: S608 - placeholders only
            f"JOIN all_users u ON u.username = t.owner WHERE t.nested = 'NO' AND "
            f"t.secondary = 'N' AND {where} ORDER BY t.owner, t.table_name",
            params,
        )
    if schemas:
        where = "table_schema IN (" + ", ".join(dialect.param(n) for n, _ in params) + ")"
    else:
        system = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS[dialect.name])
        where = f"table_schema NOT IN ({system})"
    view = "svv_tables" if dialect.name == "redshift" else "information_schema.tables"
    # svv_tables also lists external (Spectrum) tables, which are S3 data read by the
    # Glue and S3 sources; only local base tables are read here. Databricks (Unity
    # Catalog) calls its tables MANAGED or EXTERNAL; views are never read.
    kinds = (
        "table_type IN ('MANAGED', 'EXTERNAL')"
        if dialect.name == "databricks"
        else "table_type = 'BASE TABLE'"
    )
    sql = (
        f"SELECT table_schema, table_name FROM {view} "  # noqa: S608 - placeholders only
        f"WHERE {kinds} AND {where} ORDER BY table_schema, table_name"
    )
    return sql, params


def _in(dialect: Dialect, column: str, schemas: tuple[str, ...]) -> tuple[str, Params]:
    params = [(f"s{i}", s) for i, s in enumerate(schemas)]
    return f"{column} IN (" + ", ".join(dialect.param(n) for n, _ in params) + ")", params


def markers_sql(dialect: Dialect, schemas: tuple[str, ...]) -> tuple[str, Params] | None:
    """The catalog statement that says what changed in each table (one row per table:
    `table_schema`, `table_name`, and the engine's counters or times), or None for an engine
    that keeps nothing cheap to read. Only catalog views: never a table's data."""
    name = dialect.name
    params: Params = []
    if name == "postgresql":
        where = "NOT pg_is_in_recovery()"
        if schemas:
            clause, params = _in(dialect, "schemaname", schemas)
            where += f" AND {clause}"
        return (
            "SELECT schemaname AS table_schema, relname AS table_name, n_tup_ins, n_tup_upd, "  # noqa: S608 - placeholders only
            "n_tup_del, n_live_tup, last_analyze, last_autoanalyze FROM pg_stat_user_tables "
            f"WHERE {where}",
            params,
        )
    if name == "mysql":
        return (
            "SELECT table_schema, table_name, update_time FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' AND table_schema = DATABASE() "
            "AND update_time IS NOT NULL",
            [],
        )
    if name == "sqlserver":
        where = ""
        if schemas:
            clause, params = _in(dialect, "s.name", schemas)
            where = f"WHERE {clause} "
        return (
            "SELECT s.name AS table_schema, t.name AS table_name, "  # noqa: S608 - placeholders only
            "MAX(u.last_user_update) AS last_user_update FROM sys.tables t "
            "JOIN sys.schemas s ON s.schema_id = t.schema_id "
            "JOIN sys.dm_db_index_usage_stats u ON u.object_id = t.object_id "
            f"AND u.database_id = DB_ID() {where}GROUP BY s.name, t.name "
            "HAVING MAX(u.last_user_update) IS NOT NULL",
            params,
        )
    if name == "oracle":
        if schemas:
            where, params = _in(dialect, "t.owner", schemas)
        else:
            where = "u.oracle_maintained = 'N'"
        return (
            "SELECT t.owner AS table_schema, t.table_name AS table_name, t.last_analyzed, "  # noqa: S608 - placeholders only
            "m.inserts, m.updates, m.deletes, m.truncated, m.timestamp AS modified "
            "FROM all_tables t JOIN all_users u ON u.username = t.owner "
            "LEFT JOIN all_tab_modifications m ON m.table_owner = t.owner "
            "AND m.table_name = t.table_name AND m.partition_name IS NULL "
            f"WHERE t.nested = 'NO' AND t.secondary = 'N' AND {where}",
            params,
        )
    if name in ("snowflake", "databricks"):
        kinds = (
            "table_type IN ('MANAGED', 'EXTERNAL')"
            if name == "databricks"
            else "table_type = 'BASE TABLE'"
        )
        if schemas:
            where, params = _in(dialect, "table_schema", schemas)
        else:
            system = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS[name])
            where = f"table_schema NOT IN ({system})"
        return (
            "SELECT table_schema, table_name, last_altered FROM information_schema.tables "  # noqa: S608 - placeholders only
            f"WHERE {kinds} AND {where}",
            params,
        )
    return None


def table_markers(
    execute: Execute, dialect: Dialect, schemas: tuple[str, ...]
) -> dict[tuple[str, str], str] | None:
    """Each table's change marker, as text (counters and times, never data), or None when
    the engine keeps none or the user may not read it (every table is then sampled)."""
    got = markers_sql(dialect, schemas)
    if got is None:
        return None
    try:
        rows = execute(*got)
    except Exception:  # a catalog view the user may not read: no markers, as before
        return None
    out: dict[tuple[str, str], str] = {}
    for r in rows:
        low = {str(k).lower(): v for k, v in r.items()}
        key = (str(low.pop("table_schema", "") or ""), str(low.pop("table_name", "") or ""))
        values = [f"{k}={low[k]}" for k in sorted(low)]
        if all(low[k] is None for k in low):
            continue  # nothing known of this table: it is sampled
        out[key] = "|".join(values)
    return out


def sample_sql(dialect: Dialect, schema: str, table: str, limit: int) -> str:
    """The one statement that reads data: a sample of rows, by quoted identifiers. A table
    in a default schema with no name (Spanner's GoogleSQL) is named alone."""
    name = f"{dialect.ident(schema)}.{dialect.ident(table)}" if schema else dialect.ident(table)
    n = int(limit)
    if dialect.limit == "top":
        return f"SELECT TOP ({n}) * FROM {name}"  # noqa: S608 - quoted identifiers
    if dialect.limit == "fetch":
        return f"SELECT * FROM {name} FETCH FIRST {n} ROWS ONLY"  # noqa: S608 - quoted identifiers
    return f"SELECT * FROM {name} LIMIT {n}"  # noqa: S608 - quoted identifiers


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
    unchanged: int = 0  # tables skipped: unchanged since their last read (#67)
    markers: bool = False  # the engine's change markers were read


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
    index: ObjectPass | None = None,
    on_skip: Callable[[str, str], None] | None = None,
) -> SqlPass:
    """List the tables, then sample each after `after`, while the budget has room.

    `on_table(schema, table, result)` receives each table's per-column result.
    A table that cannot be read is counted and the pass goes on. The listing's
    own failure is raised to the caller. With `index` (the source's object index, its
    generation the day), a table unchanged since its last read is skipped (#67), and
    `on_skip(schema, table)` told, for a caller whose findings belong to one pass.
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
    # A fresh index has no table to skip: the markers are asked for from the second pass on.
    markers = (
        table_markers(execute, dialect, schemas)
        if index is not None and index.index is not None and index.index.rows
        else None
    )
    out.markers = markers is not None
    for schema, name in todo:
        if not has_room():
            out.done = False
            break
        key = f"{schema}\n{name}"
        marker = markers.get((schema, name)) if markers is not None else None
        why = None
        if index is not None and marker is not None:
            decision = index.table(key, marker)
            if not (decision.read or decision.rescan):
                out.unchanged += 1  # its findings stay
                out.eligible -= 1
                out.after = [schema, name]
                if on_skip is not None:
                    on_skip(schema, name)
                continue
            if decision.why is not None:
                if not index.rescans.admit():
                    index.rescans.miss(decision.why)  # the next run's
                    out.eligible -= 1
                    out.after = [schema, name]
                    if on_skip is not None:
                        on_skip(schema, name)
                    continue
                why = decision.why
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
        if why is not None:
            result.rescan = why.fields()
        if index is not None:
            index.record(key, marker=marker, readers=("sql",), text=True)
            index.rescanned(None, why)
        out.scanned += 1
        out.bytes += size
        out.partial += int(len(rows) >= max_rows)
        out.test_values += result.test_values
        out.suppressed += result.suppressed
        out.redaction_markers += result.redaction_markers
        on_table(schema, name, result)
        out.after = [schema, name]
    return out
