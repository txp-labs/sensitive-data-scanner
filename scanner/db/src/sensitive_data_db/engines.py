"""The engines: how to connect to each, check its user, and sample it read-only.

Every driver is an optional extra (`sensitive-data-scanner-db[postgresql]`, ...)
and is imported only when a database of its engine is configured; a missing
driver is the store's coverage gap (`driver_missing`), not a failure.

SQL engines share the core's sampled pass (`sensitive_data_core.scan.sql`):
list the base tables, then `SELECT * FROM "schema"."table" LIMIT n` with quoted
identifiers, read by column. Where the engine has one, the session and the
transaction are read-only (PostgreSQL, MySQL and MariaDB, Oracle), and every
transaction is rolled back. MongoDB is read with `$sample` per collection.

Connection strings are parsed here and handed to the driver; nothing here
logs, keeps or raises them. A driver's own exception is reported by its class
name only (`safety.error_name`).
"""

from __future__ import annotations

import datetime as _dt
import decimal
import importlib
import importlib.util
import json
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import TableResult, scan_rows
from sensitive_data_core.scan.sql import (
    DATABRICKS,
    ORACLE,
    SNOWFLAKE,
    SQLSERVER,
    Dialect,
    SqlPass,
    sample_tables,
)

from . import grants as g
from .config import Database, Settings

OnTable = Callable[[str, str, TableResult], None]
Params = list[tuple[str, str]]

PG = Dialect("postgresql", '"', "%({name})s")
MY = Dialect("mysql", "`", "%({name})s")
# The Python package each engine's driver is, and the extra that installs it.
DRIVERS = {
    "postgresql": "psycopg",
    "mysql": "pymysql",
    "sqlserver": "pymssql",
    "oracle": "oracledb",
    "mongodb": "pymongo",
    "snowflake": "snowflake.connector",
    "databricks": "databricks.sql",
}
MONGODB_SYSTEM_DATABASES = frozenset({"admin", "local", "config"})


class ReadRefused(Exception):
    """A read the scanner will not do; `reason` is the store's coverage gap."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def load_driver(engine: str, drivers: dict[str, Any] | None = None) -> Any | None:
    """The engine's driver module, or None when its extra is not installed."""
    if drivers is not None and engine in drivers:
        return drivers[engine]
    name = DRIVERS[engine]
    try:
        if importlib.util.find_spec(name.split(".")[0]) is None:
            return None
        return importlib.import_module(name)
    except ImportError:
        return None


@dataclass(frozen=True)
class Parsed:
    """The parts of a connection string a driver takes separately."""

    host: str
    port: int | None
    user: str
    password: str
    path: str  # without the leading "/"
    query: dict[str, str]

    def __repr__(self) -> str:
        return "Parsed(***)"


def parse(url: str) -> Parsed:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ReadRefused("error") from None
    query = {k: v for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)}
    return Parsed(
        host=parts.hostname or "",
        port=port,
        user=urllib.parse.unquote(parts.username or ""),
        password=urllib.parse.unquote(parts.password or ""),
        path=urllib.parse.unquote(parts.path.lstrip("/")),
        query=query,
    )


def _pick(query: dict[str, str], allowed: tuple[str, ...]) -> dict[str, str]:
    return {k: v for k, v in query.items() if k in allowed}


def _flag(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on", "required", "require")


# ------------------------------------------------------------------ SQL sessions


class SqlSession:
    """One DB-API connection: catalog queries, the grant check, and the sampled pass."""

    def __init__(
        self,
        engine: str,
        dialect: Dialect,
        conn: Any,
        *,
        database: str,
        check: Callable[[g.Execute], g.Grants],
        begin: tuple[str, ...] = (),
        flavor: str | None = None,
    ) -> None:
        self.engine = engine
        self.dialect = dialect
        self.conn = conn
        self.database = database
        self._check = check
        self._begin = begin
        self.flavor = flavor

    def __repr__(self) -> str:
        return f"SqlSession({self.engine})"

    def _bind(self, params: Params) -> Any:
        if self.dialect.placeholder == "?":
            return [v for _, v in params]
        return dict(params)

    def execute(self, sql: str, params: Params) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        try:
            if params:
                cur.execute(sql, self._bind(params))
            else:
                cur.execute(sql)
            if not cur.description:
                return []
            names = [str(d[0]) for d in cur.description]
            return [dict(zip(names, row, strict=False)) for row in cur.fetchall()]
        finally:
            cur.close()

    def rollback(self) -> None:
        try:
            self.conn.rollback()
        except Exception:  # an engine without transactions (Databricks) has nothing to undo
            return

    def grants(self) -> g.Grants:
        try:
            return self._check(self.execute)
        except Exception as err:
            return g.Grants(verified=False, error=error_name(err))
        finally:
            self.rollback()

    def read(
        self,
        *,
        settings: Settings,
        detector: Detector,
        has_room: Callable[[], bool],
        take: Callable[[int], None],
        on_table: OnTable,
        source: str,
    ) -> SqlPass:
        self.rollback()
        for statement in self._begin:
            self.execute(statement, [])
        try:
            return sample_tables(
                self.execute,
                self.dialect,
                detector=detector,
                has_room=has_room,
                take=take,
                on_table=on_table,
                after=None,
                schemas=settings.schemas,
                max_rows=settings.max_rows,
                max_tables=settings.max_tables,
                source=source,
            )
        finally:
            self.rollback()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # closing a broken connection: nothing left to do
            return


def connect_postgresql(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """libpq's own URL, with a read-only session and a statement timeout."""
    ms = settings.statement_seconds * 1000
    conn = driver.connect(
        db.url.reveal(),
        connect_timeout=settings.connect_seconds,
        application_name="sensitive-data-scanner",
        options=f"-c default_transaction_read_only=on -c statement_timeout={ms}",
    )
    database = str(conn.info.dbname) if getattr(conn, "info", None) is not None else ""
    return SqlSession(
        "postgresql",
        PG,
        conn,
        database=database,
        check=g.postgresql,
        begin=("SET TRANSACTION READ ONLY",),
    )


MYSQL_QUERY = ("ssl_ca", "ssl_cert", "ssl_key", "ssl_verify_cert", "ssl_verify_identity")


def connect_mysql(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """`mysql://user:password@host:3306/database` (MySQL and MariaDB); the session is read-only."""
    p = parse(db.url.reveal())
    if not p.path:
        raise ReadRefused("read_not_configured")  # the URL names no database to read
    extra: dict[str, Any] = _pick(p.query, MYSQL_QUERY)
    for k in ("ssl_verify_cert", "ssl_verify_identity"):
        if k in extra:
            extra[k] = _flag(extra[k])
    conn = driver.connect(
        host=p.host,
        port=p.port or 3306,
        user=p.user,
        password=p.password,
        database=p.path,
        connect_timeout=settings.connect_seconds,
        read_timeout=settings.statement_seconds,
        write_timeout=settings.statement_seconds,
        autocommit=False,
        charset="utf8mb4",
        init_command="SET SESSION TRANSACTION READ ONLY",
        **extra,
    )
    session = SqlSession(
        "mysql",
        MY,
        conn,
        database=p.path,
        check=g.mysql,
        begin=("START TRANSACTION READ ONLY",),
    )
    try:
        version = session.execute("SELECT VERSION() AS version", [])
        if version and "mariadb" in str(version[0].get("version", "")).lower():
            session.flavor = "mariadb"
    finally:
        session.rollback()
    return session


SQLSERVER_QUERY = ("encryption", "tds_version")


def connect_sqlserver(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """`sqlserver://user:password@host:1433/database` (SQL Server, Azure SQL, Managed Instance)."""
    p = parse(db.url.reveal())
    conn = driver.connect(
        server=p.host,
        port=str(p.port or 1433),
        user=p.user,
        password=p.password,
        database=p.path,
        login_timeout=settings.connect_seconds,
        timeout=settings.statement_seconds,
        appname="sensitive-data-scanner",
        autocommit=False,
        **_pick(p.query, SQLSERVER_QUERY),
    )
    return SqlSession("sqlserver", SQLSERVER, conn, database=p.path, check=g.sqlserver)


def connect_oracle(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """`oracle://user:password@host:1521/service_name`, thin mode (no Oracle Client)."""
    p = parse(db.url.reveal())
    conn = driver.connect(
        user=p.user,
        password=p.password,
        host=p.host,
        port=p.port or 1521,
        service_name=p.path,
        tcp_connect_timeout=settings.connect_seconds,
    )
    conn.call_timeout = settings.statement_seconds * 1000
    return SqlSession(
        "oracle",
        ORACLE,
        conn,
        database=p.path,
        check=g.oracle,
        begin=("SET TRANSACTION READ ONLY",),
    )


SNOWFLAKE_QUERY = ("warehouse", "role", "schema", "authenticator", "private_key_file")


def connect_snowflake(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """`snowflake://user:password@<account>/<database>?warehouse=...&role=...`."""
    p = parse(db.url.reveal())
    kwargs: dict[str, Any] = _pick(p.query, SNOWFLAKE_QUERY)
    if p.password:
        kwargs["password"] = p.password
    conn = driver.connect(
        account=p.host,
        user=p.user,
        database=p.path or None,
        login_timeout=settings.connect_seconds,
        network_timeout=settings.statement_seconds,
        autocommit=False,
        session_parameters={
            "QUERY_TAG": "sensitive-data-scanner",
            "STATEMENT_TIMEOUT_IN_SECONDS": settings.statement_seconds,
        },
        **kwargs,
    )
    return SqlSession("snowflake", SNOWFLAKE, conn, database=p.path, check=g.snowflake)


def connect_databricks(db: Database, settings: Settings, driver: Any) -> SqlSession:
    """`databricks://token:<token>@<workspace host>/<http path>?catalog=<catalog>`."""
    p = parse(db.url.reveal())
    catalog = p.query.get("catalog") or None
    conn = driver.connect(
        server_hostname=p.host,
        http_path="/" + p.path,
        access_token=p.password,
        catalog=catalog,
        _socket_timeout=settings.statement_seconds,
        user_agent_entry="sensitive-data-scanner",
    )
    return SqlSession("databricks", DATABRICKS, conn, database=catalog or "", check=g.databricks)


# ------------------------------------------------------------------ MongoDB


def _plain(v: Any, depth: int = 0) -> Any:
    """A BSON value as the scanner reads it: text, numbers and dates; ids and binary dropped."""
    if depth > 20:
        return None
    if v is None or isinstance(v, str | bool | int | float | decimal.Decimal | _dt.date):
        return v
    if isinstance(v, dict):
        return {str(k): _plain(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_plain(x, depth + 1) for x in v]
    to_decimal = getattr(v, "to_decimal", None)  # Decimal128
    if callable(to_decimal):
        return to_decimal()
    return None  # ObjectId, Binary, Regex, Code, Timestamp: never text a person typed


class MongoSession:
    """A MongoDB deployment (or Atlas cluster): its user's privileges, and `$sample` reads."""

    engine = "mongodb"
    flavor: str | None = None

    def __init__(self, client: Any, default_db: str | None, settings: Settings) -> None:
        self.client = client
        self.default_db = default_db
        self.database = default_db or ""
        self.settings = settings

    def __repr__(self) -> str:
        return "MongoSession()"

    def grants(self) -> g.Grants:
        try:
            status = self.client.admin.command("connectionStatus", showPrivileges=True)
        except Exception as err:
            return g.Grants(verified=False, error=error_name(err))
        return g.mongodb(status)

    def read(
        self,
        *,
        settings: Settings,
        detector: Detector,
        has_room: Callable[[], bool],
        take: Callable[[int], None],
        on_table: OnTable,
        source: str,
    ) -> SqlPass:
        out = SqlPass(after=None)
        names = (
            [self.default_db]
            if self.default_db
            else [n for n in self.client.list_database_names() if n not in MONGODB_SYSTEM_DATABASES]
        )
        collections: list[tuple[str, str]] = []
        for db_name in sorted(names):
            db = self.client[db_name]
            for c in db.list_collections(filter={"type": {"$in": ["collection", "timeseries"]}}):
                name = str(c.get("name", ""))
                if name and not name.startswith("system."):
                    collections.append((db_name, name))
        collections = sorted(collections)[: settings.max_tables]
        out.listed = out.eligible = len(collections)
        out.done = True
        ms = settings.statement_seconds * 1000
        for db_name, name in collections:
            if not has_room():
                out.done = False
                break
            try:
                cursor = self.client[db_name][name].aggregate(
                    [{"$sample": {"size": settings.max_rows}}], maxTimeMS=ms
                )
                docs = [_plain(d) for d in cursor]
            except Exception as err:  # one collection must not stop the pass
                out.unreadable += 1
                e = error_name(err)
                out.errors[e] = out.errors.get(e, 0) + 1
                log_event("item.unreadable", source=source, error=e)
                continue
            size = len(json.dumps(docs, default=str))
            take(size)
            columns = list(dict.fromkeys(k for d in docs for k in d))
            result = scan_rows("json", columns, docs, detector, settings.max_rows)
            out.scanned += 1
            out.bytes += size
            out.partial += int(len(docs) >= settings.max_rows)
            out.test_values += result.test_values
            out.suppressed += result.suppressed
            out.redaction_markers += result.redaction_markers
            on_table(db_name, name, result)
        return out

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:  # nothing left to do
            return


def connect_mongodb(db: Database, settings: Settings, driver: Any) -> MongoSession:
    """`mongodb://` or `mongodb+srv://` (Atlas). Reads prefer a secondary; nothing is written."""
    url = db.url.reveal()
    # A replica set lists several hosts, which urlsplit cannot parse: take the path by hand.
    path = url.split("://", 1)[-1].partition("/")[2].partition("?")[0]
    default_db = urllib.parse.unquote(path.split("/")[0]) or None
    client = driver.MongoClient(
        url,
        appname="sensitive-data-scanner",
        serverSelectionTimeoutMS=settings.connect_seconds * 1000,
        connectTimeoutMS=settings.connect_seconds * 1000,
        socketTimeoutMS=settings.statement_seconds * 1000,
        readPreference="secondaryPreferred",
        retryWrites=False,
    )
    return MongoSession(client, default_db, settings)


CONNECT: dict[str, Callable[[Database, Settings, Any], Any]] = {
    "postgresql": connect_postgresql,
    "mysql": connect_mysql,
    "sqlserver": connect_sqlserver,
    "oracle": connect_oracle,
    "mongodb": connect_mongodb,
    "snowflake": connect_snowflake,
    "databricks": connect_databricks,
}
