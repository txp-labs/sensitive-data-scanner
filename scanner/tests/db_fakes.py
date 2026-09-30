"""Stubbed database drivers for the databases runner: DB-API connections and a MongoDB client.

Each fake answers the statements the runner sends from a small in-memory
database, and records every statement and every connect argument, so a test
can check what was sent and that nothing but reads was. Every value is made up.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.scan.sql import SYSTEM_SCHEMAS

Rows = list[dict[str, Any]]
Answer = Callable[[str, Any], Rows | None]

# The statements a read-only run may send, by their first words.
READ_VERBS = re.compile(
    r"^\s*(SELECT|SHOW|SET (SESSION )?TRANSACTION READ ONLY|START TRANSACTION READ ONLY)\b", re.I
)
_QUOTED = r'(?:"((?:[^"]|"")*)"|`((?:[^`]|``)*)`|\[((?:[^\]]|\]\])*)\])'
SAMPLE = re.compile(r"^SELECT (?:TOP \(\d+\) )?\* FROM " + _QUOTED + r"\." + _QUOTED)


def _unquote(groups: tuple[str | None, ...]) -> str:
    for g, q in zip(groups, ('"', "`", "]"), strict=True):
        if g is not None:
            return g.replace(q + q, q)
    return ""


@dataclass
class Db:
    """An in-memory database: tables by (schema, table), and the answers to catalog queries."""

    tables: dict[tuple[str, str], Rows] = field(default_factory=dict)
    catalog: list[tuple[re.Pattern[str], Rows | Exception]] = field(default_factory=list)
    unreadable: set[tuple[str, str]] = field(default_factory=set)

    def on(self, pattern: str, rows: Rows | Exception) -> Db:
        self.catalog.append((re.compile(pattern, re.I | re.S), rows))
        return self

    def answer(self, sql: str, params: Any) -> Rows | None:
        if re.match(r"^\s*(SET|START)\b", sql, re.I):
            return None
        m = SAMPLE.match(sql)
        if m:
            key = (_unquote(m.groups()[:3]), _unquote(m.groups()[3:]))
            if key in self.unreadable:
                raise PermissionError("denied")
            return list(self.tables.get(key, []))
        if re.search(r"table_type|all_tables", sql, re.I):
            wanted = set(dict(params).values()) if isinstance(params, dict) else set(params or [])
            system = {s for v in SYSTEM_SCHEMAS.values() for s in v}
            return [
                {"table_schema": s, "table_name": t}
                for s, t in sorted(self.tables)
                if (not wanted or s in wanted) and s not in system
            ]
        for pattern, rows in self.catalog:
            if pattern.search(sql):
                if isinstance(rows, Exception):
                    raise rows
                return rows
        raise AssertionError(f"unexpected statement: {sql[:80]}")


class Cursor:
    def __init__(self, conn: Conn) -> None:
        self.conn = conn
        self.description: list[tuple[str]] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.conn.statements.append(sql)
        rows = self.conn.db.answer(sql, params)
        if rows is None:
            self.description, self._rows = None, []
            return
        cols = list(dict.fromkeys(k for r in rows for k in r)) or ["x"]
        self.description = [(c,) for c in cols]
        self._rows = [tuple(r.get(c) for c in cols) for r in rows]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def close(self) -> None:
        return None


class Info:
    dbname = "app"


class Conn:
    def __init__(self, db: Db) -> None:
        self.db = db
        self.statements: list[str] = []
        self.rollbacks = 0
        self.closed = False
        self.info = Info()
        self.call_timeout = 0

    def cursor(self) -> Cursor:
        return Cursor(self)

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class Driver:
    """A DB-API module: `connect(...)` records its arguments and returns a Conn on `db`."""

    def __init__(self, db: Db, fail: Exception | None = None) -> None:
        self.db = db
        self.fail = fail
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.conns: list[Conn] = []

    def connect(self, *args: Any, **kwargs: Any) -> Conn:
        self.calls.append((args, kwargs))
        if self.fail is not None:
            raise self.fail
        conn = Conn(self.db)
        self.conns.append(conn)
        return conn

    def statements(self) -> list[str]:
        return [s for c in self.conns for s in c.statements]


# ------------------------------------------------------------------ MongoDB


class Collection:
    def __init__(self, docs: list[dict[str, Any]], fail: Exception | None = None) -> None:
        self.docs = docs
        self.fail = fail
        self.pipelines: list[Any] = []

    def aggregate(self, pipeline: list[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
        self.pipelines.append(pipeline)
        if self.fail is not None:
            raise self.fail
        size = pipeline[0]["$sample"]["size"]
        return self.docs[:size]


class MongoDb:
    def __init__(self, collections: dict[str, Collection], views: tuple[str, ...] = ()) -> None:
        self.collections = collections
        self.views = views

    def list_collections(self, filter: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"name": n, "type": "collection"} for n in self.collections]

    def __getitem__(self, name: str) -> Collection:
        return self.collections[name]


class Admin:
    def __init__(self, status: dict[str, Any] | Exception) -> None:
        self.status = status

    def command(self, name: str, **kwargs: Any) -> dict[str, Any]:
        assert name == "connectionStatus"
        assert kwargs == {"showPrivileges": True}
        if isinstance(self.status, Exception):
            raise self.status
        return self.status


class MongoClient:
    def __init__(self, dbs: dict[str, MongoDb], status: dict[str, Any] | Exception) -> None:
        self.dbs = dbs
        self.admin = Admin(status)
        self.closed = False

    def list_database_names(self) -> list[str]:
        return [*self.dbs, "admin", "local", "config"]

    def __getitem__(self, name: str) -> MongoDb:
        return self.dbs[name]

    def close(self) -> None:
        self.closed = True


class MongoDriver:
    def __init__(self, client: MongoClient) -> None:
        self.client = client
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def MongoClient(self, *args: Any, **kwargs: Any) -> MongoClient:
        self.calls.append((args, kwargs))
        return self.client


def read_only_mongo_status() -> dict[str, Any]:
    return {
        "authInfo": {
            "authenticatedUsers": [{"user": "scanner", "db": "admin"}],
            "authenticatedUserPrivileges": [
                {"resource": {"db": "", "collection": ""}, "actions": ["find", "listCollections"]},
                {"resource": {"cluster": True}, "actions": ["listDatabases"]},
            ],
        }
    }
