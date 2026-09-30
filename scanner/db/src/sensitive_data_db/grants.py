"""Before reading: can the database user write? If so, the store is refused.

Each check lists the user's privileges from the database's own catalog and
keeps the ones that are not reads, by name (never a value). Every list below
is an allow list of reads: anything the database grants that is not on it
counts as a write, so a privilege the scanner does not know is refused, not
waved through. A check that cannot run (the catalog is hidden from the user)
is `verified=False`, and the store is refused as `grants_unverifiable`.

`execute(sql, params)` runs one statement and returns its rows as dicts; the
statements here are catalog SELECTs and SHOW commands only.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

Execute = Callable[[str, list[tuple[str, str]]], list[dict[str, Any]]]
MAX_ROLES = 50


@dataclass
class Grants:
    """What the user may do beyond reading: privilege names, and whether that could be checked."""

    write: set[str] = field(default_factory=set)
    verified: bool = True
    error: str | None = None


def _value(row: dict[str, Any], *names: str) -> Any:
    lower = {str(k).lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "t", "true", "yes", "y")
    return bool(v)


# ---------------------------------------------------------------- PostgreSQL

POSTGRESQL_SQL = (
    "SELECT r.rolsuper AS superuser, r.rolcreaterole AS createrole, r.rolcreatedb AS createdb, "
    "has_database_privilege(current_database(), 'CREATE') AS database_create, "
    "(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
    "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname NOT LIKE 'pg\\_%' "
    "AND has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')) AS table_write, "
    "(SELECT count(*) FROM pg_namespace n "
    "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname NOT LIKE 'pg\\_%' "
    "AND has_schema_privilege(n.oid, 'CREATE')) AS schema_create "
    "FROM pg_roles r WHERE r.rolname = current_user"
)


def postgresql(execute: Execute) -> Grants:
    """Superuser, CREATEROLE, CREATEDB, CREATE on the database or a schema, and INSERT,
    UPDATE, DELETE or TRUNCATE on any table or view (directly, by role or through PUBLIC)."""
    rows = execute(POSTGRESQL_SQL, [])
    if not rows:
        return Grants(verified=False)
    row = rows[0]
    out = Grants()
    for name in ("superuser", "createrole", "createdb", "database_create"):
        if _truthy(_value(row, name)):
            out.write.add(name)
    for name in ("table_write", "schema_create"):
        if int(_value(row, name) or 0) > 0:
            out.write.add(name)
    return out


# ---------------------------------------------------------------- MySQL and MariaDB

MYSQL_READS = frozenset(
    {"SELECT", "SHOW VIEW", "USAGE", "SHOW DATABASES", "PROCESS", "REPLICATION CLIENT"}
)
_GRANT_ON = re.compile(r"^GRANT (.+?) ON (.+?) TO ", re.S)
_GRANT_ROLES = re.compile(r"^GRANT (.+?) TO ", re.S)


def _mysql_privileges(text: str) -> set[str]:
    # Column privileges are `SELECT (a, b)`: the parenthesis is not a privilege.
    text = re.sub(r"\([^)]*\)", "", text)
    return {p.strip().upper() for p in text.split(",") if p.strip()}


def mysql_parse(lines: Iterable[str]) -> tuple[set[str], list[str]]:
    """Write privileges on `SHOW GRANTS` lines, and the roles granted (quoted by the server)."""
    write: set[str] = set()
    roles: list[str] = []
    for line in lines:
        text = line.strip()
        if " WITH GRANT OPTION" in text.upper():
            write.add("GRANT OPTION")
        m = _GRANT_ON.match(text)
        if m:
            for p in _mysql_privileges(m[1]):
                if p not in MYSQL_READS:
                    write.add(p)
            continue
        m = _GRANT_ROLES.match(text)
        if m:
            roles.extend(r.strip() for r in m[1].split(",") if r.strip())
    return write, roles


def _grant_lines(rows: list[dict[str, Any]]) -> list[str]:
    return [str(next(iter(r.values()))) for r in rows if r]


def mysql(execute: Execute) -> Grants:
    """`SHOW GRANTS` for the current user, with the privileges of every role granted to it
    (active or not, since the user can activate them): MySQL 8's `USING`, else MariaDB's
    `SHOW GRANTS FOR <role>`."""
    write, roles = mysql_parse(_grant_lines(execute("SHOW GRANTS FOR CURRENT_USER()", [])))
    out = Grants(write=write)
    if not roles:
        return out
    roles = roles[:MAX_ROLES]
    using = "SHOW GRANTS FOR CURRENT_USER() USING " + ", ".join(roles)
    try:
        lines = _grant_lines(execute(using, []))
    except Exception:  # MariaDB has no USING: ask for each role (and the roles it holds)
        lines = None
    if lines is not None:
        more, _ = mysql_parse(lines)
        out.write |= more
        return out
    seen: set[str] = set()
    todo = list(roles)
    while todo and len(seen) < MAX_ROLES:
        role = todo.pop()
        if role in seen:
            continue
        seen.add(role)
        try:
            w, inner = mysql_parse(_grant_lines(execute(f"SHOW GRANTS FOR {role}", [])))
        except Exception:
            return Grants(write=out.write, verified=False)
        out.write |= w
        todo.extend(inner)
    return out


# ---------------------------------------------------------------- SQL Server

SQLSERVER_READS = frozenset({"CONNECT", "SELECT", "SHOWPLAN", "REFERENCES"})
SQLSERVER_ROLES_SQL = (
    "SELECT IS_SRVROLEMEMBER('sysadmin') AS sysadmin, IS_ROLEMEMBER('db_owner') AS db_owner, "
    "IS_ROLEMEMBER('db_datawriter') AS db_datawriter, IS_ROLEMEMBER('db_ddladmin') AS db_ddladmin"
)
SQLSERVER_DATABASE_SQL = "SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE')"
_SQLSERVER_OBJECT = "QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name), 'OBJECT'"
SQLSERVER_OBJECTS_SQL = (
    "SELECT COUNT(*) AS objects FROM sys.objects o WHERE o.type IN ('U', 'V') AND ("  # noqa: S608 - fixed text
    f"HAS_PERMS_BY_NAME({_SQLSERVER_OBJECT}, 'INSERT') = 1 OR "
    f"HAS_PERMS_BY_NAME({_SQLSERVER_OBJECT}, 'UPDATE') = 1 OR "
    f"HAS_PERMS_BY_NAME({_SQLSERVER_OBJECT}, 'DELETE') = 1 OR "
    f"HAS_PERMS_BY_NAME({_SQLSERVER_OBJECT}, 'ALTER') = 1)"
)


def sqlserver(execute: Execute) -> Grants:
    """sysadmin, db_owner, db_datawriter, db_ddladmin; any database permission that is not a
    read (`VIEW ...`, CONNECT, SELECT, SHOWPLAN, REFERENCES); and INSERT, UPDATE, DELETE or
    ALTER on any table or view."""
    out = Grants()
    roles = execute(SQLSERVER_ROLES_SQL, [])
    for name in ("sysadmin", "db_owner", "db_datawriter", "db_ddladmin"):
        if roles and _value(roles[0], name) == 1:
            out.write.add(name)
    for r in execute(SQLSERVER_DATABASE_SQL, []):
        p = str(_value(r, "permission_name") or "").upper()
        if p and p not in SQLSERVER_READS and not p.startswith("VIEW "):
            out.write.add(p)
    objects = execute(SQLSERVER_OBJECTS_SQL, [])
    if objects and int(_value(objects[0], "objects") or 0) > 0:
        out.write.add("table_write")
    return out


# ---------------------------------------------------------------- Oracle

ORACLE_READS = frozenset(
    {
        "CREATE SESSION",
        "ALTER SESSION",
        "SELECT ANY TABLE",
        "READ ANY TABLE",
        "SELECT ANY DICTIONARY",
        "SELECT ANY SEQUENCE",
        "SET CONTAINER",
    }
)
ORACLE_SYSTEM_SQL = "SELECT privilege FROM session_privs"
ORACLE_OBJECTS_SQL = (
    "SELECT COUNT(*) AS objects FROM all_tab_privs WHERE grantee IN "
    "(SELECT USER FROM dual UNION SELECT role FROM session_roles UNION SELECT 'PUBLIC' FROM dual) "
    "AND privilege IN ('INSERT', 'UPDATE', 'DELETE', 'ALTER', 'INDEX', 'UNDER')"
)
ORACLE_OWNED_SQL = "SELECT COUNT(*) AS tables FROM user_tables"


def oracle(execute: Execute) -> Grants:
    """Any system privilege that is not a read; INSERT, UPDATE, DELETE, ALTER, INDEX or UNDER
    on any object (to the user, its roles or PUBLIC); and tables the user owns."""
    out = Grants()
    for r in execute(ORACLE_SYSTEM_SQL, []):
        p = str(_value(r, "privilege") or "").upper()
        if p and p not in ORACLE_READS:
            out.write.add(p)
    objects = execute(ORACLE_OBJECTS_SQL, [])
    if objects and int(_value(objects[0], "objects") or 0) > 0:
        out.write.add("object_write")
    owned = execute(ORACLE_OWNED_SQL, [])
    if owned and int(_value(owned[0], "tables") or 0) > 0:
        out.write.add("owns_tables")
    return out


# ---------------------------------------------------------------- Snowflake

SNOWFLAKE_READS = frozenset(
    {"USAGE", "SELECT", "REFERENCES", "MONITOR", "OPERATE", "READ", "IMPORTED PRIVILEGES"}
)
SNOWFLAKE_ADMIN_ROLES = frozenset(
    {"ACCOUNTADMIN", "SYSADMIN", "SECURITYADMIN", "USERADMIN", "ORGADMIN"}
)


def _sf_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def snowflake(execute: Execute) -> Grants:
    """Every role the user holds (the current one, the ones granted to the user, and the
    roles those hold): an administrative role, or any privilege that is not a read
    (OWNERSHIP, INSERT, CREATE ..., MODIFY, ALL)."""
    out = Grants()
    who = execute("SELECT CURRENT_ROLE() AS role, CURRENT_USER() AS name", [])
    if not who:
        return Grants(verified=False)
    todo = [str(_value(who[0], "role") or "")]
    user = str(_value(who[0], "name") or "")
    try:
        granted = execute(f"SHOW GRANTS TO USER {_sf_ident(user)}", [])
    except Exception:  # the user's own grants are hidden: the current role's chain still counts
        granted = []
    todo.extend(str(_value(r, "role") or "") for r in granted)
    seen: set[str] = set()
    while todo:
        role = todo.pop()
        if not role or role in seen:
            continue
        if len(seen) >= MAX_ROLES:
            return Grants(write=out.write, verified=False)
        seen.add(role)
        if role.upper() in SNOWFLAKE_ADMIN_ROLES:
            out.write.add(role.upper())
        for r in execute(f"SHOW GRANTS TO ROLE {_sf_ident(role)}", []):
            privilege = str(_value(r, "privilege") or "").upper()
            granted_on = str(_value(r, "granted_on") or "").upper()
            if privilege == "USAGE" and granted_on == "ROLE":
                todo.append(str(_value(r, "name") or ""))
            elif privilege and privilege not in SNOWFLAKE_READS:
                out.write.add(privilege)
    return out


# ---------------------------------------------------------------- Databricks (Unity Catalog)

DATABRICKS_READS = frozenset(
    {"SELECT", "USE CATALOG", "USE SCHEMA", "BROWSE", "READ VOLUME", "EXECUTE", "READ FILES"}
)
_DBX_MINE = "(grantee = current_user() OR is_account_group_member(grantee))"


def databricks_sql() -> list[str]:
    """The current catalog's privileges held by the user or a group it is in, and ownership."""
    out = [
        f"SELECT DISTINCT privilege_type FROM information_schema.{level}_privileges "  # noqa: S608 - fixed names
        f"WHERE {_DBX_MINE}"
        for level in ("catalog", "schema", "table", "volume")
    ]
    out.append(
        "SELECT COUNT(*) AS owned FROM information_schema.tables "
        "WHERE table_owner = current_user() OR is_account_group_member(table_owner)"
    )
    out.append(
        "SELECT COUNT(*) AS owned FROM information_schema.schemata "
        "WHERE schema_owner = current_user() OR is_account_group_member(schema_owner)"
    )
    return out


def databricks(execute: Execute) -> Grants:
    """Any privilege in the catalog that is not a read (MODIFY, ALL PRIVILEGES, CREATE ...,
    WRITE VOLUME, MANAGE), and owning a table or schema. Unity Catalog only."""
    out = Grants()
    for sql in databricks_sql():
        for r in execute(sql, []):
            if "privilege_type" in {str(k).lower() for k in r}:
                p = str(_value(r, "privilege_type") or "").upper().replace("_", " ")
                if p and p not in DATABRICKS_READS:
                    out.write.add(p)
            elif int(_value(r, "owned") or 0) > 0:
                out.write.add("owner")
    return out


# ---------------------------------------------------------------- MongoDB

MONGODB_READS = frozenset(
    {
        "find",
        "listCollections",
        "listIndexes",
        "listDatabases",
        "listSearchIndexes",
        "collStats",
        "dbStats",
        "dbHash",
        "indexStats",
        "killCursors",
        "changeStream",
        "planCacheRead",
        "serverStatus",
        "hostInfo",
        "connPoolStats",
        "getParameter",
        "getCmdLineOpts",
        "getLog",
        "getShardMap",
        "listShards",
        "netstat",
        "replSetGetConfig",
        "replSetGetStatus",
        "top",
        "inprog",
        "validate",
        "listSessions",
        "useUUID",
        "bypassDefaultMaxTimeMS",
    }
)


def mongodb(status: dict[str, Any]) -> Grants:
    """From `connectionStatus` with `showPrivileges`: any action that is not a read, on any
    resource. With no authenticated user (access control off) everyone can write."""
    info = status.get("authInfo") or {}
    if not info.get("authenticatedUsers"):
        return Grants(write={"no_authentication"})
    privileges = info.get("authenticatedUserPrivileges")
    if privileges is None:
        return Grants(verified=False)
    out = Grants()
    for p in privileges:
        for action in p.get("actions") or []:
            if str(action) not in MONGODB_READS:
                out.write.add(re.sub(r"[^A-Za-z0-9_]", "", str(action))[:60])
    return out
