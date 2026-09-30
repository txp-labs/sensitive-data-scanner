"""Azure's databases: Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible
servers, and Synapse dedicated SQL pools. Discovered by default, read when opted in.

**Discovery** (Resource Graph, Reader) lists every database of each kind across
the subscriptions in scope: Azure SQL databases and their servers, Managed
Instance databases and their instances, PostgreSQL and MySQL flexible servers
(their databases from Resource Manager), and Synapse workspaces' dedicated SQL
pools. System databases are not stores. A paused serverless database or pool,
or a stopped server, is `paused`: connecting would resume it.

**Reading** (`AZURE_DB_READ`, off by default) connects as the job's managed
identity with an **Entra ID token**: no password exists. The customer creates
the identity as a contained database user with read access only (docs/AZURE.md
has the T-SQL and SQL). Then, as the databases runner does:

1. **the user is checked first**, with the core's allow list of reads
   (`sensitive_data_core.grants`); a user that can write is refused as
   `db_user_can_write` with its privileges by name, and one whose privileges
   cannot be read as `grants_unverifiable`; nothing is read from either;
2. the core's sampled pass (`scan/sql.py`): the base tables, then
   `SELECT TOP (n) *` / `SELECT * ... LIMIT n` with quoted identifiers, in a
   read-only transaction where the engine has one, always rolled back.
   SQL connections also ask for `ApplicationIntent=ReadOnly`, which routes to
   a readable secondary where the tier has one.

A database the job cannot reach (public access off with no private path, a
firewall that does not admit it) is the `network` gap; a login the database
refuses (no contained user yet) is `access_denied`; a PostgreSQL server with
Entra authentication off is `no_read_path`, since the scanner never uses a
password. A driver the image does not carry is `driver_missing`.

**Encryption (1.5)** comes from Resource Manager (Reader): an Azure SQL
server's or a Managed Instance's TDE protector (`ServiceManaged` or an
`AzureKeyVault` key, hashed) and the database's TDE state; a flexible
server's `dataEncryption`; a Synapse workspace's customer key. TDE off is
`unknown`, as in the databases runner: a database cannot see the disk under it.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sensitive_data_core import grants as g
from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import (
    UNKNOWN_ENCRYPTION,
    Coverage,
    encryption_facts,
    store_field_resource,
)
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import TableResult
from sensitive_data_core.scan.sql import SQLSERVER, sample_tables
from sensitive_data_db.engines import MY, PG, SqlSession

from ..config import Settings
from ..resources import ResourceId, azure_fields, portal_link
from .base import Context, key_facts

SQL_API = "2023-08-01"
PG_API = "2024-08-01"
MYSQL_API = "2023-12-30"
# The token audience of Azure Database for PostgreSQL and MySQL.
OSSRDBMS_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"
MAX_WRITE_GRANTS = 30

SYSTEM_DATABASES = {
    "azure_sql": frozenset({"master"}),
    "azure_sql_mi": frozenset({"master", "model", "msdb", "tempdb"}),
    "azure_postgresql": frozenset({"azure_maintenance", "azure_sys", "template0", "template1"}),
    "azure_mysql": frozenset({"information_schema", "mysql", "performance_schema", "sys"}),
    "synapse_sql": frozenset(),
}
DRIVERS = {
    "azure_sql": "mssql_python",
    "azure_sql_mi": "mssql_python",
    "synapse_sql": "mssql_python",
    "azure_postgresql": "psycopg",
    "azure_mysql": "pymysql",
}

SQL_SERVERS = """resources
| where type =~ 'microsoft.sql/servers'
| project id, name, tags,
    fqdn = tostring(properties.fullyQualifiedDomainName),
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
| order by id asc"""
SQL_DATABASES = """resources
| where type =~ 'microsoft.sql/servers/databases'
| project id, name, tags,
    status = tostring(properties.status),
    keyUri = tostring(properties.encryptionProtector)
| order by id asc"""
MANAGED_INSTANCES = """resources
| where type =~ 'microsoft.sql/managedinstances'
| project id, name, tags,
    fqdn = tostring(properties.fullyQualifiedDomainName),
    dnsZone = tostring(properties.dnsZone),
    publicDataEndpoint = tobool(properties.publicDataEndpointEnabled),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    state = tostring(properties.state)
| order by id asc"""
MANAGED_INSTANCE_DATABASES = """resources
| where type =~ 'microsoft.sql/managedinstances/databases'
| project id, name, tags, status = tostring(properties.status)
| order by id asc"""
POSTGRESQL_SERVERS = """resources
| where type =~ 'microsoft.dbforpostgresql/flexibleservers'
| project id, name, tags,
    fqdn = tostring(properties.fullyQualifiedDomainName),
    state = tostring(properties.state),
    publicNetworkAccess = tostring(properties.network.publicNetworkAccess),
    entraAuth = tostring(properties.authConfig.activeDirectoryAuth),
    keyType = tostring(properties.dataEncryption.type),
    keyUri = tostring(properties.dataEncryption.primaryKeyURI)
| order by id asc"""
MYSQL_SERVERS = """resources
| where type =~ 'microsoft.dbformysql/flexibleservers'
| project id, name, tags,
    fqdn = tostring(properties.fullyQualifiedDomainName),
    state = tostring(properties.state),
    publicNetworkAccess = tostring(properties.network.publicNetworkAccess),
    keyType = tostring(properties.dataEncryption.type),
    keyUri = tostring(properties.dataEncryption.primaryKeyURI)
| order by id asc"""
SYNAPSE_WORKSPACES = """resources
| where type =~ 'microsoft.synapse/workspaces'
| project id, name, tags,
    sqlEndpoint = tostring(properties.connectivityEndpoints.sql),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    keyUri = tostring(properties.encryption.cmk.key.keyVaultUrl)
| order by id asc"""
SYNAPSE_POOLS = """resources
| where type =~ 'microsoft.synapse/workspaces/sqlpools'
| project id, name, tags, status = tostring(properties.status)
| order by id asc"""

# What a driver's message says when the database could not be reached, or refused the
# login. The message is only looked at here, never kept, logged or returned.
_NETWORK_HINTS = (
    "timeout",
    "timed out",
    "could not connect",
    "can't connect",
    "connection refused",
    "unreachable",
    "no route to host",
    "name or service not known",
    "could not translate host",
    "nodename nor servname",
    "40615",  # Azure SQL: the client's IP is not allowed by the firewall
    "47073",  # Azure SQL: public network access is denied
    "08001",
)
_DENIED_HINTS = (
    "18456",  # SQL Server: login failed
    "login failed",
    "password authentication failed",
    "authentication failed",
    "no pg_hba.conf entry",
    "28000",
    "1045",  # MySQL: access denied
    "access denied",
)


def connect_gap(err: BaseException) -> str | None:
    """`network`, `access_denied`, or None, from a connect error. Never keeps the message."""
    text = str(err).lower()
    name = error_name(err).lower()
    if any(h in text for h in _NETWORK_HINTS) or "timeout" in name:
        return "network"
    if any(h in text for h in _DENIED_HINTS):
        return "access_denied"
    return None


@dataclass
class DbTarget:
    """One database, and where to reach it."""

    kind: str
    rid: ResourceId  # the database's (or SQL pool's) own resource
    server: str  # the server, instance or workspace
    database: str
    host: str
    port: int
    network_restricted: bool = False

    def __repr__(self) -> str:
        return f"DbTarget({self.kind!r}, {redact_digits(self.server)!r})"


def _tags(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _parent(resource_id: str, child: str) -> str:
    """The parent resource's ID, lower-cased: `.../servers/s/databases/d` -> `.../servers/s`."""
    low = resource_id.lower()
    i = low.rfind(f"/{child}/")
    return low[:i] if i >= 0 else low


def _disabled(v: Any) -> bool:
    return str(v or "").strip().lower() == "disabled"


def sql_facts(
    protector: dict[str, Any] | None, tde: str | None, db_key: str | None
) -> dict[str, str]:
    """An Azure SQL database's or Managed Instance's storage encryption (1.5)."""
    if db_key:
        return key_facts("Microsoft.Keyvault", db_key)  # a database-level customer key
    if tde is not None and tde.lower() != "enabled":
        return encryption_facts(UNKNOWN_ENCRYPTION)
    if not protector:
        return encryption_facts(UNKNOWN_ENCRYPTION)
    kind = str(protector.get("serverKeyType") or "").lower()
    if kind == "azurekeyvault":
        return key_facts("Microsoft.Keyvault", str(protector.get("uri") or ""))
    if kind == "servicemanaged":
        return key_facts("Microsoft.Storage")
    return encryption_facts(UNKNOWN_ENCRYPTION)


def flexible_facts(key_type: str | None, key_uri: str | None) -> dict[str, str]:
    """A PostgreSQL or MySQL flexible server's `dataEncryption` (1.5)."""
    kind = str(key_type or "").lower()
    if kind == "azurekeyvault":
        return key_facts("Microsoft.Keyvault", key_uri)
    if kind in ("systemmanaged", ""):
        return key_facts("Microsoft.Storage")
    return encryption_facts(UNKNOWN_ENCRYPTION)


class DatabaseAdapter:
    """One kind of Azure database; each database (or SQL pool) is a store."""

    def __init__(self, kind: str) -> None:
        self.kind = kind

    def discover(self, ctx: Context, out: Discovery) -> None:
        listing: Callable[[Context, Discovery], None] = getattr(self, f"_{self.kind}")
        listing(ctx, out)

    # ------------------------------------------------------------------ listing

    def _store(self, ctx: Context, out: Discovery, target: DbTarget, tags: dict[str, str]) -> Store:
        store = Store(self.kind, f"{target.server}/{target.database}", tags=tags)
        store.extra.update(azure_fields(target.rid))
        store.extra["database"] = target.database
        if target.network_restricted:
            store.extra["networkRestricted"] = True
        store.table = target
        out.stores.append(store)
        return store

    def _decide(
        self, ctx: Context, store: Store, *, paused: bool = False, no_path: bool = False
    ) -> None:
        if paused:
            store.skip("paused")  # connecting would resume it, and bill for it
            return
        s = ctx.settings
        if not apply_rules(store, s.allow, s.deny):
            return
        if no_path:
            store.skip("no_read_path")  # Entra authentication is off: no password is used
            return
        if self.kind not in s.db_read:
            store.skip("read_not_configured")

    def _failed_listing(self, out: Discovery, rid: ResourceId, server: str, err: Exception) -> None:
        store = Store(self.kind, f"{server}/*")
        store.extra.update(azure_fields(rid))
        store.status, store.error = "error", error_name(err)
        store.reason = reason_for(store.error)
        out.stores.append(store)

    def _protector(self, ctx: Context, parent_id: str) -> dict[str, Any] | None:
        try:
            got = ctx.clients.client("arm").get(f"{parent_id}/encryptionProtector/current", SQL_API)
        except Exception as err:  # the key stays unknown; the database is still listed
            log_event("discovery.failed", kind=self.kind, error=error_name(err))
            return None
        props = got.get("properties") if isinstance(got, dict) else None
        return props if isinstance(props, dict) else None

    def _azure_sql(self, ctx: Context, out: Discovery) -> None:
        servers = {str(r.get("id") or "").lower(): r for r in ctx.graph(SQL_SERVERS)}
        protectors: dict[str, dict[str, Any] | None] = {}
        arm = ctx.clients.client("arm")
        for row in ctx.graph(SQL_DATABASES):
            rid = ResourceId.parse(str(row.get("id") or ""))
            if rid.name.lower() in SYSTEM_DATABASES[self.kind]:
                continue
            server_id = _parent(rid.value, "databases")
            srv = servers.get(server_id, {})
            server = str(srv.get("name") or ResourceId.parse(server_id).name)
            target = DbTarget(
                self.kind,
                rid,
                server,
                rid.name,
                str(srv.get("fqdn") or f"{server}.database.windows.net"),
                1433,
                _disabled(srv.get("publicNetworkAccess")),
            )
            store = self._store(ctx, out, target, _tags(row.get("tags")) or _tags(srv.get("tags")))
            if server_id not in protectors:
                protectors[server_id] = self._protector(ctx, str(srv.get("id") or server_id))
            tde: str | None = None
            try:
                got = arm.get(f"{rid.value}/transparentDataEncryption/current", SQL_API)
                tde = str((got.get("properties") or {}).get("state") or "") or None
            except Exception as err:  # TDE's state unknown: the protector still says the key
                log_event("discovery.failed", kind=self.kind, error=error_name(err))
            store.facts = sql_facts(
                protectors[server_id], tde, str(row.get("keyUri") or "") or None
            )
            self._decide(ctx, store, paused=str(row.get("status") or "").lower() == "paused")

    def _azure_sql_mi(self, ctx: Context, out: Discovery) -> None:
        instances = {str(r.get("id") or "").lower(): r for r in ctx.graph(MANAGED_INSTANCES)}
        protectors: dict[str, dict[str, Any] | None] = {}
        for row in ctx.graph(MANAGED_INSTANCE_DATABASES):
            rid = ResourceId.parse(str(row.get("id") or ""))
            if rid.name.lower() in SYSTEM_DATABASES[self.kind]:
                continue
            mi_id = _parent(rid.value, "databases")
            mi = instances.get(mi_id, {})
            name = str(mi.get("name") or ResourceId.parse(mi_id).name)
            if mi.get("publicDataEndpoint") and mi.get("dnsZone"):
                # The public data endpoint, when on: reachable without the instance's VNet.
                host, port = f"{name}.public.{mi['dnsZone']}.database.windows.net", 3342
            else:
                host, port = str(mi.get("fqdn") or ""), 1433
            target = DbTarget(
                self.kind, rid, name, rid.name, host, port, not mi.get("publicDataEndpoint")
            )
            store = self._store(ctx, out, target, _tags(row.get("tags")) or _tags(mi.get("tags")))
            if mi_id not in protectors:
                protectors[mi_id] = self._protector(ctx, str(mi.get("id") or mi_id))
            store.facts = sql_facts(protectors[mi_id], None, None)
            stopped = str(mi.get("state") or "").lower() in ("stopped", "stopping")
            self._decide(ctx, store, paused=stopped)

    def _flexible(self, ctx: Context, out: Discovery, query: str, api: str, port: int) -> None:
        arm = ctx.clients.client("arm")
        for srv in ctx.graph(query):
            server_rid = ResourceId.parse(str(srv.get("id") or ""))
            server = str(srv.get("name") or server_rid.name)
            facts = flexible_facts(str(srv.get("keyType") or ""), str(srv.get("keyUri") or ""))
            try:
                names = [
                    str(d.get("name") or "") for d in arm.list(f"{server_rid.value}/databases", api)
                ]
            except Exception as err:  # the server is reported, its databases unknown
                self._failed_listing(out, server_rid, server, err)
                continue
            stopped = str(srv.get("state") or "").lower() in ("stopped", "stopping", "disabled")
            for name in names:
                if not name or name.lower() in SYSTEM_DATABASES[self.kind]:
                    continue
                rid = ResourceId.parse(f"{server_rid.value}/databases/{name}")
                target = DbTarget(
                    self.kind,
                    rid,
                    server,
                    name,
                    str(srv.get("fqdn") or ""),
                    port,
                    _disabled(srv.get("publicNetworkAccess")),
                )
                store = self._store(ctx, out, target, _tags(srv.get("tags")))
                store.facts = dict(facts)
                no_path = self.kind == "azure_postgresql" and _disabled(srv.get("entraAuth"))
                self._decide(ctx, store, paused=stopped, no_path=no_path)

    def _azure_postgresql(self, ctx: Context, out: Discovery) -> None:
        self._flexible(ctx, out, POSTGRESQL_SERVERS, PG_API, 5432)

    def _azure_mysql(self, ctx: Context, out: Discovery) -> None:
        self._flexible(ctx, out, MYSQL_SERVERS, MYSQL_API, 3306)

    def _synapse_sql(self, ctx: Context, out: Discovery) -> None:
        workspaces = {str(r.get("id") or "").lower(): r for r in ctx.graph(SYNAPSE_WORKSPACES)}
        arm = ctx.clients.client("arm")
        for row in ctx.graph(SYNAPSE_POOLS):
            rid = ResourceId.parse(str(row.get("id") or ""))
            ws_id = _parent(rid.value, "sqlpools")
            ws = workspaces.get(ws_id, {})
            name = str(ws.get("name") or ResourceId.parse(ws_id).name)
            target = DbTarget(
                self.kind,
                rid,
                name,
                rid.name,
                str(ws.get("sqlEndpoint") or f"{name}.sql.azuresynapse.net"),
                1433,
                _disabled(ws.get("publicNetworkAccess")),
            )
            store = self._store(ctx, out, target, _tags(row.get("tags")) or _tags(ws.get("tags")))
            key = str(ws.get("keyUri") or "")
            if key:
                store.facts = key_facts("Microsoft.Keyvault", key)
            else:
                tde: str | None = None
                try:
                    got = arm.get(f"{rid.value}/transparentDataEncryption/current", SQL_API)
                    tde = str((got.get("properties") or {}).get("status") or "") or None
                except Exception as err:  # unknown
                    log_event("discovery.failed", kind=self.kind, error=error_name(err))
                protector = {"serverKeyType": "ServiceManaged"}
                store.facts = sql_facts(protector, tde or "unknown", None)
            self._decide(ctx, store, paused=str(row.get("status") or "").lower() == "paused")

    # ------------------------------------------------------------------ reading

    def source(self, ctx: Context, store: Store) -> DatabaseSource | None:
        t = store.table
        if not isinstance(t, DbTarget):
            return None
        driver = ctx.clients.client("driver", DRIVERS[self.kind])
        if driver is None:
            store.skip("driver_missing")
            return None
        s = ctx.settings
        credential = ctx.clients.credential
        return DatabaseSource(t, lambda: connect(driver, t, s, credential), s)


def _odbc(value: str) -> str:
    """An ODBC connection-string value, braced so that nothing in it is a keyword."""
    return "{" + value.replace("}", "}}") + "}"


def connect(
    driver: Any, t: DbTarget, s: Settings, credential: Any
) -> tuple[SqlSession, tuple[str, ...]]:
    """A session as the managed identity, and the statements that open a read-only
    transaction on it."""
    if t.kind in ("azure_sql", "azure_sql_mi", "synapse_sql"):
        conn = driver.connect(
            f"Server=tcp:{t.host},{t.port};Database={_odbc(t.database)};Encrypt=yes;"
            "TrustServerCertificate=no;ApplicationIntent=ReadOnly;"
            "APP=sensitive-data-scanner",
            autocommit=False,
            token_provider=credential,
            timeout=s.db_connect_seconds,
        )
        # A driver without a statement timeout: the budget's clock still runs.
        with contextlib.suppress(Exception):
            conn.timeout = s.db_statement_seconds
        return SqlSession("sqlserver", SQLSERVER, conn, database=t.database, check=g.sqlserver), ()
    token = credential.get_token(OSSRDBMS_SCOPE).token
    if t.kind == "azure_postgresql":
        ms = s.db_statement_seconds * 1000
        conn = driver.connect(
            host=t.host,
            port=t.port,
            dbname=t.database,
            user=s.db_principal,
            password=token,
            sslmode="verify-full",
            sslrootcert="system",
            connect_timeout=s.db_connect_seconds,
            application_name="sensitive-data-scanner",
            options=f"-c default_transaction_read_only=on -c statement_timeout={ms}",
        )
        session = SqlSession("postgresql", PG, conn, database=t.database, check=g.postgresql)
        return session, ("SET TRANSACTION READ ONLY",)
    conn = driver.connect(
        host=t.host,
        port=t.port,
        user=s.db_principal,
        password=token,
        database=t.database,
        connect_timeout=s.db_connect_seconds,
        read_timeout=s.db_statement_seconds,
        write_timeout=s.db_statement_seconds,
        autocommit=False,
        charset="utf8mb4",
        init_command="SET SESSION TRANSACTION READ ONLY",
        ssl_verify_cert=True,
        ssl_verify_identity=True,
    )
    session = SqlSession("mysql", MY, conn, database=t.database, check=g.mysql)
    return session, ("START TRANSACTION READ ONLY",)


Connect = Callable[[], tuple[SqlSession, tuple[str, ...]]]


class DatabaseSource:
    """One database: its user checked, then its tables sampled, resumable by table."""

    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(self, target: DbTarget, open_session: Connect, settings: Settings) -> None:
        self.t = target
        self.kind = target.kind
        self._open = open_session
        self.settings = settings
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"{target.kind}:{target.server}/{target.database}"
        self.target = f"{target.server}/{target.database}"

    def __repr__(self) -> str:
        return f"DatabaseSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        try:
            session, begin = self._open()
        except Exception as err:  # reported by name; the message can quote the host or user
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=connect_gap(err))
        try:
            return self._read(
                session,
                begin=begin,
                cov=cov,
                cursor=cursor,
                budget=budget,
                detector=detector,
                store=store,
                now=now,
            )
        finally:
            session.rollback()
            session.close()

    def _read(
        self,
        session: SqlSession,
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
            log_event(
                "source.refused", source=self.target, kind=self.kind, reason="grants_unverifiable"
            )
            return SourceRun(cov, cursor, note="grants_unverifiable")
        if grants.write:
            log_event(
                "source.refused", source=self.target, kind=self.kind, reason="db_user_can_write"
            )
            write = sorted(grants.write)[:MAX_WRITE_GRANTS]
            return SourceRun(cov, cursor, note="db_user_can_write", extra={"writeGrants": write})
        if self.facts is None:
            self.facts = encryption_facts(session.encryption())
        seen_at = now.isoformat()
        facts = self.facts
        t = self.t
        today = (now.date() - _dt.date(1970, 1, 1)).days
        op = ObjectPass(self.indexes, self.id, self.kind, generation=today, budget=budget)
        link = portal_link(t.rid)

        def on_table(schema: str, table: str, result: TableResult) -> None:
            def resource(column: str) -> dict[str, Any]:
                out = store_field_resource(
                    service=t.kind,
                    store=t.server,
                    database=t.database,
                    table=f"{schema}.{table}",
                    field=column,
                    read_by="sample",
                )
                out.update(azure_fields(t.rid))
                return out

            location = f"{self.id}\n{schema}\n{table}"
            store.replace_location(
                location, column_findings(result, resource, link, seen_at, facts=facts)
            )

        session.rollback()
        for statement in begin:
            session.execute(statement, [])
        s = self.settings
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
                source=self.target,
                index=op,
            )
        except Exception as err:  # the listing itself failed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor)
        cov.listed, cov.eligible, cov.scanned = sp.listed, sp.eligible, sp.scanned
        cov.unreadable, cov.partial, cov.bytes_scanned = sp.unreadable, sp.partial, sp.bytes
        cov.test_values, cov.suppressed = sp.test_values, sp.suppressed
        cov.redaction_markers = sp.redaction_markers
        cov.pass_complete = sp.done
        cov.backlog = not sp.done
        if sp.scanned:
            cov.formats["sql"] = sp.scanned
        op.settle(cov)
        note = "no_grant" if sp.listed == 0 else None
        return SourceRun(cov, {"after": None if sp.done else sp.after}, note=note)
