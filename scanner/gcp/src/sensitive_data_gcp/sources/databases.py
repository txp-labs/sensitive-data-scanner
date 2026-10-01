"""Cloud SQL (PostgreSQL, MySQL, SQL Server) and AlloyDB. Discovered by default, read when
opted in.

**Discovery** (Cloud Asset Inventory, then the Cloud SQL Admin and AlloyDB
APIs with `cloudsql.instances.get`, `cloudsql.databases.list`,
`alloydb.clusters.get` and `alloydb.instances.get`) lists every Cloud SQL
instance's databases, one store per `instance/database`, and every AlloyDB
cluster, one store per cluster (AlloyDB has no API that lists a cluster's
databases: they are listed by SQL once connected). System databases are not
stores. A stopped instance or cluster is `paused`: connecting would need it
started.

**Reading** (`GCP_DB_READ`, off by default) connects as the job's service
account with **IAM database authentication**: an OAuth access token (scoped to
`sqlservice.login` or `alloydb.login`) as the password, over TLS with the
server's certificate verified against the instance's own CA (Cloud SQL's
`serverCaCert`; AlloyDB's cluster CA, from `generateClientCertificate`). No
password exists. The customer creates the service account's database user
(`CREATE USER ... WITH ... IAM`, or `gcloud sql users create --type
cloud_iam_service_account`) with read access only; docs/GCP.md has the
statements. Then, as the databases runner does:

1. **the user is checked first**, with the core's allow list of reads
   (`sensitive_data_core.grants`); a user that can write is refused as
   `db_user_can_write` with its privileges by name, one whose privileges
   cannot be read as `grants_unverifiable`; nothing is read from either;
2. the core's sampled pass (`scan/sql.py`) in a read-only transaction, always
   rolled back, resumable by table (for AlloyDB, by database and table).

Cloud SQL for SQL Server has no IAM database authentication: reading it would
take a password, so it is `no_read_path`, naming `toggle: GCP_SQLSERVER`, a
hook (#105): on, it is `not_implemented` (no password-free reader is built).
AlloyDB is read only with `GCP_ALLOYDB` on (the default, #105). A PostgreSQL or MySQL instance with
the IAM authentication flag off is `no_read_path` too. An instance the job
cannot reach (no private path, no authorized network) is `network`; a login
the database refuses (no IAM user yet, or `cloudsql.instances.login` missing)
is `access_denied`.

**Encryption (1.5):** the instance's or cluster's Cloud KMS key
(`customer_managed_key`, hashed), else Google's own keys (`service_managed`).
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
import tempfile
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core import grants as g
from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Indexes
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_db.engines import MY, PG, SqlSession

from ..config import Settings
from ..resources import Located, console_link
from . import databases_read as _read_path
from .base import Context, kms_facts, labels
from .common import call_gap, connect_gap

SQLADMIN = "https://sqladmin.googleapis.com/v1"
ALLOYDB = "https://alloydb.googleapis.com/v1"
SQL_TYPE = "sqladmin.googleapis.com/Instance"
ALLOYDB_TYPE = "alloydb.googleapis.com/Cluster"
# The token audiences of IAM database authentication.
SQL_LOGIN_SCOPE = "https://www.googleapis.com/auth/sqlservice.login"
ALLOYDB_LOGIN_SCOPE = "https://www.googleapis.com/auth/alloydb.login"
MAX_ALLOYDB_DATABASES = 50

SYSTEM_DATABASES = {
    "cloudsql_postgresql": frozenset({"cloudsqladmin", "template0", "template1"}),
    "cloudsql_mysql": frozenset({"information_schema", "mysql", "performance_schema", "sys"}),
    "cloudsql_sqlserver": frozenset({"master", "model", "msdb", "tempdb"}),
    "alloydb": frozenset({"alloydbadmin", "alloydbmetadata", "template0", "template1"}),
}
DRIVERS = {
    "cloudsql_postgresql": "psycopg",
    "cloudsql_mysql": "pymysql",
    "alloydb": "psycopg",
}
# The database flag that turns IAM database authentication on, per engine.
IAM_FLAGS = {
    "cloudsql_postgresql": "cloudsql.iam_authentication",
    "cloudsql_mysql": "cloudsql_iam_authentication",
    "alloydb": "alloydb.iam_authentication",
}
LISTED_DATABASES_SQL = (
    "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname"
)


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def sql_kind(version: str) -> str | None:
    """A Cloud SQL `databaseVersion` (`POSTGRES_16`, `MYSQL_8_0`, `SQLSERVER_2022_STANDARD`)
    as the kind of store."""
    v = version.upper()
    if v.startswith("POSTGRES"):
        return "cloudsql_postgresql"
    if v.startswith("MYSQL"):
        return "cloudsql_mysql"
    if v.startswith("SQLSERVER"):
        return "cloudsql_sqlserver"
    return None


def db_user(kind: str, principal: str) -> str:
    """The service account's IAM database user: PostgreSQL and AlloyDB drop
    `.gserviceaccount.com` from its email; MySQL keeps only the part before `@`."""
    if kind == "cloudsql_mysql":
        return principal.split("@", 1)[0]
    return principal.removesuffix(".gserviceaccount.com")


def _flag_on(flags: Any, name: str) -> bool:
    for f in flags or []:
        if isinstance(f, dict) and str(f.get("name") or "") == name:
            return str(f.get("value") or "").lower() in ("on", "true")
    return False


def _flags(raw: Any) -> list[dict[str, Any]]:
    """Database flags as a list: Cloud SQL sends `[{name, value}]`, AlloyDB `{name: value}`."""
    if isinstance(raw, dict):
        return [{"name": k, "value": v} for k, v in raw.items()]
    return [f for f in raw or [] if isinstance(f, dict)]


@dataclass
class DbTarget:
    """One Cloud SQL database, or one AlloyDB cluster, and how to reach it."""

    kind: str
    where: Located  # the instance's (or cluster's) project and full resource name
    server: str  # the instance, or the cluster
    database: str | None  # None: an AlloyDB cluster, whose databases are listed by SQL
    host: str
    ca: str = field(default="", repr=False)  # the server CA's PEM; fetched when read (AlloyDB)
    link: Any = None
    ca_source: str | None = None  # AlloyDB: the cluster, whose CA is asked for when read

    def __repr__(self) -> str:
        return f"DbTarget({self.kind!r}, {redact_digits(self.server)!r})"


def _ip(addresses: Any) -> tuple[str, bool]:
    """The address to connect to (private first), and whether only a private one exists."""
    by_type: dict[str, str] = {}
    for a in addresses or []:
        if isinstance(a, dict) and a.get("ipAddress"):
            by_type.setdefault(str(a.get("type") or "PRIMARY").upper(), str(a["ipAddress"]))
    if "PRIVATE" in by_type:
        return by_type["PRIVATE"], "PRIMARY" not in by_type
    return by_type.get("PRIMARY", ""), False


@dataclass
class SqlInstance:
    """One Cloud SQL instance as discovery found it: its engine, record and databases."""

    kind: str | None
    where: Located
    name: str
    row: dict[str, Any]
    meta: dict[str, Any] = field(default_factory=dict)
    databases: list[str] = field(default_factory=list)
    error: Exception | None = None

    def __repr__(self) -> str:
        return f"SqlInstance({self.kind!r}, {redact_digits(self.name)!r})"


def cloudsql_instances(ctx: Context) -> list[SqlInstance]:
    """Every Cloud SQL instance in scope with its record and databases, once per run for the
    three engines' adapters. An instance whose record cannot be read is reported by the
    first Cloud SQL kind being discovered, unless Cloud Asset Inventory named its engine."""
    got = ctx.memo.get("cloudsql")
    if isinstance(got, list):
        return got
    first = next((k for k in ctx.settings.discover if k.startswith("cloudsql_")), None)
    out: list[SqlInstance] = []
    rest = ctx.rest
    for row in ctx.search(SQL_TYPE):
        name = str(row.get("displayName") or str(row.get("name") or "").rsplit("/", 1)[-1])
        project = ctx.project_of(row)
        version = str((row.get("additionalAttributes") or {}).get("databaseVersion") or "")
        inst = SqlInstance(
            sql_kind(version) or first, Located(project, str(row.get("name") or "")), name, row
        )
        base = f"{SQLADMIN}/projects/{_q(project)}/instances/{_q(name)}"
        try:
            inst.meta = rest.get(base)
            inst.kind = sql_kind(str(inst.meta.get("databaseVersion") or ""))
            inst.databases = [
                str(d.get("name") or "")
                for page, _ in rest.pages(f"{base}/databases", "items")
                for d in page
                if isinstance(d, dict)
            ]
        except Exception as err:  # the instance is reported, its databases unknown
            inst.error = err
        out.append(inst)
    ctx.memo["cloudsql"] = out
    return out


class DatabaseAdapter:
    """One kind of Google Cloud database."""

    def __init__(self, kind: str) -> None:
        self.kind = kind

    def discover(self, ctx: Context, out: Discovery) -> None:
        if self.kind == "alloydb":
            self._alloydb(ctx, out)
        else:
            self._cloudsql(ctx, out)

    def _decide(
        self, ctx: Context, store: Store, *, paused: bool = False, no_path: bool = False
    ) -> None:
        if paused:
            store.skip("paused")  # connecting would need it started
            return
        s = ctx.settings
        if not apply_rules(store, s.allow, s.deny):
            return
        if self.kind == "cloudsql_sqlserver":
            # #105: a hook. No IAM database authentication: a password is never used.
            if s.sqlserver_read:
                store.not_implemented("GCP_SQLSERVER")
            else:
                store.toggle_off("GCP_SQLSERVER", "no_read_path")
            return
        if no_path:
            store.skip("no_read_path")  # no IAM database authentication: a password is never used
            return
        if self.kind == "alloydb" and not s.alloydb_read:
            store.toggle_off("GCP_ALLOYDB")
            return
        if self.kind not in s.db_read:
            store.toggle_off("GCP_DB_READ")

    def _failed(self, out: Discovery, where: Located, name: str, err: Exception) -> None:
        store = Store(self.kind, f"{name}/*")
        store.extra.update(where.fields())
        store.status, store.error = "error", error_name(err)
        gap = call_gap(err)
        store.reason = "network" if gap == "network" else reason_for(store.error)
        out.stores.append(store)

    def _cloudsql(self, ctx: Context, out: Discovery) -> None:
        for inst in cloudsql_instances(ctx):
            if inst.kind != self.kind:
                continue  # listed by the adapter of its own engine
            where, instance, project = inst.where, inst.name, inst.where.project
            if inst.error is not None:
                self._failed(out, where, instance, inst.error)
                continue
            meta = inst.meta
            settings = meta.get("settings") or {}
            names = inst.databases
            row = inst.row
            host, private_only = _ip(meta.get("ipAddresses"))
            facts = kms_facts(
                (meta.get("diskEncryptionConfiguration") or {}).get("kmsKeyName") or None
            )
            stopped = str(meta.get("state") or "").upper() in ("STOPPED", "SUSPENDED") or (
                str(settings.get("activationPolicy") or "").upper() == "NEVER"
            )
            iam = self.kind in IAM_FLAGS and _flag_on(
                _flags(settings.get("databaseFlags")), IAM_FLAGS[self.kind]
            )
            link = console_link(
                f"sql/instances/{_q(instance)}/overview", {"project": project}, instance
            )
            ca = str((meta.get("serverCaCert") or {}).get("cert") or "")
            tags = {
                **labels(row),
                **{str(k): str(v) for k, v in (settings.get("userLabels") or {}).items()},
            }
            for name in names:
                if not name or name in SYSTEM_DATABASES[self.kind]:
                    continue
                target = DbTarget(self.kind, where, instance, name, host, ca, link)
                store = Store(self.kind, f"{instance}/{name}", tags=tags)
                store.extra.update(where.fields())
                store.extra["database"] = name
                if private_only:
                    store.extra["networkRestricted"] = True
                store.facts = dict(facts)
                store.table = target
                out.stores.append(store)
                self._decide(ctx, store, paused=stopped, no_path=not iam)

    def _alloydb(self, ctx: Context, out: Discovery) -> None:
        rest = ctx.rest
        for row in ctx.search(ALLOYDB_TYPE):
            full = str(row.get("name") or "")
            path = full.removeprefix("//alloydb.googleapis.com/")
            cluster = path.rsplit("/", 1)[-1]
            project = ctx.project_of(row)
            where = Located(project, full)
            try:
                meta = rest.get(f"{ALLOYDB}/{path}")
                instances = [
                    i
                    for page, _ in rest.pages(f"{ALLOYDB}/{path}/instances", "instances")
                    for i in page
                    if isinstance(i, dict)
                ]
            except Exception as err:
                self._failed(out, where, cluster, err)
                continue
            # A read pool is read-only by design: read there when the cluster has one.
            ranked = sorted(
                instances,
                key=lambda i: (str(i.get("instanceType") or "") != "READ_POOL", str(i.get("name"))),
            )
            chosen = next((i for i in ranked if str(i.get("state") or "") == "READY"), None)
            key = (meta.get("encryptionConfig") or {}).get("kmsKeyName")
            store = Store(self.kind, cluster, tags={**labels(row), **labels(meta)})
            store.extra.update(where.fields())
            store.facts = kms_facts(str(key) if key else None)
            out.stores.append(store)
            if chosen is None:
                store.skip("paused" if instances else "no_read_path")
                continue
            host = str(chosen.get("ipAddress") or chosen.get("publicIpAddress") or "")
            if not chosen.get("publicIpAddress"):
                store.extra["networkRestricted"] = True
            location = path.split("/locations/", 1)[-1].split("/", 1)[0]
            link = console_link(
                f"alloydb/locations/{_q(location)}/clusters/{_q(cluster)}/overview",
                {"project": project},
                location,
                cluster,
            )
            store.table = DbTarget(
                self.kind, where, cluster, None, host, "", link, ca_source=f"{ALLOYDB}/{path}"
            )
            iam = _flag_on(_flags(chosen.get("databaseFlags")), IAM_FLAGS[self.kind])
            self._decide(ctx, store, no_path=not iam)

    def source(self, ctx: Context, store: Store) -> DatabaseSource | None:
        t = store.table
        if not isinstance(t, DbTarget):
            return None
        driver = ctx.clients.driver(DRIVERS[self.kind])
        if driver is None:
            store.skip("driver_missing")
            return None
        s = ctx.settings
        clients = ctx.clients
        scope = ALLOYDB_LOGIN_SCOPE if self.kind == "alloydb" else SQL_LOGIN_SCOPE

        def open_session(database: str) -> tuple[SqlSession, tuple[str, ...]]:
            ca = t.ca
            if not ca and t.ca_source:
                got = clients.rest.post(f"{t.ca_source}:generateClientCertificate", {})
                ca = str(got.get("caCert") or "")
            return connect(driver, t, database, s, token=clients.token((scope,)), ca=ca)

        return DatabaseSource(t, open_session, s)


@contextlib.contextmanager
def _ca_file(pem: str) -> Iterator[str]:
    """The server CA in a file of the job's own, for the driver; removed after connecting."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)


class NoServerCa(Exception):
    """The instance's server CA is unknown, so its certificate cannot be verified."""


def connect(
    driver: Any, t: DbTarget, database: str, s: Settings, *, token: str, ca: str
) -> tuple[SqlSession, tuple[str, ...]]:
    """A session as the service account, and the statements that open a read-only
    transaction on it. The token is the password; the server's certificate is verified
    against the instance's own CA, or nothing is sent."""
    if not ca:
        raise NoServerCa("server CA unknown")
    user = db_user(t.kind, s.db_principal or "")
    with _ca_file(ca) as ca_path:
        if t.kind in ("cloudsql_postgresql", "alloydb"):
            ms = s.db_statement_seconds * 1000
            conn = driver.connect(
                host=t.host,
                port=5432,
                dbname=database,
                user=user,
                password=token,
                sslmode="verify-ca",
                sslrootcert=ca_path,
                connect_timeout=s.db_connect_seconds,
                application_name="sensitive-data-scanner",
                options=f"-c default_transaction_read_only=on -c statement_timeout={ms}",
            )
            session = SqlSession("postgresql", PG, conn, database=database, check=g.postgresql)
            return session, ("SET TRANSACTION READ ONLY",)
        conn = driver.connect(
            host=t.host,
            port=3306,
            user=user,
            password=token,
            database=database,
            connect_timeout=s.db_connect_seconds,
            read_timeout=s.db_statement_seconds,
            write_timeout=s.db_statement_seconds,
            autocommit=False,
            charset="utf8mb4",
            init_command="SET SESSION TRANSACTION READ ONLY",
            ssl_ca=ca_path,
            ssl_verify_cert=True,
            ssl_verify_identity=False,
        )
    session = SqlSession("mysql", MY, conn, database=database, check=g.mysql)
    return session, ("START TRANSACTION READ ONLY",)


Connect = Callable[[str], tuple[SqlSession, tuple[str, ...]]]
CLUSTER_WIDE = frozenset({"db_user_can_write", "grants_unverifiable", "network"})


class DatabaseSource:
    """One Cloud SQL database, or an AlloyDB cluster's databases: the user checked, then
    the tables sampled, resumable by table."""

    # A change to how this kind is listed (`listing:<kind>`) drops these cursor keys: the next
    # pass lists the store again from the start and reads only what changed (#67).
    relist_keys: tuple[str, ...] = ("after",)
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(self, target: DbTarget, open_session: Connect, settings: Settings) -> None:
        self.t = target
        self.kind = target.kind
        self._open = open_session
        self.settings = settings
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        suffix = f"/{target.database}" if target.database is not None else ""
        self.id = f"{target.kind}:{target.server}{suffix}"
        self.target = f"{target.server}{suffix}"

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
        if self.t.database is not None:
            return self._database(
                self.t.database,
                cursor,
                cov=cov,
                budget=budget,
                detector=detector,
                store=store,
                now=now,
            )
        return self._cluster(
            cursor, cov=cov, budget=budget, detector=detector, store=store, now=now
        )

    def _cluster(
        self,
        cursor: dict[str, Any],
        *,
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        """An AlloyDB cluster: its databases listed by SQL, then each read in turn."""
        try:
            session, _ = self._open("postgres")
        except Exception as err:  # reported by name; the message can quote the host or user
            return self._failed(cov, cursor, err)
        try:
            names = [str(r.get("datname") or "") for r in session.execute(LISTED_DATABASES_SQL, [])]
        except Exception as err:
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor)
        finally:
            session.rollback()
            session.close()
        names = sorted(n for n in names if n and n not in SYSTEM_DATABASES[self.kind])
        names = names[:MAX_ALLOYDB_DATABASES]
        at = cursor.get("database")
        todo = [n for n in names if at is None or n >= at]
        refused: str | None = None
        for name in todo:
            inner = cursor if name == at else {}
            got = self._database(
                name, inner, cov=cov, budget=budget, detector=detector, store=store, now=now
            )
            if got.note in CLUSTER_WIDE:
                # A user that can write in one database, or a network that keeps the job out,
                # is the whole cluster's refusal: nothing more is read from it.
                return SourceRun(cov, cursor, note=got.note, extra=got.extra)
            if cov.error is not None or got.note == "access_denied":
                cov.unreadable += 1  # this database refused the user; the others are read
                refused = refused or cov.error
                cov.error = None
                continue
            if not cov.pass_complete:
                return SourceRun(cov, {**got.cursor, "database": name})
        cov.pass_complete, cov.backlog = True, False
        if cov.scanned == 0 and cov.unreadable:
            cov.error = refused
            return SourceRun(cov, {}, note="access_denied")
        return SourceRun(cov, {}, note="no_grant" if cov.listed == 0 else None)

    def _failed(self, cov: Coverage, cursor: dict[str, Any], err: Exception) -> SourceRun:
        cov.error = error_name(err)
        log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
        return SourceRun(cov, cursor, note=connect_gap(err))

    def _database(
        self,
        database: str,
        cursor: dict[str, Any],
        *,
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        try:
            session, begin = self._open(database)
        except Exception as err:  # reported by name; the message can quote the host or user
            return self._failed(cov, cursor, err)
        try:
            return self._read(
                session,
                database,
                begin=begin,
                cursor=cursor,
                cov=cov,
                budget=budget,
                detector=detector,
                store=store,
                now=now,
            )
        finally:
            session.rollback()
            session.close()

    # The read path (`databases_read.py`, the `adapter:<kind>` component, #67).
    _read = _read_path._read
