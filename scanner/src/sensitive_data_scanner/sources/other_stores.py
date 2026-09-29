"""Other stores: ElastiCache and MemoryDB (reported), Timestream and Keyspaces (sampled).

**ElastiCache and MemoryDB** (`DISCOVER` includes `elasticache`,
`memorydb`): replication groups, clusters and serverless caches are listed,
with their snapshots counted (`snapshots`), and reported as `in_memory`: the
data lives in memory, reachable only inside the VPC with the cache's own
credentials, and a snapshot has no read path of its own. A snapshot that
was **exported to S3** (`CopySnapshot` to a bucket,
`ExportServerlessCacheSnapshot`) is an `.rdb` file there, and the S3 source
reads it (its runs of printable text), so exported snapshots are covered
wherever S3 is.

**Timestream for LiveAnalytics** (`timestream`): `ListDatabases` and
`ListTables`, then for each table one sampled read-only query,
`SELECT * FROM "db"."table" WHERE time > ago(Nd) LIMIT n`, read by column.
Timestream for InfluxDB instances are listed and reported (`no_read_path`):
they are reached inside a VPC with an InfluxDB token.

**Keyspaces** (`keyspaces`): `ListKeyspaces` and `ListTables` (system
keyspaces left out), then for each table `SELECT * FROM "ks"."table" LIMIT
n` over CQL (TLS, port 9142, SigV4 with the scanner's own role: no password),
read by column. `cassandra:Select` is the only permission it has.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
import urllib.parse
from collections.abc import Callable
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import scan_rows
from sensitive_data_core.scan.sql import Dialect, sample_sql

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .exports import drop_other_passes

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = (
    "elasticache",
    "memorydb",
    "timestream-write",
    "timestream-query",
    "timestream-influxdb",
    "keyspaces",
)

# Timestream and CQL quote names with double quotes, as PostgreSQL does.
TIMESTREAM = Dialect("timestream", '"', ":{name}")
CQL = Dialect("cql", '"', "?")
SYSTEM_KEYSPACES = ("system", "system_schema", "system_schema_mcs", "system_multiregion_info")
MAX_QUERY_PAGES = 10


# ------------------------------------------------------------------ ElastiCache and MemoryDB


class ElastiCacheAdapter:
    kind = "elasticache"

    def discover(self, ctx: Context, out: Discovery) -> None:
        ec = ctx.clients.client("elasticache")
        snaps: dict[str, int] = {}
        for page in ec.get_paginator("describe_snapshots").paginate():
            for s in page.get("Snapshots", []):
                owner = str(s.get("ReplicationGroupId") or s.get("CacheClusterId") or "")
                snaps[owner] = snaps.get(owner, 0) + 1
        for page in ec.get_paginator("describe_serverless_cache_snapshots").paginate():
            for s in page.get("ServerlessCacheSnapshots", []):
                owner = str(
                    (s.get("ServerlessCacheConfiguration") or {}).get("ServerlessCacheName")
                )
                snaps[owner] = snaps.get(owner, 0) + 1
        in_groups: set[str] = set()
        for page in ec.get_paginator("describe_replication_groups").paginate():
            for g in page.get("ReplicationGroups", []):
                name = str(g["ReplicationGroupId"])
                in_groups.update(str(m) for m in g.get("MemberClusters") or [])
                self._add(
                    ctx,
                    out,
                    name,
                    deployment="replication_group",
                    state=str(g.get("Status") or ""),
                    snaps=snaps,
                )
        for page in ec.get_paginator("describe_cache_clusters").paginate():
            for c in page.get("CacheClusters", []):
                name = str(c["CacheClusterId"])
                if c.get("ReplicationGroupId") or name in in_groups:
                    continue  # a member: its replication group is the store
                self._add(
                    ctx,
                    out,
                    name,
                    deployment="cluster",
                    state=str(c.get("CacheClusterStatus") or ""),
                    snaps=snaps,
                )
        for page in ec.get_paginator("describe_serverless_caches").paginate():
            for c in page.get("ServerlessCaches", []):
                name = str(c["ServerlessCacheName"])
                self._add(
                    ctx,
                    out,
                    name,
                    deployment="serverless",
                    state=str(c.get("Status") or ""),
                    snaps=snaps,
                )

    def _add(
        self,
        ctx: Context,
        out: Discovery,
        name: str,
        *,
        deployment: str,
        state: str,
        snaps: dict[str, int],
    ) -> None:
        store = Store(self.kind, name)
        store.extra.update(deployment=deployment, snapshots=int(snaps.get(name, 0)))
        out.stores.append(store)
        decide(store, ctx.config)
        if store.status == "pending":
            store.skip("in_memory")
            if state and state.lower() not in ("available", "active"):
                store.extra["state"] = state[:60]

    def source(self, ctx: Context, store: Store) -> None:
        return None


class MemoryDbAdapter:
    kind = "memorydb"

    def discover(self, ctx: Context, out: Discovery) -> None:
        mdb = ctx.clients.client("memorydb")
        snaps: dict[str, int] = {}
        for page in mdb.get_paginator("describe_snapshots").paginate():
            for s in page.get("Snapshots", []):
                owner = str((s.get("ClusterConfiguration") or {}).get("Name") or "")
                snaps[owner] = snaps.get(owner, 0) + 1
        for page in mdb.get_paginator("describe_clusters").paginate():
            for c in page.get("Clusters", []):
                name = str(c["Name"])
                store = Store(self.kind, name)
                store.extra["snapshots"] = snaps.get(name, 0)
                out.stores.append(store)
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("in_memory")

    def source(self, ctx: Context, store: Store) -> None:
        return None


# ------------------------------------------------------------------ Timestream


def _datum(d: dict[str, Any]) -> Any:
    """One Timestream value as Python: text for scalars, lists for arrays, rows and series."""
    if d.get("NullValue"):
        return None
    if "ScalarValue" in d:
        return str(d["ScalarValue"])
    if "ArrayValue" in d:
        return [_datum(x) for x in d["ArrayValue"]]
    if "RowValue" in d:
        return [_datum(x) for x in (d["RowValue"] or {}).get("Data", [])]
    if "TimeSeriesValue" in d:
        return [_datum(p.get("Value") or {}) for p in d["TimeSeriesValue"]]
    return None


class TimestreamAdapter:
    kind = "timestream"

    def discover(self, ctx: Context, out: Discovery) -> None:
        failures: list[BaseException] = []
        for step in (self._live, self._influx):
            try:
                step(ctx, out)
            except Exception as err:  # the other engine is still listed
                failures.append(err)
        if failures:
            raise failures[0]

    def _live(self, ctx: Context, out: Discovery) -> None:
        tw = ctx.clients.client("timestream-write")
        databases: list[str] = []
        token: str | None = None
        while True:
            r = tw.list_databases(**({"NextToken": token} if token else {}))
            databases.extend(str(d["DatabaseName"]) for d in r.get("Databases", []))
            token = r.get("NextToken")
            if not token:
                break
        for db in databases:
            token = None
            while True:
                r = tw.list_tables(DatabaseName=db, **({"NextToken": token} if token else {}))
                for t in r.get("Tables", []):
                    store = Store(self.kind, f"{db}.{t['TableName']}")
                    store.extra.update(deployment="live_analytics", database=db)
                    out.stores.append(store)
                    if str(t.get("TableStatus") or "ACTIVE") != "ACTIVE":
                        store.skip("unsupported")
                        store.extra["state"] = str(t.get("TableStatus"))[:60]
                        continue
                    tag_error: str | None = None
                    if needs_tags(ctx.config, self.kind):
                        try:
                            tr = tw.list_tags_for_resource(ResourceARN=str(t.get("Arn")))
                            store.tags = {
                                str(x["Key"]): str(x.get("Value", "")) for x in tr.get("Tags", [])
                            }
                        except Exception as err:
                            tag_error = error_name(err)
                    decide(store, ctx.config, tag_error)
                    store.extra["tableName"] = str(t["TableName"])
                token = r.get("NextToken")
                if not token:
                    break

    def _influx(self, ctx: Context, out: Discovery) -> None:
        influx = ctx.clients.client("timestream-influxdb")
        for page in influx.get_paginator("list_db_instances").paginate():
            for i in page.get("items", []):
                store = Store(self.kind, str(i.get("name")))
                store.extra["deployment"] = "influxdb"
                out.stores.append(store)
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("no_read_path")

    def source(self, ctx: Context, store: Store) -> TimestreamSource | None:
        table = store.extra.get("tableName")
        if not table:
            return None
        return TimestreamSource(
            ctx.clients.client("timestream-query"),
            database=str(store.extra.get("database")),
            table=str(table),
            region=ctx.region,
            max_rows=ctx.config.timestream_max_rows,
            lookback_days=ctx.config.timestream_lookback_days,
        )


class _TableSample:
    """A table read once per pass as one sampled query, by column."""

    kind = ""
    service = ""
    read_by = ""

    def __init__(self, *, database: str, table: str, region: str, max_rows: int) -> None:
        self.database = database
        self.table = table
        self.region = region
        self.max_rows = max_rows
        name = f"{database}.{table}"
        self.id = f"{self.service}:{hashlib.sha256(name.encode()).hexdigest()[:16]}"
        self.target = name

    def link(self) -> str:
        raise NotImplementedError

    def rows(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def fmt(self) -> str:
        return "sql"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        cov.listed = cov.eligible = 1
        pass_id = secrets.token_hex(8)
        try:
            rows = self.rows()
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, {}, None, {})
        size = sum(len(str(r)) for r in rows)
        budget.take(size)
        columns = list(dict.fromkeys(k for r in rows for k in r))
        table = scan_rows(self.fmt(), columns, rows, detector, self.max_rows)
        cov.scanned = 1
        cov.bytes_scanned = size
        cov.formats[self.fmt()] = 1
        cov.partial = int(len(rows) >= self.max_rows)
        cov.test_values, cov.suppressed = table.test_values, table.suppressed
        cov.redaction_markers = table.redaction_markers
        findings = column_findings(table, self._resource(), self.link(), now.isoformat())
        for f in findings:
            f["_pass"] = pass_id
        store.replace_location(f"{self.id}\n{self.target}", findings)
        cov.pass_complete = True
        drop_other_passes(store, self.id, pass_id)
        return SourceRun(cov, {}, None, {})

    def _resource(self) -> Callable[[str], dict[str, Any]]:
        def resource(field: str) -> dict[str, Any]:
            return store_field_resource(
                service=self.service,
                store=self.database,
                table=self.table,
                field=field,
                read_by=self.read_by,
            )

        return resource


class TimestreamSource(_TableSample):
    kind = "timestream"
    service = "timestream"
    read_by = "query"

    def __init__(
        self,
        client: Any,
        *,
        database: str,
        table: str,
        region: str,
        max_rows: int = 1000,
        lookback_days: int = 1,
    ) -> None:
        super().__init__(database=database, table=table, region=region, max_rows=max_rows)
        self.client = client
        self.lookback_days = lookback_days

    def link(self) -> str:
        q = urllib.parse.quote(f"{self.database}/{self.table}", safe="/")
        return console_link(self.region, f"timestream/home?region={self.region}#tables/{q}")

    def sql(self) -> str:
        base = sample_sql(TIMESTREAM, self.database, self.table, self.max_rows)
        head, _, limit = base.rpartition(" LIMIT ")
        return f"{head} WHERE time > ago({int(self.lookback_days)}d) LIMIT {limit}"

    def rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        args: dict[str, Any] = {"QueryString": self.sql()}
        for _ in range(MAX_QUERY_PAGES):
            r = self.client.query(**args)
            names = [str(c.get("Name")) for c in r.get("ColumnInfo", [])]
            for row in r.get("Rows", []):
                out.append(
                    {
                        names[i]: _datum(d)
                        for i, d in enumerate(row.get("Data", []))
                        if i < len(names)
                    }
                )
            token = r.get("NextToken")
            if not token or len(out) >= self.max_rows:
                break
            args = {"QueryString": self.sql(), "NextToken": token}
        return out[: self.max_rows]


# ------------------------------------------------------------------ Keyspaces


def keyspaces_session(region: str) -> Any:
    """A CQL session to Amazon Keyspaces over TLS, signed with the scanner's own role (SigV4)."""
    import ssl  # noqa: PLC0415 - only when Keyspaces is read

    import boto3  # noqa: PLC0415
    from cassandra import ConsistencyLevel  # noqa: PLC0415
    from cassandra.cluster import EXEC_PROFILE_DEFAULT, Cluster, ExecutionProfile  # noqa: PLC0415
    from cassandra.query import dict_factory  # noqa: PLC0415
    from cassandra_sigv4.auth import SigV4AuthProvider  # noqa: PLC0415

    host = f"cassandra.{region}.amazonaws.com"
    context = ssl.create_default_context()
    profile = ExecutionProfile(
        consistency_level=ConsistencyLevel.LOCAL_ONE, row_factory=dict_factory, request_timeout=30
    )
    cluster = Cluster(
        [host],
        port=9142,
        ssl_context=context,
        ssl_options={"server_hostname": host},
        auth_provider=SigV4AuthProvider(boto3.Session(region_name=region)),
        execution_profiles={EXEC_PROFILE_DEFAULT: profile},
        protocol_version=4,
        connect_timeout=15,
    )
    return cluster.connect()


class KeyspacesAdapter:
    kind = "keyspaces"

    def __init__(self) -> None:
        self._session: Any = None

    def discover(self, ctx: Context, out: Discovery) -> None:
        ks = ctx.clients.client("keyspaces")
        spaces: list[str] = []
        for page in ks.get_paginator("list_keyspaces").paginate():
            spaces.extend(str(k["keyspaceName"]) for k in page.get("keyspaces", []))
        for space in spaces:
            if space in SYSTEM_KEYSPACES or space.startswith("system_"):
                continue
            for page in ks.get_paginator("list_tables").paginate(keyspaceName=space):
                for t in page.get("tables", []):
                    store = Store(self.kind, f"{space}.{t['tableName']}")
                    store.extra.update(database=space, tableName=str(t["tableName"]))
                    out.stores.append(store)
                    tag_error: str | None = None
                    if needs_tags(ctx.config, self.kind):
                        try:
                            tr = ks.list_tags_for_resource(resourceArn=str(t.get("resourceArn")))
                            store.tags = {
                                str(x["key"]): str(x.get("value", "")) for x in tr.get("tags", [])
                            }
                        except Exception as err:
                            tag_error = error_name(err)
                    decide(store, ctx.config, tag_error)

    def source(self, ctx: Context, store: Store) -> KeyspacesSource | None:
        table = store.extra.get("tableName")
        if not table:
            return None
        factory = ctx.clients.services.get("keyspaces-cql") or keyspaces_session
        return KeyspacesSource(
            factory,
            database=str(store.extra.get("database")),
            table=str(table),
            region=ctx.region,
            max_rows=ctx.config.keyspaces_max_rows,
        )


class KeyspacesSource(_TableSample):
    kind = "keyspaces"
    service = "keyspaces"
    read_by = "cql"

    # One CQL session per run for every table, made on first use.
    _sessions: dict[int, Any] = {}  # noqa: RUF012 - keyed by factory, per process

    def __init__(
        self,
        factory: Callable[[str], Any],
        *,
        database: str,
        table: str,
        region: str,
        max_rows: int = 1000,
    ) -> None:
        super().__init__(database=database, table=table, region=region, max_rows=max_rows)
        self.factory = factory

    def fmt(self) -> str:
        return "cql"

    def link(self) -> str:
        q = urllib.parse.quote(f"{self.database}/{self.table}", safe="/")
        return console_link(self.region, f"keyspaces/home?region={self.region}#table/{q}")

    def rows(self) -> list[dict[str, Any]]:
        cql = sample_sql(CQL, self.database, self.table, self.max_rows)
        key = id(self.factory)
        for attempt in range(2):
            session = self._sessions.get(key)
            if session is None:
                session = self._sessions[key] = self.factory(self.region)
            try:
                return [dict(r) for r in session.execute(cql)][: self.max_rows]
            except Exception:
                # A session kept from an earlier (frozen) invocation may be dead: once more.
                self._sessions.pop(key, None)
                if attempt:
                    raise
        return []
