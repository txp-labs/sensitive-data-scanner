"""Cosmos DB: NoSQL containers read by default; MongoDB (vCore) clusters read when opted in.

**Cosmos DB for NoSQL** (`cosmosdb`, `account/database/container`). Resource
Graph lists the accounts; Resource Manager (Reader) lists their databases and
containers, so a container the identity cannot read is still in the run
summary. Each container is read with the **Cosmos DB Built-in Data Reader**
data-plane role (a Cosmos role assignment on each account; docs/AZURE.md) by
one query, `SELECT TOP @n * FROM c`, across partitions, with the Entra token
of the job's identity. Items are read by top-level property, as columns; the
system properties (`_rid`, `_self`, `_etag`, `_attachments`, `_ts`) are not.

**Other Cosmos DB APIs** on an RU account (MongoDB, Cassandra, Gremlin, Table)
have no Entra data-plane read: reading them would need the account's keys,
and `listKeys` returns keys that can write. They are reported, one store per
account (`account/*`), as `no_read_path`, with their `api`.

**Cosmos DB for MongoDB vCore** (`cosmosdb_mongo`, `cluster/*`) supports
Microsoft Entra ID. With `AZURE_DB_READ` naming it, the cluster is read as the
identity (MONGODB-OIDC, a token for the identity's own user, which the customer
adds with a read-only role), the user checked first with the core's MongoDB
allow list of reads (`connectionStatus`), then `$sample` per collection, as the
databases runner does. A cluster without Entra authentication is
`no_read_path`.

**Encryption (1.5):** an account's or cluster's customer key in Key Vault is
`customer_managed_key` (hashed); otherwise Cosmos DB encrypts with keys
Microsoft manages (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import itertools
import json
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import TableResult, scan_rows

from ..resources import ResourceId, azure_fields, portal_link
from .base import Context, key_facts
from .common import http_gap, plain
from .databases import OSSRDBMS_SCOPE, connect_gap

COSMOS_API = "2024-11-15"
SYSTEM_PROPERTIES = frozenset({"_rid", "_self", "_etag", "_attachments", "_ts", "_lsn"})
MAX_WRITE_GRANTS = 30

COSMOS_ACCOUNTS = """resources
| where type =~ 'microsoft.documentdb/databaseaccounts'
| project id, name, tags, kind,
    endpoint = tostring(properties.documentEndpoint),
    capabilities = properties.capabilities,
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    vnetFilter = tobool(properties.isVirtualNetworkFilterEnabled),
    ipRules = array_length(properties.ipRules),
    keyUri = tostring(properties.keyVaultKeyUri)
| order by id asc"""
MONGO_CLUSTERS = """resources
| where type =~ 'microsoft.documentdb/mongoclusters'
| project id, name, tags,
    state = tostring(properties.clusterStatus),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    authModes = properties.authConfig.allowedModes,
    keyUri = tostring(properties.encryption.customerManagedKeyEncryption.keyEncryptionKeyUrl)
| order by id asc"""


def cosmos_api(row: dict[str, Any]) -> str:
    """`sql` (NoSQL), `mongodb`, `cassandra`, `gremlin` or `table`: the account's API."""
    if str(row.get("kind") or "").lower() == "mongodb":
        return "mongodb"
    caps = {
        str(c.get("name") if isinstance(c, dict) else c).lower()
        for c in row.get("capabilities") or []
    }
    for cap, api in (
        ("enablemongo", "mongodb"),
        ("enablecassandra", "cassandra"),
        ("enablegremlin", "gremlin"),
        ("enabletable", "table"),
    ):
        if cap in caps:
            return api
    return "sql"


def _facts(row: dict[str, Any]) -> dict[str, str]:
    key = str(row.get("keyUri") or "")
    return key_facts("Microsoft.Keyvault", key) if key else key_facts("Microsoft.Storage")


def _tags(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


@dataclass
class CosmosTarget:
    """One NoSQL container."""

    rid: ResourceId  # the container's resource
    account: str
    database: str
    container: str
    endpoint: str

    def __repr__(self) -> str:
        return f"CosmosTarget({redact_digits(self.account)!r})"


class CosmosAdapter:
    kind = "cosmosdb"

    def discover(self, ctx: Context, out: Discovery) -> None:
        arm = ctx.clients.client("arm")
        for row in ctx.graph(COSMOS_ACCOUNTS):
            rid = ResourceId.parse(str(row.get("id") or ""))
            account = str(row.get("name") or rid.name)
            api = cosmos_api(row)
            facts = _facts(row)
            restricted = (
                str(row.get("publicNetworkAccess") or "").lower() == "disabled"
                or bool(row.get("vnetFilter"))
                or int(row.get("ipRules") or 0) > 0
            )
            if api != "sql":
                store = self._store(rid, f"{account}/*", row, restricted, facts)
                store.extra["api"] = api
                out.stores.append(store)
                if apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                    store.skip("no_read_path")  # only the account's keys read it, and they write
                continue
            try:
                found: list[tuple[str, str]] = []
                for db in arm.list(f"{rid.value}/sqlDatabases", COSMOS_API):
                    name = str(db.get("name") or "")
                    for c in arm.list(f"{rid.value}/sqlDatabases/{name}/containers", COSMOS_API):
                        found.append((name, str(c.get("name") or "")))
            except Exception as err:  # the account is reported, its containers unknown
                store = self._store(rid, f"{account}/*", row, restricted, facts)
                store.status, store.error = "error", error_name(err)
                store.reason = reason_for(store.error)
                out.stores.append(store)
                continue
            for database, container in found:
                crid = ResourceId.parse(
                    f"{rid.value}/sqlDatabases/{database}/containers/{container}"
                )
                store = self._store(
                    crid, f"{account}/{database}/{container}", row, restricted, facts
                )
                store.extra["api"] = "sql"
                store.table = CosmosTarget(
                    crid, account, database, container, str(row.get("endpoint") or "")
                )
                out.stores.append(store)
                apply_rules(store, ctx.settings.allow, ctx.settings.deny)

    def _store(
        self,
        rid: ResourceId,
        name: str,
        row: dict[str, Any],
        restricted: bool,
        facts: dict[str, str],
    ) -> Store:
        store = Store(self.kind, name, tags=_tags(row.get("tags")))
        store.extra.update(azure_fields(rid))
        if restricted:
            store.extra["networkRestricted"] = True
        store.facts = dict(facts)
        return store

    def source(self, ctx: Context, store: Store) -> CosmosSource | None:
        t = store.table
        if not isinstance(t, CosmosTarget):
            return None
        client = ctx.clients.client("cosmos", t.endpoint)
        container = client.get_database_client(t.database).get_container_client(t.container)
        return CosmosSource(container, t, max_items=ctx.settings.cosmos_max_items)


class CosmosSource:
    """One NoSQL container: `SELECT TOP n` items, read by top-level property."""

    kind = "cosmosdb"

    def __init__(self, container: Any, target: CosmosTarget, *, max_items: int = 1000) -> None:
        self.container = container
        self.t = target
        self.max_items = max_items
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"cosmos:{target.account}/{target.database}/{target.container}"
        self.target = f"{target.account}/{target.database}/{target.container}"

    def __repr__(self) -> str:
        return f"CosmosSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target, listed=1, eligible=1)
        if not budget.has():
            cov.backlog = True
            return SourceRun(cov, cursor, note="budget")
        try:
            items = self.container.query_items(
                "SELECT TOP @n * FROM c",
                parameters=[{"name": "@n", "value": self.max_items}],
                enable_cross_partition_query=True,
                max_item_count=min(self.max_items, 1000),
            )
            rows = [
                {k: plain(v) for k, v in dict(i).items() if k not in SYSTEM_PROPERTIES}
                for i in itertools.islice(items, self.max_items)
            ]
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        size = len(json.dumps(rows, default=str))
        budget.take(size)
        columns = list(dict.fromkeys(k for r in rows for k in r))
        result = scan_rows("json", columns, rows, detector, self.max_items)
        cov.scanned, cov.bytes_scanned, cov.pass_complete = 1, size, True
        cov.partial = int(len(rows) >= self.max_items)
        cov.formats["json"] = 1
        cov.test_values, cov.suppressed = result.test_values, result.suppressed
        cov.redaction_markers = result.redaction_markers
        t = self.t

        def resource(column: str) -> dict[str, Any]:
            out = store_field_resource(
                service=self.kind,
                store=t.account,
                database=t.database,
                table=t.container,
                field=column,
                read_by="query",
            )
            out.update(azure_fields(t.rid))
            return out

        found = column_findings(
            result, resource, portal_link(t.rid), now.isoformat(), facts=self.facts
        )
        store.replace_location(f"{self.id}\n", found)
        return SourceRun(cov, {})


# ------------------------------------------------------------------ MongoDB vCore


@dataclass
class MongoTarget:
    rid: ResourceId  # the cluster
    cluster: str
    host: str

    def __repr__(self) -> str:
        return f"MongoTarget({redact_digits(self.cluster)!r})"


class MongoClusterAdapter:
    kind = "cosmosdb_mongo"

    def discover(self, ctx: Context, out: Discovery) -> None:
        for row in ctx.graph(MONGO_CLUSTERS):
            rid = ResourceId.parse(str(row.get("id") or ""))
            cluster = str(row.get("name") or rid.name)
            store = Store(self.kind, f"{cluster}/*", tags=_tags(row.get("tags")))
            store.extra.update(azure_fields(rid))
            store.extra["api"] = "mongodb"
            if str(row.get("publicNetworkAccess") or "").lower() == "disabled":
                store.extra["networkRestricted"] = True
            store.facts = _facts(row)
            store.table = MongoTarget(
                rid, cluster, f"{cluster}.global.mongocluster.cosmos.azure.com"
            )
            out.stores.append(store)
            if str(row.get("state") or "").lower() in ("stopped", "stopping"):
                store.skip("paused")
                continue
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            modes = {str(m).lower() for m in row.get("authModes") or []}
            if "microsoftentraid" not in modes:
                store.skip("no_read_path")  # only its native users' passwords read it
            elif self.kind not in ctx.settings.db_read:
                store.skip("read_not_configured")

    def source(self, ctx: Context, store: Store) -> MongoClusterSource | None:
        t = store.table
        if not isinstance(t, MongoTarget):
            return None
        driver = ctx.clients.client("driver", "pymongo")
        if driver is None:
            store.skip("driver_missing")
            return None
        return MongoClusterSource(t, driver, ctx.clients.credential, ctx.settings)


class MongoClusterSource:
    """A vCore cluster: its user checked, then `$sample` per collection (the databases
    runner's `MongoSession`), as the managed identity."""

    kind = "cosmosdb_mongo"

    def __init__(self, target: MongoTarget, driver: Any, credential: Any, settings: Any) -> None:
        self.t = target
        self.driver = driver
        self.credential = credential
        self.settings = settings
        self.facts: dict[str, Any] | None = None
        self.id = f"mongo:{target.cluster}"
        self.target = target.cluster

    def __repr__(self) -> str:
        return f"MongoClusterSource({self.t!r})"

    def _client(self) -> Any:
        from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult  # noqa: PLC0415

        credential = self.credential

        class Token(OIDCCallback):
            def fetch(self, context: Any) -> OIDCCallbackResult:
                return OIDCCallbackResult(access_token=credential.get_token(OSSRDBMS_SCOPE).token)

        s = self.settings
        return self.driver.MongoClient(
            f"mongodb+srv://{self.t.host}/?tls=true&authMechanism=MONGODB-OIDC"
            "&retrywrites=false&maxIdleTimeMS=120000",
            authMechanismProperties={"OIDC_CALLBACK": Token()},
            appname="sensitive-data-scanner",
            serverSelectionTimeoutMS=s.db_connect_seconds * 1000,
            connectTimeoutMS=s.db_connect_seconds * 1000,
            socketTimeoutMS=s.db_statement_seconds * 1000,
            readPreference="secondaryPreferred",
        )

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        from sensitive_data_db.config import Settings as DbSettings  # noqa: PLC0415
        from sensitive_data_db.engines import MongoSession  # noqa: PLC0415

        cov = Coverage(self.kind, self.target)
        s = self.settings
        limits = DbSettings(
            site="azure",
            databases=(),
            max_rows=s.db_max_rows,
            max_tables=s.db_max_tables,
            statement_seconds=s.db_statement_seconds,
            connect_seconds=s.db_connect_seconds,
        )
        try:
            session = MongoSession(self._client(), None, limits)
        except Exception as err:  # reported by name; the message can quote the host
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=connect_gap(err))
        try:
            grants = session.grants()
            if not grants.verified:
                # The first command is where a cluster out of reach first shows.
                timeout = "timeout" in (grants.error or "").lower()
                cov.error = grants.error if timeout else None
                return SourceRun(cov, cursor, note="network" if timeout else "grants_unverifiable")
            if grants.write:
                write = sorted(grants.write)[:MAX_WRITE_GRANTS]
                return SourceRun(
                    cov, cursor, note="db_user_can_write", extra={"writeGrants": write}
                )
            t = self.t
            seen_at = now.isoformat()
            link = portal_link(t.rid)

            def on_table(database: str, collection: str, result: TableResult) -> None:
                def resource(column: str) -> dict[str, Any]:
                    out = store_field_resource(
                        service=self.kind,
                        store=t.cluster,
                        database=database,
                        table=collection,
                        field=column,
                        read_by="sample",
                    )
                    out.update(azure_fields(t.rid))
                    return out

                store.replace_location(
                    f"{self.id}\n{database}\n{collection}",
                    column_findings(result, resource, link, seen_at, facts=self.facts),
                )

            sp = session.read(
                settings=limits,
                detector=detector,
                has_room=budget.has,
                take=budget.take,
                on_table=on_table,
                source=self.target,
            )
        except Exception as err:  # the listing itself failed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            return SourceRun(cov, cursor, note=connect_gap(err))
        finally:
            session.close()
        cov.listed, cov.eligible, cov.scanned = sp.listed, sp.eligible, sp.scanned
        cov.unreadable, cov.partial, cov.bytes_scanned = sp.unreadable, sp.partial, sp.bytes
        cov.test_values, cov.suppressed = sp.test_values, sp.suppressed
        cov.redaction_markers = sp.redaction_markers
        cov.pass_complete, cov.backlog = sp.done, not sp.done
        if sp.scanned:
            cov.formats["json"] = sp.scanned
        return SourceRun(cov, {}, note="no_grant" if sp.listed == 0 else None)
