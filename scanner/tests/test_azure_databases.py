"""Azure's databases: Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible servers
and Synapse SQL pools. Discovered by default; read (opt-in) as the managed identity with an
Entra token, the user checked first. Stubbed Azure SDK and drivers; every value made up.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from azure_fakes import NOW, SUB_A, TOKEN, Arm, AzureError, Graph, Tenant, settings
from db_fakes import READ_VERBS, Db, Driver
from sensitive_data_azure.config import ConfigError, read_settings
from sensitive_data_azure.resources import resource_id_hash
from sensitive_data_azure.runner import run_scan
from sensitive_data_azure.sources.databases import OSSRDBMS_SCOPE, connect_gap
from sensitive_data_core.findings import key_hash
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
RG = f"/subscriptions/{SUB_A}/resourceGroups/rg-db/providers"
SQL = f"{RG}/Microsoft.Sql/servers/sql-contoso"
MI = f"{RG}/Microsoft.Sql/managedInstances/mi-contoso"
PG = f"{RG}/Microsoft.DBforPostgreSQL/flexibleServers/pg-contoso"
PG_OFF = f"{RG}/Microsoft.DBforPostgreSQL/flexibleServers/pg-legacy"
MY = f"{RG}/Microsoft.DBforMySQL/flexibleServers/my-contoso"
SYN = f"{RG}/Microsoft.Synapse/workspaces/syn-contoso"
PG_KEY = "https://kv-contoso.vault.azure.net/keys/pg-key"
ROLES = ("sysadmin", "db_owner", "db_datawriter", "db_ddladmin")
ROWS = [{"card_number": CARDS["visa"], "ssn": dashed(SSN_A), "note": "x"}]


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def sqlserver_db(**tables: list[dict[str, Any]]) -> Db:
    db = Db(tables={("dbo", t): rows for t, rows in tables.items()})
    db.on(
        r"IS_SRVROLEMEMBER", [{"sysadmin": 0, "db_owner": 0, "db_datawriter": 0, "db_ddladmin": 0}]
    )
    db.on(r"fn_my_permissions", [{"permission_name": "CONNECT"}, {"permission_name": "SELECT"}])
    db.on(r"HAS_PERMS_BY_NAME", [{"objects": 0}])
    return db


def postgres_db() -> Db:
    return Db(tables={("public", "customers"): ROWS}).on(
        r"FROM pg_roles r",
        [
            {
                "superuser": False,
                "createrole": False,
                "createdb": False,
                "database_create": False,
                "table_write": 0,
                "schema_create": 0,
                "public_schema_create": False,
            }
        ],
    )


def mysql_db(grant: str = "SELECT") -> Db:
    return Db(tables={("shop", "orders"): ROWS}).on(
        r"SHOW GRANTS", [{"Grants for sds@%": f"GRANT {grant} ON `shop`.* TO `sds-job`@`%`"}]
    )


class Router:
    """A driver module whose `connect` picks a stubbed database by the database named."""

    def __init__(self, dbs: dict[str, Db], fail: dict[str, Exception] | None = None) -> None:
        self.drivers = {name: Driver(db) for name, db in dbs.items()}
        self.fail = fail or {}
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def connect(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        text = args[0] if args else ""
        m = re.search(r"Database=\{([^}]*)\}", text)
        name = m[1] if m else str(kwargs.get("dbname") or kwargs.get("database") or "")
        if name in self.fail:
            raise self.fail[name]
        return self.drivers[name].connect(*args, **kwargs)

    def statements(self) -> list[str]:
        return [s for d in self.drivers.values() for s in d.statements()]


def graph() -> Graph:
    return Graph(
        {
            "microsoft.sql/servers'": [
                {
                    "id": SQL,
                    "name": "sql-contoso",
                    "fqdn": "sql-contoso.database.windows.net",
                    "publicNetworkAccess": "Enabled",
                }
            ],
            "microsoft.sql/servers/databases": [
                {"id": f"{SQL}/databases/master", "name": "master", "status": "Online"},
                {"id": f"{SQL}/databases/orders", "name": "orders", "status": "Online"},
                {"id": f"{SQL}/databases/idle", "name": "idle", "status": "Paused"},
            ],
            "microsoft.sql/managedinstances'": [
                {
                    "id": MI,
                    "name": "mi-contoso",
                    "fqdn": "mi-contoso.abc123.database.windows.net",
                    "dnsZone": "abc123",
                    "publicDataEndpoint": True,
                    "state": "Ready",
                }
            ],
            "microsoft.sql/managedinstances/databases": [
                {"id": f"{MI}/databases/hr", "name": "hr", "status": "Online"},
                {"id": f"{MI}/databases/msdb", "name": "msdb", "status": "Online"},
            ],
            "microsoft.dbforpostgresql/flexibleservers": [
                {
                    "id": PG,
                    "name": "pg-contoso",
                    "fqdn": "pg-contoso.postgres.database.azure.com",
                    "state": "Ready",
                    "publicNetworkAccess": "Enabled",
                    "entraAuth": "Enabled",
                    "keyType": "AzureKeyVault",
                    "keyUri": PG_KEY + "/0a1b2c",
                },
                {
                    "id": PG_OFF,
                    "name": "pg-legacy",
                    "fqdn": "pg-legacy.postgres.database.azure.com",
                    "state": "Ready",
                    "entraAuth": "Disabled",
                    "keyType": "SystemManaged",
                },
            ],
            "microsoft.dbformysql/flexibleservers": [
                {
                    "id": MY,
                    "name": "my-contoso",
                    "fqdn": "my-contoso.mysql.database.azure.com",
                    "state": "Ready",
                    "publicNetworkAccess": "Disabled",
                    "keyType": "SystemManaged",
                }
            ],
            "microsoft.synapse/workspaces'": [
                {
                    "id": SYN,
                    "name": "syn-contoso",
                    "sqlEndpoint": "syn-contoso.sql.azuresynapse.net",
                }
            ],
            "microsoft.synapse/workspaces/sqlpools": [
                {"id": f"{SYN}/sqlPools/dw", "name": "dw", "status": "Online"},
                {"id": f"{SYN}/sqlPools/dw2", "name": "dw2", "status": "Paused"},
            ],
        },
        page=10,
    )


def tenant(**drivers: Any) -> Tenant:
    t = Tenant(
        graph(),
        Arm(
            paths={
                f"{PG}/databases": [{"name": "app"}, {"name": "azure_maintenance"}],
                f"{PG_OFF}/databases": [{"name": "old"}],
                f"{MY}/databases": [{"name": "shop"}, {"name": "sys"}],
            },
            objects={
                f"{SQL}/encryptionProtector/current": {
                    "properties": {"serverKeyType": "ServiceManaged"}
                },
                f"{SQL}/databases/orders/transparentDataEncryption/current": {
                    "properties": {"state": "Enabled"}
                },
                f"{MI}/encryptionProtector/current": {
                    "properties": {
                        "serverKeyType": "AzureKeyVault",
                        "uri": "https://kv-contoso.vault.azure.net/keys/mi-key/99",
                    }
                },
                f"{SYN}/sqlPools/dw/transparentDataEncryption/current": {
                    "properties": {"status": "Enabled"}
                },
            },
        ),
    )
    t.drivers.update(drivers)
    return t


def run(t: Tenant, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(DISCOVER="all", **env), t.clients(), detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f"{s['kind']}:{s['name']}": s for s in doc["discovery"]["stores"]}


def drivers() -> dict[str, Router]:
    return {
        "mssql_python": Router(
            {
                "orders": sqlserver_db(customers=ROWS),
                "hr": sqlserver_db(staff=ROWS),
                "dw": sqlserver_db(facts=ROWS),
            }
        ),
        "psycopg": Router({"app": postgres_db()}),
        "pymysql": Router({"shop": mysql_db()}),
    }


# ------------------------------------------------------------------ discovery


def test_databases_are_discovered_and_not_read_unless_opted_in() -> None:
    d = drivers()
    doc = run(tenant(**d))
    s = stores(doc)
    assert "azure_sql:sql-contoso/master" not in s and "azure_sql_mi:mi-contoso/msdb" not in s
    assert "azure_postgresql:pg-contoso/azure_maintenance" not in s
    assert "azure_mysql:my-contoso/sys" not in s
    for name in (
        "azure_sql:sql-contoso/orders",
        "azure_sql_mi:mi-contoso/hr",
        "azure_postgresql:pg-contoso/app",
        "azure_mysql:my-contoso/shop",
        "synapse_sql:syn-contoso/dw",
    ):
        assert s[name]["reason"] == "read_not_configured", name
    assert s["azure_sql:sql-contoso/idle"]["reason"] == "paused"
    assert s["synapse_sql:syn-contoso/dw2"]["reason"] == "paused"
    assert s["azure_postgresql:pg-legacy/old"]["reason"] == "no_read_path"
    assert s["azure_mysql:my-contoso/shop"]["networkRestricted"] is True
    assert not any(r.calls for r in d.values())
    # Storage encryption from Resource Manager (Reader).
    assert s["azure_sql:sql-contoso/orders"]["atRestEncryption"] == "service_managed"
    assert s["azure_sql_mi:mi-contoso/hr"]["atRestKeyHash"] == key_hash(
        "https://kv-contoso.vault.azure.net/keys/mi-key"
    )
    assert s["azure_postgresql:pg-contoso/app"]["atRestKeyHash"] == key_hash(PG_KEY)
    assert s["azure_mysql:my-contoso/shop"]["atRestEncryption"] == "service_managed"
    assert s["synapse_sql:syn-contoso/dw"]["atRestEncryption"] == "service_managed"
    assert s["azure_sql:sql-contoso/orders"]["resourceIdHash"] == resource_id_hash(
        f"{SQL}/databases/orders"
    )


def test_settings_for_reading_databases() -> None:
    base = {"SCANNER_SITE": "x", "AZURE_MANAGEMENT_GROUP": "mg", "FINDINGS_FILE": "/f"}
    with pytest.raises(ConfigError) as err:
        read_settings({**base, "AZURE_DB_READ": "postgresql"})
    assert err.value.code == "azure_db_principal"
    with pytest.raises(ConfigError) as err:
        read_settings({**base, "AZURE_DB_READ": "blob"})
    assert err.value.code == "azure_db_read"
    s = read_settings({**base, "AZURE_DB_READ": "sql,synapse"})
    assert s.db_read == ("azure_sql", "synapse_sql")
    s = read_settings({**base, "AZURE_DB_READ": "all", "AZURE_DB_PRINCIPAL": "sds-job"})
    assert len(s.db_read) == 5 and s.db_principal == "sds-job"


# ------------------------------------------------------------------ reading


def test_every_kind_is_read_as_the_identity_after_the_user_check() -> None:
    d = drivers()
    t = tenant(**d)
    doc = run(t, AZURE_DB_READ="all", AZURE_DB_PRINCIPAL="sds-job")
    s = stores(doc)
    for name in (
        "azure_sql:sql-contoso/orders",
        "azure_sql_mi:mi-contoso/hr",
        "azure_postgresql:pg-contoso/app",
        "azure_mysql:my-contoso/shop",
        "synapse_sql:syn-contoso/dw",
    ):
        assert s[name]["status"] == "scanned", name
    services = {f["resource"]["service"] for f in doc["findings"]}
    assert services == {
        "azure_sql",
        "azure_sql_mi",
        "azure_postgresql",
        "azure_mysql",
        "synapse_sql",
    }
    card = next(
        f
        for f in doc["findings"]
        if f["resource"]["service"] == "azure_sql" and f["class"] == "card"
    )
    assert card["resource"] | {"resourceIdHash": ""} == {
        "type": "store_field",
        "service": "azure_sql",
        "store": "sql-contoso",
        "database": "orders",
        "table": "dbo.customers",
        "field": "card_number",
        "readBy": "sample",
        "subscription": SUB_A,
        "resourceGroup": "rg-db",
        "resourceIdHash": "",
    }
    assert (
        card["atRestEncryption"] == "service_managed"
        and card["pciNote"]["requirement"] == "3.5.1.2"
    )
    assert card["link"].startswith("https://portal.azure.com/#resource/subscriptions/")
    pg = next(f for f in doc["findings"] if f["resource"]["service"] == "azure_postgresql")
    assert pg["atRestEncryption"] == "customer_managed_key"
    # SQL: an Entra token through the driver, a read-only intent, an encrypted connection.
    sql_args, sql_kwargs = d["mssql_python"].calls[0]
    assert "ApplicationIntent=ReadOnly" in sql_args[0] and "Encrypt=yes" in sql_args[0]
    assert "TrustServerCertificate=no" in sql_args[0] and "Password" not in sql_args[0]
    assert sql_kwargs["token_provider"] is t.credential
    mi_args, _ = next(c for c in d["mssql_python"].calls if "{hr}" in c[0][0])
    assert "mi-contoso.public.abc123.database.windows.net,3342" in mi_args[0]
    # PostgreSQL and MySQL: the token as the password, TLS verified, the identity's name.
    _, pg_kwargs = d["psycopg"].calls[0]
    assert (pg_kwargs["user"], pg_kwargs["password"], pg_kwargs["sslmode"]) == (
        "sds-job",
        TOKEN,
        "verify-full",
    )
    assert "default_transaction_read_only=on" in pg_kwargs["options"]
    _, my_kwargs = d["pymysql"].calls[0]
    assert my_kwargs["ssl_verify_identity"] is True and my_kwargs["password"] == TOKEN
    assert OSSRDBMS_SCOPE in t.credential.scopes
    # Only reads were sent, and every session was rolled back.
    for router in d.values():
        sent = router.statements()
        assert sent and all(READ_VERBS.match(x) for x in sent), sent
        assert all(c.rollbacks and c.closed for drv in router.drivers.values() for c in drv.conns)


def test_a_user_that_can_write_is_refused_and_nothing_is_read() -> None:
    d = drivers()
    d["pymysql"] = Router({"shop": mysql_db("SELECT, INSERT, UPDATE")})
    d["mssql_python"].drivers["orders"].db.on(
        r"IS_SRVROLEMEMBER", [{"sysadmin": 0, "db_owner": 1, "db_datawriter": 0, "db_ddladmin": 0}]
    )
    d["mssql_python"].drivers["orders"].db.catalog.reverse()
    doc = run(tenant(**d), AZURE_DB_READ="all", AZURE_DB_PRINCIPAL="sds-job")
    s = stores(doc)
    my = s["azure_mysql:my-contoso/shop"]
    assert (my["status"], my["reason"]) == ("skipped", "db_user_can_write")
    assert my["writeGrants"] == ["INSERT", "UPDATE"]
    assert s["azure_sql:sql-contoso/orders"]["writeGrants"] == ["db_owner"]
    assert not any(re.match(r"^SELECT \*", x) for x in d["pymysql"].statements())
    assert not any(f["resource"]["service"] == "azure_mysql" for f in doc["findings"])


def test_unverifiable_grants_network_and_login_gaps() -> None:
    d = drivers()
    d["mssql_python"].drivers["dw"].db.catalog.insert(
        0, (re.compile("IS_SRVROLEMEMBER", re.I), PermissionError("not supported"))
    )
    d["mssql_python"].fail["hr"] = ConnectionError(
        "[08001] TCP Provider: Timeout error connecting to mi-contoso"
    )
    d["mssql_python"].fail["orders"] = RuntimeError(
        "Login failed for user '<token-identified principal>'. (18456)"
    )
    d["psycopg"].fail["app"] = RuntimeError("could not connect to server: Connection refused")
    doc = run(tenant(**d), AZURE_DB_READ="all", AZURE_DB_PRINCIPAL="sds-job")
    s = stores(doc)
    assert s["synapse_sql:syn-contoso/dw"]["reason"] == "grants_unverifiable"
    assert (
        s["azure_sql_mi:mi-contoso/hr"]["status"],
        s["azure_sql_mi:mi-contoso/hr"]["reason"],
    ) == (
        "skipped",
        "network",
    )
    assert s["azure_sql:sql-contoso/orders"]["reason"] == "access_denied"
    assert s["azure_sql:sql-contoso/orders"]["error"] == "RuntimeError"
    assert s["azure_postgresql:pg-contoso/app"]["reason"] == "network"


def test_a_missing_driver_is_the_stores_gap() -> None:
    d = drivers()
    t = tenant(**d)
    t.drivers["pymysql"] = None
    s = stores(run(t, AZURE_DB_READ="mysql", AZURE_DB_PRINCIPAL="sds-job"))
    assert s["azure_mysql:my-contoso/shop"]["reason"] == "driver_missing"


def test_a_database_listing_that_fails_is_the_servers_gap() -> None:
    t = tenant(**drivers())
    t.arm.paths[f"{MY}/databases"] = AzureError("AuthorizationFailed")
    s = stores(run(t))
    assert s["azure_mysql:my-contoso/*"]["reason"] == "access_denied"


def test_the_budget_resumes_a_database_by_table() -> None:
    db = sqlserver_db(**{f"t{i}": ROWS for i in range(5)})
    d = drivers()
    d["mssql_python"] = Router({"orders": db, "hr": sqlserver_db(), "dw": sqlserver_db()})
    t = tenant(**d)
    env = {"AZURE_DB_READ": "sql", "MAX_ITEMS_PER_RUN": "2", "DISCOVER": "sql"}
    read: list[str] = []
    for _ in range(4):
        doc, _ = run_scan(settings(**env), t.clients(), detector=shared_detector(), now=lambda: NOW)
        assert doc is not None
        valid(doc)
    for x in d["mssql_python"].statements():
        m = re.match(r"^SELECT TOP \(\d+\) \* FROM \[dbo\]\.\[(t\d)\]", x)
        if m:
            read.append(m[1])
    assert sorted(set(read)) == ["t0", "t1", "t2", "t3", "t4"]


def test_connect_gap_reads_the_message_and_keeps_none_of_it() -> None:
    assert (
        connect_gap(RuntimeError("Reason: 40615 client with IP 10.0.0.1 not allowed")) == "network"
    )
    assert connect_gap(RuntimeError("FATAL: password authentication failed for user")) == (
        "access_denied"
    )
    assert connect_gap(RuntimeError("something else")) is None


def test_a_link_is_dropped_when_any_name_in_it_is_masked() -> None:
    from sensitive_data_azure.resources import ResourceId, portal_link
    from sensitive_data_core.findings import link_for

    rid = ResourceId.parse(f"{RG}/Microsoft.Sql/servers/sql-{CARDS['visa']}/databases/orders")
    assert link_for({}, portal_link(rid)) is None
    assert link_for({}, portal_link(ResourceId.parse(f"{SQL}/databases/orders")))
