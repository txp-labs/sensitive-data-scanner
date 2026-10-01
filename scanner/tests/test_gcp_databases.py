"""Cloud SQL and AlloyDB: discovered by default; read (opt-in) as the service account with IAM
database authentication, the user checked first. Stubbed REST and drivers; every value made up.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from aws_fixtures import shared_detector
from db_fakes import READ_VERBS, Db
from gcp_fakes import (
    CA,
    KEY,
    NOW,
    PROJECT,
    SA,
    TOKEN,
    Cloud,
    Databases,
    error,
    settings,
    sql_instance,
    sql_row,
    vpc_denied,
)
from sensitive_data_core.findings import key_hash
from sensitive_data_gcp.config import ConfigError, read_settings
from sensitive_data_gcp.resources import resource_name_hash
from sensitive_data_gcp.runner import run_scan
from sensitive_data_gcp.sources.databases import (
    ALLOYDB_LOGIN_SCOPE,
    SQL_LOGIN_SCOPE,
    db_user,
    sql_kind,
)
from synthetic import CARDS, SSN_A, dashed
from test_azure_databases import Router, mysql_db, postgres_db
from test_gcp_gcs import valid

ALLOY = f"projects/{PROJECT}/locations/us-central1/clusters/alloy-main"
ROWS = [{"card_number": CARDS["visa"], "ssn": dashed(SSN_A), "note": "x"}]


def alloy_db() -> Db:
    db = postgres_db()
    db.tables = {("public", "payments"): ROWS}
    return db


def listing_db() -> Db:
    """`postgres`: no table of its own, and the AlloyDB cluster's list of databases."""
    db = postgres_db()
    db.tables = {}
    return db.on(r"FROM pg_database", [{"datname": "app"}, {"datname": "alloydbadmin"}])


def cloud() -> tuple[Cloud, Databases]:
    c = Cloud()
    dbs = Databases(c)
    c.assets["sqladmin.googleapis.com/Instance"] = [
        sql_row("pg-orders"),
        sql_row("my-shop"),
        sql_row("pg-legacy"),
        sql_row("ms-erp"),
        sql_row("pg-idle"),
        sql_row("pg-denied"),
    ]
    dbs.instances[(PROJECT, "pg-orders")] = sql_instance("POSTGRES_16", kms=KEY)
    dbs.databases[(PROJECT, "pg-orders")] = ["postgres", "orders", "cloudsqladmin"]
    dbs.instances[(PROJECT, "my-shop")] = sql_instance("MYSQL_8_0", private=True)
    dbs.databases[(PROJECT, "my-shop")] = ["shop", "mysql"]
    dbs.instances[(PROJECT, "pg-legacy")] = sql_instance("POSTGRES_13", iam=False)
    dbs.databases[(PROJECT, "pg-legacy")] = ["hr"]
    dbs.instances[(PROJECT, "ms-erp")] = sql_instance("SQLSERVER_2022_STANDARD")
    dbs.databases[(PROJECT, "ms-erp")] = ["erp", "master"]
    dbs.instances[(PROJECT, "pg-idle")] = sql_instance("POSTGRES_16", state="STOPPED")
    dbs.databases[(PROJECT, "pg-idle")] = ["idle"]
    dbs.instances[(PROJECT, "pg-denied")] = error(403, "PERMISSION_DENIED", message="no get")
    c.assets["alloydb.googleapis.com/Cluster"] = [
        {
            "name": f"//alloydb.googleapis.com/{ALLOY}",
            "assetType": "alloydb.googleapis.com/Cluster",
            "project": "projects/421000000001",
        }
    ]
    dbs.clusters[ALLOY] = {"encryptionConfig": {"kmsKeyName": KEY}}
    dbs.cluster_instances[ALLOY] = [
        {
            "name": f"{ALLOY}/instances/primary",
            "instanceType": "PRIMARY",
            "state": "READY",
            "ipAddress": "10.1.0.2",
            "databaseFlags": {"alloydb.iam_authentication": "on"},
        },
        {
            "name": f"{ALLOY}/instances/reads",
            "instanceType": "READ_POOL",
            "state": "READY",
            "ipAddress": "10.1.0.9",
            "databaseFlags": {"alloydb.iam_authentication": "on"},
        },
    ]
    return c, dbs


def drivers(**extra: Db) -> tuple[Router, Router]:
    pg = Router({"orders": postgres_db(), "postgres": listing_db(), "app": alloy_db(), **extra})
    my = Router({"shop": mysql_db()})
    return pg, my


def run(c: Cloud, pg: Router | None = None, my: Router | None = None, **env: str) -> dict[str, Any]:
    kinds = "cloudsql_postgresql,cloudsql_mysql,cloudsql_sqlserver,alloydb"
    doc, failed = run_scan(
        settings(DISCOVER=kinds, **env),
        c.clients({"psycopg": pg, "pymysql": my}),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


READ = {"GCP_DB_READ": "all", "GCP_DB_PRINCIPAL": SA}


def test_discovered_by_default_read_only_when_opted_in() -> None:
    c, _ = cloud()
    s = stores(run(c))
    assert s["pg-orders/orders"]["reason"] == "read_not_configured"
    assert s["pg-orders/orders"]["resourceNameHash"] == resource_name_hash(
        f"//cloudsql.googleapis.com/projects/{PROJECT}/instances/pg-orders"
    )
    assert s["pg-orders/orders"]["atRestKeyHash"] == key_hash(KEY)
    assert "pg-orders/cloudsqladmin" not in s and "my-shop/mysql" not in s
    assert s["my-shop/shop"]["networkRestricted"] is True
    assert s["pg-legacy/hr"]["reason"] == "no_read_path"  # the IAM flag is off
    assert s["ms-erp/erp"]["reason"] == "no_read_path"  # no IAM authentication for SQL Server
    assert s["ms-erp/erp"]["kind"] == "cloudsql_sqlserver" and "ms-erp/master" not in s
    assert s["pg-idle/idle"]["reason"] == "paused"
    assert (s["pg-denied/*"]["status"], s["pg-denied/*"]["reason"]) == ("error", "access_denied")
    assert s["alloy-main"]["reason"] == "read_not_configured"
    # #105: each gap names the setting that turns its read on (C4: SQL Server's is a hook).
    assert s["pg-orders/orders"]["toggle"] == "GCP_DB_READ"
    assert s["ms-erp/erp"]["toggle"] == "GCP_SQLSERVER"
    assert "toggle" not in s["pg-legacy/hr"]  # the instance's IAM flag, not a setting here


def test_sql_server_is_a_hook_and_alloydb_a_toggle() -> None:
    """C4 (#105): GCP_SQLSERVER on gives `not_implemented` (no password-free reader exists);
    C2: GCP_ALLOYDB off leaves AlloyDB unread even with GCP_DB_READ, and asks for no client
    certificate (one of the named exceptions)."""
    c, dbs = cloud()
    pg, my = drivers()
    s = stores(run(c, pg, my, GCP_SQLSERVER="on", GCP_ALLOYDB="off", **READ))
    assert (s["ms-erp/erp"]["status"], s["ms-erp/erp"]["reason"], s["ms-erp/erp"]["toggle"]) == (
        "skipped",
        "not_implemented",
        "GCP_SQLSERVER",
    )
    alloy = s["alloy-main"]
    assert (alloy["status"], alloy["reason"], alloy["toggle"]) == (
        "skipped",
        "read_not_configured",
        "GCP_ALLOYDB",
    )
    assert dbs.certificates == []
    assert not [k for _, k in pg.calls if k["host"].startswith("10.1.")]
    assert s["pg-orders/orders"]["status"] == "scanned"  # Cloud SQL is read as before


def test_read_as_the_service_account_with_its_token_over_verified_tls() -> None:
    c, _ = cloud()
    pg, my = drivers()
    doc = run(c, pg, my, **READ)
    s = stores(doc)
    assert s["pg-orders/orders"]["status"] == "scanned"
    assert s["pg-orders/postgres"]["reason"] == "no_grant"  # no table the user can see
    assert s["my-shop/shop"]["status"] == "scanned"
    assert s["alloy-main"]["status"] == "scanned"
    assert s["ms-erp/erp"]["reason"] == "no_read_path"  # opted in, still never a password
    pg_call = next(k for _, k in pg.calls if k["dbname"] == "orders")
    assert pg_call["user"] == "sds-scanner@acme-sds.iam" and pg_call["password"] == TOKEN
    assert (pg_call["sslmode"], pg_call["host"], pg_call["port"]) == ("verify-ca", "10.0.0.5", 5432)
    assert "default_transaction_read_only=on" in pg_call["options"]
    assert not os.path.exists(pg_call["sslrootcert"])  # the CA file is gone after connecting
    my_call = my.calls[0][1]
    assert (my_call["user"], my_call["password"], my_call["ssl_verify_cert"]) == (
        "sds-scanner",
        TOKEN,
        True,
    )
    assert my_call["init_command"] == "SET SESSION TRANSACTION READ ONLY"
    assert [SQL_LOGIN_SCOPE] in c.credentials.scopes
    assert [ALLOYDB_LOGIN_SCOPE] in c.credentials.scopes
    for statement in pg.statements() + my.statements():
        assert READ_VERBS.match(statement), statement
    by = {(f["resource"]["service"], f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert ("cloudsql_postgresql", "card_number", "card") in by
    assert ("cloudsql_mysql", "ssn", "us_ssn") in by
    assert ("alloydb", "card_number", "card") in by
    card = next(f for f in doc["findings"] if f["resource"]["service"] == "cloudsql_postgresql")
    r = card["resource"]
    assert (r["store"], r["database"], r["table"], r["readBy"], r["project"]) == (
        "pg-orders",
        "orders",
        "public.customers",
        "sample",
        PROJECT,
    )
    assert card["atRestKeyHash"] == key_hash(KEY)
    assert card["link"] == (
        f"https://console.cloud.google.com/sql/instances/pg-orders/overview?project={PROJECT}"
    )
    alloy = next(f for f in doc["findings"] if f["resource"]["service"] == "alloydb")
    assert (alloy["resource"]["store"], alloy["resource"]["database"]) == ("alloy-main", "app")


def test_alloydb_reads_the_read_pool_with_the_cluster_ca() -> None:
    c, dbs = cloud()
    pg, my = drivers()
    run(c, pg, my, **READ)
    alloy_calls = [k for _, k in pg.calls if k["host"].startswith("10.1.")]
    assert alloy_calls and all(k["host"] == "10.1.0.9" for k in alloy_calls)
    assert {k["dbname"] for k in alloy_calls} == {"postgres", "app"}
    assert (
        dbs.certificates
        == [f"https://alloydb.googleapis.com/v1/{ALLOY}:generateClientCertificate"] * 2
    )
    assert CA.startswith("-----BEGIN")


def test_a_user_that_can_write_is_refused() -> None:
    c, _ = cloud()
    writer = postgres_db()
    writer.catalog[0] = (writer.catalog[0][0], [{"superuser": True, "table_write": 3}])
    pg, my = drivers(orders=writer)
    s = stores(run(c, pg, my, **READ))
    assert s["pg-orders/orders"]["reason"] == "db_user_can_write"
    assert set(s["pg-orders/orders"]["writeGrants"]) >= {"superuser", "table_write"}
    assert not any("customers" in st for st in pg.drivers["orders"].statements())


def test_unreachable_is_network_and_a_refused_login_is_access_denied() -> None:
    c, _ = cloud()
    pg, my = drivers()
    pg.fail["orders"] = ConnectionError("connection to 10.0.0.5 timed out")
    my.fail["shop"] = RuntimeError(f"(1045, \"Access denied for user 'sds-scanner' {TOKEN}\")")
    s = stores(run(c, pg, my, **READ))
    assert s["pg-orders/orders"]["reason"] == "network"
    assert s["my-shop/shop"]["reason"] == "access_denied"


def test_a_perimeter_on_the_admin_api_is_network_and_a_missing_driver_is_reported() -> None:
    c, dbs = cloud()
    dbs.instances[(PROJECT, "pg-denied")] = vpc_denied()
    doc, _ = run_scan(
        settings(DISCOVER="postgresql,mysql", **READ),
        c.clients({"psycopg": None, "pymysql": None}),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None
    s = stores(doc)
    assert s["pg-denied/*"]["reason"] == "network"
    assert s["pg-orders/orders"]["reason"] == "driver_missing"


def test_settings_for_database_reads() -> None:
    base = {"SCANNER_SITE": "x", "GCP_ORGANIZATION": "1", "FINDINGS_FILE": "/f"}
    for env, code in [
        ({"GCP_DB_READ": "all"}, "gcp_db_principal"),
        ({"GCP_DB_READ": "all", "GCP_DB_PRINCIPAL": "someone@example.com"}, "gcp_db_principal"),
        ({"GCP_DB_READ": "s3"}, "gcp_db_read"),
    ]:
        with pytest.raises(ConfigError) as err:
            read_settings({**base, **env})
        assert err.value.code == code
    s = read_settings({**base, "GCP_DB_READ": "postgresql,alloy", "GCP_DB_PRINCIPAL": SA})
    assert s.db_read == ("cloudsql_postgresql", "alloydb")


def test_engine_names_and_iam_users() -> None:
    assert sql_kind("POSTGRES_16") == "cloudsql_postgresql"
    assert sql_kind("MYSQL_8_4") == "cloudsql_mysql"
    assert sql_kind("SQLSERVER_2019_WEB") == "cloudsql_sqlserver"
    assert sql_kind("ORACLE") is None
    assert db_user("cloudsql_postgresql", SA) == "sds-scanner@acme-sds.iam"
    assert db_user("alloydb", SA) == "sds-scanner@acme-sds.iam"
    assert db_user("cloudsql_mysql", SA) == "sds-scanner"
