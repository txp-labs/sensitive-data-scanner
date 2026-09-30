"""The databases runner with stubbed drivers: configuration, each engine, the user check,
the budget, and the findings document. Every value is made up."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from conftest import REPO
from db_fakes import (
    READ_VERBS,
    Collection,
    Db,
    Driver,
    MongoClient,
    MongoDb,
    MongoDriver,
    read_only_mongo_status,
)
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.scan.sql import (
    DATABRICKS,
    ORACLE,
    SNOWFLAKE,
    SQLSERVER,
    sample_sql,
    tables_sql,
)
from sensitive_data_db import grants as g
from sensitive_data_db.config import ConfigError, Secret, read_settings
from sensitive_data_db.runner import run
from synthetic import CARDS, SSN_A, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
NOW = dt.datetime(2026, 9, 29, 12, 0, tzinfo=dt.UTC)
DETECTOR = Detector(load_spec(), NOW.date())
MADE_UP_PW = "Made-up-pw-7fQ2"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def env(**urls: str) -> dict[str, str]:
    out = {"SCANNER_SITE": "dc-1", "FINDINGS_FILE": "/dev/null"}
    out.update({f"DATABASE_URL_{k.upper()}": v for k, v in urls.items()})
    return out


class Sink:
    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def push(self, document: dict[str, Any]) -> int:
        self.docs.append(document)
        return 1


def people() -> list[dict[str, Any]]:
    return [
        {"id": 1, "card_number": CARDS["visa"], "ssn": dashed(SSN_A), "note": "hello"},
        {"id": 2, "card_number": CARDS["mastercard"], "ssn": None, "note": "x"},
    ]


def scan(e: dict[str, str], drivers: dict[str, Any]) -> dict[str, Any]:
    sink = Sink()
    doc, failed = run(read_settings(e), [sink], drivers=drivers, detector=DETECTOR, now=lambda: NOW)
    assert failed == 0
    assert sink.docs == [doc]
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


def classes(doc: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(f["resource"]["table"], f["resource"]["field"], f["class"]) for f in doc["findings"]}


def only_reads(driver: Driver) -> None:
    for sql in driver.statements():
        assert READ_VERBS.match(sql), sql[:60]


# ------------------------------------------------------------------ configuration


def test_settings_from_variables_files_and_a_directory(tmp_path: Path) -> None:
    (tmp_path / "hr").write_text(f"postgresql://ro:{MADE_UP_PW}@db.internal/hr\n")
    (tmp_path / "..data").mkdir()
    (tmp_path / ".hidden").write_text("mysql://x@y/z")
    one = tmp_path.parent / f"{tmp_path.name}-one.url"
    one.write_text("mongodb+srv://ro:pw@cluster0.example.net/app")
    s = read_settings(
        {
            "SCANNER_SITE": "DC-1",
            "DATABASE_URL_ORDERS": "mysql://ro:pw@10.0.0.5:3306/orders",
            "DATABASE_URL_FILE_EVENTS": str(one),
            "DATABASE_URLS_DIR": str(tmp_path),
            "DB_SCHEMAS": "public, hr",
            "DISCOVER_DENY": "mongodb:*",
            "FINDINGS_FILE": "/out/findings.json",
        }
    )
    assert s.site == "dc-1"
    assert [(d.name, d.engine) for d in s.databases] == [
        ("events", "mongodb"),
        ("orders", "mysql"),
        ("hr", "postgresql"),
    ]
    assert s.schemas == ("public", "hr")
    assert s.deny[0].kind == "mongodb"
    assert MADE_UP_PW not in repr(s)
    assert MADE_UP_PW not in repr(s.databases)
    assert repr(Secret(MADE_UP_PW)) == "Secret(***)"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"SCANNER_SITE": ""}, "scanner_site"),
        ({"DATABASE_URL_X": ""}, "empty_connection_string"),
        ({"DATABASE_URL_X": f"redis://u:{MADE_UP_PW}@h/0"}, "unknown_scheme"),
        ({"FINDINGS_FILE": ""}, "no_findings_destination"),
        ({"FINDINGS_HTTPS_URL": "http://collector.example/in"}, "findings_url_not_https"),
        ({"FINDINGS_HTTPS_URL": "https://collector.example/in"}, "findings_hmac_key"),
        ({"FINDINGS_EVENT_BUS_ARN": "not-an-arn"}, "findings_event_bus_arn"),
        ({"DB_MAX_TABLES": "many"}, "not_a_number"),
        ({"DISCOVER_DENY": "tag:"}, "discover_rule"),
    ],
)
def test_a_wrong_setting_is_named_by_a_code_never_its_value(
    changes: dict[str, str], code: str
) -> None:
    e = env(pg=f"postgresql://ro:{MADE_UP_PW}@db/app")
    e.update(changes)
    with pytest.raises(ConfigError) as err:
        read_settings(e)
    assert err.value.code == code
    assert MADE_UP_PW not in str(err.value) and MADE_UP_PW not in repr(err.value)


def test_no_database_is_an_error() -> None:
    with pytest.raises(ConfigError) as err:
        read_settings({"SCANNER_SITE": "dc-1", "FINDINGS_FILE": "/x"})
    assert err.value.code == "no_database"


# ------------------------------------------------------------------ the SQL engines


def pg_db(**grant_row: Any) -> Db:
    row = {
        "superuser": False,
        "createrole": False,
        "createdb": False,
        "database_create": False,
        "table_write": 0,
        "schema_create": 0,
        **grant_row,
    }
    db = Db(tables={("public", "people"): people(), ("hr", "empty"): []})
    return db.on(r"FROM pg_roles r", [row])


def test_postgresql_read_only_user_is_sampled_by_column() -> None:
    driver = Driver(pg_db())
    doc = scan(env(hr=f"postgresql://ro:{MADE_UP_PW}@db.internal:5432/app"), {"postgresql": driver})
    assert doc["platform"] == "database" and doc["site"] == "dc-1"
    assert "account" not in doc and "region" not in doc
    assert classes(doc) == {
        ("public.people", "card_number", "card"),
        ("public.people", "ssn", "us_ssn"),
    }
    f = doc["findings"][0]
    assert f["resource"]["type"] == "store_field"
    assert f["resource"]["service"] == "postgresql"
    assert f["resource"]["store"] == "hr"
    assert f["resource"]["database"] == "app"
    assert f["resource"]["readBy"] == "sample"
    assert f["format"] == "sql" and f["link"] is None and f["offsets"] == []
    s = stores(doc)["hr"]
    assert (s["kind"], s["status"], s["origin"]) == ("postgresql", "scanned", "config")
    cov = doc["coverage"][0]
    assert (cov["kind"], cov["listed"], cov["scanned"], cov["passComplete"]) == (
        "postgresql",
        2,
        2,
        True,
    )
    # The session is read-only, the transaction too, and it is rolled back.
    args, kwargs = driver.calls[0]
    assert args == (f"postgresql://ro:{MADE_UP_PW}@db.internal:5432/app",)
    assert "default_transaction_read_only=on" in kwargs["options"]
    assert "statement_timeout=60000" in kwargs["options"]
    assert "SET TRANSACTION READ ONLY" in driver.statements()
    assert driver.conns[0].rollbacks >= 2 and driver.conns[0].closed
    only_reads(driver)
    assert 'SELECT * FROM "public"."people" LIMIT 1000' in driver.statements()


@pytest.mark.parametrize(
    ("row", "write"),
    [
        ({"superuser": True}, ["superuser"]),
        ({"table_write": 3}, ["table_write"]),
        ({"schema_create": 1, "createdb": True}, ["createdb", "schema_create"]),
        ({"database_create": "t"}, ["database_create"]),
    ],
)
def test_postgresql_user_that_can_write_is_refused_before_any_read(
    row: dict[str, Any], write: list[str]
) -> None:
    driver = Driver(pg_db(**row))
    doc = scan(env(hr="postgresql://rw@db/app"), {"postgresql": driver})
    s = stores(doc)["hr"]
    assert (s["status"], s["reason"], s["writeGrants"]) == ("skipped", "db_user_can_write", write)
    assert doc["findings"] == [] and doc["coverage"] == []
    assert not any(s.startswith("SELECT *") for s in driver.statements())
    assert driver.conns[0].closed


def test_a_grant_check_that_cannot_run_refuses_the_store() -> None:
    db = Db(tables={("public", "people"): people()}).on(r"FROM pg_roles r", PermissionError("x"))
    driver = Driver(db)
    doc = scan(env(hr="postgresql://ro@db/app"), {"postgresql": driver})
    s = stores(doc)["hr"]
    assert (s["status"], s["reason"], s["error"]) == (
        "skipped",
        "grants_unverifiable",
        "PermissionError",
    )
    assert not any(s.startswith("SELECT *") for s in driver.statements())


def mysql_db(grants: list[str], version: str = "8.4.2") -> Db:
    db = Db(tables={("orders", "customers"): people()})
    db.on(r"^SELECT VERSION", [{"version": version}])
    db.on(r"^SHOW GRANTS FOR CURRENT_USER\(\)$", [{"Grants for ro@%": x} for x in grants])
    return db


def test_mysql_and_mariadb_read_only() -> None:
    driver = Driver(
        mysql_db(["GRANT USAGE ON *.* TO `ro`@`%`", "GRANT SELECT ON `orders`.* TO `ro`@`%`"])
    )
    maria = Driver(mysql_db(["GRANT SELECT ON *.* TO `ro`@`%`"], "11.4.2-MariaDB-log"))
    url = f"mysql://ro:{MADE_UP_PW}@10.1.2.3:3307/orders?ssl_ca=/etc/ca.pem&ssl_verify_cert=true"
    doc = scan(env(orders=url), {"mysql": driver})
    assert classes(doc) == {
        ("orders.customers", "card_number", "card"),
        ("orders.customers", "ssn", "us_ssn"),
    }
    kwargs = driver.calls[0][1]
    assert (kwargs["host"], kwargs["port"], kwargs["user"], kwargs["database"]) == (
        "10.1.2.3",
        3307,
        "ro",
        "orders",
    )
    assert kwargs["password"] == MADE_UP_PW
    assert kwargs["init_command"] == "SET SESSION TRANSACTION READ ONLY"
    assert kwargs["ssl_ca"] == "/etc/ca.pem" and kwargs["ssl_verify_cert"] is True
    assert "START TRANSACTION READ ONLY" in driver.statements()
    assert "SELECT * FROM `orders`.`customers` LIMIT 1000" in driver.statements()
    only_reads(driver)
    doc = scan(env(orders="mariadb://ro:pw@db/orders"), {"mysql": maria})
    s = stores(doc)["orders"]
    assert (s["kind"], s["engine"], s["status"]) == ("mysql", "mariadb", "scanned")


def test_mysql_without_a_database_is_not_read() -> None:
    doc = scan(env(orders="mysql://ro:pw@db"), {"mysql": Driver(mysql_db([]))})
    assert stores(doc)["orders"]["reason"] == "read_not_configured"


def test_mysql_grants_and_roles() -> None:
    write, roles = g.mysql_parse(
        [
            "GRANT USAGE ON *.* TO `u`@`%`",
            "GRANT SELECT (`a`, `b`), INSERT ON `db`.`t` TO `u`@`%`",
            "GRANT SELECT ON `db`.* TO `u`@`%` WITH GRANT OPTION",
            "GRANT BACKUP_ADMIN,SHOW_ROUTINE ON *.* TO `u`@`%`",
            "GRANT `r_ro`@`%`,`r_etl`@`%` TO `u`@`%`",
        ]
    )
    assert write == {"INSERT", "GRANT OPTION", "BACKUP_ADMIN", "SHOW_ROUTINE"}
    assert roles == ["`r_ro`@`%`", "`r_etl`@`%`"]

    # MySQL 8: the roles' privileges through USING.
    def mysql8(sql: str, params: Any) -> list[dict[str, Any]]:
        if sql.endswith("USING `r_ro`@`%`"):
            return [{"g": "GRANT SELECT ON `db`.* TO `u`@`%`"}]
        return [{"g": "GRANT USAGE ON *.* TO `u`@`%`"}, {"g": "GRANT `r_ro`@`%` TO `u`@`%`"}]

    assert g.mysql(mysql8).write == set()

    # MariaDB: no USING, so each role's own grants, and the roles it holds.
    def maria(sql: str, params: Any) -> list[dict[str, Any]]:
        if "USING" in sql:
            raise RuntimeError("syntax")
        if sql == "SHOW GRANTS FOR `r_ro`":
            return [{"g": "GRANT SELECT ON *.* TO `r_ro`"}, {"g": "GRANT `r_etl` TO `r_ro`"}]
        if sql == "SHOW GRANTS FOR `r_etl`":
            return [{"g": "GRANT INSERT, UPDATE ON `db`.* TO `r_etl`"}]
        return [{"g": "GRANT `r_ro` TO `u`@`%`"}]

    assert g.mysql(maria).write == {"INSERT", "UPDATE"}

    def hidden(sql: str, params: Any) -> list[dict[str, Any]]:
        if sql.startswith("SHOW GRANTS FOR CURRENT_USER()") and "USING" not in sql:
            return [{"g": "GRANT `r_ro` TO `u`@`%`"}]
        raise RuntimeError("denied")

    assert g.mysql(hidden).verified is False


def test_sqlserver_read_only_and_refused() -> None:
    db = Db(tables={("dbo", "people"): people()})
    db.on(
        r"IS_SRVROLEMEMBER", [{"sysadmin": 0, "db_owner": 0, "db_datawriter": 0, "db_ddladmin": 0}]
    )
    db.on(
        r"fn_my_permissions",
        [{"permission_name": p} for p in ("CONNECT", "SELECT", "VIEW DEFINITION")],
    )
    db.on(r"HAS_PERMS_BY_NAME", [{"objects": 0}])
    driver = Driver(db)
    doc = scan(
        env(crm=f"sqlserver://ro:{MADE_UP_PW}@sql.internal:1433/crm?encryption=require"),
        {"sqlserver": driver},
    )
    assert classes(doc) == {("dbo.people", "card_number", "card"), ("dbo.people", "ssn", "us_ssn")}
    kwargs = driver.calls[0][1]
    assert (kwargs["server"], kwargs["port"], kwargs["database"], kwargs["encryption"]) == (
        "sql.internal",
        "1433",
        "crm",
        "require",
    )
    assert "SELECT TOP (1000) * FROM [dbo].[people]" in driver.statements()
    only_reads(driver)

    rw = Db(tables={("dbo", "people"): people()})
    rw.on(
        r"IS_SRVROLEMEMBER", [{"sysadmin": 0, "db_owner": 1, "db_datawriter": 1, "db_ddladmin": 0}]
    )
    rw.on(
        r"fn_my_permissions",
        [{"permission_name": p} for p in ("CONNECT", "INSERT", "CREATE TABLE")],
    )
    rw.on(r"HAS_PERMS_BY_NAME", [{"objects": 4}])
    doc = scan(env(crm="mssql://rw@sql/crm"), {"sqlserver": Driver(rw)})
    assert stores(doc)["crm"]["writeGrants"] == [
        "CREATE TABLE",
        "INSERT",
        "db_datawriter",
        "db_owner",
        "table_write",
    ]


def test_oracle_read_only_and_refused() -> None:
    db = Db(tables={("HR", "PEOPLE"): people()})
    db.on(
        r"FROM session_privs", [{"PRIVILEGE": "CREATE SESSION"}, {"PRIVILEGE": "SELECT ANY TABLE"}]
    )
    db.on(r"FROM all_tab_privs", [{"OBJECTS": 0}])
    db.on(r"FROM user_tables", [{"TABLES": 0}])
    driver = Driver(db)
    doc = scan(env(erp=f"oracle://ro:{MADE_UP_PW}@ora.internal:1521/ERP"), {"oracle": driver})
    assert classes(doc) == {("HR.PEOPLE", "card_number", "card"), ("HR.PEOPLE", "ssn", "us_ssn")}
    kwargs = driver.calls[0][1]
    assert (kwargs["host"], kwargs["port"], kwargs["service_name"]) == ("ora.internal", 1521, "ERP")
    assert driver.conns[0].call_timeout == 60_000
    statements = driver.statements()
    assert statements.index("SET TRANSACTION READ ONLY") < statements.index(
        'SELECT * FROM "HR"."PEOPLE" FETCH FIRST 1000 ROWS ONLY'
    )
    only_reads(driver)
    assert g.oracle(
        lambda sql, p: (
            [{"PRIVILEGE": "CREATE TABLE"}]
            if "session_privs" in sql
            else [{"OBJECTS": 2}]
            if "all_tab_privs" in sql
            else [{"TABLES": 1}]
        )
    ).write == {"CREATE TABLE", "object_write", "owns_tables"}


def test_snowflake_roles_are_followed() -> None:
    grants = {
        '"ANALYST"': [
            {"privilege": "USAGE", "granted_on": "DATABASE", "name": "APP"},
            {"privilege": "USAGE", "granted_on": "ROLE", "name": "READER"},
        ],
        '"READER"': [{"privilege": "SELECT", "granted_on": "TABLE", "name": "APP.PUBLIC.PEOPLE"}],
        '"LOADER"': [{"privilege": "INSERT", "granted_on": "TABLE", "name": "APP.PUBLIC.PEOPLE"}],
        '"SYSADMIN"': [],
    }

    def execute(role_of_user: list[str]) -> Any:
        def ex(sql: str, params: Any) -> list[dict[str, Any]]:
            if sql.startswith("SELECT CURRENT_ROLE()"):
                return [{"ROLE": "ANALYST", "NAME": "SCANNER"}]
            if sql == 'SHOW GRANTS TO USER "SCANNER"':
                return [{"role": r} for r in role_of_user]
            return grants[sql.removeprefix("SHOW GRANTS TO ROLE ")]

        return ex

    assert g.snowflake(execute(["ANALYST"])).write == set()
    assert g.snowflake(execute(["ANALYST", "LOADER"])).write == {"INSERT"}
    assert g.snowflake(execute(["SYSADMIN"])).write == {"SYSADMIN"}


def test_snowflake_and_databricks_are_sampled() -> None:
    sf = Db(tables={("PUBLIC", "PEOPLE"): people()})
    sf.on(r"CURRENT_ROLE", [{"ROLE": "READER", "NAME": "SCANNER"}])
    sf.on(r"SHOW GRANTS TO USER", [{"role": "READER"}])
    sf.on(r"SHOW GRANTS TO ROLE", [{"privilege": "SELECT", "granted_on": "TABLE", "name": "T"}])
    driver = Driver(sf)
    url = f"snowflake://scanner:{MADE_UP_PW}@xy12345.us-east-1/APP?warehouse=SCAN_WH&role=READER"
    doc = scan(env(dw=url), {"snowflake": driver})
    assert ("PUBLIC.PEOPLE", "card_number", "card") in classes(doc)
    kwargs = driver.calls[0][1]
    assert (kwargs["account"], kwargs["database"], kwargs["warehouse"], kwargs["role"]) == (
        "xy12345.us-east-1",
        "APP",
        "SCAN_WH",
        "READER",
    )
    assert kwargs["session_parameters"]["STATEMENT_TIMEOUT_IN_SECONDS"] == 60
    only_reads(driver)

    dbx = Db(tables={("default", "people"): people()})
    dbx.on(r"_privileges", [{"privilege_type": "USE_CATALOG"}, {"privilege_type": "SELECT"}])
    dbx.on(r"_owner", [{"owned": 0}])
    driver = Driver(dbx)
    url = "databricks://token:dapi-made-up@adb-1.azuredatabricks.net/sql/1.0/warehouses/abc?catalog=main"
    doc = scan(env(lake=url), {"databricks": driver})
    assert ("default.people", "ssn", "us_ssn") in classes(doc)
    kwargs = driver.calls[0][1]
    assert (kwargs["server_hostname"], kwargs["http_path"], kwargs["catalog"]) == (
        "adb-1.azuredatabricks.net",
        "/sql/1.0/warehouses/abc",
        "main",
    )
    assert "SELECT * FROM `default`.`people` LIMIT 1000" in driver.statements()
    rw = Db().on(r"_privileges", [{"privilege_type": "MODIFY"}]).on(r"_owner", [{"owned": 1}])
    doc = scan(env(lake=url), {"databricks": Driver(rw)})
    assert stores(doc)["lake"]["writeGrants"] == ["MODIFY", "owner"]


# ------------------------------------------------------------------ MongoDB


def test_mongodb_collections_are_sampled_and_ids_dropped() -> None:
    orders = Collection(
        [
            {
                "_id": object(),
                "customer": {"card": CARDS["amex"], "name": "x"},
                "ssn": dashed(SSN_A),
            },
            {"_id": object(), "customer": {"card": "none"}, "tags": ["a"]},
        ]
    )
    client = MongoClient(
        {"shop": MongoDb({"orders": orders, "system.views": Collection([])})},
        read_only_mongo_status(),
    )
    driver = MongoDriver(client)
    doc = scan(
        env(atlas=f"mongodb+srv://ro:{MADE_UP_PW}@cluster0.example.net/?retryWrites=true"),
        {"mongodb": driver},
    )
    assert classes(doc) == {("shop.orders", "customer", "card"), ("shop.orders", "ssn", "us_ssn")}
    assert doc["findings"][0]["format"] == "json"
    assert orders.pipelines == [[{"$sample": {"size": 1000}}]]
    assert driver.calls[0][1]["readPreference"] == "secondaryPreferred"
    assert client.closed
    # A database in the URL is the only one read.
    client2 = MongoClient(
        {"shop": MongoDb({"orders": orders}), "other": MongoDb({"x": Collection([])})},
        read_only_mongo_status(),
    )
    doc = scan(
        env(m="mongodb://ro:pw@h1:27017,h2:27017/shop?replicaSet=rs0"),
        {"mongodb": MongoDriver(client2)},
    )
    assert doc["coverage"][0]["listed"] == 1


def test_mongodb_without_access_control_or_with_write_actions_is_refused() -> None:
    open_status: dict[str, Any] = {
        "authInfo": {"authenticatedUsers": [], "authenticatedUserPrivileges": []}
    }
    doc = scan(env(m="mongodb://h/app"), {"mongodb": MongoDriver(MongoClient({}, open_status))})
    assert stores(doc)["m"]["writeGrants"] == ["no_authentication"]
    rw = read_only_mongo_status()
    rw["authInfo"]["authenticatedUserPrivileges"].append(
        {"resource": {"db": "app", "collection": ""}, "actions": ["insert", "update", "find"]}
    )
    doc = scan(env(m="mongodb://ro@h/app"), {"mongodb": MongoDriver(MongoClient({}, rw))})
    assert stores(doc)["m"]["writeGrants"] == ["insert", "update"]


# ------------------------------------------------------------------ the run


def test_rules_missing_drivers_connection_errors_and_the_budget() -> None:
    e = env(
        a="postgresql://ro@db/app",
        b="oracle://ro@ora/ERP",
        c="postgresql://ro@down/app",
        d="postgresql://ro@db/app",
    )
    e["DISCOVER_DENY"] = "d"
    good = Driver(pg_db())
    drivers: dict[str, Any] = {"postgresql": good, "oracle": None}
    doc = scan(e, drivers)
    s = stores(doc)
    assert (s["a"]["status"], s["b"]["reason"], s["d"]["reason"]) == (
        "scanned",
        "driver_missing",
        "denied",
    )
    # c connects through the same fake: make the next connect fail and run again.
    good.fail = ConnectionRefusedError("refused")
    doc = scan(env(c="postgresql://ro@down/app"), {"postgresql": good})
    assert (
        stores(doc)["c"]["status"] == "error"
        and stores(doc)["c"]["error"] == "ConnectionRefusedError"
    )
    # One table per run: the second database is deferred.
    e = env(a="postgresql://ro@db/app", z="postgresql://ro@db/app")
    e["MAX_ITEMS_PER_RUN"] = "1"
    doc = scan(e, {"postgresql": Driver(pg_db())})
    s = stores(doc)
    assert s["a"]["backlog"] is True
    assert (s["z"]["status"], s["z"]["reason"]) == ("deferred", "budget")


def test_a_table_that_cannot_be_read_is_counted_and_an_empty_database_is_no_grant() -> None:
    db = pg_db()
    db.unreadable.add(("hr", "empty"))
    doc = scan(env(a="postgresql://ro@db/app"), {"postgresql": Driver(db)})
    assert doc["coverage"][0]["unreadable"] == 1 and doc["coverage"][0]["scanned"] == 1
    empty = Db().on(r"FROM pg_roles r", pg_db().catalog[0][1])
    doc = scan(env(a="postgresql://ro@db/app"), {"postgresql": Driver(empty)})
    assert (stores(doc)["a"]["status"], stores(doc)["a"]["reason"]) == ("skipped", "no_grant")


def test_the_new_dialects_quote_and_cap() -> None:
    assert sample_sql(SQLSERVER, "dbo", "a]b", 5) == "SELECT TOP (5) * FROM [dbo].[a]]b]"
    assert sample_sql(ORACLE, "HR", 'a"b', 5) == 'SELECT * FROM "HR"."a""b" FETCH FIRST 5 ROWS ONLY'
    assert sample_sql(SNOWFLAKE, "S", "T", 5) == 'SELECT * FROM "S"."T" LIMIT 5'
    assert sample_sql(DATABRICKS, "s", "a`b", 5) == "SELECT * FROM `s`.`a``b` LIMIT 5"
    sql, params = tables_sql(ORACLE, ("HR",))
    assert "t.owner IN (:s0)" in sql and params == [("s0", "HR")]
    assert "oracle_maintained = 'N'" in tables_sql(ORACLE, ())[0]
    assert "table_type IN ('MANAGED', 'EXTERNAL')" in tables_sql(DATABRICKS, ())[0]
    assert "table_schema NOT IN ('sys', 'INFORMATION_SCHEMA')" in tables_sql(SQLSERVER, ())[0]
    assert re.search(r"%\(s0\)s", tables_sql(SNOWFLAKE, ("PUBLIC",))[0])
