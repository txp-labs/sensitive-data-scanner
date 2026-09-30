"""The databases runner against real PostgreSQL and MySQL, in containers (testcontainers).

A database is created as its admin, with made-up values in cells and in
schema, table and column names; then read-only users, a user that can
write, and a user that is read-only through a role. The runner must read
the first kind, refuse the second, and leave the data as it was.

These need Docker. Without it they are skipped, unless `SDS_REQUIRE_DOCKER=1`
(set in CI), when a missing Docker is a failure.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from sensitive_data_db.config import read_settings
from sensitive_data_db.runner import run
from synthetic import CARDS, SSN_A, SSN_B, dashed

# Pinned by digest, so a test run is reproducible.
POSTGRES = (
    "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
)
MYSQL = "mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"
ADMIN_PW = "Made-up-admin-pw-1"
USER_PW = "Made-up-user-pw-2"


def _docker() -> bool:
    try:
        import docker

        docker.from_env().ping()
    except Exception:
        return False
    return True


if not _docker():
    if os.environ.get("SDS_REQUIRE_DOCKER") == "1":
        raise RuntimeError("SDS_REQUIRE_DOCKER=1 and Docker is not reachable")
    pytest.skip("Docker is not available", allow_module_level=True)

from testcontainers.core.container import DockerContainer  # noqa: E402


class Sink:
    def __init__(self) -> None:
        self.doc: dict[str, Any] = {}

    def push(self, document: dict[str, Any]) -> int:
        self.doc = document
        return 1


def _wait(connect: Callable[[], Any], seconds: int = 120) -> Any:
    deadline = time.monotonic() + seconds
    while True:
        try:
            return connect()
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def _run(urls: dict[str, str]) -> dict[str, Any]:
    env = {"SCANNER_SITE": "ci", "FINDINGS_FILE": "/dev/null"}
    env.update({f"DATABASE_URL_{k.upper()}": v for k, v in urls.items()})
    sink = Sink()
    run(read_settings(env), [sink])
    doc = sink.doc
    for secret in (ADMIN_PW, USER_PW, SSN_A, SSN_B, *CARDS.values()):
        assert secret not in json.dumps(doc)
    doc["_stores"] = {s["name"]: s for s in doc["discovery"]["stores"]}
    return doc


TABLE = f"staff_{SSN_B}"
COLUMN = f"ssn_{SSN_A}"


@pytest.fixture(scope="module")
def postgres() -> Iterator[tuple[str, int]]:
    import psycopg

    with (
        DockerContainer(POSTGRES)
        .with_env("POSTGRES_PASSWORD", ADMIN_PW)
        .with_exposed_ports(5432) as c
    ):
        host, port = c.get_container_host_ip(), int(c.get_exposed_port(5432))
        admin = f"postgresql://postgres:{ADMIN_PW}@{host}:{port}/postgres"
        conn = _wait(lambda: psycopg.connect(admin, autocommit=True, connect_timeout=5))
        with conn:
            for sql in (
                "CREATE SCHEMA hr",
                f'CREATE TABLE hr."{TABLE}" (id int, card_number text, "{COLUMN}" text, note text)',
                f"INSERT INTO hr.\"{TABLE}\" VALUES (1, '{CARDS['visa']}', '{dashed(SSN_A)}', 'x'),"
                f" (2, '{CARDS['amex']}', '{dashed(SSN_B)}', 'y')",
                f"CREATE ROLE scanner_ro LOGIN PASSWORD '{USER_PW}'",
                "GRANT USAGE ON SCHEMA hr TO scanner_ro",
                "GRANT SELECT ON ALL TABLES IN SCHEMA hr TO scanner_ro",
                f"CREATE ROLE writer LOGIN PASSWORD '{USER_PW}'",
                "GRANT USAGE ON SCHEMA hr TO writer",
                "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA hr TO writer",
            ):
                conn.execute(sql)
        yield host, port


def test_postgresql_reads_a_read_only_user_and_refuses_writers(postgres: tuple[str, int]) -> None:
    import psycopg

    host, port = postgres
    doc = _run(
        {
            "ro": f"postgresql://scanner_ro:{USER_PW}@{host}:{port}/postgres",
            "writer": f"postgresql://writer:{USER_PW}@{host}:{port}/postgres",
            "admin": f"postgresql://postgres:{ADMIN_PW}@{host}:{port}/postgres",
        }
    )
    stores = doc["_stores"]
    assert stores["ro"]["status"] == "scanned"
    found = {(f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert ("card_number", "card") in found
    assert any(cls == "us_ssn" and field.startswith("ssn_") for field, cls in found)
    assert all(f["resource"]["table"] == "hr.staff_#########" for f in doc["findings"])
    assert (stores["writer"]["reason"], stores["writer"]["writeGrants"]) == (
        "db_user_can_write",
        ["table_write"],
    )
    assert stores["admin"]["reason"] == "db_user_can_write"
    assert "superuser" in stores["admin"]["writeGrants"]
    admin = f"postgresql://postgres:{ADMIN_PW}@{host}:{port}/postgres"
    with psycopg.connect(admin) as conn:
        count = conn.execute(f'SELECT count(*) FROM hr."{TABLE}"').fetchone()
    assert count == (2,)


@pytest.fixture(scope="module")
def mysql() -> Iterator[tuple[str, int]]:
    import pymysql

    with (
        DockerContainer(MYSQL)
        .with_env("MYSQL_ROOT_PASSWORD", ADMIN_PW)
        .with_exposed_ports(3306) as c
    ):
        host, port = c.get_container_host_ip(), int(c.get_exposed_port(3306))
        conn = _wait(
            lambda: pymysql.connect(
                host=host, port=port, user="root", password=ADMIN_PW, connect_timeout=5
            ),
            180,
        )
        with conn.cursor() as cur:
            for sql in (
                "CREATE DATABASE app",
                f"CREATE TABLE app.`{TABLE}` (id int, card_number text, `{COLUMN}` text)",
                f"INSERT INTO app.`{TABLE}` VALUES (1, '{CARDS['visa']}', '{dashed(SSN_A)}'),"
                f" (2, '{CARDS['amex']}', '{dashed(SSN_B)}')",
                f"CREATE USER 'ro'@'%' IDENTIFIED BY '{USER_PW}'",
                "GRANT SELECT ON app.* TO 'ro'@'%'",
                f"CREATE USER 'rw'@'%' IDENTIFIED BY '{USER_PW}'",
                "GRANT SELECT, INSERT ON app.* TO 'rw'@'%'",
                "CREATE ROLE 'reader', 'loader'",
                "GRANT SELECT ON app.* TO 'reader'",
                "GRANT SELECT, UPDATE ON app.* TO 'loader'",
                f"CREATE USER 'via_role'@'%' IDENTIFIED BY '{USER_PW}'",
                "GRANT 'reader' TO 'via_role'@'%'",
                "SET DEFAULT ROLE ALL TO 'via_role'@'%'",
                f"CREATE USER 'via_loader'@'%' IDENTIFIED BY '{USER_PW}'",
                "GRANT 'reader', 'loader' TO 'via_loader'@'%'",
                "SET DEFAULT ROLE 'reader' TO 'via_loader'@'%'",
            ):
                cur.execute(sql)
        conn.commit()
        conn.close()
        yield host, port


def test_mysql_reads_read_only_users_and_refuses_writers_and_their_roles(
    mysql: tuple[str, int],
) -> None:
    import pymysql

    host, port = mysql
    doc = _run(
        {
            "ro": f"mysql://ro:{USER_PW}@{host}:{port}/app",
            "via_role": f"mysql://via_role:{USER_PW}@{host}:{port}/app",
            "rw": f"mysql://rw:{USER_PW}@{host}:{port}/app",
            # The loader role is not active by default, but the user can SET ROLE it.
            "via_loader": f"mysql://via_loader:{USER_PW}@{host}:{port}/app",
            "root": f"mysql://root:{ADMIN_PW}@{host}:{port}/app",
        }
    )
    stores = doc["_stores"]
    assert (stores["ro"]["status"], stores["via_role"]["status"]) == ("scanned", "scanned")
    found = {(f["resource"]["store"], f["class"]) for f in doc["findings"]}
    assert {("ro", "card"), ("ro", "us_ssn"), ("via_role", "card")} <= found
    assert stores["rw"]["writeGrants"] == ["INSERT"]
    assert stores["via_loader"]["writeGrants"] == ["UPDATE"]
    assert stores["root"]["reason"] == "db_user_can_write"
    conn = pymysql.connect(host=host, port=port, user="root", password=ADMIN_PW, database="app")
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM `{TABLE}`")
        assert cur.fetchone() == (2,)
    conn.close()
