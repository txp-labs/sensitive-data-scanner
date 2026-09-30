"""Tables (#67 part 3): a database table unchanged since its last read is skipped by its
engine's change marker, DynamoDB reads only what changed through incremental exports, and
the rescan rules apply to tables. Every value is made up."""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from botocore.stub import ANY

from aws_fixtures import RESULTS, Env, config
from db_fakes import Driver
from sensitive_data_core.adapter import Budget
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.index import (
    READER,
    SPEC_STANDALONE,
    Indexes,
    MemoryBackend,
    ObjectPass,
)
from sensitive_data_core.scan.sql import (
    DATABRICKS,
    MYSQL,
    ORACLE,
    POSTGRESQL,
    REDSHIFT,
    SNOWFLAKE,
    SPANNER,
    SQLSERVER,
    markers_sql,
    sample_tables,
    table_markers,
)
from synthetic import CARDS, SSN_A, SSN_B, dashed
from test_rescans import bumped, use

NOW = dt.datetime(2026, 9, 29, 12, 0, tzinfo=dt.UTC)
DETECTOR = Detector(load_spec(), NOW.date())
SALT = "0" * 32


# ------------------------------------------------------------------ the change markers


def test_each_engine_asks_its_catalog_and_never_inlines_a_schema() -> None:
    for dialect in (POSTGRESQL, MYSQL, SQLSERVER, ORACLE, SNOWFLAKE, DATABRICKS):
        got = markers_sql(dialect, ("sales", "x'; DROP TABLE y; --"))
        assert got is not None, dialect.name
        sql, params = got
        assert "DROP" not in sql and sql.lstrip().upper().startswith("SELECT")
        assert all(v in ("sales", "x'; DROP TABLE y; --") for _, v in params)
    assert "pg_stat_user_tables" in str(markers_sql(POSTGRESQL, ()))
    assert "NOT pg_is_in_recovery()" in str(markers_sql(POSTGRESQL, ()))  # a replica: none
    assert "update_time" in str(markers_sql(MYSQL, ()))
    assert "last_user_update" in str(markers_sql(SQLSERVER, ()))
    assert "all_tab_modifications" in str(markers_sql(ORACLE, ()))
    assert "last_altered" in str(markers_sql(SNOWFLAKE, ()))
    for none in (REDSHIFT, SPANNER):
        assert markers_sql(none, ()) is None


def test_markers_are_text_of_counters_and_times_by_table() -> None:
    rows: list[dict[str, Any]] = [
        {"TABLE_SCHEMA": "PUBLIC", "TABLE_NAME": "ORDERS", "LAST_ALTERED": "2026-09-29 10:00"},
        {"table_schema": "hr", "table_name": "people", "n_tup_ins": 3, "last_analyze": None},
        {"table_schema": "hr", "table_name": "unknown", "update_time": None},
    ]
    got = table_markers(lambda sql, params: rows, SNOWFLAKE, ())
    assert got == {
        ("PUBLIC", "ORDERS"): "last_altered=2026-09-29 10:00",
        ("hr", "people"): "last_analyze=None|n_tup_ins=3",
    }

    def refuse(sql: str, params: Any) -> list[dict[str, Any]]:
        raise PermissionError("no VIEW SERVER STATE")

    assert table_markers(refuse, SQLSERVER, ()) is None  # sampled, as before
    assert table_markers(lambda s, p: rows, REDSHIFT, ()) is None


# ------------------------------------------------------------------ the sampled pass


class Catalog:
    """A database for `sample_tables`: tables, their markers, and every statement sent."""

    def __init__(self) -> None:
        self.tables: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("public", "people"): [{"card_number": CARDS["visa"], "ssn": dashed(SSN_A)}],
            ("public", "notes"): [{"note": "nothing here"}],
            ("hr", "staff"): [{"ssn": dashed(SSN_B)}],
        }
        self.markers: dict[tuple[str, str], int] = dict.fromkeys(self.tables, 1)
        self.sampled: list[tuple[str, str]] = []

    def execute(self, sql: str, params: Any) -> list[dict[str, Any]]:
        if "pg_stat_user_tables" in sql:
            return [
                {"table_schema": s, "table_name": t, "n_tup_ins": n}
                for (s, t), n in self.markers.items()
            ]
        if "information_schema.tables" in sql:
            return [{"table_schema": s, "table_name": t} for s, t in self.tables]
        for (s, t), rows in self.tables.items():
            if f'"{s}"."{t}"' in sql:
                self.sampled.append((s, t))
                return rows
        raise AssertionError(sql[:60])


def sample(db: Catalog, op: ObjectPass) -> tuple[Any, dict[tuple[str, str], Any]]:
    got: dict[tuple[str, str], Any] = {}
    budget = Budget(1000, 10**9, float("inf"))
    sp = sample_tables(
        db.execute,
        POSTGRESQL,
        detector=DETECTOR,
        has_room=budget.has,
        take=budget.take,
        on_table=lambda s, t, r: got.__setitem__((s, t), r),
        after=None,
        index=op,
    )
    return sp, got


def passes(backend: MemoryBackend, day: int, manifest: Any = None) -> tuple[Indexes, ObjectPass]:
    idx = Indexes(backend, SALT, manifest=manifest)
    budget = Budget(1000, 10**9, float("inf"))
    return idx, ObjectPass(idx, "pg:app", "postgresql", generation=day, budget=budget)


def test_an_unchanged_table_is_skipped_and_a_changed_one_read() -> None:
    db, backend = Catalog(), MemoryBackend()
    idx, op = passes(backend, 20_000)
    sp, _ = sample(db, op)  # a fresh index: no markers asked, every table read
    assert (sp.scanned, sp.markers) == (3, False)
    idx.save()
    idx, op = passes(backend, 20_001)
    db.sampled.clear()
    sp, _ = sample(db, op)  # the markers are recorded now
    assert (sp.scanned, sp.markers) == (3, True)
    idx.save()
    idx, op = passes(backend, 20_002)
    db.sampled.clear()
    sp, _ = sample(db, op)
    assert (sp.scanned, sp.unchanged, sp.eligible, sp.listed) == (0, 3, 0, 3)
    assert db.sampled == []
    idx.save()
    db.markers[("hr", "staff")] += 1  # one table written to
    idx, op = passes(backend, 20_003)
    sp, _ = sample(db, op)
    assert db.sampled == [("hr", "staff")] and sp.unchanged == 2
    idx.save()
    # A table unknown to the engine's counters is sampled every pass.
    del db.markers[("public", "notes")]
    db.sampled.clear()
    idx, op = passes(backend, 20_004)
    sample(db, op)
    assert db.sampled == [("public", "notes")]
    idx.save()
    # And every table is sampled again after TABLE_RESAMPLE_DAYS, whatever its marker says.
    db.sampled.clear()
    idx, op = passes(backend, 20_012)
    sample(db, op)
    assert sorted(db.sampled) == sorted(db.tables)


def test_the_rescan_rules_apply_to_tables() -> None:
    db, backend = Catalog(), MemoryBackend()
    for day in (20_000, 20_001):
        idx, op = passes(backend, day)
        sample(db, op)
        idx.save()
    db.sampled.clear()
    idx, op = passes(backend, 20_002, bumped(add={"spec-standalone/passport": "c" * 12}))
    sp, got = sample(db, op)
    assert len(db.sampled) == 3 and sp.unchanged == 0
    assert op.rescans.done == {SPEC_STANDALONE: 3}
    assert got[("public", "people")].rescan == {
        "rescanReason": SPEC_STANDALONE,
        "rescanClasses": ["passport"],
    }
    idx.save()
    # A reader for objects says nothing of tables: nothing is read again.
    db.sampled.clear()
    idx, op = passes(backend, 20_003, bumped(add={"spec-standalone/passport": "c" * 12}))
    sample(db, op)
    idx.save()
    idx, op = passes(
        backend, 20_003, bumped("reader:pdf", add={"spec-standalone/passport": "c" * 12})
    )
    sample(db, op)
    assert db.sampled == []
    # The SQL reader changed: every table, within the rescan share (a quarter of 4 items).
    manifest = bumped("reader:sql", add={"spec-standalone/passport": "c" * 12})
    idx2 = Indexes(backend, SALT, manifest=manifest)
    op2 = ObjectPass(
        idx2, "pg:app", "postgresql", generation=20_003, budget=Budget(4, 10**9, float("inf"))
    )
    sp, _ = sample(db, op2)
    assert op2.rescans.done == {READER: 1} and op2.rescans.left == {READER: 2}
    assert len(db.sampled) == 1


# ------------------------------------------------------------------ the databases runner


def test_the_databases_runner_skips_unchanged_tables_and_keeps_their_findings(
    tmp_path: Path,
) -> None:
    from sensitive_data_db.config import read_settings
    from sensitive_data_db.runner import run
    from sensitive_data_db.state import FileState
    from test_db_runner import Sink, env, pg_db

    db = pg_db()
    counters = {("public", "people"): 5, ("hr", "empty"): 0}

    def markers() -> list[dict[str, Any]]:
        return [
            {"table_schema": s, "table_name": t, "n_tup_ins": n} for (s, t), n in counters.items()
        ]

    db.catalog.insert(0, (__import__("re").compile("pg_stat_user_tables"), []))
    e = env(app="postgresql://ro@db.internal/app")
    e["STATE_LOCATION"] = str(tmp_path / "state.json")
    settings = read_settings(e)
    state = FileState(str(tmp_path / "state.json"))

    def once(day: int) -> tuple[dict[str, Any], list[str]]:
        db.catalog[0] = (db.catalog[0][0], markers())
        driver = Driver(db)
        doc, failed = run(
            settings,
            [Sink()],
            drivers={"postgresql": driver},
            detector=DETECTOR,
            now=lambda: NOW + dt.timedelta(days=day),
            state=state,
        )
        assert failed == 0
        return doc, [s for s in driver.statements() if s.startswith("SELECT * FROM")]

    first, _ = once(0)
    once(1)  # the markers are recorded
    third, sampled = once(2)
    assert sampled == []
    assert {f["id"] for f in third["findings"]} == {f["id"] for f in first["findings"]}
    assert third["findings"]
    cov = third["coverage"][0]
    assert (cov["listed"], cov["eligible"], cov["scanned"], cov["indexed"]) == (2, 0, 0, 2)
    counters[("public", "people")] += 1
    fourth, sampled = once(3)
    assert sampled == ['SELECT * FROM "public"."people" LIMIT 1000']
    assert {f["id"] for f in fourth["findings"]} == {f["id"] for f in first["findings"]}
    assert (tmp_path / "state.json.index" / "findings.json.gz").exists()


# ------------------------------------------------------------------ DynamoDB


def test_dynamodb_reads_only_what_changed_with_incremental_exports(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ddb_fixtures import Ddb, describe
    from test_exports import TABLE_ARN, ddb_estate, exports_left

    ddb = Ddb()
    env.clients.dynamodb = ddb.client
    cfg = config(s3_targets=[], discover=frozenset({"dynamodb"}), dynamodb_export=True)
    digest = hashlib.sha256(TABLE_ARN.encode()).hexdigest()[:12]
    prefix = f"exports/dynamodb/{digest}"
    t0 = NOW

    def start(kind: str, **spec: Any) -> None:
        expected: dict[str, Any] = {
            "TableArn": TABLE_ARN,
            "S3Bucket": RESULTS,
            "S3Prefix": prefix,
            "ExportFormat": "DYNAMODB_JSON",
            "ExportType": kind,
            "ClientToken": ANY,
            "S3SseAlgorithm": "AES256",
        }
        expected.update(spec)
        ddb.stub.add_response(
            "export_table_to_point_in_time",
            {"ExportDescription": {"ExportArn": f"{TABLE_ARN}/export/{kind}"}},
            expected,
        )

    def finish(export_id: str, lines: list[dict[str, Any]], at: dt.datetime | None) -> None:
        base = f"{prefix}/AWSDynamoDB/{export_id}/"
        body = gzip.compress("\n".join(json.dumps(x) for x in lines).encode())
        env.clients.s3.put_object(Bucket=RESULTS, Key=f"{base}data/a.json.gz", Body=body)
        env.clients.s3.put_object(Bucket=RESULTS, Key=f"{base}manifest-summary.json", Body=b"{}")
        desc: dict[str, Any] = {
            "ExportStatus": "COMPLETED",
            "ExportManifest": f"{base}manifest-summary.json",
        }
        if at is not None:
            desc["ExportTime"] = at
        ddb.stub.add_response("describe_export", {"ExportDescription": desc})
        ddb.stub.add_response("describe_table", describe("events", sort_key=False))

    def run(at: dt.datetime, *then: Any) -> dict[str, Any]:
        """One run at `at`: discovery's calls, then the export's (queued in call order)."""
        ddb_estate(ddb)
        for queue in then:
            queue()
        doc = env.run(cfg, now=lambda: at)
        assert doc is not None
        ddb.stub.assert_no_pending_responses()
        return doc

    # A full export, read: the table's baseline.
    run(t0, lambda: start("FULL_EXPORT"))
    card_item = {"pk": {"S": "C#1"}, "note": {"S": f"card {CARDS['visa']}"}}
    plain = {"pk": {"S": "C#2"}, "note": {"S": "hi"}}
    first = run(
        t0 + dt.timedelta(minutes=30),
        lambda: finish("full-1", [{"Item": card_item}, {"Item": plain}], t0),
    )
    assert {f["resource"]["key"]["pk"] for f in first["findings"]} == {"C#1"}
    # A day later: only what was written since, as an incremental export.
    window = {
        "ExportFromTime": t0,
        "ExportToTime": t0 + dt.timedelta(hours=24),
        "ExportViewType": "NEW_IMAGE",
    }
    pending = run(
        t0 + dt.timedelta(days=1, hours=1),
        lambda: start("INCREMENTAL_EXPORT", IncrementalExportSpecification=window),
    )
    events = next(s for s in pending["discovery"]["stores"] if s["name"] == "events")
    assert events["exportType"] == "incremental"
    changed = [
        {"Keys": {"pk": {"S": "C#1"}}},  # deleted in the window: its findings go
        {
            "Keys": {"pk": {"S": "C#2"}},
            "NewImage": {"pk": {"S": "C#2"}, "note": {"S": f"ssn {dashed(SSN_A)}"}},
        },
    ]
    second = run(t0 + dt.timedelta(days=1, hours=2), lambda: finish("incr-1", changed, None))
    assert {(f["resource"]["key"]["pk"], f["class"]) for f in second["findings"]} == {
        ("C#2", "us_ssn")
    }
    assert exports_left(env) == []
    # The attribute reader changed: the next export is a full one, a rescan.
    use(monkeypatch, bumped("reader:attributes"))
    run(t0 + dt.timedelta(days=2), lambda: start("FULL_EXPORT"))
    item = {"pk": {"S": "C#2"}, "note": {"S": f"ssn {dashed(SSN_A)}"}}
    third = run(
        t0 + dt.timedelta(days=2, hours=1),
        lambda: finish("full-2", [{"Item": item}], t0 + dt.timedelta(days=2)),
    )
    assert third["findings"] and all(f["rescanReason"] == READER for f in third["findings"])
    cov = next(c for c in third["coverage"] if c["kind"] == "dynamodb")
    assert cov["rescanned"] == {READER: 1}


# ------------------------------------------------------------------ BigQuery


def test_bigquery_rereads_an_unchanged_table_only_for_a_component_that_could_change_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_gcp_bigquery import cloud, run

    c, bq = cloud()
    run(c)
    run(c)
    calls = len(bq.data_calls)
    use(monkeypatch, bumped("reader:pdf"))
    run(c)
    assert len(bq.data_calls) == calls  # a PDF reader reads no table
    use(monkeypatch, bumped("spec-standalone/card"))
    doc = run(c)
    assert len(bq.data_calls) > calls
    rescanned = [f for f in doc["findings"] if f.get("rescanReason")]
    assert rescanned and all(f["rescanClasses"] == ["card"] for f in rescanned)
