"""One run of the databases runner: every configured database, checked, sampled, reported.

For each database, in the order configured:

1. the allow and deny rules (`DISCOVER_ALLOW`, `DISCOVER_DENY`) decide it;
2. its engine's driver must be installed (else `driver_missing`);
3. it is connected to, and **the user's privileges are checked first**: a user
   that can write is refused (`db_user_can_write`, with the privileges by
   name), and one whose privileges cannot be read is refused too
   (`grants_unverifiable`);
4. its tables (or collections) are sampled within the run's budget, and each
   column with sensitive data becomes a `store_field` finding;
5. a store the budget does not reach is `deferred` (`budget`).

The findings document names the site (`SCANNER_SITE`), not an account, and
its run summary lists every database, read or not, and why. It goes to every
configured sink. With `STATE_LOCATION` (state.py), a run starts with the database
the previous run's budget did not reach, so every database is read over a few runs;
without it, each run samples afresh in the configured order.

With `STATE_LOCATION`, a **table index** lives beside the state (#67): a table whose
engine says it has not changed since its last read (the core's `scan/sql.py` change
markers) is not sampled again, and its findings are carried from the last run
(`findings.json.gz` beside the index, findings only, never a value).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import secrets
import time
from collections.abc import Callable, Sequence
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, column_findings
from sensitive_data_core.coverage import Store, apply_rules, settle, summary
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.findings import (
    Coverage,
    encryption_facts,
    findings_document,
    store_field_resource,
)
from sensitive_data_core.index import Indexes, ObjectPass, index_salt
from sensitive_data_core.push import FindingsSink
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import TableResult
from sensitive_data_core.state import index_backend

from . import __version__
from .config import Database, Settings
from .engines import CONNECT, ReadRefused, load_driver
from .state import StateStore, load_state, save_rotation

MAX_WRITE_GRANTS = 30


CARRIED = "findings.json.gz"


def source_id(db: Database) -> str:
    return f"{db.engine}:{db.name}"


def carry(findings: FindingStore, backend: Any, in_scope: set[str]) -> None:
    """The findings of the last run, for the databases still configured: a table skipped as
    unchanged keeps them; a table read again replaces its own."""
    try:
        raw = backend.get_bytes(CARRIED)
        items = json.loads(gzip.decompress(raw)) if raw else []
    except Exception as err:  # none carried: every finding is this run's
        log_event("index.failed", error=error_name(err))
        return
    for f in items if isinstance(items, list) else []:
        if isinstance(f, dict) and str(f.get("_location", "")).split("\n", 1)[0] in in_scope:
            findings.items[str(f.get("id"))] = f


def keep(findings: FindingStore, backend: Any) -> None:
    try:
        body = json.dumps(list(findings.items.values()), separators=(",", ":")).encode()
        backend.put_bytes(CARRIED, gzip.compress(body, mtime=0))
    except Exception as err:  # the next run reads its tables afresh
        log_event("index.failed", error=error_name(err))


def _refuse(store: Store, reason: str, error: str | None = None) -> None:
    store.skip(reason, error)
    log_event("source.refused", source=store.name, kind=store.kind, reason=reason)


def check_database(
    db: Database, settings: Settings, drivers: dict[str, Any] | None = None
) -> tuple[Store, Any | None]:
    """Steps 1-3 for one database: the store, and a session ready to read (or None)."""
    store = Store(db.engine, db.name, origin="config")
    if not apply_rules(store, settings.allow, settings.deny):
        return store, None
    driver = load_driver(db.engine, drivers)
    if driver is None:
        _refuse(store, "driver_missing")
        return store, None
    try:
        session = CONNECT[db.engine](db, settings, driver)
    except ReadRefused as refused:
        _refuse(store, refused.reason)
        return store, None
    except Exception as err:  # reported by name: a driver's message can quote the host or user
        store.status, store.reason, store.error = "error", "error", error_name(err)
        log_event("source.failed", source=db.name, kind=db.engine, error=store.error)
        return store, None
    if session.database:
        store.extra["database"] = session.database
    if session.flavor:
        store.extra["engine"] = session.flavor
    grants = session.grants()
    if not grants.verified:
        session.close()
        _refuse(store, "grants_unverifiable", grants.error)
        return store, None
    if grants.write:
        session.close()
        store.extra["writeGrants"] = sorted(grants.write)[:MAX_WRITE_GRANTS]
        _refuse(store, "db_user_can_write")
        return store, None
    # Only once the user is known to be read-only: what the database says of its storage.
    store.facts = encryption_facts(session.encryption())
    return store, session


def _read(
    *,
    db: Database,
    store: Store,
    session: Any,
    settings: Settings,
    detector: Detector,
    budget: Budget,
    findings: FindingStore,
    indexes: Indexes | None = None,
    today: int = 0,
) -> Coverage:
    cov = Coverage(kind=db.engine, target=db.name)
    seen_at = findings.now
    fmt = "json" if db.engine == "mongodb" else "sql"
    op = ObjectPass(indexes, source_id(db), db.engine, generation=today, budget=budget)

    def on_table(schema: str, table: str, result: TableResult) -> None:
        def resource(column: str) -> dict[str, Any]:
            return store_field_resource(
                service=db.engine,
                store=db.name,
                database=session.database or None,
                table=f"{schema}.{table}",
                field=column,
                read_by="sample",
            )

        location = f"{source_id(db)}\n{schema}\n{table}"
        findings.replace_location(
            location, column_findings(result, resource, None, seen_at, facts=store.facts)
        )

    log_event("source.start", source=db.name, kind=db.engine)
    try:
        sp = session.read(
            settings=settings,
            detector=detector,
            has_room=budget.has,
            take=budget.take,
            on_table=on_table,
            source=db.name,
            index=op,
        )
    except Exception as err:  # the listing itself failed; the other databases still run
        cov.error = error_name(err)
        log_event("source.failed", source=db.name, kind=db.engine, error=cov.error)
        return cov
    finally:
        session.close()
    cov.listed, cov.eligible, cov.scanned = sp.listed, sp.eligible, sp.scanned
    cov.unreadable, cov.partial, cov.bytes_scanned = sp.unreadable, sp.partial, sp.bytes
    cov.test_values, cov.suppressed = sp.test_values, sp.suppressed
    cov.redaction_markers = sp.redaction_markers
    cov.pass_complete = sp.done
    cov.backlog = not sp.done
    if sp.scanned:
        cov.formats[fmt] = sp.scanned
    op.settle(cov)
    log_event(
        "source.done",
        source=db.name,
        scanned=cov.scanned,
        passComplete=cov.pass_complete,
        error=cov.error,
    )
    return cov


def run(
    settings: Settings,
    sinks: Sequence[FindingsSink],
    *,
    drivers: dict[str, Any] | None = None,
    detector: Detector | None = None,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.UTC),
    clock: Callable[[], float] = time.monotonic,
    state: StateStore | None = None,
) -> tuple[dict[str, Any], int]:
    """One run. Returns the findings document, and how many sinks failed."""
    started = now()
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    detector = detector or Detector(load_spec(), started.date())
    log_event("run.start", sources=len(settings.databases))
    budget = Budget(
        settings.max_items_per_run,
        settings.max_bytes_per_run,
        clock() + settings.max_run_seconds,
        clock,
    )
    findings = FindingStore(started.isoformat())
    stores: list[Store] = []
    coverage: list[Coverage] = []
    ordered = list(settings.databases)
    saved = load_state(state, settings.site)
    start = saved.get("rotation") if isinstance(saved.get("rotation"), str) else None
    backend = index_backend(state) if state is not None and settings.object_index else None
    indexes = (
        Indexes(
            backend,
            index_salt(saved),
            max_rows=settings.index_max_objects,
            rescan_percent=settings.rescan_percent,
        )
        if backend is not None
        else None
    )
    if indexes is not None:
        carry(findings, backend, {source_id(d) for d in ordered})
    today = (started.date() - _dt.date(1970, 1, 1)).days
    names = [d.name for d in ordered]
    if start in names:
        k = names.index(start)
        ordered = ordered[k:] + ordered[:k]
    deferred: str | None = None
    for i, db in enumerate(ordered):
        if budget.exhausted():
            store = Store(db.engine, db.name, origin="config")
            store.status, store.reason = "deferred", "budget"
            log_event("source.deferred", source=db.name, kind=db.engine)
            stores.append(store)
            deferred = deferred or db.name
            continue
        store, session = check_database(db, settings, drivers)
        stores.append(store)
        if session is None:
            continue
        share = budget.share(len(ordered) - i)
        cov = _read(
            db=db,
            store=store,
            session=session,
            settings=settings,
            detector=detector,
            budget=share,
            findings=findings,
            indexes=indexes,
            today=today,
        )
        budget.absorb(share)
        coverage.append(cov)
        settle(store, [cov])
        if cov.listed == 0 and cov.error is None:
            store.status, store.reason = "skipped", "no_grant"  # the user can see no table
    doc = findings_document(
        run_id=run_id,
        account=None,
        region=None,
        platform="database",
        site=settings.site,
        started_at=started.isoformat(),
        finished_at=now().isoformat(),
        classes=list(load_spec().class_order),
        coverage=coverage,
        findings=findings.public(),
        discovery=summary(stores, {}),
        scanner_version=__version__,
    )
    if indexes is not None and backend is not None:
        indexes.save()
        keep(findings, backend)
    save_rotation(state, settings.site, deferred, salt=indexes.salt if indexes else None)
    failed = 0
    for sink in sinks:
        try:
            if sink.push(doc) == 0:
                failed += 1
        except Exception as err:  # the other sinks still get the document
            failed += 1
            log_event("events.failed", count=1, error=error_name(err))
    log_event(
        "run.done",
        findings=doc["findingsTotal"],
        **{f"total_{k}": v for k, v in doc["totals"].items()},
    )
    return doc, failed
