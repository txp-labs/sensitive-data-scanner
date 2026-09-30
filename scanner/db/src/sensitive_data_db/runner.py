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
"""

from __future__ import annotations

import datetime as _dt
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
from sensitive_data_core.push import FindingsSink
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import TableResult

from . import __version__
from .config import Database, Settings
from .engines import CONNECT, ReadRefused, load_driver
from .state import StateStore, load_rotation, save_rotation

MAX_WRITE_GRANTS = 30


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
) -> Coverage:
    cov = Coverage(kind=db.engine, target=db.name)
    seen_at = findings.now
    fmt = "json" if db.engine == "mongodb" else "sql"

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

        location = f"{db.engine}:{db.name}\n{schema}\n{table}"
        for f in column_findings(result, resource, None, seen_at, facts=store.facts):
            findings.put(location, f)

    log_event("source.start", source=db.name, kind=db.engine)
    try:
        sp = session.read(
            settings=settings,
            detector=detector,
            has_room=budget.has,
            take=budget.take,
            on_table=on_table,
            source=db.name,
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
    start = load_rotation(state, settings.site)
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
    save_rotation(state, settings.site, deferred)
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
