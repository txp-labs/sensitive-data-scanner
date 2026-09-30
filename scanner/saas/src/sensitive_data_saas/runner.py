"""One run of the SaaS scanner: discover, read within the budget, report.

It runs in the customer's own environment, as a scheduled container:

1. **Discovery**: each kind in `DISCOVER` lists its stores (a mailbox, a
   drive, a site, a team), and the allow, deny and sampling rules decide each
   one (the core's `rules`). A listing that fails is named in `listErrors`;
   the other kinds are still listed.
2. **Reading**: a source per store that is read, in rotation (the store the
   previous run's budget did not reach goes first), each with a share of the
   run's budget (items, bytes, time) and its own cap per mailbox, drive or
   channel. A store the budget does not reach is `deferred`; one whose vendor
   kept throttling is `throttled` and goes on next run.
3. **Reporting**: the findings document (`platform: saas`, the `site`) with the
   run summary of every store, read or not, and why; pushed to every sink.

With `STATE_LOCATION` (the core's `state`), the cursors (delta links), the
findings carried between runs and the rotation are kept for the next run: an
item's findings are replaced when it is read again and dropped when it is
deleted. The state holds ids, hashes and findings; never a value, a name in
the clear or a credential.
"""

from __future__ import annotations

import datetime as _dt
import secrets
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, settle, summary
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.findings import Coverage, findings_document
from sensitive_data_core.push import FindingsSink
from sensitive_data_core.safety import ScanError, error_name, log_event
from sensitive_data_core.state import StateStore, state_location

from . import __version__
from .clients import Clients
from .config import OPT_IN_KINDS, Settings
from .sources.base import Context

STATE_VERSION = 1


class Source(Protocol):
    id: str
    target: str
    kind: str

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun: ...


def _s3() -> Any:
    import boto3  # noqa: PLC0415 - the `aws` extra, only when S3 holds the state

    return boto3.client("s3")


def state_for(settings: Settings) -> StateStore | None:
    if settings.state_location is None:
        return None
    return state_location(
        settings.state_location,
        settings.hmac_key,
        user_agent=f"sensitive-data-scanner-saas/{__version__}",
        s3_client=_s3,
    )


def discover(ctx: Context) -> Discovery:
    """Every store of every kind in `DISCOVER`, decided."""
    from .sources.saas import ADAPTERS  # noqa: PLC0415 - the adapters import the runner's parts

    out = Discovery()
    for kind in ctx.settings.configured:
        if kind not in ctx.settings.discover and kind in OPT_IN_KINDS:
            off = Store(kind, "*", origin="config")
            off.skip("read_not_configured")
            out.stores.append(off)
    for kind in ctx.settings.discover:
        adapter = ADAPTERS.get(kind)
        if adapter is None:
            continue
        try:
            adapter.discover(ctx, out)
        except Exception as err:  # the other kinds are still listed
            name = error_name(err)
            out.list_errors[kind] = name
            log_event("discovery.failed", kind=kind, error=name)
    log_event(
        "discovery.done",
        stores=len(out.stores),
        skipped=sum(1 for s in out.stores if s.status == "skipped"),
    )
    return out


def plan(ctx: Context, found: Discovery) -> tuple[list[Any], list[Store]]:
    """The sources to run, and every store (read or not)."""
    from .sources.saas import ADAPTERS  # noqa: PLC0415

    sources: list[Any] = []
    stores = sorted(found.stores, key=lambda s: (s.kind, s.name))
    for store in stores:
        if store.status != "pending":
            continue
        adapter = ADAPTERS.get(store.kind)
        got = adapter.source(ctx, store) if adapter is not None else None
        for one in got if isinstance(got, list) else [got]:
            if one is None:
                continue
            if store.facts and getattr(one, "facts", None) is None:
                one.facts = dict(store.facts)
            store.source_ids.append(one.id)
            sources.append(one)
        if not store.source_ids and store.status == "pending":
            store.skip("unsupported")
    return sources, stores


def rotate(sources: list[Any], start: str | None) -> list[Any]:
    ids = [s.id for s in sources]
    if start in ids:
        k = ids.index(start)
        return sources[k:] + sources[:k]
    return sources


def _load(state: StateStore | None, site: str) -> dict[str, Any]:
    if state is None:
        return {}
    try:
        saved = state.load() or {}
    except Exception as err:  # no state: the run starts afresh
        log_event("source.failed", source="state", error=error_name(err))
        return {}
    if saved and (saved.get("version") != STATE_VERSION or saved.get("site") != site):
        log_event("state.reset")
        return {}
    return saved


def run_scan(
    settings: Settings,
    clients: Clients,
    *,
    sinks: Sequence[FindingsSink] = (),
    state: StateStore | None = None,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.UTC),
    detector: Detector | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], int]:
    """One scan. Returns the findings document and how many sinks failed."""
    started = now()
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    state = state if state is not None else state_for(settings)
    try:
        doc = _scan(
            settings,
            clients,
            state=state,
            run_id=run_id,
            started=started,
            now=now,
            detector=detector,
            clock=clock,
        )
    except ScanError:
        raise
    except Exception as err:
        name = error_name(err)
        log_event("run.failed", error=name)
        raise ScanError(name) from None
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


def _scan(
    settings: Settings,
    clients: Clients,
    *,
    state: StateStore | None,
    run_id: str,
    started: _dt.datetime,
    now: Callable[[], _dt.datetime],
    detector: Detector | None,
    clock: Callable[[], float],
) -> dict[str, Any]:
    detector = detector or Detector(load_spec(), started.date())
    deadline = clock() + settings.max_run_seconds
    clients.http.deadline = deadline
    ctx = Context(settings, clients)
    found = discover(ctx)
    sources, stores = plan(ctx, found)
    log_event("run.start", sources=len(sources))
    saved = _load(state, settings.site)
    cursors: dict[str, Any] = dict(saved.get("cursors") or {})
    sources = rotate(sources, saved.get("rotation"))
    in_scope = {s.id for s in sources}
    findings = FindingStore(started.isoformat())
    for f in saved.get("findings") or []:
        if isinstance(f, dict) and str(f.get("_location", "")).split("\n", 1)[0] in in_scope:
            findings.items[f["id"]] = f
    budget = Budget(settings.max_items_per_run, settings.max_bytes_per_run, deadline, clock)
    coverage: list[Coverage] = []
    by_source: dict[str, Coverage] = {}
    notes: dict[str, str | None] = {}
    extras: dict[str, dict[str, Any]] = {}
    deferred: str | None = None
    for i, source in enumerate(sources):
        if budget.exhausted():
            deferred = deferred or source.id
            log_event("source.deferred", source=source.target, kind=source.kind)
            continue
        share = budget.share(len(sources) - i)
        log_event("source.start", source=source.target, kind=source.kind)
        result = source.run(cursors.get(source.id) or {}, share, detector, findings, started)
        prune = getattr(source, "prune", None)
        if callable(prune) and result.coverage.error is None:
            prune(findings, share)
        budget.absorb(share)
        cursors[source.id] = result.cursor
        coverage.append(result.coverage)
        by_source[source.id] = result.coverage
        notes[source.id] = result.note
        extras[source.id] = result.extra
        if result.coverage.backlog and deferred is None and result.note == "throttled":
            deferred = source.id
        log_event(
            "source.done",
            source=source.target,
            scanned=result.coverage.scanned,
            passComplete=result.coverage.pass_complete,
            error=result.coverage.error,
        )
    for st in stores:
        covs = [by_source[i] for i in st.source_ids if i in by_source]
        if covs:
            extra: dict[str, Any] = {}
            for sid in st.source_ids:
                extra.update(extras.get(sid) or {})
            settle(st, covs, [notes.get(i) for i in st.source_ids], extra)
        elif st.status == "pending" and st.source_ids:
            st.status, st.reason = "deferred", "budget"
    doc = findings_document(
        run_id=run_id,
        account=None,
        region=None,
        platform="saas",
        site=settings.site,
        started_at=started.isoformat(),
        finished_at=now().isoformat(),
        classes=list(load_spec().class_order),
        coverage=coverage,
        findings=findings.public(),
        discovery=summary(stores, found.list_errors),
        scanner_version=__version__,
    )
    if state is not None:
        try:
            state.save(
                {
                    "version": STATE_VERSION,
                    "site": settings.site,
                    "cursors": cursors,
                    "findings": list(findings.items.values()),
                    "lastRunAt": started.isoformat(),
                    "rotation": deferred,
                }
            )
        except Exception as err:  # the findings still go out; the next run starts afresh
            log_event("source.failed", source="state", error=error_name(err))
    return doc
