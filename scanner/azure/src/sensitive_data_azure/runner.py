"""One run of the Azure scanner: discover, read within the budget, report.

It runs in the customer's tenant as a Container Apps job, under the job's
managed identity:

1. **Discovery**: each kind in `DISCOVER` lists its stores across every
   subscription under the management group (Resource Graph), and the allow,
   deny and sampling rules decide each one (the core's `rules`). A listing
   that fails is named in `listErrors`; the other kinds are still listed.
2. **Reading**: a source per store that is read, in rotation (the store the
   previous run's budget did not reach goes first), each with a share of the
   run's budget (items, bytes, time, and a cap on blobs). A store the budget
   does not reach is `deferred`.
3. **Reporting**: the findings document (`platform: azure`, the `site`) with the
   run summary of every store, read or not, and why; written to the job's own
   container (state.py) and pushed to every configured sink.

Findings carry over between runs in the state, like the AWS scanner's: a blob's
findings are replaced when it is read again and dropped when it is deleted.
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
from sensitive_data_core.index import Indexes, PrefixBackend, index_salt
from sensitive_data_core.push import FindingsSink
from sensitive_data_core.safety import ScanError, error_name, log_event

from . import __version__
from .clients import Clients
from .config import Settings
from .sources.base import Context
from .state import INDEX, LATEST, RUNS, STATE, BlobState

STATE_VERSION = 1
# Kinds whose items are counted against MAX_OBJECTS_PER_RUN as well as the run's budget.
OBJECT_KINDS = ("azure_blob",)


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


def discover(ctx: Context) -> Discovery:
    """Every store of every kind in `DISCOVER`, decided."""
    from .sources.azure import ADAPTERS  # noqa: PLC0415 - the adapters import the runner's parts

    out = Discovery()
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
    from .sources.azure import ADAPTERS  # noqa: PLC0415

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
    """From `start` round, so a budget that cannot reach every store reaches the rest next."""
    ids = [s.id for s in sources]
    if start in ids:
        k = ids.index(start)
        return sources[k:] + sources[:k]
    return sources


def run_scan(
    settings: Settings,
    clients: Clients,
    *,
    sinks: Sequence[FindingsSink] = (),
    state: BlobState | None = None,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.UTC),
    detector: Detector | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any] | None, int]:
    """One scan. Returns the findings document (None when another run holds the lock) and
    how many sinks failed."""
    started = now()
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    if state is None and settings.state is not None:
        own = clients.client("blob", settings.state.endpoint)
        state = BlobState(own.get_container_client(settings.state.container))
    if state is not None:
        try:
            locked = state.take_lock(run_id, started)
        except Exception as err:
            name = error_name(err)
            log_event("run.failed", error=name)
            raise ScanError(name) from None
        if not locked:
            log_event("run.locked")
            return None, 0
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
    finally:
        if state is not None:
            try:
                state.release_lock()
            except Exception as err:  # a stale lock expires by itself
                log_event("run.failed", error=error_name(err))
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
    state: BlobState | None,
    run_id: str,
    started: _dt.datetime,
    now: Callable[[], _dt.datetime],
    detector: Detector | None,
    clock: Callable[[], float],
) -> dict[str, Any]:
    detector = detector or Detector(load_spec(), started.date())
    ctx = Context(settings, clients)
    found = discover(ctx)
    sources, stores = plan(ctx, found)
    log_event("run.start", sources=len(sources))
    saved = (state.get_json(STATE) if state is not None else None) or {}
    if saved and saved.get("version") != STATE_VERSION:
        log_event("state.reset")
        saved = {}
    cursors: dict[str, Any] = dict(saved.get("cursors") or {})
    sources = rotate(sources, saved.get("rotation"))
    indexes = (
        Indexes(PrefixBackend(state, INDEX), index_salt(saved), max_rows=settings.index_max_objects)
        if state is not None and settings.object_index
        else None
    )
    for source in sources:
        if hasattr(source, "indexes"):
            source.indexes = indexes
    in_scope = {s.id for s in sources}
    findings = FindingStore(started.isoformat())
    for f in saved.get("findings") or []:
        if str(f.get("_location", "")).split("\n", 1)[0] in in_scope:
            findings.items[f["id"]] = f
    deadline = clock() + settings.max_run_seconds
    budget = Budget(settings.max_items_per_run, settings.max_bytes_per_run, deadline, clock)
    objects = (
        Budget(settings.max_objects_per_run, settings.max_bytes_per_run, deadline, clock)
        if settings.max_objects_per_run
        else None
    )
    left = sum(1 for s in sources if s.kind in OBJECT_KINDS)
    coverage: list[Coverage] = []
    by_source: dict[str, Coverage] = {}
    notes: dict[str, str | None] = {}
    extras: dict[str, dict[str, Any]] = {}
    deferred: str | None = None
    for i, source in enumerate(sources):
        capped = objects if source.kind in OBJECT_KINDS else None
        ways = left
        if source.kind in OBJECT_KINDS:
            left = max(0, left - 1)
        if budget.exhausted() or (capped is not None and capped.exhausted()):
            deferred = deferred or source.id
            log_event("source.deferred", source=source.target, kind=source.kind)
            continue
        share = budget.share(len(sources) - i)
        if capped is not None:
            share.max_items = min(share.max_items, capped.share(ways).max_items)
        log_event("source.start", source=source.target, kind=source.kind)
        result = source.run(cursors.get(source.id) or {}, share, detector, findings, started)
        prune = getattr(source, "prune", None)
        if callable(prune) and result.coverage.error is None:
            prune(findings, share)
        budget.absorb(share)
        if capped is not None:
            capped.absorb(share)
        cursors[source.id] = result.cursor
        coverage.append(result.coverage)
        by_source[source.id] = result.coverage
        notes[source.id] = result.note
        extras[source.id] = result.extra
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
        platform="azure",
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
        new_state: dict[str, Any] = {
            "version": STATE_VERSION,
            "cursors": cursors,
            "findings": list(findings.items.values()),
            "lastRunAt": started.isoformat(),
            "rotation": deferred,
        }
        if indexes is not None:
            indexes.save()
            new_state["indexSalt"] = indexes.salt
        state.put_json(STATE, new_state)
        state.put_json(f"{RUNS}{run_id}.json", doc)
        state.put_json(LATEST, doc)
    return doc
