"""The batch runner: one scheduled scan of the stores named, and of the stores discovered.

It runs in the account it scans. It reads the S3 prefixes, log groups and
DynamoDB tables it was given and, with `DISCOVER` set, every store of those
kinds that discovery lists and the allow and deny lists let through
(discovery.py). It writes to its results bucket only:

- `findings/latest.json` and `findings/runs/<runId>.json`: the findings
  document (schema/findings.schema.json);
- `state/scanner-state.json`: each source's cursor and the findings carried
  between runs, for the next run only (a consumer never needs it);
- `state/lock.json`: one run at a time.

The run's budget (items, bytes, wall time, and optional per-kind caps on S3
objects, log events and table items) is shared among the sources. Stores
the budget does not reach are reported as deferred, and the next run starts
with them.

With `FINDINGS_EVENT_BUS_ARN` set, it also sends the findings as EventBridge
events to that bus (events.py).
"""

from __future__ import annotations

import datetime as _dt
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, settle, summary
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.findings import Coverage, findings_document
from sensitive_data_core.index import Indexes, S3Backend, index_salt, listed_with, relist
from sensitive_data_core.modes import BOTH, SCANNER, VENDOR, VendorCoverage, link_duplicates
from sensitive_data_core.safety import ScanError, error_name, is_kms_denial, log_event

from .config import Config, DynamoTarget
from .discovery import discover
from .events import put_findings_events
from .sources.base import Context
from .sources.cloudwatch_logs import CloudWatchLogsSource
from .sources.dynamodb import DynamoDBSource
from .sources.dynamodb_export import DynamoDBExportSource
from .sources.encryption import classifier
from .sources.exports import ExportQuota
from .sources.macie import MacieImporter
from .sources.rds import RdsDataApiSource, RdsExportSource
from .sources.s3 import S3Source

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_rds import RDSClient
    from mypy_boto3_rds_data import RDSDataServiceClient
    from mypy_boto3_s3 import S3Client

LOCK_STALE_SECONDS = 20 * 60
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


@dataclass
class Clients:
    s3: S3Client
    logs: CloudWatchLogsClient
    events: EventBridgeClient | None = None
    dynamodb: DynamoDBClient | None = None
    glue: GlueClient | None = None
    rds: RDSClient | None = None
    rds_data: RDSDataServiceClient | None = None
    # Any other service an adapter uses, by its botocore name ("redshift-data").
    # Tests put stubbed clients here; the handler gives a factory that makes one
    # the first time an adapter asks.
    services: dict[str, Any] = field(default_factory=dict)
    factory: Callable[[str], Any] | None = None

    def client(self, service: str) -> Any:
        """The client for `service`, made on first use."""
        made = self.services.get(service)
        if made is None:
            if self.factory is None:
                raise ValueError("no client for a service an adapter uses")
            made = self.services[service] = self.factory(service)
        return made


class Keys:
    def __init__(self, prefix: str) -> None:
        self.latest = f"{prefix}findings/latest.json"
        self.runs = f"{prefix}findings/runs/"
        self.state = f"{prefix}state/scanner-state.json"
        self.lock = f"{prefix}state/lock.json"
        self.index = f"{prefix}state/index/"


def _read_json(s3: S3Client, bucket: str, key: str, *, probe: str | None = None) -> Any:
    """The JSON object at `key`, or None when there is none.

    Without `s3:ListBucket` on the bucket, S3 answers a missing object with 403
    AccessDenied, not 404 (the first run, before any state exists). With
    `probe`, the key of an object known to exist under the same grant (the run's
    lock, just written), a 403 counts as missing when the probe can be read: the
    scanner's access is otherwise fine. If the probe cannot be read either, the
    denial is real and is raised, as is a KMS denial.
    """
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as err:
        name = error_name(err)
        if name in ("NoSuchKey", "404", "NotFound"):
            return None
        denied = name in ("AccessDenied", "403", "Forbidden") and not is_kms_denial(err)
        if probe is not None and denied:
            try:
                s3.head_object(Bucket=bucket, Key=probe)
            except Exception:
                raise err from None
            return None
        raise
    return json.loads(body)


def _put_json(s3: S3Client, bucket: str, key: str, body: Any) -> None:
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(body, separators=(",", ":")).encode(),
        ContentType="application/json",
    )


def _take_lock(s3: S3Client, bucket: str, key: str, run_id: str) -> bool:
    """A conditional put of the lock object; a lock older than 20 minutes is stale."""

    def put() -> None:
        s3.put_object(
            Bucket=bucket, Key=key, Body=json.dumps({"runId": run_id}).encode(), IfNoneMatch="*"
        )

    try:
        put()
        return True
    except Exception as err:
        if error_name(err) not in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
            raise
    head = s3.head_object(Bucket=bucket, Key=key)
    age = time.time() - head["LastModified"].timestamp()
    if age < LOCK_STALE_SECONDS:
        return False
    s3.delete_object(Bucket=bucket, Key=key)
    try:
        put()
        return True
    except Exception:  # another run took it first
        return False


def _s3_source(
    config: Config,
    clients: Clients,
    store: Store,
    *,
    region: str,
    prefix: str = "",
    exclude: tuple[str, ...] = (),
) -> S3Source:
    t = store.table
    source = S3Source(
        clients.s3,
        bucket=t.bucket if t else store.name,
        prefix=t.prefix if t else prefix,
        region=region,
        sample_percent=store.sample_percent or config.sample_percent,
        max_object_bytes=config.max_object_bytes,
        max_inflated_bytes=config.max_inflated_bytes,
        skew_seconds=config.s3_skew_seconds,
        max_per_prefix=(
            store.max_per_prefix
            if store.max_per_prefix is not None
            else config.s3_max_objects_per_prefix
        ),
        max_rows=config.columnar_max_rows,
        exclude_prefixes=exclude,
        catalog=(t.database, t.name) if t else None,
        columns=t.columns if t else (),
        serde=t.serde if t else None,
        delimiter=t.delimiter if t else ",",
        skip_header=t.skip_header if t else 0,
        keys=classifier(clients),
        # A bucket's key filter; a catalog table reads its own location's files.
        key_filter=None if t else store.key_filter,
    )
    source.use_inventory = config.s3_inventory
    source.inventory_min_objects = config.s3_inventory_min_objects
    return source


def _dynamodb_source(
    config: Config, clients: Clients, region: str, store: Store, target: DynamoTarget
) -> DynamoDBSource:
    if clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    source = DynamoDBSource(
        clients.dynamodb,
        target=target,
        region=region,
        page_size=config.dynamodb_page_size,
        max_pages=config.dynamodb_max_pages,
        sample_percent=store.sample_percent or config.dynamodb_sample_percent,
    )
    source.keys = classifier(clients)
    return source


def _logs_source(config: Config, clients: Clients, region: str, group: str) -> Any:
    source = CloudWatchLogsSource(
        clients.logs, log_group=group, region=region, lookback_days=config.logs_lookback_days
    )
    source.keys = classifier(clients)
    return source


def _with_facts(sources: list[Any], stores: list[Store]) -> None:
    """Each source gets its store's facts (1.5: the storage encryption discovery found), unless
    it knows its own (an S3 object's headers, a configured table's DescribeTable)."""
    by_id = {s.id: s for s in sources}
    for store in stores:
        if not store.facts:
            continue
        for i in store.source_ids:
            src = by_id.get(i)
            if src is not None and getattr(src, "facts", None) is None:
                src.facts = dict(store.facts)


def plan(
    config: Config,
    clients: Clients,
    region: str,
    discovery: Discovery | None = None,
    account: str = "",
) -> tuple[list[Any], list[Store]]:
    """The sources to run, and every store they come from (named or discovered).

    Stores named in the configuration come first, in its order; each is read
    as configured (its prefixes, its DynamoDB paths). A discovered store the
    configuration already names is read once, as configured.
    """
    sources: list[Any] = []
    stores: list[Store] = []
    by_key: dict[tuple[str, str], Store] = {}

    def named(kind: str, name: str) -> Store:
        store = by_key.get((kind, name))
        if store is None:
            store = Store(kind, name, origin="config")
            pct, per = config.sampling_for(kind, name, None)
            store.sample_percent = pct
            store.max_per_prefix = per
            if kind == "s3":
                store.key_filter = config.key_filter_for(kind, name, None)
            by_key[(kind, name)] = store
            stores.append(store)
        return store

    def add(store: Store, source: Any) -> None:
        store.source_ids.append(source.id)
        sources.append(source)

    for bucket, prefix in config.s3_targets:
        store = named("s3", bucket)
        add(store, _s3_source(config, clients, store, region=region, prefix=prefix))
    for group in config.log_groups:
        store = named("cloudwatch_logs", group)
        add(store, _logs_source(config, clients, region, group))
    if config.dynamodb_targets and clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    for t in config.dynamodb_targets:
        store = named("dynamodb", t.table)
        add(store, _dynamodb_source(config, clients, region, store, t))
    if config.data_api_targets and clients.rds_data is None:
        raise ValueError("no RDS Data API client")
    for d in config.data_api_targets:
        src = RdsDataApiSource(clients.rds_data, target=d, region=region)  # type: ignore[arg-type]
        src.rds, src.keys = clients.rds, classifier(clients)
        store = named("rds", src.identifier)
        store.extra["readBy"] = "data_api"
        add(store, src)
    quota = ExportQuota(config.max_exports_per_run)
    if discovery is None:
        return sources, stores
    _plan_discovered(
        config,
        clients,
        region,
        discovery=discovery,
        account=account,
        quota=quota,
        by_key=by_key,
        stores=stores,
        add=add,
    )
    _with_facts(sources, stores)
    return sources, stores


def _plan_discovered(
    config: Config,
    clients: Clients,
    region: str,
    *,
    discovery: Discovery,
    account: str,
    quota: ExportQuota,
    by_key: dict[tuple[str, str], Store],
    stores: list[Store],
    add: Callable[[Store, Any], None],
) -> None:
    """The discovered stores' sources, after the configured ones."""
    from .sources.aws import ADAPTERS  # noqa: PLC0415 - the adapters import discovery

    ctx = Context(config, clients, region, account, quota)
    # A catalog table's prefix is read by the table's source, not again by its bucket's.
    tables: dict[str, list[str]] = {}
    for st in discovery.stores:
        if st.table is not None and st.status == "pending":
            tables.setdefault(st.table.bucket, []).append(st.table.prefix)
        # A store read at S3 locations of its own (a Firehose destination) claims them too.
        for loc in st.extra.get("s3Locations") or [] if st.status == "pending" else []:
            b, _, p = str(loc).partition("/")
            tables.setdefault(b, []).append(p)
    for store in sorted(discovery.stores, key=lambda s: (s.kind, s.name)):
        known = by_key.get((store.kind, store.name))
        if known is not None:
            known.size_bytes = store.size_bytes if known.size_bytes is None else known.size_bytes
            known.facts = known.facts or store.facts
            continue  # read as configured
        stores.append(store)
        if store.status != "pending":
            continue
        if store.kind == "s3":
            exclude = tuple(sorted(tables.get(store.name, [])))
            add(store, _s3_source(config, clients, store, region=region, exclude=exclude))
        elif store.kind == "glue_table":
            add(store, _s3_source(config, clients, store, region=region))
        elif store.kind == "dynamodb" and store.extra.get("readBy") == "export":
            if clients.dynamodb is None:
                raise ValueError("no DynamoDB client")
            add(
                store,
                DynamoDBExportSource(
                    clients.dynamodb,
                    clients.s3,
                    table=store.name,
                    table_arn=str(store.extra.get("tableArn", "")),
                    region=region,
                    results_bucket=config.results_bucket,
                    exports_prefix=config.exports_prefix,
                    quota=quota,
                    kms_key_arn=config.dynamodb_export_kms_key_arn,
                    max_object_bytes=config.max_object_bytes,
                    max_inflated_bytes=config.max_inflated_bytes,
                    min_interval_days=config.export_min_interval_days,
                    incremental=config.dynamodb_incremental,
                ),
            )
        elif store.kind == "rds":
            if clients.rds is None:
                raise ValueError("no RDS client")
            add(
                store,
                RdsExportSource(
                    clients.rds,
                    clients.s3,
                    identifier=store.name,
                    db_type=str(store.extra.get("dbType", "cluster")),
                    engine=str(store.extra.get("engine", "")),
                    region=region,
                    results_bucket=config.results_bucket,
                    exports_prefix=config.exports_prefix,
                    role_arn=str(config.rds_export_role_arn),
                    kms_key_arn=str(config.rds_export_kms_key_arn),
                    quota=quota,
                    max_rows=config.columnar_max_rows,
                    max_object_bytes=config.max_object_bytes,
                    min_interval_days=config.export_min_interval_days,
                ),
            )
        elif store.kind == "cloudwatch_logs":
            add(store, _logs_source(config, clients, region, store.name))
        elif store.kind == "dynamodb" and store.extra.get("readBy") != "export":
            add(store, _dynamodb_source(config, clients, region, store, DynamoTarget(store.name)))
        elif store.kind in ADAPTERS:
            found_source = ADAPTERS[store.kind].source(ctx, store)
            for one in found_source if isinstance(found_source, list) else [found_source]:
                if one is not None:
                    add(store, one)


def indexes_for(config: Config, clients: Clients, state: dict[str, Any]) -> Indexes | None:
    """The run's object indexes (#67), in the results bucket under `state/index/`, keyed by
    the salt in the state document; None with `OBJECT_INDEX` off."""
    if not config.object_index:
        return None
    return Indexes(
        S3Backend(config.results_bucket, Keys(config.results_prefix).index, clients.s3),
        index_salt(state),
        max_rows=config.index_max_objects,
        rescan_percent=config.rescan_percent,
    )


def with_indexes(sources: list[Any], indexes: Indexes | None) -> None:
    """Every source that keeps an object index gets the run's."""
    for source in sources:
        if hasattr(source, "indexes"):
            source.indexes = indexes
            if indexes is not None:
                indexes.register(source.id)


def build_sources(config: Config, clients: Clients, region: str) -> list[Any]:
    """The configured sources only (no discovery)."""
    return plan(config, clients, region)[0]


def rotate(sources: list[Any], stores: list[Store], start: str | None) -> list[Any]:
    """Configured sources first; discovered ones from `start` round, so a budget that
    cannot reach every store this run reaches the rest on the next."""
    configured = {i for s in stores if s.origin == "config" for i in s.source_ids}
    head = [s for s in sources if s.id in configured]
    tail = [s for s in sources if s.id not in configured]
    ids = [s.id for s in tail]
    if start in ids:
        k = ids.index(start)
        tail = tail[k:] + tail[:k]
    return head + tail


def run_scan(
    config: Config,
    clients: Clients,
    *,
    account: str,
    region: str,
    deadline: float,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.UTC),
    detector: Detector | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any] | None:
    """One scan. Returns the findings document it wrote, or None when another run holds the lock."""
    started = now()
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    keys = Keys(config.results_prefix)
    bucket = config.results_bucket
    try:
        locked = _take_lock(clients.s3, bucket, keys.lock, run_id)
    except Exception as err:
        name = error_name(err)
        log_event("run.failed", error=name)
        raise ScanError(name) from None
    if not locked:
        log_event("run.locked")
        return None
    try:
        detector = detector or Detector(load_spec(), started.date())
        found = discover(config, clients, region, account) if config.discover else None
        sources, stores = plan(config, clients, region, found, account)
        log_event("run.start", sources=len(sources))
        state = _read_json(clients.s3, bucket, keys.state, probe=keys.lock) or {}
        if state and state.get("version") != STATE_VERSION:
            log_event("state.reset")
            state = {}
        cursors: dict[str, Any] = dict(state.get("cursors") or {})
        sources = rotate(sources, stores, state.get("rotation"))
        indexes = indexes_for(config, clients, state)
        if indexes is not None:
            indexes.scope = account  # copies across this account's stores are read once (#67)
        with_indexes(sources, indexes)
        mode = config.scan_mode
        importer = (
            MacieImporter(clients, region, mode, lookback_days=config.macie_lookback_days)
            if mode != SCANNER
            else None
        )
        if mode == VENDOR:
            # #55: Macie's findings stand for S3; this scanner reads nothing, and every
            # other kind is what Macie does not cover.
            for st in stores:
                if st.status == "pending":
                    st.skip("vendor_mode" if st.kind == "s3" else "vendor_not_covered")
            sources = []
        in_scope = {s.id for s in sources} | ({importer.id} if importer is not None else set())
        store = FindingStore(started.isoformat())
        for f in state.get("findings") or []:
            loc = f.get("_location", "")
            if loc.split("\n", 1)[0] in in_scope:
                store.items[f["id"]] = f
        if config.max_run_seconds:
            deadline = min(deadline, clock() + config.max_run_seconds)
        budget = Budget(config.max_items_per_run, config.max_bytes_per_run, deadline, clock)
        vendor_coverage: list[VendorCoverage] = []
        if importer is not None:
            # First, and apart from the scanner's share: importing reads findings, not data.
            imported, cursors[importer.id] = importer.run(
                cursors.get(importer.id) or {}, budget, store, started
            )
            vendor_coverage.append(imported)
        caps = {
            "s3": config.max_objects_per_run,
            "s3_directory": config.max_objects_per_run,
            "glue_table": config.max_objects_per_run,
            "cloudwatch_logs": config.max_log_events_per_run,
            "dynamodb": config.max_table_items_per_run,
        }
        kinds = {
            k: Budget(n, config.max_bytes_per_run, deadline, clock) for k, n in caps.items() if n
        }
        left = {k: sum(1 for s in sources if s.kind == k) for k in caps}
        coverage: list[Coverage] = []
        by_source: dict[str, Coverage] = {}
        notes: dict[str, tuple[str | None, dict[str, Any]]] = {}
        deferred: str | None = None
        for i, source in enumerate(sources):
            kind_budget = kinds.get(source.kind)
            ways = left.get(source.kind, 1)
            left[source.kind] = max(0, ways - 1)
            if budget.exhausted() or (kind_budget is not None and kind_budget.exhausted()):
                deferred = deferred or source.id
                log_event("source.deferred", source=source.target, kind=source.kind)
                continue
            share = budget.share(len(sources) - i)
            if kind_budget is not None:
                share.max_items = min(share.max_items, kind_budget.share(ways).max_items)
            log_event("source.start", source=source.target, kind=source.kind)
            cursor = relist(source, cursors.get(source.id) or {}, indexes)
            result = source.run(cursor, share, detector, store, started)
            listed_with(source, result, indexes, cursor)
            if isinstance(source, S3Source) and result.coverage.error is None:
                source.prune(store, share)
            budget.absorb(share)
            if kind_budget is not None:
                kind_budget.absorb(share)
            cursors[source.id] = result.cursor
            coverage.append(result.coverage)
            by_source[source.id] = result.coverage
            notes[source.id] = (result.note, result.extra)
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
                got = [notes[i] for i in st.source_ids if i in notes]
                extra: dict[str, Any] = {}
                for _, e in got:
                    extra.update(e)
                settle(st, covs, [n for n, _ in got], extra)
            elif st.status == "pending" and st.source_ids:
                st.status = "deferred"
                st.reason = "budget"
        run_summary = (
            summary(stores, found.list_errors if found else {}) if config.discover else None
        )
        public = store.public()
        if mode == BOTH:
            link_duplicates(public)
        doc = findings_document(
            run_id=run_id,
            account=account,
            region=region,
            started_at=started.isoformat(),
            finished_at=now().isoformat(),
            classes=list(load_spec().class_order),
            coverage=coverage,
            findings=public,
            discovery=run_summary,
            scan_mode={"aws": mode},
            vendor_coverage=[v.as_json() for v in vendor_coverage] if importer else None,
        )
        new_state: dict[str, Any] = {
            "version": STATE_VERSION,
            "cursors": cursors,
            "findings": list(store.items.values()),
            "lastRunAt": started.isoformat(),
            "rotation": deferred,
        }
        if indexes is not None:
            indexes.save()
            new_state["indexSalt"] = indexes.salt
        _put_json(clients.s3, bucket, keys.state, new_state)
        _put_json(clients.s3, bucket, f"{keys.runs}{run_id}.json", doc)
        _put_json(clients.s3, bucket, keys.latest, doc)
        if config.event_bus_arn and clients.events is not None:
            put_findings_events(clients.events, config.event_bus_arn, doc)
        log_event(
            "run.done",
            findings=doc["findingsTotal"],
            **{f"total_{k}": v for k, v in doc["totals"].items()},
        )
        return doc
    except ScanError:
        raise
    except Exception as err:
        name = error_name(err)
        log_event("run.failed", error=name)
        raise ScanError(name) from None
    finally:
        try:
            clients.s3.delete_object(Bucket=bucket, Key=keys.lock)
        except Exception as err:  # a stale lock expires by itself
            log_event("run.failed", error=error_name(err))
