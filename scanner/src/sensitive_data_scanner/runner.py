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

from .config import Config, DynamoTarget
from .detect.analyzer import Detector
from .discovery import Discovery, Store, discover, settle, summary
from .engine.spec import load_spec
from .events import put_findings_events
from .findings import Coverage, findings_document
from .safety import ScanError, error_name, is_kms_denial, log_event
from .sources.base import Budget, Context, FindingStore, SourceRun
from .sources.cloudwatch_logs import CloudWatchLogsSource
from .sources.dynamodb import DynamoDBSource
from .sources.dynamodb_export import DynamoDBExportSource
from .sources.exports import ExportQuota
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
    return S3Source(
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
    )


def _dynamodb_source(
    config: Config, clients: Clients, region: str, store: Store, target: DynamoTarget
) -> DynamoDBSource:
    if clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    return DynamoDBSource(
        clients.dynamodb,
        target=target,
        region=region,
        page_size=config.dynamodb_page_size,
        max_pages=config.dynamodb_max_pages,
        sample_percent=store.sample_percent or config.dynamodb_sample_percent,
    )


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
        add(
            store,
            CloudWatchLogsSource(
                clients.logs,
                log_group=group,
                region=region,
                lookback_days=config.logs_lookback_days,
            ),
        )
    if config.dynamodb_targets and clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    for t in config.dynamodb_targets:
        store = named("dynamodb", t.table)
        add(store, _dynamodb_source(config, clients, region, store, t))
    if config.data_api_targets and clients.rds_data is None:
        raise ValueError("no RDS Data API client")
    for d in config.data_api_targets:
        src = RdsDataApiSource(clients.rds_data, target=d, region=region)  # type: ignore[arg-type]
        store = named("rds", src.identifier)
        store.extra["readBy"] = "data_api"
        add(store, src)
    quota = ExportQuota(config.max_exports_per_run)
    if discovery is None:
        return sources, stores
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
            add(
                store,
                CloudWatchLogsSource(
                    clients.logs,
                    log_group=store.name,
                    region=region,
                    lookback_days=config.logs_lookback_days,
                ),
            )
        elif store.kind == "dynamodb" and store.extra.get("readBy") != "export":
            add(store, _dynamodb_source(config, clients, region, store, DynamoTarget(store.name)))
        elif store.kind in ADAPTERS:
            found_source = ADAPTERS[store.kind].source(ctx, store)
            for one in found_source if isinstance(found_source, list) else [found_source]:
                if one is not None:
                    add(store, one)
    return sources, stores


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
        in_scope = {s.id for s in sources}
        store = FindingStore(started.isoformat())
        for f in state.get("findings") or []:
            loc = f.get("_location", "")
            if loc.split("\n", 1)[0] in in_scope:
                store.items[f["id"]] = f
        if config.max_run_seconds:
            deadline = min(deadline, clock() + config.max_run_seconds)
        budget = Budget(config.max_items_per_run, config.max_bytes_per_run, deadline, clock)
        caps = {
            "s3": config.max_objects_per_run,
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
            result = source.run(cursors.get(source.id) or {}, share, detector, store, started)
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
        doc = findings_document(
            run_id=run_id,
            account=account,
            region=region,
            started_at=started.isoformat(),
            finished_at=now().isoformat(),
            classes=list(load_spec().class_order),
            coverage=coverage,
            findings=store.public(),
            discovery=run_summary,
        )
        _put_json(
            clients.s3,
            bucket,
            keys.state,
            {
                "version": STATE_VERSION,
                "cursors": cursors,
                "findings": list(store.items.values()),
                "lastRunAt": started.isoformat(),
                "rotation": deferred,
            },
        )
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
