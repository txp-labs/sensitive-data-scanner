"""The batch runner: one scheduled scan of the S3 prefixes and log groups named.

It runs in the account it scans. It reads the stores it was given, and writes
to its results bucket only:

- `findings/latest.json` and `findings/runs/<runId>.json`: the findings
  document (schema/findings.schema.json);
- `state/scanner-state.json`: each source's cursor and the findings carried
  between runs, for the next run only (a consumer never needs it);
- `state/lock.json`: one run at a time.

With `FINDINGS_EVENT_BUS_ARN` set, it also sends the findings as EventBridge
events to that bus (events.py).
"""

from __future__ import annotations

import datetime as _dt
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from .config import Config
from .detect.analyzer import Detector
from .engine.spec import load_spec
from .events import put_findings_events
from .findings import Coverage, findings_document
from .safety import ScanError, error_name, log_event
from .sources.base import Budget, FindingStore, SourceRun
from .sources.cloudwatch_logs import CloudWatchLogsSource
from .sources.s3 import S3Source

if TYPE_CHECKING:
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_logs import CloudWatchLogsClient
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


class Keys:
    def __init__(self, prefix: str) -> None:
        self.latest = f"{prefix}findings/latest.json"
        self.runs = f"{prefix}findings/runs/"
        self.state = f"{prefix}state/scanner-state.json"
        self.lock = f"{prefix}state/lock.json"


def _read_json(s3: S3Client, bucket: str, key: str) -> Any:
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as err:
        if error_name(err) in ("NoSuchKey", "404", "NotFound"):
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


def build_sources(config: Config, clients: Clients, region: str) -> list[Any]:
    sources: list[Any] = [
        S3Source(
            clients.s3,
            bucket=b,
            prefix=p,
            region=region,
            sample_percent=config.sample_percent,
            max_object_bytes=config.max_object_bytes,
            max_inflated_bytes=config.max_inflated_bytes,
            skew_seconds=config.s3_skew_seconds,
        )
        for b, p in config.s3_targets
    ]
    sources.extend(
        CloudWatchLogsSource(
            clients.logs, log_group=g, region=region, lookback_days=config.logs_lookback_days
        )
        for g in config.log_groups
    )
    return sources


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
        sources = build_sources(config, clients, region)
        log_event("run.start", sources=len(sources))
        state = _read_json(clients.s3, bucket, keys.state) or {}
        if state and state.get("version") != STATE_VERSION:
            log_event("state.reset")
            state = {}
        cursors: dict[str, Any] = dict(state.get("cursors") or {})
        in_scope = {s.id for s in sources}
        store = FindingStore(started.isoformat())
        for f in state.get("findings") or []:
            loc = f.get("_location", "")
            if loc.split("\n", 1)[0] in in_scope:
                store.items[f["id"]] = f
        budget = Budget(config.max_items_per_run, config.max_bytes_per_run, deadline, clock)
        coverage: list[Coverage] = []
        for i, source in enumerate(sources):
            share = budget.share(len(sources) - i)
            log_event("source.start", source=source.target, kind=source.kind)
            result = source.run(cursors.get(source.id) or {}, share, detector, store, started)
            if isinstance(source, S3Source) and result.coverage.error is None:
                source.prune(store, share)
            budget.absorb(share)
            cursors[source.id] = result.cursor
            coverage.append(result.coverage)
            log_event(
                "source.done",
                source=source.target,
                scanned=result.coverage.scanned,
                passComplete=result.coverage.pass_complete,
                error=result.coverage.error,
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
