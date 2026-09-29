"""The scanner's configuration, from environment variables. Nothing here is secret."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .scan.paths import parse_path


def _list(v: str | None) -> list[str]:
    return [s.strip() for s in (v or "").split(",") if s.strip()]


def _int(v: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int(float(v)) if v is not None and v != "" else default
    except ValueError:
        n = default
    return max(lo, min(hi, n))


def s3_targets(buckets: list[str], prefixes: list[str]) -> list[tuple[str, str]]:
    """`SCAN_BUCKETS=a,b` and `SCAN_PREFIXES=a/connect/x/` give a/connect/x/ and b (whole)."""
    out: list[tuple[str, str]] = []
    for bucket in dict.fromkeys(buckets):
        mine = [p[len(bucket) + 1 :] for p in prefixes if p.startswith(f"{bucket}/")]
        if not mine or "" in mine:
            out.append((bucket, ""))
        else:
            out.extend((bucket, p) for p in dict.fromkeys(mine))
    return out


_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_TARGET_FIELDS = frozenset(
    {"table", "partition", "sortPrefix", "include", "exclude", "keypad", "prompts", "planted"}
)


@dataclass(frozen=True)
class DynamoTarget:
    """One DynamoDB read: a Query of one partition (optionally a sort-key prefix), or a Scan.

    The attribute paths use `.` for map keys and `[]` for every list element:
    `stepResults[].observedDtmf`. A path covers everything under it.
    """

    table: str
    partition: str | None = None
    sort_prefix: str | None = None
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    keypad: tuple[str, ...] = ()
    prompts: tuple[str, ...] = ()
    planted: tuple[str, ...] = ()


def _paths(v: Any) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
        raise ValueError("SCAN_DYNAMODB: attribute paths must be a list of strings")
    for x in v:
        parse_path(x)
    return tuple(x.strip() for x in v)


def dynamodb_targets(raw: str | None) -> list[DynamoTarget]:
    """`SCAN_DYNAMODB`: a JSON list of tables to read (docs/ARCHITECTURE.md)."""
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("SCAN_DYNAMODB is not valid JSON") from None
    if not isinstance(data, list):
        raise ValueError("SCAN_DYNAMODB must be a JSON list")
    out: list[DynamoTarget] = []
    for t in data:
        if not isinstance(t, dict) or set(t) - _TARGET_FIELDS:
            raise ValueError("SCAN_DYNAMODB: unknown field in a table entry")
        table = t.get("table")
        if not isinstance(table, str) or not _TABLE_NAME.match(table):
            raise ValueError("SCAN_DYNAMODB: invalid table name")
        partition = t.get("partition")
        sort_prefix = t.get("sortPrefix")
        if partition is not None and not isinstance(partition, str | int):
            raise ValueError("SCAN_DYNAMODB: partition must be a string or a number")
        if sort_prefix is not None and (partition is None or not isinstance(sort_prefix, str)):
            raise ValueError("SCAN_DYNAMODB: sortPrefix needs a partition and must be a string")
        out.append(
            DynamoTarget(
                table=table,
                partition=None if partition is None else str(partition),
                sort_prefix=sort_prefix,
                include=_paths(t.get("include")),
                exclude=_paths(t.get("exclude")),
                keypad=_paths(t.get("keypad")),
                prompts=_paths(t.get("prompts")),
                planted=_paths(t.get("planted")),
            )
        )
    return out


@dataclass(frozen=True)
class Config:
    results_bucket: str
    results_prefix: str = ""
    s3_targets: list[tuple[str, str]] = field(default_factory=list)
    log_groups: list[str] = field(default_factory=list)
    sample_percent: int = 100
    logs_lookback_days: int = 7
    max_items_per_run: int = 20_000
    max_bytes_per_run: int = 2 * 1024**3
    max_object_bytes: int = 20 * 1024**2
    max_inflated_bytes: int = 100 * 1024**2
    event_bus_arn: str | None = None
    s3_skew_seconds: int = 300
    dynamodb_targets: list[DynamoTarget] = field(default_factory=list)
    dynamodb_page_size: int = 100
    dynamodb_max_pages: int = 200


def read_config(env: Mapping[str, str] | None = None) -> Config:
    e = os.environ if env is None else env
    bucket = e.get("RESULTS_BUCKET", "")
    if not bucket:
        raise ValueError("RESULTS_BUCKET is not set")
    prefix = e.get("RESULTS_PREFIX", "").strip("/")
    return Config(
        results_bucket=bucket,
        results_prefix=f"{prefix}/" if prefix else "",
        s3_targets=s3_targets(_list(e.get("SCAN_BUCKETS")), _list(e.get("SCAN_PREFIXES"))),
        log_groups=list(dict.fromkeys(_list(e.get("SCAN_LOG_GROUPS")))),
        sample_percent=_int(e.get("S3_SAMPLE_PERCENT"), 100, 1, 100),
        logs_lookback_days=_int(e.get("LOGS_LOOKBACK_DAYS"), 7, 1, 90),
        max_items_per_run=_int(e.get("MAX_ITEMS_PER_RUN"), 20_000, 1, 1_000_000),
        max_bytes_per_run=_int(e.get("MAX_BYTES_PER_RUN"), 2 * 1024**3, 1024, 50 * 1024**3),
        max_object_bytes=_int(e.get("MAX_OBJECT_BYTES"), 20 * 1024**2, 1024, 200 * 1024**2),
        max_inflated_bytes=_int(e.get("MAX_INFLATED_BYTES"), 100 * 1024**2, 1024, 500 * 1024**2),
        event_bus_arn=e.get("FINDINGS_EVENT_BUS_ARN") or None,
        s3_skew_seconds=_int(e.get("S3_CLOCK_SKEW_SECONDS"), 300, 0, 3600),
        dynamodb_targets=dynamodb_targets(e.get("SCAN_DYNAMODB")),
        dynamodb_page_size=_int(e.get("DYNAMODB_PAGE_SIZE"), 100, 1, 1000),
        dynamodb_max_pages=_int(e.get("DYNAMODB_MAX_PAGES"), 200, 1, 100_000),
    )
