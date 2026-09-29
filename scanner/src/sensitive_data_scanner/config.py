"""The scanner's configuration, from environment variables. Nothing here is secret."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field


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
    )
