"""The scanner's configuration, from environment variables. Nothing here is secret."""

from __future__ import annotations

import fnmatch
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


def _choice(v: str | None, allowed: tuple[str, ...], default: str) -> str:
    t = (v or "").strip().lower() or default
    if t not in allowed:
        raise ValueError("a setting has a value it does not accept")
    return t


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
    {
        "table",
        "partition",
        "sortPrefix",
        "include",
        "exclude",
        "keypad",
        "prompts",
        "planted",
        "orderBy",
    }
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
    order_by: str | None = None


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
        order_by = t.get("orderBy")
        if order_by is not None and (not isinstance(order_by, str) or not order_by.strip()):
            raise ValueError("SCAN_DYNAMODB: orderBy must be an attribute name")
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
                order_by=order_by,
            )
        )
    return out


# Discovery: which kinds of store to list, and the allow and deny overrides.
DISCOVER_KINDS = {
    "s3": "s3",
    "logs": "cloudwatch_logs",
    "dynamodb": "dynamodb",
    "glue": "glue_table",
    "rds": "rds",
    "redshift": "redshift",
}
_KIND_ALIASES = {
    "s3": "s3",
    "logs": "cloudwatch_logs",
    "cloudwatch_logs": "cloudwatch_logs",
    "dynamodb": "dynamodb",
    "glue": "glue_table",
    "glue_table": "glue_table",
    "rds": "rds",
    "redshift": "redshift",
}


def discover_kinds(raw: str | None) -> frozenset[str]:
    """`DISCOVER`: `all`, or a comma-separated list of the kinds in DISCOVER_KINDS (`s3`,
    `logs`, `dynamodb`, `glue`, `rds`, `redshift`, ...). Empty: off."""
    names = [n.lower() for n in _list(raw)]
    if not names or names == ["none"]:
        return frozenset()
    if "all" in names:
        return frozenset(DISCOVER_KINDS.values())
    out = set()
    for n in names:
        if n not in DISCOVER_KINDS:
            raise ValueError("DISCOVER: unknown kind of store")
        out.add(DISCOVER_KINDS[n])
    return frozenset(out)


@dataclass(frozen=True)
class StoreRule:
    """One allow or deny rule: a name glob, or a tag, optionally for one kind of store.

    `s3:prod-*`, `logs:/aws/lambda/*`, `dynamodb:orders`, `*-archive` (any kind),
    `tag:scan=false`, `tag:pii` (any value), `s3:tag:team=data*`.
    """

    kind: str | None = None
    name: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None

    @property
    def needs_tags(self) -> bool:
        return self.tag_key is not None

    def matches(self, kind: str, name: str, tags: dict[str, str] | None) -> bool:
        if self.kind is not None and self.kind != kind:
            return False
        if self.name is not None:
            return fnmatch.fnmatchcase(name, self.name)
        if self.tag_key is None or tags is None or self.tag_key not in tags:
            return False
        return self.tag_value is None or fnmatch.fnmatchcase(tags[self.tag_key], self.tag_value)


def parse_rule(text: str) -> StoreRule:
    t = text.strip()
    kind: str | None = None
    head, sep, rest = t.partition(":")
    if sep and head.lower() in _KIND_ALIASES:
        kind = _KIND_ALIASES[head.lower()]
        t = rest
    elif sep and head == "*":
        t = rest
    if t.startswith("tag:"):
        key, eq, value = t[4:].partition("=")
        if not key:
            raise ValueError("discovery rule: a tag rule needs a key")
        return StoreRule(kind=kind, tag_key=key, tag_value=value if eq else None)
    if not t:
        raise ValueError("discovery rule: empty pattern")
    return StoreRule(kind=kind, name=t)


def store_rules(raw: str | None) -> tuple[StoreRule, ...]:
    """`DISCOVER_ALLOW` / `DISCOVER_DENY`: comma-separated rules (StoreRule)."""
    return tuple(parse_rule(r) for r in _list(raw))


@dataclass(frozen=True)
class SamplingRule:
    """Per-store sampling: the first rule whose `match` fits a store sets its sampling."""

    match: StoreRule
    sample_percent: int | None = None
    max_objects_per_prefix: int | None = None


_SAMPLING_FIELDS = frozenset({"match", "samplePercent", "maxObjectsPerPrefix"})


def sampling_rules(raw: str | None) -> tuple[SamplingRule, ...]:
    """`DISCOVER_SAMPLING`: a JSON list of `{"match", "samplePercent", "maxObjectsPerPrefix"}`."""
    if not raw or not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("DISCOVER_SAMPLING is not valid JSON") from None
    if not isinstance(data, list):
        raise ValueError("DISCOVER_SAMPLING must be a JSON list")
    out = []
    for r in data:
        if not isinstance(r, dict) or set(r) - _SAMPLING_FIELDS or "match" not in r:
            raise ValueError("DISCOVER_SAMPLING: each entry needs match, and nothing unknown")
        if not isinstance(r["match"], str):
            raise ValueError("DISCOVER_SAMPLING: match must be a string")
        pct = r.get("samplePercent")
        per = r.get("maxObjectsPerPrefix")
        if pct is not None and (not isinstance(pct, int) or not 1 <= pct <= 100):
            raise ValueError("DISCOVER_SAMPLING: samplePercent must be 1-100")
        if per is not None and (not isinstance(per, int) or per < 0):
            raise ValueError("DISCOVER_SAMPLING: maxObjectsPerPrefix must be 0 or more")
        out.append(SamplingRule(parse_rule(r["match"]), pct, per))
    return tuple(out)


_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[A-Za-z0-9:/_.+=,@!-]{1,1600}$")
_DATA_API_FIELDS = frozenset(
    {"clusterArn", "secretArn", "database", "engine", "schemas", "maxRowsPerTable", "maxTables"}
)


@dataclass(frozen=True)
class DataApiTarget:
    """An Aurora cluster read with the RDS Data API (opt-in, for small databases)."""

    cluster_arn: str
    secret_arn: str
    database: str
    engine: str  # postgresql | mysql
    schemas: tuple[str, ...] = ()
    max_rows_per_table: int = 1000
    max_tables: int = 200


def data_api_targets(raw: str | None) -> list[DataApiTarget]:
    """`RDS_DATA_API`: a JSON list of clusters to read with read-only SQL (off by default)."""
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("RDS_DATA_API is not valid JSON") from None
    if not isinstance(data, list):
        raise ValueError("RDS_DATA_API must be a JSON list")
    out = []
    for t in data:
        if not isinstance(t, dict) or set(t) - _DATA_API_FIELDS:
            raise ValueError("RDS_DATA_API: unknown field in an entry")
        for k in ("clusterArn", "secretArn"):
            if not isinstance(t.get(k), str) or not _ARN.match(t[k]):
                raise ValueError("RDS_DATA_API: clusterArn and secretArn must be ARNs")
        if not isinstance(t.get("database"), str) or not t["database"]:
            raise ValueError("RDS_DATA_API: database is required")
        engine = t.get("engine")
        if engine not in ("postgresql", "mysql"):
            raise ValueError("RDS_DATA_API: engine must be postgresql or mysql")
        schemas = t.get("schemas") or []
        if not isinstance(schemas, list) or not all(isinstance(x, str) for x in schemas):
            raise ValueError("RDS_DATA_API: schemas must be a list of names")
        rows = t.get("maxRowsPerTable", 1000)
        tables = t.get("maxTables", 200)
        if not isinstance(rows, int) or not 1 <= rows <= 100_000:
            raise ValueError("RDS_DATA_API: maxRowsPerTable must be 1-100000")
        if not isinstance(tables, int) or not 1 <= tables <= 10_000:
            raise ValueError("RDS_DATA_API: maxTables must be 1-10000")
        out.append(
            DataApiTarget(
                cluster_arn=t["clusterArn"],
                secret_arn=t["secretArn"],
                database=t["database"],
                engine=engine,
                schemas=tuple(schemas),
                max_rows_per_table=rows,
                max_tables=tables,
            )
        )
    return out


def _arn(v: str | None) -> str | None:
    t = (v or "").strip()
    if not t:
        return None
    if not _ARN.match(t):
        raise ValueError("a setting that takes an ARN has something else")
    return t


_DB_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,126}$")


def _db_user(v: str | None) -> str | None:
    t = (v or "").strip()
    if not t:
        return None
    if not _DB_USER.match(t):
        raise ValueError("REDSHIFT_DB_USER is not a database user name")
    return t


def _bool(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


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
    # Discovery (off unless `DISCOVER` names kinds of store).
    discover: frozenset[str] = frozenset()
    allow: tuple[StoreRule, ...] = ()
    deny: tuple[StoreRule, ...] = ()
    sampling: tuple[SamplingRule, ...] = ()
    self_log_group: str | None = None
    dynamodb_sample_percent: int = 100
    dynamodb_max_table_bytes: int = 10 * 1024**3
    s3_max_objects_per_prefix: int = 0
    # Per-kind shares of the run budget (0: only the overall MAX_ITEMS_PER_RUN).
    max_objects_per_run: int = 0
    max_log_events_per_run: int = 0
    max_table_items_per_run: int = 0
    max_run_seconds: int = 0
    # Columnar and data-lake formats.
    columnar_max_rows: int = 10_000
    glue_lake_formation: str = "read"  # read (with the scanner's own IAM) | skip
    # Exports: RDS and Aurora snapshots, and large DynamoDB tables, to the results
    # bucket's exports/ prefix; scanned as Parquet or DynamoDB JSON, then deleted.
    rds_export_role_arn: str | None = None
    rds_export_kms_key_arn: str | None = None
    max_exports_per_run: int = 1
    export_min_interval_days: int = 7
    dynamodb_export: bool = False
    dynamodb_export_kms_key_arn: str | None = None
    data_api_targets: list[DataApiTarget] = field(default_factory=list)
    # Redshift and Redshift Serverless: read through the Redshift Data API with
    # sampled SELECTs. Off: discovered and reported, not read.
    redshift_read: str = "off"  # off | iam | db_user
    redshift_db_user: str | None = None
    redshift_max_rows: int = 1000
    redshift_max_tables: int = 500
    redshift_statement_seconds: int = 60

    @property
    def exports_prefix(self) -> str:
        return f"{self.results_prefix}exports/"

    def sampling_for(
        self, kind: str, name: str, tags: dict[str, str] | None
    ) -> tuple[int | None, int | None]:
        """(samplePercent, maxObjectsPerPrefix) from the first matching sampling rule."""
        for r in self.sampling:
            if r.match.matches(kind, name, tags):
                return r.sample_percent, r.max_objects_per_prefix
        return None, None


def read_config(env: Mapping[str, str] | None = None) -> Config:
    e = os.environ if env is None else env
    bucket = e.get("RESULTS_BUCKET", "")
    if not bucket:
        raise ValueError("RESULTS_BUCKET is not set")
    prefix = e.get("RESULTS_PREFIX", "").strip("/")
    config = Config(
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
        discover=discover_kinds(e.get("DISCOVER")),
        allow=store_rules(e.get("DISCOVER_ALLOW")),
        deny=store_rules(e.get("DISCOVER_DENY")),
        sampling=sampling_rules(e.get("DISCOVER_SAMPLING")),
        self_log_group=e.get("AWS_LAMBDA_LOG_GROUP_NAME") or None,
        dynamodb_sample_percent=_int(e.get("DYNAMODB_SAMPLE_PERCENT"), 100, 1, 100),
        dynamodb_max_table_bytes=_int(e.get("DYNAMODB_MAX_TABLE_BYTES"), 10 * 1024**3, 0, 1024**5),
        s3_max_objects_per_prefix=_int(e.get("S3_MAX_OBJECTS_PER_PREFIX"), 0, 0, 1_000_000),
        max_objects_per_run=_int(e.get("MAX_OBJECTS_PER_RUN"), 0, 0, 1_000_000),
        max_log_events_per_run=_int(e.get("MAX_LOG_EVENTS_PER_RUN"), 0, 0, 1_000_000),
        max_table_items_per_run=_int(e.get("MAX_TABLE_ITEMS_PER_RUN"), 0, 0, 1_000_000),
        max_run_seconds=_int(e.get("MAX_RUN_SECONDS"), 0, 0, 24 * 3600),
        columnar_max_rows=_int(e.get("COLUMNAR_MAX_ROWS"), 10_000, 1, 10_000_000),
        glue_lake_formation=_choice(e.get("GLUE_LAKE_FORMATION"), ("read", "skip"), "read"),
        rds_export_role_arn=_arn(e.get("RDS_EXPORT_ROLE_ARN")),
        rds_export_kms_key_arn=_arn(e.get("RDS_EXPORT_KMS_KEY_ARN")),
        max_exports_per_run=_int(e.get("MAX_EXPORTS_PER_RUN"), 1, 0, 20),
        export_min_interval_days=_int(e.get("EXPORT_MIN_INTERVAL_DAYS"), 7, 0, 365),
        dynamodb_export=_bool(e.get("DYNAMODB_EXPORT")),
        dynamodb_export_kms_key_arn=_arn(e.get("DYNAMODB_EXPORT_KMS_KEY_ARN")),
        data_api_targets=data_api_targets(e.get("RDS_DATA_API")),
        redshift_read=_choice(
            (e.get("REDSHIFT_READ") or "").replace("-", "_"), ("off", "iam", "db_user"), "off"
        ),
        redshift_db_user=_db_user(e.get("REDSHIFT_DB_USER")),
        redshift_max_rows=_int(e.get("REDSHIFT_MAX_ROWS_PER_TABLE"), 1000, 1, 100_000),
        redshift_max_tables=_int(e.get("REDSHIFT_MAX_TABLES"), 500, 1, 10_000),
        redshift_statement_seconds=_int(e.get("REDSHIFT_STATEMENT_TIMEOUT_SECONDS"), 60, 5, 600),
    )
    if config.redshift_read == "db_user" and not config.redshift_db_user:
        raise ValueError("REDSHIFT_READ=db_user needs REDSHIFT_DB_USER")
    return config
