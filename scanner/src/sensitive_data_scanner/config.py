"""The scanner's configuration. Nothing here is secret.

It comes from environment variables, and, because Lambda holds only 4 KB of
those, also from a configuration document: the invoke payload's `config`, or
a JSON file named by `CONFIG_LOCATION` (or the payload's `configLocation`) in
S3 or SSM Parameter Store. A document uses the environment variables' names;
what it sets wins over the environment, and the payload wins over the file.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.modes import SCANNER, read_mode
from sensitive_data_core.rules import SamplingRule, StoreRule, sampling_for
from sensitive_data_core.rules import parse_rule as _parse_rule
from sensitive_data_core.rules import sampling_rules as _sampling_rules
from sensitive_data_core.rules import store_rules as _store_rules
from sensitive_data_core.scan.paths import parse_path


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
        # Without a partition, a sort-key prefix filters a whole-table Scan (begins_with).
        if sort_prefix is not None and (not isinstance(sort_prefix, str) or not sort_prefix):
            raise ValueError("SCAN_DYNAMODB: sortPrefix must be a non-empty string")
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
    "opensearch": "opensearch",
    "documentdb": "documentdb",
    "neptune": "neptune",
    "ebs": "ebs",
    "backup": "backup",
    "efs": "efs",
    "fsx": "fsx",
    "kinesis": "kinesis",
    "firehose": "firehose",
    "sqs": "sqs",
    "ssm": "ssm",
    "secretsmanager": "secretsmanager",
    "elasticache": "elasticache",
    "memorydb": "memorydb",
    "timestream": "timestream",
    "keyspaces": "keyspaces",
    "stepfunctions": "stepfunctions",
    "lambda": "lambda",
    "xray": "xray",
    "codecommit": "codecommit",
    "s3express": "s3_directory",
    "s3_directory": "s3_directory",
    "msk": "msk",
    "mq": "mq",
    "ecr": "ecr",
    "sagemaker": "sagemaker",
    "neptune_analytics": "neptune_analytics",
    "neptune-analytics": "neptune_analytics",
    "eventbridge": "eventbridge_archive",
    "glacier": "glacier",
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
    "opensearch": "opensearch",
    "documentdb": "documentdb",
    "neptune": "neptune",
    "ebs": "ebs",
    "backup": "backup",
    "efs": "efs",
    "fsx": "fsx",
    "kinesis": "kinesis",
    "firehose": "firehose",
    "sqs": "sqs",
    "ssm": "ssm",
    "secretsmanager": "secretsmanager",
    "secrets": "secretsmanager",
    "elasticache": "elasticache",
    "memorydb": "memorydb",
    "timestream": "timestream",
    "keyspaces": "keyspaces",
    "stepfunctions": "stepfunctions",
    "states": "stepfunctions",
    "lambda": "lambda",
    "xray": "xray",
    "codecommit": "codecommit",
    "s3express": "s3_directory",
    "s3_directory": "s3_directory",
    "msk": "msk",
    "kafka": "msk",
    "mq": "mq",
    "ecr": "ecr",
    "sagemaker": "sagemaker",
    "neptune_analytics": "neptune_analytics",
    "neptune-analytics": "neptune_analytics",
    "eventbridge": "eventbridge_archive",
    "eventbridge_archive": "eventbridge_archive",
    "glacier": "glacier",
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


def parse_rule(text: str) -> StoreRule:
    return _parse_rule(text, _KIND_ALIASES)


def store_rules(raw: str | None) -> tuple[StoreRule, ...]:
    """`DISCOVER_ALLOW` / `DISCOVER_DENY`: comma-separated rules (StoreRule)."""
    return _store_rules(raw, _KIND_ALIASES)


def sampling_rules(raw: str | None) -> tuple[SamplingRule, ...]:
    """`DISCOVER_SAMPLING`: a JSON list of `{"match", "samplePercent", "maxObjectsPerPrefix"}`."""
    return _sampling_rules(raw, _KIND_ALIASES)


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


@dataclass(frozen=True)
class MqTarget:
    """One ActiveMQ broker to browse: its name, the secret holding a read-only user, and the
    queues to browse."""

    broker: str
    secret_arn: str
    queues: tuple[str, ...] = ()


_MQ_FIELDS = frozenset({"broker", "secretArn", "queues"})
_QUEUE = re.compile(r"^[A-Za-z0-9_.:/-]{1,255}$")


def mq_brokers(raw: str | None) -> list[MqTarget]:
    """`MQ_BROKERS`: a JSON list of ActiveMQ brokers to browse, each with the secret of a
    read-only user and the queues to browse (opt-in, with `MQ_READ`)."""
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("MQ_BROKERS is not valid JSON") from None
    if not isinstance(data, list):
        raise ValueError("MQ_BROKERS must be a JSON list")
    out = []
    for t in data:
        if not isinstance(t, dict) or set(t) - _MQ_FIELDS:
            raise ValueError("MQ_BROKERS: unknown field in an entry")
        if not isinstance(t.get("broker"), str) or not t["broker"]:
            raise ValueError("MQ_BROKERS: broker is required")
        if not isinstance(t.get("secretArn"), str) or not _ARN.match(t["secretArn"]):
            raise ValueError("MQ_BROKERS: secretArn must be an ARN")
        queues = t.get("queues") or []
        if not isinstance(queues, list) or not all(
            isinstance(q, str) and _QUEUE.match(q) for q in queues
        ):
            raise ValueError("MQ_BROKERS: queues must be a list of queue names")
        out.append(MqTarget(t["broker"], t["secretArn"], tuple(queues)))
    return out


def _arn(v: str | None) -> str | None:
    t = (v or "").strip()
    if not t:
        return None
    if not _ARN.match(t):
        raise ValueError("a setting that takes an ARN has something else")
    return t


_QUEUE_URL = re.compile(r"^https://sqs\.[a-z0-9-]+\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}$")


def _queue_url(v: str | None) -> str | None:
    t = (v or "").strip()
    if not t:
        return None
    if not _QUEUE_URL.match(t):
        raise ValueError("EVENTBRIDGE_REPLAY_QUEUE_URL is not an SQS queue URL")
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
    # OpenSearch: documents sampled per index, and indices per domain. Serverless
    # collections are read only when turned on (their data access policy decides).
    opensearch_docs_per_index: int = 100
    opensearch_max_indices: int = 500
    opensearch_serverless_read: bool = False
    # EBS: read snapshots' blocks with the EBS direct APIs (opt-in), sampled.
    ebs_direct_read: bool = False
    ebs_blocks_per_snapshot: int = 256
    # Kinesis: records sampled per shard from TRIM_HORIZON, and shards per stream.
    kinesis_records_per_shard: int = 100
    kinesis_max_shards: int = 50
    # SQS: dead-letter queues are received from (VisibilityTimeout=0) only when on.
    sqs_dlq_read: bool = False
    sqs_messages_per_queue: int = 100
    # SSM Parameter Store: SecureString values are decrypted through SSM unless off.
    # Secrets Manager: listed always, read only when on.
    ssm_decrypt: bool = True
    secrets_read: bool = False
    # Timestream and Keyspaces: one sampled read-only query per table.
    timestream_max_rows: int = 1000
    timestream_lookback_days: int = 1
    keyspaces_max_rows: int = 1000
    # Group 7, read by default (#35): Step Functions executions sampled per state machine and
    # events per execution; X-Ray traces per run and how far back; CodeCommit files and
    # folders per repository. The scanner's own function (Lambda sets its name) is never read.
    stepfunctions_executions: int = 20
    stepfunctions_events: int = 500
    xray_max_traces: int = 100
    xray_lookback_hours: int = 24
    codecommit_max_files: int = 200
    codecommit_max_folders: int = 500
    self_function: str | None = None
    # Opt-in brokers (#35): MSK read with IAM authentication, sampled per partition and never
    # committed; ActiveMQ queues browsed, never consumed, with a checked read-only user.
    msk_read: bool = False
    msk_records_per_partition: int = 100
    msk_max_topics: int = 50
    msk_max_partitions: int = 50
    mq_read: bool = False
    mq_brokers: list[MqTarget] = field(default_factory=list)
    mq_messages_per_queue: int = 100
    # Group 7, opt-in by size or cost (#35): ECR layers, SageMaker's offline stores, Neptune
    # Analytics by export, EventBridge archives by a replay to the scanner's own queue.
    ecr_read: bool = False
    ecr_max_layers: int = 5
    ecr_max_layer_bytes: int = 256 * 1024**2
    ecr_max_files_per_layer: int = 200
    sagemaker_read: bool = False
    neptune_analytics_export_role_arn: str | None = None
    neptune_analytics_export_kms_key_arn: str | None = None
    eventbridge_replay: bool = False
    eventbridge_replay_queue_url: str | None = None
    eventbridge_replay_queue_arn: str | None = None
    eventbridge_replay_hours: int = 24
    eventbridge_replay_max_events: int = 1000
    # #55: who finds the data: this scanner (`scanner`), Amazon Macie's findings imported
    # (`vendor`), or both, linked. `MACIE_LOOKBACK_DAYS`: how far back the first import goes.
    scan_mode: str = SCANNER
    macie_lookback_days: int = 90
    # #67: the per-object index in the results bucket (`state/index/`), and its cap per
    # source (objects past it are read by their change at the source only).
    object_index: bool = True
    index_max_objects: int = 10_000_000
    # The share of each source's budget that rescans may use (#67 part 2; 0: none).
    rescan_percent: int = 25
    # #67 part 3: after a table's full export, incremental exports of what changed.
    dynamodb_incremental: bool = True
    # #67 part 4: a bucket of at least this many objects is read from its S3 Inventory
    # report when it has one (and named as a recommendation when it has none).
    s3_inventory: bool = True
    s3_inventory_min_objects: int = 1_000_000

    @property
    def exports_prefix(self) -> str:
        return f"{self.results_prefix}exports/"

    def sampling_for(
        self, kind: str, name: str, tags: dict[str, str] | None
    ) -> tuple[int | None, int | None]:
        """(samplePercent, maxObjectsPerPrefix) from the first matching sampling rule."""
        return sampling_for(self.sampling, kind, name, tags)


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
        opensearch_docs_per_index=_int(e.get("OPENSEARCH_DOCS_PER_INDEX"), 100, 1, 10_000),
        opensearch_max_indices=_int(e.get("OPENSEARCH_MAX_INDICES"), 500, 1, 10_000),
        opensearch_serverless_read=_bool(e.get("OPENSEARCH_SERVERLESS_READ")),
        ebs_direct_read=_bool(e.get("EBS_DIRECT_READ")),
        ebs_blocks_per_snapshot=_int(e.get("EBS_BLOCKS_PER_SNAPSHOT"), 256, 4, 20_000),
        kinesis_records_per_shard=_int(e.get("KINESIS_RECORDS_PER_SHARD"), 100, 1, 10_000),
        kinesis_max_shards=_int(e.get("KINESIS_MAX_SHARDS"), 50, 1, 10_000),
        sqs_dlq_read=_bool(e.get("SQS_DLQ_READ")),
        sqs_messages_per_queue=_int(e.get("SQS_MESSAGES_PER_QUEUE"), 100, 1, 1000),
        ssm_decrypt=_bool(e.get("SSM_DECRYPT", "true")),
        secrets_read=_bool(e.get("SECRETS_READ")),
        timestream_max_rows=_int(e.get("TIMESTREAM_MAX_ROWS"), 1000, 1, 100_000),
        timestream_lookback_days=_int(e.get("TIMESTREAM_LOOKBACK_DAYS"), 1, 1, 3650),
        keyspaces_max_rows=_int(e.get("KEYSPACES_MAX_ROWS"), 1000, 1, 100_000),
        stepfunctions_executions=_int(e.get("STEPFUNCTIONS_EXECUTIONS"), 20, 1, 1000),
        stepfunctions_events=_int(e.get("STEPFUNCTIONS_EVENTS"), 500, 1, 25_000),
        xray_max_traces=_int(e.get("XRAY_MAX_TRACES"), 100, 1, 10_000),
        xray_lookback_hours=_int(e.get("XRAY_LOOKBACK_HOURS"), 24, 1, 720),
        codecommit_max_files=_int(e.get("CODECOMMIT_MAX_FILES"), 200, 1, 100_000),
        codecommit_max_folders=_int(e.get("CODECOMMIT_MAX_FOLDERS"), 500, 1, 100_000),
        self_function=e.get("AWS_LAMBDA_FUNCTION_NAME") or None,
        msk_read=_bool(e.get("MSK_READ")),
        msk_records_per_partition=_int(e.get("MSK_RECORDS_PER_PARTITION"), 100, 1, 10_000),
        msk_max_topics=_int(e.get("MSK_MAX_TOPICS"), 50, 1, 10_000),
        msk_max_partitions=_int(e.get("MSK_MAX_PARTITIONS"), 50, 1, 10_000),
        mq_read=_bool(e.get("MQ_READ")),
        mq_brokers=mq_brokers(e.get("MQ_BROKERS")),
        mq_messages_per_queue=_int(e.get("MQ_MESSAGES_PER_QUEUE"), 100, 1, 10_000),
        ecr_read=_bool(e.get("ECR_READ")),
        ecr_max_layers=_int(e.get("ECR_MAX_LAYERS"), 5, 1, 200),
        ecr_max_layer_bytes=_int(
            e.get("ECR_MAX_LAYER_BYTES"), 256 * 1024**2, 1024**2, 10 * 1024**3
        ),
        ecr_max_files_per_layer=_int(e.get("ECR_MAX_FILES_PER_LAYER"), 200, 1, 100_000),
        sagemaker_read=_bool(e.get("SAGEMAKER_READ")),
        neptune_analytics_export_role_arn=_arn(e.get("NEPTUNE_ANALYTICS_EXPORT_ROLE_ARN")),
        neptune_analytics_export_kms_key_arn=_arn(e.get("NEPTUNE_ANALYTICS_EXPORT_KMS_KEY_ARN")),
        eventbridge_replay=_bool(e.get("EVENTBRIDGE_REPLAY")),
        eventbridge_replay_queue_url=_queue_url(e.get("EVENTBRIDGE_REPLAY_QUEUE_URL")),
        eventbridge_replay_queue_arn=_arn(e.get("EVENTBRIDGE_REPLAY_QUEUE_ARN")),
        eventbridge_replay_hours=_int(e.get("EVENTBRIDGE_REPLAY_HOURS"), 24, 1, 24 * 30),
        eventbridge_replay_max_events=_int(
            e.get("EVENTBRIDGE_REPLAY_MAX_EVENTS"), 1000, 1, 100_000
        ),
        scan_mode=read_mode(e.get("SCAN_MODE")),
        macie_lookback_days=_int(e.get("MACIE_LOOKBACK_DAYS"), 90, 1, 3650),
        object_index=_bool(e.get("OBJECT_INDEX", "true")),
        index_max_objects=_int(e.get("INDEX_MAX_OBJECTS"), 10_000_000, 1000, 1_000_000_000),
        rescan_percent=_int(e.get("RESCAN_PERCENT"), 25, 0, 100),
        dynamodb_incremental=_bool(e.get("DYNAMODB_INCREMENTAL", "true")),
        s3_inventory=_bool(e.get("S3_INVENTORY", "true")),
        s3_inventory_min_objects=_int(
            e.get("S3_INVENTORY_MIN_OBJECTS"), 1_000_000, 0, 10_000_000_000
        ),
    )
    if config.eventbridge_replay and not (
        config.eventbridge_replay_queue_url and config.eventbridge_replay_queue_arn
    ):
        raise ValueError("EVENTBRIDGE_REPLAY needs the scanner's own replay queue")
    if config.redshift_read == "db_user" and not config.redshift_db_user:
        raise ValueError("REDSHIFT_READ=db_user needs REDSHIFT_DB_USER")
    return config


# ------------------------------------------------------------------ configuration documents

# Settings holding JSON: a document may give them as JSON values, not strings.
_JSON_SETTINGS = frozenset({"SCAN_DYNAMODB", "DISCOVER_SAMPLING", "RDS_DATA_API", "MQ_BROKERS"})
# Read by read_config but set by Lambda, never by a document.
_NOT_FROM_DOCUMENTS = frozenset({"AWS_LAMBDA_LOG_GROUP_NAME", "AWS_LAMBDA_FUNCTION_NAME"})
MAX_CONFIG_BYTES = 1024 * 1024
_S3_LOCATION = re.compile(r"^s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/(.{1,1024})$")
_SSM_ARN = re.compile(r"^arn:aws[a-z-]*:ssm:[a-z0-9-]+:[0-9]{12}:parameter/.{1,2000}$")


class _Asked(dict[str, str]):
    """An environment that records every name read_config asks for."""

    def __init__(self, data: Mapping[str, str]) -> None:
        super().__init__(data)
        self.asked: set[str] = set()

    def get(self, key: str, default: str | None = None) -> str | None:  # type: ignore[override]
        self.asked.add(key)
        return super().get(key, default)


def _setting(name: str, value: Any) -> str:
    """One document value as the string its environment variable would hold."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        return str(value)
    if name in _JSON_SETTINGS and isinstance(value, list | dict):
        return json.dumps(value)
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return ",".join(value)
    raise ValueError("a configuration document has a value of the wrong type")


def document_settings(doc: Any) -> dict[str, str]:
    """A configuration document (a JSON object of settings) as environment strings."""
    if not isinstance(doc, dict):
        raise ValueError("a configuration document must be a JSON object")
    out = {}
    for name, value in doc.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
            raise ValueError("a configuration document has a setting name it does not accept")
        if name in _NOT_FROM_DOCUMENTS:
            raise ValueError("a configuration document may not set that setting")
        out[name] = _setting(name, value)
    return out


def parse_document(raw: bytes | str) -> Any:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("the configuration document is too large")
    try:
        return json.loads(raw)
    except ValueError:
        raise ValueError("the configuration document is not valid JSON") from None


def read_location(location: str, client: Callable[[str], Any]) -> bytes | str:
    """The configuration file at `s3://bucket/key`, or in SSM (`ssm:<name>` or its ARN)."""
    loc = location.strip()
    m = _S3_LOCATION.match(loc)
    if m:
        body = client("s3").get_object(Bucket=m[1], Key=m[2])["Body"]
        data: bytes = body.read(MAX_CONFIG_BYTES + 1)
        return data
    if loc.startswith("ssm:") or _SSM_ARN.match(loc):
        name = loc[4:] if loc.startswith("ssm:") else loc
        if not name:
            raise ValueError("CONFIG_LOCATION names no parameter")
        got = client("ssm").get_parameter(Name=name, WithDecryption=True)
        value: str = got["Parameter"]["Value"]
        return value
    raise ValueError("CONFIG_LOCATION must be s3://bucket/key or ssm:<parameter name>")


def load_config(
    event: Any = None,
    client: Callable[[str], Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """The configuration for one invocation: environment, then the file, then the payload.

    `event` is the invoke payload. Only its `config` (a document) and
    `configLocation` (a file) are read; any other payload, such as an empty
    scheduled one, leaves the environment as it is. A setting a document names
    that the scanner does not read is an error, so a typo is not silently ignored.
    """
    e = dict(os.environ if env is None else env)
    payload = event if isinstance(event, dict) else {}
    documents: list[dict[str, str]] = []
    location = payload.get("configLocation") or e.get("CONFIG_LOCATION") or ""
    if not isinstance(location, str):
        raise ValueError("configLocation must be a string")
    if location.strip():
        if client is None:
            raise ValueError("a configuration file needs an AWS client")
        documents.append(document_settings(parse_document(read_location(location, client))))
    if payload.get("config") is not None:
        documents.append(document_settings(payload["config"]))
    for d in documents:
        e.update(d)
    asked = _Asked(e)
    config = read_config(asked)
    unknown = {name for d in documents for name in d} - asked.asked
    if unknown:
        raise ValueError("a configuration document names a setting the scanner does not read")
    return config
