"""Discovery: list the data stores in this account and region, then decide which to read.

With `DISCOVER` set, a run lists every store of the kinds it names, with no
list for the user to write:

- **S3:** `ListBuckets` for this region (`BucketRegion`), each bucket read
  whole by the S3 source;
- **CloudWatch Logs:** `DescribeLogGroups`, each group read by the logs
  source;
- **DynamoDB:** `ListTables` and `DescribeTable`, each table read by a
  (sampled) Scan;
- **Glue Data Catalog:** `GetDatabases` and `GetTables`, each table read at
  its S3 location, by column, with findings that name the database, table
  and column. The bucket's own source then leaves that prefix to it. Lake
  Formation is respected: the scanner reads with its own IAM only and
  never asks Lake Formation for credentials, so a denial is reported
  (`lake_formation`), not worked around.

An allow list and a deny list (`DISCOVER_ALLOW`, `DISCOVER_DENY`) narrow what
is read, by name glob or by tag. A deny rule wins over an allow rule. The
scanner's own results bucket and log group are never read.

Each store to be read also gets the storage encryption its own configuration
names (`atRestEncryption`, sources/encryption.py): the bucket's default, the log
group's key, the table's `SSEDescription`, the cluster's `StorageEncrypted`.

Every store listed is reported in the run's summary
(`sensitive_data_core.coverage`), **including the ones not read and why**
(`denied`, `not_allowed`, `self`, `too_large`, `unsupported`, `kms_access`,
`access_denied`, `lake_formation`, `tags_unreadable`, or `deferred` to a
later run by the budget), so a coverage gap is visible rather than silent.
Names in the summary are masked like object keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sensitive_data_core.coverage import (
    Discovery,
    Store,
    apply_rules,
    reason_for,
)
from sensitive_data_core.rules import StoreRule
from sensitive_data_core.safety import error_name, is_kms_denial, log_event

from .config import Config
from .sources.encryption import (
    classifier,
    dynamodb_facts,
    log_group_facts,
    rds_facts,
    s3_bucket_facts,
)
from .sources.rds import EXPORTABLE_ENGINES

if TYPE_CHECKING:
    from .runner import Clients

# DynamoDB table states that can be read. Anything else (CREATING, DELETING,
# ARCHIVED, INACCESSIBLE_ENCRYPTION_CREDENTIALS) is reported, not read.
READABLE_TABLE_STATES = frozenset({"ACTIVE", "UPDATING"})
# Log classes FilterLogEvents can read. DELIVERY groups only forward to S3 or
# Firehose and cannot be queried.
READABLE_LOG_CLASSES = frozenset({"STANDARD", "INFREQUENT_ACCESS"})


# Engines the RDS API lists that have their own kind (and adapter) when discovered.
OWN_KIND = {"docdb": "documentdb", "neptune": "neptune"}


@dataclass(frozen=True)
class GlueTable:
    """What the reader needs from a Glue table: where it is and how its rows are laid out."""

    database: str
    name: str
    bucket: str
    prefix: str
    columns: tuple[str, ...] = ()
    serde: str | None = None  # csv | json | None (by file)
    delimiter: str = ","
    skip_header: int = 0


def _needs_tags(config: Config, kind: str) -> bool:
    rules: list[StoreRule] = [*config.allow, *config.deny, *(r.match for r in config.sampling)]
    return any(r.needs_tags and r.kind in (None, kind) for r in rules)


def needs_tags(config: Config, kind: str) -> bool:
    """Whether an allow, deny or sampling rule for `kind` looks at tags (fetch them only then)."""
    return _needs_tags(config, kind)


def _tag_list(tags: list[dict[str, Any]] | None) -> dict[str, str]:
    return {str(t.get("Key")): str(t.get("Value", "")) for t in tags or [] if t.get("Key")}


def _s3_tags(clients: Clients, bucket: str) -> dict[str, str]:
    try:
        r = clients.s3.get_bucket_tagging(Bucket=bucket)
    except Exception as err:
        if error_name(err) in ("NoSuchTagSet", "NoSuchTagSetError"):
            return {}
        raise
    return _tag_list(r.get("TagSet"))  # type: ignore[arg-type]


def _s3_default(clients: Clients, bucket: str) -> list[dict[str, Any]] | None:
    """The bucket's default encryption rules; [] when it has none, None when unreadable."""
    try:
        r = clients.s3.get_bucket_encryption(Bucket=bucket)
    except Exception as err:
        if error_name(err) == "ServerSideEncryptionConfigurationNotFoundError":
            return []
        return None
    rules = (r.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
    return [dict(x) for x in rules]


def _logs_tags(clients: Clients, arn: str) -> dict[str, str]:
    r = clients.logs.list_tags_for_resource(resourceArn=arn)
    return {str(k): str(v) for k, v in (r.get("tags") or {}).items()}


def _ddb_tags(clients: Clients, arn: str) -> dict[str, str]:
    if clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    tags: dict[str, str] = {}
    token: str | None = None
    while True:
        args: dict[str, Any] = {"ResourceArn": arn}
        if token:
            args["NextToken"] = token
        r = clients.dynamodb.list_tags_of_resource(**args)
        tags.update(_tag_list(r.get("Tags")))  # type: ignore[arg-type]
        token = r.get("NextToken")
        if not token:
            return tags


def decide(store: Store, config: Config, tag_error: str | None = None) -> None:
    """Apply the allow and deny lists and the per-store sampling to one store."""
    if not apply_rules(store, config.allow, config.deny, tag_error):
        return
    kind, name, tags = store.kind, store.name, store.tags
    pct, per = config.sampling_for(kind, name, tags)
    if kind in ("s3", "s3_directory"):
        store.key_filter = config.key_filter_for(kind, name, tags)
    if kind in ("s3", "glue_table", "s3_directory"):
        store.sample_percent = pct if pct is not None else config.sample_percent
        store.max_per_prefix = per if per is not None else config.s3_max_objects_per_prefix
    elif kind == "dynamodb":
        store.sample_percent = pct if pct is not None else config.dynamodb_sample_percent


def _with_tags(store: Store, config: Config, fetch: Any, *args: Any) -> None:
    """Fetch tags when a rule needs them, then decide."""
    tag_error: str | None = None
    if _needs_tags(config, store.kind):
        try:
            store.tags = fetch(*args)
        except Exception as err:
            tag_error = error_name(err)
    decide(store, config, tag_error)


def _discover_s3(config: Config, clients: Clients, region: str, out: Discovery) -> None:
    paginator = clients.s3.get_paginator("list_buckets")
    for page in paginator.paginate(BucketRegion=region):
        for b in page.get("Buckets", []):
            name = str(b["Name"])
            store = Store("s3", name)
            out.stores.append(store)
            if name == config.results_bucket:
                store.skip("self")
                continue
            _with_tags(store, config, _s3_tags, clients, name)
            if store.status == "pending":
                store.facts = s3_bucket_facts(classifier(clients), _s3_default(clients, name))


def _discover_logs(config: Config, clients: Clients, out: Discovery) -> None:
    paginator = clients.logs.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for g in page.get("logGroups", []):
            name = str(g["logGroupName"])
            store = Store("cloudwatch_logs", name, size_bytes=int(g.get("storedBytes") or 0))
            out.stores.append(store)
            if name == config.self_log_group:
                store.skip("self")
                continue
            log_class = str(g.get("logGroupClass") or "STANDARD")
            if log_class not in READABLE_LOG_CLASSES:
                store.skip("unsupported")
                store.extra["logGroupClass"] = log_class
                continue
            arn = str(g.get("logGroupArn") or str(g.get("arn", "")).removesuffix(":*"))
            _with_tags(store, config, _logs_tags, clients, arn)
            if store.status == "pending":
                store.facts = log_group_facts(classifier(clients), dict(g))


def _discover_dynamodb(config: Config, clients: Clients, out: Discovery) -> None:
    if clients.dynamodb is None:
        raise ValueError("no DynamoDB client")
    ddb = clients.dynamodb
    paginator = ddb.get_paginator("list_tables")
    names: list[str] = []
    for page in paginator.paginate():
        names.extend(str(n) for n in page.get("TableNames", []))
    for name in names:
        store = Store("dynamodb", name)
        out.stores.append(store)
        # A deny by name needs no DescribeTable.
        if any(r.name is not None and r.matches("dynamodb", name, None) for r in config.deny):
            store.skip("denied")
            continue
        try:
            desc = ddb.describe_table(TableName=name)["Table"]
        except Exception as err:
            name_ = error_name(err)
            store.status = "error"
            store.reason = "kms_access" if is_kms_denial(err) else reason_for(name_)
            store.error = name_
            continue
        store.size_bytes = int(desc.get("TableSizeBytes") or 0)
        status = str(desc.get("TableStatus"))
        if status == "INACCESSIBLE_ENCRYPTION_CREDENTIALS":
            store.skip("kms_access")  # the table's KMS key is disabled or out of reach
            continue
        if status not in READABLE_TABLE_STATES:
            store.skip("unsupported")
            store.extra["tableStatus"] = status
            continue
        _with_tags(store, config, _ddb_tags, clients, str(desc.get("TableArn", "")))
        if store.status != "pending":
            continue
        store.facts = dynamodb_facts(classifier(clients), dict(desc.get("SSEDescription") or {}))
        pct = store.sample_percent or 100
        cap = config.dynamodb_max_table_bytes
        if cap and store.size_bytes * pct // 100 > cap:
            _too_large_table(config, ddb, store, name, str(desc.get("TableArn", "")))


def _too_large_table(config: Config, ddb: Any, store: Store, name: str, arn: str) -> None:
    """Too large to Scan: read it from an export when that is on and PITR allows it."""
    if not config.dynamodb_export:
        store.skip("too_large")
        return
    try:
        pitr = ddb.describe_continuous_backups(TableName=name)
        status = (
            (pitr.get("ContinuousBackupsDescription") or {})
            .get("PointInTimeRecoveryDescription", {})
            .get("PointInTimeRecoveryStatus")
        )
    except Exception as err:
        store.skip("too_large", error_name(err))
        return
    if status != "ENABLED":
        store.skip("pitr_off")  # an export needs point-in-time recovery
        store.extra["pitr"] = False
        return
    store.extra["readBy"] = "export"
    store.extra["tableArn"] = arn


def _glue_tags(clients: Clients, arn: str) -> dict[str, str]:
    if clients.glue is None:
        raise ValueError("no Glue client")
    r = clients.glue.get_tags(ResourceArn=arn)
    return {str(k): str(v) for k, v in (r.get("Tags") or {}).items()}


def is_lake_formation_denial(err: BaseException) -> bool:
    """A Glue or S3 denial that Lake Formation made (the message says so; never kept)."""
    response = getattr(err, "response", None)
    if not isinstance(response, dict):
        return False
    message = str((response.get("Error") or {}).get("Message") or "").lower()
    return "lake formation" in message or "lakeformation" in message


def _serde(sd: dict[str, Any]) -> tuple[str | None, str]:
    info = sd.get("SerdeInfo") or {}
    lib = str(info.get("SerializationLibrary") or "")
    params = info.get("Parameters") or {}
    if "OpenCSVSerde" in lib:
        return "csv", str(params.get("separatorChar") or ",")[:1] or ","
    if "LazySimpleSerDe" in lib:
        # Hive's default field delimiter is Ctrl-A.
        return "csv", str(
            params.get("field.delim") or params.get("serialization.format") or "\x01"
        )[:1]
    if "JsonSerDe" in lib or "JsonSerde" in lib:
        return "json", ","
    return None, ","


def glue_location(location: str) -> tuple[str, str] | None:
    """`s3://bucket/path/table` to (bucket, `path/table/`); None when not S3."""
    for scheme in ("s3://", "s3a://", "s3n://"):
        if location.startswith(scheme):
            rest = location[len(scheme) :]
            bucket, _, prefix = rest.partition("/")
            if not bucket:
                return None
            prefix = prefix.lstrip("/")
            if prefix and not prefix.endswith("/"):
                prefix += "/"
            return bucket, prefix
    return None


def _discover_glue(
    config: Config, clients: Clients, region: str, account: str, out: Discovery
) -> None:
    if clients.glue is None:
        raise ValueError("no Glue client")
    glue = clients.glue
    databases: list[dict[str, Any]] = []
    for page in glue.get_paginator("get_databases").paginate():
        databases.extend(page.get("DatabaseList", []))  # type: ignore[arg-type]
    for db in databases:
        db_name = str(db["Name"])
        if db.get("TargetDatabase"):
            store = Store("glue_table", f"{db_name}.*")
            store.skip("unsupported")  # a resource link: the owning account's scanner reads it
            store.extra["catalogObject"] = "resource_link"
            out.stores.append(store)
            continue
        try:
            tables: list[dict[str, Any]] = []
            for tpage in glue.get_paginator("get_tables").paginate(DatabaseName=db_name):
                tables.extend(tpage.get("TableList", []))  # type: ignore[arg-type]
        except Exception as err:
            store = Store("glue_table", f"{db_name}.*")
            store.status = "error"
            store.error = error_name(err)
            store.reason = (
                "lake_formation" if is_lake_formation_denial(err) else reason_for(store.error)
            )
            out.stores.append(store)
            continue
        for t in tables:
            _glue_table(
                config,
                clients,
                db_name,
                t,
                arn_prefix=f"arn:aws:glue:{region}:{account}:table",
                out=out,
            )


def _glue_table(
    config: Config,
    clients: Clients,
    db_name: str,
    t: dict[str, Any],
    *,
    arn_prefix: str,
    out: Discovery,
) -> None:
    name = str(t["Name"])
    store = Store("glue_table", f"{db_name}.{name}")
    out.stores.append(store)
    if t.get("IsRegisteredWithLakeFormation"):
        store.extra["lakeFormation"] = True
    if t.get("TargetTable"):
        store.skip("unsupported")
        store.extra["catalogObject"] = "resource_link"
        return
    if str(t.get("TableType") or "") == "VIRTUAL_VIEW":
        store.skip("unsupported")
        store.extra["catalogObject"] = "view"
        return
    sd = t.get("StorageDescriptor") or {}
    where = glue_location(str(sd.get("Location") or ""))
    if where is None:
        store.skip("unsupported")
        store.extra["catalogObject"] = "not_s3"
        return
    store.extra["location"] = f"{where[0]}/{where[1]}"
    if store.extra.get("lakeFormation") and config.glue_lake_formation == "skip":
        store.skip("lake_formation")
        return
    serde, delimiter = _serde(sd)
    try:
        skip = int((t.get("Parameters") or {}).get("skip.header.line.count") or 0)
    except ValueError:
        skip = 0
    columns = [str(c["Name"]) for c in sd.get("Columns") or [] if c.get("Name")]
    columns += [str(c["Name"]) for c in t.get("PartitionKeys") or [] if c.get("Name")]
    store.table = GlueTable(
        database=db_name,
        name=name,
        bucket=where[0],
        prefix=where[1],
        columns=tuple(columns),
        serde=serde,
        delimiter=delimiter,
        skip_header=max(0, skip),
    )
    arn = f"{arn_prefix}/{db_name}/{name}"
    _with_tags(store, config, _glue_tags, clients, arn)


def _rds_store(
    config: Config,
    identifier: str,
    db_type: str,
    engine: str,
    tags: Any,
    *,
    facts: dict[str, str],
) -> Store:
    store = Store("rds", identifier)
    store.facts = facts
    store.extra.update(engine=engine, dbType=db_type)
    store.tags = _tag_list(tags)
    if engine not in EXPORTABLE_ENGINES:
        store.skip("unsupported")  # Oracle, SQL Server, Db2, Neptune, DocumentDB
        return store
    decide(store, config)
    if store.status == "pending" and not (
        config.rds_export_role_arn and config.rds_export_kms_key_arn
    ):
        store.skip("export_not_configured")
    return store


def _discover_rds(config: Config, clients: Clients, out: Discovery) -> None:
    if clients.rds is None:
        raise ValueError("no RDS client")
    for page in clients.rds.get_paginator("describe_db_clusters").paginate():
        for c in page.get("DBClusters", []):
            if OWN_KIND.get(str(c.get("Engine", ""))) in config.discover:
                continue  # listed by its own adapter (sources/coverage_only.py)
            out.stores.append(
                _rds_store(
                    config,
                    str(c["DBClusterIdentifier"]),
                    "cluster",
                    str(c.get("Engine", "")),
                    c.get("TagList"),
                    facts=rds_facts(classifier(clients), dict(c)),
                )
            )
    for ipage in clients.rds.get_paginator("describe_db_instances").paginate():
        for i in ipage.get("DBInstances", []):
            if i.get("DBClusterIdentifier"):
                continue  # a cluster member: its cluster's snapshot covers it
            out.stores.append(
                _rds_store(
                    config,
                    str(i["DBInstanceIdentifier"]),
                    "instance",
                    str(i.get("Engine", "")),
                    i.get("TagList"),
                    facts=rds_facts(classifier(clients), dict(i)),
                )
            )


def discover(config: Config, clients: Clients, region: str, account: str = "") -> Discovery:
    """List the stores of each kind in `config.discover`. A listing that fails is named."""
    out = Discovery()
    steps: list[tuple[str, Any]] = []
    if "s3" in config.discover:
        steps.append(("s3", lambda: _discover_s3(config, clients, region, out)))
    if "cloudwatch_logs" in config.discover:
        steps.append(("cloudwatch_logs", lambda: _discover_logs(config, clients, out)))
    if "dynamodb" in config.discover:
        steps.append(("dynamodb", lambda: _discover_dynamodb(config, clients, out)))
    if "rds" in config.discover:
        steps.append(("rds", lambda: _discover_rds(config, clients, out)))
    if "glue_table" in config.discover:
        steps.append(("glue_table", lambda: _discover_glue(config, clients, region, account, out)))
    from .sources.aws import ADAPTERS  # noqa: PLC0415 - the adapters import this module
    from .sources.base import Context  # noqa: PLC0415

    ctx = Context(config, clients, region, account)
    for kind, adapter in ADAPTERS.items():
        if kind in config.discover:
            steps.append((kind, lambda a=adapter: a.discover(ctx, out)))
    for kind, step in steps:
        try:
            step()
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
