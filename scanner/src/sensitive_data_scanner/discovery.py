"""Discovery: list the data stores in this account and region, then decide which to read.

With `DISCOVER` set, a run lists every store of the kinds it names, with no
list for the user to write:

- **S3:** `ListBuckets` for this region (`BucketRegion`), each bucket read
  whole by the S3 source;
- **CloudWatch Logs:** `DescribeLogGroups`, each group read by the logs
  source;
- **DynamoDB:** `ListTables` and `DescribeTable`, each table read by a
  (sampled) Scan.

An allow list and a deny list (`DISCOVER_ALLOW`, `DISCOVER_DENY`) narrow what
is read, by name glob or by tag. A deny rule wins over an allow rule. The
scanner's own results bucket and log group are never read.

Every store listed is reported in the run's summary, **including the ones not
read and why** (`denied`, `not_allowed`, `self`, `too_large`, `unsupported`,
`kms_access`, `access_denied`, `tags_unreadable`, or `deferred` to a later run
by the budget), so a coverage gap is visible rather than silent. Names in the
summary are masked like object keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .config import Config, StoreRule
from .safety import error_name, is_kms_denial, log_event, redact_digits

if TYPE_CHECKING:
    from .runner import Clients

ACCESS_DENIED = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AllAccessDisabled"}
)
MAX_STORES_IN_SUMMARY = 5000
# DynamoDB table states that can be read. Anything else (CREATING, DELETING,
# ARCHIVED, INACCESSIBLE_ENCRYPTION_CREDENTIALS) is reported, not read.
READABLE_TABLE_STATES = frozenset({"ACTIVE", "UPDATING"})
# Log classes FilterLogEvents can read. DELIVERY groups only forward to S3 or
# Firehose and cannot be queried.
READABLE_LOG_CLASSES = frozenset({"STANDARD", "INFREQUENT_ACCESS"})


@dataclass
class Store:
    """One data store, listed by discovery or named in the configuration."""

    kind: str  # s3 | cloudwatch_logs | dynamodb
    name: str
    origin: str = "discovery"  # discovery | config
    tags: dict[str, str] | None = None
    size_bytes: int | None = None
    status: str = "pending"  # pending, then scanned | deferred | skipped | error
    reason: str | None = None
    error: str | None = None
    sample_percent: int | None = None
    max_per_prefix: int | None = None
    source_ids: list[str] = field(default_factory=list)
    gaps: dict[str, int] = field(default_factory=dict)
    backlog: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def skip(self, reason: str, error: str | None = None) -> None:
        self.status = "skipped"
        self.reason = reason
        self.error = error

    def as_json(self) -> dict[str, Any]:
        name = redact_digits(self.name)
        out: dict[str, Any] = {
            "kind": self.kind,
            "name": name,
            "origin": self.origin,
            "status": self.status,
        }
        if name != self.name:
            out["nameMasked"] = True
        if self.reason:
            out["reason"] = self.reason
        if self.error:
            out["error"] = self.error
        if self.size_bytes is not None:
            out["sizeBytes"] = self.size_bytes
        if self.sample_percent is not None and self.sample_percent < 100:
            out["samplePercent"] = self.sample_percent
        if self.max_per_prefix:
            out["maxObjectsPerPrefix"] = self.max_per_prefix
        if self.gaps:
            out["gaps"] = dict(sorted(self.gaps.items()))
        if self.backlog:
            out["backlog"] = True
        out.update(self.extra)
        return out


@dataclass
class Discovery:
    stores: list[Store] = field(default_factory=list)
    list_errors: dict[str, str] = field(default_factory=dict)


def _needs_tags(config: Config, kind: str) -> bool:
    rules: list[StoreRule] = [*config.allow, *config.deny, *(r.match for r in config.sampling)]
    return any(r.needs_tags and r.kind in (None, kind) for r in rules)


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
    kind, name, tags = store.kind, store.name, store.tags
    if any(r.matches(kind, name, tags) for r in config.deny):
        store.skip("denied")
        return
    if tag_error is not None and any(r.needs_tags and r.kind in (None, kind) for r in config.deny):
        # A deny-by-tag rule cannot be checked: never read what may be denied.
        store.skip("tags_unreadable", tag_error)
        return
    if config.allow and not any(r.matches(kind, name, tags) for r in config.allow):
        store.skip("not_allowed", tag_error)
        return
    pct, per = config.sampling_for(kind, name, tags)
    if kind == "s3":
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
            store.reason = "kms_access" if is_kms_denial(err) else _reason(name_)
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
        pct = store.sample_percent or 100
        cap = config.dynamodb_max_table_bytes
        if cap and store.size_bytes * pct // 100 > cap:
            store.skip("too_large")


def _reason(error: str | None) -> str:
    return "access_denied" if error in ACCESS_DENIED else "error"


def discover(config: Config, clients: Clients, region: str) -> Discovery:
    """List the stores of each kind in `config.discover`. A listing that fails is named."""
    out = Discovery()
    steps: list[tuple[str, Any]] = []
    if "s3" in config.discover:
        steps.append(("s3", lambda: _discover_s3(config, clients, region, out)))
    if "cloudwatch_logs" in config.discover:
        steps.append(("cloudwatch_logs", lambda: _discover_logs(config, clients, out)))
    if "dynamodb" in config.discover:
        steps.append(("dynamodb", lambda: _discover_dynamodb(config, clients, out)))
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


def settle(store: Store, coverages: list[Any]) -> None:
    """A store's status and gaps from the coverage of its sources this run."""
    if not coverages:
        return
    errors = [c for c in coverages if c.error]
    kms = sum(c.kms_denied for c in coverages)
    unreadable = sum(c.unreadable for c in coverages)
    unsupported = sum(sum(c.skipped.values()) for c in coverages)
    if kms:
        store.gaps["kmsDenied"] = kms
    if unreadable:
        store.gaps["unreadable"] = unreadable
    if unsupported:
        store.gaps["unsupportedFormat"] = unsupported
    store.backlog = any(c.backlog for c in coverages)
    if errors and len(errors) == len(coverages):
        store.status = "error"
        store.error = errors[0].error
        store.reason = "kms_access" if errors[0].kms_denied else _reason(store.error)
        return
    store.status = "scanned"
    if sum(c.scanned for c in coverages) == 0 and unsupported and not unreadable:
        store.reason = "unsupported_format"


def summary(stores: list[Store], list_errors: dict[str, str]) -> dict[str, Any]:
    """The run summary: every store, what happened to it, and the totals."""
    by_status: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    for s in stores:
        by_status[s.status] = by_status.get(s.status, 0) + 1
        if s.reason:
            by_reason[s.reason] = by_reason.get(s.reason, 0) + 1
    order = {"error": 0, "skipped": 1, "deferred": 2, "scanned": 3, "pending": 4}
    ranked = sorted(stores, key=lambda s: (order.get(s.status, 9), s.kind, s.name))
    kept = ranked[:MAX_STORES_IN_SUMMARY]
    return {
        "stores": [s.as_json() for s in kept],
        "storesTotal": len(stores),
        "storesTruncated": len(stores) > len(kept),
        "byStatus": dict(sorted(by_status.items())),
        "byReason": dict(sorted(by_reason.items())),
        "listErrors": dict(sorted(list_errors.items())),
    }
