"""The findings contract: what the scanner writes, and nothing else.

A findings document (schema `sensitive-data-scanner.findings`, version 1.2,
JSON Schema in schema/findings.schema.json) says, for one run in one account
and region, which locations hold which classes of sensitive data, how many,
how confident, where in the item, and how much was scanned. It never holds
a value: every string in it is a name, an id, an enum or a masked key.

The same content can go out as EventBridge events (`source`
`sensitive-data-scanner`, `detail-type` `Findings v1`) to a consumer-owned
bus; see `events.py`.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from . import __version__
from .engine.spec import SPEC_VERSION
from .safety import redact_digits

FINDINGS_SCHEMA = "sensitive-data-scanner.findings"
FINDINGS_SCHEMA_VERSION = "1.2"
EVENT_SOURCE = "sensitive-data-scanner"
EVENT_DETAIL_TYPE = "Findings v1"

MAX_OFFSETS_PER_FINDING = 50
MAX_FINDINGS_IN_DOCUMENT = 5000

SEVERITY = {
    "card": "high",
    "us_ssn": "high",
    "us_itin": "high",  # the same as us_ssn: it identifies a taxpayer the same way
    "cvv": "high",
    "pin": "high",
    "dob": "medium",
    "account_number": "medium",
    "us_ssn_last4": "low",
}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Offset:
    """Where one occurrence is: UTF-16 code units in the item's text, or in one JSON string."""

    start: int
    end: int
    pointer: str | None = None  # RFC 6901 JSON Pointer to the string, for JSON items

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"start": self.start, "end": self.end}
        if self.pointer is not None:
            out["pointer"] = redact_digits(self.pointer)
        return out


@dataclass
class ClassFinding:
    """One class of data at one location (collected while an item is scanned)."""

    cls: str
    count: int = 0  # distinct values
    occurrences: int = 0
    confidence: str = "low"
    confidence_counts: dict[str, int] = field(default_factory=dict)
    via: set[str] = field(default_factory=set)
    offsets: list[Offset] = field(default_factory=list)

    def add(self, via: str, confidence: str, offsets: list[Offset], new_value: bool) -> None:
        self.occurrences += 1
        if new_value:
            self.count += 1
        self.via.add(via)
        self.confidence_counts[confidence] = self.confidence_counts.get(confidence, 0) + 1
        if _CONF_RANK[confidence] > _CONF_RANK[self.confidence] or self.occurrences == 1:
            self.confidence = confidence
        self.offsets.extend(offsets)


def s3_link(region: str, bucket: str, key: str, version_id: str | None) -> str:
    q = {"region": region, "bucketType": "general", "prefix": key}
    if version_id and version_id != "null":
        q["versionId"] = version_id
    return (
        f"https://{region}.console.aws.amazon.com/s3/object/{urllib.parse.quote(bucket)}?"
        + urllib.parse.urlencode(q)
    )


def _cw_escape(s: str) -> str:
    # The CloudWatch console's own escaping inside its URL fragment.
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="").replace("%", "$")


def logs_link(region: str, group: str, stream: str, timestamp_ms: int) -> str:
    frag = (
        f"logsV2:log-groups/log-group/{_cw_escape(group)}/log-events/{_cw_escape(stream)}"
        + _cw_escape(f"?start={timestamp_ms}&end={timestamp_ms + 1}")
    )
    return f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#{frag}"


def s3_resource(
    bucket: str,
    key: str,
    version_id: str | None,
    *,
    column: str | None = None,
    catalog: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """An S3 object version; for a table object, the column; for a catalog table, its name."""
    masked = redact_digits(key)
    masked_bucket = redact_digits(bucket)
    out: dict[str, Any] = {"type": "s3_object", "bucket": masked_bucket, "key": masked}
    out["versionId"] = version_id or "null"
    changed = masked != key or masked_bucket != bucket
    if column is not None:
        out["column"] = redact_digits(column)
        changed = changed or out["column"] != column
    if catalog is not None:
        out["catalog"] = {"database": redact_digits(catalog[0]), "table": redact_digits(catalog[1])}
        changed = changed or (out["catalog"]["database"], out["catalog"]["table"]) != catalog
    if changed:
        out["keyMasked"] = True
    return out


def log_resource(group: str, stream: str, timestamp_ms: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "log_event",
        "logGroup": redact_digits(group),
        "logStream": redact_digits(stream),
        "timestamp": timestamp_ms,
    }
    if out["logGroup"] != group or out["logStream"] != stream:
        out["nameMasked"] = True
    return out


def dynamodb_link(region: str, table: str) -> str:
    """The table's item explorer. It names no key: the reviewer queries by the masked key."""
    return (
        f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}"
        f"#item-explorer?table={urllib.parse.quote(table, safe='')}"
    )


def dynamodb_resource(
    table: str,
    key: dict[str, str],
    key_hash: str,
    attribute_path: str,
    *,
    planted: bool = False,
) -> dict[str, Any]:
    """An item by its key hash, with the key's values masked like an S3 object key."""
    masked = {name: redact_digits(value) for name, value in sorted(key.items())}
    path = redact_digits(attribute_path)
    masked_table = redact_digits(table)
    out: dict[str, Any] = {
        "type": "dynamodb_item",
        "table": masked_table,
        "keyHash": key_hash,
        "key": masked,
        "attributePath": path,
    }
    if masked != dict(sorted(key.items())) or path != attribute_path or masked_table != table:
        out["keyMasked"] = True
    if planted:
        out["planted"] = True
    return out


def rds_link(region: str, identifier: str, db_type: str) -> str:
    """The cluster's or instance's page in the RDS console."""
    return (
        f"https://{region}.console.aws.amazon.com/rds/home?region={region}"
        f"#database:id={urllib.parse.quote(identifier, safe='')};"
        f"is-cluster={'true' if db_type == 'cluster' else 'false'}"
    )


def rds_resource(
    *,
    engine: str,
    identifier: str,
    db_type: str,
    database: str,
    table: str,
    column: str,
    read_by: str,
    snapshot_time: str | None = None,
) -> dict[str, Any]:
    """One column of one table of an RDS or Aurora database (`schema.table.column`)."""
    names = {
        "cluster": identifier,
        "database": database,
        "table": table,
        "column": column,
    }
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {
        "type": "rds_column",
        "engine": engine,
        "dbType": db_type,
        **masked,
        "readBy": read_by,
    }
    if snapshot_time:
        # The time, not the snapshot's name: an automated snapshot is named after
        # the cluster, and the name would carry whatever the cluster's name does.
        out["snapshotTime"] = snapshot_time
    if masked != names:
        out["keyMasked"] = True
    return out


# Resource fields that say which copy was read, not where the data lives.
_NOT_IN_ID = frozenset({"snapshotTime"})


def finding_id(resource: dict[str, Any], cls: str) -> str:
    """Stable across runs for the same location and class (and object version)."""
    keys = sorted(k for k in resource if k not in _NOT_IN_ID)
    basis = "|".join(f"{k}={resource[k]}" for k in keys) + f"|class={cls}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


def finding_json(
    resource: dict[str, Any],
    link: str | None,
    fmt: str,
    cf: ClassFinding,
    seen_at: str,
    *,
    first_seen_at: str | None = None,
    connect: dict[str, str] | None = None,
) -> dict[str, Any]:
    offsets = [o.as_json() for o in cf.offsets[:MAX_OFFSETS_PER_FINDING]]
    out: dict[str, Any] = {
        "id": finding_id(resource, cf.cls),
        "resource": resource,
        "format": fmt,
        "class": cf.cls,
        "severity": SEVERITY.get(cf.cls, "medium"),
        "count": cf.count,
        "occurrences": cf.occurrences,
        "confidence": cf.confidence,
        "confidenceCounts": dict(sorted(cf.confidence_counts.items())),
        "via": sorted(cf.via),
        "offsets": offsets,
        "offsetsTruncated": len(cf.offsets) > MAX_OFFSETS_PER_FINDING,
        "link": None if resource.get("keyMasked") or resource.get("nameMasked") else link,
        "firstSeenAt": first_seen_at or seen_at,
        "lastSeenAt": seen_at,
    }
    if connect:
        out["connect"] = {k: redact_digits(v) for k, v in connect.items() if v}
    return out


@dataclass
class Coverage:
    """What one source's pass read, sampled, skipped and could not read."""

    kind: str  # s3 | cloudwatch_logs | dynamodb
    target: str
    listed: int = 0
    eligible: int = 0
    scanned: int = 0
    sampled_out: int = 0
    sample_percent: int = 100
    partial: int = 0
    unreadable: int = 0
    bytes_scanned: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    formats: dict[str, int] = field(default_factory=dict)
    test_values: int = 0
    suppressed: int = 0
    redaction_markers: int = 0
    pass_complete: bool = False
    backlog: bool = False
    error: str | None = None
    kms_denied: int = 0

    def as_json(self) -> dict[str, Any]:
        d = asdict(self)
        out: dict[str, Any] = {
            "kind": d["kind"],
            "target": redact_digits(d["target"]),
            "listed": d["listed"],
            "eligible": d["eligible"],
            "scanned": d["scanned"],
            "sampledOut": d["sampled_out"],
            "samplePercent": d["sample_percent"],
            "partial": d["partial"],
            "unreadable": d["unreadable"],
            "bytesScanned": d["bytes_scanned"],
            "skipped": dict(sorted(d["skipped"].items())),
            "formats": dict(sorted(d["formats"].items())),
            "testValues": d["test_values"],
            "suppressed": d["suppressed"],
            "redactionMarkers": d["redaction_markers"],
            "passComplete": d["pass_complete"],
            "backlog": d["backlog"],
            "error": d["error"],
        }
        if self.kms_denied:
            out["kmsDenied"] = self.kms_denied
        return out


def findings_document(
    *,
    run_id: str,
    account: str,
    region: str,
    started_at: str,
    finished_at: str,
    classes: list[str],
    coverage: list[Coverage],
    findings: list[dict[str, Any]],
    discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ranked = sorted(findings, key=lambda f: (-_CONF_RANK[f["severity"]], -f["count"], f["id"]))
    kept = ranked[:MAX_FINDINGS_IN_DOCUMENT]
    totals: dict[str, int] = {}
    for f in findings:
        totals[f["class"]] = totals.get(f["class"], 0) + f["count"]
    doc: dict[str, Any] = {
        "schema": FINDINGS_SCHEMA,
        "schemaVersion": FINDINGS_SCHEMA_VERSION,
        "scannerVersion": __version__,
        "specVersion": SPEC_VERSION,
        "runId": run_id,
        "account": account,
        "region": region,
        "startedAt": started_at,
        "finishedAt": finished_at,
        "classes": classes,
        "coverage": [c.as_json() for c in coverage],
        "findings": kept,
        "findingsTotal": len(findings),
        "findingsTruncated": len(findings) > len(kept),
        "totals": dict(sorted(totals.items())),
    }
    if discovery is not None:
        doc["discovery"] = discovery
    return doc
