"""The findings contract: what the scanner writes, and nothing else.

A findings document (schema `sensitive-data-scanner.findings`, version 1.0,
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
FINDINGS_SCHEMA_VERSION = "1.0"
EVENT_SOURCE = "sensitive-data-scanner"
EVENT_DETAIL_TYPE = "Findings v1"

MAX_OFFSETS_PER_FINDING = 50
MAX_FINDINGS_IN_DOCUMENT = 5000

SEVERITY = {
    "card": "high",
    "us_ssn": "high",
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


def s3_resource(bucket: str, key: str, version_id: str | None) -> dict[str, Any]:
    masked = redact_digits(key)
    out: dict[str, Any] = {"type": "s3_object", "bucket": bucket, "key": masked}
    out["versionId"] = version_id or "null"
    if masked != key:
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
    out: dict[str, Any] = {
        "type": "dynamodb_item",
        "table": table,
        "keyHash": key_hash,
        "key": masked,
        "attributePath": path,
    }
    if masked != dict(sorted(key.items())) or path != attribute_path:
        out["keyMasked"] = True
    if planted:
        out["planted"] = True
    return out


def finding_id(resource: dict[str, Any], cls: str) -> str:
    """Stable across runs for the same location and class (and object version)."""
    basis = "|".join(f"{k}={resource[k]}" for k in sorted(resource)) + f"|class={cls}"
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
        "link": link if resource.get("keyMasked") is not True else None,
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

    def as_json(self) -> dict[str, Any]:
        d = asdict(self)
        return {
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
) -> dict[str, Any]:
    ranked = sorted(findings, key=lambda f: (-_CONF_RANK[f["severity"]], -f["count"], f["id"]))
    kept = ranked[:MAX_FINDINGS_IN_DOCUMENT]
    totals: dict[str, int] = {}
    for f in findings:
        totals[f["class"]] = totals.get(f["class"], 0) + f["count"]
    return {
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
