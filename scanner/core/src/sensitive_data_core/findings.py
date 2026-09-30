"""The findings contract: what the scanner writes, and nothing else.

A findings document (schema `sensitive-data-scanner.findings`, version 1.11,
JSON Schema in schema/findings.schema.json) says, for one run in one account
and region, which locations hold which classes of sensitive data, how many,
how confident, where in the item, and how much was scanned. It never holds
a value: every string in it is a name, an id, an enum or a masked key.

The same content can go out as EventBridge events (`source`
`sensitive-data-scanner`, `detail-type` `Findings v1`) to a consumer-owned
bus; see `push.py`. The resources and console links of one cloud's stores are
its own package's (AWS: `sensitive_data_scanner.resources`); `store_field` is
the shape any cloud's store can use.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from . import __version__
from .engine.spec import SPEC_VERSION
from .safety import redact_digits

FINDINGS_SCHEMA = "sensitive-data-scanner.findings"
FINDINGS_SCHEMA_VERSION = "1.11"
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

# The storage encryption a finding's data sat under (1.5, #35): the store's own
# configuration says which. `service_managed` is a key the service or the cloud holds
# (SSE-S3, `aws/dynamodb`, an AWS owned key); `customer_managed_key` is the customer's own,
# named only by `atRestKeyHash`, never by its identifier.
NO_ENCRYPTION = "none"
SERVICE_MANAGED = "service_managed"
CUSTOMER_MANAGED_KEY = "customer_managed_key"
UNKNOWN_ENCRYPTION = "unknown"
AT_REST = (NO_ENCRYPTION, SERVICE_MANAGED, CUSTOMER_MANAGED_KEY, UNKNOWN_ENCRYPTION)
STORAGE_ENCRYPTED = frozenset({SERVICE_MANAGED, CUSTOMER_MANAGED_KEY})

# Guidance for the customer's QSA (1.5, #35), never a verdict: the assessor decides.
PCI_STORAGE_ENCRYPTION_NOTE = {
    "requirement": "3.5.1.2",
    "guidance": (
        "PCI DSS 3.5.1.2: storage-level encryption (disk, volume or the service's at-rest "
        "encryption) alone does not render PAN unreadable on non-removable media; PAN is "
        "also to be rendered unreadable by one of the methods in 3.5.1. For your QSA to "
        "assess; the QSA decides."
    ),
}
PCI_CVV_NOTE = {
    "requirement": "3.3.1",
    "guidance": (
        "PCI DSS 3.3.1: sensitive authentication data is not retained after authorization, "
        "even if encrypted; 3.3.1.2 names the card verification code. A card verification "
        "code found in storage is prohibited storage after authorization, whatever the "
        "encryption. For your QSA to assess; the QSA decides."
    ),
}


def pci_note(cls: str, at_rest: str | None) -> dict[str, str] | None:
    """The PCI DSS note for a finding of class `cls` stored under `at_rest` (1.5), or None.

    A `cvv` finding always gets 3.3.1; a `card` finding gets 3.5.1.2 when the store encrypts
    at the storage level (`service_managed` or `customer_managed_key`)."""
    if cls == "cvv":
        return dict(PCI_CVV_NOTE)
    if cls == "card" and at_rest in STORAGE_ENCRYPTED:
        return dict(PCI_STORAGE_ENCRYPTION_NOTE)
    return None


def key_hash(key_id: str) -> str:
    """How a customer managed key is named in a finding: the SHA-256 of its key id (the part
    after `key/` in its ARN), lower-case hex. A key id is never written, even masked; hash
    your own key's id to match."""
    return hashlib.sha256(key_id.strip().encode()).hexdigest()


def encryption_facts(at_rest: str, key_id: str | None = None) -> dict[str, str]:
    """The store facts for one storage encryption (1.5): `atRestEncryption`, and
    `atRestKeyHash` when the key is the customer's (or its kind is unknown) and its id known."""
    if at_rest not in AT_REST:
        raise ValueError("not an at-rest encryption value")
    out = {"atRestEncryption": at_rest}
    if key_id and at_rest in (CUSTOMER_MANAGED_KEY, UNKNOWN_ENCRYPTION):
        out["atRestKeyHash"] = key_hash(key_id)
    return out


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


class Link(str):
    """A console link that knows the names it was built from.

    A finding keeps its link only when none of those names is changed by
    masking (`link_for`): a link names the store, and never an item's key, so
    masking a DynamoDB key or a column name does not cost the finding its link.
    A link built from a masked name is dropped, because it would carry what the
    mask hid. The region and the page's fixed text are never values.
    """

    names: tuple[str, ...]

    def __new__(cls, url: str, names: tuple[str, ...]) -> Link:
        link = super().__new__(cls, url)
        link.names = names
        return link


def link_for(resource: dict[str, Any], link: str | None) -> str | None:
    """The link a finding may carry: a plain string, or None."""
    if link is None:
        return None
    if isinstance(link, Link):
        return None if any(redact_digits(n) != n for n in link.names) else str(link)
    # A link that does not say what it was built from: dropped whenever anything was masked.
    return None if resource.get("keyMasked") or resource.get("nameMasked") else str(link)


def store_field_resource(
    *,
    service: str,
    store: str,
    field: str | None,
    read_by: str,
    database: str | None = None,
    table: str | None = None,
    snapshot_time: str | None = None,
) -> dict[str, Any]:
    """One field of one store that is not S3, logs, DynamoDB or RDS (1.3).

    A column of a warehouse table (`database`, `table`, `field`), a field of a
    search index's documents (`table` is the index), a record stream's or a
    queue's messages, a parameter's or a secret's value. The same shape serves
    any cloud: `service` names the product, `store` the cluster, domain,
    stream, queue, parameter or secret.
    """
    names = {
        k: v
        for k, v in (("store", store), ("database", database), ("table", table), ("field", field))
        if v is not None
    }
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {"type": "store_field", "service": service, **masked, "readBy": read_by}
    if snapshot_time:
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
    facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One finding. `facts` are what an adapter knows about the store from its own
    configuration, the same for every finding in it (#35: `atRestEncryption`); each is
    added to the finding and never replaces a field the contract already has. A fact
    joins the findings schema (a minor bump) in the change that first fills it.

    Every `card` and `cvv` finding also gets its `pciNote` (1.5), from its class and the
    store's `atRestEncryption` (`pci_note`)."""
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
        "link": link_for(resource, link),
        "firstSeenAt": first_seen_at or seen_at,
        "lastSeenAt": seen_at,
    }
    if connect:
        out["connect"] = {k: redact_digits(v) for k, v in connect.items() if v}
    for k, v in (facts or {}).items():
        if k in out:
            raise ValueError("a store fact may not replace a finding field")
        out[k] = redact_digits(v) if isinstance(v, str) and k != "atRestKeyHash" else v
    note = pci_note(cf.cls, out.get("atRestEncryption"))
    if note is not None:
        out["pciNote"] = note
    return out


@dataclass
class Coverage:
    """What one source's pass read, sampled, skipped and could not read."""

    kind: str  # the store kind: s3 | cloudwatch_logs | dynamodb | redshift | ...
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
    disguised: int = 0  # names that claimed another kind than the bytes are (1.9, #65)
    # (1.10, #67) Objects read again though unchanged at the source, by why; the rescans
    # still owed; and the objects the source's index holds (None: it keeps no index).
    rescanned: dict[str, int] = field(default_factory=dict)
    rescan_backlog: int = 0
    indexed: int | None = None
    # (1.10, #67 part 5) Objects not read because their bytes are an indexed object's.
    duplicates: int = 0
    # (1.11, #67) How the store is listed changed: this run listed it again from the start,
    # reading only what changed.
    relisted: bool = False

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
        if self.disguised:
            out["disguised"] = self.disguised
        if self.indexed is not None:
            out["indexed"] = self.indexed
            out["rescanned"] = dict(sorted(self.rescanned.items()))
            out["rescanBacklog"] = self.rescan_backlog
            out["duplicates"] = self.duplicates
        if self.relisted:
            out["relisted"] = True
        return out


def findings_document(
    *,
    run_id: str,
    account: str | None,
    region: str | None,
    started_at: str,
    finished_at: str,
    classes: list[str],
    coverage: list[Coverage],
    findings: list[dict[str, Any]],
    discovery: dict[str, Any] | None = None,
    platform: str | None = None,
    site: str | None = None,
    scanner_version: str | None = None,
    scan_mode: Mapping[str, str] | None = None,
    vendor_coverage: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The findings document. An AWS run names its account and region; a run of another
    platform (1.4: `platform`, such as `database`) names the `site` it runs in instead.

    (1.8, #55) Every finding says its `source` (`scanner` unless an importer made it);
    `scan_mode` is the mode each platform ran in, and `vendor_coverage` each importer's run
    (`modes.VendorCoverage`)."""
    for f in findings:
        f.setdefault("source", "scanner")
    ranked = sorted(findings, key=lambda f: (-_CONF_RANK[f["severity"]], -f["count"], f["id"]))
    kept = ranked[:MAX_FINDINGS_IN_DOCUMENT]
    totals: dict[str, int] = {}
    for f in findings:
        totals[f["class"]] = totals.get(f["class"], 0) + f["count"]
    doc: dict[str, Any] = {
        "schema": FINDINGS_SCHEMA,
        "schemaVersion": FINDINGS_SCHEMA_VERSION,
        "scannerVersion": scanner_version or __version__,
        "specVersion": SPEC_VERSION,
        "runId": run_id,
    }
    if platform is not None:
        doc["platform"] = platform
    if site is not None:
        doc["site"] = site
    if account is not None:
        doc["account"] = account
    if region is not None:
        doc["region"] = region
    doc |= {
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
    if scan_mode:
        doc["scanMode"] = dict(sorted(scan_mode.items()))
    if vendor_coverage is not None:
        doc["vendorCoverage"] = vendor_coverage
    return doc
