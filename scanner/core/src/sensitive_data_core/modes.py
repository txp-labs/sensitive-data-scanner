"""Who finds the data, per platform: our scanner, the vendor's own detection, or both (#55).

A customer chooses, per platform, how its sensitive data is found:

- `scanner` (the default): this scanner reads the stores itself;
- `vendor`: the platform's own detection (Amazon Macie, Google Sensitive Data
  Protection, Microsoft Purview DLP, the Google Workspace Alert Center's DLP
  rules, Slack's DLP) has found it, and an **importer** turns the vendor's
  findings into this scanner's findings; this scanner reads nothing itself;
- `both`: the scanner reads, the importer imports, and a finding of one that
  sits at the same location and class as a finding of the other is **linked**
  to it (`linked`), never merged.

An importer runs in the customer's environment, like the scanner. What it
imports is **never a value**: a vendor's findings can carry snippets, samples,
matched text and offsets into the item, and none of it is read into a finding.
A vendor finding keeps only the location (masked under the scanner's rules),
the vendor's detector type (`vendorType`, when it is a type's name), counts,
and the vendor's id for the finding (masked). Its class is the spec's class
the vendor's type maps to, or `other`.

Every finding says where it came from (`source`: `scanner`, or
`vendor:<name>`). The document says which mode ran for each platform
(`scanMode`), and each importer's run with what the vendor's tool does not
cover (`vendorCoverage`: `limits`).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .findings import SEVERITY, Link, finding_id, link_for, pci_note
from .safety import redact_digits

SCANNER = "scanner"
VENDOR = "vendor"
BOTH = "both"
MODES = (SCANNER, VENDOR, BOTH)
OTHER = "other"
CONFIDENCE = ("low", "medium", "high")
_TYPE = re.compile(r"[^A-Za-z0-9_ .:/()-]")
# What a vendor's tool may not cover, as fixed codes (the coverage summary's `limits`).
LIMITS = frozenset(
    {
        # Macie reads S3 only; SDP profiles BigQuery and Cloud Storage (and databases it is
        # configured for); each other kind here is the scanner's alone.
        "s3_only",
        "profiled_stores_only",
        # The vendor samples (Macie's automated discovery, SDP's profiles).
        "sampled_by_vendor",
        # Profiles are per table, column or file store, not per item.
        "profiles_not_items",
        # Only matches of the customer's own policies or rules, and only those that raised
        # an alert or an audit event.
        "policy_matches_only",
        "alerts_only",
        # The vendor's finding names no item id this scanner can link to.
        "item_not_linkable",
        # The vendor's counts are occurrences, not distinct values.
        "counts_not_distinct",
        # Slack's audit logs and DLP: Enterprise Grid only.
        "enterprise_grid_only",
        # The vendor names the rule that matched, not the kind of data (class `other`): its
        # findings are never linked, since a link needs the same class.
        "no_data_class",
    }
)


class ModeError(ValueError):
    """A mode that is not `scanner`, `vendor` or `both`."""


def read_mode(raw: str | None) -> str:
    """A platform's mode from its setting (`SCAN_MODE`, or a SaaS vendor's own)."""
    t = (raw or SCANNER).strip().lower()
    if t not in MODES:
        raise ModeError("mode")
    return t


def source_of(vendor: str) -> str:
    return f"vendor:{vendor}"


def vendor_type(raw: Any) -> str | None:
    """A vendor's detector type as a finding may carry it: a short name, masked; else None."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = _TYPE.sub("", raw.strip())[:80]
    return redact_digits(text) or None


def vendor_class(raw: Any, table: Mapping[str, str]) -> tuple[str, str | None]:
    """The spec's class for a vendor's detector type, and the type as the finding names it."""
    name = vendor_type(raw)
    if name is None:
        return OTHER, None
    return table.get(name.upper(), OTHER), name


@dataclass
class VendorDetection:
    """One class of data a vendor found at one location: counts only."""

    cls: str
    vendor_type: str | None = None
    count: int = 0
    occurrences: int = 1
    confidence: str = "medium"


def vendor_finding(
    resource: dict[str, Any],
    link: str | None,
    detection: VendorDetection,
    *,
    vendor: str,
    seen_at: str,
    vendor_finding_id: str | None = None,
    facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One finding from a vendor's detection: the scanner's contract, with no offsets (a
    vendor's positions point into content this scanner did not read), `via: vendor`,
    `format: vendor`, and its source. Nothing of the vendor's but names is copied."""
    cls = detection.cls if re.fullmatch(r"[a-z][a-z0-9_]*", detection.cls) else OTHER
    occurrences = max(1, int(detection.occurrences or 0))
    confidence = detection.confidence if detection.confidence in CONFIDENCE else "medium"
    out: dict[str, Any] = {
        # A vendor's type is part of the id: two `other` types at one place stay two.
        "id": finding_id(
            {**resource, "source": source_of(vendor), "vendorType": detection.vendor_type or ""},
            cls,
        ),
        "resource": resource,
        "format": "vendor",
        "class": cls,
        "severity": SEVERITY.get(cls, "low" if cls == OTHER else "medium"),
        "count": max(0, int(detection.count or 0)),
        "occurrences": occurrences,
        "confidence": confidence,
        "confidenceCounts": {confidence: occurrences},
        "via": ["vendor"],
        "offsets": [],
        "offsetsTruncated": False,
        "link": link_for(resource, link),
        "firstSeenAt": seen_at,
        "lastSeenAt": seen_at,
        "source": source_of(vendor),
    }
    if detection.vendor_type:
        out["vendorType"] = detection.vendor_type
    if vendor_finding_id:
        out["vendorFindingId"] = redact_digits(str(vendor_finding_id))[:200]
    for k, v in (facts or {}).items():
        if k in out:
            raise ValueError("a store fact may not replace a finding field")
        out[k] = redact_digits(v) if isinstance(v, str) and k != "atRestKeyHash" else v
    note = pci_note(cls, out.get("atRestEncryption"))
    if note is not None:
        out["pciNote"] = note
    return out


# Resource fields that name where the data is: what two sources' findings are compared by.
_WHERE = {
    "s3_object": ("bucket", "key"),
    "gcs_object": ("bucket", "object"),
    "blob_object": ("account", "container", "blob"),
    "store_field": ("service", "store", "database", "table", "field"),
    "saas_item": ("vendor", "service", "tenantHash", "itemHash"),
}


def location_key(resource: Mapping[str, Any]) -> tuple[Any, ...] | None:
    """Where a finding's data is, comparable across sources (an object's version, a column of
    a table file and a part of an item are left out: the same place, read differently)."""
    kind = resource.get("type")
    names = _WHERE.get(str(kind))
    if names is None:
        return None
    return (kind, *(resource.get(n) for n in names))


def link_duplicates(findings: Iterable[dict[str, Any]]) -> int:
    """In `both` mode: a finding at the same location and class as a finding of another
    source is linked to it (`linked`, the other findings' ids), never merged. Returns how
    many findings were linked."""
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for f in findings:
        key = location_key(f.get("resource") or {})
        if key is None:
            continue
        groups.setdefault((*key, f.get("class")), []).append(f)
    linked = 0
    for group in groups.values():
        sources = {f.get("source", SCANNER) for f in group}
        if len(sources) < 2:
            continue
        for f in group:
            others = sorted(
                g["id"] for g in group if g.get("source", SCANNER) != f.get("source", SCANNER)
            )
            if others:
                f["linked"] = others[:20]
                linked += 1
    return linked


@dataclass
class VendorCoverage:
    """One importer's run: its vendor, whether it read, and what the vendor does not cover."""

    vendor: str
    platform: str
    mode: str
    status: str = "read"  # read | not_enabled | access_denied | error | throttled
    error: str | None = None
    findings: int = 0
    covers: tuple[str, ...] = ()
    limits: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "vendor": self.vendor,
            "platform": self.platform,
            "mode": self.mode,
            "status": self.status,
            "findings": self.findings,
            "covers": sorted(self.covers),
            "limits": sorted(x for x in self.limits if x in LIMITS),
        }
        if self.error:
            out["error"] = re.sub(r"[^A-Za-z0-9._:-]", "", self.error)[:80] or "Error"
        return out


def vendor_link(url: str, *names: str) -> Link:
    """A link into the vendor's own console, built from the names (ids) it carries."""
    return Link(url, tuple(n for n in names if n))


def hashed(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
