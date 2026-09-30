"""The coverage summary: every store a run found, what happened to it, and why.

A store is listed by an adapter (discovery), decided by the allow and deny
rules (`apply_rules`), read by its sources, and settled from their coverage
(`settle`). The run summary (`summary`) lists every store, **including the
ones not read and why** (`denied`, `not_allowed`, `self`, `too_large`,
`unsupported`, `kms_access`, `access_denied`, `tags_unreadable`, `deferred`
to a later run by the budget, or an adapter's own reason), so a coverage gap
is visible rather than silent. Names in the summary are masked like object
keys. Nothing here names a cloud.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .rules import StoreRule
from .safety import redact_digits

ACCESS_DENIED = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AllAccessDisabled"}
)
MAX_STORES_IN_SUMMARY = 5000

_INTERNAL = frozenset(
    {
        "tableArn",
        "endpoint",
        "snapshotId",
        "volumeGiB",
        "queueUrl",
        "s3Locations",
        "names",
        "tableName",
        "itemFacts",
    }
)


@dataclass
class Store:
    """One data store, listed by discovery or named in the configuration."""

    kind: str  # s3 | cloudwatch_logs | dynamodb | glue_table | rds, or an adapter's kind
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
    # An adapter's own description of where the store's rows are (AWS: a Glue table).
    table: Any = None
    # What the store's own configuration says about all of its data (1.5: `atRestEncryption`
    # and `atRestKeyHash`, `findings.encryption_facts`). Its sources give each finding these,
    # and the run summary shows them.
    facts: dict[str, Any] = field(default_factory=dict)

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
        for k, v in self.extra.items():
            if k in _INTERNAL:
                continue
            out[k] = redact_digits(v) if isinstance(v, str) else v
        for k in ("atRestEncryption", "atRestKeyHash"):
            if self.facts.get(k):
                out[k] = self.facts[k]
        return out


@dataclass
class Discovery:
    stores: list[Store] = field(default_factory=list)
    list_errors: dict[str, str] = field(default_factory=dict)


def apply_rules(
    store: Store,
    allow: Sequence[StoreRule],
    deny: Sequence[StoreRule],
    tag_error: str | None = None,
) -> bool:
    """Apply the allow and deny rules to one store. False when it was skipped.

    A deny rule wins; a deny-by-tag rule that cannot be checked skips the store
    (never read what may be denied); with an allow list, a store it does not
    name is `not_allowed`.
    """
    kind, name, tags = store.kind, store.name, store.tags
    if any(r.matches(kind, name, tags) for r in deny):
        store.skip("denied")
        return False
    if tag_error is not None and any(r.needs_tags and r.kind in (None, kind) for r in deny):
        store.skip("tags_unreadable", tag_error)
        return False
    if allow and not any(r.matches(kind, name, tags) for r in allow):
        store.skip("not_allowed", tag_error)
        return False
    return True


def reason_for(error: str | None) -> str:
    """`access_denied` for an access error (by its name), else `error`."""
    return "access_denied" if error in ACCESS_DENIED else "error"


NOTES = {
    "export_pending": ("deferred", "export_pending"),
    "no_grant": ("skipped", "no_grant"),
    "budget": ("deferred", "budget"),
    "no_snapshot": ("skipped", "no_snapshot"),
    "export_failed": ("error", "export_failed"),
}


def settle(
    store: Store,
    coverages: list[Any],
    notes: list[str | None] | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """A store's status and gaps from the coverage of its sources this run."""
    if not coverages:
        return
    for k, v in (extra or {}).items():
        if v is not None:
            store.extra[k] = v
    note = next((n for n in notes or [] if n), None)
    if note in NOTES:
        store.status, store.reason = NOTES[note]
        store.backlog = any(c.backlog for c in coverages)
        if store.status == "error":
            store.error = next((c.error for c in coverages if c.error), None)
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
        store.reason = "kms_access" if errors[0].kms_denied else reason_for(store.error)
        if store.reason == "access_denied" and store.extra.get("lakeFormation"):
            store.reason = "lake_formation"
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
