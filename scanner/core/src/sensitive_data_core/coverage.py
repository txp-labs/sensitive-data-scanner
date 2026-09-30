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

from .rules import KeyFilter, StoreRule
from .safety import redact_digits

ACCESS_DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AllAccessDisabled",
        # Azure (1.6): a role the identity lacks, on the management or the data plane.
        "AuthorizationFailed",
        "AuthorizationPermissionMismatch",
        "Forbidden",
        # Google Cloud (1.7): a permission the service account lacks.
        "PERMISSION_DENIED",
        # SaaS (1.8): Microsoft Graph's codes for a permission or a scope the app lacks.
        "ErrorAccessDenied",
        "Authorization_RequestDenied",
        "accessDenied",
    }
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
        "arn",
        "branch",
        "bus",
    }
)


# Store fields that are SHA-256 hex digests, never masked.
_HASHES = frozenset({"resourceIdHash", "resourceNameHash", "tenantHash", "ownerHash"})


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
    # Which object keys are read (a bucket's `keyInclude` / `keyExclude`); empty: every key.
    key_filter: KeyFilter = field(default_factory=KeyFilter)
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
            # A hash (1.6: `resourceIdHash`) is hex that holds no value; masking would break it.
            out[k] = redact_digits(v) if isinstance(v, str) and k not in _HASHES else v
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
    (never read what may be denied). **An allow list restricts per kind**: the allow
    rules that apply to a store are those of its own kind (`s3:prod-*`) and those of
    no kind (`tag:pii-scan=yes`, `*-archive`, which apply to every kind). When any
    apply, a store none of them names is `not_allowed`; a kind no allow rule applies
    to is not restricted (an `s3:` allow rule leaves DynamoDB tables alone).
    """
    kind, name, tags = store.kind, store.name, store.tags
    if any(r.matches(kind, name, tags) for r in deny):
        store.skip("denied")
        return False
    if tag_error is not None and any(r.needs_tags and r.kind in (None, kind) for r in deny):
        store.skip("tags_unreadable", tag_error)
        return False
    own = [r for r in allow if r.kind in (None, kind)]
    if own and not any(r.matches(kind, name, tags) for r in own):
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
    # A source that found, when it tried, that it cannot or may not read (1.5).
    "vpc_only": ("skipped", "vpc_only"),
    "no_read_path": ("skipped", "no_read_path"),
    "user_can_write": ("skipped", "user_can_write"),
    "db_user_can_write": ("skipped", "db_user_can_write"),
    "grants_unverifiable": ("skipped", "grants_unverifiable"),
    # (1.6) The store's network rules keep the scanner out (a firewall, private access only).
    "network": ("skipped", "network"),
    # (1.6) A login or a role the store refused, named by a source that cannot say it by an
    # error name (a database driver's exception class says nothing about why).
    "access_denied": ("error", "access_denied"),
    "driver_missing": ("skipped", "driver_missing"),
    # (1.7) A Cloud Storage bucket whose reads are billed to the reader's project.
    "requester_pays": ("skipped", "requester_pays"),
    # (1.7) A BigQuery table with row-level access policies: a sample would hold only the rows
    # the scanner is granted.
    "row_level_policy": ("skipped", "row_level_policy"),
    # (1.8) SaaS: a grant the scanner could not prove is scoped (a mailbox read without the
    # scope check), or one it proved is not; an API the vendor has not approved the app for;
    # a user with no mailbox or drive; and a vendor that kept throttling past the budget.
    "scope_unverified": ("skipped", "scope_unverified"),
    "unscoped_grant": ("skipped", "unscoped_grant"),
    "protected_api": ("skipped", "protected_api"),
    "not_provisioned": ("skipped", "not_provisioned"),
    "throttled": ("deferred", "throttled"),
    # (1.8) A Slack channel the app's bot was not invited to (joining would be a write).
    "not_a_member": ("skipped", "not_a_member"),
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
    not_allowed = sum(sum(c.not_allowed.values()) for c in coverages)
    if not_allowed:
        store.gaps["notAllowed"] = not_allowed
    disguised = sum(c.disguised for c in coverages)
    if disguised:
        store.gaps["disguised"] = disguised
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
    # (1.11, #94) The stores still behind, by kind: read in part (`backlog`), or not
    # reached this run (`deferred`). Empty when every pass is complete.
    backlog: dict[str, int] = {}
    for s in stores:
        by_status[s.status] = by_status.get(s.status, 0) + 1
        if s.reason:
            by_reason[s.reason] = by_reason.get(s.reason, 0) + 1
        if s.backlog or (s.status == "deferred" and s.reason == "budget"):
            backlog[s.kind] = backlog.get(s.kind, 0) + 1
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
        "backlogByKind": dict(sorted(backlog.items())),
    }
