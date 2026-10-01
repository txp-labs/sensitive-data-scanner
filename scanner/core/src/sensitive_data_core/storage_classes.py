"""Storage classes and tiers: which objects are read, and what reading them costs (#109).

An object store keeps each object in a storage class (S3), an access tier (Azure
Blob Storage and ADLS Gen2) or a storage class (Google Cloud Storage). Some
classes charge for every byte read; some cannot be read at all until the
object is restored or rehydrated, which is a write the scanner never makes.
**The class comes from the listing the scanner already does** (S3
`ListObjectsV2`'s `StorageClass` and `RestoreStatus`, Azure `List Blobs`'
`AccessTier` and `ArchiveStatus`, Cloud Storage `objects.list`'s
`storageClass`), so an object the rules leave out is never fetched: it costs
nothing.

The rules (docs/limitations.md):

- S3: Standard, Reduced Redundancy, Express One Zone, Intelligent-Tiering
  (frequent, infrequent, archive instant), Standard-IA and One Zone-IA are read
  (IA within the byte budget). Glacier Instant Retrieval is read only with
  `S3_READ_GLACIER_IR` (off: `notAllowed: archive_class`). Glacier Flexible
  Retrieval, Deep Archive and Intelligent-Tiering's Archive and Deep Archive
  Access tiers are the gap `needs_restore` (a restored copy is read); the hook
  `S3_RESTORE_ARCHIVED` names them.
- Azure Blob Storage and ADLS Gen2: Hot and Cool are read. Cold is read only
  with `AZURE_READ_COLD_TIER` (off: `notAllowed: cold_tier`). Archive, and a
  blob whose rehydration is in progress, is the gap `needs_rehydration`; the
  hook `AZURE_REHYDRATE_ARCHIVE` names it.
- Cloud Storage: Standard, Nearline and Coldline are read. Archive is read only
  with `GCS_READ_ARCHIVE` (off: `notAllowed: archive_class`, #105).

A hook switched on changes nothing it cannot do: the class's entry says
`not_implemented`, never a silent no-op.

**Inventory and estimate (findings schema 1.13).** Every store of these kinds
gets `storageClasses` (objects and bytes per class, whether the class is read,
and why not) and `costEstimate` (what reading every object of the classes that
charge per byte would cost once, from the dated price table in
`storage_prices.json`, never from a pricing API at run time). A class that
needs a restore or a rehydration has counts only: the scanner cannot read it,
so it has no estimate.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

NEEDS_RESTORE = "needs_restore"
NEEDS_REHYDRATION = "needs_rehydration"
ARCHIVE_CLASS = "archive_class"
COLD_TIER = "cold_tier"
NOT_IMPLEMENTED = "not_implemented"
# The gaps an archived object is counted in (Coverage.archived) and the store's `gaps` key.
GAP_KEYS = {NEEDS_RESTORE: "needsRestore", NEEDS_REHYDRATION: "needsRehydration"}

# The settings (docs/limitations.md).
S3_READ_GLACIER_IR = "S3_READ_GLACIER_IR"
S3_RESTORE_ARCHIVED = "S3_RESTORE_ARCHIVED"
AZURE_READ_COLD_TIER = "AZURE_READ_COLD_TIER"
AZURE_REHYDRATE_ARCHIVE = "AZURE_REHYDRATE_ARCHIVE"
GCS_READ_ARCHIVE = "GCS_READ_ARCHIVE"

GIB = 1024**3
# Rounding of a USD estimate: a hundredth of a cent.
_USD_PLACES = 4


@dataclass(frozen=True)
class Rule:
    """What the scanner does with an object of one class.

    `read`: read it (within the byte budget). Otherwise `reason` says why not:
    `archive_class` / `cold_tier` (a setting that is off; counted `notAllowed`),
    `needs_restore` / `needs_rehydration` (no read-only way; counted in the
    store's gaps), and `toggle` names the setting. `hook_on`: the setting is a
    hook that is switched on, so the class says `not_implemented`."""

    read: bool
    reason: str | None = None
    toggle: str | None = None
    hook_on: bool = False

    @property
    def archived(self) -> bool:
        return self.reason in GAP_KEYS

    def entry_reason(self) -> str | None:
        return NOT_IMPLEMENTED if self.hook_on else self.reason


READ = Rule(True)


# ------------------------------------------------------------------ S3

S3_ARCHIVED = frozenset({"GLACIER", "DEEP_ARCHIVE"})
# Intelligent-Tiering's two archive tiers (an inventory report's IntelligentTieringAccessTier,
# HeadObject's x-amz-archive-status), filed as classes of their own.
S3_IT_ARCHIVED = {
    "ARCHIVE": "INTELLIGENT_TIERING_ARCHIVE_ACCESS",
    "ARCHIVE_ACCESS": "INTELLIGENT_TIERING_ARCHIVE_ACCESS",
    "DEEP_ARCHIVE": "INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS",
    "DEEP_ARCHIVE_ACCESS": "INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS",
}
# A Glacier or Deep Archive object whose restored copy is available (RestoreStatus).
RESTORED_SUFFIX = "_RESTORED"


def s3_class(obj: Mapping[str, Any]) -> str:
    """An S3 object's class, from the listing (or an inventory report's row): `STANDARD`
    when the listing gives none. A Glacier or Deep Archive object with a restored copy
    available is `<CLASS>_RESTORED`; an Intelligent-Tiering object an inventory report says
    is in an archive tier is filed under that tier."""
    cls = str(obj.get("StorageClass") or "STANDARD").upper()
    if cls in S3_ARCHIVED:
        restore = obj.get("RestoreStatus")
        if (
            isinstance(restore, Mapping)
            and restore.get("IsRestoreInProgress") is False
            and restore.get("RestoreExpiryDate")
        ):
            return cls + RESTORED_SUFFIX
        return cls
    if cls == "INTELLIGENT_TIERING":
        tier = str(obj.get("IntelligentTieringAccessTier") or "").upper()
        return S3_IT_ARCHIVED.get(tier, cls)
    return cls


def s3_rule(cls: str, *, read_glacier_ir: bool, restore_archived: bool) -> Rule:
    if cls == "GLACIER_IR":
        return READ if read_glacier_ir else Rule(False, ARCHIVE_CLASS, S3_READ_GLACIER_IR)
    if cls in S3_ARCHIVED or cls in S3_IT_ARCHIVED.values():
        return Rule(False, NEEDS_RESTORE, S3_RESTORE_ARCHIVED, hook_on=restore_archived)
    return READ


# ------------------------------------------------------------------ Azure

AZURE_ARCHIVE_PENDING = "rehydrate-pending"


def azure_tier(blob_tier: Any, archive_status: Any = None) -> str:
    """A blob's tier as the listing gives it (`Hot`, `Cool`, `Cold`, `Archive`). A blob in a
    rehydration still lists as `Archive` (its `ArchiveStatus` says
    `rehydrate-pending-to-...`). A blob with no tier (a premium account's block blob, a
    page or append blob) is `Premium`, read like Hot."""
    tier = str(blob_tier or "").strip()
    if str(archive_status or "").lower().startswith(AZURE_ARCHIVE_PENDING):
        return "Archive"
    if not tier:
        return "Premium"
    return tier[:1].upper() + tier[1:].lower()


def azure_rule(tier: str, *, read_cold: bool, rehydrate_archive: bool) -> Rule:
    if tier == "Cold":
        return READ if read_cold else Rule(False, COLD_TIER, AZURE_READ_COLD_TIER)
    if tier == "Archive":
        return Rule(False, NEEDS_REHYDRATION, AZURE_REHYDRATE_ARCHIVE, hook_on=rehydrate_archive)
    return READ


# ------------------------------------------------------------------ Google Cloud Storage


def gcs_class(obj: Mapping[str, Any]) -> str:
    return str(obj.get("storageClass") or "STANDARD").upper()


def gcs_rule(cls: str, *, read_archive: bool) -> Rule:
    if cls == "ARCHIVE" and not read_archive:
        return Rule(False, ARCHIVE_CLASS, GCS_READ_ARCHIVE)
    return READ


# ------------------------------------------------------------------ the inventory


@dataclass
class ClassCount:
    objects: int = 0
    bytes: int = 0
    # The bytes a read of every object would fetch (each up to MAX_OBJECT_BYTES): the
    # estimate's basis, never in the document.
    planned: int = 0


@dataclass
class ClassInventory:
    """Objects and bytes per storage class, over one listing pass of a store.

    A pass can take several runs; the running counts are kept in the source's cursor
    (`cursor()` / `resume()`), and the document shows the last complete pass's (or, before
    the first completes, the pass so far, `complete: false`)."""

    platform: str
    region: str | None
    counts: dict[str, ClassCount] = field(default_factory=dict)
    rules: dict[str, Rule] = field(default_factory=dict)
    complete: bool = False

    def add(self, cls: str, size: int, planned: int, rule: Rule) -> None:
        c = self.counts.setdefault(cls, ClassCount())
        c.objects += 1
        c.bytes += max(0, size)
        c.planned += max(0, planned)
        self.rules[cls] = rule

    def remove(self, cls: str, size: int, planned: int) -> None:
        """Take back one object: the run stopped before it (no budget left), and the next run
        lists it again."""
        c = self.counts.get(cls)
        if c is not None and c.objects > 0:
            c.objects -= 1
            c.bytes = max(0, c.bytes - max(0, size))
            c.planned = max(0, c.planned - max(0, planned))
            if c.objects == 0:
                del self.counts[cls]

    def move(self, size: int, planned: int, src: str, dst: str, rule: Rule) -> None:
        """An object counted under `src` is in `dst` (an Intelligent-Tiering object found in an
        archive tier only when its GET was refused)."""
        self.remove(src, size, planned)
        self.add(dst, size, planned, rule)

    def merge(self, other: ClassInventory) -> None:
        for cls, c in other.counts.items():
            mine = self.counts.setdefault(cls, ClassCount())
            mine.objects += c.objects
            mine.bytes += c.bytes
            mine.planned += c.planned
        self.rules.update(other.rules)
        self.complete = self.complete and other.complete

    def cursor(self) -> dict[str, list[int]]:
        return {k: [c.objects, c.bytes, c.planned] for k, c in sorted(self.counts.items())}

    @classmethod
    def resume(cls, platform: str, region: str | None, saved: Any) -> ClassInventory:
        inv = cls(platform, region)
        if isinstance(saved, dict):
            for k, v in saved.items():
                if isinstance(k, str) and isinstance(v, list) and len(v) == 3:
                    try:
                        inv.counts[k] = ClassCount(*(max(0, int(x)) for x in v))
                    except (TypeError, ValueError):
                        continue
        return inv

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for cls, c in sorted(self.counts.items()):
            rule = self.rules.get(cls, READ)
            entry: dict[str, Any] = {"objects": c.objects, "bytes": c.bytes, "read": rule.read}
            reason = rule.entry_reason()
            if reason:
                entry["reason"] = reason
            if rule.toggle:
                entry["toggle"] = rule.toggle
            out[_class_key(cls)] = entry
        return out

    def unread_toggle(self) -> str | None:
        """The setting that would read the most of what was left unread: a class a setting
        that is off leaves out first (it reads at once), then a hook."""
        ranked = sorted(
            (
                (r.archived, -self.counts[k].bytes, r.toggle)
                for k, r in self.rules.items()
                if not r.read and r.toggle and k in self.counts
            ),
        )
        return ranked[0][2] if ranked else None


def _class_key(cls: str) -> str:
    """A class name as the schema allows it (letters, digits, `_`)."""
    out = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in cls)[:60]
    return out or "UNKNOWN"


# ------------------------------------------------------------------ prices and the estimate

PRICES_FILE = Path(__file__).with_name("storage_prices.json")


@cache
def price_table() -> dict[str, Any]:
    """The dated price table (scripts/storage_prices.py writes it)."""
    table: dict[str, Any] = json.loads(PRICES_FILE.read_text())
    return table


@dataclass(frozen=True)
class Prices:
    region: str
    fallback: bool
    date: str
    classes: dict[str, dict[str, float]]


def prices_for(platform: str, region: str | None) -> Prices | None:
    """The prices of one platform's region. A region the table does not have is priced as the
    platform's fallback region (us-east-1, eastus; Cloud Storage has one price everywhere),
    and the estimate says so (`regionFallback`)."""
    p = price_table().get("platforms", {}).get(platform)
    if not isinstance(p, dict):
        return None
    regions: dict[str, Any] = p.get("regions", {})
    fallback_region = str(p.get("fallbackRegion"))
    key = (region or "").lower().replace(" ", "")
    if key in regions:
        return Prices(key, False, str(p["priceDate"]), regions[key])
    if "*" in regions:
        return Prices(key or "*", False, str(p["priceDate"]), regions["*"])
    if fallback_region in regions:
        return Prices(fallback_region, True, str(p["priceDate"]), regions[fallback_region])
    return None


def _price_key(platform: str, cls: str) -> str:
    """The price table's row for a class: Azure's tiers by name; a restored Glacier copy is
    not priced (its retrieval was paid by the restore)."""
    if platform == "gcp" and cls in ("MULTI_REGIONAL", "REGIONAL"):
        return "STANDARD"
    if platform == "gcp" and cls == "DURABLE_REDUCED_AVAILABILITY":
        return "NEARLINE"
    return cls


def estimate(inv: ClassInventory) -> dict[str, Any] | None:
    """The cost to read every object once, of the classes that charge per byte read and that
    the scanner can read (now, or with their setting on): retrieval per GB of the bytes a
    read fetches (each object up to MAX_OBJECT_BYTES), plus one GET per object. Ranged reads
    of a large or columnar object take a few GETs more, so the request part is a floor.
    `estimatedToScanUsd` is the classes read now; `byClass` is every priced class, read or
    not (what turning its setting on would cost). None when no class charges per byte or the
    platform has no prices."""
    prices = prices_for(inv.platform, inv.region)
    if prices is None:
        return None
    retrieval: dict[str, float] = {}
    requests: dict[str, float] = {}
    by_class: dict[str, float] = {}
    total = 0.0
    for cls, c in sorted(inv.counts.items()):
        rule = inv.rules.get(cls, READ)
        if rule.archived:
            continue  # no read-only way: counts only
        row = prices.classes.get(_price_key(inv.platform, cls))
        if row is None or float(row.get("retrievalPerGb") or 0) <= 0:
            continue
        per_gb = float(row["retrievalPerGb"])
        per_1k = float(row.get("getPer1k") or 0)
        usd = c.planned / GIB * per_gb + c.objects / 1000 * per_1k
        key = _class_key(cls)
        retrieval[key] = per_gb
        requests[key] = per_1k
        by_class[key] = _usd(usd)
        if rule.read:
            total += usd
    if not by_class:
        return None
    out: dict[str, Any] = {
        "currency": "USD",
        "retrievalPerGb": retrieval,
        "requestsPer1k": requests,
        "estimatedToScanUsd": _usd(total),
        "byClass": by_class,
        "priceDate": prices.date,
        "region": prices.region,
    }
    if prices.fallback:
        out["regionFallback"] = True
    return out


def _usd(v: float) -> float:
    if not math.isfinite(v) or v <= 0:
        return 0.0
    return round(v, _USD_PLACES)
