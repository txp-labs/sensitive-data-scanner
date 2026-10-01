"""Managed disk snapshots: coverage only. Reading one would need a SAS export, a write.

**Discovery** (Resource Graph, Reader) lists every managed disk snapshot in
scope and groups them by the disk they were taken of, as the AWS scanner does
with EBS: one store per disk (`azure_disk_snapshot`, the disk's name, or the
snapshot's when the disk is gone) holding its latest snapshot, with
`snapshotTime`, `sizeBytes`, `olderSnapshots` and the snapshot's encryption.

**Why it is not read.** A snapshot's bytes are reachable only through
`beginGetAccess`, which puts the snapshot in an exported state and mints a SAS
URL for it (`Microsoft.Compute/snapshots/beginGetAccess/action`), then
`endGetAccess`. Both change the resource, so the scanner, which holds read
roles only, never calls them. Every snapshot is the gap `needs_sas_export`,
naming `toggle: AZURE_READ_SNAPSHOTS`. docs/AZURE.md describes the opt-in
export reader, designed and not built: that setting is its hook (#105), and
turned on, each snapshot is `not_implemented`, never a silent pass.

**Encryption (1.5):** `EncryptionAtRestWithPlatformKey` is `service_managed`;
a customer key (`EncryptionAtRestWithCustomerKey`, or platform and customer
keys) through a disk encryption set is `customer_managed_key`, hashed from the
set's active key.
"""

from __future__ import annotations

from typing import Any

from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.findings import UNKNOWN_ENCRYPTION, encryption_facts

from ..resources import ResourceId, azure_fields
from .base import Context, key_facts

KIND = "azure_disk_snapshot"

SNAPSHOTS = """resources
| where type =~ 'microsoft.compute/snapshots'
| project id, name, tags,
    source = tolower(tostring(properties.creationData.sourceResourceId)),
    created = tostring(properties.timeCreated),
    sizeBytes = tolong(properties.diskSizeBytes),
    encryption = tostring(properties.encryption.type),
    encryptionSet = tolower(tostring(properties.encryption.diskEncryptionSetId))
| order by id asc"""
DISK_ENCRYPTION_SETS = """resources
| where type =~ 'microsoft.compute/diskencryptionsets'
| project id = tolower(id), keyUrl = tostring(properties.activeKey.keyUrl)
| order by id asc"""


def _facts(row: dict[str, Any], sets: dict[str, str]) -> dict[str, str]:
    kind = str(row.get("encryption") or "").lower()
    if kind == "encryptionatrestwithplatformkey":
        return key_facts("Microsoft.Storage")
    if "customerkey" in kind:
        return key_facts("Microsoft.Keyvault", sets.get(str(row.get("encryptionSet") or "")))
    return encryption_facts(UNKNOWN_ENCRYPTION)


class DiskSnapshotAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        sets = {
            str(r.get("id") or ""): str(r.get("keyUrl") or "")
            for r in ctx.graph(DISK_ENCRYPTION_SETS)
        }
        by_disk: dict[str, list[dict[str, Any]]] = {}
        for row in ctx.graph(SNAPSHOTS):
            source = str(row.get("source") or "") or str(row.get("id") or "").lower()
            by_disk.setdefault(source, []).append(row)
        for source, rows in sorted(by_disk.items()):
            rows.sort(key=lambda r: str(r.get("created") or ""))
            latest = rows[-1]
            snapshot = ResourceId.parse(str(latest.get("id") or ""))
            disk = ResourceId.parse(source)
            gone = source == snapshot.value.lower()
            store = Store(KIND, snapshot.name if gone else disk.name)
            store.tags = {str(k): str(v) for k, v in (latest.get("tags") or {}).items()}
            store.extra.update(azure_fields(snapshot))
            store.extra["resource"] = "snapshot"
            if latest.get("created"):
                store.extra["snapshotTime"] = str(latest["created"])
            if len(rows) > 1:
                store.extra["olderSnapshots"] = len(rows) - 1
            if latest.get("sizeBytes") is not None:
                store.size_bytes = int(latest["sizeBytes"])
            store.facts = _facts(latest, sets)
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            if ctx.settings.read_snapshots:
                store.not_implemented("AZURE_READ_SNAPSHOTS")  # the export reader is a hook
            else:
                # beginGetAccess changes the snapshot: never called
                store.toggle_off("AZURE_READ_SNAPSHOTS", "needs_sas_export")

    def source(self, ctx: Context, store: Store) -> None:
        return None
