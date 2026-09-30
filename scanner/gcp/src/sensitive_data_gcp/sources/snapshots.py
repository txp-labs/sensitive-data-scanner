"""Persistent disk snapshots: coverage only. Reading one needs a disk made from it, a write.

**Discovery** (`DISCOVER` includes `gce_snapshot`): Cloud Asset Inventory says
which projects hold snapshots (`compute.googleapis.com/Snapshot`); each such
project's snapshots come from the Compute Engine API
(`compute.snapshots.list`, Compute Viewer), grouped by the disk they were taken
of, as the AWS scanner groups EBS snapshots: one store per disk (the disk's
name, or the snapshot's when the disk is gone) holding its latest snapshot,
with `snapshotTime`, `sizeBytes` and `olderSnapshots`.

**Why it is not read.** Compute Engine has no API that reads a snapshot's
blocks: the only way is to create a disk from it and attach that disk to a VM,
both writes (and a VM the scanner would have to run). So every snapshot is the
gap `needs_disk_restore`.

**Encryption (1.5):** a snapshot under a Cloud KMS key
(`snapshotEncryptionKey.kmsKeyName`) is `customer_managed_key`, hashed; one
under a customer-supplied key is `customer_managed_key` with no hash (the key
is the customer's alone); otherwise `service_managed`.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.findings import CUSTOMER_MANAGED_KEY, encryption_facts
from sensitive_data_core.safety import error_name

from ..resources import Located
from .base import Context, kms_facts, labels

KIND = "gce_snapshot"
ASSET_TYPE = "compute.googleapis.com/Snapshot"
COMPUTE = "https://compute.googleapis.com/compute/v1"


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _facts(snap: dict[str, Any]) -> dict[str, str]:
    key = snap.get("snapshotEncryptionKey") or {}
    if key.get("kmsKeyName"):
        return kms_facts(str(key["kmsKeyName"]))
    if key.get("sha256") or key.get("rsaEncryptedKey") or key.get("rawKey"):
        return encryption_facts(CUSTOMER_MANAGED_KEY)
    return kms_facts(None)


class SnapshotAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        projects = sorted(
            {
                str(r.get("name") or "").split("/projects/", 1)[-1].split("/", 1)[0]
                for r in ctx.search(ASSET_TYPE)
            }
            - {""}
        )
        for project in projects:
            url = f"{COMPUTE}/projects/{_q(project)}/global/snapshots"
            snaps: list[dict[str, Any]] = []
            try:
                for page, _ in ctx.rest.pages(url, "items", {"maxResults": "500"}):
                    snaps.extend(s for s in page if isinstance(s, dict))
            except Exception as err:  # the project is reported with its error
                store = Store(KIND, f"{project}/*")
                store.extra.update(
                    Located(project, f"//compute.googleapis.com/projects/{project}").fields()
                )
                store.status, store.error = "error", error_name(err)
                store.reason = "access_denied" if store.error == "PERMISSION_DENIED" else "error"
                out.stores.append(store)
                continue
            by_disk: dict[str, list[dict[str, Any]]] = {}
            for s in snaps:
                source = str(s.get("sourceDisk") or "") or f"snapshot:{s.get('name')}"
                by_disk.setdefault(source, []).append(s)
            for source, rows in sorted(by_disk.items()):
                rows.sort(key=lambda r: str(r.get("creationTimestamp") or ""))
                latest = rows[-1]
                gone = source.startswith("snapshot:")
                name = str(latest.get("name") or "") if gone else source.rsplit("/", 1)[-1]
                snap = str(latest.get("name") or "")
                full = f"//compute.googleapis.com/projects/{project}/global/snapshots/{snap}"
                store = Store(KIND, name, tags=labels(latest))
                store.extra.update(Located(project, full).fields())
                store.extra["resource"] = "snapshot"
                if latest.get("creationTimestamp"):
                    store.extra["snapshotTime"] = str(latest["creationTimestamp"])
                if len(rows) > 1:
                    store.extra["olderSnapshots"] = len(rows) - 1
                size = latest.get("storageBytes") or (int(latest.get("diskSizeGb") or 0) * 1024**3)
                if size:
                    store.size_bytes = int(size)
                store.facts = _facts(latest)
                out.stores.append(store)
                if apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                    store.skip("needs_disk_restore")  # a disk from it is a write: never made

    def source(self, ctx: Context, store: Store) -> None:
        return None
