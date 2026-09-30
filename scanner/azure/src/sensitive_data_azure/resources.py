"""Azure's resources in findings: where a store is, masked, hashed and linked.

A store's Azure resource ID names its subscription, resource group and
resource, any of which a customer may have named with a number in it. So a
finding and a run summary entry carry:

- `subscription`: the subscription id (a GUID, masked like every name);
- `resourceGroup`: the resource group, masked like a key;
- `resourceIdHash`: the SHA-256 of the lower-cased resource ID, so a
  consumer can match a finding to a resource it knows without the ID being
  written (hash yours the same way: `printf %s "<id>" | tr A-Z a-z | shasum -a 256`).

A `link` goes to the resource's page in the Azure portal. It is built from the
subscription, resource group and resource names, and dropped when any of them
had to be masked (the core's `Link`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.findings import Link
from sensitive_data_core.safety import redact_digits

PORTAL = "https://portal.azure.com/#resource"


def resource_id_hash(resource_id: str) -> str:
    """How a resource ID is named: the SHA-256 of it, lower-cased, as lower-case hex."""
    return hashlib.sha256(resource_id.strip().lower().encode()).hexdigest()


@dataclass(frozen=True)
class ResourceId:
    """The parts of an Azure resource ID a finding names."""

    value: str
    subscription: str = ""
    resource_group: str = ""
    name: str = ""

    @classmethod
    def parse(cls, value: str) -> ResourceId:
        parts = value.strip("/").split("/")
        low = [p.lower() for p in parts]

        def after(key: str) -> str:
            return (
                parts[low.index(key) + 1] if key in low and low.index(key) + 1 < len(parts) else ""
            )

        return cls(
            value, after("subscriptions"), after("resourcegroups"), parts[-1] if parts else ""
        )

    def __repr__(self) -> str:
        return f"ResourceId({redact_digits(self.name)!r})"


def azure_fields(rid: ResourceId) -> dict[str, Any]:
    """`subscription`, `resourceGroup` and `resourceIdHash` for a finding or a store."""
    out: dict[str, Any] = {}
    if rid.subscription:
        out["subscription"] = redact_digits(rid.subscription)
    if rid.resource_group:
        out["resourceGroup"] = redact_digits(rid.resource_group)
    out["resourceIdHash"] = resource_id_hash(rid.value)
    return out


def portal_link(rid: ResourceId, page: str = "overview") -> Link:
    """The resource's page in the Azure portal. It carries every part of the resource ID (the
    subscription, the group, the server and the database, ...), so masking any drops it."""
    return Link(f"{PORTAL}{rid.value}/{page}", tuple(p for p in rid.value.split("/") if p))


@dataclass
class BlobTarget:
    """Where one container's blobs are: its account, endpoint and what discovery knew."""

    rid: ResourceId  # the storage account
    account: str
    container: str
    endpoint: str  # https://<account>.blob.core.windows.net/
    network_restricted: bool = False
    # Encryption scope name -> the store facts of its key (1.5); "" is the account's own.
    scopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The container's default: its default scope's key, else the account's.
    default: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"BlobTarget({redact_digits(self.account)!r}, {redact_digits(self.container)!r})"


@dataclass
class ShareTarget:
    """One Azure Files share: its account, endpoint and the account's key."""

    rid: ResourceId  # the storage account
    account: str
    share: str
    endpoint: str  # https://<account>.file.core.windows.net/
    facts: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"ShareTarget({redact_digits(self.account)!r}, {redact_digits(self.share)!r})"


def file_resource(t: ShareTarget, path: str, *, column: str | None = None) -> dict[str, Any]:
    """One file of an Azure Files share (and, for a table file, one column of it)."""
    names = {"account": t.account, "share": t.share, "path": path}
    if column is not None:
        names["column"] = column
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {"type": "azure_file", **masked, **azure_fields(t.rid)}
    if masked != names:
        out["keyMasked"] = True
    return out


def blob_resource(
    t: BlobTarget, blob: str, version: str | None, *, column: str | None = None
) -> dict[str, Any]:
    """One blob (and, for a table file, one column of it), masked like an S3 object."""
    names = {"account": t.account, "container": t.container, "blob": blob}
    if column is not None:
        names["column"] = column
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {
        "type": "blob_object",
        "account": masked["account"],
        "container": masked["container"],
        "blob": masked["blob"],
        "versionId": version or "null",
        **azure_fields(t.rid),
    }
    if column is not None:
        out["column"] = masked["column"]
    if masked != names:
        out["keyMasked"] = True
    return out
