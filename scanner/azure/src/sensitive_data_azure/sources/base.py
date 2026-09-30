"""What an Azure adapter is given, and the encryption facts every Azure store shares.

The adapter interface, the budget and the finding store are the core's
(`sensitive_data_core.adapter`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitive_data_core.findings import (
    CUSTOMER_MANAGED_KEY,
    SERVICE_MANAGED,
    UNKNOWN_ENCRYPTION,
    encryption_facts,
)

from ..clients import Clients
from ..config import Settings


@dataclass
class Context:
    """The settings, a client per service, and the scope discovery lists."""

    settings: Settings
    clients: Clients

    def graph(self, query: str) -> list[dict[str, Any]]:
        from ..clients import graph_query  # noqa: PLC0415 - Azure's models only when listing

        return graph_query(
            self.clients,
            query,
            management_group=self.settings.management_group,
            subscriptions=self.settings.subscriptions,
        )


def versionless_key(uri: str | None) -> str | None:
    """A Key Vault (or Managed HSM) key's identifier without its version, lower-case:
    `https://<vault>.vault.azure.net/keys/<name>`. What a customer key's hash is of."""
    if not uri:
        return None
    parts = uri.strip().rstrip("/").lower().split("/")
    if "keys" not in parts:
        return None
    i = parts.index("keys")
    if i + 1 >= len(parts):
        return None
    return "/".join(parts[: i + 2])


def key_facts(key_source: str | None, key_uri: str | None = None) -> dict[str, str]:
    """The store facts (1.5) for an Azure key source: `Microsoft.Storage` (and the other
    services' platform-managed keys) is `service_managed`; `Microsoft.Keyvault` is the
    customer's key in Key Vault or Managed HSM, named only by the hash of its versionless
    identifier. Anything else is `unknown`."""
    source = (key_source or "").strip().lower()
    if source == "microsoft.keyvault":
        return encryption_facts(CUSTOMER_MANAGED_KEY, versionless_key(key_uri))
    if source == "microsoft.storage":
        return encryption_facts(SERVICE_MANAGED)
    return encryption_facts(UNKNOWN_ENCRYPTION, versionless_key(key_uri))
