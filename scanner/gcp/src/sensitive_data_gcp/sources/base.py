"""What a Google Cloud adapter is given, and the encryption facts every store shares.

The adapter interface, the budget and the finding store are the core's
(`sensitive_data_core.adapter`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.findings import CUSTOMER_MANAGED_KEY, SERVICE_MANAGED, encryption_facts
from sensitive_data_core.safety import error_name, log_event

from ..clients import Clients, Rest, search_resources
from ..config import Settings

PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Project"
_PROJECT_IN_NAME = re.compile(r"/projects/([^/]+)/")
_VERSION = re.compile(r"/cryptoKeyVersions/[^/]+$")


@dataclass
class Context:
    """The settings, the REST client, and the scope discovery lists."""

    settings: Settings
    clients: Clients
    # Cloud Asset Inventory's results, once per run per asset type.
    _found: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _projects: dict[str, str] | None = None
    # What adapters share within one run (the Cloud SQL instances three engines' adapters list).
    memo: dict[str, Any] = field(default_factory=dict)

    @property
    def rest(self) -> Rest:
        return self.clients.rest

    def search(self, asset_type: str) -> list[dict[str, Any]]:
        """Every resource of one type in every scope (organization, folders or projects)."""
        if asset_type not in self._found:
            rows: list[dict[str, Any]] = []
            for scope in self.settings.scopes:
                rows.extend(search_resources(self.rest, scope, asset_type))
            rows.sort(key=lambda r: str(r.get("name") or ""))
            self._found[asset_type] = rows
        return self._found[asset_type]

    def projects(self) -> dict[str, str]:
        """Project number -> project id, for every project in scope."""
        if self._projects is None:
            out: dict[str, str] = {}
            try:
                for r in self.search(PROJECT_TYPE):
                    number = str(r.get("project") or r.get("name") or "").rsplit("/", 1)[-1]
                    pid = str((r.get("additionalAttributes") or {}).get("projectId") or "")
                    if number and pid:
                        out[number] = pid
            except Exception as err:  # the ids stay numbers; every store is still listed
                log_event("discovery.failed", kind="project", error=error_name(err))
            self._projects = out
        return self._projects

    def project_of(self, row: dict[str, Any]) -> str:
        """A search result's project id: from its own name, its parent's, or its number."""
        for name in (str(row.get("name") or ""), str(row.get("parentFullResourceName") or "")):
            m = _PROJECT_IN_NAME.search(name + "/")
            if m and not m[1].isdigit():
                return m[1]
        number = str(row.get("project") or "").rsplit("/", 1)[-1]
        return self.projects().get(number, number)


def versionless_kms_key(name: str | None) -> str | None:
    """A Cloud KMS key's resource name without its version:
    `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`. What a key's hash is of."""
    if not name:
        return None
    text = name.strip().removeprefix("//cloudkms.googleapis.com/")
    return _VERSION.sub("", text) or None


def kms_facts(key_name: str | None) -> dict[str, str]:
    """The store facts (1.5) for a store or an object: a Cloud KMS key (CMEK) is
    `customer_managed_key`, named only by the hash of its versionless resource name;
    without one, Google's own keys encrypt it (`service_managed`). Google Cloud encrypts
    everything at rest, so never `none`."""
    key = versionless_kms_key(key_name)
    if key:
        return encryption_facts(CUSTOMER_MANAGED_KEY, key)
    return encryption_facts(SERVICE_MANAGED)


def labels(row: dict[str, Any]) -> dict[str, str]:
    raw = row.get("labels")
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
