"""Key Vault secrets: discovered always, read only when opted in, reported as counts only.

**Discovery** (Resource Graph, Reader) lists every key vault in scope. With
`KEYVAULT_SECRETS_READ` off (the default), each is `read_not_configured`.

**Reading** (`KEYVAULT_SECRETS_READ=on`) needs **Key Vault Secrets User** on
the vaults, which the deployment grants only when that parameter is on. It
lists each vault's secrets (their properties, never a value), then reads the
current version of each enabled secret that is not a certificate's, with its
name as context, as the AWS scanner reads Secrets Manager: a finding says a
secret holds a class of data, with a count, and never the value
(`field: value`, no offsets). A disabled or expired secret, or one a
certificate manages, is counted and not read. A vault that uses access
policies rather than Azure RBAC answers 403 until an access policy is added
for the identity (`access_denied`); one whose firewall keeps the job out is
`network`.

**Encryption (1.5):** Key Vault encrypts secrets with its own keys
(`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.item import scan_item_text

from ..resources import ResourceId, azure_fields, portal_link
from .base import Context, key_facts
from .common import http_gap

KIND = "key_vault"
MAX_SECRETS = 500
MAX_SECRET_CHARS = 64 * 1024

VAULTS = """resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, tags,
    vaultUri = tostring(properties.vaultUri),
    rbac = tobool(properties.enableRbacAuthorization),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    defaultAction = tostring(properties.networkAcls.defaultAction)
| order by id asc"""


@dataclass
class VaultTarget:
    rid: ResourceId
    name: str
    uri: str

    def __repr__(self) -> str:
        return f"VaultTarget({redact_digits(self.name)!r})"


class KeyVaultAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        for row in ctx.graph(VAULTS):
            rid = ResourceId.parse(str(row.get("id") or ""))
            name = str(row.get("name") or rid.name)
            store = Store(
                KIND, name, tags={str(k): str(v) for k, v in (row.get("tags") or {}).items()}
            )
            store.extra.update(azure_fields(rid))
            if (
                str(row.get("publicNetworkAccess") or "").lower() == "disabled"
                or str(row.get("defaultAction") or "").lower() == "deny"
            ):
                store.extra["networkRestricted"] = True
            store.facts = key_facts("Microsoft.Storage")
            store.table = VaultTarget(rid, name, str(row.get("vaultUri") or ""))
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            if not ctx.settings.keyvault_secrets_read:
                store.skip("read_not_configured")

    def source(self, ctx: Context, store: Store) -> KeyVaultSource | None:
        t = store.table
        if not isinstance(t, VaultTarget) or not t.uri:
            return None
        return KeyVaultSource(ctx.clients.client("keyvault", t.uri), t)


class KeyVaultSource:
    """One vault: its secrets' current values, read one by one, reported as counts."""

    kind = KIND

    def __init__(self, client: Any, target: VaultTarget) -> None:
        self.client = client
        self.t = target
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"keyvault:{target.name}"
        self.target = target.name

    def __repr__(self) -> str:
        return f"KeyVaultSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target)
        types: dict[str, int] = {}
        try:
            listed = []
            for p in self.client.list_properties_of_secrets():
                listed.append(p)
                if len(listed) >= MAX_SECRETS:
                    break
        except Exception as err:  # reported by name
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        cov.listed = len(listed)
        link = portal_link(self.t.rid, "secrets")
        seen_at = now.isoformat()
        done = True
        for p in sorted(listed, key=lambda x: str(x.name)):
            name = str(p.name)
            expires = getattr(p, "expires_on", None)
            if getattr(p, "managed", False):
                types["Certificate"] = types.get("Certificate", 0) + 1
                continue
            if not getattr(p, "enabled", True) or (expires is not None and expires <= now):
                types["Disabled"] = types.get("Disabled", 0) + 1
                continue
            types["Secret"] = types.get("Secret", 0) + 1
            cov.eligible += 1
            if not budget.has():
                done = False
                break
            try:
                value = self.client.get_secret(name).value
            except Exception as err:  # one secret must not stop the pass
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
                continue
            text = str(value or "")[:MAX_SECRET_CHARS]
            budget.take(len(text))
            item = scan_item_text(name, text, detector)
            cov.scanned += 1
            cov.bytes_scanned += len(text)
            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            resource = store_field_resource(
                service=KIND, store=self.t.name, table=name, field="value", read_by="get_secret"
            )
            resource.update(azure_fields(self.t.rid))
            store.replace_location(
                f"{self.id}\n{name}",
                class_findings(
                    item.findings, resource, link, item.format, seen_at, facts=self.facts
                ),
            )
        cov.pass_complete, cov.backlog = done, not done
        return SourceRun(cov, {}, extra={"items": len(listed), "itemTypes": types})
