"""Secret Manager: discovered always, read only when opted in, reported as counts only.

**Discovery** (`DISCOVER` includes `secret_manager`): Cloud Asset Inventory lists
every secret in scope; a store is one project's secrets (`secret_manager`,
named by the project id), with `items`, the secrets listed. With
`SECRET_MANAGER_READ` off (the default) it is `read_not_configured`, and the
deployment grants no accessor role.

**Reading** (`SECRET_MANAGER_READ=on`) needs Secret Manager Secret Accessor
(`secretmanager.versions.access`), which the deployment grants only then, and
Secret Manager Viewer (`secretmanager.secrets.get`) for each secret's key.
The latest version of each secret is read (`versions/latest:access`) and
reported as the AWS scanner reports Secrets Manager: **counts only**, `field:
value`, no offsets, and never the value. A secret whose latest version is
disabled or destroyed is counted (`itemTypes: Disabled`), not read.

**Encryption (1.5):** a secret replicated under Cloud KMS keys
(`customerManagedEncryption`) is `customer_managed_key`, hashed from its first
key; otherwise Google's own keys (`service_managed`).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.item import looks_binary, scan_item_text

from ..clients import Rest
from ..resources import Located, console_link
from .base import Context, kms_facts
from .common import call_gap

KIND = "secret_manager"
API = "https://secretmanager.googleapis.com/v1"
ASSET_TYPE = "secretmanager.googleapis.com/Secret"
MAX_SECRETS = 500
MAX_SECRET_BYTES = 64 * 1024
DISABLED = frozenset({"FAILED_PRECONDITION", "NOT_FOUND"})


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def secret_key(meta: dict[str, Any]) -> str | None:
    """The first Cloud KMS key a secret's replication names, if any."""
    rep = meta.get("replication") or {}
    auto = (rep.get("automatic") or {}).get("customerManagedEncryption") or {}
    if auto.get("kmsKeyName"):
        return str(auto["kmsKeyName"])
    for r in (rep.get("userManaged") or {}).get("replicas") or []:
        key = ((r or {}).get("customerManagedEncryption") or {}).get("kmsKeyName")
        if key:
            return str(key)
    return None


@dataclass
class SecretsTarget:
    where: Located
    secrets: list[str] = field(default_factory=list)

    @property
    def project(self) -> str:
        return self.where.project

    def __repr__(self) -> str:
        return f"SecretsTarget({redact_digits(self.project)!r}, {len(self.secrets)})"


class SecretManagerAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        by_project: dict[str, list[str]] = {}
        numbers = {v: k for k, v in ctx.projects().items()}
        for row in ctx.search(ASSET_TYPE):
            parts = str(row.get("name") or "").split("/")
            try:
                project = parts[parts.index("projects") + 1]
                secret = parts[parts.index("secrets") + 1]
            except (ValueError, IndexError):
                continue
            project = ctx.projects().get(project, project)  # a number, as its id
            by_project.setdefault(project, []).append(secret)
        for project, secrets in sorted(by_project.items()):
            number = numbers.get(project, project)
            where = Located(project, f"//cloudresourcemanager.googleapis.com/projects/{number}")
            store = Store(KIND, project)
            store.extra.update(where.fields())
            store.extra["items"] = len(secrets)
            store.facts = kms_facts(None)
            store.table = SecretsTarget(where, sorted(secrets)[:MAX_SECRETS])
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            if not ctx.settings.secret_manager_read:
                store.skip("read_not_configured")

    def source(self, ctx: Context, store: Store) -> SecretsSource | None:
        t = store.table
        if not isinstance(t, SecretsTarget):
            return None
        return SecretsSource(ctx.rest, t)


class SecretsSource:
    """One project's secrets: each one's latest version, read, reported as counts."""

    kind = KIND

    def __init__(self, rest: Rest, target: SecretsTarget) -> None:
        self.rest = rest
        self.t = target
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"secrets:{target.project}"
        self.target = target.project

    def __repr__(self) -> str:
        return f"SecretsSource({self.t!r})"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target, listed=len(self.t.secrets))
        types: dict[str, int] = {}
        t = self.t
        link = console_link("security/secret-manager", {"project": t.project})
        seen_at = now.isoformat()
        done = True
        denied: str | None = None
        for name in t.secrets:
            if not budget.has():
                done = False
                break
            base = f"{API}/projects/{_q(t.project)}/secrets/{_q(name)}"
            try:
                got = self.rest.get(f"{base}/versions/latest:access")
            except Exception as err:
                e = error_name(err)
                if e in DISABLED:
                    types["Disabled"] = types.get("Disabled", 0) + 1
                    continue
                if call_gap(err) in ("network", "access_denied"):
                    denied = denied or e
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=e)
                continue
            types["Secret"] = types.get("Secret", 0) + 1
            cov.eligible += 1
            try:
                raw = base64.b64decode(str((got.get("payload") or {}).get("data") or ""))
            except (binascii.Error, ValueError):
                raw = b""
            raw = raw[:MAX_SECRET_BYTES]
            budget.take(len(raw))
            if not raw or looks_binary(raw):
                cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                continue
            text = raw.decode("utf-8", errors="replace")
            item = scan_item_text(name, text, detector)
            cov.scanned += 1
            cov.bytes_scanned += len(raw)
            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            facts = self.facts
            try:
                key = secret_key(self.rest.get(base))
                facts = kms_facts(key) if key else facts
            except Exception as err:  # the key stays the project's default
                log_event("item.unreadable", source=self.target, error=error_name(err))
            resource = store_field_resource(
                service=KIND, store=t.project, table=name, field="value", read_by="access"
            )
            resource.update(t.where.fields())
            store.replace_location(
                f"{self.id}\n{name}",
                class_findings(item.findings, resource, link, item.format, seen_at, facts=facts),
            )
        cov.pass_complete, cov.backlog = done, not done
        if cov.scanned == 0 and cov.unreadable and denied is not None:
            cov.error = denied  # every secret refused: the store's error
        return SourceRun(cov, {}, extra={"items": len(t.secrets), "itemTypes": types})
