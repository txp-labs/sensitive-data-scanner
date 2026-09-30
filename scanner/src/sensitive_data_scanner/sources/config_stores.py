"""Configuration stores: SSM Parameter Store and Secrets Manager.

Each is one store per account and region, holding many values. The allow and
deny rules apply to each parameter or secret by its name (`ssm:/prod/*`,
`secretsmanager:rds!*`, or by tag), and what they leave out is counted in
the summary (`excluded`). A finding names one parameter or secret
(`store_field`, `field: value`) with counts only: never the value.

**SSM Parameter Store** (`DISCOVER` includes `ssm`): `DescribeParameters`,
then `GetParameters` ten at a time. `SecureString` values are decrypted
through SSM (`SSM_DECRYPT`, on by default; `kms:Decrypt` with
`kms:ViaService` `ssm.<region>`); with it off they are counted, not read.

**Secrets Manager** (`secretsmanager`): `ListSecrets` always, so every secret
is in the summary. Reading is **off by default** (`SECRETS_READ`): a secret
holds credentials, and reading one is an event its owner audits. When on,
`GetSecretValue` for each secret, whose value is read for sensitive data
(a card number or an SSN kept in a secret is a finding) and never reported.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets as _secrets
import urllib.parse
from collections.abc import Sequence
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.item import scan_item_text

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier, weakest
from .exports import drop_other_passes

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("ssm", "secretsmanager")

PARAMETER_STORE = "parameter-store"
# The scanner's own configuration parameters (CONFIG_LOCATION): never read as data.
OWN_PARAMETERS = "/sensitive-data-scanner/"
SECRETS = "secrets-manager"


def _count(d: dict[str, int], key: str) -> None:
    d[key] = d.get(key, 0) + 1


def _members(
    ctx: Context,
    kind: str,
    items: Sequence[tuple[str, dict[str, str] | None, Any]],
    fetch_tags: Any,
) -> tuple[list[str], dict[str, int]]:
    """The names the allow and deny rules let through, and the rest counted by reason."""
    kept: list[str] = []
    excluded: dict[str, int] = {}
    wants_tags = needs_tags(ctx.config, kind)
    for name, tags, ref in items:
        one = Store(kind, name, tags=tags)
        tag_error: str | None = None
        if wants_tags and tags is None:
            try:
                one.tags = fetch_tags(ref)
            except Exception as err:
                tag_error = error_name(err)
        decide(one, ctx.config, tag_error)
        if one.status == "pending":
            kept.append(name)
        else:
            _count(excluded, str(one.reason))
    return sorted(kept), excluded


class SsmAdapter:
    kind = "ssm"

    def discover(self, ctx: Context, out: Discovery) -> None:
        ssm = ctx.clients.client("ssm")
        params: list[dict[str, Any]] = []
        for page in ssm.get_paginator("describe_parameters").paginate():
            params.extend(page.get("Parameters", []))
        store = Store("ssm", PARAMETER_STORE)
        out.stores.append(store)
        types: dict[str, int] = {}
        for p in params:
            _count(types, str(p.get("Type") or "String"))
        store.extra.update(items=len(params), itemTypes=dict(sorted(types.items())))

        def tags(name: str) -> dict[str, str]:
            r = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)
            return {str(t["Key"]): str(t.get("Value", "")) for t in r.get("TagList", [])}

        secure = {str(p["Name"]) for p in params if p.get("Type") == "SecureString"}
        keys = classifier(ctx.clients)
        # A SecureString's KMS key (`alias/aws/ssm` by default). Only a SecureString's value
        # is encrypted with KMS; a String or StringList parameter is `none` (#94).
        item_facts = {
            str(p["Name"]): keys.facts(key=p.get("KeyId") or "alias/aws/ssm")
            if p.get("Type") == "SecureString"
            else keys.facts(encrypted=False)
            for p in params
        }
        own = [str(p["Name"]) for p in params if str(p["Name"]).startswith(OWN_PARAMETERS)]
        params = [p for p in params if not str(p["Name"]).startswith(OWN_PARAMETERS)]
        # The store's own `atRestEncryption` (#94): its weakest parameter's, the scanner's
        # own configuration left out. Every parameter counts, read this run or not.
        store.facts = weakest([item_facts[str(p["Name"])] for p in params])
        kept, excluded = _members(
            ctx, "ssm", [(str(p["Name"]), None, str(p["Name"])) for p in params], tags
        )
        if own:
            excluded["self"] = len(own)
        if not ctx.config.ssm_decrypt:
            n = sum(1 for k in kept if k in secure)
            kept = [k for k in kept if k not in secure]
            if n:
                excluded["secure_string"] = n
        if excluded:
            store.extra["excluded"] = dict(sorted(excluded.items()))
        if not params:
            store.status = "scanned"  # listed: nothing in it
            return
        if not kept:
            store.skip("denied" if excluded.get("denied") else "not_allowed")
            return
        store.extra["names"] = kept
        store.extra["itemFacts"] = {k: item_facts[k] for k in kept if k in item_facts}

    def source(self, ctx: Context, store: Store) -> ParameterSource | None:
        names = store.extra.get("names")
        if not names:
            return None
        src = ParameterSource(
            ctx.clients.client("ssm"),
            names=list(names),
            region=ctx.region,
            decrypt=ctx.config.ssm_decrypt,
        )
        src.item_facts = dict(store.extra.get("itemFacts") or {})
        return src


class SecretsAdapter:
    kind = "secretsmanager"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sm = ctx.clients.client("secretsmanager")
        secrets: list[dict[str, Any]] = []
        for page in sm.get_paginator("list_secrets").paginate():
            secrets.extend(page.get("SecretList", []))
        store = Store("secretsmanager", SECRETS)
        out.stores.append(store)
        managed = sum(1 for s in secrets if s.get("OwningService"))
        store.extra.update(items=len(secrets))
        if managed:
            store.extra["itemTypes"] = {"managed": managed, "own": len(secrets) - managed}
        items = [
            (
                str(s["Name"]),
                {str(t["Key"]): str(t.get("Value", "")) for t in s.get("Tags") or []},
                None,
            )
            for s in secrets
        ]
        kept, excluded = _members(ctx, "secretsmanager", items, None)
        keys = classifier(ctx.clients)
        # Every secret is encrypted: `aws/secretsmanager` unless it names a key of its own.
        item_facts = {
            str(s["Name"]): keys.facts(key=s.get("KmsKeyId"), aws_owned=not s.get("KmsKeyId"))
            for s in secrets
        }
        if excluded:
            store.extra["excluded"] = dict(sorted(excluded.items()))
        if not secrets:
            store.status = "scanned"
            return
        if not ctx.config.secrets_read:
            store.skip("read_not_configured")
            return
        if not kept:
            store.skip("denied" if excluded.get("denied") else "not_allowed")
            return
        store.extra["names"] = kept
        store.extra["itemFacts"] = {k: item_facts[k] for k in kept if k in item_facts}

    def source(self, ctx: Context, store: Store) -> SecretSource | None:
        names = store.extra.get("names")
        if not names:
            return None
        src = SecretSource(
            ctx.clients.client("secretsmanager"), names=list(names), region=ctx.region
        )
        src.item_facts = dict(store.extra.get("itemFacts") or {})
        return src


class _ValueSource:
    """Named values read in order, resumable by name; one finding set per name."""

    kind = ""
    service = ""
    read_by = ""
    batch = 1

    def __init__(self, client: Any, *, names: list[str], region: str) -> None:
        # Each parameter's or secret's own encryption (1.5), by name.
        self.item_facts: dict[str, dict[str, Any]] = {}
        self.client = client
        self.names = sorted(names)
        self.region = region
        self.id = f"{self.service}:{hashlib.sha256(self.service.encode()).hexdigest()[:8]}"
        self.target = PARAMETER_STORE if self.kind == "ssm" else SECRETS

    def link(self, name: str) -> str:
        raise NotImplementedError

    def fetch(self, names: list[str]) -> list[tuple[str, str | None]]:
        raise NotImplementedError

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        pass_id = str(cursor.get("passId") or _secrets.token_hex(8))
        after: str | None = cursor.get("after")
        seen_at = now.isoformat()
        todo = [n for n in self.names if after is None or n > after]
        cov.listed = len(self.names)
        cov.eligible = len(todo)
        done = True
        try:
            for i in range(0, len(todo), self.batch):
                if not budget.has(0):
                    done = False
                    break
                batch = todo[i : i + self.batch]
                for name, value in self.fetch(batch):
                    if value is None:
                        cov.unreadable += 1
                        continue
                    budget.take(len(value))
                    item = scan_item_text(name, value, detector)
                    cov.scanned += 1
                    cov.bytes_scanned += len(value)
                    cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                    cov.test_values += item.test_values
                    cov.suppressed += item.suppressed
                    resource = store_field_resource(
                        service=self.service, store=name, field="value", read_by=self.read_by
                    )
                    found = class_findings(
                        item.findings,
                        resource,
                        self.link(name),
                        item.format,
                        seen_at,
                        facts=self.item_facts.get(name),
                    )
                    for f in found:
                        f["_pass"] = pass_id
                    store.replace_location(f"{self.id}\n{name}", found)
                after = batch[-1]
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            done = False
            log_event("source.failed", source=self.target, error=cov.error)
        if done:
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            return SourceRun(cov, {}, None, {})
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, {})


class ParameterSource(_ValueSource):
    kind = "ssm"
    service = "ssm"
    read_by = "get_parameters"
    batch = 10  # GetParameters takes ten names

    def __init__(self, client: Any, *, names: list[str], region: str, decrypt: bool) -> None:
        super().__init__(client, names=names, region=region)
        self.decrypt = decrypt

    def link(self, name: str) -> str:
        q = urllib.parse.quote(name.lstrip("/"), safe="")
        return console_link(
            self.region, f"systems-manager/parameters/{q}/description?region={self.region}"
        )

    def fetch(self, names: list[str]) -> list[tuple[str, str | None]]:
        r = self.client.get_parameters(Names=names, WithDecryption=self.decrypt)
        got = {str(p["Name"]): str(p.get("Value") or "") for p in r.get("Parameters", [])}
        return [(n, got.get(n)) for n in names]


class SecretSource(_ValueSource):
    kind = "secretsmanager"
    service = "secretsmanager"
    read_by = "get_secret_value"

    def link(self, name: str) -> str:
        q = urllib.parse.quote(name, safe="")
        return console_link(self.region, f"secretsmanager/secret?name={q}&region={self.region}")

    def fetch(self, names: list[str]) -> list[tuple[str, str | None]]:
        out: list[tuple[str, str | None]] = []
        for name in names:
            try:
                r = self.client.get_secret_value(SecretId=name)
            except Exception as err:
                if is_kms_denial(err) or error_name(err) in (
                    "AccessDeniedException",
                    "DecryptionFailure",
                    "ResourceNotFoundException",
                    "InvalidRequestException",
                ):
                    log_event("item.unreadable", source=self.target, error=error_name(err))
                    out.append((name, None))
                    continue
                raise
            if r.get("SecretString") is not None:
                out.append((name, str(r["SecretString"])))
            else:
                raw = bytes(r.get("SecretBinary") or b"")
                try:
                    out.append((name, raw.decode("utf-8")))
                except UnicodeDecodeError:
                    out.append((name, None))
        return out
