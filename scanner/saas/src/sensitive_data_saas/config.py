"""The SaaS scanner's settings: environment variables, and files on mounted secret volumes.

A credential is never an environment variable: a client secret, a
certificate's key and the push key are files (or the push key is an env var,
as in the other runners); a workload identity needs no secret at all. Every
secret is held in `Secret`, whose repr never shows it, and never logged. A
wrong setting is reported by a fixed code, never by its value.

**Common**

- `SCANNER_SITE`: a name for this deployment, which findings carry.
- `DISCOVER`: the kinds to read (`m365_mail`, `m365_onedrive`, ...; `all`); by
  default every default kind of each configured vendor (opt-in kinds only when
  named).
- `DISCOVER_ALLOW`, `DISCOVER_DENY`, `DISCOVER_SAMPLING`: the core's rules, by
  kind and store name.
- `SAMPLE_PERCENT`: a stable share of items (by the vendor's item id) to read.
- `MAIL_MAX_MESSAGES_PER_MAILBOX`, `FILES_MAX_PER_DRIVE`,
  `MESSAGES_MAX_PER_CHANNEL`: the most items read per mailbox, drive or
  channel (Teams: per team, and per user's chats) in one run; the rest are
  read by the runs after it.
- `LOOKBACK_DAYS`: how far back the first run reads mail and messages.
- `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES`, `COLUMNAR_MAX_ROWS`: per-file caps
  (attachments and files).
- `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS`: the run's budget.
- `MAX_THROTTLE_WAIT_SECONDS`: the longest a vendor's `Retry-After` is waited
  for; a longer one stops that source until the next run.
- `STATE_LOCATION`: where the cursors (delta links) and the findings carried
  between runs are kept: an absolute path on a mounted volume, `s3://bucket/key`
  (the `aws` extra), or an HTTPS URL (signed with the push key). Without it,
  every run reads from the start.
- `FINDINGS_HTTPS_URL` with `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE`:
  the core's signed HTTPS push (Mermera's collector). `FINDINGS_FILE`: also
  write the document to a file.

**Microsoft 365** (on when `M365_TENANT_ID` is set)

- `M365_TENANT_ID`, `M365_CLIENT_ID`: the tenant and the app registration (GUIDs).
- The credential, exactly one of: `M365_CERTIFICATE_FILE` (a PEM with the key
  and the certificate), `M365_FEDERATED_TOKEN` (`file:<path>`, `aws`, `gcp` or
  `azure`; `M365_FEDERATED_AUDIENCE` defaults to `api://AzureADTokenExchange`,
  `M365_FEDERATED_CLIENT_ID` names a user-assigned managed identity), or
  `M365_CLIENT_SECRET_FILE` (the fallback).
- `M365_USERS` (principal names or object ids) and `M365_GROUPS` (group object
  ids, expanded to their members): whose mailboxes, OneDrives and chats are read.
- `M365_MAIL_SCOPE_CHECK`: a mailbox *outside* the scope the app's mail grant is
  limited to (docs/SAAS.md). Before any mail is read, the scanner checks it is
  refused; without it, mailboxes are `scope_unverified` and not read.
- `M365_SITES`: SharePoint sites (`contoso.sharepoint.com:/sites/finance`, or a
  site id), or `all` (needs `Sites.Read.All`).
- `M365_TEAMS`: team ids whose channels are read (`m365_teams_channel`, opt-in).
- `M365_CUSTOMER_KEY_ID`: the Microsoft Purview Customer Key data encryption
  policy's id, when the tenant uses one: findings then say
  `customer_managed_key`, with its hash; otherwise `service_managed`.
"""

from __future__ import annotations

import os
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from sensitive_data_core.rules import (
    SamplingRule,
    StoreRule,
    sampling_for,
    sampling_rules,
    store_rules,
)
from sensitive_data_core.safety import Secret
from sensitive_data_core.state import valid_location

from .federation import SOURCES

# Every kind, by vendor; the ones read by default; and the ones read only when named.
M365_KINDS: tuple[str, ...] = (
    "m365_mail",
    "m365_onedrive",
    "m365_sharepoint",
    "m365_teams_channel",
    "m365_teams_chat",
)
OPT_IN_KINDS: frozenset[str] = frozenset({"m365_teams_channel", "m365_teams_chat"})
KINDS: tuple[str, ...] = M365_KINDS
KIND_ALIASES = {
    **{k: k for k in KINDS},
    "mail": "m365_mail",
    "exchange": "m365_mail",
    "onedrive": "m365_onedrive",
    "sharepoint": "m365_sharepoint",
    "teams": "m365_teams_channel",
    "channels": "m365_teams_channel",
    "chats": "m365_teams_chat",
}

_SITE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_UPN = re.compile(r"^[^@\s,]{1,113}@[A-Za-z0-9.-]{1,255}$")
_SP_SITE = re.compile(
    r"^[a-z0-9-]+\.sharepoint\.com(?::/[^,\s]{1,400}|,[0-9a-fA-F-]{36},[0-9a-fA-F-]{36})$"
)
_TEAM = _GUID
MAX_SECRET_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A setting is wrong. `code` says which, and is safe to log; nothing else is kept."""

    def __init__(self, code: str) -> None:
        self.code = re.sub(r"[^a-z0-9_]", "", code)[:60] or "config"
        super().__init__(f"configuration: {self.code}")

    def __repr__(self) -> str:
        return f"ConfigError({self.code!r})"


@dataclass(frozen=True)
class M365Settings:
    tenant: str
    client_id: str
    certificate_file: str | None = None
    federated: str | None = None
    federated_audience: str = "api://AzureADTokenExchange"
    federated_client_id: str | None = None
    secret: Secret | None = field(default=None, repr=False)
    users: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    mail_scope_check: str | None = field(default=None, repr=False)
    sites: tuple[str, ...] = ()
    all_sites: bool = False
    teams: tuple[str, ...] = ()
    customer_key_id: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"M365Settings(users={len(self.users)}, groups={len(self.groups)})"


@dataclass(frozen=True)
class Settings:
    site: str
    discover: tuple[str, ...] = ()
    allow: tuple[StoreRule, ...] = ()
    deny: tuple[StoreRule, ...] = ()
    sampling: tuple[SamplingRule, ...] = ()
    sample_percent: int = 100
    mail_max: int = 500
    files_max: int = 200
    messages_max: int = 1000
    lookback_days: int = 90
    max_object_bytes: int = 20 * 1024**2
    max_inflated_bytes: int = 100 * 1024**2
    columnar_max_rows: int = 10_000
    max_items_per_run: int = 20_000
    max_bytes_per_run: int = 2 * 1024**3
    max_run_seconds: int = 3000
    max_throttle_wait: int = 120
    state_location: Secret | None = field(default=None, repr=False)
    https_url: Secret | None = field(default=None, repr=False)
    hmac_key: Secret | None = field(default=None, repr=False)
    findings_file: str | None = None
    m365: M365Settings | None = None

    def sampling_for(
        self, kind: str, name: str, tags: dict[str, str] | None
    ) -> tuple[int | None, int | None]:
        return sampling_for(self.sampling, kind, name, tags)

    def __repr__(self) -> str:
        return f"Settings(site={self.site!r}, discover={self.discover!r})"


def _int(v: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int(float(v)) if v not in (None, "") else default
    except ValueError:
        raise ConfigError("not_a_number") from None
    return max(lo, min(hi, n))


def _list(v: str | None) -> tuple[str, ...]:
    return tuple(s.strip() for s in (v or "").split(",") if s.strip())


def read_secret(path: Path) -> str:
    try:
        data = path.read_bytes()[: MAX_SECRET_BYTES + 1]
    except OSError:
        raise ConfigError("secret_file_unreadable") from None
    if len(data) > MAX_SECRET_BYTES:
        raise ConfigError("secret_file_too_large")
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ConfigError("secret_file_not_text") from None
    if not text:
        raise ConfigError("secret_file_empty")
    return text


def _file(raw: str | None, name: str) -> str | None:
    """An absolute path, or None; `name` is the setting's code."""
    t = (raw or "").strip()
    if not t:
        return None
    if not t.startswith("/"):
        raise ConfigError(name)
    return t


def _federated(raw: str | None) -> str | None:
    t = (raw or "").strip()
    if not t:
        return None
    if t.startswith("file:"):
        path = urllib.parse.unquote(t.removeprefix("file:").removeprefix("//"))
        if not path.startswith("/"):
            raise ConfigError("federated_token")
        return t
    if t not in SOURCES or t == "file":
        raise ConfigError("federated_token")
    return t


def _principals(raw: str | None, name: str) -> tuple[str, ...]:
    out: list[str] = []
    for p in _list(raw):
        if not (_GUID.match(p) or _UPN.match(p)):
            raise ConfigError(name)
        if p.lower() not in (o.lower() for o in out):
            out.append(p)
    return tuple(out)


def _m365(e: Mapping[str, str]) -> M365Settings | None:
    tenant = (e.get("M365_TENANT_ID") or "").strip().lower()
    if not tenant:
        return None
    if not _GUID.match(tenant):
        raise ConfigError("m365_tenant_id")
    client = (e.get("M365_CLIENT_ID") or "").strip().lower()
    if not _GUID.match(client):
        raise ConfigError("m365_client_id")
    cert = _file(e.get("M365_CERTIFICATE_FILE"), "m365_certificate_file")
    federated = _federated(e.get("M365_FEDERATED_TOKEN"))
    secret_file = _file(e.get("M365_CLIENT_SECRET_FILE"), "m365_client_secret_file")
    if sum(x is not None for x in (cert, federated, secret_file)) != 1:
        raise ConfigError("m365_credential")
    if e.get("M365_CLIENT_SECRET"):
        # A secret in the environment shows in the task definition and the process table.
        raise ConfigError("m365_client_secret_in_env")
    secret = Secret(read_secret(Path(secret_file))) if secret_file else None
    audience = (e.get("M365_FEDERATED_AUDIENCE") or "api://AzureADTokenExchange").strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,200}$", audience):
        raise ConfigError("m365_federated_audience")
    mi = (e.get("M365_FEDERATED_CLIENT_ID") or "").strip().lower() or None
    if mi is not None and not _GUID.match(mi):
        raise ConfigError("m365_federated_client_id")
    groups = _list(e.get("M365_GROUPS"))
    if any(not _GUID.match(g) for g in groups):
        raise ConfigError("m365_groups")
    check = (e.get("M365_MAIL_SCOPE_CHECK") or "").strip() or None
    if check is not None and not (_GUID.match(check) or _UPN.match(check)):
        raise ConfigError("m365_mail_scope_check")
    sites_raw = _list(e.get("M365_SITES"))
    all_sites = sites_raw == ("all",)
    sites = () if all_sites else sites_raw
    if any(not _SP_SITE.match(s) for s in sites):
        raise ConfigError("m365_sites")
    teams = _list(e.get("M365_TEAMS"))
    if any(not _TEAM.match(t) for t in teams):
        raise ConfigError("m365_teams")
    key_id = (e.get("M365_CUSTOMER_KEY_ID") or "").strip() or None
    if key_id is not None and not re.match(r"^[A-Za-z0-9._:/-]{1,200}$", key_id):
        raise ConfigError("m365_customer_key_id")
    return M365Settings(
        tenant=tenant,
        client_id=client,
        certificate_file=cert,
        federated=federated,
        federated_audience=audience,
        federated_client_id=mi,
        secret=secret,
        users=_principals(e.get("M365_USERS"), "m365_users"),
        groups=tuple(g.lower() for g in groups),
        mail_scope_check=check,
        sites=sites,
        all_sites=all_sites,
        teams=tuple(t.lower() for t in teams),
        customer_key_id=key_id,
    )


def default_kinds(configured: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(k for k in configured if k not in OPT_IN_KINDS)


def _kinds(raw: str | None, configured: tuple[str, ...]) -> tuple[str, ...]:
    names = _list(raw)
    if not names:
        return default_kinds(configured)
    if names == ("all",):
        return configured
    if names == ("off",):
        return ()
    out: list[str] = []
    for n in names:
        kind = KIND_ALIASES.get(n.lower())
        if kind is None:
            raise ConfigError("discover_kind")
        if kind not in configured:
            raise ConfigError("discover_vendor_not_configured")
        if kind not in out:
            out.append(kind)
    return tuple(out)


def read_settings(env: Mapping[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    site = (e.get("SCANNER_SITE") or "").strip().lower()
    if not _SITE.match(site):
        raise ConfigError("scanner_site")
    m365 = _m365(e)
    configured: tuple[str, ...] = M365_KINDS if m365 is not None else ()
    if not configured:
        raise ConfigError("no_vendor")
    https_url: Secret | None = None
    if e.get("FINDINGS_HTTPS_URL"):
        parts = urllib.parse.urlsplit(e["FINDINGS_HTTPS_URL"].strip())
        if parts.scheme != "https" or not parts.hostname:
            raise ConfigError("findings_url_not_https")
        https_url = Secret(e["FINDINGS_HTTPS_URL"].strip())
    key: Secret | None = None
    if e.get("FINDINGS_HMAC_KEY_FILE"):
        key = Secret(read_secret(Path(e["FINDINGS_HMAC_KEY_FILE"])))
    elif e.get("FINDINGS_HMAC_KEY"):
        key = Secret(e["FINDINGS_HMAC_KEY"].strip())
    if https_url is not None and (key is None or len(key.reveal()) < 32):
        raise ConfigError("findings_hmac_key")
    findings_file = (e.get("FINDINGS_FILE") or "").strip() or None
    if https_url is None and findings_file is None:
        raise ConfigError("no_findings_destination")
    state: Secret | None = None
    raw_state = (e.get("STATE_LOCATION") or "").strip()
    if raw_state:
        name = valid_location(raw_state)
        if name is not None:
            raise ConfigError(name)
        if raw_state.startswith("https://") and key is None:
            raise ConfigError("state_hmac_key")
        state = Secret(raw_state)
    try:
        allow = store_rules(e.get("DISCOVER_ALLOW"), KIND_ALIASES)
        deny = store_rules(e.get("DISCOVER_DENY"), KIND_ALIASES)
        sampling = sampling_rules(e.get("DISCOVER_SAMPLING"), KIND_ALIASES)
    except ValueError:
        raise ConfigError("discover_rule") from None
    return Settings(
        site=site,
        discover=_kinds(e.get("DISCOVER"), configured),
        allow=allow,
        deny=deny,
        sampling=sampling,
        sample_percent=_int(e.get("SAMPLE_PERCENT"), 100, 1, 100),
        mail_max=_int(e.get("MAIL_MAX_MESSAGES_PER_MAILBOX"), 500, 1, 100_000),
        files_max=_int(e.get("FILES_MAX_PER_DRIVE"), 200, 1, 100_000),
        messages_max=_int(e.get("MESSAGES_MAX_PER_CHANNEL"), 1000, 1, 100_000),
        lookback_days=_int(e.get("LOOKBACK_DAYS"), 90, 1, 3650),
        max_object_bytes=_int(e.get("MAX_OBJECT_BYTES"), 20 * 1024**2, 1024, 1024**3),
        max_inflated_bytes=_int(e.get("MAX_INFLATED_BYTES"), 100 * 1024**2, 1024, 4 * 1024**3),
        columnar_max_rows=_int(e.get("COLUMNAR_MAX_ROWS"), 10_000, 1, 1_000_000),
        max_items_per_run=_int(e.get("MAX_ITEMS_PER_RUN"), 20_000, 1, 1_000_000),
        max_bytes_per_run=_int(e.get("MAX_BYTES_PER_RUN"), 2 * 1024**3, 1024, 50 * 1024**3),
        max_run_seconds=_int(e.get("MAX_RUN_SECONDS"), 3000, 60, 24 * 3600),
        max_throttle_wait=_int(e.get("MAX_THROTTLE_WAIT_SECONDS"), 120, 1, 3600),
        state_location=state,
        https_url=https_url,
        hmac_key=key,
        findings_file=findings_file,
        m365=m365,
    )
