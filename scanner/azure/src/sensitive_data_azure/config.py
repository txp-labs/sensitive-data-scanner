"""The Azure scanner's settings: environment variables, as the Container Apps job sets them.

No secret is configured: the job's managed identity signs every request
(`DefaultAzureCredential`). The only secrets a customer may add are the HMAC
key of the HTTPS push and its URL (which may carry a token); both are held in
`Secret`, whose repr never shows them, and never logged. A wrong setting is
reported by a fixed code, never by its value.

- `SCANNER_SITE`: a name for this deployment, which findings carry (the
  management group, say).
- `AZURE_MANAGEMENT_GROUP`: discover every subscription under this management
  group; or `AZURE_SUBSCRIPTIONS`: these subscriptions (comma-separated ids).
- `DISCOVER`: the kinds to discover (`azure_blob`, `azure_sql`, ...; `all`);
  by default, every kind.
- `AZURE_DB_READ`: the database kinds that are read (`azure_sql`,
  `azure_sql_mi`, `azure_postgresql`, `azure_mysql`, `synapse_sql`,
  `cosmosdb_mongo`, or `all`); off by default, since each database needs a user
  for the identity.
- `TABLE_MAX_ENTITIES`, `COSMOS_MAX_ITEMS`: entities sampled per table, items per
  Cosmos DB container.
- `LOGS_LOOKBACK_DAYS`, `LOGS_MAX_ROWS_PER_TABLE`: Log Analytics' window and the
  rows sampled per table.
- `KEYVAULT_SECRETS_READ`: `on` reads Key Vault secrets' values (counts only);
  off by default.
- `AZURE_DB_PRINCIPAL`: the identity's name as a PostgreSQL or MySQL user.
- `DB_SCHEMAS`, `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES`,
  `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS`: as the databases
  runner's.
- `DISCOVER_ALLOW`, `DISCOVER_DENY`, `DISCOVER_SAMPLING`: the core's rules, by
  kind and name (`azure_blob:prodlake/*`, `tag:scan=false`).
- `SAMPLE_PERCENT`, `BLOB_MAX_OBJECTS_PER_PREFIX`: blob sampling, a stable share
  of blobs and at most n per directory.
- `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES`, `COLUMNAR_MAX_ROWS`: per-blob caps.
- `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS`,
  `MAX_OBJECTS_PER_RUN`: the run's budget.
- `STATE_CONTAINER_URL`: the job's own container
  (`https://<account>.blob.core.windows.net/<container>`), for the findings,
  the cursors and the lock.
- `FINDINGS_HTTPS_URL` with `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE`:
  the core's signed HTTPS push.
- `FINDINGS_EVENT_GRID_ENDPOINT`: push to an Event Grid topic as the managed
  identity (`EventGrid Data Sender` on that topic, granted by its owner).
- `FINDINGS_FILE`: write the findings document to a file (a mounted volume).
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

# Azure's databases: discovered by default, read only when named in AZURE_DB_READ.
DATABASE_KINDS: tuple[str, ...] = (
    "azure_sql",
    "azure_sql_mi",
    "azure_postgresql",
    "azure_mysql",
    "synapse_sql",
    "cosmosdb_mongo",
)
# Every kind this package discovers, and the ones discovered by default.
KINDS: tuple[str, ...] = (
    "azure_blob",
    "azure_table",
    "azure_queue",
    "cosmosdb",
    "log_analytics",
    "azure_disk_snapshot",
    "key_vault",
    *DATABASE_KINDS,
)
DEFAULT_KINDS: tuple[str, ...] = KINDS
# Rule and DISCOVER prefixes: each kind, and shorter names for it.
KIND_ALIASES = {
    **{k: k for k in KINDS},
    "blob": "azure_blob",
    "adls": "azure_blob",
    "sql": "azure_sql",
    "sqlmi": "azure_sql_mi",
    "postgresql": "azure_postgresql",
    "postgres": "azure_postgresql",
    "mysql": "azure_mysql",
    "synapse": "synapse_sql",
    "table": "azure_table",
    "queue": "azure_queue",
    "cosmos": "cosmosdb",
    "mongo": "cosmosdb_mongo",
    "logs": "log_analytics",
    "monitor": "log_analytics",
    "snapshot": "azure_disk_snapshot",
    "snapshots": "azure_disk_snapshot",
    "keyvault": "key_vault",
    "kv": "key_vault",
}

_SITE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_MANAGEMENT_GROUP = re.compile(r"^[A-Za-z0-9._()-]{1,90}$")
_STORAGE_HOST = re.compile(r"^[a-z0-9]{3,24}\.blob\.[a-z0-9.-]+$")
_CONTAINER = re.compile(r"^(?:\$root|[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62})$")
# The managed identity's name as a database user (PostgreSQL and MySQL name it).
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
MAX_SECRET_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A setting is wrong. `code` says which, and is safe to log; nothing else is kept."""

    def __init__(self, code: str) -> None:
        self.code = re.sub(r"[^a-z0-9_]", "", code)[:60] or "config"
        super().__init__(f"configuration: {self.code}")

    def __repr__(self) -> str:
        return f"ConfigError({self.code!r})"


@dataclass(frozen=True)
class StateContainer:
    """The job's own blob container: its account's endpoint and the container's name."""

    endpoint: str  # https://<account>.blob.core.windows.net/
    account: str
    container: str


@dataclass(frozen=True)
class Settings:
    site: str
    management_group: str | None = None
    subscriptions: tuple[str, ...] = ()
    discover: tuple[str, ...] = DEFAULT_KINDS
    allow: tuple[StoreRule, ...] = ()
    deny: tuple[StoreRule, ...] = ()
    sampling: tuple[SamplingRule, ...] = ()
    sample_percent: int = 100
    blob_max_objects_per_prefix: int = 0
    max_object_bytes: int = 20 * 1024**2
    max_inflated_bytes: int = 100 * 1024**2
    columnar_max_rows: int = 10_000
    skew_seconds: int = 300
    max_items_per_run: int = 20_000
    max_bytes_per_run: int = 2 * 1024**3
    max_run_seconds: int = 3000
    max_objects_per_run: int = 0
    state: StateContainer | None = None
    https_url: Secret | None = field(default=None, repr=False)
    hmac_key: Secret | None = field(default=None, repr=False)
    event_grid_endpoint: str | None = None
    findings_file: str | None = None
    # Azure's databases (opt-in): which kinds are read, as whom, and how much.
    db_read: tuple[str, ...] = ()
    db_principal: str | None = None
    db_schemas: tuple[str, ...] = ()
    db_max_rows: int = 1000
    db_max_tables: int = 500
    db_statement_seconds: int = 60
    db_connect_seconds: int = 15
    # Table Storage and Cosmos DB for NoSQL: entities or items sampled per table or container.
    table_max_entities: int = 1000
    cosmos_max_items: int = 1000
    # Log Analytics: how far back a table's rows are sampled, and how many.
    logs_lookback_days: int = 1
    logs_max_rows: int = 500
    # Key Vault secrets' values: off by default, counts only when on.
    keyvault_secrets_read: bool = False

    def sampling_for(
        self, kind: str, name: str, tags: dict[str, str] | None
    ) -> tuple[int | None, int | None]:
        return sampling_for(self.sampling, kind, name, tags)

    def needs_tags(self, kind: str) -> bool:
        rules = [*self.allow, *self.deny, *(r.match for r in self.sampling)]
        return any(r.needs_tags and r.kind in (None, kind) for r in rules)


def _int(v: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int(float(v)) if v not in (None, "") else default
    except ValueError:
        raise ConfigError("not_a_number") from None
    return max(lo, min(hi, n))


def _on(v: str | None) -> bool | None:
    """True for on, False for off, None for anything else."""
    t = (v or "off").strip().lower()
    if t in ("on", "true", "1", "yes"):
        return True
    if t in ("off", "false", "0", "no", ""):
        return False
    return None


def _list(v: str | None) -> tuple[str, ...]:
    return tuple(s.strip() for s in (v or "").split(",") if s.strip())


def _read_secret(path: Path) -> str:
    try:
        data = path.read_bytes()[: MAX_SECRET_BYTES + 1]
    except OSError:
        raise ConfigError("secret_file_unreadable") from None
    if len(data) > MAX_SECRET_BYTES:
        raise ConfigError("secret_file_too_large")
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ConfigError("secret_file_not_text") from None


def _https(url: str) -> urllib.parse.SplitResult | None:
    parts = urllib.parse.urlsplit(url)
    return parts if parts.scheme == "https" and parts.hostname else None


def _state(raw: str | None) -> StateContainer | None:
    t = (raw or "").strip().rstrip("/")
    if not t:
        return None
    parts = _https(t)
    if parts is None:
        raise ConfigError("state_container_url")
    host = (parts.hostname or "").lower()
    container = parts.path.strip("/")
    if not _STORAGE_HOST.match(host) or not _CONTAINER.match(container) or parts.query:
        raise ConfigError("state_container_url")
    return StateContainer(f"https://{host}/", host.split(".", 1)[0], container)


def _kinds(
    raw: str | None, default: tuple[str, ...] = DEFAULT_KINDS, every: tuple[str, ...] = KINDS
) -> tuple[str, ...]:
    names = _list(raw)
    if not names:
        return default
    if names == ("all",):
        return every
    if names == ("off",):
        return ()
    out: list[str] = []
    for n in names:
        kind = KIND_ALIASES.get(n.lower())
        if kind is None or kind not in every:
            raise ConfigError("discover_kind")
        if kind not in out:
            out.append(kind)
    return tuple(out)


def read_settings(env: Mapping[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    site = (e.get("SCANNER_SITE") or "").strip().lower()
    if not _SITE.match(site):
        raise ConfigError("scanner_site")
    group = (e.get("AZURE_MANAGEMENT_GROUP") or "").strip() or None
    if group is not None and not _MANAGEMENT_GROUP.match(group):
        raise ConfigError("azure_management_group")
    subscriptions = _list(e.get("AZURE_SUBSCRIPTIONS"))
    if any(not _GUID.match(s) for s in subscriptions):
        raise ConfigError("azure_subscriptions")
    if group is None and not subscriptions:
        raise ConfigError("no_scope")
    if group is not None and subscriptions:
        raise ConfigError("scope_twice")
    https_url: Secret | None = None
    if e.get("FINDINGS_HTTPS_URL"):
        if _https(e["FINDINGS_HTTPS_URL"].strip()) is None:
            raise ConfigError("findings_url_not_https")
        https_url = Secret(e["FINDINGS_HTTPS_URL"].strip())
    key: Secret | None = None
    if e.get("FINDINGS_HMAC_KEY_FILE"):
        key = Secret(_read_secret(Path(e["FINDINGS_HMAC_KEY_FILE"])))
    elif e.get("FINDINGS_HMAC_KEY"):
        key = Secret(e["FINDINGS_HMAC_KEY"].strip())
    if https_url is not None and (key is None or len(key.reveal()) < 32):
        raise ConfigError("findings_hmac_key")
    grid = (e.get("FINDINGS_EVENT_GRID_ENDPOINT") or "").strip() or None
    if grid is not None and _https(grid) is None:
        raise ConfigError("findings_event_grid_endpoint")
    findings_file = (e.get("FINDINGS_FILE") or "").strip() or None
    state = _state(e.get("STATE_CONTAINER_URL"))
    if state is None and https_url is None and grid is None and findings_file is None:
        raise ConfigError("no_findings_destination")
    keyvault = _on(e.get("KEYVAULT_SECRETS_READ"))
    if keyvault is None:
        raise ConfigError("keyvault_secrets_read")
    try:
        db_read = _kinds(e.get("AZURE_DB_READ"), (), DATABASE_KINDS)
    except ConfigError:
        raise ConfigError("azure_db_read") from None
    principal = (e.get("AZURE_DB_PRINCIPAL") or "").strip() or None
    if principal is not None and not _PRINCIPAL.match(principal):
        raise ConfigError("azure_db_principal")
    if principal is None and {"azure_postgresql", "azure_mysql"} & set(db_read):
        raise ConfigError("azure_db_principal")
    try:
        allow = store_rules(e.get("DISCOVER_ALLOW"), KIND_ALIASES)
        deny = store_rules(e.get("DISCOVER_DENY"), KIND_ALIASES)
        sampling = sampling_rules(e.get("DISCOVER_SAMPLING"), KIND_ALIASES)
    except ValueError:
        raise ConfigError("discover_rule") from None
    return Settings(
        site=site,
        management_group=group,
        subscriptions=subscriptions,
        discover=_kinds(e.get("DISCOVER")),
        allow=allow,
        deny=deny,
        sampling=sampling,
        sample_percent=_int(e.get("SAMPLE_PERCENT"), 100, 1, 100),
        blob_max_objects_per_prefix=_int(e.get("BLOB_MAX_OBJECTS_PER_PREFIX"), 0, 0, 1_000_000),
        max_object_bytes=_int(e.get("MAX_OBJECT_BYTES"), 20 * 1024**2, 1024, 1024**3),
        max_inflated_bytes=_int(e.get("MAX_INFLATED_BYTES"), 100 * 1024**2, 1024, 4 * 1024**3),
        columnar_max_rows=_int(e.get("COLUMNAR_MAX_ROWS"), 10_000, 1, 1_000_000),
        max_items_per_run=_int(e.get("MAX_ITEMS_PER_RUN"), 20_000, 1, 1_000_000),
        max_bytes_per_run=_int(e.get("MAX_BYTES_PER_RUN"), 2 * 1024**3, 1024, 50 * 1024**3),
        max_run_seconds=_int(e.get("MAX_RUN_SECONDS"), 3000, 60, 24 * 3600),
        max_objects_per_run=_int(e.get("MAX_OBJECTS_PER_RUN"), 0, 0, 10_000_000),
        state=state,
        https_url=https_url,
        hmac_key=key,
        event_grid_endpoint=grid,
        findings_file=findings_file,
        db_read=db_read,
        db_principal=principal,
        db_schemas=_list(e.get("DB_SCHEMAS")),
        db_max_rows=_int(e.get("DB_MAX_ROWS_PER_TABLE"), 1000, 1, 100_000),
        db_max_tables=_int(e.get("DB_MAX_TABLES"), 500, 1, 10_000),
        db_statement_seconds=_int(e.get("DB_STATEMENT_TIMEOUT_SECONDS"), 60, 5, 3600),
        db_connect_seconds=_int(e.get("DB_CONNECT_TIMEOUT_SECONDS"), 15, 1, 300),
        table_max_entities=_int(e.get("TABLE_MAX_ENTITIES"), 1000, 1, 100_000),
        cosmos_max_items=_int(e.get("COSMOS_MAX_ITEMS"), 1000, 1, 100_000),
        logs_lookback_days=_int(e.get("LOGS_LOOKBACK_DAYS"), 1, 1, 730),
        logs_max_rows=_int(e.get("LOGS_MAX_ROWS_PER_TABLE"), 500, 1, 30_000),
        keyvault_secrets_read=keyvault,
    )
