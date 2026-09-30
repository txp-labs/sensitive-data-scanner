"""The databases runner's configuration: environment variables and mounted files.

Connection strings are secrets. They come from the customer's secret store as
an environment variable or a mounted file (a Kubernetes or Docker secret, an
ECS or Container Instances secret), are held in `Secret`, whose repr never
shows them, and are never logged, written or sent. A configuration error names
the setting that is wrong by a fixed code, never by its value.

| Setting | What |
|---|---|
| `DATABASE_URL_<NAME>` | A connection string; `<NAME>` names the store in findings |
| `DATABASE_URL_FILE_<NAME>` | A file holding one |
| `DATABASE_URLS_DIR` | A directory of files, one connection string each, named by the store |
| `SCANNER_SITE` | Where this runs (a data center, a cluster): findings name it |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | Rules by store name or engine (`postgresql:hr-*`) |
| `DB_SCHEMAS` | Schemas to read (all but the system's when empty) |
| `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES` | Rows (documents) per table, tables per database |
| `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS` | Timeouts |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | The run's budget |
| `FINDINGS_HTTPS_URL`, `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | Signed HTTPS push |
| `FINDINGS_EVENT_BUS_ARN` | Push to an EventBridge bus (the `aws` extra) |
| `FINDINGS_FILE` | Write the findings document to a file (a mounted volume) |
"""

from __future__ import annotations

import os
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from sensitive_data_core.rules import StoreRule, store_rules
from sensitive_data_core.safety import redact_digits

# URL schemes, by engine (the store kind in findings).
SCHEMES = {
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlserver": "sqlserver",
    "mssql": "sqlserver",
    "oracle": "oracle",
    "mongodb": "mongodb",
    "mongodb+srv": "mongodb",
    "snowflake": "snowflake",
    "databricks": "databricks",
}
ENGINES = tuple(sorted(set(SCHEMES.values())))
# Rule prefixes (`postgresql:hr-*`): each engine, and the schemes' other names.
KIND_ALIASES = {**{e: e for e in ENGINES}, **SCHEMES}

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_SITE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_ARN = re.compile(r"^arn:aws[a-z-]*:events:[a-z0-9-]+:[0-9]{12}:event-bus/[A-Za-z0-9._/-]{1,256}$")
MAX_SECRET_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A setting is wrong. `code` says which, and is safe to log; nothing else is kept."""

    def __init__(self, code: str) -> None:
        self.code = re.sub(r"[^a-z0-9_]", "", code)[:60] or "config"
        super().__init__(f"configuration: {self.code}")

    def __repr__(self) -> str:
        return f"ConfigError({self.code!r})"


class Secret:
    """A connection string or a key: never shown by repr or str."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


@dataclass(frozen=True, repr=False)
class Database:
    """One database to read: the name it has in findings, its engine, its connection string."""

    name: str
    engine: str
    url: Secret = field(repr=False)

    def __repr__(self) -> str:
        # The name is the customer's, and masked like every name the scanner shows.
        return f"Database({redact_digits(self.name)!r}, {self.engine!r})"


@dataclass(frozen=True)
class Settings:
    site: str
    databases: tuple[Database, ...]
    allow: tuple[StoreRule, ...] = ()
    deny: tuple[StoreRule, ...] = ()
    schemas: tuple[str, ...] = ()
    max_rows: int = 1000
    max_tables: int = 500
    statement_seconds: int = 60
    connect_seconds: int = 15
    max_items_per_run: int = 20_000
    max_bytes_per_run: int = 2 * 1024**3
    max_run_seconds: int = 3600
    https_url: Secret | None = field(default=None, repr=False)
    hmac_key: Secret | None = field(default=None, repr=False)
    event_bus_arn: str | None = None
    findings_file: str | None = None


def engine_of(url: str) -> str:
    """The engine a connection string is for, by its scheme."""
    scheme = url.split("://", 1)[0].strip().lower() if "://" in url else ""
    engine = SCHEMES.get(scheme)
    if engine is None:
        raise ConfigError("unknown_scheme")
    return engine


def _int(v: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int(float(v)) if v not in (None, "") else default
    except ValueError:
        raise ConfigError("not_a_number") from None
    return max(lo, min(hi, n))


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


def _database(name: str, url: str) -> Database:
    if not _NAME.match(name):
        raise ConfigError("database_name")
    if not url:
        raise ConfigError("empty_connection_string")
    return Database(name=name, engine=engine_of(url), url=Secret(url))


def databases(env: Mapping[str, str]) -> tuple[Database, ...]:
    """Every database named by `DATABASE_URL_*`, `DATABASE_URL_FILE_*` and `DATABASE_URLS_DIR`."""
    found: dict[str, Database] = {}

    def add(db: Database) -> None:
        if db.name in found:
            raise ConfigError("database_named_twice")
        found[db.name] = db

    for key in sorted(env):
        if key.startswith("DATABASE_URL_FILE_"):
            name = key.removeprefix("DATABASE_URL_FILE_").lower()
            add(_database(name, _read_secret(Path(env[key]))))
        elif key.startswith("DATABASE_URL_"):
            name = key.removeprefix("DATABASE_URL_").lower()
            add(_database(name, env[key].strip()))
    directory = env.get("DATABASE_URLS_DIR", "").strip()
    if directory:
        root = Path(directory)
        if not root.is_dir():
            raise ConfigError("urls_dir_missing")
        # A Kubernetes secret volume also holds `..data` and timestamped links: skip dot files.
        for path in sorted(root.iterdir()):
            if path.name.startswith(".") or not path.is_file():
                continue
            add(_database(path.name, _read_secret(path)))
    return tuple(found.values())


def _https(url: str) -> Secret:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ConfigError("findings_url_not_https")
    return Secret(url)


def read_settings(env: Mapping[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    site = (e.get("SCANNER_SITE") or "").strip().lower()
    if not _SITE.match(site):
        raise ConfigError("scanner_site")
    dbs = databases(e)
    if not dbs:
        raise ConfigError("no_database")
    https_url = _https(e["FINDINGS_HTTPS_URL"].strip()) if e.get("FINDINGS_HTTPS_URL") else None
    key: Secret | None = None
    if e.get("FINDINGS_HMAC_KEY_FILE"):
        key = Secret(_read_secret(Path(e["FINDINGS_HMAC_KEY_FILE"])))
    elif e.get("FINDINGS_HMAC_KEY"):
        key = Secret(e["FINDINGS_HMAC_KEY"].strip())
    if https_url is not None and (key is None or len(key.reveal()) < 32):
        raise ConfigError("findings_hmac_key")
    bus = (e.get("FINDINGS_EVENT_BUS_ARN") or "").strip() or None
    if bus is not None and not _ARN.match(bus):
        raise ConfigError("findings_event_bus_arn")
    findings_file = (e.get("FINDINGS_FILE") or "").strip() or None
    if https_url is None and bus is None and findings_file is None:
        raise ConfigError("no_findings_destination")
    try:
        allow = store_rules(e.get("DISCOVER_ALLOW"), KIND_ALIASES)
        deny = store_rules(e.get("DISCOVER_DENY"), KIND_ALIASES)
    except ValueError:
        raise ConfigError("discover_rule") from None
    return Settings(
        site=site,
        databases=dbs,
        allow=allow,
        deny=deny,
        schemas=_list(e.get("DB_SCHEMAS")),
        max_rows=_int(e.get("DB_MAX_ROWS_PER_TABLE"), 1000, 1, 100_000),
        max_tables=_int(e.get("DB_MAX_TABLES"), 500, 1, 10_000),
        statement_seconds=_int(e.get("DB_STATEMENT_TIMEOUT_SECONDS"), 60, 5, 3600),
        connect_seconds=_int(e.get("DB_CONNECT_TIMEOUT_SECONDS"), 15, 1, 300),
        max_items_per_run=_int(e.get("MAX_ITEMS_PER_RUN"), 20_000, 1, 1_000_000),
        max_bytes_per_run=_int(e.get("MAX_BYTES_PER_RUN"), 2 * 1024**3, 1024, 50 * 1024**3),
        max_run_seconds=_int(e.get("MAX_RUN_SECONDS"), 3600, 60, 24 * 3600),
        https_url=https_url,
        hmac_key=key,
        event_bus_arn=bus,
        findings_file=findings_file,
    )
