"""The Google Cloud scanner's settings: environment variables, as the Cloud Run job sets them.

No key is configured: the job's service account signs every request through
Application Default Credentials (the metadata server on Cloud Run). The only
secrets a customer may add are the HMAC key of the HTTPS push and its URL
(which may carry a token); both are held in `Secret`, whose repr never shows
them, and never logged. A wrong setting is reported by a fixed code, never by
its value.

- `SCANNER_SITE`: a name for this deployment, which findings carry (the
  organization or folder, say).
- The scope, exactly one of: `GCP_ORGANIZATION` (an organization's number),
  `GCP_FOLDERS` (folder numbers, comma-separated) or `GCP_PROJECTS` (project
  ids, comma-separated). Cloud Asset Inventory lists every store under it.
- `DISCOVER`: the kinds to discover (`gcs`, `bigquery`, ...; `all`); by default,
  every kind.
- `BIGQUERY_MAX_ROWS`: rows read per BigQuery table (`tabledata.list`).
- `DOCUMENTS_MAX_PER_COLLECTION`, `DOCUMENTS_MAX_COLLECTIONS`: Firestore
  documents (Datastore entities) sampled per collection (kind), and the
  collections (kinds) read per database.
- `BIGTABLE_MAX_ROWS`: rows sampled per Bigtable table.
- `LOGGING_LOOKBACK_DAYS`, `LOGGING_MAX_ENTRIES_PER_LOG`, `LOGGING_MAX_LOGS`:
  Cloud Logging's window, and the entries and logs sampled per project;
  `LOGGING_PRIVATE_READ`: `on` also reads Data Access audit logs (Private Logs
  Viewer); off by default.
- `SECRET_MANAGER_READ`: `on` reads Secret Manager secrets' latest versions
  (counts only); off by default.
- `GCP_DB_READ`: the database kinds that are read (`cloudsql_postgresql`,
  `cloudsql_mysql`, `alloydb`, or `all`); off by default, since each database
  needs an IAM database user for the service account.
- `GCP_DB_PRINCIPAL`: the service account's email, whose IAM database users
  are logged in as.
- `DB_SCHEMAS`, `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES`,
  `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS`: as the databases
  runner's.
- `DISCOVER_ALLOW`, `DISCOVER_DENY`, `DISCOVER_SAMPLING`: the core's rules, by
  kind and name (`gcs:prod-*`, `tag:scan=false`; a store's tags are its labels).
- `SAMPLE_PERCENT`, `GCS_MAX_OBJECTS_PER_PREFIX`: object sampling, a stable
  share of objects and at most n per directory.
- `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES`, `COLUMNAR_MAX_ROWS`: per-object caps.
- `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS`,
  `MAX_OBJECTS_PER_RUN`: the run's budget.
- `STATE_BUCKET`: the job's own bucket (`gs://<bucket>`), for the findings, the
  cursors and the lock.
- `FINDINGS_HTTPS_URL` with `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE`:
  the core's signed HTTPS push.
- `FINDINGS_PUBSUB_TOPIC`: also publish to a Pub/Sub topic
  (`projects/<project>/topics/<topic>`) as the job's service account, which
  the topic's owner grants Pub/Sub Publisher on that topic only.
- `FINDINGS_FILE`: write the findings document to a file (a mounted volume).
- `SCAN_MODE` (#55): `scanner` (the default), `vendor` (Sensitive Data
  Protection's data profiles are imported and nothing is read) or `both`;
  `SDP_LOCATIONS` (default `global`): where its discovery keeps the profiles;
  `SDP_MAX_PROFILES`: the most profiles imported a run.
"""

from __future__ import annotations

import os
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from sensitive_data_core.modes import SCANNER, ModeError, read_mode
from sensitive_data_core.rules import (
    SamplingRule,
    StoreRule,
    sampling_for,
    sampling_rules,
    store_rules,
)
from sensitive_data_core.safety import Secret

# Google Cloud's databases: discovered by default, read only when named in GCP_DB_READ.
DATABASE_KINDS: tuple[str, ...] = (
    "cloudsql_postgresql",
    "cloudsql_mysql",
    "cloudsql_sqlserver",
    "alloydb",
)
# Every kind this package discovers, and the ones discovered by default.
KINDS: tuple[str, ...] = (
    "gcs",
    "bigquery",
    "firestore",
    "datastore",
    "spanner",
    "bigtable",
    "cloud_logging",
    "pubsub",
    "gce_snapshot",
    "secret_manager",
    *DATABASE_KINDS,
)
DEFAULT_KINDS: tuple[str, ...] = KINDS
# Rule and DISCOVER prefixes: each kind, and shorter names for it.
KIND_ALIASES = {
    **{k: k for k in KINDS},
    "storage": "gcs",
    "bucket": "gcs",
    "buckets": "gcs",
    "bq": "bigquery",
    "cloudsql": "cloudsql_postgresql",
    "postgresql": "cloudsql_postgresql",
    "postgres": "cloudsql_postgresql",
    "mysql": "cloudsql_mysql",
    "sqlserver": "cloudsql_sqlserver",
    "alloy": "alloydb",
    "documents": "firestore",
    "logging": "cloud_logging",
    "logs": "cloud_logging",
    "topics": "pubsub",
    "snapshots": "gce_snapshot",
    "snapshot": "gce_snapshot",
    "secrets": "secret_manager",
    "secretmanager": "secret_manager",
}

_SITE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_NUMBER = re.compile(r"^[0-9]{1,24}$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$|^[a-z][a-z0-9.:-]{4,62}[a-z0-9]$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")
# The service account's email, whose IAM database users the customer creates.
_PRINCIPAL = re.compile(r"^[a-z][a-z0-9-]{4,62}@[a-z][a-z0-9.:-]{4,62}\.iam\.gserviceaccount\.com$")
_TOPIC = re.compile(
    r"^projects/[a-z][a-z0-9.:-]{4,62}[a-z0-9]/topics/[A-Za-z][A-Za-z0-9._~+%-]{2,254}$"
)
MAX_SECRET_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A setting is wrong. `code` says which, and is safe to log; nothing else is kept."""

    def __init__(self, code: str) -> None:
        self.code = re.sub(r"[^a-z0-9_]", "", code)[:60] or "config"
        super().__init__(f"configuration: {self.code}")

    def __repr__(self) -> str:
        return f"ConfigError({self.code!r})"


@dataclass(frozen=True)
class Settings:
    site: str
    # Cloud Asset Inventory scopes: `organizations/<n>`, `folders/<n>` or `projects/<id>`.
    scopes: tuple[str, ...] = ()
    discover: tuple[str, ...] = DEFAULT_KINDS
    allow: tuple[StoreRule, ...] = ()
    deny: tuple[StoreRule, ...] = ()
    sampling: tuple[SamplingRule, ...] = ()
    sample_percent: int = 100
    gcs_max_objects_per_prefix: int = 0
    max_object_bytes: int = 20 * 1024**2
    max_inflated_bytes: int = 100 * 1024**2
    columnar_max_rows: int = 10_000
    skew_seconds: int = 300
    max_items_per_run: int = 20_000
    max_bytes_per_run: int = 2 * 1024**3
    max_run_seconds: int = 3000
    # #67: the per-object index beside the state (`OBJECT_INDEX`, on), and its cap per source.
    object_index: bool = True
    index_max_objects: int = 10_000_000
    rescan_percent: int = 25  # the share of each source's budget rescans may use (0: none)
    max_objects_per_run: int = 0
    state_bucket: str | None = None
    https_url: Secret | None = field(default=None, repr=False)
    hmac_key: Secret | None = field(default=None, repr=False)
    pubsub_topic: str | None = None
    findings_file: str | None = None
    # BigQuery: rows read per table with tabledata.list.
    bigquery_max_rows: int = 1000
    # Firestore and Datastore: documents (entities) sampled per collection (kind), and how
    # many collections; Bigtable: rows sampled per table.
    documents_max: int = 500
    documents_max_collections: int = 200
    bigtable_max_rows: int = 1000
    # Cloud Logging: the window sampled, entries per log, logs per project, and whether
    # private (Data Access) logs are read.
    logging_lookback_days: int = 1
    logging_max_entries: int = 500
    logging_max_logs: int = 200
    logging_private_read: bool = False
    # Secret Manager's values: off by default, counts only when on.
    secret_manager_read: bool = False
    # Cloud SQL and AlloyDB (opt-in): which kinds are read, as whom, and how much.
    db_read: tuple[str, ...] = ()
    db_principal: str | None = None
    db_schemas: tuple[str, ...] = ()
    db_max_rows: int = 1000
    db_max_tables: int = 500
    db_statement_seconds: int = 60
    db_connect_seconds: int = 15
    # #55: who finds the data (the core's modes), and where Sensitive Data Protection keeps
    # its profiles (its discovery configuration's locations).
    scan_mode: str = SCANNER
    sdp_locations: tuple[str, ...] = ("global",)
    sdp_max_profiles: int = 20_000

    def sampling_for(
        self, kind: str, name: str, tags: dict[str, str] | None
    ) -> tuple[int | None, int | None]:
        return sampling_for(self.sampling, kind, name, tags)


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


def _state(raw: str | None) -> str | None:
    t = (raw or "").strip().rstrip("/")
    if not t:
        return None
    if not t.startswith("gs://") or not _BUCKET.match(t[5:]):
        raise ConfigError("state_bucket")
    return t[5:]


def _scopes(e: Mapping[str, str]) -> tuple[str, ...]:
    org = (e.get("GCP_ORGANIZATION") or "").strip()
    folders = _list(e.get("GCP_FOLDERS"))
    projects = _list(e.get("GCP_PROJECTS"))
    given = [bool(org), bool(folders), bool(projects)]
    if sum(given) == 0:
        raise ConfigError("no_scope")
    if sum(given) > 1:
        raise ConfigError("scope_twice")
    if org:
        if not _NUMBER.match(org):
            raise ConfigError("gcp_organization")
        return (f"organizations/{org}",)
    if folders:
        if any(not _NUMBER.match(f) for f in folders):
            raise ConfigError("gcp_folders")
        return tuple(f"folders/{f}" for f in folders)
    if any(not _PROJECT.match(p) for p in projects):
        raise ConfigError("gcp_projects")
    return tuple(f"projects/{p}" for p in projects)


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


def _mode(raw: str | None) -> str:
    try:
        return read_mode(raw)
    except ModeError:
        raise ConfigError("scan_mode") from None


def _locations(raw: str | None) -> tuple[str, ...]:
    got = _list(raw) or ("global",)
    if any(not re.match(r"^[a-z][a-z0-9-]{1,40}$", x) for x in got):
        raise ConfigError("sdp_locations")
    return got


def read_settings(env: Mapping[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    site = (e.get("SCANNER_SITE") or "").strip().lower()
    if not _SITE.match(site):
        raise ConfigError("scanner_site")
    scopes = _scopes(e)
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
    topic = (e.get("FINDINGS_PUBSUB_TOPIC") or "").strip() or None
    if topic is not None and not _TOPIC.match(topic):
        raise ConfigError("findings_pubsub_topic")
    findings_file = (e.get("FINDINGS_FILE") or "").strip() or None
    state = _state(e.get("STATE_BUCKET"))
    if state is None and https_url is None and topic is None and findings_file is None:
        raise ConfigError("no_findings_destination")
    private = _on(e.get("LOGGING_PRIVATE_READ"))
    if private is None:
        raise ConfigError("logging_private_read")
    secrets = _on(e.get("SECRET_MANAGER_READ"))
    if secrets is None:
        raise ConfigError("secret_manager_read")
    try:
        db_read = _kinds(e.get("GCP_DB_READ"), (), DATABASE_KINDS)
    except ConfigError:
        raise ConfigError("gcp_db_read") from None
    principal = (e.get("GCP_DB_PRINCIPAL") or "").strip().lower() or None
    if principal is not None and not _PRINCIPAL.match(principal):
        raise ConfigError("gcp_db_principal")
    if principal is None and set(db_read) - {"cloudsql_sqlserver"}:
        raise ConfigError("gcp_db_principal")
    try:
        allow = store_rules(e.get("DISCOVER_ALLOW"), KIND_ALIASES)
        deny = store_rules(e.get("DISCOVER_DENY"), KIND_ALIASES)
        sampling = sampling_rules(e.get("DISCOVER_SAMPLING"), KIND_ALIASES)
    except ValueError:
        raise ConfigError("discover_rule") from None
    return Settings(
        site=site,
        scopes=scopes,
        discover=_kinds(e.get("DISCOVER")),
        allow=allow,
        deny=deny,
        sampling=sampling,
        sample_percent=_int(e.get("SAMPLE_PERCENT"), 100, 1, 100),
        gcs_max_objects_per_prefix=_int(e.get("GCS_MAX_OBJECTS_PER_PREFIX"), 0, 0, 1_000_000),
        max_object_bytes=_int(e.get("MAX_OBJECT_BYTES"), 20 * 1024**2, 1024, 1024**3),
        max_inflated_bytes=_int(e.get("MAX_INFLATED_BYTES"), 100 * 1024**2, 1024, 4 * 1024**3),
        columnar_max_rows=_int(e.get("COLUMNAR_MAX_ROWS"), 10_000, 1, 1_000_000),
        max_items_per_run=_int(e.get("MAX_ITEMS_PER_RUN"), 20_000, 1, 1_000_000),
        max_bytes_per_run=_int(e.get("MAX_BYTES_PER_RUN"), 2 * 1024**3, 1024, 50 * 1024**3),
        max_run_seconds=_int(e.get("MAX_RUN_SECONDS"), 3000, 60, 24 * 3600),
        object_index=(e.get("OBJECT_INDEX") or "on").strip().lower()
        not in ("off", "false", "0", "no"),
        index_max_objects=_int(e.get("INDEX_MAX_OBJECTS"), 10_000_000, 1000, 1_000_000_000),
        rescan_percent=_int(e.get("RESCAN_PERCENT"), 25, 0, 100),
        max_objects_per_run=_int(e.get("MAX_OBJECTS_PER_RUN"), 0, 0, 10_000_000),
        state_bucket=state,
        https_url=https_url,
        hmac_key=key,
        pubsub_topic=topic,
        findings_file=findings_file,
        bigquery_max_rows=_int(e.get("BIGQUERY_MAX_ROWS"), 1000, 1, 100_000),
        documents_max=_int(e.get("DOCUMENTS_MAX_PER_COLLECTION"), 500, 1, 10_000),
        documents_max_collections=_int(e.get("DOCUMENTS_MAX_COLLECTIONS"), 200, 1, 5000),
        bigtable_max_rows=_int(e.get("BIGTABLE_MAX_ROWS"), 1000, 1, 100_000),
        logging_lookback_days=_int(e.get("LOGGING_LOOKBACK_DAYS"), 1, 1, 400),
        logging_max_entries=_int(e.get("LOGGING_MAX_ENTRIES_PER_LOG"), 500, 1, 1000),
        logging_max_logs=_int(e.get("LOGGING_MAX_LOGS"), 200, 1, 5000),
        logging_private_read=private,
        secret_manager_read=secrets,
        db_read=db_read,
        db_principal=principal,
        db_schemas=_list(e.get("DB_SCHEMAS")),
        db_max_rows=_int(e.get("DB_MAX_ROWS_PER_TABLE"), 1000, 1, 100_000),
        db_max_tables=_int(e.get("DB_MAX_TABLES"), 500, 1, 10_000),
        db_statement_seconds=_int(e.get("DB_STATEMENT_TIMEOUT_SECONDS"), 60, 5, 3600),
        db_connect_seconds=_int(e.get("DB_CONNECT_TIMEOUT_SECONDS"), 15, 1, 300),
        scan_mode=_mode(e.get("SCAN_MODE")),
        sdp_locations=_locations(e.get("SDP_LOCATIONS")),
        sdp_max_profiles=_int(e.get("SDP_MAX_PROFILES"), 20_000, 1, 1_000_000),
    )
