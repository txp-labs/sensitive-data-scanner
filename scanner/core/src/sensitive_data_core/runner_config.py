"""Settings pulled from Mermera, and where each setting a run used came from (#109).

A runner that pushes its findings to Mermera (`FINDINGS_HTTPS_URL` and the
site's HMAC key) pulls its settings from the same site before it reads its own
configuration: `GET <base>/config`, next to the push's `<base>/findings`,
signed like a push over `<t>.config:<siteId>`. The response is the **runner
config contract** (docs/mermera-config.md): a flat JSON object of setting
names and string values, `CONFIG_CONTRACT: "1"`.

**Precedence**, per setting: an explicit environment variable or template
parameter (a non-empty value), then Mermera's value, then the default. Only
the settings `REGISTRY` names for the runner's platform can be set by Mermera;
any other name in the response is ignored and listed by name
(`configPull.ignored`), and a value the setting does not accept is ignored
too (`configPull.invalid`). Nothing the response says is ever logged.

**IAM-gated settings.** A setting whose read needs a permission the deploy
template grants only with its own parameter (Parameter Store decryption,
Secrets Manager, Macie's reads, ...) is gated: the template tells the runner
which grants it made (`IAM_GRANTS`, a comma list of setting names). When the
value Mermera asks for needs a grant the role does not have, the run keeps the
setting at its default and reports `gate: iam` with the template parameter to
change. It never fails silently, and it never tries a read it knows will be
denied. Without `IAM_GRANTS` (a template older than #109, a test) nothing is
gated: a missing permission then shows as the store's `access_denied`.

The run reports both (findings schema 1.13): `settingsSource` (each setting's
effective value and source: `env`, `mermera` or `default`, with `gate`,
`parameter` and `requested` when gated) and `configPull` (how the pull went).
Values are enumerations, booleans or small numbers: never a name, an ARN or a
secret.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .push import SIGNATURE_HEADER, Revealable, sign
from .safety import error_name, log_event

CONTRACT = "1"
CONTRACT_KEY = "CONFIG_CONTRACT"
# Keys the response may carry that are not settings (Mermera's own statements): accepted,
# never applied, never listed as ignored.
INFORMATIONAL = frozenset({CONTRACT_KEY, "FINDINGS_SCHEMA_ACCEPTED", "FINDINGS_SCHEMA_REVIEWED"})
MAX_CONFIG_BYTES = 64 * 1024
TIMEOUT_SECONDS = 10
_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_SITE_PATH = re.compile(r"/sites/([0-9A-Fa-f-]{36})/findings/?$")

ENV = "env"
MERMERA = "mermera"
DEFAULT = "default"

_ON = ("on", "true", "1", "yes")
_OFF = ("off", "false", "0", "no")


@dataclass(frozen=True)
class Setting:
    """One setting Mermera may set.

    `kind`: `bool` (any of on/off/true/false/1/0/yes/no, written `true` / `false`), `enum`
    (one of `choices`, lower case), or `int` (within `lo`..`hi`). `parameter`: the deploy
    template's parameter that sets it (scanner.yaml, main.bicep or Terraform). `grant`: the
    name the template lists in `IAM_GRANTS` when its role holds what a read needs, and
    `gated`: the values that need it. `hook`: the read it turns on is not built."""

    name: str
    kind: str
    default: str
    parameter: str
    choices: tuple[str, ...] = ()
    lo: int = 0
    hi: int = 0
    grant: str | None = None
    gated: tuple[str, ...] = ("true",)
    hook: bool = False
    # A setting whose default is another's value (a SaaS vendor's mode defaults to SCAN_MODE).
    inherit: str | None = None

    def normalize(self, raw: str) -> str | None:
        """The value as written in the report, or None when this setting does not accept it."""
        v = raw.strip().lower()
        if self.kind == "bool":
            return "true" if v in _ON else "false" if v in _OFF else None
        if self.kind == "enum":
            return v if v in self.choices else None
        if self.kind == "int":
            try:
                n = int(v)
            except ValueError:
                return None
            return str(n) if self.lo <= n <= self.hi else None
        return None


def _bool(name: str, default: bool, parameter: str, **kw: Any) -> Setting:
    return Setting(name, "bool", "true" if default else "false", parameter, **kw)


_MODES = ("scanner", "vendor", "both")

# The settings Mermera may set, per platform (docs/mermera-config.md lists them with their
# template parameters). A setting that names resources (ARNs, subnets, brokers) or that the
# template must build something for (a queue, a role) is not here: it is the template's.
REGISTRY: dict[str, tuple[Setting, ...]] = {
    "aws": (
        _bool("S3_READ_GLACIER_IR", False, "S3ReadGlacierIr"),
        _bool("S3_RESTORE_ARCHIVED", False, "S3RestoreArchived", hook=True),
        Setting(
            "SCAN_MODE",
            "enum",
            "scanner",
            "ScanMode",
            choices=_MODES,
            grant="MACIE_IMPORT",
            gated=("vendor", "both"),
        ),
        _bool("SSM_DECRYPT", False, "SsmDecrypt", grant="SSM_DECRYPT"),
        _bool("SECRETS_READ", False, "SecretsRead", grant="SECRETS_READ"),
        _bool("TIMESTREAM_READ", True, "TimestreamRead", grant="TIMESTREAM_READ"),
        _bool("KEYSPACES_READ", True, "KeyspacesRead", grant="KEYSPACES_READ"),
        Setting(
            "GLUE_LAKE_FORMATION", "enum", "read", "GlueLakeFormation", choices=("read", "skip")
        ),
        _bool("FILESYSTEM_TASK_ENABLED", False, "FilesystemTaskEnabled", hook=True),
        _bool("EBS_DIRECT_READ", False, "EbsDirectRead", grant="EBS_DIRECT_READ"),
        _bool("SQS_DLQ_READ", False, "SqsDlqRead", grant="SQS_DLQ_READ"),
        _bool("MSK_READ", False, "MskRead", grant="MSK_READ"),
        _bool("ECR_READ", False, "EcrRead", grant="ECR_READ"),
        _bool("SAGEMAKER_READ", False, "SageMakerRead"),
        _bool(
            "OPENSEARCH_SERVERLESS_READ",
            False,
            "OpenSearchServerlessRead",
            grant="OPENSEARCH_SERVERLESS_READ",
        ),
    ),
    "azure": (
        _bool("AZURE_READ_COLD_TIER", False, "readColdTier"),
        _bool("AZURE_REHYDRATE_ARCHIVE", False, "rehydrateArchive", hook=True),
        _bool("KEYVAULT_SECRETS_READ", False, "readKeyVaultSecrets", grant="KEYVAULT_SECRETS_READ"),
        _bool("AZURE_FILES_READ", False, "readFileShares", grant="AZURE_FILES_READ"),
        _bool("AZURE_LOG_ANALYTICS", True, "readLogAnalytics"),
        _bool("AZURE_READ_SNAPSHOTS", False, "readDiskSnapshots", hook=True),
        _bool("AZURE_COSMOS_READER_POLICY", False, "assignCosmosReaderPolicy", hook=True),
    ),
    "gcp": (
        _bool("GCS_READ_ARCHIVE", False, "read_archive_objects"),
        Setting(
            "SCAN_MODE",
            "enum",
            "scanner",
            "scan_mode",
            choices=_MODES,
            grant="SDP_PROFILES",
            gated=("vendor", "both"),
        ),
        _bool("GCP_SPANNER", True, "read_spanner", grant="GCP_SPANNER"),
        _bool("GCP_ALLOYDB", True, "read_alloydb", grant="GCP_ALLOYDB"),
        _bool("SECRET_MANAGER_READ", False, "read_secrets", grant="SECRET_MANAGER_READ"),
        _bool("LOGGING_PRIVATE_READ", False, "read_private_logs", grant="LOGGING_PRIVATE_READ"),
        _bool("GCP_SQLSERVER", False, "read_sqlserver", hook=True),
        _bool("GCP_READ_PUBSUB_DLQ", False, "read_pubsub_dead_letters", hook=True),
    ),
    "saas": (
        Setting("SCAN_MODE", "enum", "scanner", "SCAN_MODE", choices=_MODES),
        *(
            Setting(
                f"SCAN_MODE_{vendor}",
                "enum",
                "scanner",
                f"SCAN_MODE_{vendor}",
                choices=_MODES,
                inherit="SCAN_MODE",
            )
            for vendor in ("M365", "GOOGLE_WORKSPACE", "SLACK")
        ),
        _bool("M365_MAIL", True, "M365_MAIL"),
        _bool("GWS_ALERT_CENTER", True, "GWS_ALERT_CENTER"),
        _bool("LINK_VENDOR_ALERTS_BY_LOCATION", True, "LINK_VENDOR_ALERTS_BY_LOCATION"),
    ),
}


# ------------------------------------------------------------------ the pull


@dataclass
class Pull:
    """How the pull went. `status`: `ok`, `not_configured` (no push URL or key: nothing to pull
    from), `failed` (the endpoint could not be reached, or answered 5xx / 429), `refused` (a
    4xx), or `invalid` (not the contract: not a JSON object, too large, another contract
    major, or a value that is not a string). Only `ok` applies anything."""

    status: str
    settings: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    http_status: int | None = None


def config_target(findings_url: str) -> tuple[str, str] | None:
    """The config URL beside a push URL (`.../sites/<siteId>/findings` ->
    `.../sites/<siteId>/config`), and the site id the signature covers; None for a URL
    that names no site this way."""
    parts = urllib.parse.urlsplit(findings_url.strip())
    if parts.scheme != "https" or not parts.netloc:
        return None
    m = _SITE_PATH.search(parts.path)
    if m is None:
        return None
    path = parts.path[: m.start()] + f"/sites/{m[1]}/config"
    return urllib.parse.urlunsplit(("https", parts.netloc, path, "", "")), m[1]


def parse_config(raw: bytes) -> Pull:
    """A config response body, checked against the contract."""
    if len(raw) > MAX_CONFIG_BYTES:
        return Pull("invalid", error="too_large")
    try:
        doc = json.loads(raw)
    except ValueError:
        return Pull("invalid", error="not_json")
    if not isinstance(doc, dict):
        return Pull("invalid", error="not_an_object")
    contract = doc.get(CONTRACT_KEY)
    if contract is not None and str(contract).split(".", 1)[0] != CONTRACT:
        return Pull("invalid", error="contract_unsupported")
    out: dict[str, str] = {}
    for k, v in doc.items():
        if not isinstance(k, str) or not _NAME.match(k) or not isinstance(v, str):
            return Pull("invalid", error="not_a_setting")
        out[k] = v
    return Pull("ok", out)


def pull(
    findings_url: str | None,
    key: str | None,
    *,
    schema_version: str,
    opener: Callable[..., Any] | None = None,
    clock: Callable[[], float] = time.time,
) -> Pull:
    """GET the site's config, signed like a push over `<t>.config:<siteId>`. Never raises:
    every failure is a status, and the run goes on with its own settings."""
    if not findings_url or not key:
        return Pull("not_configured")
    target = config_target(findings_url)
    if target is None:
        return Pull("not_configured", error="no_site_in_url")
    url, site_id = target
    ts = str(int(clock()))
    query = urllib.parse.urlencode({"schemaVersion": schema_version})
    req = urllib.request.Request(  # noqa: S310 - https only (config_target)
        f"{url}?{query}",
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": f"sensitive-data-scanner/{__version__}",
            SIGNATURE_HEADER: sign(key.encode(), ts, f"config:{site_id}".encode()),
        },
    )
    try:
        with (opener or urllib.request.urlopen)(req, timeout=TIMEOUT_SECONDS) as resp:
            status = int(getattr(resp, "status", 200))
            body = resp.read(MAX_CONFIG_BYTES + 1)
    except Exception as err:  # reported by name only; the URL and the key never are
        code = getattr(err, "code", None)
        if isinstance(code, int):
            kind = "refused" if 400 <= code < 500 and code != 429 else "failed"
            return Pull(kind, error=f"http_{code}", http_status=code)
        return Pull("failed", error=error_name(err))
    if status >= 300:
        kind = "refused" if 400 <= status < 500 and status != 429 else "failed"
        return Pull(kind, error=f"http_{status}", http_status=status)
    return parse_config(body)


# ------------------------------------------------------------------ precedence


@dataclass
class Report:
    """What the run reports: each setting's effective value and source, and the pull."""

    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    pull: Pull = field(default_factory=lambda: Pull("not_configured"))
    ignored: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        cp: dict[str, Any] = {"status": self.pull.status, "contract": CONTRACT}
        if self.pull.error:
            cp["error"] = self.pull.error
        if self.pull.status == "ok":
            cp["applied"] = sorted(n for n, s in self.sources.items() if s["source"] == MERMERA)
        if self.ignored:
            cp["ignored"] = sorted(self.ignored)[:50]
        if self.invalid:
            cp["invalid"] = sorted(self.invalid)[:50]
        return {"settingsSource": dict(sorted(self.sources.items())), "configPull": cp}

    @property
    def gated(self) -> dict[str, dict[str, Any]]:
        return {k: v for k, v in self.sources.items() if v.get("gate")}


def grants_from(env: Mapping[str, str]) -> frozenset[str] | None:
    """The grants the deploy template made (`IAM_GRANTS`); None when it does not say."""
    raw = env.get("IAM_GRANTS")
    if raw is None:
        return None
    return frozenset(g.strip().upper() for g in raw.split(",") if g.strip()) - {"NONE"}


def resolve(
    platform: str,
    env: Mapping[str, str],
    remote: Mapping[str, str] | None,
    grants: frozenset[str] | None = None,
) -> tuple[dict[str, str], Report]:
    """The environment a runner reads its configuration from, with Mermera's settings applied
    under the precedence env > mermera > default, and the report of each setting's source.
    An invalid value in the environment is left for the runner's own configuration check
    (which refuses it); an invalid value from Mermera is ignored."""
    out = dict(env)
    report = Report()
    registry = {s.name: s for s in REGISTRY.get(platform, ())}
    remote = dict(remote or {})
    for name in remote:
        if name not in registry and name not in INFORMATIONAL:
            report.ignored.append(name)
    for s in registry.values():
        explicit = (env.get(s.name) or "").strip()
        inherited = False
        entry: dict[str, Any]
        if explicit:
            value = s.normalize(explicit) or explicit.lower()
            entry = {"value": value, "source": ENV}
        elif s.name in remote and s.normalize(remote[s.name]) is not None:
            value = str(s.normalize(remote[s.name]))
            entry = {"value": value, "source": MERMERA}
        else:
            if s.name in remote:
                report.invalid.append(s.name)
            parent = report.sources.get(s.inherit) if s.inherit else None
            if parent is not None:
                # Unset, it follows the setting it defaults to, as the runner reads it.
                value = str(parent["value"])
                entry = {"value": value, "source": parent["source"]}
                inherited = True
            else:
                value = s.default
                entry = {"value": value, "source": DEFAULT}
                if s.name in env:
                    out[s.name] = value  # set but empty (a template parameter left unset)
        if (
            s.grant is not None
            and grants is not None
            and value in s.gated
            and s.grant not in grants
        ):
            # The role lacks what this value needs: kept at the default, and named.
            requested = value
            value = s.default if s.default not in s.gated else _off(s)
            entry = {
                "value": value,
                "source": entry["source"],
                "gate": "iam",
                "parameter": s.parameter,
                "requested": requested,
            }
        if s.hook and value == "true":
            entry["hook"] = True
        report.sources[s.name] = entry
        if (entry["source"] == MERMERA and not inherited) or entry.get("gate"):
            out[s.name] = value
    return out, report


def _off(s: Setting) -> str:
    return "false" if s.kind == "bool" else s.default


def apply_mermera(
    platform: str,
    env: Mapping[str, str],
    *,
    schema_version: str,
    opener: Callable[..., Any] | None = None,
    clock: Callable[[], float] = time.time,
    key: Revealable | None = None,
    key_error: str | None = None,
) -> tuple[dict[str, str], Report]:
    """Pull Mermera's settings for this runner (when it pushes to Mermera) and apply them.
    The push URL and key are read as the runner reads them (`FINDINGS_HTTPS_URL`, and
    `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE`); the runner still checks them itself.
    A runner that holds its key elsewhere (AWS: a Secrets Manager secret, read once per cold
    start) passes it as `key`, or the name of the error that kept it from it (`key_error`:
    the pull is then `failed`, never silently skipped)."""
    url = (env.get("FINDINGS_HTTPS_URL") or "").strip() or None
    if key_error is not None and url is not None:
        merged, report = resolve(platform, env, None, grants_from(env))
        report.pull = Pull("failed", error=f"key:{key_error}"[:80])
        log_event("config.pull_failed", status="failed", error=report.pull.error)
        return merged, report
    if key is not None:
        held = key.reveal()
        key_text: str | None = held.strip() or None
    else:
        key_text = (env.get("FINDINGS_HMAC_KEY") or "").strip() or None
    key = None  # the revealed text lives only in this call
    key_file = (env.get("FINDINGS_HMAC_KEY_FILE") or "").strip()
    if key_text is None and key_file:
        try:
            key_text = Path(key_file).read_text(encoding="utf-8").strip() or None
        except OSError:
            key_text = None
    got = pull(url, key_text, schema_version=schema_version, opener=opener, clock=clock)
    merged, report = resolve(
        platform, env, got.settings if got.status == "ok" else None, grants_from(env)
    )
    report.pull = got
    if got.status not in ("ok", "not_configured"):
        log_event("config.pull_failed", status=got.status, error=got.error)
    for name, entry in report.gated.items():
        log_event("config.gated", setting=name, parameter=entry["parameter"])
    return merged, report
