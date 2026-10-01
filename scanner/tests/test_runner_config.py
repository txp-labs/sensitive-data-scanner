"""Settings pulled from Mermera: the contract, the precedence, and IAM gating (#109).

A runner that pushes to Mermera pulls `GET .../config` (signed over
`<t>.config:<siteId>`), and applies the settings it is allowed to under
env > mermera > default. A setting whose read needs a grant the template did not
make (`IAM_GRANTS`) stays at its default and is reported `gate: iam` with the
template parameter. The run reports `settingsSource` and `configPull`
(findings schema 1.13; docs/mermera-config.md). No network: every response is a
fake. All values are made up.
"""

from __future__ import annotations

import dataclasses
import io
import json
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, Env, config
from conftest import REPO
from sensitive_data_core.push import verify
from sensitive_data_core.runner_config import (
    CONTRACT,
    REGISTRY,
    Pull,
    apply_mermera,
    config_target,
    grants_from,
    parse_config,
    pull,
    resolve,
)
from sensitive_data_scanner.config import load_config, read_config

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
SITE = "0b7c2f4e-1a2b-4c3d-8e9f-0123456789ab"
TENANT = "11111111-2222-3333-4444-555555555555"
URL = f"https://api.dev.example/v1/scanner/sites/{SITE}/findings"
INGEST = f"https://ingest.dev.example/v1/tenants/{TENANT}/sites/{SITE}/findings"
KEY = "k" * 40  # a made-up site key
DOC = Path(__file__).resolve().parents[2] / "docs" / "mermera-config.md"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


class Resp(io.BytesIO):
    status = 200

    def __enter__(self) -> Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class Mermera:
    """A fake config endpoint: checks the signature as Mermera does, answers `body`."""

    def __init__(self, body: Any, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requests: list[Any] = []

    def __call__(self, req: Any, timeout: float) -> Resp:
        self.requests.append(req)
        if self.status >= 400:
            raise urllib.error.HTTPError(req.full_url, self.status, "no", {}, None)  # type: ignore[arg-type]
        raw = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        resp = Resp(raw)
        resp.status = self.status
        return resp


# ------------------------------------------------------------------ the pull


def test_the_config_url_is_beside_the_push_url_on_either_host() -> None:
    assert config_target(URL) == (f"https://api.dev.example/v1/scanner/sites/{SITE}/config", SITE)
    assert config_target(INGEST) == (
        f"https://ingest.dev.example/v1/tenants/{TENANT}/sites/{SITE}/config",
        SITE,
    )
    assert config_target(URL + "/") is not None
    assert config_target(URL.replace("https:", "http:")) is None
    assert config_target("https://collector.example/hook") is None


def test_the_pull_is_signed_over_config_and_the_site_and_names_the_schema() -> None:
    m = Mermera({"CONFIG_CONTRACT": "1", "SCAN_MODE": "both"})
    got = pull(URL, KEY, schema_version="1.13", opener=m, clock=lambda: 1_790_000_000)
    assert got == Pull("ok", {"CONFIG_CONTRACT": "1", "SCAN_MODE": "both"})
    req = m.requests[0]
    assert req.get_method() == "GET"
    parts = urllib.parse.urlsplit(req.full_url)
    assert parts.path.endswith(f"/sites/{SITE}/config")
    assert urllib.parse.parse_qs(parts.query) == {"schemaVersion": ["1.13"]}
    header = req.get_header("X-sds-signature")
    assert verify(KEY.encode(), header, f"config:{SITE}".encode(), now=1_790_000_000)
    assert not verify(KEY.encode(), header, b"config:other", now=1_790_000_000)


@pytest.mark.parametrize(
    ("mermera", "status", "error"),
    [
        (Mermera({}, 401), "refused", "http_401"),
        (Mermera({}, 403), "refused", "http_403"),
        (Mermera({}, 429), "failed", "http_429"),
        (Mermera({}, 503), "failed", "http_503"),
        (Mermera(b"not json"), "invalid", "not_json"),
        (Mermera([1, 2]), "invalid", "not_an_object"),
        (Mermera({"CONFIG_CONTRACT": "2"}), "invalid", "contract_unsupported"),
        (Mermera({"SCAN_MODE": True}), "invalid", "not_a_setting"),
        (Mermera({"scan mode": "both"}), "invalid", "not_a_setting"),
        (Mermera(b"{" + b" " * 70_000 + b"}"), "invalid", "too_large"),
    ],
)
def test_a_pull_that_goes_wrong_is_a_status_never_an_exception(
    mermera: Mermera, status: str, error: str
) -> None:
    got = pull(URL, KEY, schema_version="1.13", opener=mermera)
    assert (got.status, got.error, got.settings) == (status, error, {})


def test_an_unreachable_endpoint_is_failed_by_error_name() -> None:
    def down(req: Any, timeout: float) -> Any:
        raise urllib.error.URLError("made-up outage")

    got = pull(URL, KEY, schema_version="1.13", opener=down)
    assert (got.status, got.error) == ("failed", "URLError")


def test_without_a_push_url_or_key_there_is_nothing_to_pull() -> None:
    assert pull(None, KEY, schema_version="1.13").status == "not_configured"
    assert pull(URL, None, schema_version="1.13").status == "not_configured"
    got = pull("https://collector.example/hook", KEY, schema_version="1.13")
    assert (got.status, got.error) == ("not_configured", "no_site_in_url")


def test_a_minor_contract_version_is_accepted() -> None:
    assert parse_config(b'{"CONFIG_CONTRACT":"1.4","SCAN_MODE":"vendor"}').status == "ok"
    assert parse_config(b'{"SCAN_MODE":"vendor"}').status == "ok"  # Mermera before the key


# ------------------------------------------------------------------ precedence


def test_env_wins_then_mermera_then_the_default() -> None:
    env = {"SSM_DECRYPT": "false", "SECRETS_READ": ""}
    remote = {"SSM_DECRYPT": "true", "SECRETS_READ": "on", "S3_READ_GLACIER_IR": "yes"}
    out, report = resolve("aws", env, remote)
    src = report.sources
    assert src["SSM_DECRYPT"] == {"value": "false", "source": "env"}
    assert src["SECRETS_READ"] == {"value": "true", "source": "mermera"}
    assert src["S3_READ_GLACIER_IR"] == {"value": "true", "source": "mermera"}
    assert src["TIMESTREAM_READ"] == {"value": "true", "source": "default"}
    assert src["SCAN_MODE"] == {"value": "scanner", "source": "default"}
    assert out["SSM_DECRYPT"] == "false" and out["SECRETS_READ"] == "true"
    assert out["S3_READ_GLACIER_IR"] == "true"
    assert set(src) == {s.name for s in REGISTRY["aws"]}


def test_an_empty_template_parameter_is_unset_and_takes_the_default() -> None:
    # TIMESTREAM_READ is on by default: an empty variable must not read as off.
    out, report = resolve("aws", {"TIMESTREAM_READ": "", "GLUE_LAKE_FORMATION": ""}, None)
    assert out["TIMESTREAM_READ"] == "true" and out["GLUE_LAKE_FORMATION"] == "read"
    assert read_config({"RESULTS_BUCKET": "x", **out}).timestream_read is True
    assert report.sources["TIMESTREAM_READ"]["source"] == "default"


def test_what_mermera_may_not_set_is_ignored_and_named() -> None:
    remote = {
        "RESULTS_BUCKET": "elsewhere",
        "KMS_ALLOWED_KEY_ARNS": "arn:aws:kms:us-east-1:111122223333:key/x",
        "FINDINGS_SCHEMA_ACCEPTED": "1.x",
        "FINDINGS_SCHEMA_REVIEWED": "1.12",
        "CONFIG_CONTRACT": "1",
        "SSM_DECRYPT": "maybe",
    }
    out, report = resolve("aws", {"RESULTS_BUCKET": "mine"}, remote)
    assert out["RESULTS_BUCKET"] == "mine" and "KMS_ALLOWED_KEY_ARNS" not in out
    assert sorted(report.ignored) == ["KMS_ALLOWED_KEY_ARNS", "RESULTS_BUCKET"]
    assert report.invalid == ["SSM_DECRYPT"]
    assert report.sources["SSM_DECRYPT"] == {"value": "false", "source": "default"}


def test_a_setting_mermera_turns_on_without_its_grant_is_gated_with_its_parameter() -> None:
    grants = grants_from({"IAM_GRANTS": "none,SSM_DECRYPT,,"})
    assert grants == frozenset({"SSM_DECRYPT"})
    remote = {"SSM_DECRYPT": "on", "SECRETS_READ": "on", "SCAN_MODE": "vendor", "MSK_READ": "off"}
    out, report = resolve("aws", {}, remote, grants)
    src = report.sources
    assert src["SSM_DECRYPT"] == {"value": "true", "source": "mermera"}
    assert src["SECRETS_READ"] == {
        "value": "false",
        "source": "mermera",
        "gate": "iam",
        "parameter": "SecretsRead",
        "requested": "true",
    }
    assert src["SCAN_MODE"]["gate"] == "iam" and src["SCAN_MODE"]["value"] == "scanner"
    assert src["SCAN_MODE"]["parameter"] == "ScanMode"
    # A default-on setting the template did not grant (an old role) is gated too.
    assert src["TIMESTREAM_READ"]["gate"] == "iam" and src["TIMESTREAM_READ"]["value"] == "false"
    # Off needs nothing.
    assert "gate" not in src["MSK_READ"]
    assert out["SECRETS_READ"] == "false" and out["SCAN_MODE"] == "scanner"
    assert set(report.gated) == {"SECRETS_READ", "SCAN_MODE", "TIMESTREAM_READ", "KEYSPACES_READ"}


def test_without_iam_grants_nothing_is_gated() -> None:
    assert grants_from({}) is None
    _, report = resolve("aws", {}, {"SECRETS_READ": "on"}, None)
    assert report.sources["SECRETS_READ"] == {"value": "true", "source": "mermera"}


def test_a_hook_switched_on_is_flagged() -> None:
    _, report = resolve("aws", {}, {"S3_RESTORE_ARCHIVED": "on"})
    assert report.sources["S3_RESTORE_ARCHIVED"] == {
        "value": "true",
        "source": "mermera",
        "hook": True,
    }


def test_a_saas_vendors_mode_follows_scan_mode_unless_set() -> None:
    out, report = resolve("saas", {"SCAN_MODE_SLACK": "scanner"}, {"SCAN_MODE": "both"})
    src = report.sources
    assert src["SCAN_MODE"] == {"value": "both", "source": "mermera"}
    assert src["SCAN_MODE_M365"] == {"value": "both", "source": "mermera"}
    assert src["SCAN_MODE_SLACK"] == {"value": "scanner", "source": "env"}
    assert "SCAN_MODE_M365" not in out  # the runner's own fallback reads SCAN_MODE


@pytest.mark.parametrize("platform", ["aws", "azure", "gcp", "saas"])
def test_every_platform_reads_each_setting_mermera_may_set(platform: str) -> None:
    configs = {
        "aws": REPO / "scanner/src/sensitive_data_scanner/config.py",
        "azure": REPO / "scanner/azure/src/sensitive_data_azure/config.py",
        "gcp": REPO / "scanner/gcp/src/sensitive_data_gcp/config.py",
        "saas": REPO / "scanner/saas/src/sensitive_data_saas/config.py",
    }
    source = configs[platform].read_text()
    for s in REGISTRY[platform]:
        assert f'"{s.name}"' in source or '"SCAN_MODE_{' in source, (platform, s.name)
        assert s.normalize(s.default) == s.default, s.name


def test_the_contract_doc_lists_every_setting_with_its_parameter() -> None:
    text = DOC.read_text()
    assert f'"CONFIG_CONTRACT": "{CONTRACT}"' in text
    for platform, settings in REGISTRY.items():
        for s in settings:
            rows = [line for line in text.splitlines() if line.startswith(f"| `{s.name}` |")]
            assert any(f"`{s.parameter}`" in r and platform in r for r in rows), (platform, s.name)


def test_apply_reads_the_key_from_its_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text(KEY + "\n")
    m = Mermera({"AZURE_READ_COLD_TIER": "on"})
    env = {"FINDINGS_HTTPS_URL": INGEST, "FINDINGS_HMAC_KEY_FILE": str(key_file)}
    out, report = apply_mermera("azure", env, schema_version="1.13", opener=m)
    assert out["AZURE_READ_COLD_TIER"] == "true"
    assert report.as_json()["configPull"] == {
        "status": "ok",
        "contract": "1",
        "applied": ["AZURE_READ_COLD_TIER"],
    }


def test_a_failed_pull_leaves_the_run_on_its_own_settings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    m = Mermera({}, 503)
    out, report = apply_mermera(
        "gcp",
        {"FINDINGS_HTTPS_URL": URL, "FINDINGS_HMAC_KEY": KEY},
        schema_version="1.13",
        opener=m,
    )
    assert "GCS_READ_ARCHIVE" not in out
    assert report.as_json()["configPull"] == {
        "status": "failed",
        "contract": "1",
        "error": "http_503",
    }
    assert all(s["source"] == "default" for s in report.sources.values())
    logged = capsys.readouterr().out
    assert (
        '"event":"config.pull_failed"' in logged
        and KEY not in logged
        and "dev.example" not in logged
    )


# ------------------------------------------------------------------ the runners


def test_the_aws_function_pulls_when_it_has_a_site_and_reports_each_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    m = Mermera(
        {
            "CONFIG_CONTRACT": "1",
            "S3_READ_GLACIER_IR": "on",
            "SSM_DECRYPT": "on",
            "SECRETS_READ": "on",
            "SCAN_MODE": "both",
            "FINDINGS_SCHEMA_REVIEWED": "1.13",
        }
    )
    monkeypatch.setattr("urllib.request.urlopen", m)
    env = {
        "RESULTS_BUCKET": "results",
        "FINDINGS_HTTPS_URL": URL,
        "FINDINGS_HMAC_KEY": KEY,
        "IAM_GRANTS": ",,SSM_DECRYPT,,TIMESTREAM_READ,KEYSPACES_READ,,,,",
        "S3_READ_GLACIER_IR": "",
        "SCAN_MODE": "",
        "SECRETS_READ": "",
    }
    c = load_config(None, None, env)
    assert c.mermera_pull and c.s3_read_glacier_ir and c.ssm_decrypt
    assert not c.secrets_read and c.scan_mode == "scanner"
    src = c.settings_report["settingsSource"]
    assert src["SECRETS_READ"]["parameter"] == "SecretsRead"
    assert src["SCAN_MODE"] == {
        "value": "scanner",
        "source": "mermera",
        "gate": "iam",
        "parameter": "ScanMode",
        "requested": "both",
    }
    # Mermera's values decided these (two of them were then gated).
    assert c.settings_report["configPull"]["applied"] == [
        "S3_READ_GLACIER_IR",
        "SCAN_MODE",
        "SECRETS_READ",
        "SSM_DECRYPT",
    ]
    out = capsys.readouterr().out
    assert '"event":"config.gated"' in out and '"parameter":"SecretsRead"' in out


def test_a_configuration_document_counts_as_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("urllib.request.urlopen", Mermera({"S3_READ_GLACIER_IR": "on"}))
    env = {"RESULTS_BUCKET": "r", "FINDINGS_HTTPS_URL": URL, "FINDINGS_HMAC_KEY": KEY}
    c = load_config({"config": {"S3_READ_GLACIER_IR": False}}, None, env)
    assert not c.s3_read_glacier_ir
    assert c.settings_report["settingsSource"]["S3_READ_GLACIER_IR"]["source"] == "env"


def test_the_aws_function_needs_https_and_a_real_key_to_pull() -> None:
    with pytest.raises(ValueError, match="https"):
        read_config({"RESULTS_BUCKET": "r", "FINDINGS_HTTPS_URL": URL.replace("https", "http")})
    with pytest.raises(ValueError, match="FINDINGS_HMAC_KEY"):
        read_config({"RESULTS_BUCKET": "r", "FINDINGS_HTTPS_URL": URL, "FINDINGS_HMAC_KEY": "x"})
    assert not read_config({"RESULTS_BUCKET": "r"}).mermera_pull


def test_no_pull_without_a_site_and_the_document_still_says_so() -> None:
    c = load_config(None, None, {"RESULTS_BUCKET": "r"})
    assert c.settings_report["configPull"] == {"status": "not_configured", "contract": "1"}
    assert c.settings_report["settingsSource"]["S3_READ_GLACIER_IR"] == {
        "value": "false",
        "source": "default",
    }


def test_the_aws_document_carries_the_report_and_is_valid(env: Env) -> None:
    env.put("a.txt", "nothing")
    _, report = resolve("aws", {}, {"S3_READ_GLACIER_IR": "on", "SECRETS_READ": "on"}, frozenset())
    report.pull = Pull("ok")
    doc = env.run(config(settings_report=report.as_json(), s3_targets=[(DATA, "")]))
    assert doc is not None
    valid(doc)
    assert doc["settingsSource"]["SECRETS_READ"]["gate"] == "iam"
    assert doc["configPull"]["status"] == "ok"


def test_the_azure_job_pulls_before_it_reads_its_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import test_azure_blob as tab
    from sensitive_data_azure import __main__ as entry
    from sensitive_data_azure.sinks import sinks_for

    m = Mermera(
        {"CONFIG_CONTRACT": "1", "AZURE_READ_COLD_TIER": "on", "KEYVAULT_SECRETS_READ": "on"}
    )
    monkeypatch.setattr("urllib.request.urlopen", m)
    # The document goes to a file only here (the push is the core's, tested on its own).
    monkeypatch.setattr(
        entry,
        "sinks_for",
        lambda s, c: sinks_for(dataclasses.replace(s, https_url=None, hmac_key=None), c),
    )
    out = tmp_path / "doc.json"
    for k, v in {
        "SCANNER_SITE": "mg-contoso",
        "AZURE_MANAGEMENT_GROUP": "mg-contoso",
        "STATE_CONTAINER_URL": "https://sdsstate.blob.core.windows.net/scanner",
        "FINDINGS_FILE": str(out),
        "FINDINGS_HTTPS_URL": INGEST,
        "FINDINGS_HMAC_KEY": KEY,
        "IAM_GRANTS": "none",
    }.items():
        monkeypatch.setenv(k, v)
    t = tab.tenant()
    assert entry.main(["scan"], clients=t.clients()) == 0
    doc = json.loads(out.read_text())
    valid(doc)
    src = doc["settingsSource"]
    assert src["AZURE_READ_COLD_TIER"] == {"value": "true", "source": "mermera"}
    assert src["KEYVAULT_SECRETS_READ"]["gate"] == "iam"
    assert src["KEYVAULT_SECRETS_READ"]["parameter"] == "readKeyVaultSecrets"
    assert doc["configPull"]["status"] == "ok"
    # The pull was signed for this site, on the ingest host's tenant path.
    assert m.requests[0].full_url.startswith(
        f"https://ingest.dev.example/v1/tenants/{TENANT}/sites/{SITE}/config?"
    )
