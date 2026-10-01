"""Findings retention (#119): the results store keeps per-run files for FindingsRetentionDays
(default 90; 0 keeps them forever) and never expires the current files or the state.

Every key each runner writes is checked against each template's rule, so a change of key
layout that would put a current file under the expiring prefix fails here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

from cfn_templates import load_path
from sensitive_data_azure import state as azure_state
from sensitive_data_core.report import FINDINGS_CSV, REPORT_HTML
from sensitive_data_core.runner_config import REGISTRY
from sensitive_data_gcp import state as gcp_state
from sensitive_data_scanner.runner import Keys
from test_azure_template import load as load_azure
from test_azure_template import resources as azure_resources

REPO = Path(__file__).resolve().parents[2]
SCANNER = load_path(REPO / "deploy" / "scanner.yaml")
ESTATE = load_path(REPO / "deploy" / "estate-stackset.yaml")
PREFIX = "findings/runs/"


def aws_rule() -> dict[str, Any]:
    rules = SCANNER["Resources"]["ResultsBucket"]["Properties"]["LifecycleConfiguration"]["Rules"]
    cond = [r for r in rules if isinstance(r, dict) and "Fn::If" in r]
    assert len(cond) == 1
    name, rule, otherwise = cond[0]["Fn::If"]
    assert name == "ExpireFindings"
    assert otherwise == {"Ref": "AWS::NoValue"}
    out: dict[str, Any] = rule
    return out


def aws_current_keys() -> list[str]:
    k = Keys("")
    return [k.latest, f"{k.report}{REPORT_HTML}", f"{k.report}{FINDINGS_CSV}", k.state, k.lock]


# ------------------------------------------------------------------ AWS


def test_aws_parameter_defaults_to_90_and_0_means_forever() -> None:
    p = SCANNER["Parameters"]["FindingsRetentionDays"]
    assert (p["Type"], p["Default"], p["MinValue"]) == ("Number", 90, 0)
    assert "RunHistoryDays" not in SCANNER["Parameters"]
    assert SCANNER["Conditions"]["ExpireFindings"] == {
        "Fn::Not": [{"Fn::Equals": [{"Ref": "FindingsRetentionDays"}, 0]}]
    }


def test_aws_rule_expires_only_per_run_files_and_their_versions() -> None:
    rule = aws_rule()
    assert rule["Status"] == "Enabled"
    assert rule["Prefix"] == PREFIX
    assert "Filter" not in rule  # a prefix, nothing broader
    assert rule["ExpirationInDays"] == {"Ref": "FindingsRetentionDays"}
    assert rule["NoncurrentVersionExpiration"] == {
        "NoncurrentDays": {"Ref": "FindingsRetentionDays"}
    }


def test_aws_rule_never_matches_the_current_files_or_the_state() -> None:
    prefix = aws_rule()["Prefix"]
    keys = Keys("")
    for key in aws_current_keys():
        assert not key.startswith(prefix), key
    assert not f"{keys.index}some-index".startswith(prefix)
    assert f"{keys.runs}20260929T060000Z-1a2b3c4d.json".startswith(prefix)
    # No other lifecycle rule reaches findings/ or state/.
    rules = SCANNER["Resources"]["ResultsBucket"]["Properties"]["LifecycleConfiguration"]["Rules"]
    for r in rules:
        if isinstance(r, dict) and "Prefix" in r:
            assert not r["Prefix"].startswith(("findings", "state")), r


def test_the_stackset_passes_the_retention_with_the_same_default() -> None:
    p = ESTATE["Parameters"]["FindingsRetentionDays"]
    assert p["Default"] == "90"
    assert re.fullmatch(p["AllowedPattern"], "0") and not re.fullmatch(p["AllowedPattern"], "-1")
    passed = {
        x["ParameterKey"]: x["ParameterValue"]
        for x in ESTATE["Resources"]["ScannerStackSet"]["Properties"]["Parameters"]
    }
    assert passed["FindingsRetentionDays"] == {"Ref": "FindingsRetentionDays"}


def test_retention_is_template_only_never_a_mermera_setting() -> None:
    names = {s.name for settings in REGISTRY.values() for s in settings}
    params = {s.parameter for settings in REGISTRY.values() for s in settings}
    assert not {n for n in names if "RETENTION" in n}
    assert (
        not {"FindingsRetentionDays", "findingsRetentionDays", "findings_retention_days"} & params
    )
    env = SCANNER["Resources"]["Function"]["Properties"]["Environment"]["Variables"]
    assert "FindingsRetentionDays" not in str(env)


# ------------------------------------------------------------------ Azure


def azure_policies() -> list[dict[str, Any]]:
    return [
        r
        for _, r in azure_resources(load_azure())
        if r.get("type") == "Microsoft.Storage/storageAccounts/managementPolicies"
    ]


def test_azure_policy_expires_only_per_run_blobs_with_the_same_default() -> None:
    bicep = (REPO / "deploy" / "azure" / "main.bicep").read_text()
    assert "param findingsRetentionDays int = 90" in bicep
    job = (REPO / "deploy" / "azure" / "modules" / "job.bicep").read_text()
    assert "param findingsRetentionDays int = 90" in job
    assert "@minValue(0)\n@maxValue(36500)\nparam findingsRetentionDays" in job
    policies = azure_policies()
    assert policies, "the compiled template holds the lifecycle policy"
    for p in policies:
        assert p["condition"] == "[greater(parameters('findingsRetentionDays'), 0)]"
        (rule,) = p["properties"]["policy"]["rules"]
        d = rule["definition"]
        assert d["filters"]["prefixMatch"] == [
            "[format('{0}/findings/runs/', variables('stateContainerName'))]"
        ]
        assert set(d["actions"]) == {"baseBlob", "version"}
        days = "[parameters('findingsRetentionDays')]"
        assert d["actions"]["baseBlob"]["delete"] == {"daysAfterModificationGreaterThan": days}
        assert d["actions"]["version"]["delete"] == {"daysAfterCreationGreaterThan": days}


def test_azure_rule_never_matches_the_current_files() -> None:
    assert azure_state.RUNS == PREFIX
    for key in (azure_state.LATEST, f"findings/{REPORT_HTML}", f"findings/{FINDINGS_CSV}"):
        assert not key.startswith(azure_state.RUNS), key
    for name in dir(azure_state):
        value = getattr(azure_state, name)
        if name.isupper() and isinstance(value, str) and "/" in value and name != "RUNS":
            assert not value.startswith(PREFIX), name


# ------------------------------------------------------------------ Google Cloud


def gcp_bucket() -> dict[str, Any]:
    with (REPO / "deploy" / "gcp" / "main.tf").open() as f:
        tf = hcl2.load(f)
    for block in tf["resource"]:
        kinds = {k.strip('"'): v for k, v in block.items()}
        names = {k.strip('"'): v for k, v in (kinds.get("google_storage_bucket") or {}).items()}
        if "state" in names:
            out: dict[str, Any] = names["state"]
            return out
    raise AssertionError("no state bucket")


def test_gcp_rule_expires_only_per_run_objects_with_the_same_default() -> None:
    with (REPO / "deploy" / "gcp" / "variables.tf").open() as f:
        variables = {k.strip('"'): v for d in hcl2.load(f)["variable"] for k, v in d.items()}
    assert variables["findings_retention_days"]["default"] == 90
    assert "runs_retention_days" not in variables
    text = (REPO / "deploy" / "gcp" / "main.tf").read_text()
    assert "for_each = var.findings_retention_days > 0 ? [var.findings_retention_days] : []" in text
    assert 'matches_prefix = ["findings/runs/"]' in text
    assert 'with_state     = "ANY"' in text
    assert "dynamic" in str(gcp_bucket())  # no rule at all with 0 (terraform test proves it)


def test_gcp_rule_never_matches_the_current_files() -> None:
    assert gcp_state.RUNS == PREFIX
    for key in (gcp_state.LATEST, f"findings/{REPORT_HTML}", f"findings/{FINDINGS_CSV}"):
        assert not key.startswith(gcp_state.RUNS), key
    for name in dir(gcp_state):
        value = getattr(gcp_state, name)
        if name.isupper() and isinstance(value, str) and "/" in value and name != "RUNS":
            assert not value.startswith(PREFIX), name
