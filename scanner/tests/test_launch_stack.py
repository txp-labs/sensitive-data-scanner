"""The one-click quick start (#117): Launch Stack links, the template's release defaults, and
the release workflow that publishes scanner.yaml where the links point."""

from __future__ import annotations

import importlib.util
import json
import re
import urllib.parse
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from cfn_templates import load_path
from sensitive_data_scanner import __version__

REPO = Path(__file__).resolve().parents[2]
SCANNER = load_path(REPO / "deploy" / "scanner.yaml")
ESTATE = load_path(REPO / "deploy" / "estate-stackset.yaml")
RELEASE = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())


def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "launch_stack", REPO / "scripts" / "launch_stack.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LS = script()


def publish_env() -> dict[str, Any]:
    env: dict[str, Any] = RELEASE["jobs"]["aws-publish"]["env"]
    return env


def test_links_and_defaults_are_current_for_this_version() -> None:
    assert LS.version() == __version__
    assert LS.main(["--check"]) == 0


def test_check_fails_for_another_version(monkeypatch: Any) -> None:
    monkeypatch.setattr(LS, "version", lambda: "9.9.9")
    assert LS.main(["--check"]) == 1


def test_a_launch_link_is_a_quick_create_url_for_the_regions_own_template() -> None:
    url = LS.launch_url("eu-west-1", "1.2.3")
    base, _, fragment = url.partition("#")
    assert base == "https://console.aws.amazon.com/cloudformation/home?region=eu-west-1"
    path, _, query = fragment.partition("?")
    assert path == "/stacks/quickcreate"
    q = dict(urllib.parse.parse_qsl(query))
    assert q == {
        "templateURL": "https://txp-labs-sensitive-data-scanner-eu-west-1.s3.eu-west-1.amazonaws.com/releases/1.2.3/scanner.yaml",
        "stackName": "sensitive-data-scanner",
        "param_Discover": "all",
        "param_MaxBytesPerRun": "268435456",
    }
    # Every quick-create parameter is one the template takes, with a value it accepts.
    params = SCANNER["Parameters"]
    for name, value in LS.QUICK_START.items():
        assert name in params
        pattern = params[name].get("AllowedPattern")
        assert pattern is None or re.fullmatch(pattern, value)


def test_every_region_has_a_link_in_the_readme_and_the_quick_start() -> None:
    for doc in LS.DOCS:
        text = (REPO / doc).read_text()
        for region in LS.REGIONS:
            assert LS.launch_url(region, __version__) in text, (doc, region)


def test_regions_agree_with_the_release_workflow_and_the_template() -> None:
    regions = set(publish_env()["ARTIFACT_REGIONS"].split())
    assert set(LS.REGIONS) == regions
    assert set(SCANNER["Mappings"]["ReleaseSigning"]) == regions
    cond = SCANNER["Conditions"]["ReleaseRegion"]["Fn::Or"]
    assert {c["Fn::Equals"][1] for c in cond} == regions


def test_the_signing_table_is_the_one_the_release_signs_with_and_documents() -> None:
    pinned = json.loads(publish_env()["SIGNING_PROFILE_VERSIONS"])
    table = {r: v["ProfileVersionArn"] for r, v in SCANNER["Mappings"]["ReleaseSigning"].items()}
    assert table == pinned
    releasing = (REPO / "docs" / "RELEASING.md").read_text()
    for region, arn in table.items():
        assert f"| {region} | `{arn}` |" in releasing


def test_the_templates_default_to_this_release_and_its_signing() -> None:
    key = LS.zip_key(__version__)
    for t in (SCANNER, ESTATE):
        p = t["Parameters"]
        assert p["CodeS3BucketPrefix"]["Default"] == "txp-labs-sensitive-data-scanner"
        assert p["CodeS3Key"]["Default"] == key
        assert p["CodeSigningProfileVersionArn"]["Default"] == "release"
    pattern = SCANNER["Parameters"]["CodeSigningProfileVersionArn"]["AllowedPattern"]
    for ok in ("", "release", "arn:aws:signer:us-west-2:895544787721:/signing-profiles/X/Ab1"):
        assert re.fullmatch(pattern, ok)
    res = SCANNER["Resources"]
    assert res["ReleaseCodeSigningConfig"]["Condition"] == "SignedZipByRelease"
    publishers = res["ReleaseCodeSigningConfig"]["Properties"]["AllowedPublishers"]
    assert publishers["SigningProfileVersionArns"] == [
        {"Fn::FindInMap": ["ReleaseSigning", {"Ref": "AWS::Region"}, "ProfileVersionArn"]}
    ]
    assert res["ReleaseCodeSigningConfig"]["Properties"]["CodeSigningPolicies"] == {
        "UntrustedArtifactOnDeployment": "Enforce"
    }
    # The table is read only where it has the region; release and an ARN never both apply.
    conds = SCANNER["Conditions"]
    assert {"Fn::Condition": "ReleaseRegion"} in conds["SignedZipByRelease"]["Fn::And"]
    assert {
        "Fn::Not": [{"Fn::Equals": [{"Ref": "CodeSigningProfileVersionArn"}, "release"]}]
    } in conds["SignedZip"]["Fn::And"]


def test_the_report_settings_reach_the_function() -> None:
    env = SCANNER["Resources"]["Function"]["Properties"]["Environment"]["Variables"]
    assert env["REPORT_CTA"] == {"Ref": "ReportCta"}
    assert env["MAX_BYTES_PER_RUN"] == {"Ref": "MaxBytesPerRun"}
    # Empty: the scanner decides (on, unless connected to Mermera); true and false override.
    assert SCANNER["Parameters"]["ReportCta"]["Default"] == ""
    assert SCANNER["Parameters"]["ReportCta"]["AllowedValues"] == ["", "true", "false"]
    assert SCANNER["Parameters"]["MaxBytesPerRun"]["Default"] == ""
    assert "findings/report.html" in str(SCANNER["Outputs"]["Report"]["Value"])


def test_the_release_publishes_the_template_write_once_and_reads_it_back() -> None:
    steps = RELEASE["jobs"]["aws-publish"]["steps"]
    step = next(s for s in steps if "scanner.yaml" in s.get("name", ""))
    run = step["run"]
    assert step["if"] == "steps.gate.outputs.enabled == 'true'"
    assert "--if-none-match '*'" in run
    assert 'key="releases/${VERSION}/scanner.yaml"' in run
    assert "curl -fsS" in run  # the anonymous read-back
    assert "for region in ${ARTIFACT_REGIONS}" in run
    # It publishes the tag's own template, which must name the tag's zip.
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "refs/tags/${{ inputs.tag || github.ref_name }}"
    assert checkout["with"]["persist-credentials"] is False
    assert "releases/${VERSION}/sensitive-data-scanner-${VERSION}-lambda" in run


def test_every_action_is_pinned_to_a_commit() -> None:
    text = (REPO / ".github" / "workflows" / "release.yml").read_text()
    for uses in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", uses), uses
