"""IAM's size limits, for every role in every CloudFormation template, in the worst case.

IAM refused deploy/scanner.yaml at fb9097a: its role's inline policies came to about
14,700 characters against the 10,240 a role may hold in all (ServiceLimitExceeded,
"Maximum policy size of 10240 bytes exceeded"). The Denies and the opt-in Allows are
managed policies since. These tests hold every role to IAM's limits with every opt-in
parameter on (a statement under a condition counts when the condition is true), and
hold the scanner's role to exactly the permissions it had before the move.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cfn_templates import (
    INLINE_TOTAL,
    MANAGED_EACH,
    MANAGED_PER_ROLE,
    Resolver,
    load_path,
    normalized,
    role_documents,
    role_sizes,
    statements_with_gates,
)
from conftest import REPO

DEPLOY = REPO / "deploy"
TEMPLATES = ["scanner.yaml", "estate-stackset.yaml", "saas/ecs.yaml", "artifacts/artifacts.yaml"]
SNAPSHOT = Path(__file__).parent / "fixtures" / "scanner_role_statements.json"

P, R, A = Resolver.PARTITION, Resolver.REGION, Resolver.ACCOUNT
KEY = f"arn:{P}:kms:{R}:{A}:key/{'0' * 36}"
# A list parameter of ARNs is as long as the customer makes it: three of each, at
# realistic maximum lengths, is the case sized here (docs/ARCHITECTURE.md, Policy sizes).
SECRETS = ",".join(f"arn:{P}:secretsmanager:{R}:{A}:secret:{'s' * 64}-AbCdEf" for _ in range(3))
CLUSTERS = ",".join(f"arn:{P}:rds:{R}:{A}:cluster:{'c' * 63}" for _ in range(3))

# scanner.yaml with every opt-in on. RedshiftRead's iam and db-user exclude each other.
ALL_ON: dict[str, Any] = {
    "ConfigLocation": "ssm:/sensitive-data-scanner/config",
    "AllowKmsDecrypt": "true",
    # #105: an allow-list of keys puts three key ARNs in every kms:Decrypt statement.
    "KmsAllowedKeyArns": ",".join([KEY] * 3),
    "VpcSubnetIds": "subnet-0123456789abcdef0,subnet-0123456789abcdef1",
    "VpcSecurityGroupIds": "sg-0123456789abcdef0",
    "RdsExportKmsKeyArn": KEY,
    "EnableDynamoDBExport": "true",
    "DynamoDBExportKmsKeyArn": KEY,
    "DataApiTargets": "[...]",
    "DataApiClusterArns": CLUSTERS,
    "DataApiSecretArns": SECRETS,
    "RedshiftDbUser": "u" * 127,
    "OpenSearchServerlessRead": "true",
    "EbsDirectRead": "true",
    "SqsDlqRead": "true",
    "SsmDecrypt": "true",
    "SecretsRead": "true",
    "MskRead": "true",
    "MqRead": "true",
    "MqSecretArns": SECRETS,
    "EcrRead": "true",
    "SageMakerRead": "true",
    "NeptuneAnalyticsExportKmsKeyArn": KEY,
    "EventBridgeReplay": "true",
    "ScanMode": "both",
    "FindingsEventBusArn": f"arn:{P}:events:{R}:{A}:event-bus/{'e' * 256}",
}
ALL_OFF: dict[str, Any] = {
    "AllowKmsDecrypt": "false",
    "SsmDecrypt": "false",
    "TimestreamRead": "false",
    "KeyspacesRead": "false",
}
SCENARIOS: dict[str, dict[str, dict[str, Any]]] = {
    "scanner.yaml": {
        "all opt-ins, Redshift iam": {**ALL_ON, "RedshiftRead": "iam"},
        "all opt-ins, Redshift db-user": {**ALL_ON, "RedshiftRead": "db-user"},
        "defaults": {},
        "every opt-in off": ALL_OFF,
    },
    "estate-stackset.yaml": {"defaults": {}},
    # Release hosting (#108): the release role exists in the home region only, so the
    # resolver's region is made the home region.
    "artifacts/artifacts.yaml": {"home region": {"HomeRegion": R}},
    "saas/ecs.yaml": {
        "defaults": {
            "PushKeySecretArn": SECRETS.split(",")[0],
            "StateBucket": "b" * 63,
        }
    },
}


def roles(template: dict[str, Any]) -> list[str]:
    return [n for n, r in template["Resources"].items() if r["Type"] == "AWS::IAM::Role"]


CASES = [
    pytest.param(name, scenario, role, id=f"{name}:{role}:{scenario}")
    for name in TEMPLATES
    for scenario in SCENARIOS[name]
    for role in roles(load_path(DEPLOY / name))
]


def test_every_cloudformation_template_is_covered() -> None:
    found = sorted(
        str(p.relative_to(DEPLOY))
        for p in DEPLOY.rglob("*.yaml")
        if "AWSTemplateFormatVersion" in p.read_text()
    )
    assert found == sorted(TEMPLATES)
    # The StackSet holds no role of its own: it deploys scanner.yaml, sized above.
    assert roles(load_path(DEPLOY / "estate-stackset.yaml")) == []


@pytest.mark.parametrize(("name", "scenario", "role"), CASES)
def test_every_role_fits_iams_limits(name: str, scenario: str, role: str) -> None:
    sizes = role_sizes(load_path(DEPLOY / name), role, SCENARIOS[name][scenario])
    assert sizes["inline"] <= INLINE_TOTAL, f"{role}: inline policies {sizes['inline']}"
    for policy, size in sizes["managed"].items():
        assert size <= MANAGED_EACH, f"{role}: {policy} is {size}"
    assert sizes["count"] <= MANAGED_PER_ROLE, f"{role}: {sizes['count']} managed policies"


@pytest.mark.parametrize("scenario", list(SCENARIOS["scanner.yaml"]))
def test_every_attached_policy_has_a_statement(scenario: str) -> None:
    """IAM refuses a policy with no statement: each managed policy attached to the role
    keeps at least one whatever the opt-ins are."""
    t = load_path(DEPLOY / "scanner.yaml")
    r = Resolver(t, SCENARIOS["scanner.yaml"][scenario])
    docs = role_documents(t, "ScannerRole")
    for label, doc in docs["inline"] + docs["managed"]:
        resolved = r.resolve(doc)
        if resolved is not None:
            assert resolved["Statement"], label


def test_the_worst_case_is_the_all_on_case() -> None:
    """Sanity: turning the opt-ins on grows the role (so the limits above bind)."""
    t = load_path(DEPLOY / "scanner.yaml")
    on = role_sizes(t, "ScannerRole", SCENARIOS["scanner.yaml"]["all opt-ins, Redshift db-user"])
    off = role_sizes(t, "ScannerRole", ALL_OFF)
    assert sum(on["managed"].values()) > sum(off["managed"].values())
    assert on["count"] == 9 and off["count"] == 4


def test_the_scanner_role_keeps_exactly_its_permissions() -> None:
    """Every statement the role can hold, with the conditions it comes under, is exactly
    what it held at fb9097a (the reviewed snapshot), whichever policy now carries it."""
    t = load_path(DEPLOY / "scanner.yaml")
    got = sorted(normalized(g, s) for g, s in statements_with_gates(t, "ScannerRole"))
    want = sorted(
        json.dumps(s, sort_keys=True) for s in json.loads(SNAPSHOT.read_text())["statements"]
    )
    assert got == want
    props = t["Resources"]["ScannerRole"]["Properties"]
    assert "PermissionsBoundary" not in props
    # No AWS managed policy (their statements are not in the template to compare).
    assert not [label for label, doc in role_documents(t, "ScannerRole")["managed"] if doc is None]


def _plain(doc: Any) -> Any:
    """A policy document without its resource's Condition around it."""
    return doc["Fn::If"][1] if isinstance(doc, dict) and "Fn::If" in doc else doc


def test_the_denies_are_managed_and_the_function_waits_for_them() -> None:
    t = load_path(DEPLOY / "scanner.yaml")
    res = t["Resources"]
    docs = role_documents(t, "ScannerRole")
    inline = [s for _, d in docs["inline"] for s in d["Statement"]]
    assert all(s["Effect"] == "Allow" for s in inline if isinstance(s, dict) and "Effect" in s)
    by_sid = {
        s["Sid"]: name for name, d in docs["managed"] for s in _plain(d)["Statement"] if "Sid" in s
    }
    assert by_sid["NoDataStoreWrites"] == "DataStoreWriteDenyPolicy"
    alone = res["DataStoreWriteDenyPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    assert [s["Sid"] for s in alone] == ["NoDataStoreWrites"]
    # Attached by the role itself, so the role never exists without its Denies; and every
    # policy the role always holds is also a named dependency of the function.
    attached = res["ScannerRole"]["Properties"]["ManagedPolicyArns"]
    always = [x["Ref"] for x in attached if "Ref" in x]
    assert {"DataStoreWriteDenyPolicy", "GuardDenyPolicy"} <= set(always)
    assert set(always) <= set(res["Function"]["DependsOn"])
    for name, r in res.items():
        if r["Type"] == "AWS::IAM::ManagedPolicy":
            assert "Roles" not in r["Properties"], f"{name}: attach it through ManagedPolicyArns"
        if r["Type"] == "AWS::Lambda::Function":
            assert r["Properties"]["Role"] == {"Fn::GetAtt": ["ScannerRole", "Arn"]}


# ------------------------------------------------------------------ the template's own size

TEMPLATE_BODY_LIMIT = 51_200  # --template-body; larger templates go through S3
TEMPLATE_URL_LIMIT = 1_048_576  # --template-url / TemplateURL


def test_the_template_fits_cloudformation_and_its_upload_is_documented() -> None:
    size = len((DEPLOY / "scanner.yaml").read_bytes())
    assert size <= TEMPLATE_URL_LIMIT
    if size > TEMPLATE_BODY_LIMIT:
        # Too large to pass inline: the docs say to deploy it from S3.
        doc = (REPO / "docs" / "ARCHITECTURE.md").read_text()
        assert "51,200" in doc and "--s3-bucket" in doc and "--template-url" in doc
