"""The estate rollout templates (deploy/): least privilege, read-only, and in step with the code.

cfn-lint checks the templates' syntax and resource properties in CI. These
tests check what cfn-lint cannot: that every action the scanner's role is
allowed is a read, except writes aimed at its own bucket, log group, bus and
exports; that every AWS call the code makes is allowed; that every
environment variable the template sets is one the code reads; and that
nothing can escalate through Lake Formation.
"""

from __future__ import annotations

import ast
import re
from typing import Any

import botocore.session
import pytest
import yaml

from conftest import REPO

DEPLOY = REPO / "deploy"
PACKAGE = REPO / "scanner" / "src" / "sensitive_data_scanner"


class CfnLoader(yaml.SafeLoader):
    """YAML with CloudFormation's short-form tags, as {"Fn::X": value}."""


def _tag(loader: CfnLoader, suffix: str, node: yaml.Node) -> Any:
    name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    if suffix == "GetAtt" and isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node).split(".", 1)}
    if isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {name: loader.construct_sequence(node, deep=True)}
    assert isinstance(node, yaml.MappingNode)
    return {name: loader.construct_mapping(node, deep=True)}


CfnLoader.add_multi_constructor("!", _tag)


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load((DEPLOY / name).read_text(), Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass
    return data


SCANNER = load("scanner.yaml")
ESTATE = load("estate-stackset.yaml")
RES = SCANNER["Resources"]


def statements() -> list[dict[str, Any]]:
    """Every statement the scanner's role can hold, with the condition it comes under."""
    out: list[dict[str, Any]] = []

    def add(stmts: list[Any]) -> None:
        for raw in stmts:
            s = raw["Fn::If"][1] if isinstance(raw, dict) and "Fn::If" in raw else raw
            if isinstance(s, dict) and "Effect" in s:
                out.append(s)

    for p in RES["ScannerRole"]["Properties"]["Policies"]:
        add(p["PolicyDocument"]["Statement"])
    for name in ("RdsExportPolicy", "DynamoDBExportPolicy", "DataApiPolicy", "RedshiftReadPolicy"):
        assert RES[name]["Properties"]["RoleName"] == {"Ref": "ScannerRole"}
        add(RES[name]["Properties"]["PolicyDocument"]["Statement"])
    return out


def actions(s: dict[str, Any]) -> list[str]:
    a = s["Action"]
    return [a] if isinstance(a, str) else list(a)


ALLOWED = [a for s in statements() if s["Effect"] == "Allow" for a in actions(s)]
READ = re.compile(
    r"^(s3:(List|Get)|logs:(Describe|FilterLogEvents|ListTags)|dynamodb:(List|Describe|Scan|Query)"
    r"|glue:Get|rds:Describe|kms:Decrypt$|kms:DescribeKey$|secretsmanager:GetSecretValue$"
    r"|redshift:DescribeClusters$|redshift-serverless:List"
    r"|redshift-data:(DescribeStatement|GetStatementResult|ListDatabases)$"
    r"|es:(ListDomainNames|DescribeDomains|ListTags|ESHttpGet)$|aoss:(List|BatchGet)"
    r"|ec2:Describe(Volumes|Snapshots)$|ebs:(ListSnapshotBlocks|GetSnapshotBlock)$|backup:List"
    r"|elasticfilesystem:Describe|fsx:Describe|docdb-elastic:List)"
)
IN_ACCOUNT = "${AWS::Partition}:{service}:${AWS::Region}:${AWS::AccountId}:"


def in_account(resource: Any, service: str, *kinds: str) -> bool:
    """Every resource is in this account and region, and one of these resource types."""
    items = resource if isinstance(resource, list) else [resource]
    head = "arn:" + IN_ACCOUNT.replace("{service}", service)
    return all(
        isinstance(r, dict)
        and str(r.get("Fn::Sub", "")).startswith(head)
        and str(r["Fn::Sub"])[len(head) :].startswith(kinds)
        for r in items
    )


OWN_BUCKET = [{"Fn::Sub": "${ResultsBucket.Arn}/*"}, {"Fn::GetAtt": ["ResultsBucket", "Arn"]}]


def _redshift_sql(s: dict[str, Any], a: str) -> bool:
    # The Data API runs SQL; the scanner's statements are sampled SELECTs, and the
    # database user's grants make them read-only (docs/ARCHITECTURE.md).
    return a == "redshift-data:ExecuteStatement" and all(
        in_account(r, "redshift", "cluster:") or in_account(r, "redshift-serverless", "workgroup/")
        for r in s["Resource"]
    )


def _db_user_credentials(s: dict[str, Any], a: str) -> bool:
    user, dbname = s["Resource"]
    return (
        in_account(user, "redshift", "dbuser:")
        and str(user["Fn::Sub"]).endswith(":dbuser:*/${RedshiftDbUser}")
        and in_account(dbname, "redshift", "dbname:")
    )


# Writes, or credential vending, that are aimed: checked by Sid, lazily.
AIMED: dict[str, Any] = {
    "ReadOnlySqlOnRedshift": _redshift_sql,
    "ServerlessIamCredentials": lambda s, a: in_account(
        s["Resource"], "redshift-serverless", "workgroup/"
    ),
    "ClusterIamCredentials": lambda s, a: in_account(s["Resource"], "redshift", "dbname:"),
    "ClusterDbUserCredentials": _db_user_credentials,
    # Data-plane access to collections; each collection's data access policy grants
    # the role aoss:ReadDocument only (docs/ARCHITECTURE.md).
    "ReadServerlessCollections": lambda s, a: (
        a == "aoss:APIAccessAll" and in_account(s["Resource"], "aoss", "collection/")
    ),
}


def test_every_allow_is_a_read_or_an_aimed_write() -> None:
    for s in statements():
        if s["Effect"] != "Allow":
            continue
        for a in actions(s):
            if READ.match(a):
                continue
            sid = s.get("Sid")
            aimed = {
                "OwnResultsBucket": s["Resource"] in OWN_BUCKET,
                "OwnLogs": s["Resource"] == {"Fn::Sub": "${LogGroup.Arn}"},
                "PushFindings": s["Resource"] == {"Ref": "FindingsEventBusArn"},
                "StartExports": all("snapshot:" in str(r) for r in s["Resource"]),
                "PassTheExportRoleOnly": s["Resource"] == {"Fn::GetAtt": ["RdsExportRole", "Arn"]}
                and s["Condition"]["StringEquals"]["iam:PassedToService"]
                == "export.rds.amazonaws.com",
                "GrantOnTheExportKeyOnlyThroughRds": s["Resource"] == {"Ref": "RdsExportKmsKeyArn"}
                and "rds." in str(s["Condition"]["StringEquals"]["kms:ViaService"])
                and s["Condition"]["Bool"]["kms:GrantIsForAWSResource"] == "true",
                "ExportLargeTables": a
                in ("dynamodb:ExportTableToPointInTime", "dynamodb:DescribeContinuousBackups"),
                "EncryptExportsThroughS3": s["Resource"] == {"Ref": "DynamoDBExportKmsKeyArn"},
                "ReadOnlySqlOnNamedClusters": "DataApiClusterArns" in str(s["Resource"]),
            }.get(str(sid), False) or AIMED.get(str(sid), lambda s, a: False)(s, a)
            assert aimed, f"{sid}: {a} is a write not aimed at the scanner's own resources"


def test_kms_is_used_only_through_a_service() -> None:
    for s in statements():
        if s["Effect"] == "Allow" and any(a.startswith("kms:") for a in actions(s)):
            assert "kms:ViaService" in s["Condition"]["StringEquals"], s.get("Sid")


def test_denies_keep_writes_home_and_lake_formation_out() -> None:
    denies = {s["Sid"]: s for s in statements() if s["Effect"] == "Deny"}
    home = denies["NoWritesOutsideOwnBucket"]
    assert {"s3:PutObject", "s3:DeleteObject"} <= set(actions(home))
    assert home["NotResource"] == [
        {"Fn::GetAtt": ["ResultsBucket", "Arn"]},
        {"Fn::Sub": "${ResultsBucket.Arn}/*"},
    ]
    assert actions(denies["NeverAskLakeFormation"]) == ["lakeformation:*"]
    assert "dynamodb:PutItem" in actions(denies["NoDataStoreWrites"])
    # Nothing allowed is also denied (a Deny would silently break a source).
    denied = [a for s in denies.values() if "Resource" in s for a in actions(s)]
    for a in ALLOWED:
        assert not any(re.fullmatch(d.replace("*", ".*"), a) for d in denied), a


def test_the_export_role_writes_only_the_exports_prefix() -> None:
    role = RES["RdsExportRole"]["Properties"]
    assert role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
        "Service": "export.rds.amazonaws.com"
    }
    stmts = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert stmts[0]["Resource"] == {"Fn::Sub": "${ResultsBucket.Arn}/exports/rds/*"}


def test_no_named_iam_resources_so_regions_do_not_collide() -> None:
    for name, r in RES.items():
        if r["Type"] in ("AWS::IAM::Role", "AWS::IAM::ManagedPolicy"):
            assert "RoleName" not in r["Properties"], name
            assert "ManagedPolicyName" not in r["Properties"], name
    assert "${AWS::Region}" in RES["ResultsBucket"]["Properties"]["BucketName"]["Fn::Sub"]


# ------------------------------------------------------------------ in step with the code

S3_ACTIONS = {
    "ListObjectsV2": "s3:ListBucket",
    "ListBuckets": "s3:ListAllMyBuckets",
    "HeadObject": "s3:GetObject",
    "DeleteObjects": "s3:DeleteObject",
}
SERVICES = {
    "s3": "s3",
    "logs": "logs",
    "dynamodb": "dynamodb",
    "glue": "glue",
    "rds": "rds",
    "rds-data": "rds-data",
    "events": "events",
    "redshift": "redshift",
    "redshift-serverless": "redshift-serverless",
    "redshift-data": "redshift-data",
    "opensearch": "es",
    "opensearchserverless": "aoss",
    "docdb": "rds",
    "neptune": "rds",
    "docdb-elastic": "docdb-elastic",
    "ec2": "ec2",
    "ebs": "ebs",
    "backup": "backup",
    "efs": "elasticfilesystem",
    "fsx": "fsx",
}


def operations() -> dict[str, list[str]]:
    """Snake-case operation name to the IAM actions it may be, across the services used."""
    session = botocore.session.get_session()
    out: dict[str, list[str]] = {}
    for service, prefix in SERVICES.items():
        model = session.get_service_model(service)
        for op in model.operation_names:
            snake = botocore.xform_name(op)
            action = S3_ACTIONS.get(op, f"{prefix}:{op}") if service == "s3" else f"{prefix}:{op}"
            out.setdefault(snake, []).append(action)
    return out


def _is_session(node: ast.expr) -> bool:
    """`boto3.Session()`: calls on it are the SDK's (credentials), not AWS operations."""
    return isinstance(node, ast.Call) and ast.unparse(node.func) == "boto3.Session"


def calls() -> set[str]:
    """Every AWS operation the package calls: `x.op(...)` and `get_paginator("op")`."""
    ops = operations()
    found: set[str] = set()
    for path in PACKAGE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Attribute) and _is_session(f.value):
                continue
            if isinstance(f, ast.Attribute) and f.attr == "get_paginator" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
            elif isinstance(f, ast.Attribute) and f.attr in ops:
                found.add(f.attr)
    # The DynamoDB source calls through self._call(op, ...).
    found.update({"describe_table", "query", "scan"})
    return {c for c in found if c in ops}


def test_every_aws_call_the_code_makes_is_allowed() -> None:
    ops = operations()
    granted = set(ALLOWED) | {"logs:CreateLogStream", "logs:PutLogEvents"}
    missing = []
    for call in sorted(calls()):
        if call in ("put_object", "get_object", "delete_object", "delete_objects", "head_object"):
            continue  # S3, checked by resource below
        if not any(a in granted for a in ops[call]):
            missing.append(f"{call} -> {ops[call]}")
    assert missing == []
    assert {"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:PutObject"} <= granted


def test_each_adapter_calls_only_its_own_services() -> None:
    """An adapter module names the services it calls (AWS_SERVICES); each call it makes is an
    operation of one of them, and allowed for that service's own IAM prefix."""
    session = botocore.session.get_session()
    granted = set(ALLOWED)
    checked = 0
    for path in sorted((PACKAGE / "sources").glob("*.py")):
        tree = ast.parse(path.read_text())
        names = [
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "AWS_SERVICES" for t in n.targets)
        ]
        if not names:
            continue
        services = ast.literal_eval(names[0])
        own: dict[str, list[str]] = {}
        for service in services:
            model = session.get_service_model(service)
            for op in model.operation_names:
                own.setdefault(botocore.xform_name(op), []).append(f"{SERVICES[service]}:{op}")
        every = operations()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            f = node.func
            op = f.attr
            if _is_session(f.value):
                continue  # boto3.Session().get_credentials(): the SDK's own, not an API call
            if op == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                op = str(node.args[0].value)
            if op not in every or op in ("client", "get"):
                continue
            assert op in own, f"{path.name}: {op} is not an operation of {services}"
            assert any(a in granted for a in own[op]), f"{path.name}: {op} -> {own[op]}"
            checked += 1
    assert checked >= 8


def test_redshift_reads_cannot_create_users_or_run_batches() -> None:
    denied = {a for s in statements() if s["Effect"] == "Deny" for a in actions(s)}
    # GetClusterCredentials with AutoCreate needs CreateClusterUser; DbGroups needs JoinGroup.
    assert {"redshift:CreateClusterUser", "redshift:JoinGroup"} <= denied
    assert "redshift-data:BatchExecuteStatement" in denied
    own = next(s for s in statements() if s.get("Sid") == "OwnStatementsOnly")
    assert own["Condition"]["StringEquals"] == {
        "redshift-data:statement-owner-iam-userid": "${aws:userid}"
    }
    assert RES["RedshiftReadPolicy"]["Condition"] == "RedshiftReads"


def test_opensearch_is_read_with_get_only() -> None:
    domains = next(s for s in statements() if s.get("Sid") == "ReadOpenSearchDomains")
    assert actions(domains) == ["es:ESHttpGet"]
    assert in_account(domains["Resource"], "es", "domain/")
    denied = {a for s in statements() if s["Effect"] == "Deny" for a in actions(s)}
    assert {"es:ESHttpPost", "es:ESHttpPut", "es:ESHttpPatch", "es:ESHttpDelete"} <= denied
    serverless = RES["ScannerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    gated = [s for s in serverless if isinstance(s, dict) and "Fn::If" in s]
    assert any(s["Fn::If"][0] == "OpenSearchServerless" for s in gated)


def test_snapshots_are_read_in_place_never_copied_or_attached() -> None:
    blocks = next(s for s in statements() if s.get("Sid") == "ReadEbsSnapshotBlocks")
    assert actions(blocks) == ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock"]
    assert blocks["Resource"] == {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}::snapshot/*"}
    denied = {a for s in statements() if s["Effect"] == "Deny" for a in actions(s)}
    assert {
        "ebs:StartSnapshot",
        "ebs:PutSnapshotBlock",
        "ec2:CreateVolume",
        "ec2:AttachVolume",
        "ec2:CreateSnapshot*",
        "backup:Start*",
        "elasticfilesystem:ClientWrite",
    } <= denied


def test_every_environment_variable_is_one_the_code_reads() -> None:
    source = (PACKAGE / "config.py").read_text()
    known = set(re.findall(r'e\.get\("([A-Z0-9_]+)"', source))
    env = RES["Function"]["Properties"]["Environment"]["Variables"]
    assert set(env) <= known, set(env) - known
    assert {"RESULTS_BUCKET", "DISCOVER", "FINDINGS_EVENT_BUS_ARN"} <= set(env)


def test_every_parameter_is_used() -> None:
    body = str(SCANNER["Resources"]) + str(SCANNER["Conditions"])
    for name in SCANNER["Parameters"]:
        assert f"'{name}'" in body or f"${{{name}}}" in body, name


@pytest.mark.parametrize("name", ["scanner.yaml", "estate-stackset.yaml"])
def test_templates_parse(name: str) -> None:
    assert load(name)["AWSTemplateFormatVersion"] == "2010-09-09"


def test_the_stackset_is_service_managed_for_an_ou_and_passes_real_parameters() -> None:
    ss = ESTATE["Resources"]["ScannerStackSet"]["Properties"]
    assert ss["PermissionModel"] == "SERVICE_MANAGED"
    assert ss["AutoDeployment"]["Enabled"] is True
    assert ss["Capabilities"] == ["CAPABILITY_IAM"]
    targets = ss["StackInstancesGroup"][0]
    assert targets["DeploymentTargets"]["OrganizationalUnitIds"] == {"Ref": "OrganizationalUnitIds"}
    assert targets["Regions"] == {"Ref": "Regions"}
    passed = {p["ParameterKey"] for p in ss["Parameters"]}
    assert passed <= set(SCANNER["Parameters"])
    assert "FindingsEventBusArn" in passed


def test_docs_name_every_allowed_action() -> None:
    doc = (REPO / "docs" / "ARCHITECTURE.md").read_text()
    for a in sorted(set(ALLOWED)):
        assert a in doc, f"{a} is allowed in deploy/scanner.yaml but not documented"
