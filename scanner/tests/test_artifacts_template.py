"""Release hosting in txp-labs-artifacts (deploy/artifacts/, #108).

cfn-lint checks the template's syntax. These tests hold what the issue requires
of it: the public grant is s3:GetObject on releases/* and nothing else, the
release role trusts only this repository's release.yml at a v* tag, its writes
are aimed, and every place that lists the approved regions lists the same seven.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

import yaml

from cfn_templates import load_path
from conftest import REPO

ARTIFACTS = load_path(REPO / "deploy" / "artifacts" / "artifacts.yaml")
RES = ARTIFACTS["Resources"]
REGIONS = {
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-2",
}


def actions(s: dict[str, Any]) -> list[str]:
    a = s["Action"]
    return [a] if isinstance(a, str) else list(a)


def bucket_statements(name: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = RES[name]["Properties"]["PolicyDocument"]["Statement"]
    return statements


def test_the_only_public_allow_is_get_object_on_releases() -> None:
    public = [
        s
        for name in ("ReleaseBucketPolicy", "AccessLogBucketPolicy")
        for s in bucket_statements(name)
        if s["Effect"] == "Allow" and s["Principal"] == "*"
    ]
    assert len(public) == 1
    assert actions(public[0]) == ["s3:GetObject"]
    assert public[0]["Resource"] == {"Fn::Sub": "${ReleaseBucket.Arn}/releases/*"}
    assert "Condition" not in public[0]


def test_buckets_are_tls_only_versioned_logged_and_acl_free() -> None:
    for name in ("ReleaseBucketPolicy", "AccessLogBucketPolicy"):
        tls = [s for s in bucket_statements(name) if s.get("Sid") == "TlsOnly"]
        assert tls and tls[0]["Effect"] == "Deny"
        assert tls[0]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    release = RES["ReleaseBucket"]["Properties"]
    assert release["VersioningConfiguration"]["Status"] == "Enabled"
    assert release["LoggingConfiguration"]["DestinationBucketName"] == {"Ref": "AccessLogBucket"}
    assert release["OwnershipControls"]["Rules"][0]["ObjectOwnership"] == "BucketOwnerEnforced"
    # ACLs stay blocked; only the policy may be public.
    bpa = release["PublicAccessBlockConfiguration"]
    assert bpa == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    logs = RES["AccessLogBucket"]["Properties"]["PublicAccessBlockConfiguration"]
    assert all(logs.values())


def test_published_releases_are_write_once() -> None:
    deny = [
        s for s in bucket_statements("ReleaseBucketPolicy") if s.get("Sid") == "ReleasesWriteOnce"
    ]
    assert deny and deny[0]["Effect"] == "Deny"
    assert actions(deny[0]) == ["s3:PutObject"]
    assert deny[0]["Condition"] == {"Null": {"s3:if-none-match": "true"}}


def test_the_role_trusts_only_release_yml_at_a_v_tag() -> None:
    trust = RES["ReleaseRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert len(trust) == 1
    cond = trust[0]["Condition"]
    assert cond["StringEquals"]["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    assert cond["StringEquals"]["token.actions.githubusercontent.com:repository_id"] == {
        "Ref": "GitHubRepoId"
    }
    like = cond["StringLike"]
    sub = like["token.actions.githubusercontent.com:sub"]["Fn::Sub"]
    # ID-qualified, and a tag: never a branch, a pull request or an environment.
    assert (
        sub == "repo:${GitHubOwner}@${GitHubOwnerId}/${GitHubRepo}@${GitHubRepoId}:ref:refs/tags/v*"
    )
    assert like["token.actions.githubusercontent.com:ref"] == "refs/tags/v*"
    assert like["token.actions.githubusercontent.com:job_workflow_ref"] == {
        "Fn::Sub": "${GitHubOwner}/${GitHubRepo}/.github/workflows/release.yml@refs/tags/v*"
    }


def test_the_role_writes_only_where_a_release_goes() -> None:
    policy = RES["ReleaseRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    by_sid = {s["Sid"]: s for s in policy}
    for s in policy:
        assert s["Effect"] == "Allow"
        assert not any(a.endswith("*") for a in actions(s)), s["Sid"]
    publish = by_sid["PublishReleases"]
    assert actions(publish) == ["s3:PutObject"]
    resources = [r["Fn::Sub"] for r in publish["Resource"]]
    assert {
        re.sub(r"^arn:\$\{AWS::Partition\}:s3:::\$\{BucketPrefix\}-(.+)/releases/\*$", r"\1", r)
        for r in resources
    } == REGIONS
    assert by_sid["SigningWorkspace"]["Resource"] == {"Fn::Sub": "${ReleaseBucket.Arn}/signing/*"}
    assert "s3:DeleteObject" not in [a for s in policy for a in actions(s)]
    # Only GetAuthorizationToken (which takes no resource) is unscoped.
    assert [s["Sid"] for s in policy if s["Resource"] == "*"] == ["EcrLogin"]
    assert actions(by_sid["EcrLogin"]) == ["ecr:GetAuthorizationToken"]


def test_ecr_replicates_to_every_other_approved_region() -> None:
    rule = RES["ImageReplication"]["Properties"]["ReplicationConfiguration"]["Rules"][0]
    assert {d["Region"] for d in rule["Destinations"]} == REGIONS - {"us-west-2"}
    assert RES["ImageRepository"]["Properties"]["ImageTagMutability"] == "IMMUTABLE"


def test_every_list_of_regions_agrees() -> None:
    deploy = (REPO / "deploy" / "artifacts" / "deploy.sh").read_text()
    m = re.search(r"^REGIONS=\((.*)\)$", deploy, re.M)
    assert m and set(shlex.split(m[1])) == REGIONS
    release = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())
    env = release["jobs"]["aws-publish"]["env"]
    assert set(env["ARTIFACT_REGIONS"].split()) == REGIONS
    assert env["BUCKET_PREFIX"] == ARTIFACTS["Parameters"]["BucketPrefix"]["Default"]
    assert env["HOME_REGION"] == ARTIFACTS["Parameters"]["HomeRegion"]["Default"]
    notes = (REPO / "scripts" / "release-notes.py").read_text()
    for region in REGIONS:
        assert f'"{region}"' in notes


def test_aws_steps_are_skipped_without_the_role_variable() -> None:
    release = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())
    steps = release["jobs"]["aws-publish"]["steps"]
    assert steps[0]["id"] == "gate"
    assert "vars.ARTIFACTS_ROLE_ARN" in steps[0]["env"]["ROLE_ARN"]
    for step in steps[1:]:
        assert step["if"] == "steps.gate.outputs.enabled == 'true'", step.get(
            "name", step.get("uses")
        )


def test_npm_publishes_by_trusted_publishing_with_provenance() -> None:
    text = (REPO / ".github" / "workflows" / "release.yml").read_text()
    release = yaml.safe_load(text)
    npm = release["jobs"]["npm"]
    assert npm["permissions"]["id-token"] == "write"
    assert "npm publish --provenance --access public" in npm["steps"][-1]["run"]
    # No token anywhere: no secret is read, and none is passed to npm.
    assert "secrets.NPM" not in text and "NODE_AUTH_TOKEN" not in text
