#!/usr/bin/env python3
"""Print the GitHub Release notes for a version: its CHANGELOG section, then
docs/release-notes/v<version>.md if present (what is proven, what is not),
then the images' digests.

    scripts/release-notes.py <version> <image-digest> [<databases-image-digest> [<azure-image-digest> [<gcp-image-digest> [<saas-image-digest>]]]]
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def section(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text()
    m = re.search(rf"^## {re.escape(version)} .*?$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        raise SystemExit("no CHANGELOG section for this version")
    return m[1].strip()


REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-2",
)


def signed_zip(version: str) -> str:
    """The AWS line, only when the release workflow's aws-publish job ran (AWS_PUBLISHED=true)."""
    if os.environ.get("AWS_PUBLISHED") != "true":
        return "- The Lambda zip was not signed or published to S3 in this release (AWS publishing not configured)\n"
    name = f"sensitive-data-scanner-{version}-lambda-python3.12-x86_64.zip"
    return (
        "- The Lambda zip signed with AWS Signer in each region by that region's profile "
        "`TxpLabsSensitiveDataScanner`, at "
        f"`s3://txp-labs-sensitive-data-scanner-<region>/releases/{version}/{name}` "
        f"in {', '.join(REGIONS)}; each region's `releases/{version}/signing.json` names the "
        "profile version ARN its code signing config allows (docs/RELEASING.md, Where the code is). "
        f"The Lambda image in ECR at `895544787721.dkr.ecr.<region>.amazonaws.com/sensitive-data-scanner:{version}` "
        "in the same regions\n"
    )


def main() -> None:
    version, digest = sys.argv[1], sys.argv[2]
    db_digest = sys.argv[3] if len(sys.argv) > 3 else None
    azure_digest = sys.argv[4] if len(sys.argv) > 4 else None
    gcp_digest = sys.argv[5] if len(sys.argv) > 5 else None
    saas_digest = sys.argv[6] if len(sys.argv) > 6 else None
    parts = []
    extra = ROOT / "docs" / "release-notes" / f"v{version}.md"
    if extra.is_file():
        parts.append(extra.read_text().strip())
    parts.append("## Changes\n\n" + section(version))
    db = (
        "- Databases runner image: "
        f"`ghcr.io/txp-labs/sensitive-data-scanner-databases@{db_digest}` "
        f"(tag `{version}`; docs/DATABASES.md)\n"
        if db_digest
        else ""
    )
    azure = (
        "- Azure scanner image: "
        f"`ghcr.io/txp-labs/sensitive-data-scanner-azure@{azure_digest}` "
        f"(tag `{version}`; docs/AZURE.md), and its deployment, "
        "`sensitive-data-scanner-azure.json` (deploy/azure/main.bicep, compiled)\n"
        if azure_digest
        else ""
    )
    gcp = (
        "- Google Cloud scanner image: "
        f"`ghcr.io/txp-labs/sensitive-data-scanner-gcp@{gcp_digest}` "
        f"(tag `{version}`; docs/GCP.md), and its deployment, "
        "`sensitive-data-scanner-gcp-terraform.tar.gz` (deploy/gcp)\n"
        if gcp_digest
        else ""
    )
    saas = (
        "- SaaS scanner image: "
        f"`ghcr.io/txp-labs/sensitive-data-scanner-saas@{saas_digest}` "
        f"(tag `{version}`; docs/SAAS.md), and its deploy examples, "
        "`sensitive-data-scanner-saas-deploy.tar.gz` (deploy/saas)\n"
        if saas_digest
        else ""
    )
    parts.append(
        "## Artifacts\n\n"
        f"- Container image: `ghcr.io/txp-labs/sensitive-data-scanner@{digest}` "
        f"(tag `{version}`)\n"
        f"{db}"
        f"{azure}"
        f"{gcp}"
        f"{saas}"
        "- Lambda zip (python3.12, x86_64) and the wheels (scanner, core, databases runner, "
        "Azure scanner, Google Cloud scanner, SaaS scanner) "
        "attached below\n"
        "- SPDX SBOMs for the zip and the images, and `SHA256SUMS` for every file\n"
        "- Every image signed with cosign (keyless, this repository's release workflow) "
        "and its SPDX SBOM attached as a signed attestation\n"
        f"{signed_zip(version)}"
        "- How to verify: docs/RELEASING.md, Verifying a release"
    )
    sys.stdout.write("\n\n".join(parts) + "\n")


if __name__ == "__main__":
    main()
