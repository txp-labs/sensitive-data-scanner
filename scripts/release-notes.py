#!/usr/bin/env python3
"""Print the GitHub Release notes for a version: its CHANGELOG section, then
docs/release-notes/v<version>.md if present (what is proven, what is not),
then the images' digests.

    scripts/release-notes.py <version> <image-digest> [<databases-image-digest> [<azure-image-digest> [<gcp-image-digest>]]]
"""

from __future__ import annotations

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


def main() -> None:
    version, digest = sys.argv[1], sys.argv[2]
    db_digest = sys.argv[3] if len(sys.argv) > 3 else None
    azure_digest = sys.argv[4] if len(sys.argv) > 4 else None
    gcp_digest = sys.argv[5] if len(sys.argv) > 5 else None
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
    parts.append(
        "## Artifacts\n\n"
        f"- Container image: `ghcr.io/txp-labs/sensitive-data-scanner@{digest}` "
        f"(tag `{version}`)\n"
        f"{db}"
        f"{azure}"
        f"{gcp}"
        "- Lambda zip (python3.12, x86_64) and the wheels (scanner, core, databases runner, "
        "Azure scanner, Google Cloud scanner) "
        "attached below\n"
        "- SPDX SBOMs for the zip and the images, and `SHA256SUMS` for every file\n"
        "- Not signed yet: see docs/RELEASING.md"
    )
    sys.stdout.write("\n\n".join(parts) + "\n")


if __name__ == "__main__":
    main()
