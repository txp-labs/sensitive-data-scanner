#!/usr/bin/env python3
"""Print the GitHub Release notes for a version: its CHANGELOG section, then
docs/release-notes/v<version>.md if present (what is proven, what is not),
then the image digest.

    scripts/release-notes.py <version> <image-digest>
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
    parts = []
    extra = ROOT / "docs" / "release-notes" / f"v{version}.md"
    if extra.is_file():
        parts.append(extra.read_text().strip())
    parts.append("## Changes\n\n" + section(version))
    parts.append(
        "## Artifacts\n\n"
        f"- Container image: `ghcr.io/txp-labs/sensitive-data-scanner@{digest}` "
        f"(tag `{version}`)\n"
        "- Lambda zip (python3.12, x86_64), wheel and sdist attached below\n"
        "- SPDX SBOMs for the zip and the image, and `SHA256SUMS` for every file\n"
        "- Not signed yet: see docs/RELEASING.md"
    )
    sys.stdout.write("\n\n".join(parts) + "\n")


if __name__ == "__main__":
    main()
