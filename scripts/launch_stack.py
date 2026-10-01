"""The one-click Launch Stack links and the templates' release defaults, for one version (#117).

    uv run python ../scripts/launch_stack.py --write   # from scanner/: rewrite them
    uv run python ../scripts/launch_stack.py --check   # tests: fail when stale

Every release publishes `scanner.yaml` to each approved region's bucket at
`releases/<version>/scanner.yaml` (release.yml, aws-publish), write-once and anonymously
readable, so a CloudFormation quick-create link works in every region. This script keeps,
for the version in scanner/pyproject.toml:

- the Launch Stack table between `<!-- launch-stack:start -->` and `<!-- launch-stack:end -->`
  in README.md and docs/QUICKSTART.md: one quick-create link per region, with the quick
  start's defaults (discovery on, opt-in reads off as they are by default, a 256 MiB byte
  budget for a first run);
- the `CodeS3Key` default of deploy/scanner.yaml and deploy/estate-stackset.yaml: the
  release's own zip, so the published template deploys the code it came with.

The release-closing PR runs `--write` after bumping the version (docs/RELEASING.md).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUCKET_PREFIX = "txp-labs-sensitive-data-scanner"
# Keep in step with release.yml's ARTIFACT_REGIONS and deploy/artifacts.
REGIONS = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "Europe (Ireland)",
    "eu-central-1": "Europe (Frankfurt)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
}
STACK_NAME = "sensitive-data-scanner"
# The quick start's parameters: discovery on (every kind), and a small first run.
QUICK_START = {"Discover": "all", "MaxBytesPerRun": "268435456"}
BUTTON = "https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png"
START = "<!-- launch-stack:start -->"
END = "<!-- launch-stack:end -->"
DOCS = ("README.md", "docs/QUICKSTART.md")
TEMPLATES = ("deploy/scanner.yaml", "deploy/estate-stackset.yaml")
# The quick start's CLI example names the version too.
_CLI_VERSION = re.compile(
    r"(?m)^(VERSION=)[0-9][0-9A-Za-z.+-]*(\s+# the version in the table above)$"
)
_KEY = re.compile(
    r"(\n  CodeS3Key:\n(?:    #[^\n]*\n)*    Type: String\n(?:    #[^\n]*\n)*    Default: )([^\n]*)"
)


def version() -> str:
    data = tomllib.loads((ROOT / "scanner" / "pyproject.toml").read_text())
    return str(data["project"]["version"])


def template_url(region: str, v: str) -> str:
    return f"https://{BUCKET_PREFIX}-{region}.s3.{region}.amazonaws.com/releases/{v}/scanner.yaml"


def launch_url(region: str, v: str) -> str:
    query = [("templateURL", template_url(region, v)), ("stackName", STACK_NAME)]
    query += [(f"param_{k}", val) for k, val in QUICK_START.items()]
    fragment = "/stacks/quickcreate?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
    return f"https://console.aws.amazon.com/cloudformation/home?region={region}#{fragment}"


def zip_key(v: str) -> str:
    return f"releases/{v}/sensitive-data-scanner-{v}-lambda-python3.12-x86_64.zip"


def table(v: str) -> str:
    rows = [
        f"| {name} | `{r}` | [![Launch Stack in {r}]({BUTTON})]({launch_url(r, v)}) |"
        for r, name in REGIONS.items()
    ]
    return "\n".join(
        [
            START,
            f"Version {v}. Each button opens CloudFormation's quick-create page in that region "
            "with the release's own template.",
            "",
            "| Region | | Launch |",
            "|---|---|---|",
            *rows,
            END,
        ]
    )


def rewritten(path: Path, v: str) -> str:
    text = path.read_text()
    if path.suffix == ".md":
        block = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)
        if not block.search(text):
            raise SystemExit(f"{path}: no {START} ... {END} block")
        text = block.sub(lambda _: table(v), text)
        return _CLI_VERSION.sub(lambda m: m[1] + v + m[2], text)
    if not _KEY.search(text):
        raise SystemExit(f"{path}: no CodeS3Key default")
    return _KEY.sub(lambda m: m[1] + zip_key(v), text)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    v = version()
    stale = []
    for name in (*DOCS, *TEMPLATES):
        path = ROOT / name
        new = rewritten(path, v)
        if new != path.read_text():
            stale.append(name)
            if args.write:
                path.write_text(new)
    if stale and args.check:
        print(f"stale for {v}: {', '.join(stale)}; run scripts/launch_stack.py --write")  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
