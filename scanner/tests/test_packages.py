"""The split: a cloud-neutral core, and a package per platform built on it."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import sensitive_data_core
import sensitive_data_scanner

SCANNER = Path(__file__).resolve().parents[1]
REPO = SCANNER.parent
CORE = SCANNER / "core" / "src" / "sensitive_data_core"
# Modules that belong to a cloud: the core imports none of them.
CLOUD_MODULES = ("boto3", "botocore", "mypy_boto3", "cassandra", "sensitive_data_scanner")


def _imports(path: Path) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.add(node.module)
    return out


def test_the_core_names_no_cloud() -> None:
    for path in sorted(CORE.rglob("*.py")):
        for name in _imports(path):
            assert not name.startswith(CLOUD_MODULES), f"{path.name} imports {name}"


def test_the_core_depends_on_no_cloud_sdk() -> None:
    project = tomllib.loads((SCANNER / "core" / "pyproject.toml").read_text())["project"]
    deps = " ".join(project["dependencies"]).lower()
    for sdk in ("boto", "azure", "google-cloud", "cassandra"):
        assert sdk not in deps


def test_every_package_has_the_release_version() -> None:
    root = tomllib.loads((SCANNER / "pyproject.toml").read_text())["project"]["version"]
    for pyproject in sorted(SCANNER.glob("*/pyproject.toml")):
        assert tomllib.loads(pyproject.read_text())["project"]["version"] == root, pyproject
    assert sensitive_data_scanner.__version__ == root
    assert sensitive_data_core.__version__ == root
