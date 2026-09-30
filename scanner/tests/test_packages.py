"""The split: a cloud-neutral core, and a package per platform built on it."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import sensitive_data_azure
import sensitive_data_core
import sensitive_data_db
import sensitive_data_scanner

SCANNER = Path(__file__).resolve().parents[1]
REPO = SCANNER.parent
CORE = SCANNER / "core" / "src" / "sensitive_data_core"
# Modules that belong to a cloud: the core imports none of them.
CLOUD_MODULES = (
    "boto3",
    "botocore",
    "mypy_boto3",
    "cassandra",
    "azure",
    "sensitive_data_scanner",
    "sensitive_data_azure",
    "sensitive_data_db",
)


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
    assert sensitive_data_db.__version__ == root
    assert sensitive_data_azure.__version__ == root


def test_azure_sdks_stay_in_the_azure_package() -> None:
    """Only `sensitive_data_azure` imports Azure; the AWS scanner and the databases runner
    do not, and the Azure package imports no AWS SDK."""
    azure_pkg = SCANNER / "azure" / "src" / "sensitive_data_azure"
    for pkg in (SCANNER / "src" / "sensitive_data_scanner", SCANNER / "db" / "src"):
        for path in sorted(pkg.rglob("*.py")):
            assert not any(n.startswith("azure") for n in _imports(path)), path.name
    for path in sorted(azure_pkg.rglob("*.py")):
        assert not any(n.startswith(("boto3", "botocore")) for n in _imports(path)), path.name


def test_a_store_fact_is_added_to_each_finding_and_never_replaces_a_field() -> None:
    """The hook #35 fills: what an adapter knows about the store (`atRestEncryption`)."""
    import pytest

    from sensitive_data_core.findings import ClassFinding, finding_json

    cf = ClassFinding("card", count=1, occurrences=1, confidence="high")
    resource = {"type": "store_field", "service": "x", "store": "y", "readBy": "sample"}
    plain = finding_json(resource, None, "sql", cf, "2026-09-29T00:00:00+00:00")
    with_fact = finding_json(
        resource, None, "sql", cf, "2026-09-29T00:00:00+00:00", facts={"fact": "value"}
    )
    assert with_fact == {**plain, "fact": "value"}
    with pytest.raises(ValueError, match="may not replace"):
        finding_json(resource, None, "sql", cf, "2026-09-29T00:00:00+00:00", facts={"class": "x"})
