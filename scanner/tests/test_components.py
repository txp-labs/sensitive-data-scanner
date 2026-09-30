"""The component manifest (#67): every adapter, reader, the sniffer and the spec have a
version from their source, and a change without a regenerated manifest fails CI."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from sensitive_data_core.index import Manifest

REPO = Path(__file__).resolve().parents[2]


def _components() -> ModuleType:
    spec = importlib.util.spec_from_file_location("components", REPO / "scripts/components.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["components"] = mod
    spec.loader.exec_module(mod)
    return mod


C = _components()


def _copy(tmp: Path) -> Path:
    """The parts of the repository the manifest is made from, in a scratch directory."""
    root = tmp / "repo"
    for part in ("spec", "scripts"):
        shutil.copytree(REPO / part, root / part)
    for pkg in ("src", "core/src", "db/src", "azure/src", "gcp/src", "saas/src"):
        shutil.copytree(
            REPO / "scanner" / pkg,
            root / "scanner" / pkg,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    return root


def test_the_committed_manifest_is_current() -> None:
    assert C.stale(REPO) == [], "run `uv run python ../scripts/components.py --write`"
    assert C.main(["--check"]) == 0


def test_every_sources_module_is_a_component_or_a_named_helper() -> None:
    assert C.uncovered(REPO) == []


def test_the_manifest_ships_in_the_core_and_names_every_part() -> None:
    m = Manifest.load()
    for name in (
        "adapter:s3",
        "adapter:m365_sharepoint",
        "adapter:dynamodb",
        "adapter:postgresql",
        "adapter:azure_blob",
        "adapter:gcs",
        "adapter:macie",
        "sniffer",
        "spec-standalone",
        "spec-conversation",
    ):
        assert m.version(name), name
    for reader in (
        "docx",
        "xlsx",
        "pptx",
        "pdf",
        "archive-zip",
        "archive-tar",
        "columnar",
        "avro",
        "text",
        "transcript",
    ):
        assert m.reader(reader), reader
    assert set(m.classes) >= {"card", "us_ssn", "us_itin", "dob", "cvv"}
    assert m.readers_for("pdf") == ("pdf",)
    assert m.readers_for("7z") == ()
    assert len(m.digest) == 12


def test_a_reader_change_without_regeneration_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _copy(tmp_path)
    assert C.stale(root) == []
    pdf = root / "scanner/core/src/sensitive_data_core/scan/pdf.py"
    pdf.write_text(pdf.read_text() + "\n# a better text layer\n")
    assert C.stale(root) == ["reader:pdf"]
    monkeypatch.setattr(C, "ROOT", root)
    assert C.main(["--check"]) == 1
    assert "reader:pdf" in capsys.readouterr().err
    assert C.main(["--write"]) == 0
    assert C.main(["--check"]) == 0


def test_versions_move_only_with_what_they_are_made_of(tmp_path: Path) -> None:
    """A change to one symbol of a shared file moves only the readers made of it; a change to
    one class's rules moves only that class; prompts move the conversation spec only."""
    root = _copy(tmp_path)
    before = C.compute(root)["components"]

    def changed() -> set[str]:
        after = C.compute(root)["components"]
        return {k for k in set(before) | set(after) if before.get(k) != after.get(k)}

    office = root / "scanner/core/src/sensitive_data_core/scan/office.py"
    office.write_text(office.read_text().replace("def _pptx(", "def _pptx(  # slides\n", 1))
    assert changed() == {"reader:pptx"}
    before = C.compute(root)["components"]

    objects = root / "scanner/core/src/sensitive_data_core/scan/objects.py"
    text = objects.read_text()
    objects.write_text(text.replace("def _tar(", "def _tar(  # tapes\n", 1))
    assert changed() == {"reader:archive-tar"}
    before = C.compute(root)["components"]

    sniff = root / "scanner/core/src/sensitive_data_core/scan/sniff.py"
    sniff.write_text(sniff.read_text() + "\n# a new magic number\n")
    assert changed() == {"sniffer"}
    before = C.compute(root)["components"]

    spec = root / "spec/classes.yaml"
    raw = spec.read_text()
    old = 'contextWords: ["social", "ssn", "social security"]'
    spec.write_text(raw.replace(old, old[:-1] + ', "ss#"]'))
    assert changed() == {"spec-standalone/us_ssn"}
    before = C.compute(root)["components"]

    raw = spec.read_text()
    spec.write_text(raw.replace('      - "ssn"\n', '      - "ssn"\n      - "social sec"\n', 1))
    assert changed() == {"spec-conversation"}
    before = C.compute(root)["components"]

    raw = spec.read_text()
    new_class = (
        '\n  passport:\n    severity: medium\n    promptPhrases: ["passport number"]\n'
        "    shape:\n      digits: 9\n"
    )
    spec.write_text(raw.replace("\n  card:\n", new_class + "\n  card:\n", 1))
    assert changed() == {"spec-standalone/passport", "spec-conversation"}
    before = C.compute(root)["components"]

    s3 = root / "scanner/src/sensitive_data_scanner/sources/s3.py"
    s3.write_text(s3.read_text() + "\n# a listing change\n")
    assert changed() == {"adapter:s3", "adapter:glue_table", "adapter:s3_directory"}


def test_the_manifest_is_valid_json_with_hex_versions() -> None:
    doc = json.loads((REPO / C.MANIFEST).read_text())
    assert doc["manifestVersion"] == 1
    for name, version in doc["components"].items():
        assert len(version) == 12 and int(version, 16) >= 0, name
