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
        "listing:s3",
        "listing:m365_sharepoint",
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

    # An adapter is its read path: a change to how a bucket is listed moves `listing:`, never
    # `adapter:` (#67), and a change to how an object is read moves `adapter:` only.
    s3 = root / "scanner/src/sensitive_data_scanner/sources/s3.py"
    s3.write_text(s3.read_text() + "\n# a listing change\n")
    assert changed() == {"listing:s3", "listing:glue_table", "listing:s3_directory"}
    before = C.compute(root)["components"]

    inventory = root / "scanner/src/sensitive_data_scanner/sources/inventory.py"
    inventory.write_text(inventory.read_text() + "\n# a report format\n")
    assert changed() == {"listing:s3", "listing:glue_table"}
    before = C.compute(root)["components"]

    s3_read = root / "scanner/src/sensitive_data_scanner/sources/s3_read.py"
    s3_read.write_text(s3_read.read_text() + "\n# a read change\n")
    assert changed() == {"adapter:s3", "adapter:glue_table", "adapter:s3_directory"}
    before = C.compute(root)["components"]

    sharepoint = root / "scanner/saas/src/sensitive_data_saas/sources/m365_files.py"
    sharepoint.write_text(sharepoint.read_text() + "\n# a discovery change\n")
    assert changed() == {"listing:m365_sharepoint", "listing:m365_onedrive"}


def test_an_indexed_adapter_without_a_read_module_fails_the_check(tmp_path: Path) -> None:
    """A module that records objects in the index keeps its read path in its own module, or
    a change to its listing would move its objects' versions; a read module needs its adapter
    module beside it."""
    root = _copy(tmp_path)
    assert C.uncovered(root) == []
    sources = root / "scanner/src/sensitive_data_scanner/sources"
    (sources / "code_read.py").unlink()
    assert any("code.py" in u and "_read.py" in u for u in C.uncovered(root))
    (sources / "orphan_read.py").write_text('READS = ("codecommit",)\n')
    assert any("orphan_read.py" in u for u in C.uncovered(root))


def test_the_manifest_is_valid_json_with_hex_versions() -> None:
    doc = json.loads((REPO / C.MANIFEST).read_text())
    assert doc["manifestVersion"] == 2  # adapters narrowed to their read path (#67)
    for name, version in doc["components"].items():
        assert len(version) == 12 and int(version, 16) >= 0, name


SAAS_READERS = {
    "adapter:confluence_space",
    "adapter:gws_drive",
    "adapter:gws_gmail",
    "adapter:gws_shared_drive",
    "adapter:jira_project",
    "adapter:m365_mail",
    "adapter:m365_onedrive",
    "adapter:m365_sharepoint",
    "adapter:m365_teams_channel",
    "adapter:m365_teams_chat",
    "adapter:slack_channel",
    "adapter:slack_dm",
}


def test_a_shared_read_helper_is_part_of_every_read_path_that_uses_it(tmp_path: Path) -> None:
    """The SaaS sources' `ItemReader` reads every item and file they read: a change to it
    moves the adapter of every SaaS kind that reads with it, and nothing else (#67). Plumbing
    beside it in the same module (a refused call as a gap) moves nothing."""
    root = _copy(tmp_path)
    before = C.compute(root)["components"]

    def changed() -> set[str]:
        after = C.compute(root)["components"]
        return {k for k in set(before) | set(after) if before.get(k) != after.get(k)}

    base = root / "scanner/saas/src/sensitive_data_saas/sources/base.py"
    base.write_text(
        base.read_text().replace("    def text(", "    def text(  # a read change\n", 1)
    )
    assert changed() == SAAS_READERS
    before = C.compute(root)["components"]

    base.write_text(base.read_text().replace("def call_gap(", "def call_gap(  # a gap\n", 1))
    assert changed() == set()

    base.write_text(base.read_text().replace("def html_text(", "def html_text(  # markup\n", 1))
    assert changed() == {
        "adapter:confluence_space",
        "adapter:gws_gmail",
        "adapter:jira_project",
        "adapter:m365_teams_channel",
        "adapter:m365_teams_chat",
    }
    before = C.compute(root)["components"]

    common = root / "scanner/azure/src/sensitive_data_azure/sources/common.py"
    common.write_text(common.read_text().replace("def message_text(", "def message_text(  # b64\n"))
    assert changed() == {"adapter:azure_queue", "adapter:azure_table"}


def test_a_helper_a_read_path_uses_must_belong_to_a_component(tmp_path: Path) -> None:
    """A name an adapter's read path imports from a helper module is a shared read helper
    (hashed into that adapter) or named as plumbing: a new helper that reads, left out of
    both, fails the check, since a change to it would rescan nothing."""
    root = _copy(tmp_path)
    assert C.uncovered(root) == []
    sources = root / "scanner/saas/src/sensitive_data_saas/sources"
    base = sources / "base.py"
    base.write_text(base.read_text() + "\n\ndef decode_body(raw: bytes) -> str:\n    return ''\n")
    slack = sources / "slack_read.py"
    slack.write_text(
        slack.read_text().replace("from .base import (", "from .base import (\n    decode_body,", 1)
    )
    loose = C.uncovered(root)
    assert len(loose) == 1
    assert "slack_read.py" in loose[0] and "decode_body" in loose[0] and "SHARED_READ" in loose[0]

    # `from . import base` would use every name unseen: it is flagged the same way.
    teams = sources / "m365_teams.py"
    teams.write_text("from . import base\n" + teams.read_text())
    assert any("m365_teams.py" in u and "imports *" in u for u in C.uncovered(root))


def test_every_shared_read_helper_is_used_and_names_real_symbols() -> None:
    read = C.adapters(REPO)
    for entry in C.SHARED_READ:
        path = entry.partition("::")[0]
        assert Path(path).name in C.HELPERS, entry
        assert C.source_text(REPO, entry), entry
        assert any(entry in files for files in read.values()), f"{entry} is part of no adapter"
    assert all(name in C.HELPERS for name in (Path(p).name for p in C.PLUMBING))
