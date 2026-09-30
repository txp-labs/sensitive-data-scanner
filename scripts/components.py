"""The component manifest: a version for every part that decides what a read finds (#67).

    uv run python ../scripts/components.py --write   # from scanner/: regenerate
    uv run python ../scripts/components.py --check   # CI: fail when it is stale

A component's version is the first 12 hex of a SHA-256 over its source: whole
files, or named top-level functions and classes of a file (`path::a,b`), and
for the spec, the parts of `spec/classes.yaml` and `spec/normalize.yaml` it
reads. Nobody bumps a version by hand, so nobody can forget to: change a
reader's source and its version changes; forget to regenerate and CI fails.

The components (docs/ARCHITECTURE.md, "How rescans are chosen"):

- `adapter:<kind>`: the source module(s) that read a kind of store, found by
  the `kind = "..."` literals in every platform's `sources/` modules, plus the
  kinds named below that a module sets at run time;
- `reader:<name>`: the core's readers, and the kinds of object each reads;
- `sniffer`: what an object is (`scan/sniff.py`) and the routing that sends it
  to a reader;
- `spec-standalone` (the unprompted engine: shape, context, recognizers) and
  `spec-standalone/<class>` (one class's own rules, so a change to one class,
  or a new class, is named);
- `spec-conversation`: prompts, carryover, normalization and answer windows.

The manifest (`scanner/core/src/sensitive_data_core/components.json`) ships in
the core package; the scanner compares an object's recorded versions with it.
Nothing here is a value: paths, names and hashes of source code.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "scanner/core/src/sensitive_data_core/components.json"
MANIFEST_VERSION = 1

CORE = "scanner/core/src/sensitive_data_core"
OBJECTS = f"{CORE}/scan/objects.py"
_OFFICE_SHARED = "OfficeUnreadable,OfficeText,_Budget,_xml,_paragraphs,office_text,office_zip_text"

# Each reader: what it is made of, and the kinds of object (scan/sniff.py's names) it reads.
READERS: dict[str, dict[str, Any]] = {
    "text": {
        "sources": [
            f"{CORE}/scan/item.py::looks_binary,ItemResult,_Collector,_pointer_escape,"
            "_document_context,_json_leaves,_json_format,_scan_json,_parse_json,scan_item_text",
        ],
        "kinds": ["text"],
    },
    "transcript": {
        "sources": [f"{CORE}/parsers.py", f"{CORE}/scan/item.py::_conversation,_scan_json"],
        "kinds": ["text"],
    },
    "docx": {"sources": [f"{CORE}/scan/office.py::{_OFFICE_SHARED},_docx"], "kinds": ["docx"]},
    "xlsx": {
        "sources": [f"{CORE}/scan/office.py::{_OFFICE_SHARED},_col_index,_xlsx"],
        "kinds": ["xlsx"],
    },
    "pptx": {"sources": [f"{CORE}/scan/office.py::{_OFFICE_SHARED},_pptx"], "kinds": ["pptx"]},
    "pdf": {"sources": [f"{CORE}/scan/pdf.py", f"{OBJECTS}::_pdf"], "kinds": ["pdf"]},
    "archive-zip": {
        "sources": [f"{OBJECTS}::_zip,_entry,_counted,_entry_limit,archive_fields"],
        "kinds": ["zip"],
    },
    "archive-tar": {
        "sources": [f"{OBJECTS}::_tar,_entry,_counted,archive_fields"],
        "kinds": ["tar"],
    },
    "archive-stream": {
        "sources": [
            f"{OBJECTS}::_stream,_inflate,inner_name,gunzip",
            f"{CORE}/scan/columnar.py::zstd_text",
        ],
        "kinds": ["gzip", "bzip2", "xz", "zstd"],
    },
    "columnar": {
        "sources": [f"{CORE}/scan/columnar.py", f"{OBJECTS}::_table"],
        "kinds": ["parquet", "orc"],
    },
    "avro": {"sources": [f"{CORE}/scan/avro.py", f"{OBJECTS}::_table"], "kinds": ["avro"]},
    "rdb": {"sources": [f"{CORE}/scan/raw.py", f"{OBJECTS}::_leaf"], "kinds": ["rdb"]},
    # Tables and items (#67 part 3): a sampled SQL pass, a DynamoDB item's attributes.
    "sql": {"sources": [f"{CORE}/scan/sql.py"], "kinds": []},
    "attributes": {"sources": [f"{CORE}/scan/attributes.py"], "kinds": []},
}

SNIFFER = [
    f"{CORE}/scan/sniff.py",
    f"{OBJECTS}::read_object,_read,_leaf,_Src,RangeFile,_disguise,_ole_encrypted,is_rdb,"
    "compression,planned_bytes",
]

SPEC_STANDALONE_CODE = [
    f"{CORE}/engine/rules.py",
    f"{CORE}/engine/spec.py",
    f"{CORE}/detect/analyzer.py",
    f"{CORE}/detect/enhancer.py",
    f"{CORE}/detect/entities.py",
    f"{CORE}/detect/recognizers.py",
]
SPEC_CONVERSATION_CODE = [
    f"{CORE}/engine/conversation.py",
    f"{CORE}/engine/normalize.py",
    f"{CORE}/engine/spec.py",
    "spec/normalize.yaml",
]
# Keys of `spec/classes.yaml`: a class's prompts, and the conversation settings.
CONVERSATION_CLASS_KEYS = frozenset({"promptPhrases"})
CONVERSATION_KEYS = ("retryPrefixes", "promptCarryover", "contextWindow")
# Top-level keys that belong to one class's standalone rules.
CLASS_EXTRAS = {"card": ("cardBrands",)}

# Where each platform's adapters live.
SOURCE_DIRS = (
    "scanner/src/sensitive_data_scanner/sources",
    "scanner/azure/src/sensitive_data_azure/sources",
    "scanner/gcp/src/sensitive_data_gcp/sources",
    "scanner/saas/src/sensitive_data_saas/sources",
)
# Kinds a module sets at run time (no `kind = "..."` literal), and the databases runner's
# engines. Each is read by the files named.
EXTRA_ADAPTERS: dict[str, list[str]] = {
    **dict.fromkeys(
        ["azure_sql", "azure_sql_mi", "azure_postgresql", "azure_mysql", "synapse_sql"],
        ["scanner/azure/src/sensitive_data_azure/sources/databases.py"],
    ),
    **dict.fromkeys(
        ["cloudsql_postgresql", "cloudsql_mysql", "cloudsql_sqlserver", "alloydb"],
        ["scanner/gcp/src/sensitive_data_gcp/sources/databases.py"],
    ),
    **dict.fromkeys(
        ["firestore", "datastore"], ["scanner/gcp/src/sensitive_data_gcp/sources/documents.py"]
    ),
    "dynamodb": ["scanner/src/sensitive_data_scanner/sources/dynamodb_export.py"],
    "rds": ["scanner/src/sensitive_data_scanner/sources/exports.py"],
    "gws_alerts": ["scanner/saas/src/sensitive_data_saas/sources/gws_alerts.py"],
    "purview": ["scanner/saas/src/sensitive_data_saas/sources/purview.py"],
    "slack_audit": ["scanner/saas/src/sensitive_data_saas/sources/slack_audit.py"],
    "sdp": ["scanner/gcp/src/sensitive_data_gcp/sources/sdp.py"],
    **{
        engine: [f"scanner/db/src/sensitive_data_db/engines.py::{fn}"]
        for engine, fn in (
            ("postgresql", "connect_postgresql,SqlSession"),
            ("mysql", "connect_mysql,mysql_encryption,SqlSession"),
            ("sqlserver", "connect_sqlserver,sqlserver_encryption,SqlSession"),
            ("oracle", "connect_oracle,SqlSession"),
            ("snowflake", "connect_snowflake,SqlSession"),
            ("databricks", "connect_databricks,SqlSession"),
            ("mongodb", "connect_mongodb,MongoSession,_plain"),
        )
    },
}
# A vendor's importer (#55) names the kind whose findings it imports, but reads no object:
# it is its own component, and never part of that kind's adapter.
IMPORTERS = {"scanner/src/sensitive_data_scanner/sources/macie.py": "macie"}
# Modules in a `sources/` directory that read no store of their own: shared plumbing (the
# context, the adapter lists, encryption and export helpers). A new module must either
# name a kind or be listed here (tests/test_components.py).
HELPERS = frozenset(
    {
        "__init__.py",
        "aws.py",
        "azure.py",
        "gcp.py",
        "saas.py",
        "base.py",
        "common.py",
        "encryption.py",
        "exports.py",
        "m365.py",
        "gws.py",
    }
)
_KIND = re.compile(r'^\s*(?:self\.)?(?:kind|KIND)\s*(?::\s*str\s*)?=\s*"([a-z0-9_]+)"', re.M)


def _symbols(text: str, names: Iterable[str], path: str) -> str:
    """The source of the named top-level functions, classes and assignments, in file order."""
    wanted = {n.strip() for n in names if n.strip()}
    tree = ast.parse(text)
    parts: list[str] = []
    found: set[str] = set()
    for node in tree.body:
        name: str | None = None
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            name = node.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            name = t.id if isinstance(t, ast.Name) else None
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
        if name in wanted:
            found.add(name)
            decorators = getattr(node, "decorator_list", [])
            for d in decorators:
                parts.append("@" + (ast.get_source_segment(text, d) or ""))
            parts.append(ast.get_source_segment(text, node) or "")
    missing = wanted - found
    if missing:
        raise SystemExit(f"components: {path} has no {', '.join(sorted(missing))}")
    return "\n".join(parts)


def source_text(root: Path, entry: str) -> str:
    """One entry's source: a whole file, or `path::name,name` for named symbols of it."""
    path, _, names = entry.partition("::")
    text = (root / path).read_text(encoding="utf-8").replace("\r\n", "\n")
    return _symbols(text, names.split(","), path) if names else text


def digest(root: Path, entries: Iterable[str], extra: Any = None) -> str:
    h = hashlib.sha256()
    for entry in sorted(set(entries)):
        h.update(entry.encode() + b"\0")
        h.update(source_text(root, entry).encode() + b"\0")
    if extra is not None:
        h.update(json.dumps(extra, sort_keys=True, separators=(",", ":")).encode())
    return h.hexdigest()[:12]


def adapters(root: Path) -> dict[str, list[str]]:
    """Each store kind and the files that read it: every `sources/` module's kinds."""
    out: dict[str, list[str]] = {k: list(v) for k, v in EXTRA_ADAPTERS.items()}
    for d in SOURCE_DIRS:
        for f in sorted((root / d).glob("*.py")):
            rel = f.relative_to(root).as_posix()
            if rel in IMPORTERS:
                out.setdefault(IMPORTERS[rel], []).append(rel)
                continue
            kinds = sorted(set(_KIND.findall(f.read_text(encoding="utf-8"))))
            for kind in kinds:
                files = out.setdefault(kind, [])
                if rel not in files:
                    files.append(rel)
    return dict(sorted(out.items()))


def uncovered(root: Path) -> list[str]:
    """`sources/` modules that name no kind, are not an extra adapter's, and are no helper."""
    named = {e.partition("::")[0] for files in adapters(root).values() for e in files}
    out = []
    for d in SOURCE_DIRS:
        for f in sorted((root / d).glob("*.py")):
            rel = f.relative_to(root).as_posix()
            if f.name not in HELPERS and rel not in named:
                out.append(rel)
    return out


def _spec(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    doc = yaml.safe_load((root / "spec/classes.yaml").read_text(encoding="utf-8"))
    classes: dict[str, Any] = doc.get("classes") or {}
    standalone = {
        cls: {
            "rules": {k: v for k, v in (body or {}).items() if k not in CONVERSATION_CLASS_KEYS},
            **{k: doc.get(k) for k in CLASS_EXTRAS.get(cls, ())},
        }
        for cls, body in classes.items()
    }
    conversation = {
        "prompts": {cls: (body or {}).get("promptPhrases") for cls, body in classes.items()},
        **{k: doc.get(k) for k in CONVERSATION_KEYS},
    }
    return standalone, conversation


def compute(root: Path = ROOT) -> dict[str, Any]:
    """The manifest for the source tree at `root`."""
    components: dict[str, str] = {}
    for kind, files in adapters(root).items():
        components[f"adapter:{kind}"] = digest(root, files)
    for name, reader in READERS.items():
        components[f"reader:{name}"] = digest(root, reader["sources"])
    components["sniffer"] = digest(root, SNIFFER)
    standalone, conversation = _spec(root)
    components["spec-standalone"] = digest(root, SPEC_STANDALONE_CODE)
    for cls, rules in standalone.items():
        components[f"spec-standalone/{cls}"] = digest(root, [], rules)
    components["spec-conversation"] = digest(root, SPEC_CONVERSATION_CODE, conversation)
    return {
        "manifestVersion": MANIFEST_VERSION,
        "generator": "scripts/components.py",
        "components": dict(sorted(components.items())),
        "readerKinds": {name: list(r["kinds"]) for name, r in sorted(READERS.items())},
    }


def render(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def stale(root: Path = ROOT) -> list[str]:
    """The components whose committed version differs from the source's (added and removed
    included); empty when the manifest is current."""
    want = compute(root)
    try:
        have = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["<manifest missing>"]
    a, b = have.get("components") or {}, want["components"]
    out = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    if have.get("readerKinds") != want["readerKinds"]:
        out.append("<readerKinds>")
    if have.get("manifestVersion") != want["manifestVersion"]:
        out.append("<manifestVersion>")
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true", help="regenerate the manifest")
    g.add_argument("--check", action="store_true", help="fail when the manifest is stale")
    args = p.parse_args(argv)
    if args.write:
        (ROOT / MANIFEST).write_text(render(compute(ROOT)), encoding="utf-8")
        return 0
    loose = uncovered(ROOT)
    if loose:
        print("components: a sources module names no kind: " + ", ".join(loose), file=sys.stderr)
        return 1
    changed = stale(ROOT)
    if changed:
        print(
            "components: the manifest is stale for "
            + ", ".join(changed)
            + ". Run `uv run python ../scripts/components.py --write` in scanner/ and commit "
            + MANIFEST,
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
