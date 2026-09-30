"""The component manifest: a version for every part that decides what a read finds (#67).

    uv run python ../scripts/components.py --write   # from scanner/: regenerate
    uv run python ../scripts/components.py --check   # CI: fail when it is stale

A component's version is the first 12 hex of a SHA-256 over its source: whole
files, or named top-level functions and classes of a file (`path::a,b`), and
for the spec, the parts of `spec/classes.yaml` and `spec/normalize.yaml` it
reads. Nobody bumps a version by hand, so nobody can forget to: change a
reader's source and its version changes; forget to regenerate and CI fails.

The components (docs/ARCHITECTURE.md, "How rescans are chosen"):

- `adapter:<kind>`: the **read path** of a kind of store: the functions that fetch
  and interpret its data. An adapter whose objects are recorded in the object
  index keeps them in its own module, `sources/<name>_read.py`, which names the
  kinds it reads (`READS = ("s3", ...)`); the rest of the adapter (discovery,
  listing, inventory, configuration, logging) stays in `sources/<name>.py` and is
  `listing:<kind>`. A change to `listing:<kind>` re-lists the store and never
  re-reads an object (#67). Adapters that record nothing in the index (they read
  forward, or every pass) are not split: the module is the adapter, found by the
  `kind = "..."` literals in every platform's `sources/` modules, plus the kinds
  named below that a module sets at run time;
- `listing:<kind>`: the split adapters' other modules;
- shared read helpers (`SHARED_READ`): code in a `sources/` helper module that
  reads for the adapters (the SaaS sources' `ItemReader`, Azure's queue message
  text), hashed into the `adapter:<kind>` of every kind whose modules import it,
  so a change to it rescans what it read. A name an adapter's read path imports
  from a helper module is either a shared read helper or named as plumbing
  (`PLUMBING`: the context, gaps, encryption facts), or the check fails;
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
# 2: adapters narrowed to their read path (`adapter:<kind>`), with `listing:<kind>` beside
# them (#67). Rows recorded under 1 hashed whole modules: their adapter versions are not
# compared (sensitive_data_core.index).
MANIFEST_VERSION = 2

CORE = "scanner/core/src/sensitive_data_core"
OBJECTS = f"{CORE}/scan/objects.py"
_OFFICE_SHARED = "OfficeUnreadable,OfficeText,_Budget,_xml,_paragraphs,office_text,office_zip_text"

# Each reader: what it is made of, and the kinds of object (scan/sniff.py's names) it reads.
READERS: dict[str, dict[str, Any]] = {
    "text": {
        "sources": [
            f"{CORE}/scan/item.py::looks_binary,ItemResult,_Collector,_pointer_escape,"
            "_labels,_json_leaves,csv_cells,_scan_csv,_csv_column,_json_format,_scan_json,_parse_json,scan_item_text",
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
# engines. Each is read by the files named. (A split adapter's read module names its kinds in
# `READS`, so the Azure and Google Cloud databases and DynamoDB exports need no entry here.)
EXTRA_ADAPTERS: dict[str, list[str]] = {
    **dict.fromkeys(
        ["firestore", "datastore"], ["scanner/gcp/src/sensitive_data_gcp/sources/documents.py"]
    ),
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
# Helpers that find a split adapter's objects without reading them: part of its listing.
EXTRA_LISTINGS: dict[str, list[str]] = {
    **dict.fromkeys(
        ["s3", "glue_table"], ["scanner/src/sensitive_data_scanner/sources/inventory.py"]
    ),
    **dict.fromkeys(["rds", "dynamodb"], ["scanner/src/sensitive_data_scanner/sources/exports.py"]),
    **dict.fromkeys(
        ["azure_sql", "azure_sql_mi", "azure_postgresql", "azure_mysql", "synapse_sql"],
        ["scanner/azure/src/sensitive_data_azure/sources/databases.py"],
    ),
    **dict.fromkeys(
        ["cloudsql_postgresql", "cloudsql_mysql", "cloudsql_sqlserver", "alloydb"],
        ["scanner/gcp/src/sensitive_data_gcp/sources/databases.py"],
    ),
}
READ_SUFFIX = "_read.py"
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
        # How a large bucket's objects are found (S3 Inventory reports), not how they are
        # read: `listing:s3` (EXTRA_LISTINGS).
        "inventory.py",
    }
)
_SAAS = "scanner/saas/src/sensitive_data_saas/sources"
_AZURE = "scanner/azure/src/sensitive_data_azure/sources"
_GCP = "scanner/gcp/src/sensitive_data_gcp/sources"
_AWS = "scanner/src/sensitive_data_scanner/sources"
# Code in a helper module that reads for the adapters: each entry is hashed into the
# `adapter:<kind>` of every kind whose modules (read path or listing) import one of its
# names, so a change to it rescans what it read (#67).
SHARED_READ: tuple[str, ...] = (
    # How every SaaS source reads an item's text and a file: the core's readers, the findings
    # made of what they found, and an attachment's findings put back in place.
    f"{_SAAS}/base.py::ItemReader",
    f"{_SAAS}/base.py::_Text,html_text",
    f"{_SAAS}/base.py::bytes_fetch",
    # A stored value, a queue message's text, and a queue's findings added up.
    f"{_AZURE}/common.py::plain",
    f"{_AZURE}/common.py::_printable,message_text",
    f"{_AZURE}/common.py::_CONF_RANK,merge_items",
    # An export's (a layer's, a repository's) findings for one column added up across files.
    f"{_AWS}/exports.py::merge",
)
# Names an adapter's read path imports from a helper module that decide nothing a read finds:
# the context, a refused call as a gap, encryption facts, settings, time stamps, the export
# state machine. A name in neither this nor SHARED_READ fails the check (`uncovered`).
PLUMBING: dict[str, frozenset[str]] = {
    f"{_AWS}/base.py": frozenset({"Context"}),
    f"{_AWS}/encryption.py": frozenset(
        {"KeyClassifier", "classifier", "log_group_facts", "s3_object_facts", "weakest"}
    ),
    f"{_AWS}/exports.py": frozenset(
        {"ExportQuota", "delete_prefix", "drop_other_passes", "due", "list_keys"}
    ),
    f"{_AZURE}/base.py": frozenset({"Context", "key_facts"}),
    f"{_AZURE}/common.py": frozenset({"http_gap"}),
    f"{_GCP}/base.py": frozenset({"Context", "kms_facts", "labels"}),
    f"{_GCP}/common.py": frozenset({"call_gap"}),
    f"{_SAAS}/base.py": frozenset({"Context", "call_gap", "parse_time", "vendor_facts"}),
    f"{_SAAS}/gws.py": frozenset({"VENDOR", "facts_of", "settings_of", "tenant_of"}),
    f"{_SAAS}/m365.py": frozenset(
        {"Person", "facts_of", "fields_of", "people", "settings_of", "tenant_of"}
    ),
}
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


def _reads(path: Path) -> tuple[str, ...]:
    """A read module's `READS = ("kind", ...)`: the kinds whose read path it is."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "READS"
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, tuple) and all(isinstance(k, str) for k in value):
                return value
    raise SystemExit(f"components: {path} has no READS tuple")


def _shared_read() -> dict[str, list[tuple[str, frozenset[str]]]]:
    """SHARED_READ by helper module: each entry, and the names that bring it in."""
    out: dict[str, list[tuple[str, frozenset[str]]]] = {}
    for entry in SHARED_READ:
        path, _, names = entry.partition("::")
        out.setdefault(path, []).append((entry, frozenset(n.strip() for n in names.split(","))))
    return out


def helper_imports(root: Path, rel: str) -> set[tuple[str, str]]:
    """What a `sources/` module imports from the helper modules beside it: (the helper's
    path, the name). `from . import base` is the name `*`: every name is its to use."""
    f = root / rel
    out: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.ImportFrom) or node.level != 1:
            continue
        if node.module is None:
            for alias in node.names:
                if alias.name + ".py" in HELPERS:
                    out.add(((f.parent / (alias.name + ".py")).relative_to(root).as_posix(), "*"))
        elif "." not in node.module and node.module + ".py" in HELPERS:
            helper = (f.parent / (node.module + ".py")).relative_to(root).as_posix()
            out.update((helper, alias.name) for alias in node.names)
    return out


def _in_sources(rel: str) -> bool:
    return any(rel.startswith(d + "/") for d in SOURCE_DIRS)


def _modules(root: Path) -> list[Path]:
    return [f for d in SOURCE_DIRS for f in sorted((root / d).glob("*.py"))]


def _split(f: Path) -> bool:
    """A module whose read path is its own `<name>_read.py`."""
    return f.with_name(f.stem + READ_SUFFIX).exists()


def components_of(root: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Each store kind's read path (`adapter:<kind>`) and, for a split adapter, the rest of
    it (`listing:<kind>`), as the files that make each."""
    read: dict[str, list[str]] = {k: list(v) for k, v in EXTRA_ADAPTERS.items()}
    listing: dict[str, list[str]] = {}
    split_kinds: set[str] = set()
    for f in _modules(root):
        if f.name.endswith(READ_SUFFIX):
            rel = f.relative_to(root).as_posix()
            for kind in _reads(f):
                read.setdefault(kind, []).append(rel)
                split_kinds.add(kind)
    for f in _modules(root):
        rel = f.relative_to(root).as_posix()
        if f.name.endswith(READ_SUFFIX):
            continue
        if rel in IMPORTERS:
            read.setdefault(IMPORTERS[rel], []).append(rel)
            continue
        for kind in sorted(set(_KIND.findall(f.read_text(encoding="utf-8")))):
            # A kind with a read module: its other modules are its listing, whether or not
            # they are split themselves (DynamoDB's Scan reads every pass and records no row).
            target = listing if kind in split_kinds else read
            files = target.setdefault(kind, [])
            if rel not in files:
                files.append(rel)
    for kind, files in EXTRA_LISTINGS.items():
        for rel in files:
            if kind in split_kinds and rel not in listing.setdefault(kind, []):
                listing[kind].append(rel)
    # A shared read helper is part of the read path of every kind whose modules use it.
    shared = _shared_read()
    for kind, files in read.items():
        modules = {e for e in files + listing.get(kind, []) if "::" not in e and _in_sources(e)}
        used = set().union(*(helper_imports(root, rel) for rel in modules)) if modules else set()
        for helper, entries in shared.items():
            names = {n for h, n in used if h == helper}
            for entry, brings in entries:
                if names & brings and entry not in files:
                    files.append(entry)
    return dict(sorted(read.items())), dict(sorted(listing.items()))


def adapters(root: Path) -> dict[str, list[str]]:
    """Each store kind and the files of its read path."""
    return components_of(root)[0]


def uncovered(root: Path) -> list[str]:
    """`sources/` modules that belong to no component: a module that names no kind, is not an
    extra adapter's or listing's, and is no helper; a read module with no module beside it;
    and a module that records objects in the index (`ObjectPass(`) without a read module of
    its own, so its listing would move its objects' versions; and a name a read path imports
    from a helper module that is neither a shared read helper nor named as plumbing, so a
    change to it would rescan nothing."""
    read, listing = components_of(root)
    named = {
        e.partition("::")[0] for group in (read, listing) for files in group.values() for e in files
    }
    out = []
    for f in _modules(root):
        rel = f.relative_to(root).as_posix()
        if f.name.endswith(READ_SUFFIX):
            base = f.with_name(f.name[: -len(READ_SUFFIX)] + ".py")
            if not base.exists():
                out.append(f"{rel} (a read module with no adapter module beside it)")
            continue
        if f.name not in HELPERS and rel not in named:
            out.append(rel)
        elif "ObjectPass(" in f.read_text(encoding="utf-8") and not _split(f):
            out.append(f"{rel} (records objects in the index: its read path needs a {READ_SUFFIX})")
    shared = {h: set().union(*(b for _, b in entries)) for h, entries in _shared_read().items()}
    reads = sorted(
        {e for files in read.values() for e in files if "::" not in e and _in_sources(e)}
    )
    for rel in reads:
        for helper, name in sorted(helper_imports(root, rel)):
            if name not in shared.get(helper, set()) and name not in PLUMBING.get(helper, ()):
                out.append(
                    f"{rel} (imports {name} from {helper}: a shared read helper belongs to a"
                    " component, SHARED_READ, or is named as plumbing, PLUMBING)"
                )
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
    read, listing = components_of(root)
    for kind, files in read.items():
        components[f"adapter:{kind}"] = digest(root, files)
    for kind, files in listing.items():
        components[f"listing:{kind}"] = digest(root, files)
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
        print("components: a sources module has no component: " + ", ".join(loose), file=sys.stderr)
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
