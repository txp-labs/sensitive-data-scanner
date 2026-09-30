"""Firestore and Datastore: every database, sampled by collection or kind. Read by default.

**Discovery**: Cloud Asset Inventory lists every Firestore database in scope
(`firestore.googleapis.com/Database`); its record (`databases.get`: its mode
and Cloud KMS key) comes from the Firestore API with `datastore.databases.getMetadata`.
A database in Native mode is a `firestore` store and one in Datastore mode a
`datastore` store, `project/database`.

**Reading** needs only `datastore.entities.list` and `datastore.entities.get`
(Cloud Datastore Viewer):

- **Firestore** (Native mode): the root collections (`listCollectionIds`),
  then the first `DOCUMENTS_MAX_PER_COLLECTION` documents of each with one
  `runQuery` (`limit n`), read by top-level field, as columns. Subcollections
  are not listed.
- **Datastore** (Datastore mode): the kinds of the default namespace (a
  `__kind__` query), then the first entities of each with one `runQuery`
  (`limit n`), read by property.

Only queries are sent, and a query cannot write. `bytesValue` and
`blobValue` are not read. A database the budget does not finish resumes at
its next collection or kind.

**Encryption (1.5):** the database's CMEK (`cmekConfig`), hashed, else Google's
own keys (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows

from ..clients import Rest
from ..resources import Located, console_link
from .base import Context, kms_facts, labels
from .common import call_gap

FIRESTORE = "https://firestore.googleapis.com/v1"
DATASTORE = "https://datastore.googleapis.com/v1"
ASSET_TYPE = "firestore.googleapis.com/Database"
MAX_DEPTH = 15


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def value(v: Any, depth: int = 0) -> Any:
    """A Firestore or Datastore `Value` as a plain value. Bytes and blobs are dropped."""
    if not isinstance(v, dict) or depth > MAX_DEPTH:
        return None
    for key in ("stringValue", "integerValue", "doubleValue", "booleanValue", "timestampValue"):
        if key in v:
            return v[key]
    if "mapValue" in v:
        return fields_of((v["mapValue"] or {}).get("fields"), depth + 1)
    if "entityValue" in v:
        return fields_of((v["entityValue"] or {}).get("properties"), depth + 1)
    if "arrayValue" in v:
        return [value(x, depth + 1) for x in (v["arrayValue"] or {}).get("values") or []]
    return None  # null, bytes, blobs, references, keys and points hold no text a person typed


def fields_of(raw: Any, depth: int = 0) -> dict[str, Any]:
    return {str(k): value(x, depth) for k, x in raw.items()} if isinstance(raw, dict) else {}


@dataclass
class DocTarget:
    """One Firestore or Datastore database."""

    kind: str
    project: str
    database: str
    where: Located
    facts: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"DocTarget({self.kind!r}, {redact_digits(self.database)!r})"


@dataclass
class FirestoreDb:
    """A database as discovery found it: its mode and record, or why it could not be read."""

    row: dict[str, Any]
    project: str
    database: str
    mode: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    error: Exception | None = None


def firestore_databases(ctx: Context) -> list[FirestoreDb]:
    """Every Firestore database in scope with its mode, once per run for both adapters."""
    got = ctx.memo.get("firestore")
    if isinstance(got, list):
        return got
    out: list[FirestoreDb] = []
    for row in ctx.search(ASSET_TYPE):
        name = str(row.get("name") or "")
        parts = name.split("/")
        try:
            project = parts[parts.index("projects") + 1]
            database = parts[parts.index("databases") + 1]
        except (ValueError, IndexError):
            continue
        db = FirestoreDb(row, project, database)
        try:
            db.meta = ctx.rest.get(f"{FIRESTORE}/projects/{_q(project)}/databases/{_q(database)}")
            db.mode = str(db.meta.get("type") or "FIRESTORE_NATIVE").upper()
        except Exception as err:  # reported by the Firestore adapter
            db.error = err
        out.append(db)
    ctx.memo["firestore"] = out
    return out


class DocumentAdapter:
    """Firestore in Native mode (`firestore`) or in Datastore mode (`datastore`)."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.mode = "DATASTORE_MODE" if kind == "datastore" else "FIRESTORE_NATIVE"

    def discover(self, ctx: Context, out: Discovery) -> None:
        for db in firestore_databases(ctx):
            where = Located(db.project, str(db.row.get("name") or ""))
            if db.error is not None:
                if self.kind != "firestore" and "firestore" in ctx.settings.discover:
                    continue  # reported once, by the Firestore adapter
                store = Store(self.kind, f"{db.project}/{db.database}", tags=labels(db.row))
                store.extra.update(where.fields())
                store.status, store.error = "error", error_name(db.error)
                gap = call_gap(db.error)
                store.reason = "network" if gap == "network" else reason_for(store.error)
                out.stores.append(store)
                continue
            if db.mode != self.mode:
                continue
            key = (db.meta.get("cmekConfig") or {}).get("kmsKeyName")
            store = Store(self.kind, f"{db.project}/{db.database}", tags=labels(db.row))
            store.extra.update(where.fields())
            store.facts = kms_facts(str(key) if key else None)
            store.table = DocTarget(self.kind, db.project, db.database, where, dict(store.facts))
            out.stores.append(store)
            apply_rules(store, ctx.settings.allow, ctx.settings.deny)

    def source(self, ctx: Context, store: Store) -> DocumentSource | None:
        t = store.table
        if not isinstance(t, DocTarget):
            return None
        s = ctx.settings
        return DocumentSource(
            ctx.rest, t, max_documents=s.documents_max, max_collections=s.documents_max_collections
        )


class DocumentSource:
    """One database: its collections (or kinds), each sampled with one query."""

    def __init__(
        self, rest: Rest, target: DocTarget, *, max_documents: int = 500, max_collections: int = 200
    ) -> None:
        self.rest = rest
        self.t = target
        self.kind = target.kind
        self.max_documents = max_documents
        self.max_collections = max_collections
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"{target.kind}:{target.project}/{target.database}"
        self.target = f"{target.project}/{target.database}"

    def __repr__(self) -> str:
        return f"DocumentSource({self.t!r})"

    # ------------------------------------------------------------------ Firestore

    def _documents(self) -> str:
        t = self.t
        return f"{FIRESTORE}/projects/{_q(t.project)}/databases/{_q(t.database)}/documents"

    def _collections(self) -> list[str]:
        out: list[str] = []
        token: str | None = None
        while len(out) < self.max_collections:
            body: dict[str, Any] = {"pageSize": 300}
            if token:
                body["pageToken"] = token
            page = self.rest.post(f"{self._documents()}:listCollectionIds", body)
            out.extend(str(c) for c in page.get("collectionIds") or [])
            token = str(page.get("nextPageToken") or "") or None
            if token is None:
                break
        return out

    def _collection_rows(self, name: str) -> list[dict[str, Any]]:
        query = {"structuredQuery": {"from": [{"collectionId": name}], "limit": self.max_documents}}
        got = self.rest.post(f"{self._documents()}:runQuery", query)
        items = got if isinstance(got, list) else [got]
        return [
            fields_of((i.get("document") or {}).get("fields"))
            for i in items
            if isinstance(i, dict) and i.get("document")
        ]

    # ------------------------------------------------------------------ Datastore

    def _datastore(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        t = self.t
        body = {
            "databaseId": "" if t.database == "(default)" else t.database,
            "partitionId": {
                "projectId": t.project,
                **({} if t.database == "(default)" else {"databaseId": t.database}),
            },
            "query": query,
        }
        got = self.rest.post(f"{DATASTORE}/projects/{_q(t.project)}:runQuery", body)
        results = (got.get("batch") or {}).get("entityResults") or []
        return [r.get("entity") or {} for r in results if isinstance(r, dict)]

    def _kinds(self) -> list[str]:
        kinds = self._datastore({"kind": [{"name": "__kind__"}], "limit": self.max_collections})
        names = []
        for e in kinds:
            path = (e.get("key") or {}).get("path") or []
            name = str((path[-1] if path else {}).get("name") or "")
            if name and not name.startswith("__"):
                names.append(name)
        return names

    def _kind_rows(self, name: str) -> list[dict[str, Any]]:
        entities = self._datastore({"kind": [{"name": name}], "limit": self.max_documents})
        return [fields_of(e.get("properties")) for e in entities]

    # ------------------------------------------------------------------ the pass

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        native = self.kind == "firestore"
        try:
            names = sorted(set(self._collections() if native else self._kinds()))
        except Exception as err:  # the database could not be listed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=self.kind, error=cov.error)
            gap = call_gap(err)
            return SourceRun(cov, cursor, note=gap if gap == "network" else None)
        names = names[: self.max_collections]
        after = cursor.get("after")
        cov.listed = len(names)
        todo = [n for n in names if after is None or n > after]
        cov.eligible = len(todo)
        t = self.t
        page = "data" if native else "entities"
        link = console_link(
            f"{'firestore' if native else 'datastore'}/databases/{_q(t.database)}/{page}",
            {"project": t.project},
            t.database,
        )
        done = True
        for name in todo:
            if not budget.has():
                done = False
                break
            try:
                rows = self._collection_rows(name) if native else self._kind_rows(name)
            except Exception as err:  # one collection must not stop the pass
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
                after = name
                continue
            size = len(json.dumps(rows, default=str))
            budget.take(size)
            columns = list(dict.fromkeys(k for r in rows for k in r))
            result = scan_rows("json", columns, rows, detector, self.max_documents)
            cov.scanned += 1
            cov.bytes_scanned += size
            cov.partial += int(len(rows) >= self.max_documents)
            cov.test_values += result.test_values
            cov.suppressed += result.suppressed
            cov.redaction_markers += result.redaction_markers
            cov.formats["json"] = cov.formats.get("json", 0) + 1

            def resource(column: str, table: str = name) -> dict[str, Any]:
                out = store_field_resource(
                    service=self.kind,
                    store=t.database,
                    table=table,
                    field=column,
                    read_by="query",
                )
                out.update(t.where.fields())
                return out

            store.replace_location(
                f"{self.id}\n{name}",
                column_findings(result, resource, link, now.isoformat(), facts=self.facts),
            )
            after = name
        cov.pass_complete, cov.backlog = done, not done
        return SourceRun(cov, {"after": None if done else after})
