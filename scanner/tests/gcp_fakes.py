"""A stubbed Google Cloud for the Google Cloud scanner's tests. Every value is made up.

The scanner calls Google's REST APIs through one authorized session; `Cloud`
is that session. It answers the calls the scanner makes, and nothing more:
Cloud Asset Inventory's `searchAllResources` (two results to a page), Cloud
Storage's JSON API (paged object listings, ranged media reads, metadata, and
the job's own state writes), and Pub/Sub's `publish`. A test adds a route for
any other API (`Cloud.route`).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_gcp.clients import Clients
from sensitive_data_gcp.config import Settings, read_settings

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
ORG = "123456789012"
PROJECT = "acme-data"
PROJECT_NUMBER = "421000000001"
OTHER = "acme-pay"
OTHER_NUMBER = "421000000002"
STATE_BUCKET = "acme-sds-state"
TOKEN = "made-up-token"  # noqa: S105 - a made-up access token
KEY = "projects/acme-kms/locations/us/keyRings/lake/cryptoKeys/lake-key"


class Resp:
    """What `requests` returns: a status, a body, and `json()`."""

    def __init__(self, status: int = 200, body: Any = None, content: bytes | None = None) -> None:
        self.status_code = status
        if content is not None:
            self.content = content
        elif body is None:
            self.content = b""
        else:
            self.content = json.dumps(body).encode()
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return json.loads(self.content)


def error(
    status: int,
    code: str | None = None,
    *,
    reason: str | None = None,
    message: str = "",
) -> Resp:
    """A Google API error: `status`, and a message that may quote anything."""
    err: dict[str, Any] = {"code": status, "message": message or f"failed {status}"}
    if code:
        err["status"] = code
    if reason:
        err["errors"] = [{"reason": reason, "message": message}]
        err["details"] = [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}]
    return Resp(status, {"error": err})


def vpc_denied(message: str = "Request is prohibited by organization's policy.") -> Resp:
    return error(403, "PERMISSION_DENIED", reason="SECURITY_POLICY_VIOLATED", message=message)


@dataclass
class Obj:
    data: bytes
    updated: dt.datetime = NOW - dt.timedelta(days=1)
    generation: str = "1700000000000001"
    kms: str | None = None
    csek: bool = False
    storage_class: str = "STANDARD"
    fail: Resp | None = None
    md5: bool = False  # the listing gives md5Hash (#67 part 5)


@dataclass
class Bucket:
    objects: dict[str, Obj] = field(default_factory=dict)
    per_page: int = 1000
    list_fail: Resp | None = None


def bucket_row(
    name: str,
    *,
    project: str = PROJECT,
    number: str = PROJECT_NUMBER,
    kms: str | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """A Cloud Asset Inventory result for a bucket."""
    row: dict[str, Any] = {
        "name": f"//storage.googleapis.com/{name}",
        "assetType": "storage.googleapis.com/Bucket",
        "project": f"projects/{number}",
        "displayName": name,
        "location": "us",
        "labels": labels or {},
        "parentFullResourceName": f"//cloudresourcemanager.googleapis.com/projects/{number}",
    }
    if kms:
        row["kmsKeys"] = [kms]
    return row


def project_row(project: str, number: str) -> dict[str, Any]:
    return {
        "name": f"//cloudresourcemanager.googleapis.com/projects/{number}",
        "assetType": "cloudresourcemanager.googleapis.com/Project",
        "project": f"projects/{number}",
        "displayName": project,
        "additionalAttributes": {"projectId": project},
    }


@dataclass
class Req:
    """One call the scanner made: what a route's handler is given."""

    method: str
    url: str
    query: dict[str, Any]
    body: Any = None
    data: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


Handler = Callable[[Req], Resp]


class Cloud:
    """An authorized session's `request`, answered from made-up resources."""

    def __init__(self) -> None:
        self.assets: dict[str, list[dict[str, Any]]] = {
            "cloudresourcemanager.googleapis.com/Project": [
                project_row(PROJECT, PROJECT_NUMBER),
                project_row(OTHER, OTHER_NUMBER),
            ]
        }
        self.asset_fail: dict[str, Resp] = {}
        self.buckets: dict[str, Bucket] = {STATE_BUCKET: Bucket()}
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.writes: list[tuple[str, str]] = []
        self.published: list[dict[str, Any]] = []
        self.routes: list[tuple[str, re.Pattern[str], Handler]] = []
        self.page = 2
        self.credentials = Credentials()

    def route(self, method: str, pattern: str, handler: Handler) -> None:
        """Answer `method` on URLs matching `pattern` (a regex) with `handler`."""
        self.routes.append((method, re.compile(pattern), handler))

    def bucket(self, name: str) -> Bucket:
        return self.buckets.setdefault(name, Bucket())

    def state(self, name: str) -> Any:
        return json.loads(self.buckets[STATE_BUCKET].objects[name].data)

    # ------------------------------------------------------------------ the session

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        json: Any = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Resp:
        query: dict[str, Any] = {}
        for k, v in params.items() if isinstance(params, dict) else params or []:
            query.setdefault(k, v)
        self.requests.append((method, url, query))
        for m, pattern, handler in self.routes:
            if m == method and pattern.search(url):
                return handler(Req(method, url, query, json, data, headers or {}))
        parts = urllib.parse.urlsplit(url)
        path = parts.path
        if parts.hostname == "cloudasset.googleapis.com":
            return self._assets(path, query)
        if parts.hostname == "pubsub.googleapis.com" and path.endswith(":publish"):
            self.published.extend(json["messages"])
            return Resp(200, {"messageIds": ["1"]})
        if parts.hostname == "storage.googleapis.com":
            return self._storage(method, path, query, data, headers or {})
        return error(404, "NOT_FOUND", message=f"no route for {url}")

    def _assets(self, path: str, query: dict[str, Any]) -> Resp:
        kind = str(query.get("assetTypes"))
        if kind in self.asset_fail:
            return self.asset_fail[kind]
        rows = self.assets.get(kind, [])
        start = int(query.get("pageToken") or 0)
        end = start + self.page
        body: dict[str, Any] = {"results": rows[start:end]}
        if end < len(rows):
            body["nextPageToken"] = str(end)
        return Resp(200, body)

    def _storage(
        self,
        method: str,
        path: str,
        query: dict[str, Any],
        data: bytes | None,
        headers: dict[str, str],
    ) -> Resp:
        m = re.match(r"^/upload/storage/v1/b/([^/]+)/o$", path)
        if m and method == "POST":
            bucket = self.bucket(urllib.parse.unquote(m[1]))
            name = str(query["name"])
            if query.get("ifGenerationMatch") == "0" and name in bucket.objects:
                return error(412, reason="conditionNotMet", message=f"{name} exists")
            bucket.objects[name] = Obj(bytes(data or b""), updated=NOW - dt.timedelta(minutes=1))
            self.writes.append((urllib.parse.unquote(m[1]), name))
            return Resp(200, {"name": name})
        m = re.match(r"^/storage/v1/b/([^/]+)/o$", path)
        if m and method == "GET":
            return self._list(urllib.parse.unquote(m[1]), query)
        m = re.match(r"^/storage/v1/b/([^/]+)/o/(.+)$", path)
        if m is None:
            return error(404, "NOT_FOUND")
        found = self.buckets.get(urllib.parse.unquote(m[1]))
        name = urllib.parse.unquote(m[2])
        obj = found.objects.get(name) if found else None
        if method == "DELETE":
            if found is None or obj is None:
                return error(404, reason="notFound", message=f"no object {name}")
            del found.objects[name]
            self.writes.append((urllib.parse.unquote(m[1]), name))
            return Resp(204)
        if obj is None:
            return error(404, reason="notFound", message=f"No such object: {name}")
        if obj.fail is not None:
            return obj.fail
        if query.get("alt") == "media":
            rng = re.match(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
            if rng:
                return Resp(206, content=obj.data[int(rng[1]) : int(rng[2]) + 1])
            return Resp(200, content=obj.data)
        return Resp(
            200,
            {"name": name, "updated": obj.updated.isoformat(), "generation": obj.generation},
        )

    def _list(self, name: str, query: dict[str, Any]) -> Resp:
        bucket = self.buckets.get(name)
        if bucket is None:
            return error(404, reason="notFound", message=f"no bucket {name}")
        if bucket.list_fail is not None:
            return bucket.list_fail
        prefix = str(query.get("prefix") or "")
        items = []
        for key, o in sorted(bucket.objects.items()):
            if prefix and not key.startswith(prefix):
                continue
            item: dict[str, Any] = {
                "name": key,
                "size": str(len(o.data)),
                "updated": o.updated.isoformat().replace("+00:00", "Z"),
                "generation": o.generation,
                "storageClass": o.storage_class,
            }
            if o.kms:
                item["kmsKeyName"] = o.kms + "/cryptoKeyVersions/3"
            if o.csek:
                item["customerEncryption"] = {"encryptionAlgorithm": "AES256", "keySha256": "x"}
            if o.md5:
                digest = hashlib.md5(o.data, usedforsecurity=False).digest()
                item["md5Hash"] = base64.b64encode(digest).decode()
            items.append(item)
        per = min(bucket.per_page, int(query.get("maxResults") or bucket.per_page))
        start = int(query.get("pageToken") or 0)
        end = start + per
        body: dict[str, Any] = {"items": items[start:end]}
        if end < len(items):
            body["nextPageToken"] = str(end)
        return Resp(200, body)

    def clients(self, drivers: dict[str, Any] | None = None) -> Clients:
        out = Clients(credentials=self.credentials, session=self, sleep=lambda s: None)
        out.drivers.update(drivers or {})
        return out


class Credentials:
    """The job's service account: made-up tokens, and the scopes they were asked for."""

    token = TOKEN
    service_account_email = "sds-scanner@acme-sds.iam.gserviceaccount.com"

    def __init__(self) -> None:
        self.scopes: list[list[str]] = []

    def with_scopes(self, scopes: list[str]) -> Credentials:
        self.scopes.append(list(scopes))
        return self

    def refresh(self, request: Any) -> None:
        return None


def settings(**env: str) -> Settings:
    base = {
        "SCANNER_SITE": "acme-org",
        "GCP_ORGANIZATION": ORG,
        "STATE_BUCKET": f"gs://{STATE_BUCKET}",
    }
    return read_settings({**base, **env})


# ------------------------------------------------------------------ BigQuery


def dataset_row(project: str, dataset: str, number: str = PROJECT_NUMBER) -> dict[str, Any]:
    return {
        "name": f"//bigquery.googleapis.com/projects/{project}/datasets/{dataset}",
        "assetType": "bigquery.googleapis.com/Dataset",
        "project": f"projects/{number}",
        "displayName": dataset,
    }


def bq_cells(fields: list[dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    """A row as tabledata.list sends it: `{"f": [{"v": ...}]}`, strings for scalars."""

    def one(f: dict[str, Any], v: Any) -> Any:
        if v is None:
            return None
        if f.get("mode") == "REPEATED":
            return [{"v": one({**f, "mode": "NULLABLE"}, x)} for x in v]
        if f.get("type") == "RECORD":
            return bq_cells(f["fields"], v)
        return str(v)

    return {"f": [{"v": one(f, row.get(f["name"]))} for f in fields]}


@dataclass
class BqTable:
    fields: list[dict[str, Any]]
    rows: list[dict[str, Any]] = field(default_factory=list)
    type: str = "TABLE"
    kms: str | None = None
    policies: list[dict[str, Any]] = field(default_factory=list)
    modified: str = "1759100000000"
    fail: Resp | None = None


@dataclass
class BqDataset:
    tables: dict[str, BqTable] = field(default_factory=dict)
    access: list[dict[str, Any]] = field(default_factory=list)
    kms: str | None = None
    fail: Resp | None = None


class BigQuery:
    """BigQuery's REST API for `Cloud`: datasets, tables, row access policies, tabledata."""

    def __init__(self, cloud: Cloud) -> None:
        self.datasets: dict[tuple[str, str], BqDataset] = {}
        self.data_calls: list[dict[str, Any]] = []
        cloud.route("GET", r"^https://bigquery\.googleapis\.com/", self.answer)

    def answer(self, req: Req) -> Resp:
        query = req.query
        path = urllib.parse.urlsplit(req.url).path.removeprefix("/bigquery/v2/")
        parts = [urllib.parse.unquote(p) for p in path.split("/")]
        ds = self.datasets.get((parts[1], parts[3])) if len(parts) >= 4 else None
        if ds is None:
            return error(404, reason="notFound", message=f"Not found: {path}")
        if ds.fail is not None:
            return ds.fail
        if len(parts) == 4:
            meta: dict[str, Any] = {"access": ds.access}
            if ds.kms:
                meta["defaultEncryptionConfiguration"] = {"kmsKeyName": ds.kms}
            return Resp(200, meta)
        if len(parts) == 5:
            tables = [
                {"tableReference": {"tableId": t}, "type": tb.type}
                for t, tb in sorted(ds.tables.items())
            ]
            return Resp(200, {"tables": tables})
        tb = ds.tables.get(parts[5])
        if tb is None:
            return error(404, reason="notFound", message=f"Not found: {parts[5]}")
        if tb.fail is not None:
            return tb.fail
        if len(parts) == 6:
            meta = {
                "schema": {"fields": tb.fields},
                "type": tb.type,
                "lastModifiedTime": tb.modified,
                "numBytes": "2048",
            }
            if tb.kms:
                meta["encryptionConfiguration"] = {"kmsKeyName": tb.kms}
            return Resp(200, meta)
        if parts[6] == "rowAccessPolicies":
            return Resp(200, {"rowAccessPolicies": tb.policies} if tb.policies else {})
        self.data_calls.append(query)
        selected = str(query.get("selectedFields") or "")
        fields = [f for f in tb.fields if not selected or f["name"] in selected.split(",")]
        n = int(query.get("maxResults") or 100)
        return Resp(200, {"rows": [bq_cells(fields, r) for r in tb.rows[:n]]})


# ------------------------------------------------------------------ Cloud SQL and AlloyDB

SA = "sds-scanner@acme-sds.iam.gserviceaccount.com"
CA = "-----BEGIN CERTIFICATE-----\nMADEUP\n-----END CERTIFICATE-----\n"


def sql_row(instance: str, project: str = PROJECT, number: str = PROJECT_NUMBER) -> dict[str, Any]:
    return {
        "name": f"//cloudsql.googleapis.com/projects/{project}/instances/{instance}",
        "assetType": "sqladmin.googleapis.com/Instance",
        "project": f"projects/{number}",
        "displayName": instance,
    }


def sql_instance(
    version: str,
    *,
    iam: bool = True,
    private: bool = False,
    state: str = "RUNNABLE",
    kms: str | None = None,
) -> dict[str, Any]:
    flag = (
        "cloudsql_iam_authentication"
        if version.startswith("MYSQL")
        else "cloudsql.iam_authentication"
    )
    meta: dict[str, Any] = {
        "databaseVersion": version,
        "state": state,
        "settings": {
            "activationPolicy": "ALWAYS",
            "databaseFlags": [{"name": flag, "value": "on" if iam else "off"}],
            "userLabels": {"team": "data"},
        },
        "ipAddresses": [{"type": "PRIVATE" if private else "PRIMARY", "ipAddress": "10.0.0.5"}],
        "serverCaCert": {"cert": CA},
    }
    if kms:
        meta["diskEncryptionConfiguration"] = {"kmsKeyName": kms}
    return meta


class Databases:
    """The Cloud SQL Admin and AlloyDB APIs for `Cloud`: instances, databases, clusters."""

    def __init__(self, cloud: Cloud) -> None:
        self.instances: dict[tuple[str, str], dict[str, Any] | Resp] = {}
        self.databases: dict[tuple[str, str], list[str]] = {}
        self.clusters: dict[str, dict[str, Any]] = {}
        self.cluster_instances: dict[str, list[dict[str, Any]]] = {}
        self.certificates: list[str] = []
        cloud.route("GET", r"^https://sqladmin\.googleapis\.com/", self.sql)
        cloud.route("GET", r"^https://alloydb\.googleapis\.com/", self.alloy)
        cloud.route("POST", r"^https://alloydb\.googleapis\.com/", self.alloy_post)

    def sql(self, req: Req) -> Resp:
        parts = [urllib.parse.unquote(p) for p in urllib.parse.urlsplit(req.url).path.split("/")]
        project, instance = parts[3], parts[5]
        got = self.instances.get((project, instance))
        if got is None:
            return error(404, "NOT_FOUND", message=f"no instance {instance}")
        if isinstance(got, Resp):
            return got
        if parts[-1] == "databases":
            names = self.databases.get((project, instance), [])
            return Resp(200, {"items": [{"name": n} for n in names]})
        return Resp(200, got)

    def alloy(self, req: Req) -> Resp:
        path = urllib.parse.urlsplit(req.url).path.removeprefix("/v1/")
        if path.endswith("/instances"):
            return Resp(200, {"instances": self.cluster_instances.get(path.rsplit("/", 1)[0], [])})
        got = self.clusters.get(path)
        return Resp(200, got) if got is not None else error(404, "NOT_FOUND")

    def alloy_post(self, req: Req) -> Resp:
        self.certificates.append(req.url)
        return Resp(200, {"caCert": CA, "pemCertificateChain": []})


# ------------------------------------------------------ Firestore, Datastore, Spanner, Bigtable


def fs_value(v: Any) -> dict[str, Any]:
    """A plain value as a Firestore (or Datastore) `Value`."""
    if isinstance(v, bytes):
        return {"bytesValue": base64.b64encode(v).decode()}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {k: fs_value(x) for k, x in v.items()}}}
    if isinstance(v, list):
        return {"arrayValue": {"values": [fs_value(x) for x in v]}}
    if v is None:
        return {"nullValue": None}
    return {"stringValue": str(v)}


def asset(kind: str, name: str, number: str = PROJECT_NUMBER) -> dict[str, Any]:
    return {"name": name, "assetType": kind, "project": f"projects/{number}"}


def b64(v: Any) -> str:
    return base64.b64encode(v if isinstance(v, bytes) else str(v).encode()).decode()


class NoSql:
    """Firestore, Datastore, Spanner and Bigtable's REST APIs for `Cloud`."""

    def __init__(self, cloud: Cloud) -> None:
        # Firestore databases: (project, database) -> {"type", "kms", "collections": {name: docs}}
        self.firestore: dict[tuple[str, str], dict[str, Any]] = {}
        # Spanner databases: path -> {"dialect", "kms", "tables": {name: rows}, "bytes": col}
        self.spanner: dict[str, dict[str, Any]] = {}
        # Bigtable tables: path -> rows {key: {"family:qualifier": value}}
        self.bigtable: dict[str, dict[str, dict[str, Any]]] = {}
        self.bigtable_keys: dict[str, str] = {}
        self.sql: list[dict[str, Any]] = []
        self.sessions: list[str] = []
        self.deleted: list[str] = []
        self.queries: list[dict[str, Any]] = []
        self.fail: dict[str, Resp] = {}
        cloud.route("GET", r"^https://firestore\.googleapis\.com/", self.firestore_get)
        cloud.route("POST", r"^https://firestore\.googleapis\.com/", self.firestore_post)
        cloud.route("POST", r"^https://datastore\.googleapis\.com/", self.datastore_post)
        cloud.route("GET", r"^https://spanner\.googleapis\.com/", self.spanner_get)
        cloud.route("POST", r"^https://spanner\.googleapis\.com/", self.spanner_post)
        cloud.route("DELETE", r"^https://spanner\.googleapis\.com/", self.spanner_delete)
        cloud.route("GET", r"^https://bigtableadmin\.googleapis\.com/", self.bigtable_admin)
        cloud.route("POST", r"^https://bigtable\.googleapis\.com/", self.bigtable_read)

    def _path(self, req: Req) -> list[str]:
        path = urllib.parse.urlsplit(req.url).path
        return [urllib.parse.unquote(p) for p in path.split("/")]

    def _failed(self, req: Req) -> Resp | None:
        return next((r for k, r in self.fail.items() if k in urllib.parse.unquote(req.url)), None)

    # ------------------------------------------------------------------ Firestore

    def firestore_get(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        parts = self._path(req)  # /v1/projects/p/databases/d
        db = self.firestore.get((parts[3], parts[5]))
        if db is None:
            return error(404, "NOT_FOUND")
        meta: dict[str, Any] = {"type": db["type"]}
        if db.get("kms"):
            meta["cmekConfig"] = {"kmsKeyName": db["kms"]}
        return Resp(200, meta)

    def firestore_post(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        parts = self._path(req)
        db = self.firestore[(parts[3], parts[5])]
        self.queries.append(req.body)
        if req.url.endswith(":listCollectionIds"):
            return Resp(200, {"collectionIds": sorted(db["collections"])})
        name = req.body["structuredQuery"]["from"][0]["collectionId"]
        limit = req.body["structuredQuery"]["limit"]
        docs = db["collections"][name][:limit]
        return Resp(
            200,
            [
                {"document": {"name": f"x/{i}", "fields": {k: fs_value(v) for k, v in d.items()}}}
                for i, d in enumerate(docs)
            ]
            or [{"readTime": "2026-09-29T00:00:00Z"}],
        )

    def datastore_post(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        project = self._path(req)[3].removesuffix(":runQuery")
        database = req.body.get("databaseId") or "(default)"
        db = self.firestore[(project, database)]
        self.queries.append(req.body)
        kind = req.body["query"]["kind"][0]["name"]
        limit = req.body["query"]["limit"]
        if kind == "__kind__":
            names = [*sorted(db["collections"]), "__Stat_Total__"]
            results: list[dict[str, Any]] = [
                {"entity": {"key": {"path": [{"kind": "__kind__", "name": n}]}}} for n in names
            ]
        else:
            results = [
                {"entity": {"properties": {k: fs_value(v) for k, v in e.items()}}}
                for e in db["collections"][kind][:limit]
            ]
        return Resp(200, {"batch": {"entityResults": results}})

    # ------------------------------------------------------------------ Spanner

    def _spanner_db(self, parts: list[str]) -> tuple[str, dict[str, Any]] | None:
        path = "/".join(parts[2:8])
        db = self.spanner.get(path)
        return (path, db) if db is not None else None

    def spanner_get(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        found = self._spanner_db(self._path(req))
        if found is None:
            return error(404, "NOT_FOUND")
        db = found[1]
        meta: dict[str, Any] = {"state": db.get("state", "READY"), "databaseDialect": db["dialect"]}
        if db.get("kms"):
            meta["encryptionConfig"] = {"kmsKeyName": db["kms"]}
        return Resp(200, meta)

    def spanner_post(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        parts = self._path(req)
        if parts[-1] == "sessions":
            name = "/".join(parts[2:]) + f"/s{len(self.sessions)}"
            self.sessions.append(name)
            return Resp(200, {"name": name})
        found = self._spanner_db(parts)
        assert found is not None and parts[-1].endswith(":executeSql")
        db = found[1]
        self.sql.append(req.body)
        sql = req.body["sql"]
        if "information_schema.tables" in sql:
            schema = "public" if db["dialect"] == "POSTGRESQL" else ""
            names = ["table_schema", "table_name"]
            rows = [[schema, t] for t in sorted(db["tables"])]
        else:
            m = re.search(r'[`"]([^`"]+)[`"] LIMIT (\d+)$', sql)
            assert m, sql
            data = db["tables"][m[1]][: int(m[2])]
            names = list(dict.fromkeys(k for r in data for k in r))
            rows = [[r.get(n) for n in names] for r in data]
        fields = [
            {"name": n, "type": {"code": "BYTES" if n == db.get("bytes") else "STRING"}}
            for n in names
        ]
        return Resp(200, {"metadata": {"rowType": {"fields": fields}}, "rows": rows})

    def spanner_delete(self, req: Req) -> Resp:
        self.deleted.append(urllib.parse.urlsplit(req.url).path)
        return Resp(200, {})

    # ------------------------------------------------------------------ Bigtable

    def bigtable_admin(self, req: Req) -> Resp:
        parts = self._path(req)  # /v2/projects/p/instances/i/clusters
        key = self.bigtable_keys.get("/".join(parts[2:6]))
        cluster: dict[str, Any] = {"name": "c1"}
        if key:
            cluster["encryptionConfig"] = {"kmsKeyName": key}
        return Resp(200, {"clusters": [cluster]})

    def bigtable_read(self, req: Req) -> Resp:
        if (got := self._failed(req)) is not None:
            return got
        path = urllib.parse.unquote(urllib.parse.urlsplit(req.url).path)
        table = path.removeprefix("/v2/").removesuffix(":readRows")
        self.queries.append(req.body)
        rows = self.bigtable[table]
        chunks: list[dict[str, Any]] = []
        for key, cells in list(rows.items())[: int(req.body["rowsLimit"])]:
            for i, (column, v) in enumerate(cells.items()):
                family, qualifier = column.split(":", 1)
                chunk: dict[str, Any] = {
                    "familyName": family,
                    "qualifier": b64(qualifier),
                    "timestampMicros": "1",
                    "value": b64(v),
                }
                if i == 0:
                    chunk["rowKey"] = b64(key)
                if i == len(cells) - 1:
                    chunk["commitRow"] = True
                chunks.append(chunk)
        # Two messages, as the stream sends them.
        half = len(chunks) // 2
        return Resp(200, [{"chunks": chunks[:half]}, {"chunks": chunks[half:]}])


# ------------------------------------------------------ Logging, Pub/Sub, snapshots, secrets


class Ops:
    """Cloud Logging, Pub/Sub subscriptions, Compute snapshots and Secret Manager for `Cloud`."""

    def __init__(self, cloud: Cloud) -> None:
        # Logging: project -> {log name: entries}; the _Default bucket's key by project.
        self.logs: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self.log_keys: dict[str, str] = {}
        self.entries_calls: list[dict[str, Any]] = []
        self.quota_after: int | None = None
        # Pub/Sub: project -> subscriptions
        self.subscriptions: dict[str, list[dict[str, Any]] | Resp] = {}
        # Compute: project -> snapshots
        self.snapshots: dict[str, list[dict[str, Any]] | Resp] = {}
        # Secret Manager: (project, secret) -> value bytes, or an error; and its record.
        self.secrets: dict[tuple[str, str], bytes | Resp] = {}
        self.secret_meta: dict[tuple[str, str], dict[str, Any]] = {}
        self.accessed: list[str] = []
        cloud.route("GET", r"^https://logging\.googleapis\.com/", self.logging_get)
        cloud.route("POST", r"^https://logging\.googleapis\.com/v2/entries:list", self.entries)
        cloud.route("GET", r"^https://pubsub\.googleapis\.com/", self.pubsub)
        cloud.route("GET", r"^https://compute\.googleapis\.com/", self.compute)
        cloud.route("GET", r"^https://secretmanager\.googleapis\.com/", self.secret)

    def _parts(self, req: Req) -> list[str]:
        path = urllib.parse.urlsplit(req.url).path
        return [urllib.parse.unquote(p) for p in path.split("/")]

    def logging_get(self, req: Req) -> Resp:
        parts = self._parts(req)  # /v2/projects/p/logs | /v2/projects/p/locations/-/buckets
        project = parts[3]
        if parts[-1] == "buckets":
            bucket: dict[str, Any] = {
                "name": f"projects/{project}/locations/global/buckets/_Default"
            }
            if project in self.log_keys:
                bucket["cmekSettings"] = {"kmsKeyName": self.log_keys[project]}
            return Resp(200, {"buckets": [bucket]})
        names = [
            f"projects/{project}/logs/{urllib.parse.quote(n, safe='')}"
            for n in self.logs.get(project, {})
        ]
        return Resp(200, {"logNames": names})

    def entries(self, req: Req) -> Resp:
        if self.quota_after is not None and len(self.entries_calls) >= self.quota_after:
            return error(429, "RESOURCE_EXHAUSTED", message="Quota exceeded for reads")
        self.entries_calls.append(req.body)
        project = req.body["resourceNames"][0].split("/", 1)[1]
        m = re.match(r'logName="([^"]+)"', req.body["filter"])
        assert m, req.body["filter"]
        name = urllib.parse.unquote(m[1].rsplit("/logs/", 1)[1])
        found = self.logs[project][name][: req.body["pageSize"]]
        return Resp(200, {"entries": found})

    def pubsub(self, req: Req) -> Resp:
        got = self.subscriptions.get(self._parts(req)[3], [])
        return got if isinstance(got, Resp) else Resp(200, {"subscriptions": got})

    def compute(self, req: Req) -> Resp:
        got = self.snapshots.get(self._parts(req)[4], [])
        return got if isinstance(got, Resp) else Resp(200, {"items": got})

    def secret(self, req: Req) -> Resp:
        parts = self._parts(req)  # /v1/projects/p/secrets/s[/versions/latest:access]
        key = (parts[3], parts[5])
        if len(parts) == 6:
            return Resp(200, self.secret_meta.get(key, {"replication": {"automatic": {}}}))
        self.accessed.append(parts[5])
        got = self.secrets.get(key)
        if got is None:
            return error(404, "NOT_FOUND")
        if isinstance(got, Resp):
            return got
        return Resp(200, {"payload": {"data": base64.b64encode(got).decode()}})
