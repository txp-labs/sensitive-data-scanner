"""A stubbed Google Cloud for the Google Cloud scanner's tests. Every value is made up.

The scanner calls Google's REST APIs through one authorized session; `Cloud`
is that session. It answers the calls the scanner makes, and nothing more:
Cloud Asset Inventory's `searchAllResources` (two results to a page), Cloud
Storage's JSON API (paged object listings, ranged media reads, metadata, and
the job's own state writes), and Pub/Sub's `publish`. A test adds a route for
any other API (`Cloud.route`).
"""

from __future__ import annotations

import datetime as dt
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
            items.append(item)
        per = min(bucket.per_page, int(query.get("maxResults") or bucket.per_page))
        start = int(query.get("pageToken") or 0)
        end = start + per
        body: dict[str, Any] = {"items": items[start:end]}
        if end < len(items):
            body["nextPageToken"] = str(end)
        return Resp(200, body)

    def clients(self) -> Clients:
        return Clients(credentials=Credentials(), session=self, sleep=lambda s: None)


class Credentials:
    """The job's service account: made-up tokens."""

    token = TOKEN
    service_account_email = "sds-scanner@acme-sds.iam.gserviceaccount.com"

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
