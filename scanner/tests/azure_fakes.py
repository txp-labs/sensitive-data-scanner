"""Stubbed Azure SDK clients for the Azure scanner's tests. Every value is made up.

Each fake has the surface of the SDK object the scanner calls, and nothing
more: Resource Graph's `resources(QueryRequest)`, a small Resource Manager
client (`list`, `get`), and the Blob service's `ContainerClient` (paged
`list_blobs`, ranged `download_blob`, and the job's own state writes).
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from sensitive_data_azure.clients import Clients
from sensitive_data_azure.config import Settings, read_settings

NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)
SUB_A = "11111111-2222-3333-4444-555555555555"
SUB_B = "66666666-7777-8888-9999-aaaaaaaaaaaa"
STATE_URL = "https://sdsstate.blob.core.windows.net/scanner"
TOKEN = "made-up-token"  # noqa: S105 - a made-up Entra token


class AzureError(Exception):
    """What azure-core raises: an `error_code`, and a message that may quote anything."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.error_code = code


def account_id(sub: str, group: str, name: str) -> str:
    storage = "providers/Microsoft.Storage/storageAccounts"
    return f"/subscriptions/{sub}/resourceGroups/{group}/{storage}/{name}"


def account_row(
    name: str,
    *,
    sub: str = SUB_A,
    group: str = "rg-data",
    kind: str = "StorageV2",
    hns: bool = False,
    key_source: str = "Microsoft.Storage",
    vault: str = "",
    key_name: str = "",
    public: str = "Enabled",
    default_action: str = "Allow",
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": account_id(sub, group, name),
        "name": name,
        "subscriptionId": sub,
        "resourceGroup": group,
        "kind": kind,
        "tags": tags or {},
        "blobEndpoint": "" if kind == "FileStorage" else f"https://{name}.blob.core.windows.net/",
        "tableEndpoint": "" if kind == "FileStorage" else f"https://{name}.table.core.windows.net/",
        "queueEndpoint": "" if kind == "FileStorage" else f"https://{name}.queue.core.windows.net/",
        "fileEndpoint": f"https://{name}.file.core.windows.net/",
        "tableKeyType": "Service",
        "queueKeyType": "Service",
        "hns": hns,
        "keySource": key_source,
        "keyVaultUri": vault,
        "keyName": key_name,
        "publicNetworkAccess": public,
        "defaultAction": default_action,
    }


class Graph:
    """Resource Graph: rows by a word in the query, served two to a page with skip tokens."""

    def __init__(self, tables: dict[str, list[dict[str, Any]]], page: int = 2) -> None:
        self.tables = tables
        self.page = page
        self.requests: list[Any] = []
        self.fail: Exception | None = None

    def resources(self, request: Any) -> Any:
        self.requests.append(request)
        if self.fail is not None:
            raise self.fail
        rows: list[dict[str, Any]] = []
        for word, table in self.tables.items():
            if word in request.query:
                rows = table
        start = int(request.options.skip_token or 0)
        end = start + self.page
        return SimpleNamespace(
            data=rows[start:end], skip_token=str(end) if end < len(rows) else None
        )


class Arm:
    """Resource Manager: lists (`paths`) and objects (`objects`) by path; a path mapped to an
    exception raises it."""

    def __init__(
        self,
        paths: dict[str, list[dict[str, Any]] | Exception] | None = None,
        objects: dict[str, dict[str, Any] | Exception] | None = None,
    ) -> None:
        self.paths = paths or {}
        self.objects = objects or {}
        self.calls: list[str] = []

    def list(self, path: str, api_version: str) -> Iterator[dict[str, Any]]:
        self.calls.append(path)
        got = self.paths.get(path, [])
        if isinstance(got, Exception):
            raise got
        yield from got

    def get(self, path: str, api_version: str) -> dict[str, Any]:
        self.calls.append(path)
        got = self.objects.get(path, {})
        if isinstance(got, Exception):
            raise got
        return got


@dataclass
class Blob:
    data: bytes
    modified: dt.datetime = NOW - dt.timedelta(days=1)
    version_id: str | None = None
    encryption_scope: str | None = None
    blob_tier: str = "Hot"
    cpk: bool = False
    fail: Exception | None = None


class Downloader:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def readall(self) -> bytes:
        return self._data


class Pages:
    """An azure-core page iterator: pages of BlobProperties, and the next page's token."""

    def __init__(self, names: list[Any], per_page: int, token: str | None) -> None:
        self.items = names
        self.per_page = per_page
        self.at = int(token or 0)
        self.continuation_token: str | None = token

    def __iter__(self) -> Pages:
        return self

    def __next__(self) -> Iterator[Any]:
        if self.at >= len(self.items) or (self.continuation_token is None and self.at > 0):
            raise StopIteration
        page = self.items[self.at : self.at + self.per_page]
        self.at += self.per_page
        self.continuation_token = str(self.at) if self.at < len(self.items) else None
        return iter(page)


class Paged:
    def __init__(self, items: list[Any], per_page: int, fail: Exception | None) -> None:
        self.items = items
        self.per_page = per_page
        self.fail = fail

    def by_page(self, continuation_token: str | None = None) -> Pages:
        if self.fail is not None:
            raise self.fail
        return Pages(self.items, self.per_page, continuation_token)


class Container:
    """A `ContainerClient`: its blobs, and what was downloaded and written."""

    def __init__(self, blobs: dict[str, Blob] | None = None, per_page: int = 1000) -> None:
        self.blobs = blobs or {}
        self.per_page = per_page
        self.list_fail: Exception | None = None
        self.downloads: list[tuple[str, int, int]] = []
        self.written: dict[str, bytes] = {}
        self.writes: list[str] = []

    def list_blobs(self, name_starts_with: str | None = None, **kwargs: Any) -> Paged:
        self.per_page = min(self.per_page, int(kwargs.get("results_per_page") or self.per_page))
        props = [
            SimpleNamespace(
                name=name,
                size=len(b.data),
                last_modified=b.modified,
                version_id=b.version_id,
                encryption_scope=b.encryption_scope,
                blob_tier=b.blob_tier,
                encryption_key_sha256="made-up-sha" if b.cpk else None,
            )
            for name, b in sorted(self.blobs.items())
            if not name_starts_with or name.startswith(name_starts_with)
        ]
        return Paged(props, self.per_page, self.list_fail)

    def download_blob(
        self, name: str, offset: int | None = None, length: int | None = None, **kw: Any
    ) -> Downloader:
        if name in self.written and name not in self.blobs:
            return Downloader(self.written[name])
        b = self.blobs.get(name)
        if b is None:
            raise AzureError("BlobNotFound", f"no blob {name}")
        if b.fail is not None:
            raise b.fail
        start = offset or 0
        end = len(b.data) if length is None else start + length
        self.downloads.append((name, start, end))
        return Downloader(b.data[start:end])

    def upload_blob(self, name: str, data: bytes, overwrite: bool = False, **kw: Any) -> None:
        if not overwrite and name in self.written:
            raise AzureError("BlobAlreadyExists", f"{name} exists")
        self.written[name] = bytes(data)
        self.writes.append(name)

    def delete_blob(self, name: str, **kw: Any) -> None:
        self.written.pop(name, None)

    def get_blob_client(self, name: str) -> Any:
        container = self

        class Client:
            def get_blob_properties(self) -> Any:
                if name in container.written:
                    return SimpleNamespace(last_modified=NOW - dt.timedelta(minutes=1))
                if name not in container.blobs:
                    raise AzureError("BlobNotFound", f"no blob {name}")
                return SimpleNamespace(last_modified=container.blobs[name].modified)

        return Client()

    def json(self, name: str) -> Any:
        return json.loads(self.written[name])


class Service:
    """A `BlobServiceClient` for one account."""

    def __init__(self, containers: dict[str, Container]) -> None:
        self.containers = containers

    def get_container_client(self, name: str) -> Container:
        return self.containers.setdefault(name, Container())


class Credential:
    """A managed identity's credential: made-up tokens, and the audiences asked for."""

    def __init__(self) -> None:
        self.scopes: list[str] = []

    def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        self.scopes.extend(scopes)
        return SimpleNamespace(token=TOKEN, expires_on=0)


@dataclass
class Tenant:
    """The fakes behind one test's `Clients`."""

    graph: Graph
    arm: Arm = field(default_factory=Arm)
    services: dict[str, Service] = field(default_factory=dict)
    drivers: dict[str, Any] = field(default_factory=dict)
    credential: Credential = field(default_factory=Credential)

    def clients(self) -> Clients:
        _ = self.state  # the job's own container always exists
        made: dict[tuple[str, str], Any] = {
            ("resourcegraph", ""): self.graph,
            ("arm", ""): self.arm,
        }
        for account, svc in self.services.items():
            made[("blob", f"https://{account}.blob.core.windows.net/")] = svc
        for module, driver in self.drivers.items():
            made[("driver", module)] = driver
        return Clients(credential=self.credential, made=made)

    def container(self, account: str, name: str) -> Container:
        return self.services.setdefault(account, Service({})).get_container_client(name)

    @property
    def state(self) -> Container:
        return self.container("sdsstate", "scanner")


def settings(**env: str) -> Settings:
    base = {
        "SCANNER_SITE": "mg-contoso",
        "AZURE_MANAGEMENT_GROUP": "mg-contoso",
        "STATE_CONTAINER_URL": STATE_URL,
    }
    return read_settings({**base, **env})


def containers(*names: str) -> list[dict[str, Any]]:
    return [
        {"name": n, "properties": {"defaultEncryptionScope": "$account-encryption-key"}}
        for n in names
    ]


# ------------------------------------------------------------------ Azure Files


@dataclass
class File:
    data: bytes
    modified: dt.datetime = NOW - dt.timedelta(days=1)
    fail: Exception | None = None


class Share:
    """A `ShareClient` over REST: directories, files, ranged downloads; and what it was
    asked. It has no method that writes."""

    def __init__(self, files: dict[str, File] | None = None) -> None:
        self.files = files or {}
        self.list_fail: Exception | None = None
        self.downloads: list[tuple[str, int, int]] = []
        self.listed: list[tuple[str, Any]] = []

    def get_directory_client(self, directory: str) -> Any:
        share = self

        class Directory:
            def list_directories_and_files(self, **kwargs: Any) -> list[Any]:
                share.listed.append((directory, kwargs.get("include")))
                if share.list_fail is not None:
                    raise share.list_fail
                prefix = f"{directory}/" if directory else ""
                out: dict[str, Any] = {}
                for path, f in sorted(share.files.items()):
                    if not path.startswith(prefix):
                        continue
                    rest = path[len(prefix) :]
                    head, sep, _ = rest.partition("/")
                    if sep:
                        out.setdefault(head, SimpleNamespace(name=head, is_directory=True))
                    else:
                        out[head] = SimpleNamespace(
                            name=head,
                            is_directory=False,
                            size=len(f.data),
                            last_modified=f.modified,
                        )
                return list(out.values())

        return Directory()

    def get_file_client(self, path: str) -> Any:
        share = self

        class FileClient:
            def download_file(self, offset: int = 0, length: int | None = None) -> Downloader:
                f = share.files.get(path)
                if f is None:
                    raise AzureError("ResourceNotFound", f"no file {path}")
                if f.fail is not None:
                    raise f.fail
                end = len(f.data) if length is None else offset + length
                share.downloads.append((path, offset, end))
                return Downloader(f.data[offset:end])

            def get_file_properties(self) -> Any:
                if path not in share.files:
                    raise AzureError("ResourceNotFound", f"no file {path}")
                return SimpleNamespace(size=len(share.files[path].data))

        return FileClient()


class FileService:
    """A `ShareServiceClient` for one account, and the token intent it was made with."""

    def __init__(self, shares: dict[str, Share]) -> None:
        self.shares = shares

    def get_share_client(self, name: str) -> Share:
        return self.shares.setdefault(name, Share())
