"""Azure's clients, made on first use and signed by the job's managed identity.

`DefaultAzureCredential` finds the Container Apps job's system-assigned
managed identity (or, for a local run, the developer's `az login`); no key,
connection string or SAS is configured or made. The clients are:

- `resourcegraph`: Azure Resource Graph, which lists every store of a kind
  across the subscriptions of a management group in one query;
- `arm`: a few GETs on Azure Resource Manager (a storage account's containers
  and encryption scopes), with the Reader role;
- `blob`: a storage account's Blob service (Blob Storage and ADLS Gen2), with
  Storage Blob Data Reader;
- `table`, `queue`: a storage account's Table and Queue services, with Storage
  Table Data Reader and Storage Queue Data Reader;
- `files`: a storage account's File service (Azure Files) over REST, with
  Storage File Data Privileged Reader and the backup intent (opt-in);
- `cosmos`: a Cosmos DB for NoSQL account, with its Built-in Data Reader role;
- `logs`: the Log Analytics query API, with Log Analytics Reader;
- `keyvault`: a key vault's secrets, with Key Vault Secrets User (opt-in);
- `driver`: a database driver module, imported only when a database of its
  kind is read.

Tests put stubbed clients in `made` (or give a `factory`); nothing else here
needs Azure.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterator
from typing import Any

from . import __version__

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
USER_AGENT = f"sensitive-data-scanner-azure/{__version__}"
MAX_PAGES = 1000


class ArmError(Exception):
    """A Resource Manager GET failed; `error_code` is Azure's code (never its message)."""

    error_code = "ArmError"
    status_code = 0


class Arm:
    """GETs on Azure Resource Manager: a resource's children, paged by `nextLink`."""

    def __init__(self, credential: Any, endpoint: str = ARM_ENDPOINT) -> None:
        from azure.core import PipelineClient  # noqa: PLC0415 - Azure only when used
        from azure.core.pipeline.policies import (  # noqa: PLC0415
            BearerTokenCredentialPolicy,
            HeadersPolicy,
            RetryPolicy,
            UserAgentPolicy,
        )

        self._endpoint = endpoint.rstrip("/")
        self._client: Any = PipelineClient(
            self._endpoint,
            policies=[
                HeadersPolicy(),
                UserAgentPolicy(base_user_agent=USER_AGENT),
                RetryPolicy(),
                BearerTokenCredentialPolicy(credential, ARM_SCOPE),
            ],
        )

    def __repr__(self) -> str:
        return "Arm()"

    def _get(self, url: str, params: dict[str, str] | None) -> dict[str, Any]:
        from azure.core.rest import HttpRequest  # noqa: PLC0415

        resp = self._client.send_request(HttpRequest("GET", url, params=params))
        if resp.status_code >= 400:
            code: str | None = None
            try:
                code = str((resp.json().get("error") or {}).get("code") or "") or None
            except Exception:  # a body that is not JSON: the status is the name
                code = None
            failed = ArmError()
            failed.error_code = code or f"Http{resp.status_code}"
            failed.status_code = resp.status_code
            raise failed
        data: dict[str, Any] = resp.json()
        return data

    def get(self, path: str, api_version: str) -> dict[str, Any]:
        return self._get(self._endpoint + path, {"api-version": api_version})

    def list(self, path: str, api_version: str) -> Iterator[dict[str, Any]]:
        page = self.get(path, api_version)
        for _ in range(MAX_PAGES):
            yield from page.get("value") or []
            nxt = page.get("nextLink")
            if not nxt or not str(nxt).startswith(self._endpoint + "/"):
                return
            page = self._get(str(nxt), None)


class Clients:
    """A client per service and endpoint, made the first time an adapter asks."""

    def __init__(
        self,
        credential: Any | None = None,
        *,
        made: dict[tuple[str, str], Any] | None = None,
        factory: Callable[[str, str], Any] | None = None,
    ) -> None:
        self._credential = credential
        self.made: dict[tuple[str, str], Any] = dict(made or {})
        self._factory = factory

    def __repr__(self) -> str:
        return "Clients()"

    @property
    def credential(self) -> Any:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential  # noqa: PLC0415

            # The managed identity in Azure; never a browser or a stored secret.
            self._credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return self._credential

    def client(self, service: str, endpoint: str = "") -> Any:
        key = (service, endpoint)
        if key not in self.made:
            self.made[key] = (self._factory or self._make)(service, endpoint)
        return self.made[key]

    def _make(self, service: str, endpoint: str) -> Any:
        if service == "resourcegraph":
            from azure.mgmt.resourcegraph import ResourceGraphClient  # noqa: PLC0415

            return ResourceGraphClient(self.credential, user_agent=USER_AGENT)
        if service == "arm":
            return Arm(self.credential)
        if service == "blob":
            from azure.storage.blob import BlobServiceClient  # noqa: PLC0415

            return BlobServiceClient(endpoint, credential=self.credential, user_agent=USER_AGENT)
        if service == "table":
            from azure.data.tables import TableServiceClient  # noqa: PLC0415

            return TableServiceClient(endpoint, credential=self.credential, user_agent=USER_AGENT)
        if service == "queue":
            from azure.storage.queue import QueueServiceClient  # noqa: PLC0415

            return QueueServiceClient(endpoint, credential=self.credential, user_agent=USER_AGENT)
        if service == "files":
            from azure.storage.fileshare import ShareServiceClient  # noqa: PLC0415

            # An OAuth token reads files over REST only with the backup intent, which
            # Storage File Data Privileged Reader's readFileBackupSemantics grants.
            return ShareServiceClient(
                endpoint,
                credential=self.credential,
                token_intent="backup",  # noqa: S106 - the request intent, not a secret
                user_agent=USER_AGENT,
            )
        if service == "cosmos":
            from azure.cosmos import CosmosClient  # noqa: PLC0415

            return CosmosClient(endpoint, credential=self.credential, user_agent=USER_AGENT)
        if service == "logs":
            from azure.monitor.query import LogsQueryClient  # noqa: PLC0415

            return LogsQueryClient(self.credential, user_agent=USER_AGENT)
        if service == "keyvault":
            from azure.keyvault.secrets import SecretClient  # noqa: PLC0415

            return SecretClient(endpoint, self.credential, user_agent=USER_AGENT)
        if service == "driver":
            # A database driver module (`mssql_python`, `psycopg`, `pymysql`), or None when
            # the image does not carry it (the store's `driver_missing` gap).
            try:
                return importlib.import_module(endpoint)
            except ImportError:
                return None
        raise ValueError("no client for a service an adapter uses")


def graph_query(
    clients: Clients,
    query: str,
    *,
    management_group: str | None,
    subscriptions: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Every row of a Resource Graph query over the scope, paged by skip token."""
    from azure.mgmt.resourcegraph.models import (  # noqa: PLC0415
        QueryRequest,
        QueryRequestOptions,
    )

    graph = clients.client("resourcegraph")
    rows: list[dict[str, Any]] = []
    token: str | None = None
    for _ in range(MAX_PAGES):
        request = QueryRequest(
            query=query,
            management_groups=[management_group] if management_group else None,
            subscriptions=list(subscriptions) or None,
            options=QueryRequestOptions(result_format="objectArray", top=1000, skip_token=token),
        )
        page = graph.resources(request)
        rows.extend(r for r in (page.data or []) if isinstance(r, dict))
        token = page.skip_token
        if not token:
            break
    return rows
