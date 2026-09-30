"""Google's APIs over REST, signed by the job's service account.

Every call goes through one authorized session (`google.auth`'s
`AuthorizedSession`), with the credentials Application Default Credentials
find: on Cloud Run, the job's own service account from the metadata server;
for a local run, the developer's `gcloud auth application-default login`. No
key file is configured or made. The image carries no gRPC stack: each API the
scanner calls is a handful of REST methods (`Rest`).

A failed call raises `GcpError`, whose `error_code` is Google's canonical
status (`PERMISSION_DENIED`, `NOT_FOUND`, ...), or `VPC_SERVICE_CONTROLS` when
a service perimeter refused it, or `USER_PROJECT_MISSING` for a requester-pays
bucket; never Google's message, which can quote a resource's name.

Tests give `Clients` a stubbed session (any object with `request`); nothing
else here needs Google.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any

from . import __version__

USER_AGENT = f"sensitive-data-scanner-gcp/{__version__}"
CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"
ASSET_API = "https://cloudasset.googleapis.com/v1"
STORAGE_API = "https://storage.googleapis.com/storage/v1"
UPLOAD_API = "https://storage.googleapis.com/upload/storage/v1"
PUBSUB_API = "https://pubsub.googleapis.com/v1"
MAX_PAGES = 1000
RETRIES = 3
TIMEOUT = 60

# HTTP statuses as Google's canonical codes, for an error body that does not name one.
_BY_STATUS = {
    400: "INVALID_ARGUMENT",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    409: "ALREADY_EXISTS",
    412: "FAILED_PRECONDITION",
    416: "OUT_OF_RANGE",
    429: "RESOURCE_EXHAUSTED",
    500: "INTERNAL",
    503: "UNAVAILABLE",
    504: "DEADLINE_EXCEEDED",
}
# A service perimeter (VPC Service Controls) refused the call: the store's `network` gap.
_PERIMETER = frozenset({"SECURITY_POLICY_VIOLATED", "vpcServiceControls"})


class GcpError(Exception):
    """A Google API call failed. `error_code` names why; the message is never kept."""

    error_code = "GcpError"
    status_code = 0

    def __init__(self, code: str, status: int = 0) -> None:
        super().__init__(code)
        self.error_code = code
        self.status_code = status

    def __repr__(self) -> str:
        return f"GcpError({self.error_code!r})"


def error_of(resp: Any) -> GcpError:
    """The canonical code of a failed response. The message is looked at only to tell a
    requester-pays bucket apart, and never kept."""
    status = int(getattr(resp, "status_code", 0) or 0)
    code: str | None = None
    try:
        body = resp.json()
    except Exception:  # a body that is not JSON: the status is the name
        body = None
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        reasons = {
            str(d.get("reason") or "")
            for d in [*(err.get("details") or []), *(err.get("errors") or [])]
            if isinstance(d, dict)
        }
        message = str(err.get("message") or "").lower()
        if reasons & _PERIMETER or "vpc service controls" in message:
            code = "VPC_SERVICE_CONTROLS"
        elif "user project" in message and "requester pays" in message:
            code = "USER_PROJECT_MISSING"
        elif isinstance(err.get("status"), str) and err["status"]:
            code = str(err["status"])
    return GcpError(code or _BY_STATUS.get(status, f"Http{status}"), status)


class Rest:
    """GETs and POSTs on Google's REST APIs through one authorized session."""

    def __init__(
        self,
        session: Any,
        *,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = TIMEOUT,
    ) -> None:
        self._session = session
        self._sleep = sleep
        self._timeout = timeout

    def __repr__(self) -> str:
        return "Rest()"

    def call(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | list[tuple[str, str]] | None = None,
        body: Any = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """The response of one call, retried on 429 and 5xx. Raises GcpError on failure."""
        head = {"User-Agent": USER_AGENT, **(headers or {})}
        for attempt in range(RETRIES):
            resp = self._session.request(
                method,
                url,
                params=params,
                json=body,
                data=data,
                headers=head,
                timeout=timeout or self._timeout,
            )
            status = int(resp.status_code)
            if status < 400:
                return resp
            if (status == 429 or status >= 500) and attempt < RETRIES - 1:
                self._sleep(2**attempt)
                continue
            failed = error_of(resp)
            raise failed
        raise GcpError("UNAVAILABLE")  # pragma: no cover - the loop returns or raises

    def get(self, url: str, params: dict[str, Any] | list[tuple[str, str]] | None = None) -> Any:
        resp = self.call("GET", url, params=params)
        return resp.json() if resp.content else {}

    def post(self, url: str, body: Any, params: dict[str, Any] | None = None) -> Any:
        resp = self.call("POST", url, params=params, body=body)
        return resp.json() if resp.content else {}

    def pages(
        self,
        url: str,
        items: str,
        params: dict[str, Any] | list[tuple[str, str]] | None = None,
        *,
        token: str | None = None,
    ) -> Iterator[tuple[list[Any], str | None]]:
        """Each page's items and the token of the page after it, from `token` on."""
        base = list(params.items()) if isinstance(params, dict) else list(params or [])
        for _ in range(MAX_PAGES):
            query = base + ([("pageToken", token)] if token else [])
            page = self.get(url, query)
            token = str(page.get("nextPageToken") or "") or None
            yield list(page.get(items) or []), token
            if token is None:
                return


class Clients:
    """The authorized session, made the first time an adapter asks."""

    def __init__(
        self,
        credentials: Any | None = None,
        *,
        session: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._credentials = credentials
        self._session = session
        self._sleep = sleep
        self._rest: Rest | None = None

    def __repr__(self) -> str:
        return "Clients()"

    @property
    def credentials(self) -> Any:
        if self._credentials is None:
            import google.auth  # noqa: PLC0415 - Google only when used

            # The job's service account (the metadata server); never a key file.
            self._credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM])
        return self._credentials

    @property
    def rest(self) -> Rest:
        if self._rest is None:
            if self._session is None:
                from google.auth.transport.requests import AuthorizedSession  # noqa: PLC0415

                self._session = AuthorizedSession(self.credentials)  # type: ignore[no-untyped-call]
            self._rest = Rest(self._session, sleep=self._sleep)
        return self._rest


def search_resources(rest: Rest, scope: str, asset_type: str) -> list[dict[str, Any]]:
    """Every resource of one type under a scope (Cloud Asset Inventory,
    `searchAllResources`), paged. Needs `cloudasset.assets.searchAllResources` there."""
    out: list[dict[str, Any]] = []
    url = f"{ASSET_API}/{scope}:searchAllResources"
    for page, _ in rest.pages(url, "results", [("assetTypes", asset_type), ("pageSize", "500")]):
        out.extend(r for r in page if isinstance(r, dict))
    return out
