"""Microsoft Graph, read-only: GETs with the app's token, paged, errors by Graph's code.

- The app's token is sent to `graph.microsoft.com` and nowhere else. A file's
  content is fetched from Graph's `/content`, which redirects to a
  pre-authenticated download URL on SharePoint; `requests` drops the
  `Authorization` header when a redirect leaves the host, so the token never
  reaches it.
- Only GET is ever sent to Graph (`get`, `pages`, `download`); the scanner has
  no call that writes.
- A failure is `SaasError` with Graph's `error.code` (`ErrorAccessDenied`,
  `Authorization_RequestDenied`, `ResourceNotFound`, `MailboxNotEnabledForRESTAPI`,
  ...). A 403 whose message says the API is protected (Teams chats and channel
  messages need Microsoft's approval first) is `ProtectedApiNotApproved`; the
  message is looked at only for that, and never kept.
- Throttling (429, 503, 504) is the shared client's (`http.py`): Graph's
  `Retry-After` is honored.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterator
from typing import Any, Protocol

from .http import Http, SaasError

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_HOST = "graph.microsoft.com"
MAX_PAGES = 10_000


class TokenSource(Protocol):
    def token(self) -> str: ...


def graph_error(resp: Any) -> SaasError:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        body = resp.json()
    except Exception:  # not JSON: the status names it
        body = None
    err = body.get("error") if isinstance(body, dict) else None
    code: str | None = None
    if isinstance(err, dict):
        message = str(err.get("message") or "").lower()
        if status == 403 and "protected api" in message:
            code = "ProtectedApiNotApproved"
        elif isinstance(err.get("code"), str) and err["code"]:
            code = str(err["code"])
    return SaasError(code or f"Http{status}", status)


class Graph:
    """GETs on Microsoft Graph as the app."""

    def __init__(self, http: Http, app: TokenSource) -> None:
        self.http = http
        self.app = app

    def __repr__(self) -> str:
        return "Graph()"

    def _url(self, path_or_url: str) -> str:
        url = path_or_url if path_or_url.startswith("https://") else GRAPH + path_or_url
        if urllib.parse.urlsplit(url).hostname != GRAPH_HOST:
            raise SaasError("NotGraph")
        return url

    def call(
        self,
        path_or_url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        head = {"Authorization": f"Bearer {self.app.token()}", **(headers or {})}
        return self.http.call(
            "GET", self._url(path_or_url), params=params, headers=head, error_of=graph_error
        )

    def get(
        self,
        path_or_url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        resp = self.call(path_or_url, params, headers=headers)
        return resp.json() if resp.content else {}

    def pages(
        self,
        path_or_url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> Iterator[tuple[list[dict[str, Any]], str | None, str | None]]:
        """Each page's items, the URL of the page after it, and (on the last page of a delta
        query) its delta link. A next link carries the query, so `params` go with the first
        page only."""
        url: str | None = path_or_url
        first = True
        for _ in range(MAX_PAGES):
            if url is None:
                return
            page = self.get(url, params if first else None, headers=headers)
            first = False
            items = [i for i in page.get("value") or [] if isinstance(i, dict)]
            nxt = page.get("@odata.nextLink")
            delta = page.get("@odata.deltaLink")
            url = str(nxt) if nxt else None
            yield items, url, (str(delta) if delta else None)

    def download(self, path: str, start: int, end: int) -> bytes:
        """Bytes `start` to `end` (inclusive) of a drive item's or attachment's content."""
        resp = self.call(path, headers={"Range": f"bytes={start}-{end}"})
        data: bytes = resp.content
        if resp.status_code == 200 and (start or end < len(data) - 1):
            data = data[start : end + 1]  # a server that ignored the range
        return data
