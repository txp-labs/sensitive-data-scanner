"""Slack's Web API, read-only: a token from a mounted file, GETs, and Slack's own errors.

The customer installs a Slack app of its own with **read scopes only**
(docs/SAAS.md) and gives the container its token in a file
(`SLACK_TOKEN_FILE`): a bot token (`xoxb-`), or, for the Discovery API on
Enterprise Grid, an org-level token (`xoxp-`) with `discovery:read`.

- Only Slack's read methods are called (`auth.test`, `conversations.list`,
  `conversations.history`, `conversations.replies`, `files.list`, and the
  Discovery API's `discovery.*.list` and `discovery.conversations.history`);
  a file's content is fetched from `files.slack.com` with the token, the one
  other host the token is ever sent to.
- Slack answers most failures with HTTP 200 and `{"ok": false, "error": ...}`:
  that `error` (`missing_scope`, `not_in_channel`, `channel_not_found`) names
  the `SaasError`; nothing else of the answer is kept.
- A 429's `Retry-After` is honored (`http.py`).
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterator
from typing import Any

from sensitive_data_core.safety import Secret

from .http import Http, SaasError

API = "https://slack.com/api"
HOSTS = frozenset({"slack.com", "files.slack.com"})
MAX_PAGES = 10_000


def slack_error(resp: Any) -> SaasError:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        body = resp.json()
    except Exception:  # not JSON: the status names it
        body = None
    err = body.get("error") if isinstance(body, dict) else None
    return SaasError(str(err) if isinstance(err, str) and err else f"Http{status}", status)


class Slack:
    """GETs on Slack's Web API with one token."""

    def __init__(self, http: Http, token: Secret) -> None:
        self.http = http
        self._token = token

    def __repr__(self) -> str:
        return "Slack(***)"

    def _head(self, url: str) -> dict[str, str]:
        if urllib.parse.urlsplit(url).hostname not in HOSTS:
            raise SaasError("NotSlack")
        return {"Authorization": f"Bearer {self._token.reveal()}"}

    def get(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{API}/{method}"
        resp = self.http.call(
            "GET", url, params=params, headers=self._head(url), error_of=slack_error
        )
        body = resp.json()
        if not isinstance(body, dict) or not body.get("ok"):
            failed = slack_error(resp)
            raise failed
        return body

    def pages(
        self,
        method: str,
        items: str,
        params: dict[str, Any] | None = None,
        *,
        cursor: str | None = None,
    ) -> Iterator[tuple[list[dict[str, Any]], str | None, dict[str, Any]]]:
        """Each page's items, the cursor of the page after it, and the page."""
        for _ in range(MAX_PAGES):
            query = dict(params or {})
            if cursor:
                query["cursor"] = cursor
            page = self.get(method, query)
            meta = page.get("response_metadata") or {}
            cursor = str(meta.get("next_cursor") or "") or None
            yield [i for i in page.get(items) or [] if isinstance(i, dict)], cursor, page
            if cursor is None:
                return

    def download(self, url: str, start: int, end: int) -> bytes:
        resp = self.http.call(
            "GET", url, headers={**self._head(url), "Range": f"bytes={start}-{end}"}
        )
        data: bytes = resp.content
        if resp.status_code == 200 and (start or end < len(data) - 1):
            data = data[start : end + 1]
        return data
