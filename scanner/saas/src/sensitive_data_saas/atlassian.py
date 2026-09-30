"""Atlassian Cloud (Jira and Confluence), read-only: an API token or OAuth 2.0 (3LO).

Two ways to sign in, both with read scopes only (docs/SAAS.md):

- **An API token** of a read-only service account: `ATLASSIAN_EMAIL` and
  `ATLASSIAN_API_TOKEN_FILE`, sent as HTTP basic authentication to the site
  (`https://<site>.atlassian.net`). What it reads is what that account can
  browse: give it Browse projects and View spaces, and nothing that edits.
- **OAuth 2.0 (3LO)**: an app in the Atlassian developer console with the
  classic read scopes only (`read:jira-work`, `read:confluence-content.all`,
  `read:confluence-space.summary`, `readonly:content.attachment:confluence`,
  and `offline_access`), consented once by an admin, whose refresh token is in
  `ATLASSIAN_OAUTH_REFRESH_TOKEN_FILE`. Calls go through
  `https://api.atlassian.com/ex/{jira,confluence}/<cloud id>`. Atlassian
  rotates the refresh token on each use; the new one is written back to the
  same file (atomically), so that file must be writable. A token it cannot
  save stops the run (`RefreshTokenNotSaved`) rather than lose the grant.

Only GETs are sent to Jira and Confluence (the one POST is the OAuth token
exchange). An attachment's content redirects to Atlassian's media host;
`requests` drops the `Authorization` header when a redirect leaves the host,
so the credential never goes there. A failure is `SaasError` named by
Confluence's `code`, else the HTTP status; never Atlassian's message.
"""

from __future__ import annotations

import base64
import os
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sensitive_data_core.safety import Secret

from .entra import token_error
from .http import Http, SaasError

AUTH_URL = "https://auth.atlassian.com/oauth/token"
GATEWAY = "https://api.atlassian.com"
REFRESH_SECONDS = 300


def atlassian_error(resp: Any) -> SaasError:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        body = resp.json()
    except Exception:  # not JSON: the status names it
        body = None
    code: str | None = None
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            got = errs[0].get("code")
            code = str(got) if isinstance(got, str) and got else None
    return SaasError(code or f"Http{status}", status)


class ApiToken:
    """Basic authentication with a service account's address and API token."""

    def __init__(self, email: Secret, token: Secret) -> None:
        self._email = email
        self._token = token

    def __repr__(self) -> str:
        return "ApiToken(***)"

    def header(self) -> str:
        raw = f"{self._email.reveal()}:{self._token.reveal()}".encode()
        return "Basic " + base64.b64encode(raw).decode()


class OAuth:
    """OAuth 2.0 (3LO) with a rotating refresh token kept in its own file."""

    def __init__(
        self,
        http: Http,
        client_id: str,
        client_secret: Secret,
        refresh_file: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.http = http
        self.client_id = client_id
        self._secret = client_secret
        self._file = Path(refresh_file)
        self._clock = clock
        self._token: Secret | None = None
        self._expires = 0.0

    def __repr__(self) -> str:
        return "OAuth(***)"

    def _save(self, refresh: str) -> None:
        tmp = self._file.with_name(self._file.name + ".tmp")
        try:
            tmp.write_text(refresh)
            os.replace(tmp, self._file)
        except OSError:
            raise SaasError("RefreshTokenNotSaved") from None

    def header(self) -> str:
        now = self._clock()
        if self._token is not None and now < self._expires - REFRESH_SECONDS:
            return f"Bearer {self._token.reveal()}"
        try:
            refresh = self._file.read_text().strip()
        except OSError:
            raise SaasError("RefreshTokenUnreadable") from None
        resp = self.http.call(
            "POST",
            AUTH_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self._secret.reveal(),
                "refresh_token": refresh,
            },
            error_of=token_error,
        )
        body = resp.json()
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SaasError("NoAccessToken")
        rotated = body.get("refresh_token")
        if isinstance(rotated, str) and rotated and rotated != refresh:
            self._save(rotated)
        self._token = Secret(token)
        self._expires = now + float(body.get("expires_in") or 3600)
        return f"Bearer {token}"


class Atlassian:
    """GETs on one Atlassian Cloud site's Jira and Confluence APIs."""

    def __init__(self, http: Http, site: str, auth: ApiToken | OAuth) -> None:
        self.http = http
        self.site = site
        self.auth = auth
        self._cloud: str | None = None

    def __repr__(self) -> str:
        return "Atlassian(***)"

    def cloud_id(self) -> str:
        """The site's cloud id: what findings name the tenant by (hashed)."""
        if self._cloud is None:
            resp = self.http.call(
                "GET", f"https://{self.site}/_edge/tenant_info", error_of=atlassian_error
            )
            self._cloud = str(resp.json().get("cloudId") or self.site)
        return self._cloud

    def base(self, product: str) -> str:
        """`jira` or `confluence`'s API root for this sign-in."""
        wiki = "/wiki" if product == "confluence" else ""
        if isinstance(self.auth, OAuth):
            return f"{GATEWAY}/ex/{product}/{self.cloud_id()}{wiki}"
        return f"https://{self.site}{wiki}"

    def _check(self, url: str) -> None:
        host = urllib.parse.urlsplit(url).hostname
        if host not in (self.site, "api.atlassian.com"):
            raise SaasError("NotAtlassian")

    def call(self, url: str, params: Any = None, headers: dict[str, str] | None = None) -> Any:
        self._check(url)
        head = {
            "Authorization": self.auth.header(),
            "Accept": "application/json",
            **(headers or {}),
        }
        return self.http.call("GET", url, params=params, headers=head, error_of=atlassian_error)

    def get(self, url: str, params: Any = None) -> Any:
        resp = self.call(url, params)
        return resp.json() if resp.content else {}

    def download(self, url: str, start: int, end: int) -> bytes:
        resp = self.call(url, headers={"Range": f"bytes={start}-{end}", "Accept": "*/*"})
        data: bytes = resp.content
        if resp.status_code == 200 and (start or end < len(data) - 1):
            data = data[start : end + 1]
        return data
