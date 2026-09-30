"""Google Workspace, read-only: domain-wide delegation to a service account, over REST.

The customer makes a service account (in any Google Cloud project), and in the
Admin console gives its client id **domain-wide delegation** for read-only
scopes only (docs/SAAS.md). The scanner then acts as each user in scope, for
those scopes, and nothing else: a token is minted per user from a JWT the
service account signs (`sub` = the user, `scope` = the read-only scopes), and
exchanged at `oauth2.googleapis.com/token`.

**Who signs the JWT** (`GWS_CREDENTIAL`):

- `gcp`: the job runs as a Google service account (Cloud Run): the metadata
  server's access token calls IAM Credentials' `signJwt` for the delegated
  service account. No key exists.
- `file:<path>`, `aws`, `azure`: **workload identity federation**. The
  platform's own token (`federation.py`) is exchanged at Google's STS for a
  federated token (`GWS_WORKLOAD_PROVIDER`, the pool provider's resource
  name), which calls `signJwt`. No key exists.
- `GWS_KEY_FILE` (the fallback): a service account key, a JSON file on a
  mounted secret volume, signs the JWT locally (`RS256`).

The signer holds only `iam.serviceAccounts.signJwt` on the delegated service
account (Service Account Token Creator on it); the service account itself
holds no IAM role at all. No key, JWT or token is logged or shown by a repr.

A failure is `SaasError` with Google's `status` (`PERMISSION_DENIED`,
`NOT_FOUND`, `FAILED_PRECONDITION`) or, from the token endpoint, its `error`
(`unauthorized_client`: the delegation does not cover a scope, or the user).
A 403 for a rate limit (`rateLimitExceeded`, `userRateLimitExceeded`) is
retried like a 429.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from sensitive_data_core.safety import Secret

from .entra import b64url, token_error
from .federation import WorkloadToken
from .http import Http, SaasError

TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - a URL
STS_URL = "https://sts.googleapis.com/v1/token"
IAM_CREDENTIALS = "https://iamcredentials.googleapis.com/v1"
METADATA_TOKEN = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"  # noqa: S105
)
# The federated signer's token: IAM Credentials only (what it may do is its one role).
IAM_SCOPE = "https://www.googleapis.com/auth/iam"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
GOOGLE_HOSTS = frozenset({"gmail.googleapis.com", "www.googleapis.com", "admin.googleapis.com"})
RATE_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"})
REFRESH_SECONDS = 300
MAX_KEY_BYTES = 64 * 1024
MAX_PAGES = 10_000


def _body(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:  # not JSON: the status names it
        return None


def google_error(resp: Any) -> SaasError:
    """Google's canonical `status`, else the first error's `reason`, else the HTTP status."""
    status = int(getattr(resp, "status_code", 0) or 0)
    body = _body(resp)
    err = body.get("error") if isinstance(body, dict) else None
    code: str | None = None
    if isinstance(err, dict):
        if isinstance(err.get("status"), str) and err["status"]:
            code = str(err["status"])
        else:
            reasons = [e.get("reason") for e in err.get("errors") or [] if isinstance(e, dict)]
            code = next((str(r) for r in reasons if r), None)
    elif isinstance(err, str) and err:
        code = err
    return SaasError(code or f"Http{status}", status)


def rate_limited(resp: Any) -> bool:
    """A 403 that is Google's per-user or per-project rate limit, not a denial."""
    if int(getattr(resp, "status_code", 0) or 0) != 403:
        return False
    body = _body(resp)
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return False
    reasons = {str(e.get("reason") or "") for e in err.get("errors") or [] if isinstance(e, dict)}
    return bool(reasons & RATE_REASONS)


class KeySigner:
    """A service account key file: signs a JWT locally."""

    def __init__(self, path: str) -> None:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        try:
            raw = Path(path).read_bytes()[: MAX_KEY_BYTES + 1]
            doc = json.loads(raw)
            self.email = str(doc["client_email"])
            self._key: Any = serialization.load_pem_private_key(
                str(doc["private_key"]).encode(), password=None
            )
        except (OSError, ValueError, KeyError, TypeError):
            raise SaasError("KeyFileUnreadable") from None

    def __repr__(self) -> str:
        return "KeySigner(***)"

    def sign(self, claims: dict[str, Any]) -> str:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415

        head = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signature = self._key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{b64url(signature)}"


class IamSigner:
    """IAM Credentials' `signJwt` for the delegated service account, as a keyless caller: the
    job's own service account (the metadata server), or a federated workload identity."""

    def __init__(
        self,
        http: Http,
        service_account: str,
        *,
        federated: WorkloadToken | None = None,
        provider: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.http = http
        self.email = service_account
        self._federated = federated
        self._provider = provider
        self._clock = clock
        self._token: Secret | None = None
        self._expires = 0.0

    def __repr__(self) -> str:
        return "IamSigner(***)"

    def _caller(self) -> str:
        now = self._clock()
        if self._token is not None and now < self._expires - REFRESH_SECONDS:
            return self._token.reveal()
        if self._federated is None:
            resp = self.http.call("GET", METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
            body = resp.json()
        else:
            resp = self.http.call(
                "POST",
                STS_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "audience": f"//iam.googleapis.com/{self._provider}",
                    "scope": IAM_SCOPE,
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    "subject_token": self._federated.token(),
                },
                error_of=token_error,
            )
            body = resp.json()
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SaasError("NoAccessToken")
        self._token = Secret(token)
        self._expires = now + float(body.get("expires_in") or 3600)
        return token

    def sign(self, claims: dict[str, Any]) -> str:
        name = urllib.parse.quote(self.email, safe="@.")
        resp = self.http.call(
            "POST",
            f"{IAM_CREDENTIALS}/projects/-/serviceAccounts/{name}:signJwt",
            json={"payload": json.dumps(claims, separators=(",", ":"))},
            headers={"Authorization": f"Bearer {self._caller()}"},
            error_of=google_error,
        )
        jwt = resp.json().get("signedJwt")
        if not isinstance(jwt, str) or not jwt:
            raise SaasError("NoSignedJwt")
        return jwt


class Delegation:
    """Tokens for a user in scope, for read-only scopes: domain-wide delegation."""

    def __init__(
        self,
        http: Http,
        signer: KeySigner | IamSigner,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.http = http
        self.signer = signer
        self._clock = clock
        self._tokens: dict[tuple[str, str], tuple[Secret, float]] = {}

    def __repr__(self) -> str:
        return "Delegation(***)"

    def token(self, user: str, scopes: tuple[str, ...]) -> str:
        key = (user.lower(), " ".join(sorted(scopes)))
        now = self._clock()
        got = self._tokens.get(key)
        if got is not None and now < got[1] - REFRESH_SECONDS:
            return got[0].reveal()
        claims = {
            "iss": self.signer.email,
            "sub": user,
            "scope": key[1],
            "aud": TOKEN_URL,
            "iat": int(now),
            "exp": int(now) + 3600,
        }
        assertion = self.signer.sign(claims)
        resp = self.http.call(
            "POST",
            TOKEN_URL,
            data={"grant_type": JWT_BEARER, "assertion": assertion},
            error_of=token_error,
        )
        body = resp.json()
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SaasError("NoAccessToken")
        self._tokens[key] = (Secret(token), now + float(body.get("expires_in") or 3600))
        return token


class GoogleApi:
    """GETs on Google's APIs as one user in scope, for one set of read-only scopes."""

    def __init__(self, delegation: Delegation, user: str, scopes: tuple[str, ...]) -> None:
        self.http = delegation.http
        self._delegation = delegation
        self._user = user
        self.scopes = scopes

    def __repr__(self) -> str:
        return "GoogleApi(***)"

    def call(
        self,
        url: str,
        params: dict[str, Any] | list[tuple[str, str]] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        if urllib.parse.urlsplit(url).hostname not in GOOGLE_HOSTS:
            raise SaasError("NotGoogle")
        token = self._delegation.token(self._user, self.scopes)
        return self.http.call(
            "GET",
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}", **(headers or {})},
            error_of=google_error,
            retry_if=rate_limited,
        )

    def get(self, url: str, params: dict[str, Any] | list[tuple[str, str]] | None = None) -> Any:
        resp = self.call(url, params)
        return resp.json() if resp.content else {}

    def pages(
        self,
        url: str,
        items: str,
        params: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Iterator[tuple[list[dict[str, Any]], str | None, dict[str, Any]]]:
        """Each page's items, the token of the page after it, and the page itself."""
        for _ in range(MAX_PAGES):
            query = dict(params or {})
            if token:
                query["pageToken"] = token
            page = self.get(url, query)
            token = str(page.get("nextPageToken") or "") or None
            yield [i for i in page.get(items) or [] if isinstance(i, dict)], token, page
            if token is None:
                return

    def download(self, url: str, start: int, end: int, params: dict[str, Any]) -> bytes:
        resp = self.call(url, params, headers={"Range": f"bytes={start}-{end}"})
        data: bytes = resp.content
        if resp.status_code == 200 and (start or end < len(data) - 1):
            data = data[start : end + 1]
        return data
