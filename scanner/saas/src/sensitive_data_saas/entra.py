"""Microsoft Entra app tokens for Microsoft Graph: the client credentials flow, three ways.

The customer registers an app in its own tenant, grants it Graph application
permissions that only read (docs/SAAS.md), and gives the container one of:

- **a certificate** (preferred): `M365_CERTIFICATE_FILE`, a PEM file holding the
  private key and the certificate. Each token request carries a client
  assertion, a JWT signed with the key (`PS256`, the certificate named by its
  `x5t#S256` thumbprint), valid for ten minutes.
- **a federated workload identity** (preferred): `M365_FEDERATED_TOKEN`, a
  token from where the container runs (`federation.py`) that the app trusts
  through a federated identity credential. No secret exists at all.
- **a client secret** (the fallback): `M365_CLIENT_SECRET_FILE`, a file on a
  mounted secret volume. Never an environment variable, never logged.

The token is for `https://graph.microsoft.com/.default`, so it carries exactly
the application permissions the admin consented to, and it is kept in memory
until five minutes before it expires. No credential, assertion or token is
logged, and no repr shows one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sensitive_data_core.safety import Secret

from .federation import WorkloadToken
from .http import Http, SaasError

LOGIN = "https://login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
FEDERATED_AUDIENCE = "api://AzureADTokenExchange"
REFRESH_SECONDS = 300
MAX_PEM_BYTES = 64 * 1024


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token_error(resp: Any) -> SaasError:
    """Entra's `error` (`invalid_client`, `unauthorized_client`), never its description."""
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        body = resp.json()
    except Exception:  # not JSON: the status names it
        body = None
    code = body.get("error") if isinstance(body, dict) else None
    return SaasError(str(code) if isinstance(code, str) and code else f"Http{status}", status)


class Certificate:
    """A PEM file's private key and certificate, loaded once. Signs client assertions."""

    def __init__(self, path: str) -> None:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        try:
            pem = Path(path).read_bytes()[: MAX_PEM_BYTES + 1]
        except OSError:
            raise SaasError("CertificateUnreadable") from None
        if len(pem) > MAX_PEM_BYTES:
            raise SaasError("CertificateUnreadable")
        try:
            self._key: Any = serialization.load_pem_private_key(pem, password=None)
            cert = x509.load_pem_x509_certificate(pem)
        except (ValueError, TypeError):
            raise SaasError("CertificateUnreadable") from None
        der = cert.public_bytes(serialization.Encoding.DER)
        self.thumbprint = b64url(hashlib.sha256(der).digest())

    def __repr__(self) -> str:
        return "Certificate(***)"

    def assertion(self, client_id: str, audience: str, now: float) -> str:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415

        header = {"alg": "PS256", "typ": "JWT", "x5t#S256": self.thumbprint}
        claims = {
            "aud": audience,
            "iss": client_id,
            "sub": client_id,
            "jti": secrets.token_hex(16),
            "iat": int(now),
            "nbf": int(now),
            "exp": int(now) + 600,
        }
        signing = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self._key.sign(
            signing.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return signing + "." + b64url(signature)


class EntraApp:
    """An app's Graph token from the client credentials flow, cached until near expiry."""

    def __init__(
        self,
        http: Http,
        tenant: str,
        client_id: str,
        *,
        certificate: Certificate | None = None,
        federated: WorkloadToken | None = None,
        secret: Secret | None = None,
        scope: str = GRAPH_SCOPE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if sum(x is not None for x in (certificate, federated, secret)) != 1:
            raise ValueError("exactly one credential")
        self.http = http
        self.tenant = tenant
        self.client_id = client_id
        self._certificate = certificate
        self._federated = federated
        self._secret = secret
        self.scope = scope
        self._clock = clock
        self._token: Secret | None = None
        self._expires = 0.0

    def __repr__(self) -> str:
        return "EntraApp(***)"

    @property
    def endpoint(self) -> str:
        return f"{LOGIN}/{self.tenant}/oauth2/v2.0/token"

    def token(self) -> str:
        now = self._clock()
        if self._token is not None and now < self._expires - REFRESH_SECONDS:
            return self._token.reveal()
        form = {
            "client_id": self.client_id,
            "scope": self.scope,
            "grant_type": "client_credentials",
        }
        if self._certificate is not None:
            form["client_assertion_type"] = ASSERTION_TYPE
            form["client_assertion"] = self._certificate.assertion(
                self.client_id, self.endpoint, now
            )
        elif self._federated is not None:
            form["client_assertion_type"] = ASSERTION_TYPE
            form["client_assertion"] = self._federated.token()
        elif self._secret is not None:
            form["client_secret"] = self._secret.reveal()
        resp = self.http.call("POST", self.endpoint, data=form, error_of=token_error)
        body = resp.json()
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SaasError("NoAccessToken")
        self._token = Secret(token)
        self._expires = now + float(body.get("expires_in") or 3600)
        return token
