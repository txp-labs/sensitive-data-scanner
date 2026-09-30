"""Workload identity: a token that proves which workload the container is, with no secret.

A vendor that trusts a workload identity (Microsoft Entra's federated
credentials, Google's workload identity federation) takes a short-lived token
the platform issues to the running container, in place of a secret. The
container gets one from where it runs:

- `file:<path>`: a projected token file (Kubernetes service account tokens with
  the vendor's audience, AKS workload identity's `AZURE_FEDERATED_TOKEN_FILE`,
  EKS), read afresh each time;
- `aws`: `sts:GetWebIdentityToken` (IAM outbound identity federation) as the
  task's or pod's role, for the audience (the `aws` extra's boto3);
- `gcp`: the metadata server's identity token of the job's service account;
- `azure`: a managed identity's token for the audience, from the Container
  Apps identity endpoint or the instance metadata service.

A token is held only while it is exchanged, and never logged; `repr` shows
nothing but the source.
"""

from __future__ import annotations

import os
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from .http import Http, SaasError

GCP_METADATA = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
AZURE_IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
MAX_TOKEN_BYTES = 16 * 1024
SOURCES = ("file", "aws", "gcp", "azure")


class WorkloadToken(Protocol):
    def token(self) -> str: ...


class FileToken:
    """A projected token file, read afresh each time (the platform rotates it)."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def __repr__(self) -> str:
        return "FileToken()"

    def token(self) -> str:
        try:
            data = self.path.read_bytes()[: MAX_TOKEN_BYTES + 1]
        except OSError:
            raise SaasError("FederatedTokenUnreadable") from None
        text = data.decode("utf-8", "replace").strip()
        if not text or len(data) > MAX_TOKEN_BYTES:
            raise SaasError("FederatedTokenUnreadable")
        return text


class AwsToken:
    """`sts:GetWebIdentityToken` as the container's role, for the vendor's audience."""

    def __init__(self, audience: str, client_factory: Callable[[], Any] | None = None) -> None:
        self.audience = audience
        self._factory = client_factory

    def __repr__(self) -> str:
        return "AwsToken()"

    def token(self) -> str:
        if self._factory is None:
            import boto3  # noqa: PLC0415 - the `aws` extra, only for an AWS-federated identity

            client = boto3.client("sts")
        else:
            client = self._factory()
        got = client.get_web_identity_token(
            Audience=[self.audience], SigningAlgorithm="RS256", DurationSeconds=300
        )
        return str(got["WebIdentityToken"])


class GcpToken:
    """The job's service account's identity token, from the metadata server."""

    def __init__(self, audience: str, http: Http) -> None:
        self.audience = audience
        self.http = http

    def __repr__(self) -> str:
        return "GcpToken()"

    def token(self) -> str:
        resp = self.http.call(
            "GET",
            GCP_METADATA,
            params={"audience": self.audience, "format": "full"},
            headers={"Metadata-Flavor": "Google"},
        )
        return str(resp.text).strip()


class AzureToken:
    """A managed identity's token for the audience (Container Apps, or the instance's)."""

    def __init__(
        self,
        audience: str,
        http: Http,
        *,
        client_id: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.audience = audience
        self.http = http
        self.client_id = client_id
        self._env = dict(os.environ) if env is None else env

    def __repr__(self) -> str:
        return "AzureToken()"

    def token(self) -> str:
        endpoint = self._env.get("IDENTITY_ENDPOINT")
        header = self._env.get("IDENTITY_HEADER")
        params = {"resource": self.audience}
        if self.client_id:
            params["client_id"] = self.client_id
        if endpoint and header:
            params["api-version"] = "2019-08-01"
            resp = self.http.call(
                "GET", endpoint, params=params, headers={"X-IDENTITY-HEADER": header}
            )
        else:
            params["api-version"] = "2018-02-01"
            resp = self.http.call("GET", AZURE_IMDS, params=params, headers={"Metadata": "true"})
        return str(resp.json()["access_token"])


def workload_token(
    source: str,
    audience: str,
    http: Http,
    *,
    aws_client: Callable[[], Any] | None = None,
    azure_client_id: str | None = None,
) -> WorkloadToken:
    """The workload token a setting names: `file:<path>`, `aws`, `gcp` or `azure`."""
    if source.startswith("file:"):
        return FileToken(urllib.parse.unquote(source.removeprefix("file:").removeprefix("//")))
    if source == "aws":
        return AwsToken(audience, aws_client)
    if source == "gcp":
        return GcpToken(audience, http)
    if source == "azure":
        return AzureToken(audience, http, client_id=azure_client_id)
    raise ValueError("unknown workload token source")
