"""The HTTPS session and each vendor's API, made the first time an adapter asks.

Tests give `Clients` a stubbed session (any object with `request`) and a clock;
nothing else here reaches a network.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .atlassian import ApiToken, Atlassian, OAuth
from .config import GwsSettings, M365Settings, Settings
from .entra import Certificate, EntraApp
from .federation import workload_token
from .google import Delegation, GoogleApi, IamSigner, KeySigner
from .graph import Graph
from .http import Http
from .slack import Slack


def _session() -> Any:
    import requests  # noqa: PLC0415 - only when a real run makes the session

    return requests.Session()


class Clients:
    """The session, and each vendor's API: Graph as the app, Google Workspace's delegation,
    Slack's token, Atlassian's sign-in."""

    def __init__(
        self,
        settings: Settings,
        *,
        session: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        aws_client: Callable[[], Any] | None = None,
    ) -> None:
        self.settings = settings
        self._session = session
        self._sleep = sleep
        self._clock = clock
        self._wall = wall
        self._aws_client = aws_client
        self._http: Http | None = None
        self._graph: Graph | None = None
        self._delegation: Delegation | None = None
        self._slack: Slack | None = None
        self._atlassian: Atlassian | None = None
        self._slack_audit: Slack | None = None

    def __repr__(self) -> str:
        return "Clients()"

    @property
    def http(self) -> Http:
        if self._http is None:
            self._http = Http(
                self._session if self._session is not None else _session(),
                sleep=self._sleep,
                clock=self._clock,
                wall=self._wall,
                max_wait=float(self.settings.max_throttle_wait),
            )
        return self._http

    def entra(self, m: M365Settings) -> EntraApp:
        if m.certificate_file is not None:
            return EntraApp(
                self.http,
                m.tenant,
                m.client_id,
                certificate=Certificate(m.certificate_file),
                clock=self._wall,
            )
        if m.federated is not None:
            source = workload_token(
                m.federated,
                m.federated_audience,
                self.http,
                aws_client=self._aws_client,
                azure_client_id=m.federated_client_id,
            )
            return EntraApp(self.http, m.tenant, m.client_id, federated=source, clock=self._wall)
        return EntraApp(self.http, m.tenant, m.client_id, secret=m.secret, clock=self._wall)

    @property
    def graph(self) -> Graph:
        if self._graph is None:
            m = self.settings.m365
            if m is None:
                raise RuntimeError("m365 is not configured")
            self._graph = Graph(self.http, self.entra(m))
        return self._graph

    def signer(self, g: GwsSettings) -> KeySigner | IamSigner:
        if g.key_file is not None:
            return KeySigner(g.key_file)
        if g.credential == "gcp":
            return IamSigner(self.http, g.service_account, clock=self._wall)
        source = workload_token(
            # The audience a workload identity provider accepts by default.
            str(g.credential),
            f"https://iam.googleapis.com/{g.provider}",
            self.http,
            aws_client=self._aws_client,
        )
        return IamSigner(
            self.http, g.service_account, federated=source, provider=g.provider, clock=self._wall
        )

    @property
    def delegation(self) -> Delegation:
        if self._delegation is None:
            g = self.settings.gws
            if g is None:
                raise RuntimeError("google workspace is not configured")
            self._delegation = Delegation(self.http, self.signer(g), clock=self._wall)
        return self._delegation

    def google(self, user: str, scopes: tuple[str, ...]) -> GoogleApi:
        """Google's APIs as `user` in scope, for read-only `scopes`."""
        return GoogleApi(self.delegation, user, scopes)

    @property
    def slack(self) -> Slack:
        if self._slack is None:
            sl = self.settings.slack
            if sl is None:
                raise RuntimeError("slack is not configured")
            self._slack = Slack(self.http, sl.token)
        return self._slack

    @property
    def atlassian(self) -> Atlassian:
        if self._atlassian is None:
            a = self.settings.atlassian
            if a is None:
                raise RuntimeError("atlassian is not configured")
            auth: ApiToken | OAuth
            if a.api_token is not None and a.email is not None:
                auth = ApiToken(a.email, a.api_token)
            elif a.oauth_client_id and a.oauth_secret is not None and a.oauth_refresh_file:
                auth = OAuth(
                    self.http,
                    a.oauth_client_id,
                    a.oauth_secret,
                    a.oauth_refresh_file,
                    clock=self._wall,
                )
            else:  # pragma: no cover - the settings allow no other
                raise RuntimeError("no atlassian credential")
            self._atlassian = Atlassian(self.http, a.site, auth)
        return self._atlassian

    @property
    def slack_audit(self) -> Slack:
        """Slack's Audit Logs API, with the org token (#55)."""
        if self._slack_audit is None:
            sl = self.settings.slack
            if sl is None or sl.audit_token is None:
                raise RuntimeError("slack audit is not configured")
            self._slack_audit = Slack(self.http, sl.audit_token)
        return self._slack_audit
