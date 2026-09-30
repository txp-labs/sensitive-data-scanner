"""The HTTPS session and each vendor's API, made the first time an adapter asks.

Tests give `Clients` a stubbed session (any object with `request`) and a clock;
nothing else here reaches a network.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .config import M365Settings, Settings
from .entra import Certificate, EntraApp
from .federation import workload_token
from .graph import Graph
from .http import Http


def _session() -> Any:
    import requests  # noqa: PLC0415 - only when a real run makes the session

    return requests.Session()


class Clients:
    """The session, and Graph as the app."""

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
