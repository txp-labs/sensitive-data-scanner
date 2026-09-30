"""Where the Azure scanner's findings go: the core's `FindingsSink`, three ways.

- **HTTPS, signed** (`FINDINGS_HTTPS_URL`): the core's `push.HttpsSink`, the
  same signed POSTs as the databases runner (DATABASES.md, Verifying a push).
- **Event Grid** (`FINDINGS_EVENT_GRID_ENDPOINT`, optional): each part of the
  document as a CloudEvent (`source` `sensitive-data-scanner`, `type`
  `Findings v1`, the part as `data`), sent as the job's managed identity, which
  the topic's owner grants `EventGrid Data Sender` on that topic only.
- **A file** (`FINDINGS_FILE`): the whole document, written atomically.

And always, when the job has its state container, `findings/latest.json`
there (runner.py). Only findings leave, never a value; no URL or key is logged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import FindingsSink, HttpsSink, event_details
from sensitive_data_core.safety import error_name, log_event

from . import __version__
from .clients import Clients
from .config import Settings

EVENT_GRID_SCOPE = "https://eventgrid.azure.net/.default"


class EventGridSink:
    """Each part of the document as a CloudEvent on a consumer's Event Grid topic."""

    def __init__(self, endpoint: str, credential: Any, client: Any | None = None) -> None:
        self.endpoint = endpoint
        self._credential = credential
        self._client = client

    def __repr__(self) -> str:
        return "EventGridSink()"

    def _grid(self) -> Any:
        if self._client is None:
            from azure.eventgrid import EventGridPublisherClient  # noqa: PLC0415 - optional

            self._client = EventGridPublisherClient(self.endpoint, self._credential)
        return self._client

    def push(self, document: dict[str, Any]) -> int:
        from azure.core.messaging import CloudEvent  # noqa: PLC0415

        sent = failed = 0
        for detail in event_details(document):
            event = CloudEvent(
                source=EVENT_SOURCE,
                type=EVENT_DETAIL_TYPE,
                subject=str(detail.get("runId") or ""),
                data=json.loads(json.dumps(detail)),
            )
            try:
                self._grid().send([event])
                sent += 1
            except Exception as err:  # the other parts are still sent
                failed += 1
                log_event("events.failed", count=1, error=error_name(err))
        log_event("events.sent", count=sent)
        return 0 if failed else sent


class FileSink:
    """The whole document to a file on a mounted volume, replaced atomically."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def __repr__(self) -> str:
        return "FileSink()"

    def push(self, document: dict[str, Any]) -> int:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(document, indent=2) + "\n")
        os.replace(tmp, self.path)
        return 1


def sinks_for(settings: Settings, clients: Clients) -> list[FindingsSink]:
    out: list[FindingsSink] = []
    if settings.https_url is not None and settings.hmac_key is not None:
        out.append(
            HttpsSink(
                settings.https_url,
                settings.hmac_key,
                user_agent=f"sensitive-data-scanner-azure/{__version__}",
            )
        )
    if settings.event_grid_endpoint:
        out.append(EventGridSink(settings.event_grid_endpoint, clients.credential))
    if settings.findings_file:
        out.append(FileSink(settings.findings_file))
    return out
