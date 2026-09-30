"""Where the Google Cloud scanner's findings go: the core's `FindingsSink`, three ways.

- **HTTPS, signed** (`FINDINGS_HTTPS_URL`): the core's `push.HttpsSink`, the
  same signed POSTs as the databases runner (DATABASES.md, Verifying a push).
- **Pub/Sub** (`FINDINGS_PUBSUB_TOPIC`, optional): each part of the document as
  one message (the part as JSON `data`, with the attributes `source`
  `sensitive-data-scanner`, `type` `Findings v1`, `runId` and `part`),
  published as the job's service account, which the topic's owner grants
  Pub/Sub Publisher on that topic only.
- **A file** (`FINDINGS_FILE`): the whole document, written atomically.

And always, when the job has its state bucket, `findings/latest.json` there
(runner.py). Only findings leave, never a value; no URL or key is logged.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import FindingsSink, HttpsSink, event_details
from sensitive_data_core.safety import error_name, log_event

from . import __version__
from .clients import PUBSUB_API, Clients, Rest
from .config import Settings


class PubSubSink:
    """Each part of the document as a message on a consumer's Pub/Sub topic."""

    def __init__(self, topic: str, rest: Rest) -> None:
        self.topic = topic
        self._rest = rest

    def __repr__(self) -> str:
        return "PubSubSink()"

    def push(self, document: dict[str, Any]) -> int:
        sent = failed = 0
        for detail in event_details(document):
            data = json.dumps(detail, separators=(",", ":")).encode()
            message = {
                "data": base64.b64encode(data).decode(),
                "attributes": {
                    "source": EVENT_SOURCE,
                    "type": EVENT_DETAIL_TYPE,
                    "runId": str(detail.get("runId") or ""),
                    "part": f"{detail['part']}/{detail['parts']}",
                },
            }
            try:
                self._rest.post(f"{PUBSUB_API}/{self.topic}:publish", {"messages": [message]})
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
                user_agent=f"sensitive-data-scanner-gcp/{__version__}",
            )
        )
    if settings.pubsub_topic:
        out.append(PubSubSink(settings.pubsub_topic, clients.rest))
    if settings.findings_file:
        out.append(FileSink(settings.findings_file))
    return out
