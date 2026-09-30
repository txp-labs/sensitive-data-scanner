"""Where the databases runner's findings go: the core's `FindingsSink`, three ways.

- **HTTPS, signed** (`FINDINGS_HTTPS_URL`, the core's `push.HttpsSink`): each
  part of the document is POSTed as JSON with `X-SDS-Signature: t=<unix time>,v1=<hex>`, where `v1`
  is HMAC-SHA256 under the shared key of `<t>.` followed by the exact body.
  The receiver recomputes it, compares in constant time and rejects a `t`
  more than five minutes old (docs/DATABASES.md, Verifying a push).
- **EventBridge** (`FINDINGS_EVENT_BUS_ARN`): the same events as the AWS
  scanner (`Findings v1`), with the `aws` extra's boto3 and the credentials
  the container is given.
- **A file** (`FINDINGS_FILE`): the whole document, written atomically.

Only findings leave, never a value. Neither the URL nor the key is logged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sensitive_data_core import push as core_push
from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import (
    SIGNATURE_HEADER,
    FindingsSink,
    PushRejected,
    event_details,
    sign,
    verify,
)
from sensitive_data_core.safety import error_name, log_event

from . import __version__
from .config import Secret, Settings

MAX_ENTRIES_PER_CALL = 10

__all__ = [
    "SIGNATURE_HEADER",
    "EventBridgeSink",
    "FileSink",
    "HttpsSink",
    "PushRejected",
    "sign",
    "sinks_for",
    "verify",
]


class HttpsSink(core_push.HttpsSink):
    """The core's signed HTTPS sink, named as the databases runner."""

    def __init__(self, url: Secret, key: Secret, **kwargs: Any) -> None:
        kwargs.setdefault("user_agent", f"sensitive-data-scanner-db/{__version__}")
        super().__init__(url, key, **kwargs)


class EventBridgeSink:
    """The AWS scanner's events, sent from anywhere: `Findings v1` on a consumer's bus."""

    def __init__(self, bus_arn: str, client: Any | None = None) -> None:
        self.bus_arn = bus_arn
        self._client = client

    def _events(self) -> Any:
        if self._client is None:
            import boto3  # noqa: PLC0415 - the `aws` extra, only when this sink is used

            self._client = boto3.client("events", region_name=self.bus_arn.split(":")[3])
        return self._client

    def push(self, document: dict[str, Any]) -> int:
        entries = [
            {
                "Source": EVENT_SOURCE,
                "DetailType": EVENT_DETAIL_TYPE,
                "Detail": json.dumps(d, separators=(",", ":")),
                "EventBusName": self.bus_arn,
            }
            for d in event_details(document)
        ]
        sent = failed = 0
        for i in range(0, len(entries), MAX_ENTRIES_PER_CALL):
            batch = entries[i : i + MAX_ENTRIES_PER_CALL]
            try:
                r = self._events().put_events(Entries=batch)
            except Exception as err:
                failed += len(batch)
                log_event("events.failed", count=len(batch), error=error_name(err))
                continue
            n = int(r.get("FailedEntryCount", 0))
            failed += n
            sent += len(batch) - n
        if failed:
            log_event("events.failed", count=failed, error="FailedEntries")
        log_event("events.sent", count=sent)
        return sent


class FileSink:
    """The whole document to a file on a mounted volume, replaced atomically."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def push(self, document: dict[str, Any]) -> int:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(document, indent=2) + "\n")
        os.replace(tmp, self.path)
        return 1


def sinks_for(settings: Settings) -> list[FindingsSink]:
    out: list[FindingsSink] = []
    if settings.https_url is not None and settings.hmac_key is not None:
        out.append(HttpsSink(settings.https_url, settings.hmac_key))
    if settings.event_bus_arn:
        out.append(EventBridgeSink(settings.event_bus_arn))
    if settings.findings_file:
        out.append(FileSink(settings.findings_file))
    return out
