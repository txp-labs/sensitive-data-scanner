"""Where the databases runner's findings go: the core's `FindingsSink`, three ways.

- **HTTPS, signed** (`FINDINGS_HTTPS_URL`): each part of the document is
  POSTed as JSON with `X-SDS-Signature: t=<unix time>,v1=<hex>`, where `v1`
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

import hashlib
import hmac
import json
import os
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import FindingsSink, event_details
from sensitive_data_core.safety import error_name, log_event

from . import __version__
from .config import Secret, Settings

SIGNATURE_HEADER = "X-SDS-Signature"
RETRIES = 3
MAX_ENTRIES_PER_CALL = 10


def sign(key: bytes, timestamp: str, body: bytes) -> str:
    """The signature header's value for one body."""
    mac = hmac.new(key, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(key: bytes, header: str, body: bytes, now: float, tolerance: int = 300) -> bool:
    """What a receiver does: the signature matches and the timestamp is recent."""
    fields = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    t, v1 = fields.get("t", ""), fields.get("v1", "")
    if not t.isdigit() or abs(now - int(t)) > tolerance:
        return False
    return hmac.compare_digest(sign(key, t, body), f"t={t},v1={v1}")


class PushRejected(Exception):
    """The endpoint answered with a status that is not a success; `code` is the status."""

    code = 0


class HttpsSink:
    """POST each part of the document to the customer's (or Mermera's) HTTPS endpoint."""

    def __init__(
        self,
        url: Secret,
        key: Secret,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = url
        self._key = key
        self._open = opener
        self._sleep = sleep
        self._clock = clock

    def __repr__(self) -> str:
        return "HttpsSink(***)"

    def _post(self, body: bytes, part: int, parts: int) -> None:
        ts = str(int(self._clock()))
        req = urllib.request.Request(  # noqa: S310 - https only (config.py)
            self._url.reveal(),
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"sensitive-data-scanner-db/{__version__}",
                SIGNATURE_HEADER: sign(self._key.reveal().encode(), ts, body),
                "X-SDS-Part": f"{part}/{parts}",
            },
        )
        with self._open(req, timeout=30) as resp:
            status = int(getattr(resp, "status", 200))
            if status >= 300:
                rejected = PushRejected()
                rejected.code = status
                raise rejected

    def push(self, document: dict[str, Any]) -> int:
        details = event_details(document)
        sent = 0
        for detail in details:
            body = json.dumps(detail, separators=(",", ":")).encode()
            for attempt in range(RETRIES):
                try:
                    self._post(body, int(detail["part"]), int(detail["parts"]))
                    sent += 1
                    break
                except Exception as err:  # retried, then reported by name only
                    code = getattr(err, "code", None)
                    final = attempt == RETRIES - 1 or (
                        isinstance(code, int) and 400 <= code < 500 and code != 429
                    )
                    if final:
                        log_event("events.failed", count=1, error=error_name(err))
                        break
                    self._sleep(2**attempt)
        log_event("events.sent", count=sent)
        return sent


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
