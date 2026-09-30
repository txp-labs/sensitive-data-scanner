"""The findings push: how a run's findings document leaves the environment it scans.

A sink takes the findings document and delivers it; the runner does not know
where. Every platform uses the same document and the same split into parts:
EventBridge on AWS (`sensitive_data_scanner.events`), Event Grid on Azure
(`sensitive_data_azure.sinks`), and from anywhere an HTTPS endpoint with an
HMAC signature (`HttpsSink`, here: it needs no cloud SDK). A part stays
under EventBridge's 256 KB event limit, which also keeps an HTTPS body small;
a larger run sends several, numbered by `part` and `parts`, and the union of
the parts is the document. Only findings leave: never a value.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from . import __version__
from .safety import error_name, log_event


class FindingsSink(Protocol):
    """Somewhere a run's findings document goes."""

    def push(self, document: dict[str, Any]) -> int:
        """Deliver the document (in parts). Returns how many parts were accepted."""
        ...


MAX_DETAIL_BYTES = 200_000  # below the 256 KB event limit, with room for the envelope


def event_details(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The document split into event details, each under the size limit.

    `findings`, `coverage` and the discovery summary's `stores` are the lists
    that grow with the estate; each is split across the parts, and the union
    of the parts is the document. Everything else is repeated in every part.
    """
    discovery = document.get("discovery")
    base = {k: v for k, v in document.items() if k not in ("findings", "coverage", "discovery")}
    head = dict(discovery, stores=[]) if isinstance(discovery, dict) else None
    fixed = len(json.dumps(base)) + (len(json.dumps(head)) if head is not None else 0) + 64
    entries: list[tuple[str, Any]] = [("findings", f) for f in document.get("findings", [])]
    entries += [("coverage", c) for c in document.get("coverage", [])]
    if isinstance(discovery, dict):
        entries += [("stores", s) for s in discovery.get("stores", [])]
    chunks: list[list[tuple[str, Any]]] = [[]]
    size = fixed
    for entry in entries:
        n = len(json.dumps(entry[1])) + 1
        if chunks[-1] and size + n > MAX_DETAIL_BYTES:
            chunks.append([])
            size = fixed
        chunks[-1].append(entry)
        size += n
    parts = len(chunks)
    out = []
    for i, chunk in enumerate(chunks):
        detail: dict[str, Any] = {
            **base,
            "part": i + 1,
            "parts": parts,
            "findings": [v for k, v in chunk if k == "findings"],
            "coverage": [v for k, v in chunk if k == "coverage"],
        }
        if head is not None:
            detail["discovery"] = dict(head, stores=[v for k, v in chunk if k == "stores"])
        out.append(detail)
    return out


# ------------------------------------------------------------------ HTTPS, signed

SIGNATURE_HEADER = "X-SDS-Signature"
RETRIES = 3


class Revealable(Protocol):
    """A secret held so that no repr shows it (`safety.Secret`)."""

    def reveal(self) -> str: ...


def sign(key: bytes, timestamp: str, body: bytes) -> str:
    """The signature header's value for one body: HMAC-SHA256 of `<t>.` and the body."""
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
    """POST each part of the document to the customer's (or Mermera's) HTTPS endpoint.

    Each part is sent as JSON with `X-SDS-Signature: t=<unix time>,v1=<hex>`, where `v1`
    is HMAC-SHA256 under the shared key of `<t>.` followed by the exact body, and
    `X-SDS-Part: <part>/<parts>`. A 5xx or 429 is retried; neither the URL nor the key
    is ever logged."""

    def __init__(
        self,
        url: Revealable,
        key: Revealable,
        *,
        user_agent: str = f"sensitive-data-scanner/{__version__}",
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = url
        self._key = key
        self._agent = user_agent
        self._open = opener
        self._sleep = sleep
        self._clock = clock

    def __repr__(self) -> str:
        return "HttpsSink(***)"

    def _post(self, body: bytes, part: int, parts: int) -> None:
        ts = str(int(self._clock()))
        req = urllib.request.Request(  # noqa: S310 - https only (each platform's settings)
            self._url.reveal(),
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": self._agent,
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
