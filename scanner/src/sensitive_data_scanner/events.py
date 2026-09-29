"""Findings as EventBridge events, pushed to a consumer-owned bus.

Optional in batch mode (set `FINDINGS_EVENT_BUS_ARN`), and the delivery path
of the event-driven phase 2 (docs/ARCHITECTURE.md). The runner calls
PutEvents from the account it scans onto a bus in the consumer's account;
the consumer's bus policy allows that account. The consumer receives, and
never calls in.

Each event: `source` "sensitive-data-scanner", `detail-type` "Findings v1",
and a `detail` that is a findings document (the same schema as
findings/latest.json) holding a slice of the run's findings. An event stays
under EventBridge's 256 KB limit; a run with more findings sends several,
numbered by `part` and `parts`.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from .safety import error_name, log_event

if TYPE_CHECKING:
    from mypy_boto3_events import EventBridgeClient

MAX_DETAIL_BYTES = 200_000  # below the 256 KB event limit, with room for the envelope
MAX_ENTRIES_PER_CALL = 10


def event_details(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The document split into event details, each under the size limit."""
    base = {k: v for k, v in document.items() if k != "findings"}
    chunks: list[list[dict[str, Any]]] = [[]]
    size = len(json.dumps(base))
    for f in document["findings"]:
        n = len(json.dumps(f)) + 1
        if chunks[-1] and size + n > MAX_DETAIL_BYTES:
            chunks.append([])
            size = len(json.dumps(base))
        chunks[-1].append(f)
        size += n
    parts = len(chunks)
    return [{**base, "part": i + 1, "parts": parts, "findings": c} for i, c in enumerate(chunks)]


def put_findings_events(client: EventBridgeClient, bus_arn: str, document: dict[str, Any]) -> int:
    """Send the run's findings to the bus. Returns how many events were accepted."""
    entries = [
        {
            "Source": EVENT_SOURCE,
            "DetailType": EVENT_DETAIL_TYPE,
            "Detail": json.dumps(d, separators=(",", ":")),
            "EventBusName": bus_arn,
        }
        for d in event_details(document)
    ]
    sent = 0
    failed = 0
    for i in range(0, len(entries), MAX_ENTRIES_PER_CALL):
        batch = entries[i : i + MAX_ENTRIES_PER_CALL]
        try:
            r = client.put_events(Entries=batch)  # type: ignore[arg-type]
        except Exception as err:  # reported by name; the results bucket still holds the run
            failed += len(batch)
            log_event("events.failed", count=len(batch), error=error_name(err))
            continue
        failed += int(r.get("FailedEntryCount", 0))
        sent += len(batch) - int(r.get("FailedEntryCount", 0))
    if failed:
        log_event("events.failed", count=failed, error="FailedEntries")
    log_event("events.sent", count=sent)
    return sent
