"""Findings as EventBridge events, pushed to a consumer-owned bus.

Optional in batch mode (set `FINDINGS_EVENT_BUS_ARN`), and the delivery path
of the event-driven phase 2 (docs/ARCHITECTURE.md). The runner calls
PutEvents from the account it scans onto a bus in the consumer's account;
the consumer's bus policy allows that account. The consumer receives, and
never calls in.

Each event: `source` "sensitive-data-scanner", `detail-type` "Findings v1",
and a `detail` that is a findings document (the same schema as
findings/latest.json) holding a slice of the run's findings, coverage and
discovered stores. An event stays under EventBridge's 256 KB limit; a larger
run sends several, numbered by `part` and `parts` (`sensitive_data_core.push`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_core.push import event_details
from sensitive_data_core.safety import error_name, log_event

if TYPE_CHECKING:
    from mypy_boto3_events import EventBridgeClient

MAX_ENTRIES_PER_CALL = 10


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


@dataclass
class EventBridgeSink:
    """The AWS findings sink (`sensitive_data_core.push.FindingsSink`): a consumer-owned bus."""

    client: Any
    bus_arn: str

    def push(self, document: dict[str, Any]) -> int:
        return put_findings_events(self.client, self.bus_arn, document)
