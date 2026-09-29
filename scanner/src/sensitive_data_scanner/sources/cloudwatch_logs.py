"""CloudWatch Logs source: one log group, read with FilterLogEvents.

An Amazon Connect flow log group (`/aws/connect/<alias>`), a Lex V2
conversation log group, a fulfillment Lambda's `/aws/lambda/<name>`. No
export and no Logs Insights (which bills per GB scanned).

Incremental by event time: each run reads from the watermark (the end of the
last window it finished) in windows of at most 24 hours, up to two minutes
ago (for late events). The first run looks back `lookback_days`.

Budgeted: when a window has more events than the run's share of the budget,
the events read so far are scanned, the rest of that window is skipped, and
the coverage says so (`partial`, one per window cut short).

Lex V2 records are grouped by session within a window, so the bot's prompt in
one record classes the customer's answer in the next.

A finding is one log event: group, stream and timestamp.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Analysis, Detection, Detector
from sensitive_data_core.engine.conversation import utf16_index
from sensitive_data_core.findings import Coverage, Offset, finding_json
from sensitive_data_core.parsers import Conversation, is_lex_record, parse_lex_records
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.item import ItemResult, _Collector, scan_log_event

from ..resources import log_resource, logs_link

if TYPE_CHECKING:
    from mypy_boto3_logs import CloudWatchLogsClient

WINDOW_MS = 24 * 60 * 60 * 1000
SETTLE_MS = 2 * 60 * 1000


class CloudWatchLogsSource:
    kind = "cloudwatch_logs"

    def __init__(
        self,
        client: CloudWatchLogsClient,
        *,
        log_group: str,
        region: str,
        lookback_days: int = 7,
    ) -> None:
        self.client = client
        self.log_group = log_group
        self.region = region
        self.lookback_days = lookback_days
        self.id = f"logs:{log_group}"
        self.target = log_group

    def _record(
        self,
        store: FindingStore,
        stream: str,
        ts: int,
        item: ItemResult,
        *,
        seen_at: str,
        cov: Coverage,
    ) -> None:
        cov.scanned += 1
        cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
        cov.redaction_markers += item.redaction_markers
        cov.test_values += item.test_values
        cov.suppressed += item.suppressed
        if not item.findings:
            return
        resource = log_resource(self.log_group, stream, ts)
        link = logs_link(self.region, self.log_group, stream, ts)
        connect = (
            {"contactId": item.contact_id, "instanceId": item.instance_id or ""}
            if item.contact_id
            else None
        )
        for cf in item.findings.values():
            store.put(
                f"{self.id}\n{stream}\n{ts}",
                finding_json(resource, link, item.format, cf, seen_at, connect=connect),
            )

    def _flush_lex(
        self,
        pending: dict[str, list[tuple[int, dict[str, Any]]]],
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        cov: Coverage,
    ) -> None:
        """Scan buffered Lex records one session at a time. A value is reported on the
        event that holds its (first part of the) answer."""
        for stream, events in pending.items():
            collectors: dict[int, _Collector] = {}
            for conv in parse_lex_records([r for _, r in events]):
                analysis = detector.analyze_conversation(conv.turns)
                if conv.turns:
                    first = collectors.setdefault(
                        int(conv.pointers[0].split("/")[1]), _Collector("lex_v2_log")
                    )
                    first.add(Analysis([], analysis.test_values, analysis.suppressed), list)
                for d in analysis.detections:
                    n = int(conv.pointers[d.spans[0].turn or 0].split("/")[1])
                    col = collectors.setdefault(n, _Collector("lex_v2_log"))

                    def offsets(
                        det: Detection, n: int = n, conv: Conversation = conv
                    ) -> list[Offset]:
                        out = []
                        for sp in det.spans:
                            turn = sp.turn or 0
                            pointer = conv.pointers[turn]
                            if int(pointer.split("/")[1]) != n:
                                continue
                            text = conv.turns[turn].text
                            out.append(
                                Offset(
                                    utf16_index(text, sp.start),
                                    utf16_index(text, sp.end),
                                    "/" + pointer.split("/", 2)[2],
                                )
                            )
                        return out

                    col.add(Analysis([d]), offsets)
            for n, (ts, _) in enumerate(events):
                found = collectors.get(n)
                item = found.result if found else ItemResult("lex_v2_log")
                self._record(store, stream, ts, item, seen_at=seen_at, cov=cov)
        pending.clear()

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("cloudwatch_logs", self.target)
        now_ms = int(now.timestamp() * 1000)
        end = now_ms - SETTLE_MS
        start = cursor.get("watermarkMs")
        if not isinstance(start, int):
            start = now_ms - self.lookback_days * 24 * 60 * 60 * 1000
        seen_at = now.isoformat()
        try:
            while start < end and budget.time_left():
                window_end = min(end, start + WINDOW_MS)
                token: str | None = None
                cut = False
                pending: dict[str, list[tuple[int, dict[str, Any]]]] = {}
                while True:
                    args: dict[str, Any] = {
                        "logGroupName": self.log_group,
                        "startTime": start,
                        "endTime": window_end - 1,
                        "limit": 1000,
                    }
                    if token:
                        args["nextToken"] = token
                    page = self.client.filter_log_events(**args)
                    for ev in page.get("events", []):
                        message = ev.get("message", "")
                        cov.listed += 1
                        cov.eligible += 1
                        size = len(message.encode("utf-8"))
                        if not budget.has(size):
                            cut = True
                            break
                        budget.take(size)
                        cov.bytes_scanned += size
                        stream = ev.get("logStreamName", "")
                        ts = int(ev.get("timestamp", 0))
                        doc = _try_json(message)
                        if is_lex_record(doc):
                            pending.setdefault(stream, []).append((ts, doc))
                            continue
                        item = scan_log_event(message, detector)
                        self._record(store, stream, ts, item, seen_at=seen_at, cov=cov)
                    token = None if cut else page.get("nextToken")
                    if not token:
                        break
                self._flush_lex(pending, detector, store, seen_at, cov)
                if cut:
                    cov.partial += 1
                start = window_end
                if cut:
                    break
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
        cov.pass_complete = cov.error is None and start >= end
        cov.backlog = cov.error is None and start < end
        return SourceRun(cov, {"watermarkMs": start})


def _try_json(message: str) -> Any:
    t = message.strip()
    if not t.startswith("{"):
        return None
    try:
        return json.loads(t)
    except ValueError:
        return None
