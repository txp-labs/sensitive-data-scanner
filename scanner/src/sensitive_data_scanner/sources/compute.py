"""Where applications leave data in passing: Step Functions history, Lambda environment
variables and X-Ray traces (#35). All three are read by default when discovered.

**Step Functions** (`DISCOVER` includes `stepfunctions`): `ListStateMachines`,
`DescribeStateMachine` (its encryption), then for each Standard state machine
the most recent executions (`ListExecutions`, `STEPFUNCTIONS_EXECUTIONS`) and
each one's history (`GetExecutionHistory` with its data, up to
`STEPFUNCTIONS_EVENTS` events): the input, output, parameters, result, error
and cause of every event are read. An Express state machine keeps no history
in the service (its runs go to CloudWatch Logs, read there), so it is reported
`unsupported` with `workflowType: express`. Nothing is started, stopped or
redriven; the role denies it.

**Lambda environment variables** (`lambda`): `ListFunctions`, then
`GetFunctionConfiguration` per function. Each variable's value is read with
its name as context, and reported like a secret: counts only, never the value.
A variable encrypted with a customer managed key the scanner may not use is
counted unreadable. The scanner's own function is never read (`self`).

**X-Ray** (`xray`): one store per account and region, `xray-traces`.
`GetTraceSummaries` (sampled) over the time since the last run (at most
`XRAY_LOOKBACK_HOURS`), then `BatchGetTraces` five at a time, up to
`XRAY_MAX_TRACES`: each segment's and subsegment's annotations and metadata are
read. A finding names the segment's service as `store`.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
import urllib.parse
from collections.abc import Iterator
from typing import Any

from sensitive_data_core.adapter import (
    Budget,
    FindingStore,
    SourceRun,
    class_findings,
    column_findings,
)
from sensitive_data_core.coverage import Discovery, Store, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import scan_rows
from sensitive_data_core.scan.item import scan_item_text

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import drop_other_passes, merge

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("stepfunctions", "lambda", "xray")

# The parts of an execution history event that carry data.
EVENT_FIELDS = ("input", "output", "parameters", "result", "error", "cause")
MAX_FIELD_CHARS = 256 * 1024  # an event's input or output is at most 256 KB
XRAY_STORE = "xray-traces"
XRAY_WINDOW = _dt.timedelta(hours=6)


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _fail(cov: Coverage, target: str, err: BaseException) -> None:
    cov.error = error_name(err)
    if is_kms_denial(err):
        cov.kms_denied += 1
    log_event("source.failed", source=target, error=cov.error)


# ------------------------------------------------------------------ Step Functions


class StepFunctionsAdapter:
    kind = "stepfunctions"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sfn = ctx.clients.client("stepfunctions")
        for page in sfn.get_paginator("list_state_machines").paginate():
            for m in page.get("stateMachines", []):
                name, arn = str(m["name"]), str(m["stateMachineArn"])
                store = Store(self.kind, name)
                out.stores.append(store)
                kind = str(m.get("type") or "STANDARD").lower()
                store.extra["workflowType"] = kind
                if kind != "standard":
                    store.skip("unsupported")  # Express: no history in the service
                    continue
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        r = sfn.list_tags_for_resource(resourceArn=arn)
                        store.tags = {
                            str(t["key"]): str(t.get("value", "")) for t in r.get("tags", [])
                        }
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status != "pending":
                    continue
                store.extra["arn"] = arn
                try:
                    d = sfn.describe_state_machine(stateMachineArn=arn)
                except Exception as err:
                    store.status, store.error = "error", error_name(err)
                    store.reason = reason_for(store.error)
                    continue
                enc = d.get("encryptionConfiguration") or {}
                keys = classifier(ctx.clients)
                if str(enc.get("type") or "AWS_OWNED_KEY") == "CUSTOMER_MANAGED_KMS_KEY":
                    store.facts = keys.facts(key=enc.get("kmsKeyId"))
                else:
                    store.facts = keys.facts(aws_owned=True)

    def source(self, ctx: Context, store: Store) -> StepFunctionsSource | None:
        arn = store.extra.get("arn")
        if not arn:
            return None
        return StepFunctionsSource(
            ctx.clients.client("stepfunctions"),
            name=store.name,
            arn=str(arn),
            region=ctx.region,
            executions=ctx.config.stepfunctions_executions,
            events=ctx.config.stepfunctions_events,
        )


class StepFunctionsSource:
    """One Standard state machine: its most recent executions' history, sampled."""

    kind = "stepfunctions"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        client: Any,
        *,
        name: str,
        arn: str,
        region: str,
        executions: int = 20,
        events: int = 500,
    ) -> None:
        self.client = client
        self.name = name
        self.arn = arn
        self.region = region
        self.executions = executions
        self.events = events
        self.id = f"stepfunctions:{_digest(arn)}"
        self.target = name

    def link(self) -> str:
        q = urllib.parse.quote(self.arn, safe="")
        return console_link(
            self.region, f"states/home?region={self.region}#/statemachines/view/{q}"
        )

    def _recent(self) -> list[str]:
        out: list[str] = []
        args: dict[str, Any] = {
            "stateMachineArn": self.arn,
            "maxResults": min(1000, self.executions),
        }
        while len(out) < self.executions:
            r = self.client.list_executions(**args)
            out.extend(str(e["executionArn"]) for e in r.get("executions", []))
            if not r.get("nextToken"):
                break
            args["nextToken"] = r["nextToken"]
        return out[: self.executions]  # newest first

    def _history(self, arn: str) -> Iterator[dict[str, Any]]:
        args: dict[str, Any] = {
            "executionArn": arn,
            "maxResults": min(1000, self.events),
            "includeExecutionData": True,
        }
        seen = 0
        while seen < self.events:
            r = self.client.get_execution_history(**args)
            for ev in r.get("events", []):
                seen += 1
                yield ev
                if seen >= self.events:
                    return
            if not r.get("nextToken"):
                return
            args["nextToken"] = r["nextToken"]

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        pass_id = str(cursor.get("passId") or secrets.token_hex(8))
        done_ids = set(cursor.get("read") or [])  # executions read this pass, by hash
        seen_at, link = now.isoformat(), self.link()
        complete = True
        try:
            recent = self._recent()
            cov.listed = len(recent)
            todo = [a for a in recent if _digest(a) not in done_ids]
            cov.eligible = len(todo)
            for arn in todo:
                if not budget.has(0):
                    complete = False
                    break
                for ev in self._history(arn):
                    for key, details in ev.items():
                        if not key.endswith("EventDetails") or not isinstance(details, dict):
                            continue
                        for field in EVENT_FIELDS:
                            text = details.get(field)
                            if not isinstance(text, str) or not text:
                                continue
                            text = text[:MAX_FIELD_CHARS]
                            budget.take(len(text))
                            cov.bytes_scanned += len(text)
                            item = scan_item_text(f"{field}.json", text, detector)
                            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                            cov.test_values += item.test_values
                            cov.suppressed += item.suppressed
                            cov.redaction_markers += item.redaction_markers
                            resource = store_field_resource(
                                service="stepfunctions",
                                store=self.name,
                                field=field,
                                read_by="execution_history",
                            )
                            for f in class_findings(
                                item.findings,
                                resource,
                                link,
                                item.format,
                                seen_at,
                                facts=self.facts,
                            ):
                                merge(store, f"{self.id}\n{field}", f, pass_id)
                cov.scanned += 1
                done_ids.add(_digest(arn))
        except Exception as err:  # recorded by name on the source
            _fail(cov, self.target, err)
            complete = False
        if complete:
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            return SourceRun(cov, {}, None, {})
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "read": sorted(done_ids)}, None, {})


# ------------------------------------------------------------------ Lambda


class LambdaAdapter:
    kind = "lambda"

    def discover(self, ctx: Context, out: Discovery) -> None:
        lam = ctx.clients.client("lambda")
        keys = classifier(ctx.clients)
        for page in lam.get_paginator("list_functions").paginate():
            for f in page.get("Functions", []):
                name = str(f["FunctionName"])
                store = Store(self.kind, name)
                out.stores.append(store)
                if name == ctx.config.self_function:
                    store.skip("self")
                    continue
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        r = lam.list_tags(Resource=str(f.get("FunctionArn")))
                        store.tags = {str(k): str(v) for k, v in (r.get("Tags") or {}).items()}
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status == "pending":
                    key = f.get("KMSKeyArn")
                    store.facts = keys.facts(key=key, aws_owned=not key)

    def source(self, ctx: Context, store: Store) -> LambdaEnvSource:
        return LambdaEnvSource(ctx.clients.client("lambda"), name=store.name, region=ctx.region)


class LambdaEnvSource:
    """One function's environment variables: each value read, reported as counts only."""

    kind = "lambda"
    facts: dict[str, Any] | None = None

    def __init__(self, client: Any, *, name: str, region: str) -> None:
        self.client = client
        self.name = name
        self.region = region
        self.id = f"lambda:{_digest(name)}"
        self.target = name

    def link(self) -> str:
        q = urllib.parse.quote(self.name, safe="")
        return console_link(
            self.region, f"lambda/home?region={self.region}#/functions/{q}?tab=configure"
        )

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        cov.listed = cov.eligible = 1
        try:
            r = self.client.get_function_configuration(FunctionName=self.name)
        except Exception as err:  # recorded by name on the source
            _fail(cov, self.target, err)
            return SourceRun(cov, {}, None, {})
        env = r.get("Environment") or {}
        if env.get("Error"):
            # A key the scanner may not use: Lambda returns the error, not the values.
            cov.unreadable = 1
            code = str((env.get("Error") or {}).get("ErrorCode") or "")
            cov.kms_denied = int("KMS" in code.upper())
            cov.pass_complete = True
            return SourceRun(cov, {}, None, {})
        variables = {str(k): str(v) for k, v in (env.get("Variables") or {}).items()}
        size = sum(len(k) + len(v) for k, v in variables.items())
        budget.take(size)
        cov.scanned, cov.bytes_scanned = 1, size
        table = scan_rows("json", list(variables), [variables], detector, 1)
        cov.formats["json"] = 1
        cov.test_values, cov.suppressed = table.test_values, table.suppressed
        cov.redaction_markers = table.redaction_markers

        def resource(variable: str) -> dict[str, Any]:
            return store_field_resource(
                service="lambda",
                store=self.name,
                field=variable,
                read_by="get_function_configuration",
            )

        findings = column_findings(table, resource, self.link(), now.isoformat(), facts=self.facts)
        store.replace_location(f"{self.id}\n{self.name}", findings)
        cov.pass_complete = True
        return SourceRun(cov, {}, None, {})


# ------------------------------------------------------------------ X-Ray


class XRayAdapter:
    kind = "xray"

    def discover(self, ctx: Context, out: Discovery) -> None:
        xray = ctx.clients.client("xray")
        store = Store(self.kind, XRAY_STORE)
        out.stores.append(store)
        decide(store, ctx.config)
        if store.status != "pending":
            return
        keys = classifier(ctx.clients)
        try:
            enc = xray.get_encryption_config().get("EncryptionConfig") or {}
        except Exception:  # traces are still read; their findings say `unknown`
            store.facts = keys.facts(encrypted=None)
            return
        # `NONE` is X-Ray's default: encrypted at rest with a key AWS holds.
        if str(enc.get("Type") or "NONE") == "KMS":
            store.facts = keys.facts(key=enc.get("KeyId"))
        else:
            store.facts = keys.facts(aws_owned=True)

    def source(self, ctx: Context, store: Store) -> XRaySource:
        return XRaySource(
            ctx.clients.client("xray"),
            region=ctx.region,
            max_traces=ctx.config.xray_max_traces,
            lookback_hours=ctx.config.xray_lookback_hours,
        )


def _segment_parts(doc: dict[str, Any], depth: int = 0) -> Iterator[tuple[str, str, Any]]:
    """(the segment's name, `annotations` or `metadata`, the value) for a segment and its
    subsegments."""
    if depth > 32:
        return
    name = str(doc.get("name") or "segment")
    for part in ("annotations", "metadata"):
        if doc.get(part):
            yield name, part, doc[part]
    for sub in doc.get("subsegments") or []:
        if isinstance(sub, dict):
            yield from _segment_parts(sub, depth + 1)


class XRaySource:
    """The account's traces since the last run, sampled: annotations and metadata."""

    kind = "xray"
    facts: dict[str, Any] | None = None

    def __init__(
        self, client: Any, *, region: str, max_traces: int = 100, lookback_hours: int = 24
    ) -> None:
        self.client = client
        self.region = region
        self.max_traces = max_traces
        self.lookback = _dt.timedelta(hours=lookback_hours)
        self.id = "xray:traces"
        self.target = XRAY_STORE

    def link(self) -> str:
        return console_link(self.region, f"cloudwatch/home?region={self.region}#xray:traces")

    def _trace_ids(self, start: _dt.datetime, end: _dt.datetime, want: int) -> list[str]:
        ids: list[str] = []
        args: dict[str, Any] = {"StartTime": start, "EndTime": end, "Sampling": True}
        while len(ids) < want:
            r = self.client.get_trace_summaries(**args)
            ids.extend(str(t["Id"]) for t in r.get("TraceSummaries", []) if t.get("Id"))
            if not r.get("NextToken"):
                break
            args["NextToken"] = r["NextToken"]
        return ids[:want]

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        pass_id = secrets.token_hex(8)
        seen_at, link = now.isoformat(), self.link()
        end = now - _dt.timedelta(minutes=1)
        mark = cursor.get("watermark")
        start = (
            max(_dt.datetime.fromisoformat(mark), end - self.lookback)
            if mark
            else (end - self.lookback)
        )
        try:
            while start < end and cov.listed < self.max_traces and budget.has(0):
                window_end = min(end, start + XRAY_WINDOW)
                ids = self._trace_ids(start, window_end, self.max_traces - cov.listed)
                cov.listed += len(ids)
                cov.eligible += len(ids)
                for i in range(0, len(ids), 5):  # BatchGetTraces takes five
                    if not budget.has(0):
                        cov.partial += 1  # the rest of the window is left: a sample
                        break
                    r = self.client.batch_get_traces(TraceIds=ids[i : i + 5])
                    for trace in r.get("Traces", []):
                        cov.scanned += 1
                        for seg in trace.get("Segments", []):
                            self._segment(
                                seg,
                                cov=cov,
                                budget=budget,
                                detector=detector,
                                store=store,
                                seen_at=seen_at,
                                link=link,
                                pass_id=pass_id,
                            )
                start = window_end
        except Exception as err:  # recorded by name on the source
            _fail(cov, self.target, err)
            return SourceRun(cov, dict(cursor), None, {})
        cov.pass_complete = start >= end
        cov.backlog = not cov.pass_complete
        return SourceRun(cov, {"watermark": start.isoformat()}, None, {})

    def _segment(
        self,
        seg: dict[str, Any],
        *,
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        link: str,
        pass_id: str,
    ) -> None:
        try:
            doc = json.loads(str(seg.get("Document") or "{}"))
        except ValueError:
            cov.unreadable += 1
            return
        if not isinstance(doc, dict):
            return
        for service, part, value in _segment_parts(doc):
            text = json.dumps(value, default=str)[:MAX_FIELD_CHARS]
            budget.take(len(text))
            cov.bytes_scanned += len(text)
            item = scan_item_text(f"{part}.json", text, detector)
            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            resource = store_field_resource(
                service="xray", store=service, field=part, read_by="batch_get_traces"
            )
            for f in class_findings(
                item.findings, resource, link, item.format, seen_at, facts=self.facts
            ):
                merge(store, f"{self.id}\n{service}\n{part}", f, pass_id)
