"""Cloud Logging: every project's logs, one sampled `entries.list` per log. Read by default.

**Discovery** (`DISCOVER` includes `cloud_logging`): every project in scope
(Cloud Asset Inventory's projects) is one store, named by the project id. Its
log buckets (`logging.buckets.list`) say whether its `_Default` bucket is under
a customer key.

**Reading** needs Logs Viewer's `logging.logs.list` and `logging.logEntries.list`:

1. the project's logs (`logs.list`), sorted, at most `LOGGING_MAX_LOGS`;
2. for each, one `entries.list` with a filter on that log and the lookback
   window (`LOGGING_LOOKBACK_DAYS`, 1), newest first, at most
   `LOGGING_MAX_ENTRIES_PER_LOG` (500), the log's name quoted so that nothing
   in it is filter syntax;
3. each entry read by column: `textPayload`, and the top-level fields of
   `jsonPayload` and `protoPayload` (`jsonPayload.<field>`), with `labels`.

**Data Access audit logs** (`cloudaudit.googleapis.com/data_access`, and
Access Transparency's) are private: reading them needs Private Logs Viewer
(`logging.privateLogEntries.list`), which is **opt-in**
(`LOGGING_PRIVATE_READ=on`); otherwise each is counted as skipped
`private_log`. `entries.list` is free, but a project allows 60 calls a minute:
a pass that meets the quota stops and resumes at that log next run.

**Encryption (1.5):** the `_Default` bucket's Cloud KMS key (`cmekSettings`),
hashed, else Google's own keys (`service_managed`).
"""

from __future__ import annotations

import datetime as _dt
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import scan_rows

from ..clients import Rest
from ..resources import Located, console_link
from .base import Context, kms_facts
from .common import call_gap

KIND = "cloud_logging"
API = "https://logging.googleapis.com/v2"
PRIVATE_LOGS = (
    "cloudaudit.googleapis.com/data_access",
    "cloudaudit.googleapis.com/access_transparency",
)
PAYLOADS = ("jsonPayload", "protoPayload")


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def log_id(name: str) -> str:
    """A log's id from its name (`projects/p/logs/cloudaudit.googleapis.com%2Factivity`)."""
    return urllib.parse.unquote(name.rsplit("/logs/", 1)[-1])


def filter_for(name: str, since: _dt.datetime) -> str:
    """The `entries.list` filter for one log and the window, the log's name quoted."""
    quoted = '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f'logName={quoted} AND timestamp>="{stamp}"'


def entry_row(entry: dict[str, Any]) -> dict[str, Any]:
    """One log entry as columns: its text payload, its payloads' top-level fields, labels."""
    row: dict[str, Any] = {}
    if isinstance(entry.get("textPayload"), str):
        row["textPayload"] = entry["textPayload"]
    for key in PAYLOADS:
        payload = entry.get(key)
        if isinstance(payload, dict):
            for field, v in payload.items():
                if not str(field).startswith("@"):
                    row[f"{key}.{field}"] = v
    if isinstance(entry.get("labels"), dict):
        row["labels"] = entry["labels"]
    return row


@dataclass
class ProjectTarget:
    where: Located

    @property
    def project(self) -> str:
        return self.where.project

    def __repr__(self) -> str:
        return f"ProjectTarget({redact_digits(self.project)!r})"


class LoggingAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        for number, project in sorted(ctx.projects().items(), key=lambda p: p[1]):
            where = Located(project, f"//cloudresourcemanager.googleapis.com/projects/{number}")
            store = Store(KIND, project)
            store.extra.update(where.fields())
            store.facts = self._key(ctx, project)
            store.table = ProjectTarget(where)
            out.stores.append(store)
            apply_rules(store, ctx.settings.allow, ctx.settings.deny)

    def _key(self, ctx: Context, project: str) -> dict[str, str]:
        try:
            got = ctx.rest.get(f"{API}/projects/{_q(project)}/locations/-/buckets")
        except Exception as err:  # the key stays Google's; the project is still read
            log_event("discovery.failed", kind=KIND, error=error_name(err))
            return kms_facts(None)
        for b in got.get("buckets") or []:
            if isinstance(b, dict) and str(b.get("name") or "").endswith("/buckets/_Default"):
                return kms_facts((b.get("cmekSettings") or {}).get("kmsKeyName") or None)
        return kms_facts(None)

    def source(self, ctx: Context, store: Store) -> LoggingSource | None:
        t = store.table
        if not isinstance(t, ProjectTarget):
            return None
        s = ctx.settings
        return LoggingSource(
            ctx.rest,
            t,
            lookback_days=s.logging_lookback_days,
            max_entries=s.logging_max_entries,
            max_logs=s.logging_max_logs,
            private=s.logging_private_read,
        )


class LoggingSource:
    """One project: its logs, each sampled with one `entries.list`."""

    kind = KIND

    def __init__(
        self,
        rest: Rest,
        target: ProjectTarget,
        *,
        lookback_days: int = 1,
        max_entries: int = 500,
        max_logs: int = 200,
        private: bool = False,
    ) -> None:
        self.rest = rest
        self.t = target
        self.lookback_days = lookback_days
        self.max_entries = max_entries
        self.max_logs = max_logs
        self.private = private
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"logging:{target.project}"
        self.target = target.project

    def __repr__(self) -> str:
        return f"LoggingSource({self.t!r})"

    def _logs(self) -> list[str]:
        url = f"{API}/projects/{_q(self.t.project)}/logs"
        names: list[str] = []
        for page, _ in self.rest.pages(url, "logNames", {"pageSize": "1000"}):
            names.extend(str(n) for n in page)
            if len(names) >= self.max_logs * 4:
                break
        return sorted(set(names))[: self.max_logs]

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target)
        try:
            logs = self._logs()
        except Exception as err:  # the project's logs could not be listed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            gap = call_gap(err)
            return SourceRun(cov, cursor, note=gap if gap == "network" else None)
        after = cursor.get("after")
        cov.listed = len(logs)
        todo = [n for n in logs if after is None or n > after]
        cov.eligible = len(todo)
        since = now - _dt.timedelta(days=self.lookback_days)
        t = self.t
        link = console_link("logs/query", {"project": t.project})
        seen_at = now.isoformat()
        done = True
        for name in todo:
            lid = log_id(name)
            if lid in PRIVATE_LOGS and not self.private:
                cov.skipped["private_log"] = cov.skipped.get("private_log", 0) + 1
                after = name
                continue
            if not budget.has():
                done = False
                break
            body = {
                "resourceNames": [f"projects/{t.project}"],
                "filter": filter_for(name, since),
                "orderBy": "timestamp desc",
                "pageSize": self.max_entries,
            }
            try:
                got = self.rest.post(f"{API}/entries:list", body)
            except Exception as err:
                e = error_name(err)
                if e == "RESOURCE_EXHAUSTED":  # the project's read quota: resume here next run
                    log_event("source.throttled", source=self.target, kind=KIND)
                    done = False
                    break
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=e)
                after = name
                continue
            rows = [entry_row(e) for e in got.get("entries") or [] if isinstance(e, dict)]
            size = len(json.dumps(rows, default=str))
            budget.take(size)
            columns = list(dict.fromkeys(k for r in rows for k in r))
            result = scan_rows("json", columns, rows, detector, self.max_entries)
            cov.scanned += 1
            cov.bytes_scanned += size
            cov.partial += int(len(rows) >= self.max_entries)
            cov.test_values += result.test_values
            cov.suppressed += result.suppressed
            cov.redaction_markers += result.redaction_markers
            cov.formats["json"] = cov.formats.get("json", 0) + 1

            def resource(column: str, table: str = lid) -> dict[str, Any]:
                out = store_field_resource(
                    service=KIND, store=t.project, table=table, field=column, read_by="entries_list"
                )
                out.update(t.where.fields())
                return out

            store.replace_location(
                f"{self.id}\n{name}",
                column_findings(result, resource, link, seen_at, facts=self.facts),
            )
            after = name
        cov.pass_complete, cov.backlog = done, not done
        return SourceRun(cov, {"after": None if done else after})
