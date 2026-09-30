"""Slack's DLP events, from the Audit Logs API, imported (#55).

With `SCAN_MODE_SLACK` `vendor` or `both`, the scanner reads the Audit Logs
API (`GET https://api.slack.com/audit/v1/logs`, Enterprise Grid only, an
org-level token with `auditlogs:read` in `SLACK_AUDIT_TOKEN_FILE`) for the
actions Slack's native DLP (or a DLP partner) records, named in
`SLACK_DLP_AUDIT_ACTIONS`, since the last run.

Each event becomes a finding with `source: vendor:slack_dlp`, class `other`
and `vendorType` the event's action (an audit event names the rule that
matched, not the kind of data), on the entity it names:

- a **message**: its channel and timestamp, the same `itemHash` as this
  scanner's finding for that message;
- a **file**: its id, the same `itemHash` as this scanner's finding for it.

The event says which rule matched, not the kind of data, so its class is
`other` and it is never linked to a scanner finding (a link needs the same
class): a consumer can still match the two by `itemHash` (`no_data_class`).

**Never read into a finding:** the actor (their address included), the
rule's name, the message's text or the file's name, and anything else in the
event's `details`.

Coverage: Enterprise Grid only (`enterprise_grid_only`), and only the rules
the organization set and their events (`policy_matches_only`).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.modes import (
    VendorCoverage,
    VendorDetection,
    hashed,
    vendor_finding,
    vendor_type,
)
from sensitive_data_core.safety import error_name, log_event

from ..resources import saas_item, tenant_hash
from .base import Context, vendor_facts
from .slack import team_of

VENDOR = "slack_dlp"
ID = "vendor:slack_dlp"
AUDIT = "https://api.slack.com/audit/v1/logs"
COVERS = ("slack_channel", "slack_dm")
LIMITS = ("enterprise_grid_only", "policy_matches_only", "no_data_class")


class SlackAuditImporter:
    id = ID
    vendor = VENDOR
    platform = "slack"
    covers = COVERS

    def __init__(self, ctx: Context, mode: str) -> None:
        self.ctx = ctx
        self.mode = mode

    def __repr__(self) -> str:
        return "SlackAuditImporter()"

    def run(
        self, cursor: dict[str, Any], budget: Budget, store: FindingStore, now: _dt.datetime
    ) -> tuple[VendorCoverage, dict[str, Any]]:
        cov = VendorCoverage(VENDOR, self.platform, self.mode, covers=COVERS, limits=LIMITS)
        sl = self.ctx.settings.slack
        if sl is None or sl.audit_token is None:  # pragma: no cover - the settings require it
            cov.status, cov.error = "error", "NoAuditToken"
            return cov, dict(cursor)
        lookback = _dt.timedelta(days=self.ctx.settings.lookback_days)
        oldest = int(cursor.get("oldest") or (now - lookback).timestamp())
        newest = oldest
        api = self.ctx.clients.slack_audit
        facts = vendor_facts(sl.ekm_key_id)
        try:
            _, tenant = team_of(self.ctx)
            for action in sl.dlp_actions:
                for page, _, _ in api.audit_pages(
                    AUDIT, {"action": action, "oldest": str(oldest), "limit": "200"}
                ):
                    for event in page:
                        if not budget.time_left():
                            break
                        found = self._one(event, tenant, facts, now)
                        if found is None:
                            continue
                        eid, finding, when = found
                        store.replace_location(f"{ID}\n{hashed(eid)}", [finding])
                        cov.findings += 1
                        newest = max(newest, when)
        except Exception as err:  # what was imported stands
            name = error_name(err)
            denied = (
                "missing_scope",
                "not_allowed_token_type",
                "invalid_auth",
                "feature_not_enabled",
            )
            cov.status = "access_denied" if name in denied else "error"
            cov.error = name
            log_event("source.failed", source=ID, error=name)
            return cov, dict(cursor)
        return cov, {"oldest": newest}

    def _one(
        self, event: dict[str, Any], tenant: str, facts: dict[str, Any], now: _dt.datetime
    ) -> tuple[str, dict[str, Any], int] | None:
        eid = str(event.get("id") or "")
        entity = event.get("entity") if isinstance(event.get("entity"), dict) else {}
        kind = str((entity or {}).get("type") or "")
        if not eid:
            return None
        if kind == "file":
            item = str(((entity or {}).get("file") or {}).get("id") or "")
            part, channel = "attachment", None
        elif kind == "message":
            msg = (entity or {}).get("message") or {}
            channel = str(msg.get("channel") or "") or None
            ts = str(msg.get("timestamp") or msg.get("ts") or "")
            item = f"{channel}/{ts}" if channel and ts else ""
            part = "message"
        else:
            return None
        if not item:
            return None
        service = "dm" if (channel or "").startswith("D") else "channel"
        resource = saas_item("slack", service, tenant_hash(tenant), item, part, channel=channel)
        finding = vendor_finding(
            resource,
            None,
            VendorDetection("other", vendor_type(event.get("action")) or "DLP_EVENT", 0, 1),
            vendor=VENDOR,
            seen_at=now.isoformat(),
            vendor_finding_id=hashed(eid)[:32],
            facts=facts,
        )
        when = int(event.get("date_create") or 0)
        return eid, finding, when
