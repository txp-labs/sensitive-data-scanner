"""Google Workspace DLP's rule violations, from the Alert Center, imported (#55).

With `SCAN_MODE_GOOGLE_WORKSPACE` `vendor` or `both`, the scanner lists the
Alert Center's DLP alerts (`alerts.list`, `type="DlpRuleViolation"`, created
since the last run) as `GWS_ADMIN_USER`, through domain-wide delegation of
`https://www.googleapis.com/auth/apps.alerts`.

**That scope is not read-only by its name**: it also lets its holder change an
alert's feedback, delete or undelete it. So the delegated administrator must
hold an admin role whose Alert Center privilege is **View** only (docs/SAAS.md):
Google then refuses any change whatever the scope. The scanner only lists.

Each violation becomes one finding per detector that matched, with
`source: vendor:google_workspace_dlp`:

- **Where:** the data source (`DRIVE` to `drive`, `GMAIL` to `gmail`, `CHAT`
  to `chat`) and, for Drive, the document's id: the same `itemHash` as this
  scanner's Drive finding for that file, so `both` mode links them. The
  triggering user is only their address's hash (`ownerHash`).
- **Class:** a predefined detector's name maps to the spec's class
  (`CREDIT_CARD_NUMBER` to `card`, `US_SOCIAL_SECURITY_NUMBER` to `us_ssn`,
  ...), else `other`; a custom detector is `other`, `custom:<its name>`
  masked.
- **Never read into a finding:** the resource's title, the recipients, the
  triggering user's address, the rule's name, and anything else.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.modes import (
    VendorCoverage,
    VendorDetection,
    hashed,
    vendor_class,
    vendor_finding,
)
from sensitive_data_core.safety import error_name, log_event

from ..resources import owner_hash, saas_item
from ..scopes import GWS_ALERTS
from .base import Context
from .gws import VENDOR as GWS
from .gws import facts_of, settings_of, tenant_of

VENDOR = "google_workspace_dlp"
ID = "vendor:google_workspace_dlp"
ALERTS = "https://alertcenter.googleapis.com/v1beta1/alerts"
COVERS = ("gws_gmail", "gws_drive", "gws_shared_drive")
LIMITS = ("alerts_only", "policy_matches_only")
SERVICES = {"DRIVE": "drive", "GMAIL": "gmail", "CHAT": "chat"}
TYPES = {
    "CREDIT_CARD_NUMBER": "card",
    "CREDIT_CARD_TRACK_NUMBER": "card",
    "US_SOCIAL_SECURITY_NUMBER": "us_ssn",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "us_itin",
    "DATE_OF_BIRTH": "dob",
    "FINANCIAL_ACCOUNT_NUMBER": "account_number",
    "IBAN_CODE": "account_number",
}


def _detections(info: dict[str, Any]) -> list[VendorDetection]:
    out: dict[tuple[str, str | None], VendorDetection] = {}
    for m in info.get("matchInfo") or []:
        if not isinstance(m, dict):
            continue
        predefined = m.get("predefinedDetector") or {}
        custom = m.get("userDefinedDetector") or {}
        if predefined.get("detectorName"):
            cls, name = vendor_class(predefined["detectorName"], TYPES)
        elif custom.get("displayName"):
            cls, raw = vendor_class(custom["displayName"], {})
            name = f"custom:{raw}"[:80] if raw else None
        else:
            continue
        got = out.setdefault((cls, name), VendorDetection(cls, name, 0, 0, "medium"))
        got.occurrences += 1
    return list(out.values()) or [VendorDetection("other", "DLP_RULE_MATCH", 0, 1)]


class WorkspaceAlertsImporter:
    id = ID
    vendor = VENDOR
    platform = "google_workspace"
    covers = COVERS

    def __init__(self, ctx: Context, mode: str) -> None:
        self.ctx = ctx
        self.mode = mode

    def __repr__(self) -> str:
        return "WorkspaceAlertsImporter()"

    def run(
        self, cursor: dict[str, Any], budget: Budget, store: FindingStore, now: _dt.datetime
    ) -> tuple[VendorCoverage, dict[str, Any]]:
        cov = VendorCoverage(VENDOR, self.platform, self.mode, covers=COVERS, limits=LIMITS)
        lookback = _dt.timedelta(days=self.ctx.settings.lookback_days)
        since = str(cursor.get("since") or (now - lookback).strftime("%Y-%m-%dT%H:%M:%SZ"))
        newest = since
        api = self.ctx.clients.google(settings_of(self.ctx).admin_user, GWS_ALERTS)
        tenant = tenant_of(self.ctx)
        facts = facts_of(self.ctx)
        params = {
            "customerId": "my_customer",
            "filter": f'type="DlpRuleViolation" AND createTime >= "{since}"',
            "orderBy": "create_time asc",
            "pageSize": "100",
        }
        try:
            for page, _, _ in api.pages(ALERTS, "alerts", params):
                for alert in page:
                    if not budget.time_left():
                        break
                    aid = str(alert.get("alertId") or "")
                    info = (alert.get("data") or {}).get("ruleViolationInfo") or {}
                    if not aid or not isinstance(info, dict):
                        continue
                    service = SERVICES.get(str(info.get("dataSource") or ""), "drive")
                    res = info.get("resourceInfo") or {}
                    doc_id = str(res.get("documentId") or "")
                    item = doc_id if service == "drive" and doc_id else f"alert/{hashed(aid)[:32]}"
                    user = info.get("triggeringUserEmail")
                    resource = saas_item(
                        GWS,
                        service,
                        tenant,
                        item,
                        "file" if service == "drive" else "message",
                        owner=owner_hash(user) if isinstance(user, str) and user else None,
                    )
                    found = [
                        vendor_finding(
                            resource,
                            None,
                            d,
                            vendor=VENDOR,
                            seen_at=now.isoformat(),
                            vendor_finding_id=hashed(aid)[:32],
                            facts=facts,
                        )
                        for d in _detections(info)
                    ]
                    store.replace_location(f"{ID}\n{hashed(aid)}", found)
                    cov.findings += 1
                    created = str(alert.get("createTime") or "")[:19]
                    if created and created + "Z" > newest:
                        newest = created + "Z"
        except Exception as err:  # what was imported stands
            name = error_name(err)
            cov.status = (
                "access_denied" if name in ("PERMISSION_DENIED", "unauthorized_client") else "error"
            )
            cov.error = name
            log_event("source.failed", source=ID, error=name)
            return cov, dict(cursor)
        return cov, {"since": newest}
