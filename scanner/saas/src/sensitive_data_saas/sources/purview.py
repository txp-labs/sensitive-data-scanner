"""Microsoft Purview DLP's alerts, imported (#55): `SCAN_MODE_M365` `vendor` or `both`.

**Why here, and not in the Azure package.** Purview DLP watches Microsoft 365
content (Exchange, SharePoint, OneDrive, Teams), its alerts are read through
Microsoft Graph with the same Entra app and sign-in as the Microsoft 365
scanner, and they name the same people and services this package's findings
do. The Azure package reads Azure resources through Azure Resource Manager and
has no Graph client.

**Read.** Graph's security alerts (`GET /security/alerts_v2`, application
permission `SecurityAlert.Read.All`), those from Purview DLP
(`serviceSource eq 'microsoftDataLossPrevention'`), updated since the last
run. Each alert becomes a finding (`source: vendor:purview`, class `other`,
`vendorType` `DLP_POLICY_MATCH`: an alert names the policy that matched, not
the sensitive information type) on a `saas_item` of the service its evidence
names (`exchange` for a message or mailbox, else `sharepoint`), owned by the
hash of the user its evidence names.

**Never read into a finding:** the alert's title and description (the policy
and rule names the customer wrote), and every evidence field but its type and
the user's principal name (which is hashed): message subjects, senders,
recipients, file names and paths, URLs, IP addresses.

Coverage: only matches of the customer's policies that raised an alert
(`alerts_only`, `policy_matches_only`), and an alert names no Graph item this
scanner reads (`item_not_linkable`), so `both` mode does not link them.
Content Explorer's counts are not in Graph (only its PowerShell export), so
they are not imported.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.modes import VendorCoverage, VendorDetection, hashed, vendor_finding
from sensitive_data_core.safety import error_name, log_event

from ..resources import owner_hash, saas_item
from .base import Context, call_gap
from .m365 import facts_of, tenant_of

VENDOR = "purview"
ID = "vendor:purview"
LIMITS = ("alerts_only", "policy_matches_only", "item_not_linkable", "no_data_class")
COVERS = (
    "m365_mail",
    "m365_onedrive",
    "m365_sharepoint",
    "m365_teams_channel",
    "m365_teams_chat",
)
MAIL_EVIDENCE = ("analyzedMessageEvidence", "mailboxEvidence", "mailClusterEvidence")


def _service(evidence: list[dict[str, Any]]) -> str:
    kinds = [str(e.get("@odata.type") or "") for e in evidence]
    if any(k.endswith(MAIL_EVIDENCE) for k in kinds):
        return "exchange"
    return "sharepoint"


def _owner(evidence: list[dict[str, Any]]) -> str | None:
    for e in evidence:
        account = e.get("userAccount") if isinstance(e.get("userAccount"), dict) else None
        upn = (account or {}).get("userPrincipalName")
        if isinstance(upn, str) and upn:
            return owner_hash(upn)
    return None


class PurviewImporter:
    id = ID
    vendor = VENDOR
    platform = "m365"
    covers = COVERS

    def __init__(self, ctx: Context, mode: str) -> None:
        self.ctx = ctx
        self.mode = mode

    def __repr__(self) -> str:
        return "PurviewImporter()"

    def run(
        self, cursor: dict[str, Any], budget: Budget, store: FindingStore, now: _dt.datetime
    ) -> tuple[VendorCoverage, dict[str, Any]]:
        cov = VendorCoverage(VENDOR, self.platform, self.mode, covers=COVERS, limits=LIMITS)
        lookback = _dt.timedelta(days=self.ctx.settings.lookback_days)
        since = str(cursor.get("since") or (now - lookback).strftime("%Y-%m-%dT%H:%M:%SZ"))
        newest = since
        tenant = tenant_of(self.ctx)
        facts = facts_of(self.ctx)
        query = urllib.parse.urlencode(
            {
                "$filter": (
                    "serviceSource eq 'microsoftDataLossPrevention' "
                    f"and lastUpdateDateTime ge {since}"
                ),
                "$top": "100",
            }
        )
        try:
            for page, _, _ in self.ctx.clients.graph.pages(f"/security/alerts_v2?{query}"):
                for alert in page:
                    if not budget.time_left():
                        break
                    aid = str(alert.get("id") or "")
                    if not aid:
                        continue
                    evidence = [e for e in alert.get("evidence") or [] if isinstance(e, dict)]
                    resource = saas_item(
                        "m365",
                        _service(evidence),
                        tenant,
                        f"alert/{hashed(aid)[:32]}",
                        "message" if _service(evidence) == "exchange" else "file",
                        owner=_owner(evidence),
                    )
                    finding = vendor_finding(
                        resource,
                        None,
                        VendorDetection("other", "DLP_POLICY_MATCH", 0, 1),
                        vendor=VENDOR,
                        seen_at=now.isoformat(),
                        vendor_finding_id=hashed(aid)[:32],
                        facts=facts,
                    )
                    store.replace_location(f"{ID}\n{hashed(aid)}", [finding])
                    cov.findings += 1
                    updated = str(alert.get("lastUpdateDateTime") or "")
                    if updated > newest:
                        newest = updated[:19] + "Z" if len(updated) >= 19 else newest
        except Exception as err:  # what was imported stands
            name = error_name(err)
            gap = call_gap(err)
            cov.status = {"access_denied": "access_denied", "throttled": "throttled"}.get(
                gap or "", "error"
            )
            cov.error = name
            log_event("source.failed", source=ID, error=name)
            return cov, dict(cursor)
        return cov, {"since": newest}
