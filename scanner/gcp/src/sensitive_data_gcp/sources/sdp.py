"""Google Cloud Sensitive Data Protection's own data profiles, imported (#55).

With `SCAN_MODE` `vendor` or `both`, the Google Cloud scanner reads the data
profiles Sensitive Data Protection's discovery keeps (read-only:
`dlp.columnDataProfiles.list`, `dlp.fileStoreProfiles.list`), in each
location of `SDP_LOCATIONS`, for the organization or each project in scope,
and turns each into this scanner's findings with `source: vendor:google_sdp`:

- **A BigQuery column profile** (`columnDataProfiles`): its column's
  predicted info type, as a finding on the same `store_field` this scanner's
  BigQuery reads name (dataset, table, column, `project`,
  `resourceNameHash`), so the two link in `both` mode.
- **A Cloud Storage file store profile** (`fileStoreDataProfiles`): each info
  type found in the bucket, as a finding on the bucket (`store_field`,
  service `gcs`): a profile names no object.

Only the profile's location, its info types' names and the hash of the
profile's name are kept; a profile says nothing of the store's key, so these
findings carry no `atRestEncryption`. Nothing else of a profile is read into
a finding; Sensitive Data Protection's inspection results (which can hold
quotes of the matched text) are never read. Info types map to the spec's
classes (`CREDIT_CARD_NUMBER` to `card`, `US_SOCIAL_SECURITY_NUMBER` to
`us_ssn`, ...); any other is `other`.

Coverage: profiles, not items (`profiles_not_items`); only the stores the
customer's discovery configuration profiles (`profiled_stores_only`), sampled
by the vendor (`sampled_by_vendor`); a profile counts no values.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.findings import store_field_resource
from sensitive_data_core.modes import (
    VendorCoverage,
    VendorDetection,
    hashed,
    vendor_class,
    vendor_finding,
)
from sensitive_data_core.safety import error_name, log_event

from ..resources import gcp_fields
from .base import Context

VENDOR = "google_sdp"
ID = "vendor:google_sdp"
DLP = "https://dlp.googleapis.com/v2"
TYPES = {
    "CREDIT_CARD_NUMBER": "card",
    "CREDIT_CARD_TRACK_NUMBER": "card",
    "US_SOCIAL_SECURITY_NUMBER": "us_ssn",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "us_itin",
    "DATE_OF_BIRTH": "dob",
    "FINANCIAL_ACCOUNT_NUMBER": "account_number",
    "IBAN_CODE": "account_number",
}
LIMITS = ("profiled_stores_only", "profiles_not_items", "sampled_by_vendor")
_TABLE = "//bigquery.googleapis.com/projects/"


def _table_parts(full: str) -> tuple[str, str, str] | None:
    """(project, dataset, table) of a BigQuery table's full resource name."""
    if not full.startswith(_TABLE):
        return None
    parts = full[len(_TABLE) :].split("/")
    if len(parts) != 5 or parts[1] != "datasets" or parts[3] != "tables":
        return None
    return parts[0], parts[2], parts[4]


def parents(ctx: Context) -> list[str]:
    """Where profiles are listed: the organization, else each project in scope, per location."""
    out: list[str] = []
    for loc in ctx.settings.sdp_locations:
        for scope in ctx.settings.scopes:
            if scope.startswith(("organizations/", "projects/")):
                out.append(f"{scope}/locations/{loc}")
            else:  # a folder: its projects, one by one
                out.extend(
                    f"projects/{p}/locations/{loc}" for p in sorted(set(ctx.projects().values()))
                )
    return sorted(set(out))


class SdpImporter:
    """Sensitive Data Protection's column and file store profiles, as this scanner's findings."""

    id = ID

    def __init__(self, ctx: Context, mode: str) -> None:
        self.ctx = ctx
        self.mode = mode

    def __repr__(self) -> str:
        return "SdpImporter()"

    def run(
        self, cursor: dict[str, Any], budget: Budget, store: FindingStore, now: _dt.datetime
    ) -> tuple[VendorCoverage, dict[str, Any]]:
        cov = VendorCoverage(VENDOR, "gcp", self.mode, covers=("bigquery", "gcs"), limits=LIMITS)
        seen: set[str] = set()
        limit = self.ctx.settings.sdp_max_profiles
        try:
            for parent in parents(self.ctx):
                for kind, key in (
                    ("columnDataProfiles", "columnDataProfiles"),
                    ("fileStoreDataProfiles", "fileStoreDataProfiles"),
                ):
                    url = f"{DLP}/{parent}/{kind}"
                    for page, _ in self.ctx.rest.pages(url, key, {"pageSize": "100"}):
                        for profile in page:
                            if not isinstance(profile, dict) or not budget.time_left():
                                continue
                            if len(seen) >= limit:
                                break
                            name = str(profile.get("name") or "")
                            if not name:
                                continue
                            location = f"{ID}\n{hashed(name)}"
                            seen.add(location)
                            found = (
                                self._column(profile, now)
                                if kind == "columnDataProfiles"
                                else self._file_store(profile, now)
                            )
                            store.replace_location(location, found)
                            cov.findings += 1
        except Exception as err:  # what was imported stands
            name = error_name(err)
            cov.status = "access_denied" if name == "PERMISSION_DENIED" else "error"
            if name in ("SERVICE_DISABLED", "FAILED_PRECONDITION"):
                cov.status = "not_enabled"
            cov.error = name
            log_event("source.failed", source=ID, error=name)
            return cov, dict(cursor)
        # A profile that is gone (its table or bucket deleted) takes its findings with it.
        for location in store.locations(f"{ID}\n"):
            if location not in seen and len(seen) < limit:
                store.remove_location(location)
        return cov, {"lastRunAt": now.isoformat()}

    def _column(self, p: dict[str, Any], now: _dt.datetime) -> list[dict[str, Any]]:
        parts = _table_parts(str(p.get("tableFullResource") or ""))
        info = ((p.get("columnInfoType") or {}).get("infoType") or {}).get("name")
        column = str(p.get("column") or "")
        if parts is None or not column or not info:
            return []
        project, dataset, table = parts
        resource = store_field_resource(
            service="bigquery",
            store=dataset,
            table=table,
            field=column,
            read_by="sdp_profile",
        )
        resource.update(gcp_fields(project, str(p.get("tableFullResource"))))
        cls, vtype = vendor_class(info, TYPES)
        return [
            vendor_finding(
                resource,
                None,
                VendorDetection(cls, vtype, 0, 1),
                vendor=VENDOR,
                seen_at=now.isoformat(),
                vendor_finding_id=hashed(str(p.get("name")))[:32],
            )
        ]

    def _file_store(self, p: dict[str, Any], now: _dt.datetime) -> list[dict[str, Any]]:
        path = str(p.get("fileStorePath") or "")
        if not path.startswith("gs://"):
            return []
        bucket = urllib.parse.urlsplit(path).netloc
        if not bucket:
            return []
        resource = store_field_resource(
            service="gcs", store=bucket, field=None, read_by="sdp_profile"
        )
        resource.update(
            gcp_fields(str(p.get("projectId") or ""), f"//storage.googleapis.com/{bucket}")
        )
        types: set[str] = set()
        for s in p.get("fileStoreInfoTypeSummaries") or []:
            name = ((s or {}).get("infoType") or {}).get("name")
            if isinstance(name, str):
                types.add(name)
        out = []
        for t in sorted(types):
            cls, vtype = vendor_class(t, TYPES)
            out.append(
                vendor_finding(
                    resource,
                    None,
                    VendorDetection(cls, vtype, 0, 1),
                    vendor=VENDOR,
                    seen_at=now.isoformat(),
                    vendor_finding_id=hashed(str(p.get("name")))[:32],
                )
            )
        return out
