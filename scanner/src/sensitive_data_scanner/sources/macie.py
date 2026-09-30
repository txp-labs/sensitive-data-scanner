"""Amazon Macie's own findings, imported (#55): `SCAN_MODE` `vendor` or `both`.

Macie finds sensitive data in S3 (sensitive data discovery jobs and automated
discovery) and keeps a finding per object. The importer reads those findings
in the account it runs in, read-only (`macie2:GetMacieSession`,
`macie2:ListFindings`, `macie2:GetFindings`), and turns each into this
scanner's findings, one per class, with `source: vendor:macie`:

- **Kept:** the bucket and the object's key (masked like any S3 key) and
  version, each detection's type (`CREDIT_CARD_NUMBER`, a custom data
  identifier's name, masked) and its count, the object's encryption, and
  Macie's finding id (masked).
- **Never read into a finding:** the detections' `occurrences` (cell, line,
  page, record and offset positions into the object), Macie's title and
  description, and anything else. The scanner never calls
  `GetSensitiveDataOccurrences` (which would reveal samples of the values);
  the template denies it, and every other Macie write.
- **Classes:** Macie's managed data identifiers map to the spec's classes
  (`CREDIT_CARD_NUMBER` to `card`, `USA_SOCIAL_SECURITY_NUMBER` to `us_ssn`,
  ...); any other type, and every custom data identifier, is `other` with the
  type named in `vendorType`.
- **Incremental:** findings updated since the last run (the first run:
  `MACIE_LOOKBACK_DAYS`), in update order; a finding's findings replace what
  was imported for it before.

Coverage: Macie reads S3 only (`s3_only`); what it inspects is what its jobs
and automated discovery sample (`sampled_by_vendor`); its counts are
occurrences, not distinct values (`counts_not_distinct`). A Macie that is not
enabled in the account and region is `not_enabled`.
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

from ..resources import s3_link, s3_resource
from .encryption import classifier, s3_object_facts

AWS_SERVICES = ("macie2",)
VENDOR = "macie"
ID = "vendor:macie"
MAX_PER_CALL = 50
TYPES = {
    "CREDIT_CARD_NUMBER": "card",
    "CREDIT_CARD_NUMBER_(NO_KEYWORD)": "card",
    "CREDIT_CARD_MAGNETIC_STRIPE": "card",
    "CREDIT_CARD_SECURITY_CODE": "cvv",
    "USA_SOCIAL_SECURITY_NUMBER": "us_ssn",
    "USA_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER": "us_itin",
    "DATE_OF_BIRTH": "dob",
    "BANK_ACCOUNT_NUMBER": "account_number",
    "USA_BANK_ACCOUNT_NUMBER": "account_number",
}
LIMITS = ("s3_only", "sampled_by_vendor", "counts_not_distinct")


def _ms(t: _dt.datetime) -> int:
    return int(t.timestamp() * 1000)


def _time(v: Any) -> _dt.datetime | None:
    if isinstance(v, _dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=_dt.UTC)
    try:
        return _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


def detections(finding: dict[str, Any]) -> list[VendorDetection]:
    """Each type Macie found in the object, with its count: nothing of the occurrences."""
    result = ((finding.get("classificationDetails") or {}).get("result")) or {}
    by: dict[tuple[str, str | None], VendorDetection] = {}

    def add(raw_type: Any, count: Any, custom: bool) -> None:
        cls, name = vendor_class(raw_type, {} if custom else TYPES)
        if custom and name is not None:
            name = f"custom:{name}"[:80]
        n = max(0, int(count or 0))
        got = by.setdefault((cls, name), VendorDetection(cls, name, 0, 0, "medium"))
        got.count += n
        got.occurrences += n

    for group in result.get("sensitiveData") or []:
        if isinstance(group, dict):
            for d in group.get("detections") or []:
                if isinstance(d, dict):
                    add(d.get("type"), d.get("count"), False)
    custom = result.get("customDataIdentifiers") or {}
    for d in custom.get("detections") or []:
        if isinstance(d, dict):
            add(d.get("name"), d.get("count"), True)
    return list(by.values())


class MacieImporter:
    """Macie's findings for this account and region, as this scanner's findings."""

    id = ID
    kind = "s3"

    def __init__(self, clients: Any, region: str, mode: str, *, lookback_days: int = 90) -> None:
        self.clients = clients
        self.macie = clients.client("macie2")
        self.region = region
        self.mode = mode
        self.lookback = _dt.timedelta(days=lookback_days)

    def __repr__(self) -> str:
        return "MacieImporter()"

    def run(
        self, cursor: dict[str, Any], budget: Budget, store: FindingStore, now: _dt.datetime
    ) -> tuple[VendorCoverage, dict[str, Any]]:
        cov = VendorCoverage(VENDOR, "aws", self.mode, covers=("s3",), limits=LIMITS)
        since = _time(cursor.get("updatedAt")) or (now - self.lookback)
        newest = since
        try:
            self.macie.get_macie_session()
        except Exception as err:
            name = error_name(err)
            cov.status = "not_enabled" if _not_enabled(err) else "access_denied"
            if cov.status == "access_denied" and name not in ("AccessDeniedException",):
                cov.status = "error"
            cov.error = name
            log_event("source.failed", source=ID, error=name)
            return cov, dict(cursor)
        try:
            token: str | None = None
            while budget.time_left():
                args: dict[str, Any] = {
                    "findingCriteria": {
                        "criterion": {
                            "category": {"eq": ["CLASSIFICATION"]},
                            "updatedAt": {"gte": _ms(since)},
                        }
                    },
                    "sortCriteria": {"attributeName": "updatedAt", "orderBy": "ASC"},
                    "maxResults": MAX_PER_CALL,
                }
                if token:
                    args["nextToken"] = token
                page = self.macie.list_findings(**args)
                ids = [str(i) for i in page.get("findingIds") or []]
                if ids:
                    got = self.macie.get_findings(
                        findingIds=ids,
                        sortCriteria={"attributeName": "updatedAt", "orderBy": "ASC"},
                    )
                    for finding in got.get("findings") or []:
                        if not isinstance(finding, dict):
                            continue
                        when = self._one(finding, store, budget, now)
                        cov.findings += 1
                        if when is not None and when > newest:
                            newest = when
                token = page.get("nextToken") or None
                if not token:
                    break
        except Exception as err:  # what was imported stands
            name = error_name(err)
            cov.status = "throttled" if "Throttl" in name else "error"
            cov.error = name
            log_event("source.failed", source=ID, error=name)
        return cov, {"updatedAt": newest.isoformat()}

    def _one(
        self, finding: dict[str, Any], store: FindingStore, budget: Budget, now: _dt.datetime
    ) -> _dt.datetime | None:
        fid = str(finding.get("id") or "")
        res = finding.get("resourcesAffected") or {}
        bucket = str((res.get("s3Bucket") or {}).get("name") or "")
        obj = res.get("s3Object") or {}
        key = str(obj.get("key") or "")
        if not fid or not bucket or not key:
            return _time(finding.get("updatedAt"))
        version = str(obj.get("versionId") or "") or None
        sse = obj.get("serverSideEncryption") or {}
        kind = str(sse.get("encryptionType") or "")
        if kind == "UNKNOWN":
            facts: dict[str, str] = classifier(self.clients).facts(encrypted=None)
        else:
            headers = {} if kind in ("", "NONE") else {"ServerSideEncryption": kind}
            if sse.get("kmsMasterKeyId"):
                headers["SSEKMSKeyId"] = str(sse["kmsMasterKeyId"])
            facts = s3_object_facts(classifier(self.clients), headers)
        resource = s3_resource(bucket, key, version)
        link = s3_link(self.region, bucket, key, version)
        seen_at = now.isoformat()
        found = [
            vendor_finding(
                resource,
                link,
                d,
                vendor=VENDOR,
                seen_at=seen_at,
                vendor_finding_id=fid,
                facts=facts,
            )
            for d in detections(finding)
            if d.occurrences
        ]
        # The state names a Macie finding by its id's hash: nothing of Macie's is kept raw.
        store.replace_location(f"{ID}\n{hashed(fid)}", found)
        return _time(finding.get("updatedAt"))


def _not_enabled(err: BaseException) -> bool:
    """Macie answers a disabled account with AccessDeniedException whose message says so; the
    message is only looked at here, never kept."""
    response = getattr(err, "response", None)
    message = ""
    if isinstance(response, dict):
        message = str((response.get("Error") or {}).get("Message") or "")
    return "not enabled" in message.lower()
