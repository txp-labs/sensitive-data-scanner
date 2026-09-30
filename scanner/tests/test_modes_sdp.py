"""Google Cloud Sensitive Data Protection's data profiles, imported (#55).

The profiles come from a stubbed DLP API on the stubbed Google Cloud (gcp_fakes.py). Every
value is made up.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

import pytest

from aws_fixtures import shared_detector
from gcp_fakes import NOW, ORG, PROJECT, Cloud, Req, Resp, error, settings
from sensitive_data_gcp.config import ConfigError
from sensitive_data_gcp.resources import resource_name_hash
from sensitive_data_gcp.runner import run_scan
from synthetic import CARDS, SSN_A, dashed
from test_gcp_bigquery import cloud
from test_gcp_gcs import valid


def column_profile(dataset: str, table: str, column: str, info: str) -> dict[str, Any]:
    """A column data profile, with fields the importer must never read into a finding."""
    return {
        "name": f"organizations/{ORG}/locations/global/columnDataProfiles/{dataset}-{column}",
        "tableFullResource": (
            f"//bigquery.googleapis.com/projects/{PROJECT}/datasets/{dataset}/tables/{table}"
        ),
        "datasetProjectId": PROJECT,
        "datasetId": dataset,
        "tableId": table,
        "column": column,
        "columnInfoType": {"infoType": {"name": info}, "estimatedPrevalence": 12},
        "otherMatches": [{"infoType": {"name": "PHONE_NUMBER"}, "quote": CARDS["amex"]}],
        "sensitivityScore": {"score": "SENSITIVITY_HIGH"},
    }


def file_store_profile(bucket: str, *infos: str) -> dict[str, Any]:
    return {
        "name": f"organizations/{ORG}/locations/global/fileStoreDataProfiles/{bucket}",
        "fileStorePath": f"gs://{bucket}",
        "projectId": PROJECT,
        "fileStoreInfoTypeSummaries": [{"infoType": {"name": i}} for i in infos],
        "sampleFindings": [{"quote": dashed(SSN_A)}],
    }


class Dlp:
    """The DLP API's profile listings, read-only."""

    def __init__(self, c: Cloud) -> None:
        self.columns: list[dict[str, Any]] = []
        self.file_stores: list[dict[str, Any]] = []
        self.fail: Resp | None = None
        self.parents: list[str] = []
        c.route("GET", r"^https://dlp\.googleapis\.com/", self.answer)

    def answer(self, req: Req) -> Resp:
        if self.fail is not None:
            return self.fail
        path = urllib.parse.urlsplit(req.url).path.removeprefix("/v2/")
        m = re.fullmatch(r"(.+/locations/[^/]+)/(columnDataProfiles|fileStoreDataProfiles)", path)
        assert m, path
        self.parents.append(m[1])
        rows = self.columns if m[2] == "columnDataProfiles" else self.file_stores
        return Resp(200, {m[2]: rows})


def run(c: Cloud, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(DISCOVER="bigquery", **env),
        c.clients(),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def test_the_mode_and_locations_settings() -> None:
    s = settings(SCAN_MODE="both", SDP_LOCATIONS="us,europe-west1")
    assert s.scan_mode == "both" and s.sdp_locations == ("us", "europe-west1")
    for bad, code in (
        ({"SCAN_MODE": "x"}, "scan_mode"),
        ({"SDP_LOCATIONS": "US East"}, "sdp_locations"),
    ):
        with pytest.raises(ConfigError) as err:
            settings(**bad)
        assert err.value.code == code


def test_both_links_a_column_profile_to_the_scanners_column() -> None:
    c, _ = cloud()
    dlp = Dlp(c)
    dlp.columns = [
        column_profile("sales", "orders", "card_number", "CREDIT_CARD_NUMBER"),
        column_profile("sales", "customers", "email", "EMAIL_ADDRESS"),
    ]
    dlp.file_stores = [file_store_profile("acme-lake", "US_SOCIAL_SECURITY_NUMBER", "PASSPORT")]
    doc = run(c, SCAN_MODE="both")
    assert doc["scanMode"] == {"gcp": "both"}
    (cov,) = doc["vendorCoverage"]
    assert (cov["vendor"], cov["status"], cov["findings"]) == ("google_sdp", "read", 3)
    assert cov["covers"] == ["bigquery", "gcs"] and "profiles_not_items" in cov["limits"]
    assert dlp.parents == [f"organizations/{ORG}/locations/global"] * 2
    sdp = [f for f in doc["findings"] if f["source"] == "vendor:google_sdp"]
    card = next(f for f in sdp if f["class"] == "card")
    assert card["resource"]["field"] == "card_number" and card["resource"]["table"] == "orders"
    assert card["resource"]["resourceNameHash"] == resource_name_hash(
        f"//bigquery.googleapis.com/projects/{PROJECT}/datasets/sales/tables/orders"
    )
    ours = [
        f
        for f in doc["findings"]
        if f["source"] == "scanner"
        and f["class"] == "card"
        and f["resource"].get("table") == "orders"
        and f["resource"].get("field") == "card_number"
    ]
    assert ours and card["linked"] == [ours[0]["id"]] and ours[0]["linked"] == [card["id"]]
    other = next(f for f in sdp if f["vendorType"] == "EMAIL_ADDRESS")
    assert other["class"] == "other" and "linked" not in other
    gcs = [f for f in sdp if f["resource"]["service"] == "gcs"]
    assert {(f["class"], f["vendorType"]) for f in gcs} == {
        ("us_ssn", "US_SOCIAL_SECURITY_NUMBER"),
        ("other", "PASSPORT"),
    }
    assert all("atRestEncryption" not in f and f["offsets"] == [] for f in sdp)


def test_vendor_mode_reads_nothing_and_a_gone_profile_drops() -> None:
    c, bq = cloud()
    dlp = Dlp(c)
    dlp.columns = [column_profile("sales", "orders", "card_number", "CREDIT_CARD_NUMBER")]
    doc = run(c, SCAN_MODE="vendor")
    assert doc["coverage"] == [] and not bq.data_calls
    bq_stores = [s for s in doc["discovery"]["stores"] if s["kind"] == "bigquery"]
    assert "vendor_mode" in {s.get("reason") for s in bq_stores}
    assert not any(s["status"] == "scanned" for s in bq_stores)
    assert [f["source"] for f in doc["findings"]] == ["vendor:google_sdp"]


def test_sdp_errors_are_named() -> None:
    c, _ = cloud()
    dlp = Dlp(c)
    dlp.fail = error(403, "PERMISSION_DENIED", message=f"no dlp for {CARDS['visa']}")
    doc = run(c, SCAN_MODE="both")
    (cov,) = doc["vendorCoverage"]
    assert (cov["status"], cov["error"]) == ("access_denied", "PERMISSION_DENIED")
    assert CARDS["visa"] not in json.dumps(doc)
