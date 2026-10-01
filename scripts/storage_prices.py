"""The dated price table the cost-to-scan estimate reads (#109).

    python3 scripts/storage_prices.py --write   # refetch every price, write the table
    python3 scripts/storage_prices.py --check   # the table parses and is dated (no network)

The table (`scanner/core/src/sensitive_data_core/storage_prices.json`) holds, per
platform and region, what reading an object of each storage class costs: the
retrieval fee per GB and the GET (read operation) price per 1,000 requests, in
USD. The scanner never calls a pricing API at run time; it reads this file, and
every estimate names the table's date (`priceDate`).

Sources (public, no credentials), each also cited in the table itself:

- AWS: the Price List Bulk API for AmazonS3, one offer file per region
  (https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/current/region_index.json),
  the same figures as https://aws.amazon.com/s3/pricing/ ("Requests & data retrievals").
- Azure: the Retail Prices API (https://prices.azure.com/api/retail/prices), product
  "General Block Blob v2", LRS meters, the same figures as
  https://azure.microsoft.com/pricing/details/storage/blobs/.
- Google Cloud: https://cloud.google.com/storage/pricing ("Retrieval fees" and
  "Operation charges", Class B, flat namespace). Cloud Storage's retrieval fees and
  Class B prices are the same in every location, so the table has one row
  (`*`); they are typed in below from that page, with its date, since Google
  publishes no unauthenticated price API.

Run `--write` when a provider changes its prices, review the diff, and commit it
with the new date.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
TABLE = REPO / "scanner" / "core" / "src" / "sensitive_data_core" / "storage_prices.json"

AWS_INDEX = (
    "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/current/region_index.json"
)
AWS_PAGE = "https://aws.amazon.com/s3/pricing/"
AZURE_API = "https://prices.azure.com/api/retail/prices"
AZURE_PAGE = "https://azure.microsoft.com/pricing/details/storage/blobs/"
GCP_PAGE = "https://cloud.google.com/storage/pricing"

# AWS usage types (after the region's own prefix) per storage class.
AWS_RETRIEVAL = {
    "STANDARD_IA": "Retrieval-SIA",
    "ONEZONE_IA": "Retrieval-ZIA",
    "GLACIER_IR": "Retrieval-GIR",
}
AWS_GET = {
    "STANDARD": "Requests-Tier2",
    "STANDARD_IA": "Requests-SIA-Tier2",
    "ONEZONE_IA": "Requests-ZIA-Tier2",
    "GLACIER_IR": "Requests-GIR-Tier2",
    "INTELLIGENT_TIERING": "Requests-INT-Tier2",
}

# Azure regions priced (the commercial regions with Cool and Cold blob tiers).
AZURE_REGIONS = (
    "eastus",
    "eastus2",
    "centralus",
    "northcentralus",
    "southcentralus",
    "westcentralus",
    "westus",
    "westus2",
    "westus3",
    "canadacentral",
    "canadaeast",
    "brazilsouth",
    "northeurope",
    "westeurope",
    "uksouth",
    "ukwest",
    "francecentral",
    "germanywestcentral",
    "switzerlandnorth",
    "norwayeast",
    "swedencentral",
    "italynorth",
    "polandcentral",
    "spaincentral",
    "uaenorth",
    "qatarcentral",
    "israelcentral",
    "southafricanorth",
    "centralindia",
    "southindia",
    "westindia",
    "eastasia",
    "southeastasia",
    "japaneast",
    "japanwest",
    "koreacentral",
    "koreasouth",
    "australiaeast",
    "australiasoutheast",
    "australiacentral",
    "mexicocentral",
    "newzealandnorth",
)
# Azure meters (LRS SKUs) per tier: (retrieval meter, read-operations meter, per 10K).
AZURE_METERS = {
    "Hot": (None, "Hot Read Operations"),
    "Cool": ("Cool Data Retrieval", "Cool Read Operations"),
    "Cold": ("Cold LRS Data Retrieval", "Cold LRS Read Operations"),
    "Archive": ("Archive Data Retrieval", "Archive Read Operations"),
}

# Google Cloud Storage (GCP_PAGE, read 2026-10-01): retrieval per GiB, Class B per 1,000
# (flat namespace; the same for regions, dual-regions and multi-regions).
GCP_PRICES = {
    "STANDARD": {"retrievalPerGb": 0.0, "getPer1k": 0.0004},
    "NEARLINE": {"retrievalPerGb": 0.01, "getPer1k": 0.001},
    "COLDLINE": {"retrievalPerGb": 0.02, "getPer1k": 0.01},
    "ARCHIVE": {"retrievalPerGb": 0.05, "getPer1k": 0.05},
}
GCP_DATE = "2026-10-01"


def _get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URLs
        return json.loads(resp.read())


def _aws() -> tuple[dict[str, Any], str]:
    index = _get(AWS_INDEX)
    published = str(index.get("publicationDate", ""))[:10]
    out: dict[str, Any] = {}
    for region, entry in sorted(index["regions"].items()):
        # Commercial regions only: not GovCloud, not local zones, not "aws-other".
        if region.startswith("us-gov") or region.count("-") != 2:
            continue
        offer = _get("https://pricing.us-east-1.amazonaws.com" + entry["currentVersionUrl"])
        by_usage: dict[str, float] = {}
        for sku, product in offer["products"].items():
            usage = product["attributes"].get("usagetype", "")
            suffix = usage.split("-", 1)[1] if usage[:1].isupper() and "-" in usage else usage
            for term in offer["terms"].get("OnDemand", {}).get(sku, {}).values():
                for dim in term["priceDimensions"].values():
                    price = float(dim["pricePerUnit"].get("USD", "nan"))
                    for name in (usage, suffix):
                        by_usage.setdefault(name, price)
        row: dict[str, dict[str, float]] = {}
        for cls, usage in AWS_GET.items():
            if usage in by_usage:
                row.setdefault(cls, {})["getPer1k"] = round(by_usage[usage] * 1000, 6)
        for cls, usage in AWS_RETRIEVAL.items():
            if usage in by_usage:
                row.setdefault(cls, {})["retrievalPerGb"] = round(by_usage[usage], 6)
        for cls in row:
            row[cls].setdefault("retrievalPerGb", 0.0)
        if all(c in row and "getPer1k" in row[c] for c in AWS_GET if c != "INTELLIGENT_TIERING"):
            out[region] = row
    return out, published


def _azure() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for region in AZURE_REGIONS:
        flt = (
            "serviceName eq 'Storage' and productName eq 'General Block Blob v2' "
            f"and armRegionName eq '{region}' and priceType eq 'Consumption'"
        )
        url = AZURE_API + "?" + urllib.parse.urlencode({"$filter": flt})
        items: list[dict[str, Any]] = []
        while url:
            page = _get(url)
            items += page.get("Items", [])
            url = page.get("NextPageLink") or ""
        lrs = {
            i["meterName"]: float(i["retailPrice"]) for i in items if i["skuName"].endswith(" LRS")
        }
        row: dict[str, dict[str, float]] = {}
        for tier, (retrieval, reads) in AZURE_METERS.items():
            if reads not in lrs or (retrieval is not None and retrieval not in lrs):
                continue
            row[tier] = {
                "retrievalPerGb": lrs[retrieval] if retrieval else 0.0,
                "getPer1k": round(lrs[reads] / 10, 6),  # the meter is per 10K
            }
        if set(row) == set(AZURE_METERS):
            out[region] = row
    return out


def build() -> dict[str, Any]:
    today = _dt.date.today().isoformat()
    aws, aws_published = _aws()
    return {
        "schema": "sensitive-data-scanner.storage-prices",
        "version": 1,
        "currency": "USD",
        "note": "Retrieval per GB and GET (read operation) per 1,000 requests, by platform, region and storage class. Regenerate with scripts/storage_prices.py --write.",
        "platforms": {
            "aws": {
                "priceDate": aws_published or today,
                "sources": [AWS_PAGE, AWS_INDEX],
                "fallbackRegion": "us-east-1",
                "regions": aws,
            },
            "azure": {
                "priceDate": today,
                "sources": [AZURE_PAGE, AZURE_API],
                "fallbackRegion": "eastus",
                "basis": "General Block Blob v2, LRS (other redundancies may differ); hierarchical-namespace (ADLS Gen2) read operations are priced as flat",
                "regions": _azure(),
            },
            "gcp": {
                "priceDate": GCP_DATE,
                "sources": [GCP_PAGE],
                "fallbackRegion": "*",
                "basis": "Retrieval fees and Class B operations (flat namespace) are the same in every location; buckets with Autoclass have no retrieval fee",
                "regions": {"*": GCP_PRICES},
            },
        },
    }


def check(table: dict[str, Any]) -> list[str]:
    problems = []
    for name, p in table.get("platforms", {}).items():
        try:
            _dt.date.fromisoformat(p["priceDate"])
        except (KeyError, ValueError):
            problems.append(f"{name}: no priceDate")
        if not p.get("sources"):
            problems.append(f"{name}: no sources")
        if p.get("fallbackRegion") not in p.get("regions", {}):
            problems.append(f"{name}: the fallback region has no prices")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.write:
        TABLE.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")
    problems = check(json.loads(TABLE.read_text()))
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
