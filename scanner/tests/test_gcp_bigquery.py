"""The Google Cloud scanner's BigQuery source: tables sampled with tabledata.list.

Every Google call goes to a stubbed session (gcp_fakes.py); every value is made up.
"""

from __future__ import annotations

from typing import Any

from aws_fixtures import shared_detector
from gcp_fakes import (
    KEY,
    NOW,
    OTHER,
    PROJECT,
    BigQuery,
    BqDataset,
    BqTable,
    Cloud,
    dataset_row,
    error,
    settings,
    vpc_denied,
)
from sensitive_data_core.findings import key_hash
from sensitive_data_gcp.resources import resource_name_hash
from sensitive_data_gcp.runner import run_scan
from sensitive_data_gcp.sources.bigquery import cell, full_name
from synthetic import CARDS, SSN_A, dashed
from test_gcp_gcs import valid

DATASET_TYPE = "bigquery.googleapis.com/Dataset"
FIELDS: list[dict[str, Any]] = [
    {"name": "name", "type": "STRING"},
    {"name": "card_number", "type": "STRING"},
    {
        "name": "payer",
        "type": "RECORD",
        "fields": [{"name": "ssn", "type": "STRING"}, {"name": "note", "type": "STRING"}],
    },
    {"name": "tags", "type": "STRING", "mode": "REPEATED"},
    {"name": "blob", "type": "BYTES"},
]
TABLE_KEY = "projects/acme-kms/locations/us/keyRings/bq/cryptoKeys/orders"


def cloud() -> tuple[Cloud, BigQuery]:
    c = Cloud()
    bq = BigQuery(c)
    c.assets[DATASET_TYPE] = [
        dataset_row(PROJECT, "sales"),
        dataset_row(PROJECT, "reporting"),
        dataset_row(OTHER, "fenced"),
        dataset_row(OTHER, "hidden"),
    ]
    rows = [
        {
            "name": "A",
            "card_number": CARDS["visa"],
            "payer": {"ssn": dashed(SSN_A), "note": "x"},
            "tags": ["vip", f"card {CARDS['mastercard']}"],
            "blob": "AAEC",
        }
    ]
    bq.datasets[(PROJECT, "sales")] = BqDataset(
        tables={
            "orders": BqTable(FIELDS, rows, kms=TABLE_KEY),
            "customers": BqTable(FIELDS, rows),
            "by_region": BqTable(FIELDS, rows, policies=[{"rowAccessPolicyReference": {}}]),
            "masked": BqTable(
                [
                    {"name": "email", "type": "STRING"},
                    {"name": "ssn", "type": "STRING", "policyTags": {"names": ["pt/1"]}},
                ],
                [{"email": "a@example.com", "ssn": dashed(SSN_A)}],
            ),
            "orders_view": BqTable(FIELDS, type="VIEW"),
            "lake_ext": BqTable(FIELDS, type="EXTERNAL"),
            "orders_snap": BqTable(FIELDS, rows, type="SNAPSHOT"),
        },
        kms=KEY,
    )
    bq.datasets[(PROJECT, "reporting")] = BqDataset(
        tables={"summary": BqTable(FIELDS, type="VIEW")},
    )
    # `sales` authorizes the view `reporting.summary` to read it.
    bq.datasets[(PROJECT, "sales")].access = [
        {"role": "READER", "specialGroup": "projectReaders"},
        {"view": {"projectId": PROJECT, "datasetId": "reporting", "tableId": "summary"}},
    ]
    bq.datasets[(OTHER, "fenced")] = BqDataset(fail=vpc_denied())
    bq.datasets[(OTHER, "hidden")] = BqDataset(
        fail=error(403, "PERMISSION_DENIED", message="no bigquery.datasets.get")
    )
    return c, bq


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


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


def test_every_table_is_a_store_and_each_gap_has_its_reason() -> None:
    c, _ = cloud()
    s = stores(run(c))
    sales = f"{PROJECT}.sales"
    assert s[f"{sales}.orders"]["status"] == "scanned"
    assert s[f"{sales}.orders"]["resourceNameHash"] == resource_name_hash(
        full_name(PROJECT, "sales", "orders")
    )
    assert s[f"{sales}.orders_snap"]["status"] == "scanned"
    assert (s[f"{sales}.orders_view"]["reason"], s[f"{sales}.orders_view"]["tableType"]) == (
        "unsupported",
        "VIEW",
    )
    assert s[f"{sales}.lake_ext"]["reason"] == "unsupported"
    assert s[f"{PROJECT}.reporting.summary"]["reason"] == "authorized_view"
    assert (s[f"{sales}.by_region"]["status"], s[f"{sales}.by_region"]["reason"]) == (
        "skipped",
        "row_level_policy",
    )
    assert s[f"{sales}.masked"]["protectedColumns"] == 1
    assert (s[f"{OTHER}.fenced.*"]["status"], s[f"{OTHER}.fenced.*"]["reason"]) == (
        "error",
        "network",
    )
    assert s[f"{OTHER}.hidden.*"]["reason"] == "access_denied"
    assert s[f"{sales}.customers"]["atRestKeyHash"] == key_hash(KEY)  # the dataset's default


def test_rows_are_read_by_column_with_tabledata_list_and_no_query() -> None:
    c, bq = cloud()
    doc = run(c)
    found = [f for f in doc["findings"] if f["resource"]["table"] == "orders"]
    by = {(f["resource"]["field"], f["class"]) for f in found}
    assert {("card_number", "card"), ("payer", "us_ssn"), ("tags", "card")} <= by
    card = next(f for f in found if f["resource"]["field"] == "card_number")
    r = card["resource"]
    assert (r["type"], r["service"], r["store"], r["readBy"], r["project"]) == (
        "store_field",
        "bigquery",
        "sales",
        "tabledata_list",
        PROJECT,
    )
    assert card["format"] == "json" and card["offsets"] == []
    assert (card["atRestEncryption"], card["atRestKeyHash"]) == (
        "customer_managed_key",
        key_hash(TABLE_KEY),  # the table's own key over the dataset's
    )
    assert card["link"].startswith("https://console.cloud.google.com/bigquery?project=")
    # No query ever runs: no job is created, no bytes billed.
    assert not any("/jobs" in u or "/queries" in u for _, u, _ in c.requests)
    assert all(q["maxResults"] == "1000" for q in bq.data_calls)


def test_policy_tagged_columns_are_left_out_of_the_read() -> None:
    c, bq = cloud()
    doc = run(c)
    masked = [q for q in bq.data_calls if q.get("selectedFields")]
    assert masked and masked[0]["selectedFields"] == "email"
    assert not any(f["resource"]["table"] == "masked" for f in doc["findings"])


def test_a_table_unchanged_since_its_last_read_is_not_read_again() -> None:
    c, bq = cloud()
    first = run(c)
    calls = len(bq.data_calls)
    second = run(c)
    assert len(bq.data_calls) == calls
    assert {f["id"] for f in second["findings"]} == {f["id"] for f in first["findings"]}
    bq.datasets[(PROJECT, "sales")].tables["orders"].modified = "1759200000000"
    run(c)
    assert len(bq.data_calls) == calls + 1


def test_the_budget_defers_tables() -> None:
    c, _ = cloud()
    doc = run(c, MAX_ITEMS_PER_RUN="1")
    s = stores(doc)
    assert any(v["status"] == "deferred" or v.get("reason") == "budget" for v in s.values())


def test_a_read_refused_is_access_denied_and_rows_setting() -> None:
    c, bq = cloud()
    bq.datasets[(PROJECT, "sales")].tables["customers"].fail = error(
        403, "PERMISSION_DENIED", message="no getData"
    )
    s = stores(run(c, BIGQUERY_MAX_ROWS="5"))
    assert s[f"{PROJECT}.sales.customers"]["reason"] == "access_denied"
    assert all(q["maxResults"] == "5" for q in bq.data_calls)


def test_cells_decode_by_schema_and_drop_bytes() -> None:
    f = {"name": "x", "type": "RECORD", "mode": "REPEATED", "fields": [FIELDS[1], FIELDS[4]]}
    v = [{"v": {"f": [{"v": "4111"}, {"v": "AAEC"}]}}]
    assert cell(f, v) == [{"card_number": "4111", "blob": None}]
    assert cell({"type": "INTEGER"}, None) is None
