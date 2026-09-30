"""The Azure scanner: settings, discovery, Blob Storage and ADLS Gen2, state, sinks.

Every Azure call goes to a stubbed SDK client (azure_fakes.py); every value is made up.
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from azure_fakes import (
    NOW,
    SUB_A,
    SUB_B,
    Arm,
    AzureError,
    Blob,
    Graph,
    Tenant,
    account_id,
    account_row,
    containers,
    settings,
)
from sensitive_data_azure import __main__ as entry
from sensitive_data_azure.config import ConfigError, read_settings
from sensitive_data_azure.resources import resource_id_hash
from sensitive_data_azure.runner import run_scan
from sensitive_data_azure.sinks import EventGridSink, FileSink, sinks_for
from sensitive_data_azure.sources.base import versionless_key
from sensitive_data_core.findings import key_hash
from sensitive_data_core.push import verify
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
LAKE = account_id(SUB_A, "rg-data", "contosolake")
VAULT_KEY = "https://kv-contoso.vault.azure.net/keys/lake-key"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def csv_body() -> bytes:
    return f"name,card_number,ssn\nA,{CARDS['visa']},{dashed(SSN_A)}\n".encode()


def parquet_body() -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    buf = io.BytesIO()
    pq.write_table(pa.table({"card_number": [CARDS["mastercard"]], "note": ["x"]}), buf)
    return buf.getvalue()


def tenant() -> Tenant:
    graph = Graph(
        {
            "storageaccounts": [
                account_row("contosolake", hns=True, tags={"env": "prod"}),
                account_row(
                    "contosocmk",
                    sub=SUB_B,
                    group="rg-pay",
                    key_source="Microsoft.Keyvault",
                    vault="https://kv-contoso.vault.azure.net/",
                    key_name="lake-key",
                ),
                account_row("contosofiles", kind="FileStorage"),
                account_row("contosolocked", public="Disabled", default_action="Deny"),
                account_row("sdsstate", group="rg-sds"),
            ]
        }
    )
    t = Tenant(graph)
    t.arm = Arm(
        {
            f"{LAKE}/blobServices/default/containers": containers("raw", "curated"),
            f"{LAKE}/encryptionScopes": [
                {
                    "name": "pay-scope",
                    "properties": {
                        "source": "Microsoft.KeyVault",
                        "keyVaultProperties": {"keyUri": VAULT_KEY + "/0123abcd"},
                    },
                }
            ],
            account_id(SUB_B, "rg-pay", "contosocmk") + "/blobServices/default/containers": [
                {"name": "cards", "properties": {}}
            ],
            account_id(SUB_A, "rg-data", "contosolocked")
            + "/blobServices/default/containers": containers("vault"),
            account_id(SUB_A, "rg-sds", "sdsstate")
            + "/blobServices/default/containers": containers("scanner", "other"),
        }
    )
    t.container("contosolake", "raw").blobs.update(
        {
            "exports/cards.csv": Blob(csv_body()),
            "exports/pay.csv": Blob(csv_body(), encryption_scope="pay-scope"),
            "exports/cards.csv.gz": Blob(gzip.compress(csv_body())),
            "lake/part-0.parquet": Blob(parquet_body()),
            "media/call.wav": Blob(b"RIFF\x24\x00\x00\x00WAVEfmt made up"),
            "cold/old.csv": Blob(csv_body(), blob_tier="Archive"),
            "cpk/secret.csv": Blob(csv_body(), cpk=True),
            "dir/": Blob(b""),
        }
    )
    t.container("contosolake", "curated").blobs["notes.txt"] = Blob(b"nothing here")
    t.container("contosocmk", "cards").blobs["c.json"] = Blob(
        json.dumps({"cardNumber": CARDS["amex"], "cvv": "cvv 123"}).encode()
    )
    t.container("contosolocked", "vault").list_fail = AzureError(
        "AuthorizationFailure", "This request is not authorized to perform this operation."
    )
    t.container("sdsstate", "other").blobs["x.txt"] = Blob(b"nothing")
    return t


def run(t: Tenant, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(**env), t.clients(), detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


# ------------------------------------------------------------------ settings


def test_settings_need_a_scope_a_site_and_a_destination() -> None:
    for env, code in [
        ({}, "scanner_site"),
        (
            {"SCANNER_SITE": "x", "STATE_CONTAINER_URL": "https://a1.blob.core.windows.net/c"},
            "no_scope",
        ),
        ({"SCANNER_SITE": "x", "AZURE_MANAGEMENT_GROUP": "mg"}, "no_findings_destination"),
        (
            {"SCANNER_SITE": "x", "AZURE_SUBSCRIPTIONS": "not-a-guid", "FINDINGS_FILE": "/f"},
            "azure_subscriptions",
        ),
        (
            {
                "SCANNER_SITE": "x",
                "AZURE_MANAGEMENT_GROUP": "mg",
                "STATE_CONTAINER_URL": "http://a",
            },
            "state_container_url",
        ),
        (
            {
                "SCANNER_SITE": "x",
                "AZURE_MANAGEMENT_GROUP": "mg",
                "FINDINGS_HTTPS_URL": "https://collector.example/x",
                "FINDINGS_HMAC_KEY": "short",
            },
            "findings_hmac_key",
        ),
        (
            {
                "SCANNER_SITE": "x",
                "AZURE_MANAGEMENT_GROUP": "mg",
                "FINDINGS_FILE": "/f",
                "DISCOVER": "s3",
            },
            "discover_kind",
        ),
    ]:
        with pytest.raises(ConfigError) as err:
            read_settings(env)
        assert err.value.code == code


def test_settings_hold_the_push_url_and_key_as_secrets() -> None:
    s = read_settings(
        {
            "SCANNER_SITE": "mg-contoso",
            "AZURE_SUBSCRIPTIONS": f"{SUB_A},{SUB_B}",
            "FINDINGS_HTTPS_URL": "https://collector.example/x?token=made-up-token",
            "FINDINGS_HMAC_KEY": "k" * 40,
            "DISCOVER": "blob,adls",
        }
    )
    assert s.subscriptions == (SUB_A, SUB_B) and s.discover == ("azure_blob",)
    assert "made-up-token" not in repr(s) and "k" * 40 not in repr(s)


# ------------------------------------------------------------------ discovery


def test_discovery_lists_every_container_under_the_management_group() -> None:
    t = tenant()
    doc = run(t)
    request = t.graph.requests[0]
    assert request.management_groups == ["mg-contoso"] and request.subscriptions is None
    storage = [r for r in t.graph.requests if "storageaccounts" in r.query]
    assert len(storage) == 3  # five accounts, two to a page
    s = stores(doc)
    assert "contosofiles/*" not in s and not any(n.startswith("contosofiles") for n in s)
    lake = s["contosolake/raw"]
    assert lake["status"] == "scanned" and lake["hierarchicalNamespace"] is True
    assert lake["subscription"] == SUB_A and lake["resourceGroup"] == "rg-data"
    assert lake["resourceIdHash"] == resource_id_hash(LAKE)
    assert lake["atRestEncryption"] == "service_managed"
    assert s["contosocmk/cards"]["atRestEncryption"] == "customer_managed_key"
    assert s["contosocmk/cards"]["atRestKeyHash"] == key_hash(VAULT_KEY)
    assert s["contosocmk/cards"]["subscription"] == SUB_B
    assert s["sdsstate/scanner"]["reason"] == "self"
    assert s["sdsstate/other"]["status"] == "scanned"
    locked = s["contosolocked/vault"]
    assert (locked["status"], locked["reason"], locked["networkRestricted"]) == (
        "skipped",
        "network",
        True,
    )
    assert doc["platform"] == "azure" and doc["site"] == "mg-contoso"
    assert "account" not in doc and "region" not in doc


def test_a_container_listing_that_fails_is_the_accounts_gap() -> None:
    t = tenant()
    t.arm.paths[f"{LAKE}/blobServices/default/containers"] = AzureError("AuthorizationFailed")
    s = stores(run(t))
    assert s["contosolake/*"]["status"] == "error"
    assert s["contosolake/*"]["reason"] == "access_denied"
    assert s["contosolake/*"]["error"] == "AuthorizationFailed"


def test_a_resource_graph_failure_is_a_listing_error() -> None:
    t = tenant()
    t.graph.fail = AzureError("AuthorizationFailed", "denied on mg-contoso")
    doc = run(t)
    assert doc["discovery"]["listErrors"]["azure_blob"] == "AuthorizationFailed"


def test_allow_deny_and_sampling_rules_decide_containers() -> None:
    t = tenant()
    doc = run(
        t,
        DISCOVER_DENY="blob:contosolocked/*,tag:scan=false",
        DISCOVER_ALLOW="azure_blob:contoso*",
        DISCOVER_SAMPLING=json.dumps([{"match": "tag:env=prod", "samplePercent": 50}]),
    )
    s = stores(doc)
    assert s["contosolocked/vault"]["reason"] == "denied"
    assert s["sdsstate/other"]["reason"] == "not_allowed"
    assert s["contosolake/raw"]["samplePercent"] == 50
    assert any(
        c["target"] == "contosolake/raw/" and c["samplePercent"] == 50 for c in doc["coverage"]
    )


def test_subscriptions_scope_instead_of_a_management_group() -> None:
    t = tenant()
    doc, _ = run_scan(
        read_settings(
            {"SCANNER_SITE": "two-subs", "AZURE_SUBSCRIPTIONS": SUB_A, "FINDINGS_FILE": "/dev/null"}
        ),
        t.clients(),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None
    assert t.graph.requests[0].subscriptions == [SUB_A]
    assert t.graph.requests[0].management_groups is None


# ------------------------------------------------------------------ reading


def test_blobs_are_read_by_format_with_their_own_encryption() -> None:
    t = tenant()
    doc = run(t)
    raw = next(c for c in doc["coverage"] if c["target"] == "contosolake/raw/")
    assert raw["scanned"] == 4  # two CSVs, the gzip, the Parquet file
    assert raw["skipped"] == {"archive_tier": 1, "audio": 1}
    assert (raw["unreadable"], raw["kmsDenied"]) == (1, 1)  # the customer-provided key
    assert raw["formats"] == {"csv": 3, "parquet": 1}
    by_blob: dict[str, list[dict[str, Any]]] = {}
    for f in doc["findings"]:
        by_blob.setdefault(f["resource"]["blob"], []).append(f)
    plain = {f["class"]: f for f in by_blob["exports/cards.csv"]}
    assert {"card", "us_ssn"} <= set(plain)
    card = plain["card"]
    assert card["resource"]["type"] == "blob_object" and card["resource"]["versionId"] == "null"
    assert card["resource"]["resourceIdHash"] == resource_id_hash(LAKE)
    assert (
        card["atRestEncryption"] == "service_managed"
        and card["pciNote"]["requirement"] == "3.5.1.2"
    )
    assert card["link"].startswith("https://portal.azure.com/#resource/subscriptions/")
    scoped = next(f for f in by_blob["exports/pay.csv"] if f["class"] == "card")
    assert scoped["atRestEncryption"] == "customer_managed_key"
    assert scoped["atRestKeyHash"] == key_hash(VAULT_KEY)
    column = next(f for f in by_blob["lake/part-0.parquet"])
    assert (column["resource"]["column"], column["format"]) == ("card_number", "parquet")
    cmk = next(f for f in doc["findings"] if f["resource"]["account"] == "contosocmk")
    assert (
        cmk["atRestEncryption"] == "customer_managed_key"
        and cmk["resource"]["subscription"] == SUB_B
    )
    # Nothing is written to a customer's account: only the job's own container.
    assert all(
        not c.writes
        for a, svc in t.services.items()
        for c in svc.containers.values()
        if a != "sdsstate"
    )


def test_the_next_run_reads_only_what_changed_and_keeps_findings() -> None:
    t = tenant()
    first = run(t)
    downloads = len(t.container("contosolake", "raw").downloads)
    state = t.state.json("state/scanner-state.json")
    assert state["version"] == 1 and state["cursors"]
    second = run(t)
    assert len(t.container("contosolake", "raw").downloads) == downloads
    assert {f["id"] for f in second["findings"]} == {f["id"] for f in first["findings"]}
    latest = t.state.json("findings/latest.json")
    assert latest["runId"] == second["runId"]
    assert f"findings/runs/{first['runId']}.json" in t.state.written
    # A blob that is gone takes its findings with it.
    del t.container("contosolake", "raw").blobs["exports/cards.csv"]
    third = run(t)
    assert not any(f["resource"]["blob"] == "exports/cards.csv" for f in third["findings"])


def test_the_budget_defers_and_the_next_run_resumes() -> None:
    t = tenant()
    t.container("contosolake", "raw").per_page = 2
    doc = run(t, MAX_OBJECTS_PER_RUN="2")
    s = stores(doc)
    deferred = [n for n, v in s.items() if v["status"] == "deferred" or v.get("backlog")]
    assert deferred
    before = len(t.container("contosolake", "raw").downloads)
    run(t, MAX_OBJECTS_PER_RUN="50")
    assert len(t.container("contosolake", "raw").downloads) > before


def test_a_missing_data_role_is_access_denied() -> None:
    t = tenant()
    t.container("contosolake", "curated").list_fail = AzureError(
        "AuthorizationPermissionMismatch", "no Storage Blob Data Reader"
    )
    s = stores(run(t))
    assert (s["contosolake/curated"]["status"], s["contosolake/curated"]["reason"]) == (
        "error",
        "access_denied",
    )


def test_another_run_holding_the_lock_stops_this_one() -> None:
    t = tenant()
    t.state.written["state/lock.json"] = b"{}"
    doc, failed = run_scan(settings(), t.clients(), detector=shared_detector(), now=lambda: NOW)
    assert doc is None and failed == 0


def test_versionless_key_is_what_a_customer_hashes() -> None:
    assert versionless_key(VAULT_KEY.upper() + "/ABC") == VAULT_KEY
    assert versionless_key("https://hsm.managedhsm.azure.net/keys/k") == (
        "https://hsm.managedhsm.azure.net/keys/k"
    )
    assert versionless_key("not a key") is None


# ------------------------------------------------------------------ sinks and entry point


def test_sinks_https_signed_event_grid_and_a_file(tmp_path: Path) -> None:
    key = "k" * 40
    s = read_settings(
        {
            "SCANNER_SITE": "mg-contoso",
            "AZURE_MANAGEMENT_GROUP": "mg-contoso",
            "FINDINGS_HTTPS_URL": "https://collector.example/findings",
            "FINDINGS_HMAC_KEY": key,
            "FINDINGS_EVENT_GRID_ENDPOINT": "https://topic.westus-1.eventgrid.azure.net/api/events",
            "FINDINGS_FILE": str(tmp_path / "f.json"),
        }
    )
    t = tenant()
    got = sinks_for(s, t.clients())
    assert [type(x).__name__ for x in got] == ["HttpsSink", "EventGridSink", "FileSink"]

    posted: list[Any] = []

    class Response(io.BytesIO):
        status = 202

    def opener(req: Any, timeout: float) -> Response:
        posted.append(req)
        return Response(b"")

    sent: list[Any] = []

    class Grid:
        def send(self, events: list[Any]) -> None:
            sent.extend(events)

    https = got[0]
    https._open = opener  # type: ignore[attr-defined]
    grid = EventGridSink("https://topic.example/api/events", object(), client=Grid())
    doc, failed = run_scan(
        s, t.clients(), sinks=[https, grid, got[2]], detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    req = posted[0]
    assert req.get_header("User-agent").startswith("sensitive-data-scanner-azure/")
    assert verify(
        key.encode(), req.get_header("X-sds-signature"), req.data, now=dt.datetime.now().timestamp()
    )
    assert sent and sent[0].type == "Findings v1" and sent[0].source == "sensitive-data-scanner"
    assert sent[0].data["runId"] == doc["runId"]
    assert json.loads((tmp_path / "f.json").read_text())["runId"] == doc["runId"]


def test_an_event_grid_failure_fails_the_sink(capsys: pytest.CaptureFixture[str]) -> None:
    class Grid:
        def send(self, events: list[Any]) -> None:
            raise AzureError("Unauthorized", "topic says no")

    sink = EventGridSink("https://topic.example/api/events", object(), client=Grid())
    assert sink.push({"runId": "r", "findings": [], "coverage": []}) == 0
    assert '"error":"Unauthorized"' in capsys.readouterr().out
    assert FileSink.__name__ == "FileSink"


def test_the_entry_point_reports_a_bad_setting_by_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SCANNER_SITE", "mg-contoso")
    monkeypatch.setenv("AZURE_MANAGEMENT_GROUP", "mg-contoso")
    monkeypatch.setenv("FINDINGS_HTTPS_URL", "http://collector.example/made-up-token")
    assert entry.main(["scan"]) == 1
    out = capsys.readouterr().out
    assert '"error":"findings_url_not_https"' in out and "made-up-token" not in out
    assert entry.main(["nope"]) == 1


def test_check_lists_and_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {
        "SCANNER_SITE": "mg-contoso",
        "AZURE_MANAGEMENT_GROUP": "mg-contoso",
        "STATE_CONTAINER_URL": "https://sdsstate.blob.core.windows.net/scanner",
    }.items():
        monkeypatch.setenv(k, v)
    t = tenant()
    assert entry.main(["check"], clients=t.clients()) == 0
    assert not t.container("contosolake", "raw").downloads and not t.state.writes
    t.graph.fail = AzureError("AuthorizationFailed")
    assert entry.main(["check"], clients=t.clients()) == 2
    monkeypatch.setenv("FINDINGS_FILE", "/nonexistent/dir/f.json")
    assert entry.main(["scan"], clients=tenant().clients()) == 1


def test_a_pass_resumes_mid_page_and_reads_each_blob_once() -> None:
    import time

    from sensitive_data_azure.resources import BlobTarget, ResourceId
    from sensitive_data_azure.sources.blob import BlobSource
    from sensitive_data_core.adapter import Budget, FindingStore

    t = tenant()
    box = t.container("contosolake", "many")
    for i in range(7):
        box.blobs[f"d/{i}.txt"] = Blob(f"row {i}".encode())
    target = BlobTarget(ResourceId.parse(LAKE), "contosolake", "many", "https://x/")
    source = BlobSource(box, target=target, page_size=2, columnar=False)
    cursor: dict[str, Any] = {}
    runs = 0
    while True:
        runs += 1
        budget = Budget(3, 10**9, time.monotonic() + 60)
        result = source.run(cursor, budget, shared_detector(), FindingStore("x"), NOW)
        cursor = result.cursor
        if result.coverage.pass_complete:
            break
        assert runs < 10
    names = [n for n, _, _ in box.downloads]
    assert sorted(names) == sorted(set(names)) and len(names) == 7
    assert runs == 3 and cursor["watermark"]


def test_a_large_container_is_named_for_a_blob_inventory() -> None:
    """Blob Inventory is not built (#67, on demand): a container whose complete pass listed
    at least AZURE_BLOB_INVENTORY_MIN_OBJECTS is named in the run summary, and listed as
    before; a smaller one is not."""
    t = tenant()
    doc = run(t, AZURE_BLOB_INVENTORY_MIN_OBJECTS="5")
    s = stores(doc)
    assert s["contosolake/raw"]["recommendation"] == "blob_inventory"  # eight blobs listed
    assert "recommendation" not in s["contosolake/curated"]  # one
    assert "recommendation" not in stores(run(t))["contosolake/raw"]  # the default: a million
