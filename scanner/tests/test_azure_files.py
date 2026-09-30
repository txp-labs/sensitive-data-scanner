"""Azure Files shares: discovered always; read (opt-in) over REST with the backup intent and
Storage File Data Privileged Reader. Stubbed Azure SDK; every value made up.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest

from aws_fixtures import shared_detector
from azure_fakes import (
    NOW,
    SUB_A,
    Arm,
    AzureError,
    File,
    FileService,
    Graph,
    Share,
    Tenant,
    account_id,
    account_row,
    settings,
)
from sensitive_data_azure.clients import Clients
from sensitive_data_azure.config import ConfigError, read_settings
from sensitive_data_azure.resources import resource_id_hash
from sensitive_data_azure.runner import run_scan
from sensitive_data_core.findings import key_hash
from synthetic import CARDS, SSN_A, dashed
from test_azure_blob import valid

FILES = account_id(SUB_A, "rg-files", "contosofiles")
LAKE = account_id(SUB_A, "rg-data", "contosolake")
VAULT_KEY = "https://kv-contoso.vault.azure.net/keys/files-key"


def csv_body() -> bytes:
    return f"name,card_number,ssn\nA,{CARDS['visa']},{dashed(SSN_A)}\n".encode()


def tenant() -> tuple[Tenant, dict[str, Share]]:
    t = Tenant(
        Graph(
            {
                "storageaccounts": [
                    account_row(
                        "contosofiles",
                        group="rg-files",
                        kind="FileStorage",
                        key_source="Microsoft.Keyvault",
                        vault="https://kv-contoso.vault.azure.net/",
                        key_name="files-key",
                    ),
                    account_row("contosolake"),
                ]
            }
        )
    )
    t.arm = Arm(
        {
            f"{FILES}/fileServices/default/shares": [
                {
                    "name": "finance",
                    "properties": {"enabledProtocols": "SMB", "shareUsageBytes": 4096},
                },
                {"name": "nfsdata", "properties": {"enabledProtocols": "NFS"}},
            ],
            f"{LAKE}/fileServices/default/shares": [{"name": "hr", "properties": {}}],
            f"{LAKE}/blobServices/default/containers": [],
        }
    )
    shares = {
        "finance": Share(
            {
                "exports/cards.csv": File(csv_body()),
                "exports/2026/cards.csv.gz": File(gzip.compress(csv_body())),
                "notes/readme.txt": File(b"nothing here"),
                "media/call.wav": File(b"RIFF\x24\x00\x00\x00WAVEfmt made up"),
                "broken.txt": File(b"x", fail=AzureError("InternalError", "failed")),
            }
        ),
        "hr": Share({"people.json": File(json.dumps({"ssn": dashed(SSN_A)}).encode())}),
    }
    return t, shares


def clients(t: Tenant, shares: dict[str, Share]) -> Clients:
    c = t.clients()
    c.made[("files", "https://contosofiles.file.core.windows.net/")] = FileService(
        {"finance": shares["finance"], "nfsdata": Share()}
    )
    c.made[("files", "https://contosolake.file.core.windows.net/")] = FileService(
        {"hr": shares["hr"]}
    )
    return c


def run(t: Tenant, shares: dict[str, Share], **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(DISCOVER="files", **env),
        clients(t, shares),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


ON = {"AZURE_FILES_READ": "on"}


def test_shares_are_discovered_and_not_read_by_default() -> None:
    t, shares = tenant()
    s = stores(run(t, shares))
    finance = s["contosofiles/finance"]
    assert (finance["status"], finance["reason"]) == ("skipped", "read_not_configured")
    assert finance["sizeBytes"] == 4096
    assert finance["resourceIdHash"] == resource_id_hash(FILES)
    assert (finance["atRestEncryption"], finance["atRestKeyHash"]) == (
        "customer_managed_key",
        key_hash(VAULT_KEY),
    )
    assert s["contosofiles/nfsdata"]["reason"] == "no_read_path"  # NFS: no REST access
    assert s["contosolake/hr"]["reason"] == "read_not_configured"
    assert not shares["finance"].downloads and not shares["finance"].listed


def test_when_on_files_are_read_by_format_and_nothing_is_written() -> None:
    t, shares = tenant()
    doc = run(t, shares, **ON)
    s = stores(doc)
    assert s["contosofiles/finance"]["status"] == "scanned"
    assert s["contosofiles/nfsdata"]["reason"] == "no_read_path"
    cov = next(c for c in doc["coverage"] if c["target"] == "contosofiles/finance")
    assert (cov["scanned"], cov["unreadable"], cov["skipped"]) == (3, 1, {"audio": 1})
    by = {(f["resource"]["path"], f["class"]) for f in doc["findings"]}
    assert {("exports/cards.csv", "card"), ("exports/2026/cards.csv.gz", "us_ssn")} <= by
    assert ("people.json", "us_ssn") in by
    f = next(x for x in doc["findings"] if x["resource"]["path"] == "exports/cards.csv")
    r = f["resource"]
    assert (r["type"], r["account"], r["share"]) == ("azure_file", "contosofiles", "finance")
    assert r["resourceIdHash"] == resource_id_hash(FILES)
    assert f["atRestKeyHash"] == key_hash(VAULT_KEY)
    assert f["link"].startswith("https://portal.azure.com/#resource/subscriptions/")
    assert all(inc == ["timestamps"] for _, inc in shares["finance"].listed)


def test_the_client_asks_for_the_backup_intent(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure.storage import fileshare

    made: list[dict[str, Any]] = []

    def recording(url: str, **kwargs: Any) -> Any:
        made.append({"url": url, **kwargs})
        return object()

    monkeypatch.setattr(fileshare, "ShareServiceClient", recording)
    Clients(credential=object()).client("files", "https://a1.file.core.windows.net/")
    assert made and made[0]["token_intent"] == "backup"  # noqa: S105 - an intent
    assert made[0]["url"] == "https://a1.file.core.windows.net/"


def test_a_pass_resumes_after_the_last_file_and_reads_changes_only() -> None:
    t, shares = tenant()
    first = run(t, shares, MAX_ITEMS_PER_RUN="2", **ON)
    assert (
        stores(first)["contosofiles/finance"].get("backlog")
        or stores(first)["contosofiles/finance"]["status"] == "deferred"
    )
    run(t, shares, **ON)
    reads = [p for p, _, _ in shares["finance"].downloads]
    assert len(reads) == len(set(reads))  # each file read once across the two runs
    before = len(shares["finance"].downloads)
    run(t, shares, **ON)
    assert len(shares["finance"].downloads) == before  # nothing changed since
    shares["finance"].files["exports/new.csv"] = File(csv_body(), modified=NOW)
    run(t, shares, **ON)
    assert [p for p, _, _ in shares["finance"].downloads[before:]] == ["exports/new.csv"]
    del shares["finance"].files["exports/cards.csv"]
    doc = run(t, shares, **ON)
    assert not any(f["resource"]["path"] == "exports/cards.csv" for f in doc["findings"])


def test_a_firewall_is_network_and_a_missing_role_is_access_denied() -> None:
    t, shares = tenant()
    shares["finance"].list_fail = AzureError(
        "AuthorizationFailure", "This request is not authorized to perform this operation."
    )
    denied = AzureError("AuthorizationPermissionMismatch", "no Storage File Data Privileged Reader")
    denied.status_code = 403  # type: ignore[attr-defined]
    shares["hr"].list_fail = denied
    s = stores(run(t, shares, **ON))
    assert s["contosofiles/finance"]["reason"] == "network"
    assert s["contosolake/hr"]["reason"] == "access_denied"


def test_setting_and_a_share_listing_that_fails() -> None:
    with pytest.raises(ConfigError) as err:
        read_settings(
            {
                "SCANNER_SITE": "x",
                "AZURE_MANAGEMENT_GROUP": "mg",
                "FINDINGS_FILE": "/f",
                "AZURE_FILES_READ": "maybe",
            }
        )
    assert err.value.code == "azure_files_read"
    t, shares = tenant()
    t.arm.paths[f"{LAKE}/fileServices/default/shares"] = AzureError("AuthorizationFailed")
    s = stores(run(t, shares))
    assert (s["contosolake/*"]["status"], s["contosolake/*"]["reason"]) == (
        "error",
        "access_denied",
    )
