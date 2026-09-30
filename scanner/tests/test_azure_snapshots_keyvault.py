"""Managed disk snapshots (coverage only) and Key Vault secrets (off by default, counts only).

Stubbed Azure SDK; every value is made up.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from azure_fakes import NOW, SUB_A, AzureError, Graph, Tenant, settings
from sensitive_data_azure.config import ConfigError, read_settings
from sensitive_data_azure.runner import run_scan
from sensitive_data_core.findings import key_hash
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
RG = f"/subscriptions/{SUB_A}/resourceGroups/rg-vm/providers"
DISK = f"{RG}/Microsoft.Compute/disks/vm1-os"
DES = f"{RG}/Microsoft.Compute/diskEncryptionSets/des-1"
VAULT = f"{RG}/Microsoft.KeyVault/vaults/kv-app"
DES_KEY = "https://kv-disk.vault.azure.net/keys/disk-key"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


class Secrets:
    """A `SecretClient`: properties, then values; any other call fails the test."""

    def __init__(self, secrets: dict[str, dict[str, Any]], fail: Exception | None = None) -> None:
        self.secrets = secrets
        self.fail = fail
        self.got: list[str] = []

    def list_properties_of_secrets(self, **kwargs: Any) -> Any:
        if self.fail is not None:
            raise self.fail
        return iter(
            SimpleNamespace(
                name=n,
                enabled=s.get("enabled", True),
                managed=s.get("managed", False),
                expires_on=s.get("expires_on"),
            )
            for n, s in self.secrets.items()
        )

    def get_secret(self, name: str, version: str | None = None, **kwargs: Any) -> Any:
        self.got.append(name)
        return SimpleNamespace(value=self.secrets[name]["value"])

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"a key vault was asked to {name}")


def tenant(secrets: Secrets) -> Tenant:
    t = Tenant(
        Graph(
            {
                "compute/snapshots": [
                    {
                        "id": f"{RG}/Microsoft.Compute/snapshots/vm1-os-mon",
                        "name": "vm1-os-mon",
                        "source": DISK.lower(),
                        "created": "2026-09-28T00:00:00Z",
                        "sizeBytes": 34359738368,
                        "encryption": "EncryptionAtRestWithPlatformKey",
                    },
                    {
                        "id": f"{RG}/Microsoft.Compute/snapshots/vm1-os-tue",
                        "name": "vm1-os-tue",
                        "source": DISK.lower(),
                        "created": "2026-09-29T00:00:00Z",
                        "sizeBytes": 34359738368,
                        "encryption": "EncryptionAtRestWithCustomerKey",
                        "encryptionSet": DES.lower(),
                    },
                    {
                        "id": f"{RG}/Microsoft.Compute/snapshots/orphan",
                        "name": "orphan",
                        "source": "",
                        "created": "2026-09-01T00:00:00Z",
                        "encryption": "EncryptionAtRestWithPlatformKey",
                    },
                ],
                "compute/diskencryptionsets": [{"id": DES.lower(), "keyUrl": DES_KEY + "/v1"}],
                "keyvault/vaults": [
                    {"id": VAULT, "name": "kv-app", "vaultUri": "https://kv-app.vault.azure.net/"}
                ],
            },
            page=10,
        )
    )
    t.drivers["_kv"] = secrets
    return t


def run(t: Tenant, **env: str) -> dict[str, Any]:
    clients = t.clients()
    clients.made[("keyvault", "https://kv-app.vault.azure.net/")] = t.drivers["_kv"]
    doc, failed = run_scan(
        settings(DISCOVER="snapshots,keyvault", **env),
        clients,
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def secrets() -> Secrets:
    return Secrets(
        {
            "db-conn": {"value": f"Server=x;card={CARDS['visa']}"},
            "payroll-ssn": {"value": json.dumps({"ssn": dashed(SSN_A)})},
            "old": {"value": CARDS["amex"], "enabled": False},
            "expired": {"value": CARDS["amex"], "expires_on": NOW - dt.timedelta(days=1)},
            "tls-cert": {"value": "MIIC...", "managed": True},
        }
    )


def test_snapshots_are_reported_per_disk_and_never_read() -> None:
    s = {x["name"]: x for x in run(tenant(secrets()))["discovery"]["stores"]}
    disk = s["vm1-os"]
    assert (disk["status"], disk["reason"]) == ("skipped", "needs_sas_export")
    assert disk["olderSnapshots"] == 1 and disk["resource"] == "snapshot"
    assert disk["snapshotTime"] == "2026-09-29T00:00:00Z" and disk["sizeBytes"] == 34359738368
    assert disk["atRestEncryption"] == "customer_managed_key"
    assert disk["atRestKeyHash"] == key_hash(DES_KEY)
    assert s["orphan"]["atRestEncryption"] == "service_managed"


def test_key_vault_secrets_are_off_by_default() -> None:
    kv = secrets()
    s = {x["name"]: x for x in run(tenant(kv))["discovery"]["stores"]}
    assert s["kv-app"]["reason"] == "read_not_configured"
    assert kv.got == []


def test_key_vault_secrets_when_on_are_counts_only() -> None:
    kv = secrets()
    doc = run(tenant(kv), KEYVAULT_SECRETS_READ="on")
    s = {x["name"]: x for x in doc["discovery"]["stores"]}
    assert s["kv-app"]["status"] == "scanned"
    assert s["kv-app"]["items"] == 5
    assert s["kv-app"]["itemTypes"] == {"Certificate": 1, "Disabled": 2, "Secret": 2}
    assert sorted(kv.got) == ["db-conn", "payroll-ssn"]
    found = {(f["resource"]["table"], f["class"]) for f in doc["findings"]}
    assert {("db-conn", "card"), ("payroll-ssn", "us_ssn")} <= found
    for f in doc["findings"]:
        assert f["resource"]["field"] == "value" and f["resource"]["readBy"] == "get_secret"
        assert f["offsets"] == [] and f["atRestEncryption"] == "service_managed"


def test_a_vault_that_refuses_is_access_denied_or_network() -> None:
    def reason(message: str) -> str:
        err = AzureError("Forbidden", message)
        err.status_code = 403  # type: ignore[attr-defined]
        doc = run(tenant(Secrets({}, err)), KEYVAULT_SECRETS_READ="on")
        return str({x["name"]: x for x in doc["discovery"]["stores"]}["kv-app"]["reason"])

    assert reason("The user does not have secrets list permission (access policy)") == (
        "access_denied"
    )
    assert reason("Client address is not authorized. ForbiddenByFirewall") == "network"


def test_keyvault_setting_is_on_or_off() -> None:
    base = {"SCANNER_SITE": "x", "AZURE_MANAGEMENT_GROUP": "mg", "FINDINGS_FILE": "/f"}
    assert read_settings({**base, "KEYVAULT_SECRETS_READ": "on"}).keyvault_secrets_read
    assert not read_settings(base).keyvault_secrets_read
    with pytest.raises(ConfigError) as err:
        read_settings({**base, "KEYVAULT_SECRETS_READ": "maybe"})
    assert err.value.code == "keyvault_secrets_read"
