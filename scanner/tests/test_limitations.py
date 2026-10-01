"""Every deliberate limitation has a setting, a default, a named gap and a deployed toggle (#105).

docs/limitations.md lists each limitation. These tests hold it to the code: each setting
is one the platform's configuration reads, with the default the issue gives; each is set by
the platform's deploy template with that default; a store left unread because a setting is
off names the setting (`toggle`); and a hook switched on says `not_implemented`. The
per-store behavior (each toggle off gives its named gap, on reads or says it cannot) is
tested beside each adapter: test_config_stores, test_other_stores, test_opensearch,
test_snapshots, test_azure_logs, test_azure_snapshots_keyvault, test_gcp_gcs,
test_gcp_nosql, test_gcp_databases, test_gcp_ops, test_saas_m365, test_modes_saas and
test_saas_atlassian.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import config
from cfn_templates import load_path
from sensitive_data_azure.config import read_settings as azure_settings
from sensitive_data_azure.runner import name_toggles as azure_name_toggles
from sensitive_data_core.coverage import Store, summary
from sensitive_data_core.findings import Coverage
from sensitive_data_core.modes import link_duplicates
from sensitive_data_gcp.config import read_settings as gcp_settings
from sensitive_data_gcp.runner import name_toggles as gcp_name_toggles
from sensitive_data_saas.config import read_settings as saas_settings
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.runner import name_toggles as aws_name_toggles

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
LIMITATIONS = (DOCS / "limitations.md").read_text()
SCHEMA = json.loads((REPO / "schema" / "findings.schema.json").read_text())


@dataclass(frozen=True)
class Toggle:
    row: str  # the issue's row, as docs/limitations.md numbers it
    platform: str  # aws | azure | gcp | saas
    env: str  # the setting the scanner reads
    default: Any  # what the configuration holds when it is not set
    template: str  # the deploy template's parameter or variable that sets it ("" for none)
    hook: bool = False  # designed, not built: on gives `not_implemented`


TOGGLES = (
    Toggle("A1", "aws", "MAX_EXPORTS_PER_RUN", 1, "MaxExportsPerRun"),
    Toggle("A1", "aws", "EXPORT_MIN_INTERVAL_DAYS", 7, "ExportMinIntervalDays"),
    Toggle("A2", "aws", "GLUE_LAKE_FORMATION", "read", "GlueLakeFormation"),
    Toggle("A3", "aws", "KMS_ALLOWED_KEY_ARNS", (), "KmsAllowedKeyArns"),
    Toggle("A4", "aws", "SSM_DECRYPT", False, "SsmDecrypt"),
    Toggle("A4b", "aws", "SECRETS_READ", False, "SecretsRead"),
    Toggle("A4c", "aws", "TIMESTREAM_READ", True, "TimestreamRead"),
    Toggle("A4c", "aws", "KEYSPACES_READ", True, "KeyspacesRead"),
    Toggle("A5", "aws", "FILESYSTEM_TASK_ENABLED", False, "FilesystemTaskEnabled", hook=True),
    Toggle("A6", "aws", "VPC_SUBNET_IDS", (), "VpcSubnetIds"),
    Toggle("A6", "aws", "VPC_SECURITY_GROUP_IDS", (), "VpcSecurityGroupIds"),
    Toggle("B1", "azure", "AZURE_LOG_ANALYTICS", True, "readLogAnalytics"),
    Toggle("B2", "azure", "AZURE_DB_READ", (), "readDatabases"),
    Toggle("B3", "azure", "AZURE_COSMOS_READER_POLICY", False, "assignCosmosReaderPolicy", True),
    Toggle("B4", "azure", "AZURE_READ_SNAPSHOTS", False, "readDiskSnapshots", hook=True),
    Toggle("C6", "azure", "AZURE_FILES_READ", False, "readFileShares"),
    Toggle("C2", "gcp", "GCP_SPANNER", True, "read_spanner"),
    Toggle("C2", "gcp", "GCP_ALLOYDB", True, "read_alloydb"),
    Toggle("C3", "gcp", "GCS_READ_ARCHIVE", False, "read_archive_objects"),
    Toggle("C4", "gcp", "GCP_SQLSERVER", False, "read_sqlserver", hook=True),
    Toggle("C5", "gcp", "GCP_READ_PUBSUB_DLQ", False, "read_pubsub_dead_letters", hook=True),
    Toggle("D1", "saas", "GWS_ALERT_CENTER", True, ""),
    Toggle("D2", "saas", "LINK_VENDOR_ALERTS_BY_LOCATION", True, ""),
    Toggle("D3", "saas", "M365_MAIL", True, ""),
    Toggle("D4", "saas", "ATLASSIAN_AUTH_MODE", "token", ""),
)
# The rows with no setting, and why (docs/limitations.md says the same).
NO_TOGGLE = {
    "A7": "the refusal of a user that can write is always on",
    "B5": "a hard gap: only keys that can write read it",
    "C1": "a deployment requirement",
    "C7": "a release step",
    "D5": "the customer declares its keys (existing settings)",
}
# Where each platform's settings are read, and the deploy templates that set them.
CONFIG = {
    "aws": REPO / "scanner/src/sensitive_data_scanner/config.py",
    "azure": REPO / "scanner/azure/src/sensitive_data_azure/config.py",
    "gcp": REPO / "scanner/gcp/src/sensitive_data_gcp/config.py",
    "saas": REPO / "scanner/saas/src/sensitive_data_saas/config.py",
}
SAAS_EXAMPLES = sorted((REPO / "deploy/saas").glob("*.yaml"))


def aws() -> Any:
    return read_config({"RESULTS_BUCKET": "x"})


def azure(**env: str) -> Any:
    return azure_settings(
        {
            "SCANNER_SITE": "x",
            "AZURE_SUBSCRIPTIONS": "0" * 8 + "-0000-0000-0000-" + "0" * 12,
            "FINDINGS_FILE": "/f",
            **env,
        }
    )


def gcp(**env: str) -> Any:
    return gcp_settings(
        {"SCANNER_SITE": "x", "GCP_ORGANIZATION": "1234", "FINDINGS_FILE": "/f", **env}
    )


def saas(tmp_path: Path, **env: str) -> Any:
    secret = tmp_path / "secret"
    secret.write_text("made-up")
    gws_key = tmp_path / "gws-key.json"
    gws_key.write_text("{}")
    return saas_settings(
        {
            "SCANNER_SITE": "x",
            "FINDINGS_FILE": "/f",
            "M365_TENANT_ID": "00000000-0000-0000-0000-000000000001",
            "M365_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
            "M365_CLIENT_SECRET_FILE": str(secret),
            "GWS_CUSTOMER_ID": "C0abcdef1",
            "GWS_SERVICE_ACCOUNT": "sds-scanner@acme-sds.iam.gserviceaccount.com",
            "GWS_ADMIN_USER": "admin@acme.example",
            "GWS_KEY_FILE": str(gws_key),
            "ATLASSIAN_SITE": "acme.atlassian.net",
            "ATLASSIAN_EMAIL": "sds@acme.example",
            "ATLASSIAN_API_TOKEN_FILE": str(secret),
            **env,
        }
    )


# ------------------------------------------------------------------ the page


def test_the_page_lists_every_row_with_its_setting_and_default() -> None:
    for t in TOGGLES:
        row = next(
            (line for line in LIMITATIONS.splitlines() if line.startswith(f"| {t.row} |")), None
        )
        assert row is not None, t.row
        assert f"`{t.env}`" in row, (t.row, t.env)
        if t.template:
            assert f"`{t.template}`" in row, (t.row, t.template)
        if t.hook:
            assert "**a hook**" in row and "not_implemented" in row, t.row
    for row, why in NO_TOGGLE.items():
        line = next(x for x in LIMITATIONS.splitlines() if x.startswith(f"| {row} |"))
        assert "none" in line, (row, why)


def test_the_page_is_linked_from_the_readme_and_each_platform_guide() -> None:
    assert "docs/limitations.md" in (REPO / "README.md").read_text()
    for guide in ("ARCHITECTURE.md", "AZURE.md", "GCP.md", "SAAS.md", "DATABASES.md", "README.md"):
        assert "(limitations.md)" in (DOCS / guide).read_text(), guide


def test_every_setting_is_one_its_platform_reads() -> None:
    for t in TOGGLES:
        source = CONFIG[t.platform].read_text()
        assert f'"{t.env}"' in source, (t.platform, t.env)


# ------------------------------------------------------------------ defaults


def test_aws_defaults() -> None:
    c = aws()
    got = {
        "MAX_EXPORTS_PER_RUN": c.max_exports_per_run,
        "EXPORT_MIN_INTERVAL_DAYS": c.export_min_interval_days,
        "GLUE_LAKE_FORMATION": c.glue_lake_formation,
        "KMS_ALLOWED_KEY_ARNS": c.kms_allowed_key_arns,
        "SSM_DECRYPT": c.ssm_decrypt,
        "SECRETS_READ": c.secrets_read,
        "TIMESTREAM_READ": c.timestream_read,
        "KEYSPACES_READ": c.keyspaces_read,
        "FILESYSTEM_TASK_ENABLED": c.filesystem_task,
        "VPC_SUBNET_IDS": c.vpc_subnet_ids,
        "VPC_SECURITY_GROUP_IDS": c.vpc_security_group_ids,
    }
    assert got == {t.env: t.default for t in TOGGLES if t.platform == "aws"}


def test_azure_defaults() -> None:
    s = azure()
    got = {
        "AZURE_LOG_ANALYTICS": s.log_analytics_read,
        "AZURE_DB_READ": s.db_read,
        "AZURE_COSMOS_READER_POLICY": s.cosmos_reader_policy,
        "AZURE_READ_SNAPSHOTS": s.read_snapshots,
        "AZURE_FILES_READ": s.files_read,
    }
    assert got == {t.env: t.default for t in TOGGLES if t.platform == "azure"}


def test_gcp_defaults() -> None:
    s = gcp()
    got = {
        "GCP_SPANNER": s.spanner_read,
        "GCP_ALLOYDB": s.alloydb_read,
        "GCS_READ_ARCHIVE": s.gcs_read_archive,
        "GCP_SQLSERVER": s.sqlserver_read,
        "GCP_READ_PUBSUB_DLQ": s.pubsub_dlq_read,
    }
    assert got == {t.env: t.default for t in TOGGLES if t.platform == "gcp"}


def test_saas_defaults(tmp_path: Path) -> None:
    s = saas(tmp_path)
    assert s.atlassian is not None and s.atlassian.api_token is not None  # token mode
    got = {
        "GWS_ALERT_CENTER": s.gws.alert_center,
        "LINK_VENDOR_ALERTS_BY_LOCATION": s.link_by_location,
        "M365_MAIL": s.m365.mail_read,
        "ATLASSIAN_AUTH_MODE": "token",
    }
    assert got == {t.env: t.default for t in TOGGLES if t.platform == "saas"}


@pytest.mark.parametrize(
    ("make", "env", "code"),
    [
        (azure, "AZURE_LOG_ANALYTICS", "azure_log_analytics"),
        (azure, "AZURE_READ_SNAPSHOTS", "azure_read_snapshots"),
        (azure, "AZURE_COSMOS_READER_POLICY", "azure_cosmos_reader_policy"),
        (gcp, "GCP_SPANNER", "gcp_spanner"),
        (gcp, "GCS_READ_ARCHIVE", "gcs_read_archive"),
        (gcp, "GCP_SQLSERVER", "gcp_sqlserver"),
        (gcp, "GCP_READ_PUBSUB_DLQ", "gcp_read_pubsub_dlq"),
    ],
)
def test_a_toggle_takes_on_or_off_and_names_itself_when_wrong(
    make: Any, env: str, code: str
) -> None:
    with pytest.raises(ValueError) as err:
        make(**{env: "maybe"})
    assert getattr(err.value, "code", None) == code
    assert make(**{env: "on"}) != make(**{env: "off"})


def test_aws_vpc_settings_go_together_and_are_ids() -> None:
    for env in (
        {"VPC_SUBNET_IDS": "subnet-0123456789abcdef0"},
        {"VPC_SECURITY_GROUP_IDS": "sg-0123abcd"},
        {"VPC_SUBNET_IDS": "not-a-subnet", "VPC_SECURITY_GROUP_IDS": "sg-0123abcd"},
        {"KMS_ALLOWED_KEY_ARNS": "alias/mine"},
    ):
        with pytest.raises(ValueError):
            read_config({"RESULTS_BUCKET": "x", **env})


# ------------------------------------------------------------------ the deploy templates


def test_scanner_yaml_sets_each_aws_toggle_with_its_default() -> None:
    t = load_path(REPO / "deploy/scanner.yaml")
    env = t["Resources"]["Function"]["Properties"]["Environment"]["Variables"]
    for toggle in (x for x in TOGGLES if x.platform == "aws"):
        assert toggle.env in env, toggle.env
        assert toggle.template in json.dumps(env[toggle.env]), toggle.env
        p = t["Parameters"][toggle.template]
        want = toggle.default
        if isinstance(want, bool):
            want = "true" if want else "false"
        elif isinstance(want, tuple):
            want = ""
        assert p["Default"] == want, toggle.template
    # The function joins the VPC only when the subnets are set.
    assert "VpcConfig" in t["Resources"]["Function"]["Properties"]
    assert t["Resources"]["VpcNetworkInterfacePermissions"]["Condition"] == "VpcAttached"


def test_bicep_sets_each_azure_toggle_with_its_default() -> None:
    main = json.loads((REPO / "deploy/azure/main.json").read_text())
    job = (REPO / "deploy/azure/modules/job.bicep").read_text()
    for toggle in (x for x in TOGGLES if x.platform == "azure"):
        p = main["parameters"][toggle.template]
        want = "" if toggle.default == () else toggle.default
        assert p["defaultValue"] == want, toggle.template
        assert f"name: '{toggle.env}'" in job, toggle.env


def test_terraform_sets_each_gcp_toggle_with_its_default() -> None:
    main = (REPO / "deploy/gcp/main.tf").read_text()
    variables = (REPO / "deploy/gcp/variables.tf").read_text()
    for toggle in (x for x in TOGGLES if x.platform == "gcp"):
        assert re.search(rf"{toggle.env}\s+= var\.{toggle.template} \?", main), toggle.env
        block = variables[variables.index(f'variable "{toggle.template}"') :]
        default = re.search(r"default\s+=\s+(\w+)", block)
        assert default is not None and default[1] == str(toggle.default).lower(), toggle.template


def test_the_saas_examples_set_the_saas_toggles() -> None:
    text = "\n".join(p.read_text() for p in SAAS_EXAMPLES)
    for toggle in (x for x in TOGGLES if x.platform == "saas"):
        assert toggle.env in text, toggle.env


# ------------------------------------------------------------------ the named gaps


def valid_summary(stores: list[Store]) -> dict[str, Any]:
    out = summary(stores, {})
    store_schema = SCHEMA["$defs"]["discovery"]["properties"]["stores"]
    validator = Draft202012Validator({**store_schema, "$defs": SCHEMA["$defs"]})
    assert list(validator.iter_errors(out["stores"])) == []
    return out


def test_a_store_names_its_toggle_and_a_hook_says_not_implemented() -> None:
    off, hook = Store("efs", "fs-1"), Store("efs", "fs-2")
    off.toggle_off("FILESYSTEM_TASK_ENABLED", "needs_task")
    hook.not_implemented("FILESYSTEM_TASK_ENABLED")
    out = valid_summary([off, hook])
    got = {s["name"]: (s["status"], s["reason"], s["toggle"]) for s in out["stores"]}
    assert got == {
        "fs-1": ("skipped", "needs_task", "FILESYSTEM_TASK_ENABLED"),
        "fs-2": ("skipped", "not_implemented", "FILESYSTEM_TASK_ENABLED"),
    }
    assert out["byReason"] == {"needs_task": 1, "not_implemented": 1}
    with pytest.raises(ValueError):
        Store("s3", "b").name_toggle("not a setting")


def test_aws_names_the_toggle_behind_each_gap() -> None:
    exporting = SimpleNamespace(id="rds:db1", quota=object())
    budget = Store("rds", "db1", reason="budget", status="deferred")
    budget.source_ids.append("rds:db1")
    run_budget = Store("s3", "b", reason="budget", status="deferred")  # the run's own budget
    redshift = Store("redshift", "wh", reason="read_not_configured", status="skipped")
    vpc = Store("msk", "kafka", reason="vpc_only", status="skipped")
    kms = Store("s3", "locked", reason="kms_access", status="error")
    large = Store("dynamodb", "big", reason="too_large", status="skipped")
    stores = [budget, run_budget, redshift, vpc, kms, large]
    notes: dict[str, tuple[str | None, dict[str, Any]]] = {"rds:db1": ("budget", {})}
    aws_name_toggles(config(), stores, [exporting], notes)
    assert [s.toggle for s in stores] == [
        "MAX_EXPORTS_PER_RUN",
        None,
        "REDSHIFT_READ",
        "VPC_SUBNET_IDS",
        None,  # no allow-list: the key policy, not a setting, keeps it out
        "DYNAMODB_EXPORT",
    ]
    key = "arn:aws:kms:us-west-2:123456789012:key/" + "0" * 36
    kms2 = Store("s3", "locked", reason="kms_access", status="error")
    vpc2 = Store("msk", "kafka", reason="vpc_only", status="skipped")
    aws_name_toggles(
        config(
            kms_allowed_key_arns=(key,),
            vpc_subnet_ids=("subnet-0123456789abcdef0",),
            vpc_security_group_ids=("sg-0123abcd",),
        ),
        [kms2, vpc2],
        [],
        {},
    )
    assert (kms2.toggle, vpc2.toggle) == ("KMS_ALLOWED_KEY_ARNS", None)
    valid_summary(stores)


def test_azure_names_the_toggle_behind_each_gap_and_the_cosmos_policy_hook() -> None:
    def gaps() -> list[Store]:
        return [
            Store("azure_sql", "srv/db", reason="read_not_configured", status="skipped"),
            Store("azure_files", "acct/share", reason="read_not_configured", status="skipped"),
            Store("key_vault", "kv", reason="read_not_configured", status="skipped"),
            Store("cosmosdb", "acct/db/c", reason="access_denied", status="error"),
            Store("cosmosdb", "acct/*", reason="no_read_path", status="skipped"),  # B5: hard gap
        ]

    off = gaps()
    azure_name_toggles(azure(), off)
    assert [(s.status, s.reason, s.toggle) for s in off] == [
        ("skipped", "read_not_configured", "AZURE_DB_READ"),
        ("skipped", "read_not_configured", "AZURE_FILES_READ"),
        ("skipped", "read_not_configured", "KEYVAULT_SECRETS_READ"),
        ("error", "access_denied", "assignCosmosReaderPolicy"),
        ("skipped", "no_read_path", None),
    ]
    on = gaps()
    azure_name_toggles(azure(AZURE_COSMOS_READER_POLICY="on"), on)
    assert (on[3].status, on[3].reason, on[3].toggle) == (
        "skipped",
        "not_implemented",
        "assignCosmosReaderPolicy",
    )
    valid_summary(off + on)


def test_gcp_names_the_toggle_behind_each_gap() -> None:
    bucket = Store("gcs", "cold", status="scanned")
    bucket.source_ids.append("gcs:cold/")
    cov = Coverage("gcs", "cold/")
    cov.not_allowed["archive_class"] = 3
    plain = Store("gcs", "warm", status="scanned")
    secrets = Store("secret_manager", "proj", reason="read_not_configured", status="skipped")
    gcp_name_toggles([bucket, plain, secrets], {"gcs:cold/": cov})
    assert [s.toggle for s in (bucket, plain, secrets)] == [
        "GCS_READ_ARCHIVE",
        None,
        "SECRET_MANAGER_READ",
    ]


# ------------------------------------------------------------------ linking by location


def finding(fid: str, source: str, cls: str, item: str = "i1") -> dict[str, Any]:
    return {
        "id": fid,
        "source": source,
        "class": cls,
        "resource": {
            "type": "saas_item",
            "vendor": "slack",
            "service": "channel",
            "tenantHash": "t",
            "itemHash": item,
        },
    }


def test_a_class_less_alert_links_by_location_only_from_the_named_sources() -> None:
    ours = finding("a" * 32, "scanner", "card")
    alert = finding("b" * 32, "vendor:slack_dlp", "other")
    elsewhere = finding("d" * 32, "vendor:slack_dlp", "other", item="i2")
    assert link_duplicates([ours, alert, elsewhere], by_location=("vendor:slack_dlp",)) == 2
    assert ours["linked"] == [alert["id"]] and alert["linked"] == [ours["id"]]
    assert ours["linkedBy"] == alert["linkedBy"] == "location"
    assert "linked" not in elsewhere
    # Only the named sources: a Workspace custom detector's alert is not linked so.
    custom = finding("c" * 32, "vendor:google_workspace_dlp", "other")
    again = finding("a" * 32, "scanner", "card")
    assert link_duplicates([again, custom], by_location=("vendor:slack_dlp",)) == 0
    plain = [finding("a" * 32, "scanner", "card"), finding("b" * 32, "vendor:slack_dlp", "other")]
    assert link_duplicates(plain) == 0  # off: a link needs the same class
    assert not any("linked" in f for f in plain)
    schema = SCHEMA["$defs"]["finding"]["properties"]
    assert schema["linkedBy"] == {
        "description": schema["linkedBy"]["description"],
        "const": "location",
    }
