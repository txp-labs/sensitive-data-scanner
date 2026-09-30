"""The Azure deployment (deploy/azure/main.bicep, compiled to main.json) grants reads only.

The strict test, as test_template.py is for the AWS templates: every role the
template assigns is looked up in the built-in role definitions below (their
actions and data actions as Azure publishes them), and every action must read.
The one exception is Storage Blob Data Contributor, and only on the job's own
state container. Key Vault Secrets User only with `readKeyVaultSecrets`;
Storage File Data Privileged Reader only with `readFileShares`. No
custom role, no `listKeys`, no role on anything else. CI rebuilds main.json
with a pinned Bicep and fails if it differs (the `azure-template` job).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "deploy" / "azure" / "main.json"
BICEP = REPO / "deploy" / "azure"
CONFIG = REPO / "scanner" / "azure" / "src" / "sensitive_data_azure" / "config.py"

# The built-in roles the template may assign, with their permissions as Azure defines
# them (Azure built-in roles reference). A role not here fails the test; so does any
# action in these that does not read, except where READ_ACTIONS names it.
BUILT_IN_ROLES: dict[str, dict[str, Any]] = {
    "acdd72a7-3b69-4de9-b1f8-e1ede9c4a46c": {
        "name": "Reader",
        "actions": ["*/read"],
        "dataActions": [],
    },
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": {
        "name": "Storage Blob Data Reader",
        "actions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ],
        "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    },
    "76199698-9eea-4c19-bc75-cec21354c6b6": {
        "name": "Storage Table Data Reader",
        "actions": ["Microsoft.Storage/storageAccounts/tableServices/tables/read"],
        "dataActions": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"],
    },
    "19e7f393-937e-4f77-808e-94535e297925": {
        "name": "Storage Queue Data Reader",
        "actions": ["Microsoft.Storage/storageAccounts/queueServices/queues/read"],
        # Peek only: Get Messages (dequeue) needs .../messages/process/action, not granted.
        "dataActions": ["Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"],
    },
    "b8eda974-7b85-4f76-af95-65846b26df6d": {
        "name": "Storage File Data Privileged Reader",
        "actions": [],
        # Read files over REST with an OAuth token and the backup intent, whatever their
        # NTFS ACLs say: reads only.
        "dataActions": [
            "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
            "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
        ],
    },
    "4633458b-17de-408a-b874-0445c86b69e6": {
        "name": "Key Vault Secrets User",
        "actions": [],
        "dataActions": [
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        ],
    },
}
# Actions named `/action` that read: a secret's value or metadata, and the key a
# user-delegation SAS is signed with (such a SAS can do no more than its signer: read).
READ_ACTIONS = frozenset(
    {
        "Microsoft.KeyVault/vaults/secrets/getSecret/action",
        "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        # Azure Files over REST with the backup intent: reading a file past its ACL.
        "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
    }
)
# The one write role, on the job's own container only.
STATE_WRITER = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"  # Storage Blob Data Contributor
VAULT_READ_ROLE = "4633458b-17de-408a-b874-0445c86b69e6"
FILE_READ_ROLE = "b8eda974-7b85-4f76-af95-65846b26df6d"
COSMOS_DATA_READER = "00000000-0000-0000-0000-000000000001"
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(TEMPLATE.read_text())
    return data


def resources(template: dict[str, Any], path: str = "main") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every resource, nested deployments' included, with where it is."""
    items = template.get("resources", [])
    for r in items.values() if isinstance(items, dict) else items:
        yield path, r
        inner = (r.get("properties") or {}).get("template")
        if r.get("type") == "Microsoft.Resources/deployments" and isinstance(inner, dict):
            yield from resources(inner, f"{path}/{r.get('name')}")


def of_type(kind: str) -> list[tuple[str, dict[str, Any]]]:
    return [(p, r) for p, r in resources(load()) if r.get("type") == kind]


def bicep(name: str = "") -> str:
    """One Bicep file's text, or every file's."""
    if name:
        return (BICEP / name).read_text()
    return "\n".join(p.read_text() for p in sorted(BICEP.rglob("*.bicep")))


def is_read(action: str) -> bool:
    return action == "*/read" or action.endswith("/read") or action in READ_ACTIONS


def test_every_built_in_role_listed_reads() -> None:
    for role_id, role in BUILT_IN_ROLES.items():
        for action in [*role["actions"], *role["dataActions"]]:
            assert is_read(action), f"{role['name']}: {action}"
        assert _GUID.fullmatch(role_id)


def test_every_role_id_in_the_template_is_a_read_role_the_writer_or_cosmos_reader() -> None:
    allowed = {*BUILT_IN_ROLES, STATE_WRITER, COSMOS_DATA_READER}
    ids = set(_GUID.findall(bicep().lower()))
    assert ids and ids <= allowed, ids - allowed
    # The compiled template carries the same ids and no other role.
    compiled = set(_GUID.findall(TEMPLATE.read_text().lower()))
    assert ids <= compiled
    assert {g for g in compiled if g in allowed} == ids


def test_every_role_assignment_assigns_a_listed_role() -> None:
    """Each assignment's role is the loop over `roles` (the read roles, and Key Vault
    Secrets User only when asked) or, in the job module, the state writer."""
    found = 0
    for path in sorted(BICEP.rglob("*.bicep")):
        text = path.read_text()
        for m in re.finditer(r"roleDefinitionId: (.+)", text):
            found += 1
            expr = m[1]
            if path.name == "job.bicep":
                assert "blobDataContributor" in expr
            elif path.name == "cosmos-reader.bicep":
                assert "builtInDataReader" in expr
            else:
                assert re.search(r"'Microsoft\.Authorization/roleDefinitions', role\)$", expr), expr
    assert found == 4
    main = bicep("main.bicep")
    assert "for role in roles:" in main
    assert "roles: roles" in main  # the per-subscription module gets the same list
    assert "for role in roles:" in bicep("modules/read-roles.bicep")


def test_the_read_role_list_is_exactly_the_read_roles() -> None:
    text = (BICEP / "main.bicep").read_text()
    block = text.split("var readRoles = [", 1)[1].split("]", 1)[0]
    ids = _GUID.findall(block)
    assert ids and all(i in BUILT_IN_ROLES for i in ids)
    assert VAULT_READ_ROLE not in ids  # only with readKeyVaultSecrets
    assert FILE_READ_ROLE not in ids  # only with readFileShares
    assert "readKeyVaultSecrets ? [vaultReadRole] : []" in text
    assert "readFileShares ? [fileReadRole] : []" in text


def test_key_vault_secrets_user_only_when_asked() -> None:
    t = load()
    roles = t["variables"]["roles"]
    assert "readKeyVaultSecrets" in roles and "vaultReadRole" in roles
    assert t["parameters"]["readKeyVaultSecrets"]["defaultValue"] is False


def test_file_privileged_reader_only_when_asked() -> None:
    t = load()
    roles = t["variables"]["roles"]
    assert "readFileShares" in roles and "fileReadRole" in roles
    assert t["variables"]["fileReadRole"] == FILE_READ_ROLE
    assert t["parameters"]["readFileShares"]["defaultValue"] is False


def test_the_state_writer_is_on_the_jobs_own_container_only() -> None:
    assert STATE_WRITER not in bicep("main.bicep")
    job = bicep("modules/job.bicep")
    assert job.count(STATE_WRITER) == 1
    block = job.split("resource stateWriter", 1)[1].split("\n}\n", 1)[0]
    assert "scope: stateContainer" in block and "blobDataContributor" in block
    writers = [
        a
        for _, a in of_type("Microsoft.Authorization/roleAssignments")
        if "blobDataContributor" in json.dumps(a)
    ]
    assert writers and all("blobServices/containers" in str(a["scope"]) for a in writers)


def test_no_custom_role_no_keys_no_policy_writes() -> None:
    text = TEMPLATE.read_text()
    assert not of_type("Microsoft.Authorization/roleDefinitions")
    assert not of_type("Microsoft.Authorization/policyAssignments")
    for fn in ("listKeys", "listSecrets", "listConnectionStrings", "listAccountSas"):
        assert fn not in text, fn
    state = [r for _, r in of_type("Microsoft.Storage/storageAccounts")]
    assert state and all(r["properties"]["allowSharedKeyAccess"] is False for r in state)


def test_cosmos_gets_only_the_built_in_data_reader() -> None:
    assert of_type("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments")
    text = bicep("modules/cosmos-reader.bicep")
    assert f"builtInDataReader = '{COSMOS_DATA_READER}'" in text
    assert "sqlRoleDefinitions/${builtInDataReader}" in text


def test_the_job_runs_as_its_system_assigned_identity_with_no_secret_for_azure() -> None:
    jobs = of_type("Microsoft.App/jobs")
    assert jobs
    for _, j in jobs:
        assert j["identity"]["type"] == "SystemAssigned"
        config = j["properties"]["configuration"]
        assert config["triggerType"] == "Schedule"
        assert config["scheduleTriggerConfig"]["parallelism"] == 1
    text = TEMPLATE.read_text()
    assert "AZURE_CLIENT_SECRET" not in text and "connectionString" not in text


def test_every_environment_variable_is_one_the_code_reads() -> None:
    names = set(re.findall(r"name: '([A-Z][A-Z0-9_]+)'", bicep("modules/job.bicep")))
    code = CONFIG.read_text()
    assert names >= {"SCANNER_SITE", "STATE_CONTAINER_URL", "AZURE_MANAGEMENT_GROUP"}
    for name in names:
        assert f'"{name}"' in code, name


def test_the_blob_inventory_threshold_is_a_parameter_that_reaches_every_job() -> None:
    """AZURE_BLOB_INVENTORY_MIN_OBJECTS is set from `blobInventoryMinObjects` (the scanner's
    own default, 0 to never name a container), in central and per-subscription mode alike."""
    t = load()
    p = t["parameters"]["blobInventoryMinObjects"]
    assert p["type"] == "int"
    assert p["defaultValue"] == 1_000_000
    assert p["minValue"] == 0
    assert p["maxValue"] == 10_000_000_000
    jobs = [r for _, r in resources(t) if r.get("type") == "Microsoft.Resources/deployments"]
    passed = [
        j["properties"]["parameters"]["blobInventoryMinObjects"]["value"]
        for j in jobs
        if "jobName" in (j["properties"].get("parameters") or {})
    ]
    assert passed == ["[parameters('blobInventoryMinObjects')]"] * 2
    job = bicep("modules/job.bicep")
    assert "param blobInventoryMinObjects int = 1000000" in job
    assert re.search(
        r"name: 'AZURE_BLOB_INVENTORY_MIN_OBJECTS'\s+value: string\(blobInventoryMinObjects\)", job
    )
    assert "1_000_000, 0, 10_000_000_000" in CONFIG.read_text()


@pytest.mark.parametrize("module", sorted(p.name for p in (BICEP / "modules").glob("*.bicep")))
def test_every_module_is_in_the_compiled_template(module: str) -> None:
    assert module.removesuffix(".bicep") in (BICEP / "main.bicep").read_text()
