"""The Google Cloud deployment (deploy/gcp, Terraform) grants reads only.

The strict test, as test_azure_template.py is for Bicep: every permission in
the scanner's custom roles reads (by its verb), or is one of the few named
exceptions below, each with its reason; the opt-in permissions sit in their
own roles, made only when their variable is on (off by default). No
predefined role is bound except three, each on the job's own resource only:
Storage Object User on its state bucket, Secret Accessor on its two push
secrets, and Run Invoker on the job for the scheduler's own account. Nothing
is bound authoritatively (`_iam_binding`, `_iam_policy`), and no service
account key is made. CI also runs `terraform validate` and `terraform test`
(offline, a mock provider) with a pinned, checksum-verified Terraform.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy" / "gcp"
CONFIG = REPO / "scanner" / "gcp" / "src" / "sensitive_data_gcp" / "config.py"

# A permission reads when its verb (the last part) is one of these.
READ_VERBS = frozenset(
    {
        "get",
        "list",
        "getData",
        "getMetadata",
        "searchAllResources",
        "readRows",
        "select",
        "beginReadOnlyTransaction",
    }
)
# Verbs allowed only in an opt-in role: a secret's value (counts only), a database login.
OPT_IN_VERBS = frozenset({"access", "login"})
# Permissions that are not a read by their verb, and why each is allowed.
EXCEPTIONS = {
    "spanner.sessions.create": "a session holds no data; each statement in it is a single-use "
    "read-only transaction",
    "spanner.sessions.delete": "the scanner's own session, deleted after its pass",
    "alloydb.clusters.generateClientCertificate": "returns the cluster's CA, which TLS is "
    "verified against, with a short-lived client certificate; changes nothing on the cluster",
    "serviceusage.services.use": "lets the service account's calls count against a project's "
    "quota, which AlloyDB's IAM login needs",
}
OPT_IN_ROLES = {
    "private_log_permissions": ("read_private_logs", {"logging.privateLogEntries.list"}),
    "secret_permissions": (
        "read_secrets",
        {"secretmanager.secrets.get", "secretmanager.versions.access"},
    ),
    "database_permissions": ("read_databases", {"cloudsql.instances.login"}),
}
# (#105, docs/limitations.md) Roles made by default, each under its own variable, holding the
# named exceptions: off, the role (and its exceptions) is not made.
DEFAULT_ON_ROLES = {
    "spanner_permissions": (
        "read_spanner",
        {
            "spanner.databases.beginReadOnlyTransaction",
            "spanner.databases.select",
            "spanner.sessions.create",
            "spanner.sessions.delete",
        },
    ),
    "alloydb_permissions": (
        "read_alloydb",
        {
            "alloydb.clusters.generateClientCertificate",
            "alloydb.users.login",
            "serviceusage.services.use",
        },
    ),
}
# The only predefined roles bound, each on the job's own resource.
OWN_RESOURCE_ROLES = {
    "roles/storage.objectUser": ("google_storage_bucket_iam_member", "state"),
    "roles/secretmanager.secretAccessor": ("google_secret_manager_secret_iam_member", "push"),
    "roles/run.invoker": ("google_cloud_run_v2_job_iam_member", "scheduler"),
}
_PERMISSION = re.compile(r"^[a-z]+\.[a-zA-Z]+\.[a-zA-Z]+$")


def unquote(v: Any) -> Any:
    """python-hcl2 keeps a string's quotes: drop them, and from keys, all the way down."""
    if isinstance(v, str):
        return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
    if isinstance(v, list):
        return [unquote(x) for x in v]
    if isinstance(v, dict):
        return {unquote(k): unquote(x) for k, x in v.items() if k != "__comments__"}
    return v


def load() -> dict[str, Any]:
    """Every .tf file: `resource` as {type: {name: body}}, `locals` and `variable` merged."""
    out: dict[str, Any] = {"resource": {}, "locals": {}, "variable": {}}
    for path in sorted(DEPLOY.glob("*.tf")):
        with path.open() as f:
            data = unquote(hcl2.load(f))
        for block in data.get("resource") or []:
            for kind, named in block.items():
                out["resource"].setdefault(kind, {}).update(named)
        for block in data.get("locals") or []:
            out["locals"].update(block)
        for block in data.get("variable") or []:
            out["variable"].update(block)
    return out


def text() -> str:
    return "\n".join(p.read_text() for p in sorted(DEPLOY.glob("*.tf")))


def verb(permission: str) -> str:
    return permission.rsplit(".", 1)[-1]


def test_every_default_permission_reads() -> None:
    perms = load()["locals"]["read_permissions"]
    assert perms and len(perms) == len(set(perms))
    for p in perms:
        assert _PERMISSION.match(p), p
        assert verb(p) in READ_VERBS or p in EXCEPTIONS, p
        assert verb(p) not in OPT_IN_VERBS, p
    # No permission that creates, changes, exports or grants.
    joined = " ".join(perms).lower()
    for word in ("create", "update", "delete", "set", "export", "insert", "patch", "admin"):
        assert all(word not in verb(p).lower() or p in EXCEPTIONS for p in perms), word
    assert "setiampolicy" not in joined and "actas" not in joined


def test_opt_in_permissions_sit_in_their_own_roles_off_by_default() -> None:
    t = load()
    source = (DEPLOY / "main.tf").read_text()
    for local, (variable, expected) in OPT_IN_ROLES.items():
        perms = set(t["locals"][local])
        assert perms == expected, local
        for p in perms:
            assert verb(p) in READ_VERBS | OPT_IN_VERBS or p in EXCEPTIONS, p
            assert p not in t["locals"]["read_permissions"], p
        assert t["variable"][variable]["default"] is False
        # The role is in local.roles only when its variable is on.
        assert re.search(rf"var\.{variable} \? \{{ \w+ = \{{[^}}]*local\.{local}", source), local
    # Secret access and database logins are never in the default role.
    assert not any(verb(p) in OPT_IN_VERBS for p in t["locals"]["read_permissions"])


def test_every_named_exception_sits_in_a_role_its_toggle_can_turn_off() -> None:
    """#105 (C2): the exceptions are Spanner's (GCP_SPANNER) and AlloyDB's (GCP_ALLOYDB), each in
    a role of its own that is made only with its variable on (the default), never the read role."""
    t = load()
    source = (DEPLOY / "main.tf").read_text()
    held: set[str] = set()
    for local, (variable, expected) in DEFAULT_ON_ROLES.items():
        perms = set(t["locals"][local])
        assert perms == expected, local
        held |= perms
        assert not perms & set(t["locals"]["read_permissions"]), local
        assert t["variable"][variable]["default"] is True
        assert re.search(rf"var\.{variable} \? \{{ \w+ = \{{[^}}]*local\.{local}", source), local
    assert set(EXCEPTIONS) <= held
    env = {
        "GCP_SPANNER": "read_spanner",
        "GCP_ALLOYDB": "read_alloydb",
        "GCS_READ_ARCHIVE": "read_archive_objects",
        "GCP_SQLSERVER": "read_sqlserver",
        "GCP_READ_PUBSUB_DLQ": "read_pubsub_dead_letters",
    }
    for name, variable in env.items():
        assert re.search(rf"{name}\s+= var\.{variable} \? \"on\" : \"off\"", source), name


def test_sdp_profiles_are_listed_only_in_vendor_or_both() -> None:
    """#55: Sensitive Data Protection's data profiles, listed (never its inspection results,
    which can quote matched text), by a role made only when scan_mode is not scanner."""
    t = load()
    perms = set(t["locals"]["sdp_permissions"])
    assert perms == {"dlp.columnDataProfiles.list", "dlp.fileStoreProfiles.list"}
    assert all(verb(p) == "list" for p in perms)
    assert not perms & set(t["locals"]["read_permissions"])
    assert t["variable"]["scan_mode"]["default"] == "scanner"
    source = (DEPLOY / "main.tf").read_text()
    assert re.search(
        r'var\.scan_mode != "scanner" \? \{ sdp = \{[^}]*local\.sdp_permissions', source
    )
    assert "dlp.jobs" not in source and "inspectFindings" not in source


def test_custom_roles_are_the_read_roles_and_only_they_are_bound_at_the_scope() -> None:
    r = load()["resource"]
    roles = r["google_organization_iam_custom_role"]
    assert list(roles) == ["scanner"]
    assert roles["scanner"]["for_each"] == "${local.roles}"
    assert roles["scanner"]["permissions"] == "${each.value.permissions}"
    scanner = "serviceAccount:${google_service_account.scanner.email}"
    for kind in (
        "google_organization_iam_member",
        "google_folder_iam_member",
        "google_project_iam_member",
    ):
        (binding,) = r[kind].values()
        assert "google_organization_iam_custom_role.scanner[" in binding["role"], kind
        assert binding["member"] == scanner, kind


def test_the_only_predefined_roles_are_on_the_jobs_own_resources() -> None:
    r = load()["resource"]
    found = set(re.findall(r"roles/[A-Za-z.]+", text()))
    assert found == set(OWN_RESOURCE_ROLES), found
    for role, (kind, name) in OWN_RESOURCE_ROLES.items():
        assert list(r[kind]) == [name], kind
        body = r[kind][name]
        assert body["role"] == role
    assert r["google_storage_bucket_iam_member"]["state"]["bucket"] == (
        "${google_storage_bucket.state.name}"
    )
    assert r["google_secret_manager_secret_iam_member"]["push"]["for_each"] == (
        "${google_secret_manager_secret.push}"
    )
    invoker = r["google_cloud_run_v2_job_iam_member"]["scheduler"]
    assert invoker["name"] == "${google_cloud_run_v2_job.scanner.name}"
    assert invoker["member"] == "serviceAccount:${google_service_account.scheduler.email}"


def test_nothing_authoritative_no_keys_no_basic_roles() -> None:
    r = load()["resource"]
    for kind in r:
        assert not kind.endswith(("_iam_binding", "_iam_policy")), kind
        assert kind != "google_service_account_key", kind
    for basic in ("roles/owner", "roles/editor", "roles/viewer", "roles/iam."):
        assert basic not in text(), basic
    iam = [k for k in r if k.endswith("_iam_member")]
    assert sorted(iam) == [
        "google_cloud_run_v2_job_iam_member",
        "google_folder_iam_member",
        "google_organization_iam_member",
        "google_project_iam_member",
        "google_secret_manager_secret_iam_member",
        "google_storage_bucket_iam_member",
    ]


def test_the_state_bucket_is_private() -> None:
    bucket = load()["resource"]["google_storage_bucket"]["state"]
    assert bucket["uniform_bucket_level_access"] is True
    assert bucket["public_access_prevention"] == "enforced"
    assert bucket["force_destroy"] is False


def test_the_job_runs_as_the_scanner_account_and_every_setting_it_sets_is_read() -> None:
    t = load()
    job = t["resource"]["google_cloud_run_v2_job"]["scanner"]
    inner = job["template"][0]["template"][0]
    assert inner["service_account"] == "${google_service_account.scanner.email}"
    assert inner["max_retries"] == 0
    source = (DEPLOY / "main.tf").read_text()
    names = set(re.findall(r"^\s+([A-Z][A-Z0-9_]+)\s+=", source, re.M))
    names |= {"GCP_ORGANIZATION", "GCP_FOLDERS", "GCP_PROJECTS"}
    names |= set(re.findall(r'"(FINDINGS_[A-Z_]+)"', source))
    assert {"SCANNER_SITE", "STATE_BUCKET", "FINDINGS_HTTPS_URL", "FINDINGS_HMAC_KEY"} <= names
    config = CONFIG.read_text()
    for name in names:
        assert f'"{name}"' in config, name
    image = t["variable"]["image"]
    assert "@sha256:" in str(image["validation"])


def test_the_gcs_inventory_threshold_is_a_variable_that_reaches_the_job() -> None:
    """GCS_INVENTORY_MIN_OBJECTS is set from `gcs_inventory_min_objects`: the scanner's own
    default and bounds, 0 to never name a bucket (`terraform test` plans both)."""
    t = load()
    v = t["variable"]["gcs_inventory_min_objects"]
    assert v["type"] == "number"
    assert v["default"] == 1_000_000
    assert "10000000000" in str(v["validation"])
    source = (DEPLOY / "main.tf").read_text()
    assert re.search(
        r"^\s+GCS_INVENTORY_MIN_OBJECTS\s+= tostring\(var\.gcs_inventory_min_objects\)$",
        source,
        re.M,
    )
    assert "1_000_000, 0, 10_000_000_000" in CONFIG.read_text()


def test_the_scheduler_account_can_only_start_the_job() -> None:
    r = load()["resource"]
    uses = [
        (kind, name)
        for kind, named in r.items()
        for name, body in named.items()
        if "google_service_account.scheduler" in str(body)
    ]
    assert sorted(uses) == [
        ("google_cloud_run_v2_job_iam_member", "scheduler"),
        ("google_cloud_scheduler_job", "scanner"),
    ]


# Google Cloud's limits on a custom role: 3,000 permissions, and 64 KB for its title,
# description and permission names together; 300 custom roles in an organization.
ROLE_PERMISSIONS = 3_000
ROLE_BYTES = 64_000
ORG_ROLES = 300


def test_every_custom_role_fits_googles_limits_with_every_opt_in_on() -> None:
    """The worst case: every opt-in variable on, so every role in local.roles is made."""
    t = load()
    source = (DEPLOY / "main.tf").read_text()
    made = re.findall(
        r'\{ \w+ = \{ id = "(\w+)", title = "([^"]+)", permissions = local\.(\w+) \}', source
    )
    # read, the opt-ins, SDP profiles, and the roles made by default (#105)
    assert len(made) == 1 + len(OPT_IN_ROLES) + 1 + len(DEFAULT_ON_ROLES)
    (role,) = load()["resource"]["google_organization_iam_custom_role"].values()
    description = str(role["description"])
    for role_id, title, local in made:
        perms = t["locals"][local]
        assert len(perms) <= ROLE_PERMISSIONS, role_id
        size = len(title.encode()) + len(description.encode()) + sum(len(p.encode()) for p in perms)
        assert size <= ROLE_BYTES, f"{role_id}: {size} bytes"
    assert len(made) <= ORG_ROLES
