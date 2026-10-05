"""The SaaS scanner asks for read-only grants only: held here, strictly (#21 step 6).

- Every permission and scope the scanner requests (`sensitive_data_saas.scopes`)
  is on its vendor's list of scopes that only read, and reads by its own name.
- Every scope-like string in the package, docs/SAAS.md and the deploy examples
  is on those lists too: a scope cannot be added in one place and slip past
  the list.
- The package sends only GETs to the vendors, except the named token exchanges
  and the one opt-in write, Slack's `conversations.join` (#139); no PUT, PATCH or
  DELETE anywhere; Slack only its read methods, and that join.
- The two Slack manifests (`deploy/saas/slack/`): invite-only reads only, and
  auto-join is it plus `channels:join` and nothing else; docs/SAAS.md shows both.
- The deploy examples set no secret in the environment, only settings the
  code reads, and the ECS template's roles hold only the actions named here.
"""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path
from typing import Any

import yaml

from sensitive_data_saas import scopes

SCANNER = Path(__file__).resolve().parents[1]
REPO = SCANNER.parent
SAAS = SCANNER / "saas" / "src" / "sensitive_data_saas"
DOCS = REPO / "docs" / "SAAS.md"
DEPLOY = REPO / "deploy" / "saas"
MANIFESTS = DEPLOY / "slack"
INVITE_ONLY = MANIFESTS / "slack-manifest-invite-only.yaml"
AUTO_JOIN = MANIFESTS / "slack-manifest-auto-join.yaml"

# The read-only scopes each vendor may be asked for. Adding one here is the review.
ALLOWED: dict[str, frozenset[str]] = {
    "m365": frozenset(
        {
            "User.Read.All",
            "GroupMember.Read.All",
            "Mail.Read",
            "Files.Read.All",
            "Sites.Selected",
            "Sites.Read.All",
            "Team.ReadBasic.All",
            "Channel.ReadBasic.All",
            "ChannelMessage.Read.All",
            "Chat.Read.All",
            "SecurityAlert.Read.All",
        }
    ),
    "google_workspace": frozenset(
        {
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            "https://www.googleapis.com/auth/apps.alerts",
        }
    ),
    "google_signer": frozenset({"https://www.googleapis.com/auth/iam"}),
    "slack": frozenset(
        {
            "channels:read",
            "groups:read",
            "channels:history",
            "groups:history",
            "files:read",
            "discovery:read",
            "auditlogs:read",
        }
    ),
    "atlassian": frozenset(
        {
            "read:jira-work",
            "read:confluence-content.all",
            "read:confluence-space.summary",
            "readonly:content.attachment:confluence",
            "offline_access",
        }
    ),
}
# How each vendor names a scope that reads.
READS = {
    "m365": re.compile(r"^[A-Za-z]+\.(Read|ReadBasic)\.All$|^Mail\.Read$|^Sites\.Selected$"),
    "google_workspace": re.compile(r"^https://www\.googleapis\.com/auth/[a-z.]+\.readonly$"),
    "google_signer": re.compile(r"^https://www\.googleapis\.com/auth/iam$"),
    "slack": re.compile(r"^[a-z]+:(read|history)$"),
    "atlassian": re.compile(r"^(read|readonly):[a-z:.-]+$|^offline_access$"),
}
WRITES = re.compile(
    r"ReadWrite|Write|Manage|FullControl|Send|Create|Delete|\.modify|\.compose|\.send"
    r"|:write|write:|manage:|admin\.directory\.(user|group)$|chat:write|files:write",
    re.I,
)
# Strings shaped like each vendor's scopes, to find every one mentioned anywhere.
SHAPES = {
    "m365": re.compile(
        r"\b[A-Z][A-Za-z]+\.(?:Read|ReadWrite|ReadBasic|Selected|Write|Send|Manage|FullControl)(?:\.[A-Za-z]+)*\b"
    ),
    "google_workspace": re.compile(r"https://www\.googleapis\.com/auth/[a-z._-]+"),
    "slack": re.compile(
        r"\b(?:channels|groups|im|mpim|files|chat|users|discovery|admin|team):[a-z.]+\b"
    ),
    "atlassian": re.compile(r"\b(?:read|write|readonly|manage|delete):[a-z]+(?:[-.:][a-z]+)*\b"),
}
# Scopes allowed although their name does not say they only read, each with its reason.
NAMED_EXCEPTIONS = {
    "https://www.googleapis.com/auth/apps.alerts": (
        "the Alert Center has no read-only scope; the scanner only lists alerts, and the "
        "delegated administrator's role holds Alert Center View only, so Google refuses any "
        "change (docs/SAAS.md)"
    ),
}
# Scopes named only to say the scanner never holds them: `Sites.FullControl.All`, which the
# docs name as what the *admin's own* tool holds for the one-time `Sites.Selected` grant.
# Never requested, never in a manifest.
NAMED_NEVER = frozenset({"Sites.FullControl.All"})
# Scopes that write, each behind an opt-in setting, never requested (scopes.OPT_IN_WRITES).
OPT_IN_WRITES = {
    "channels:join": (
        "SLACK_JOIN_PUBLIC_CHANNELS (#139): join the public channels the bot is not in; only "
        "in the auto-join manifest, off by default, never set by Mermera"
    ),
}
# The only POSTs: the token exchanges, by function.
TOKEN_POSTS = {
    ("entra.py", "token"),
    ("google.py", "_caller"),
    ("google.py", "sign"),
    ("google.py", "token"),
    ("atlassian.py", "header"),
}
# The one other POST: Slack's opt-in join (#139), in the client's `join` only.
JOIN_POSTS = {("slack.py", "join")}
SLACK_METHODS = frozenset(
    {
        "auth.test",
        "conversations.list",
        "conversations.history",
        "conversations.replies",
        "files.list",  # a channel's files, for rescans (#67): `files:read`
        "discovery.conversations.list",
        "discovery.conversations.history",
    }
)
SECRET_ENVS = frozenset(
    {
        "M365_CLIENT_SECRET",
        "SLACK_TOKEN",
        "SLACK_BOT_TOKEN",
        "ATLASSIAN_API_TOKEN",
        "ATLASSIAN_OAUTH_CLIENT_SECRET",
        "FINDINGS_HMAC_KEY",
    }
)


def test_every_requested_scope_reads() -> None:
    assert set(scopes.REQUESTED) == set(ALLOWED)
    assert not NAMED_NEVER & set().union(*scopes.REQUESTED.values())
    # The opt-in writes are never requested, and are exactly the ones named here.
    assert scopes.OPT_IN_WRITES == {"slack": ("channels:join",)}
    assert set().union(*map(set, scopes.OPT_IN_WRITES.values())) == set(OPT_IN_WRITES)
    assert not set(OPT_IN_WRITES) & set().union(*scopes.REQUESTED.values())
    for vendor, requested in scopes.REQUESTED.items():
        for scope in requested:
            assert scope in ALLOWED[vendor], (vendor, scope)
            if scope in NAMED_EXCEPTIONS:
                continue
            assert READS[vendor].match(scope), (vendor, scope)
            assert not WRITES.search(scope), (vendor, scope)
    for vendor, allowed in ALLOWED.items():
        for scope in allowed:
            if scope in NAMED_EXCEPTIONS:
                continue
            assert READS[vendor].match(scope) and not WRITES.search(scope), (vendor, scope)
    # The one exception is requested only for the importer, as the administrator.
    assert tuple(NAMED_EXCEPTIONS) == scopes.GWS_ALERTS


def _texts() -> dict[str, str]:
    out = {p.name: p.read_text() for p in sorted(SAAS.rglob("*.py"))}
    out["SAAS.md"] = DOCS.read_text()
    out.update({f"deploy/{p.name}": p.read_text() for p in sorted(DEPLOY.glob("*.yaml"))})
    out.update({f"deploy/slack/{p.name}": p.read_text() for p in sorted(MANIFESTS.glob("*"))})
    return out


def test_every_scope_mentioned_anywhere_is_on_the_list() -> None:
    every = set().union(*ALLOWED.values())
    found = 0
    for name, text in _texts().items():
        for vendor, shape in SHAPES.items():
            for m in shape.finditer(text):
                scope = m[0]
                if vendor == "atlassian" and not scope.startswith(
                    ("read", "write", "manage", "delete")
                ):
                    continue
                found += 1
                if scope in NAMED_NEVER or scope in OPT_IN_WRITES:
                    continue
                assert scope in every or scope.rstrip(".") in every, f"{name}: {scope}"
    assert found > 20


def _bot_scopes(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text())
    bot: list[str] = doc["oauth_config"]["scopes"]["bot"]
    return bot


def test_the_invite_only_manifest_holds_only_read_scopes() -> None:
    bot = _bot_scopes(INVITE_ONLY)
    assert set(bot) <= ALLOWED["slack"] and "channels:join" not in bot
    assert set(bot) == set(scopes.SLACK_CHANNELS) | set(scopes.SLACK_FILES)


def test_the_two_manifests_differ_by_channels_join_only() -> None:
    """#139: auto-join is invite-only plus `channels:join`, and nothing else: the same
    document but for that one scope, and the same text but for that one line."""
    invite, auto = (yaml.safe_load(p.read_text()) for p in (INVITE_ONLY, AUTO_JOIN))
    assert _bot_scopes(AUTO_JOIN) == [*_bot_scopes(INVITE_ONLY), "channels:join"]
    auto["oauth_config"]["scopes"]["bot"].remove("channels:join")
    assert auto == invite
    a, b = INVITE_ONLY.read_text().splitlines(), AUTO_JOIN.read_text().splitlines()
    extra = [line for line in b if line not in a]
    assert extra == ["      - channels:join"] and [x for x in b if x != extra[0]] == a
    assert sorted(p.name for p in MANIFESTS.iterdir()) == [AUTO_JOIN.name, INVITE_ONLY.name]


def test_saas_md_shows_both_manifests_word_for_word() -> None:
    text = DOCS.read_text()
    blocks = [
        textwrap.dedent(m[1])
        for m in re.finditer(
            r"```yaml\n((?:[ ]*display_information:.*?\n)(?:.*?\n)*?)[ ]*```", text
        )
    ]
    assert blocks == [INVITE_ONLY.read_text(), AUTO_JOIN.read_text()]
    # The table names both files, and the setting.
    table = text[text.index("### Choose your manifest") :]
    for needle in (
        "deploy/saas/slack/slack-manifest-invite-only.yaml",
        "deploy/saas/slack/slack-manifest-auto-join.yaml",
        "SLACK_JOIN_PUBLIC_CHANNELS",
    ):
        assert needle in table, needle


def _calls() -> list[tuple[str, str, ast.Call]]:
    out = []
    for path in sorted(SAAS.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call):
                        out.append((path.name, fn.name, node))
    return out


def test_only_gets_go_to_the_vendors_but_the_token_exchanges() -> None:
    posts = set()
    for file, fn, call in _calls():
        if ast.unparse(call.func).endswith(("http.call", "_session.request")) or (
            isinstance(call.func, ast.Attribute) and call.func.attr == "call"
        ):
            first = call.args[0] if call.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                method = first.value
                assert method in ("GET", "POST"), f"{file}:{fn} {method}"
                if method == "POST":
                    posts.add((file, fn))
    assert posts == TOKEN_POSTS | JOIN_POSTS
    for path in sorted(SAAS.rglob("*.py")):
        text = path.read_text()
        for verb in ('"PUT"', '"PATCH"', '"DELETE"'):
            assert verb not in text, f"{path.name}: {verb}"


def test_slack_is_asked_only_its_read_methods() -> None:
    names = set()
    for file, _, call in _calls():
        if file not in ("slack.py",):
            continue
        func = ast.unparse(call.func)
        if func.endswith(("api.get", "api.pages", "slack.get", "slack.pages")) and call.args:
            first = call.args[0]
            if isinstance(first, ast.Constant):
                names.add(first.value)
    assert names and names <= SLACK_METHODS, names - SLACK_METHODS


def test_the_one_slack_write_is_the_opt_in_join() -> None:
    """#139: `conversations.join` is named only in the client's `join`; the only call of it
    is the adapter's `Joiner.join`, and a `Joiner` is made only with the setting on."""
    named = [(file, fn) for file, fn, call in _calls() if "conversations.join" in ast.unparse(call)]
    assert named == [("slack.py", "join")], named
    joins = [(file, fn) for file, fn, call in _calls() if ast.unparse(call.func) == "self.api.join"]
    assert joins == [("slack.py", "join")], joins
    source = (SAAS / "sources" / "slack.py").read_text()
    made = [line.strip() for line in source.splitlines() if "Joiner(ctx)" in line]
    assert made == ["joiner = Joiner(ctx) if sl.join_public and bot else None"], made


def _read_names() -> str:
    return "\n".join(p.read_text() for p in sorted(SAAS.rglob("*.py")))


def _envs(doc: Any) -> dict[str, str]:
    """Every NAME=value an example sets on the scanner's container."""
    out: dict[str, str] = {}

    def visit(v: Any) -> None:
        if isinstance(v, dict):
            name = v.get("name") or v.get("Name")
            if (
                isinstance(name, str)
                and re.fullmatch(r"[A-Z][A-Z0-9_]+", name)
                and ("value" in v or "Value" in v)
            ):
                out[name] = str(v.get("value", v.get("Value")))
            if isinstance(v.get("data"), dict) and v.get("kind") == "ConfigMap":
                out.update({str(k): str(x) for k, x in v["data"].items()})
            for x in v.values():
                visit(x)
        elif isinstance(v, list):
            for x in v:
                visit(x)

    visit(doc)
    return out


class _Cfn(yaml.SafeLoader):
    pass


def _tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)  # type: ignore[arg-type]


_Cfn.add_multi_constructor("!", _tag)


def _load(path: Path) -> list[Any]:
    return [d for d in yaml.load_all(path.read_text(), Loader=_Cfn) if d is not None]


def test_the_deploy_examples_set_no_secret_and_only_settings_the_code_reads() -> None:
    code = _read_names()
    examples = sorted(DEPLOY.glob("*.yaml"))
    assert {p.name for p in examples} == {
        "ecs.yaml",
        "kubernetes.yaml",
        "azure-container-apps.yaml",
        "cloud-run.yaml",
    }
    for path in examples:
        envs: dict[str, str] = {}
        for doc in _load(path):
            envs.update(_envs(doc))
        envs.pop("SDS_SECRETS", None)  # the ECS example's secret fetcher, not the scanner
        assert envs, path.name
        for name in envs:
            assert name not in SECRET_ENVS, f"{path.name}: {name}"
            assert f'"{name}"' in code, f"{path.name}: {name} is not read"
        assert any(n.endswith("_FILE") for n in envs), path.name
        text = path.read_text()
        assert "sensitive-data-scanner-saas@sha256:" in text, path.name


def test_the_ecs_template_holds_only_its_own_actions() -> None:
    (doc,) = _load(DEPLOY / "ecs.yaml")
    allowed = {
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "secretsmanager:GetSecretValue",
        "s3:GetObject",
        "s3:PutObject",
        "sts:GetWebIdentityToken",
        "ecs:RunTask",
        "iam:PassRole",
        "sts:AssumeRole",
    }
    actions: list[str] = []
    for res in doc["Resources"].values():
        if res["Type"] != "AWS::IAM::Role":
            continue
        assert "ManagedPolicyArns" not in res["Properties"]
        statements = [
            s
            for p in res["Properties"].get("Policies", [])
            for s in p["PolicyDocument"]["Statement"]
        ]
        statements += res["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        for st in statements:
            assert st["Effect"] == "Allow"
            got = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            actions.extend(got)
            for a in got:
                assert "*" not in a, a
                if a not in {"sts:GetWebIdentityToken", "sts:AssumeRole"}:
                    assert st.get("Resource") != "*", a
    assert set(actions) <= allowed, set(actions) - allowed


def test_every_deploy_example_wires_the_slack_tokens_as_files() -> None:
    """#123: each example gives the scanner its Slack tokens from the customer's own
    secret store, as files; ECS only when a secret is given, reading only it."""
    paths = {
        "ecs.yaml": "/run/secrets/sds/slack-token",
        "kubernetes.yaml": "/run/secrets/sds/slack-token",
        "azure-container-apps.yaml": "/run/secrets/sds/slack-token",
        "cloud-run.yaml": "/run/secrets/slack/slack-token",
    }
    for name, path in paths.items():
        envs: dict[str, str] = {}
        for doc in _load(DEPLOY / name):
            envs.update(_envs(doc))
        assert "SLACK_TOKEN_FILE" in envs, name
        assert path in (DEPLOY / name).read_text(), name
        for refused in ("SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_AUDIT_TOKEN"):
            assert refused not in envs, f"{name}: {refused}"

    (doc,) = _load(DEPLOY / "ecs.yaml")
    params = doc["Parameters"]
    for p in ("SlackTokenSecretArn", "SlackAuditTokenSecretArn"):
        assert params[p]["Default"] == "", p
    scanner, fetcher = (
        next(
            c
            for c in doc["Resources"]["TaskDefinition"]["Properties"]["ContainerDefinitions"]
            if c["Name"] == n
        )
        for n in ("scanner", "secrets")
    )
    env = {e["Name"]: e["Value"] for e in scanner["Environment"]}
    assert env["SLACK_TOKEN_FILE"] == ["HasSlackToken", "/run/secrets/sds/slack-token", ""]
    assert env["SLACK_AUDIT_TOKEN_FILE"] == [
        "HasSlackAuditToken",
        "/run/secrets/sds/slack-audit-token",
        "",
    ]
    fetch = str(fetcher["Environment"])
    assert "slack-token=${SlackTokenSecretArn}" in fetch
    assert "slack-audit-token=${SlackAuditTokenSecretArn}" in fetch
    statements = doc["Resources"]["TaskRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"
    ]
    (read,) = (s for s in statements if s["Sid"] == "ReadOwnSecrets")
    assert read["Resource"] == [
        "PushKeySecretArn",
        ["HasSlackToken", "SlackTokenSecretArn", "AWS::NoValue"],
        ["HasSlackAuditToken", "SlackAuditTokenSecretArn", "AWS::NoValue"],
    ]
