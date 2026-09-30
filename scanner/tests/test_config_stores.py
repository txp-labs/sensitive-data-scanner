"""SSM Parameter Store and Secrets Manager: values read for sensitive data, never reported.

Every AWS answer comes from botocore's Stubber; every value is made up.
"""

from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.stub import Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import Env, config
from conftest import REPO
from sensitive_data_scanner.config import read_config, store_rules
from synthetic import CARDS, SSN_A, SSN_B, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    # Every finding the runner writes says what storage encryption it sat under (1.5).
    assert all("atRestEncryption" in f for f in doc["findings"])


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["kind"]: s for s in doc["discovery"]["stores"]}


def stubs(env: Env, *services: str) -> dict[str, Stubber]:
    out = {}
    for s in services:
        c: Any = boto3.client(
            s,  # type: ignore[call-overload]
            region_name="us-west-2",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
        )
        stub = Stubber(c)
        stub.activate()
        env.clients.services[s] = c
        out[s] = stub
    return out


PARAMS = {
    "/app/db-host": ("String", "db.internal"),
    "/app/owner-ssn": ("String", f"ssn {dashed(SSN_A)}"),
    "/app/payment": ("SecureString", json.dumps({"card_number": CARDS["visa"]})),
    "/app/regions": ("StringList", "us-west-2,us-east-1"),
    "/prod/secret-key": ("SecureString", f"card {CARDS['jcb']}"),
    "/sensitive-data-scanner/config": ("String", "{}"),
}


def ssm_estate(ssm: Stubber, params: dict[str, tuple[str, str]] = PARAMS) -> None:
    ssm.add_response(
        "describe_parameters",
        {"Parameters": [{"Name": n, "Type": t} for n, (t, _) in params.items()]},
    )


def get(ssm: Stubber, names: list[str], *, decrypt: bool = True, params: Any = PARAMS) -> None:
    ssm.add_response(
        "get_parameters",
        {
            "Parameters": [{"Name": n, "Type": params[n][0], "Value": params[n][1]} for n in names],
        },
        {"Names": names, "WithDecryption": decrypt},
    )


def test_parameters_are_read_decrypted_and_named(env: Env) -> None:
    s = stubs(env, "ssm")
    ssm_estate(s["ssm"])
    get(s["ssm"], ["/app/db-host", "/app/owner-ssn", "/app/payment", "/app/regions"])
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"ssm"}), deny=store_rules("ssm:/prod/*"))
    )
    assert doc is not None
    valid(doc)
    s["ssm"].assert_no_pending_responses()
    found = {(f["resource"]["store"], f["class"]) for f in doc["findings"]}
    assert found == {("/app/owner-ssn", "us_ssn"), ("/app/payment", "card")}
    f = next(f for f in doc["findings"] if f["class"] == "card")
    assert f["resource"] == {
        "type": "store_field",
        "service": "ssm",
        "store": "/app/payment",
        "field": "value",
        "readBy": "get_parameters",
    }
    assert f["offsets"] == []
    st = stores(doc)["ssm"]
    assert (st["name"], st["status"], st["items"], st["excluded"]) == (
        "parameter-store",
        "scanned",
        6,
        {"denied": 1, "self": 1},  # its own configuration is never read as data
    )
    assert st["itemTypes"] == {"SecureString": 2, "String": 3, "StringList": 1}
    assert "names" not in st


def test_parameter_store_says_its_at_rest_encryption(env: Env) -> None:
    """#94: the real run had no `atRestEncryption` on `parameter-store`. A SecureString is
    under its KMS key; a String or StringList is `none`, and so is the store that holds one."""
    s = stubs(env, "ssm")
    ssm_estate(s["ssm"])
    get(s["ssm"], ["/app/db-host", "/app/owner-ssn", "/app/payment", "/app/regions"])
    doc = env.run(
        config(s3_targets=[], discover=frozenset({"ssm"}), deny=store_rules("ssm:/prod/*"))
    )
    assert doc is not None
    valid(doc)
    at_rest = {f["resource"]["store"]: f["atRestEncryption"] for f in doc["findings"]}
    assert at_rest == {"/app/owner-ssn": "none", "/app/payment": "service_managed"}
    assert stores(doc)["ssm"]["atRestEncryption"] == "none"


def test_a_parameter_store_of_secure_strings_only_is_under_kms(env: Env) -> None:
    secure = {k: v for k, v in PARAMS.items() if v[0] == "SecureString"}
    s = stubs(env, "ssm")
    ssm_estate(s["ssm"], secure)
    get(s["ssm"], sorted(secure), params=secure)
    doc = env.run(config(s3_targets=[], discover=frozenset({"ssm"})))
    assert doc is not None
    valid(doc)
    st = stores(doc)["ssm"]
    assert st["atRestEncryption"] == "service_managed"  # alias/aws/ssm, the default
    assert "atRestKeyHash" not in st


def test_without_decrypt_secure_strings_are_counted_not_read(env: Env) -> None:
    s = stubs(env, "ssm")
    ssm_estate(s["ssm"])
    get(s["ssm"], ["/app/db-host", "/app/owner-ssn", "/app/regions"], decrypt=False)
    doc = env.run(config(s3_targets=[], discover=frozenset({"ssm"}), ssm_decrypt=False))
    assert doc is not None
    s["ssm"].assert_no_pending_responses()
    assert stores(doc)["ssm"]["excluded"] == {"secure_string": 2, "self": 1}
    assert read_config({"RESULTS_BUCKET": "x"}).ssm_decrypt is True
    assert read_config({"RESULTS_BUCKET": "x", "SSM_DECRYPT": "false"}).ssm_decrypt is False


def test_parameters_go_ten_at_a_time_and_resume(env: Env) -> None:
    s = stubs(env, "ssm")
    many = {f"/p/{i:02d}": ("String", f"value {i}") for i in range(12)}
    many["/p/11"] = ("String", f"ssn {dashed(SSN_B)}")
    names = sorted(many)
    cfg = config(s3_targets=[], discover=frozenset({"ssm"}), max_items_per_run=1)
    ssm_estate(s["ssm"], many)
    get(s["ssm"], names[:10], params=many)
    first = env.run(cfg)
    assert first is not None
    s["ssm"].assert_no_pending_responses()
    assert first["coverage"][0]["backlog"] is True
    ssm_estate(s["ssm"], many)
    get(s["ssm"], names[10:], params=many)
    second = env.run(cfg)
    assert second is not None
    s["ssm"].assert_no_pending_responses()
    assert [f["resource"]["store"] for f in second["findings"]] == ["/p/11"]
    assert second["coverage"][0]["passComplete"] is True


def secrets_estate(sm: Stubber) -> None:
    sm.add_response(
        "list_secrets",
        {
            "SecretList": [
                {"Name": "app/customer", "Tags": [{"Key": "team", "Value": "pay"}]},
                {"Name": "app/cert", "Tags": []},
                {"Name": "rds!cluster-abc", "OwningService": "rds"},
                {"Name": "locked", "Tags": []},
            ]
        },
    )


def test_secrets_are_listed_always_and_read_only_when_on(env: Env) -> None:
    s = stubs(env, "secretsmanager")
    sm = s["secretsmanager"]
    secrets_estate(sm)
    off = env.run(config(s3_targets=[], discover=frozenset({"secretsmanager"})))
    assert off is not None
    valid(off)
    sm.assert_no_pending_responses()
    st = stores(off)["secretsmanager"]
    assert (st["name"], st["reason"], st["items"], st["itemTypes"]) == (
        "secrets-manager",
        "read_not_configured",
        4,
        {"managed": 1, "own": 3},
    )
    secrets_estate(sm)
    sm.add_response("get_secret_value", {"Name": "app/cert", "SecretBinary": b"\xff\xfe\x00"})
    sm.add_response(
        "get_secret_value",
        {"Name": "app/customer", "SecretString": json.dumps({"ssn": dashed(SSN_B), "pw": "x"})},
        {"SecretId": "app/customer"},
    )
    sm.add_client_error(
        "get_secret_value", service_error_code="AccessDeniedException", http_status_code=400
    )
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"secretsmanager"}),
            secrets_read=True,
            deny=store_rules("secretsmanager:rds!*"),
        )
    )
    assert doc is not None
    valid(doc)
    sm.assert_no_pending_responses()
    [f] = doc["findings"]
    assert (f["resource"]["service"], f["resource"]["store"], f["class"]) == (
        "secretsmanager",
        "app/customer",
        "us_ssn",
    )
    cov = doc["coverage"][0]
    assert (cov["scanned"], cov["unreadable"], cov["passComplete"]) == (1, 2, True)
    assert stores(doc)["secretsmanager"]["excluded"] == {"denied": 1}
    assert read_config({"RESULTS_BUCKET": "x"}).secrets_read is False
