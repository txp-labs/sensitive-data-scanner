"""A stubbed DynamoDB client (botocore Stubber) and the Stugum-shaped item fixtures.

The fixtures under fixtures/dynamodb/ are synthetic: made-up values in the
shape of a call-test result item. The positive control holds the keypad
entries in clear; the negative control holds `[REDACTED:…]` labels instead.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import boto3
from botocore.stub import ANY, Stubber

from sensitive_data_scanner.config import DynamoTarget

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dynamodb"
TABLE = "example-call-tests"
PARTITION = "T#t_0000example"


def load_item(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text())
    return copy.deepcopy(data["Item"])


def target(**kw: Any) -> DynamoTarget:
    base: dict[str, Any] = {
        "table": TABLE,
        "partition": PARTITION,
        "sort_prefix": "R#",
        "include": ("stepResults[].observedDtmf", "stepResults[].heard", "steps"),
        "keypad": ("stepResults[].observedDtmf", "steps[].digits"),
        "prompts": ("stepResults[].heard", "steps[].text"),
        "planted": ("steps",),
    }
    base.update(kw)
    return DynamoTarget(**base)


def describe(table: str = TABLE, *, sort_key: bool = True) -> dict[str, Any]:
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    if sort_key:
        attrs.append({"AttributeName": "sk", "AttributeType": "S"})
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
    return {"Table": {"TableName": table, "AttributeDefinitions": attrs, "KeySchema": keys}}


def key_of(item: dict[str, Any]) -> dict[str, Any]:
    return {k: item[k] for k in ("pk", "sk") if k in item}


def page(items: list[dict[str, Any]], last: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"Items": items, "Count": len(items), "ScannedCount": len(items)}
    if last:
        out["LastEvaluatedKey"] = last
    return out


class Ddb:
    """A real boto3 DynamoDB client whose every call is answered by a Stubber."""

    def __init__(self, region: str = "us-west-2") -> None:
        self.client = boto3.client(
            "dynamodb",
            region_name=region,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
        )
        self.stub = Stubber(self.client)
        self.stub.activate()

    def describe(self, **kw: Any) -> None:
        self.stub.add_response("describe_table", describe(**kw), {"TableName": ANY})

    def query(self, response: dict[str, Any], expected: dict[str, Any] | None = None) -> None:
        self.stub.add_response("query", response, expected)

    def scan(self, response: dict[str, Any], expected: dict[str, Any] | None = None) -> None:
        self.stub.add_response("scan", response, expected)

    def error(self, op: str, code: str) -> None:
        self.stub.add_client_error(op, service_error_code=code, http_status_code=400)
