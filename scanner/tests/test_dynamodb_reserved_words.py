"""DynamoDB reserved words in the expressions the scanner builds (#94, item 7).

DynamoDB refuses an expression that names a reserved word bare (`status`, `name`, `data`,
`plan`, `trigger` and about 570 more):
`ValidationException: ... Attribute name is a reserved keyword`. A stubbed client accepts
any expression, so the bug shows only against the real service (Stugum found it on its
deployed dev, crmarr/templates `dynamodb-reserved-words.md`).

The scanner builds its Projection, KeyCondition and Filter expressions from names the
customer configures (`SCAN_DYNAMODB` paths) and from the table's key names. Every name
goes through an `ExpressionAttributeNames` placeholder. These tests hold that:

- against moto's DynamoDB, which parses expressions and refuses a bare reserved word as
  the service does (the negative control shows it), with reserved-word attribute and key
  names in every shape of read: a Query with a sort-key prefix, a filtered Scan, a sampled
  Scan and a projection;
- and by reading the source: every literal part of an expression the scanner writes names
  attributes only as `#placeholders`.
"""

from __future__ import annotations

import ast
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from aws_fixtures import NOW, shared_detector
from conftest import REPO
from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_scanner.config import dynamodb_targets
from sensitive_data_scanner.sources.dynamodb import DynamoDBSource
from synthetic import SSN_A, dashed

REGION = "us-west-2"
TABLE = "reserved-words-table"
# Every one a DynamoDB reserved word, used as a key, a top-level attribute, or a leaf.
HASH, RANGE = "name", "data"
EXPRESSION_KEYS = (
    "ProjectionExpression",
    "KeyConditionExpression",
    "FilterExpression",
    "ConditionExpression",
    "UpdateExpression",
)


@pytest.fixture
def ddb(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    with mock_aws():
        client = boto3.client("dynamodb", region_name=REGION)
        client.create_table(
            TableName=TABLE,
            KeySchema=[
                {"AttributeName": HASH, "KeyType": "HASH"},
                {"AttributeName": RANGE, "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": HASH, "AttributeType": "S"},
                {"AttributeName": RANGE, "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        for i in range(3):
            client.put_item(
                TableName=TABLE,
                Item={
                    HASH: {"S": "tenant-a"},
                    RANGE: {"S": f"RUN#{i}"},
                    "status": {"S": "done"},
                    "plan": {"S": f"customer ssn {dashed(SSN_A)}"},
                    "trigger": {"S": "manual"},
                    "steps": {
                        "L": [
                            {"M": {"kind": {"S": "sendDtmf"}, "observedDtmf": {"S": "1234"}}},
                        ]
                    },
                    "comment": {"S": "not projected"},
                },
            )
        yield client


def read(client: Any, config: str) -> Any:
    (target,) = dynamodb_targets(config)
    src = DynamoDBSource(client, target=target, region=REGION, sleep=lambda s: None)
    store = FindingStore(NOW.isoformat())
    result = src.run({}, Budget(1000, 10**9, time.monotonic() + 60), shared_detector(), store, NOW)
    return result, store


INCLUDE = '["plan", "status", "trigger", "steps[].observedDtmf", "data", "name"]'


@pytest.mark.parametrize(
    ("shape", "config"),
    [
        (
            "query, sort-key prefix, projection",
            f'[{{"table": "{TABLE}", "partition": "tenant-a", "sortPrefix": "RUN#",'
            f' "include": {INCLUDE}, "orderBy": "status"}}]',
        ),
        (
            "scan filtered on the sort key, projection",
            f'[{{"table": "{TABLE}", "sortPrefix": "RUN#", "include": {INCLUDE}}}]',
        ),
        ("scan, projection", f'[{{"table": "{TABLE}", "include": {INCLUDE}}}]'),
        ("query, no projection", f'[{{"table": "{TABLE}", "partition": "tenant-a"}}]'),
    ],
)
def test_reserved_word_names_in_every_shape_of_read(ddb: Any, shape: str, config: str) -> None:
    result, store = read(ddb, config)
    assert result.coverage.error is None, shape
    assert result.coverage.scanned == 3, shape
    paths = {f["resource"]["attributePath"] for f in store.public()}
    assert "plan" in paths, shape


def test_a_sampled_scan_with_reserved_word_names(ddb: Any) -> None:
    (target,) = dynamodb_targets(f'[{{"table": "{TABLE}", "include": {INCLUDE}}}]')
    src = DynamoDBSource(ddb, target=target, region=REGION, sample_percent=50, sleep=lambda s: None)
    result = src.run(
        {},
        Budget(1000, 10**9, time.monotonic() + 60),
        shared_detector(),
        FindingStore(NOW.isoformat()),
        NOW,
    )
    assert result.coverage.error is None


def test_moto_refuses_a_bare_reserved_word_as_dynamodb_does(ddb: Any) -> None:
    """The negative control: this harness would catch a bare name."""
    for expression, names in (("plan, #s", {"#s": "status"}), ("#p, status", {"#p": "plan"})):
        with pytest.raises(ddb.exceptions.ClientError, match="reserved keyword"):
            ddb.scan(
                TableName=TABLE, ProjectionExpression=expression, ExpressionAttributeNames=names
            )


# ------------------------------------------------------------------ the source, statically

PLACEHOLDER_OK = {"AND", "OR", "NOT", "BETWEEN", "IN", "begins_with", "attribute_exists"}


def _expression_literals() -> Iterator[tuple[str, int, str]]:
    """Every literal string part assigned to an expression key, in every package's source."""
    roots = [REPO / "scanner" / p for p in ("src", "core/src", "db/src", "azure/src", "gcp/src")]
    roots.append(REPO / "scanner" / "saas" / "src")
    for root in roots:
        for path in sorted(Path(root).rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                value: ast.AST | None = None
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if (
                            isinstance(t, ast.Subscript)
                            and isinstance(t.slice, ast.Constant)
                            and t.slice.value in EXPRESSION_KEYS
                        ):
                            value = node.value
                elif isinstance(node, ast.keyword) and node.arg in EXPRESSION_KEYS:
                    value = node.value
                elif isinstance(node, ast.Dict):
                    for k, v in zip(node.keys, node.values, strict=True):
                        if isinstance(k, ast.Constant) and k.value in EXPRESSION_KEYS:
                            yield from _strings(path, v)
                if value is not None:
                    yield from _strings(path, value)


def _strings(path: Path, node: ast.AST) -> Iterator[tuple[str, int, str]]:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            yield str(path.relative_to(REPO)), sub.lineno, sub.value


def test_every_name_in_a_written_expression_is_a_placeholder() -> None:
    found = list(_expression_literals())
    # The DynamoDB source writes all three kinds; the scan found them.
    assert {f for f, _, _ in found} >= {"scanner/src/sensitive_data_scanner/sources/dynamodb.py"}
    bare: list[str] = []
    for file, line, text in found:
        # Drop placeholders (#name, :value) and punctuation; what is left must be keywords.
        words = [
            w
            for w in re.findall(r"[#:]?[A-Za-z_][A-Za-z0-9_]*", text)
            if not w.startswith(("#", ":"))
        ]
        # `f"#p{i}"` leaves the literal "#p"; `", "` leaves nothing.
        bare += [f"{file}:{line}: {w}" for w in words if w not in PLACEHOLDER_OK]
    assert bare == []
