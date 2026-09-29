"""Configuration beyond Lambda's 4 KB of environment (#24): the invoke payload,
a file in S3 or SSM, and the first run's state file read without s3:ListBucket.

Every name and value here is made up.
"""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from aws_fixtures import RESULTS, Env, config
from sensitive_data_scanner import handler
from sensitive_data_scanner.config import (
    MAX_CONFIG_BYTES,
    document_settings,
    load_config,
    read_config,
)
from sensitive_data_scanner.safety import ScanError

ENV = {"RESULTS_BUCKET": RESULTS, "DISCOVER": "s3"}


def tables(n: int) -> list[dict[str, Any]]:
    """n DynamoDB entries in the shape Stugum uses: well past 4 KB for n = 16."""
    return [
        {
            "table": f"example-table-{i:02d}",
            "partition": "T#t_0000example",
            "sortPrefix": "RUN#",
            "include": ["stepResults[].observedDtmf", "stepResults[].observedText", "steps"],
            "keypad": ["stepResults[kind=sendDtmf].observedDtmf", "steps[kind=sendDtmf].digits"],
            "prompts": ["stepResults[kind=waitForPrompt].observedText"],
            "planted": ["steps"],
            "orderBy": "stepIndex",
        }
        for i in range(n)
    ]


def test_the_environment_alone_still_works() -> None:
    assert load_config({}, env=ENV) == read_config(ENV)
    # A scheduled invoke's payload is whatever the schedule sends; other keys are ignored.
    assert load_config({"source": "aws.scheduler"}, env=ENV) == read_config(ENV)
    assert load_config(None, env=ENV) == read_config(ENV)


def test_the_payload_carries_a_config_larger_than_lambda_allows() -> None:
    entries = tables(16)
    assert len(json.dumps(entries)) > 4096
    got = load_config(
        {
            "config": {
                "SCAN_DYNAMODB": entries,
                "DISCOVER": ["s3", "dynamodb"],
                "MAX_ITEMS_PER_RUN": 5,
            }
        },
        env=ENV,
    )
    assert len(got.dynamodb_targets) == 16
    assert got.dynamodb_targets[3].table == "example-table-03"
    assert got.discover == frozenset({"s3", "dynamodb"})
    assert got.max_items_per_run == 5
    assert got.results_bucket == RESULTS  # still from the environment


def test_values_are_given_as_the_environment_would_hold_them() -> None:
    assert document_settings(
        {
            "DYNAMODB_EXPORT": True,
            "S3_SAMPLE_PERCENT": 10,
            "SCAN_BUCKETS": ["a-bucket", "b-bucket"],
            "DISCOVER_SAMPLING": [{"match": "s3:*", "samplePercent": 5}],
            "FINDINGS_EVENT_BUS_ARN": None,
        }
    ) == {
        "DYNAMODB_EXPORT": "true",
        "S3_SAMPLE_PERCENT": "10",
        "SCAN_BUCKETS": "a-bucket,b-bucket",
        "DISCOVER_SAMPLING": '[{"match": "s3:*", "samplePercent": 5}]',
        "FINDINGS_EVENT_BUS_ARN": "",
    }


@pytest.mark.parametrize(
    "doc",
    [
        {"SCAN_DYNAMOBD": "[]"},  # a typo is an error, not silently ignored
        {"CONFIG_LOCATION": "s3://example-bucket/x.json"},  # no chaining
        {"AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/other"},  # Lambda's to set
        {"lower_case": "x"},
        {"DISCOVER": {"s3": True}},
        ["DISCOVER"],
    ],
)
def test_a_document_is_checked(doc: Any) -> None:
    with pytest.raises(ValueError):
        load_config({"config": doc}, env=ENV)


def test_errors_quote_nothing_from_the_document() -> None:
    with pytest.raises(ValueError) as err:
        load_config({"config": {"SCAN_DYNAMODB": "not json 123456789"}}, env=ENV)
    assert "123456789" not in str(err.value)


class Clients:
    def __init__(self) -> None:
        self.made: list[str] = []

    def __call__(self, service: str) -> Any:
        self.made.append(service)
        return boto3.client(service, region_name="us-west-2")  # type: ignore[call-overload]


def test_a_file_in_s3(env: Env) -> None:
    body = json.dumps({"SCAN_DYNAMODB": tables(16), "MAX_RUN_SECONDS": 600})
    env.clients.s3.put_object(Bucket=RESULTS, Key="config/scanner.json", Body=body.encode())
    clients = Clients()
    got = load_config(
        {}, clients, {**ENV, "CONFIG_LOCATION": f"s3://{RESULTS}/config/scanner.json"}
    )
    assert len(got.dynamodb_targets) == 16
    assert got.max_run_seconds == 600
    assert clients.made == ["s3"]


def test_the_payload_wins_over_the_file_and_the_file_over_the_environment(env: Env) -> None:
    body = json.dumps({"MAX_ITEMS_PER_RUN": 7, "S3_SAMPLE_PERCENT": 50})
    env.clients.s3.put_object(Bucket=RESULTS, Key="c.json", Body=body.encode())
    got = load_config(
        {"configLocation": f"s3://{RESULTS}/c.json", "config": {"S3_SAMPLE_PERCENT": 20}},
        Clients(),
        {**ENV, "MAX_ITEMS_PER_RUN": "3", "LOGS_LOOKBACK_DAYS": "9"},
    )
    assert (got.max_items_per_run, got.sample_percent, got.logs_lookback_days) == (7, 20, 9)


def test_a_file_in_ssm(env: Env) -> None:
    ssm = boto3.client("ssm", region_name="us-west-2")
    ssm.put_parameter(
        Name="/sensitive-data-scanner/config",
        Value=json.dumps({"SCAN_DYNAMODB": tables(2)}),
        Type="String",
    )
    for location in (
        "ssm:/sensitive-data-scanner/config",
        "arn:aws:ssm:us-west-2:123456789012:parameter/sensitive-data-scanner/config",
    ):
        got = load_config({}, Clients(), {**ENV, "CONFIG_LOCATION": location})
        assert [t.table for t in got.dynamodb_targets] == ["example-table-00", "example-table-01"]


@pytest.mark.parametrize("location", ["https://example.com/c.json", "s3://x", "ssm:"])
def test_an_unknown_location_is_an_error(location: str) -> None:
    with pytest.raises(ValueError):
        load_config({}, Clients(), {**ENV, "CONFIG_LOCATION": location})


def test_a_file_too_large_or_not_json_is_an_error(env: Env) -> None:
    env.clients.s3.put_object(Bucket=RESULTS, Key="big.json", Body=b" " * (MAX_CONFIG_BYTES + 1))
    env.clients.s3.put_object(Bucket=RESULTS, Key="bad.json", Body=b"{nope")
    for key in ("big.json", "bad.json"):
        with pytest.raises(ValueError):
            load_config({}, Clients(), {**ENV, "CONFIG_LOCATION": f"s3://{RESULTS}/{key}"})


def test_the_handler_reads_the_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("boto3.client", lambda name, **kw: name)
    seen: dict[str, Any] = {}

    def run_scan(cfg: Any, clients: Any, **kw: Any) -> None:
        seen["config"] = cfg
        seen["clients"] = clients

    monkeypatch.setattr(handler, "run_scan", run_scan)
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    class Context:
        invoked_function_arn = "arn:aws:lambda:us-west-2:123456789012:function:sds"

        def get_remaining_time_in_millis(self) -> int:
            return 900_000

    event = {"config": {"SCAN_DYNAMODB": tables(16)}}
    assert handler.handler(event, Context()) == {"status": "locked"}
    assert len(seen["config"].dynamodb_targets) == 16
    assert seen["clients"].dynamodb == "dynamodb"


# ------------------------------------------------------------------ the first run's state file


class DeniedWhenMissing:
    """S3 without s3:ListBucket: a missing object answers 403 AccessDenied, not 404."""

    def __init__(self, s3: Any, *, deny_all_reads: bool = False) -> None:
        self._s3 = s3
        self.deny_all_reads = deny_all_reads

    def __getattr__(self, name: str) -> Any:
        return getattr(self._s3, name)

    def _denied(self, op: str) -> ClientError:
        return ClientError({"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, op)

    def get_object(self, **kw: Any) -> Any:
        if self.deny_all_reads:
            raise self._denied("GetObject")
        try:
            return self._s3.get_object(**kw)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchKey":
                raise self._denied("GetObject") from None
            raise

    def head_object(self, **kw: Any) -> Any:
        if self.deny_all_reads:
            raise self._denied("HeadObject")
        return self._s3.head_object(**kw)


def test_a_missing_state_file_is_empty_without_list_bucket(env: Env) -> None:
    env.put("notes/a.txt", "nothing here")
    env.clients.s3 = DeniedWhenMissing(env.clients.s3)  # type: ignore[assignment]
    doc = env.run(config())
    assert doc is not None
    assert env.state()["version"]


def test_a_real_denial_is_still_a_failure(env: Env) -> None:
    env.clients.s3 = DeniedWhenMissing(env.clients.s3, deny_all_reads=True)  # type: ignore[assignment]
    with pytest.raises(ScanError) as err:
        env.run(config())
    assert err.value.error == "AccessDenied"


def test_a_kms_denial_on_the_state_file_is_not_taken_for_missing(env: Env) -> None:
    class KmsDenied(DeniedWhenMissing):
        def get_object(self, **kw: Any) -> Any:
            if kw["Key"].endswith("scanner-state.json"):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "not allowed by kms key"}},
                    "GetObject",
                )
            return super().get_object(**kw)

    env.clients.s3 = KmsDenied(env.clients.s3)  # type: ignore[assignment]
    with pytest.raises(ScanError):
        env.run(config())
