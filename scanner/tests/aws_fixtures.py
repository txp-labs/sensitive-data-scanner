"""Moto-backed AWS for the runner tests: a data bucket, a results bucket, log groups.

Everything here is synthetic. Documents are built with the fixture builders
ported from txp-labs/mermera-attestation-app#1067.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import boto3
import pytest
from moto import mock_aws

from sensitive_data_scanner.config import Config
from sensitive_data_scanner.detect.analyzer import Detector
from sensitive_data_scanner.runner import Clients, run_scan

REGION = "us-west-2"
ACCOUNT = "123456789012"
DATA = "example-connect-data"
RESULTS = "example-scanner-results"
NOW = dt.datetime(2026, 9, 29, 12, 0, 0, tzinfo=dt.UTC)


@dataclass
class Env:
    clients: Clients
    detector: Detector

    def run(self, config: Config, **kw: Any) -> dict[str, Any] | None:
        return run_scan(
            config,
            self.clients,
            account=ACCOUNT,
            region=REGION,
            deadline=time.monotonic() + 600,
            detector=self.detector,
            **kw,
        )

    def latest(self) -> dict[str, Any]:
        body = self.clients.s3.get_object(Bucket=RESULTS, Key="findings/latest.json")["Body"]
        data: dict[str, Any] = json.loads(body.read())
        return data

    def state(self) -> dict[str, Any]:
        body = self.clients.s3.get_object(Bucket=RESULTS, Key="state/scanner-state.json")["Body"]
        data: dict[str, Any] = json.loads(body.read())
        return data

    def put(self, key: str, body: str | bytes) -> None:
        self.clients.s3.put_object(
            Bucket=DATA, Key=key, Body=body.encode() if isinstance(body, str) else body
        )

    def log(self, group: str, stream: str, messages: list[tuple[int, str]]) -> None:
        logs = self.clients.logs
        with contextlib.suppress(logs.exceptions.ResourceAlreadyExistsException):
            logs.create_log_group(logGroupName=group)
        with contextlib.suppress(logs.exceptions.ResourceAlreadyExistsException):
            logs.create_log_stream(logGroupName=group, logStreamName=stream)
        logs.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": ts, "message": m} for ts, m in messages],
        )


_DETECTOR: Detector | None = None


def shared_detector() -> Detector:
    global _DETECTOR  # noqa: PLW0603 - one Presidio engine for the whole session
    if _DETECTOR is None:
        _DETECTOR = Detector(now=NOW.date())
    return _DETECTOR


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        for b in (DATA, RESULTS):
            s3.create_bucket(
                Bucket=b, CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
            )
        s3.put_bucket_versioning(Bucket=DATA, VersioningConfiguration={"Status": "Enabled"})
        yield Env(
            Clients(
                s3=s3,
                logs=boto3.client("logs", region_name=REGION),
                events=boto3.client("events", region_name=REGION),
            ),
            shared_detector(),
        )


def config(**kw: Any) -> Config:
    base: dict[str, Any] = {
        "results_bucket": RESULTS,
        "s3_targets": [(DATA, "")],
        "log_groups": [],
        "logs_lookback_days": 7,
    }
    base.update(kw)
    return Config(**base)


def epoch_ms(t: dt.datetime) -> int:
    return int(t.timestamp() * 1000)
