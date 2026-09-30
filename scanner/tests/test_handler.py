"""The Lambda handler (#94): its cold start, one run at a time, and the findings bus's region.

The first whole-account run in a real account hit Lambda's 10-second init limit
(`INIT_REPORT ... Status: timeout`): importing the handler imported the runner, the
detector (Presidio, spaCy) and the AWS SDK. A synchronous CLI invoke that ran past the
CLI's timeout was retried, starting a second run. And a scanner outside the bus's
region made its EventBridge client in its own region.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import pytest

from aws_fixtures import RESULTS, Env, config
from sensitive_data_scanner import handler
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.events import bus_region
from sensitive_data_scanner.runner import _release_lock

# The handler module's import, measured in a fresh interpreter. Lambda's init limit is
# 10 s for the whole of init; this holds the module to a small part of it.
IMPORT_BUDGET_S = 3.0
# Never imported at init: each is imported on the first invoke.
HEAVY = ("presidio_analyzer", "spacy", "thinc", "numpy", "pyarrow", "pypdf", "boto3", "botocore")

PROBE = """
import json, sys, time
t = time.perf_counter()
import sensitive_data_scanner.handler
elapsed = time.perf_counter() - t
heavy = sorted({m.split(".")[0] for m in sys.modules} & set(json.loads(sys.argv[1])))
print(json.dumps({"seconds": elapsed, "heavy": heavy}))
"""


def _probe() -> dict[str, Any]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}  # as in the image: nothing written
    out = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", PROBE, json.dumps(HEAVY)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    result: dict[str, Any] = json.loads(out.stdout.strip().splitlines()[-1])
    return result


def test_the_handler_imports_nothing_heavy_at_init() -> None:
    got = _probe()
    assert got["heavy"] == [], got["heavy"]
    assert got["seconds"] < IMPORT_BUDGET_S, got["seconds"]


def test_the_runner_is_imported_on_the_first_invoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`handler.run_scan` is the runner's, imported when it is first called."""
    seen: dict[str, Any] = {}

    def fake(*args: Any, **kw: Any) -> None:
        seen["called"] = True

    monkeypatch.setattr("sensitive_data_scanner.runner.run_scan", fake)
    assert handler.run_scan() is None
    assert seen == {"called": True}


# ------------------------------------------------------------------ one run at a time


def test_a_second_run_while_one_holds_the_lock_changes_nothing(env: Env) -> None:
    held = json.dumps({"runId": "20260930T000000Z-0a1b2c3d"}).encode()
    env.clients.s3.put_object(Bucket=RESULTS, Key="state/lock.json", Body=held)
    assert env.run(config()) is None
    # The lock is the first run's still, and nothing else was written.
    lock = env.clients.s3.get_object(Bucket=RESULTS, Key="state/lock.json")["Body"].read()
    assert lock == held
    keys = [o["Key"] for o in env.clients.s3.list_objects_v2(Bucket=RESULTS).get("Contents", [])]
    assert keys == ["state/lock.json"]


def test_a_run_releases_its_own_lock_only(env: Env) -> None:
    s3 = env.clients.s3
    ours, theirs = "20260930T000000Z-0a1b2c3d", "20260930T002100Z-4e5f6a7b"
    s3.put_object(Bucket=RESULTS, Key="state/lock.json", Body=json.dumps({"runId": theirs}))
    _release_lock(s3, RESULTS, "state/lock.json", ours)  # taken over: left alone
    assert json.loads(s3.get_object(Bucket=RESULTS, Key="state/lock.json")["Body"].read()) == {
        "runId": theirs
    }
    _release_lock(s3, RESULTS, "state/lock.json", theirs)
    assert "Contents" not in s3.list_objects_v2(Bucket=RESULTS)


def test_a_run_ends_with_its_lock_released(env: Env) -> None:
    assert env.run(config()) is not None
    keys = [o["Key"] for o in env.clients.s3.list_objects_v2(Bucket=RESULTS)["Contents"]]
    assert "state/lock.json" not in keys
    assert env.run(config()) is not None  # the next run is not locked out


# ------------------------------------------------------------------ the findings bus's region

BUS_EU = "arn:aws:events:eu-west-1:210987654321:event-bus/findings"


class _Context:
    invoked_function_arn = "arn:aws:lambda:us-west-2:123456789012:function:sds"

    def get_remaining_time_in_millis(self) -> int:
        return 900_000


def test_the_events_client_is_made_in_the_bus_s_region(monkeypatch: pytest.MonkeyPatch) -> None:
    made: list[tuple[str, str]] = []

    def fake_client(name: str, **kw: Any) -> str:
        made.append((name, kw["region_name"]))
        return name

    monkeypatch.setattr("boto3.client", fake_client)
    seen: dict[str, Any] = {}

    def run_scan(config: Any, clients: Any, **kw: Any) -> None:
        seen["clients"] = clients

    monkeypatch.setattr(handler, "run_scan", run_scan)
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    for k, v in {"RESULTS_BUCKET": RESULTS, "FINDINGS_EVENT_BUS_ARN": BUS_EU}.items():
        monkeypatch.setenv(k, v)
    assert handler.handler({}, _Context()) == {"status": "locked"}
    assert ("events", "eu-west-1") in made
    assert all(region == "us-west-2" for name, region in made if name != "events")
    assert seen["clients"].events == "events"


@pytest.mark.parametrize(
    ("arn", "region"),
    [
        (BUS_EU, "eu-west-1"),
        ("arn:aws:events:us-west-2:210987654321:event-bus/default", "us-west-2"),
        ("arn:aws-us-gov:events:us-gov-west-1:210987654321:event-bus/f", "us-gov-west-1"),
        ("arn:aws-cn:events:cn-north-1:210987654321:event-bus/f", "cn-north-1"),
    ],
)
def test_the_bus_region_comes_from_its_arn(arn: str, region: str) -> None:
    assert bus_region(arn) == region
    assert read_config({"RESULTS_BUCKET": "x", "FINDINGS_EVENT_BUS_ARN": arn}).event_bus_arn == arn


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:sns:eu-west-1:210987654321:findings",
        "arn:aws:events:eu-west-1:210987654321:rule/findings",
        "findings",
        "arn:aws:events::210987654321:event-bus/findings",
    ],
)
def test_a_value_that_is_not_a_bus_arn_is_refused(arn: str) -> None:
    with pytest.raises(ValueError, match="FINDINGS_EVENT_BUS_ARN"):
        bus_region(arn)
    with pytest.raises(ValueError):
        read_config({"RESULTS_BUCKET": "x", "FINDINGS_EVENT_BUS_ARN": arn})
    assert read_config({"RESULTS_BUCKET": "x", "FINDINGS_EVENT_BUS_ARN": ""}).event_bus_arn is None
