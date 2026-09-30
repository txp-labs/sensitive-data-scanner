"""Lambda entry point for scheduled batch scans (EventBridge Scheduler).

    sensitive_data_scanner.handler.handler

The scan's configuration comes from environment variables, and from a
configuration document in the invoke payload (`{"config": {...}}`) or in a
file in S3 or SSM (`CONFIG_LOCATION`, or the payload's `configLocation`); see
config.py. A failed run raises `ScanError`, whose message is an error name only.

**Cold start (#94).** Importing this module imports nothing heavy: the AWS SDK,
Presidio and spaCy, pyarrow and pypdf are imported on the first invoke, inside
the handler. Lambda gives a function's init 10 seconds, and the first real run
passed it (`INIT_REPORT ... Status: timeout`) when this module imported the
runner; an invoke has the function's whole timeout. `tests/test_handler.py`
holds the import to a budget.

**Invoking by hand.** Invoke asynchronously (`--invocation-type Event`). A
synchronous CLI invoke that runs longer than the CLI's read timeout is retried by
the CLI, which starts a second run; the second finds the lock held and returns
`{"status": "locked"}`, or, after the first finishes, runs again
(docs/ARCHITECTURE.md, "Invoking a run").
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Any

from sensitive_data_core.safety import ScanError, error_name, log_event

if TYPE_CHECKING:
    from .config import Config

# Time kept back from the Lambda timeout to write results and release the lock.
RESERVE_SECONDS = 90

# Third-party libraries log nothing the scanner has not vetted.
for _name in ("presidio-analyzer", "botocore", "boto3", "urllib3"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)


def run_scan(*args: Any, **kwargs: Any) -> dict[str, Any] | None:
    """`runner.run_scan`, imported on first use (it imports the detector and every source)."""
    from .runner import run_scan as run  # noqa: PLC0415 - lazy: kept out of Lambda's init

    return run(*args, **kwargs)


def _clients(config: Config, region: str, client: Any) -> Any:
    import boto3  # noqa: PLC0415 - lazy: kept out of Lambda's init

    from .events import bus_region  # noqa: PLC0415
    from .runner import Clients  # noqa: PLC0415

    return Clients(
        s3=client("s3"),
        logs=boto3.client("logs", region_name=region),
        # The bus's own region, which may not be the scanner's (#94).
        events=(
            boto3.client("events", region_name=bus_region(config.event_bus_arn))
            if config.event_bus_arn
            else None
        ),
        dynamodb=(
            boto3.client("dynamodb", region_name=region)
            if config.dynamodb_targets or "dynamodb" in config.discover
            else None
        ),
        glue=boto3.client("glue", region_name=region) if "glue_table" in config.discover else None,
        rds=boto3.client("rds", region_name=region) if "rds" in config.discover else None,
        rds_data=(
            boto3.client("rds-data", region_name=region) if config.data_api_targets else None
        ),
        # Every adapter's client is made on first use, so a kind not discovered
        # makes no client.
        factory=lambda service: boto3.client(service, region_name=region),  # type: ignore[call-overload]
    )


def handler(event: Any, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "us-east-1")
    account = str(context.invoked_function_arn).split(":")[4]
    remaining_s = context.get_remaining_time_in_millis() / 1000
    made: dict[str, Any] = {}

    try:
        import boto3  # noqa: PLC0415 - lazy: kept out of Lambda's init

        from .config import load_config  # noqa: PLC0415

        def client(service: str) -> Any:
            if service not in made:
                made[service] = boto3.client(service, region_name=region)  # type: ignore[call-overload]
            return made[service]

        config = load_config(event, client)
        doc = run_scan(
            config,
            _clients(config, region, client),
            account=account,
            region=region,
            deadline=time.monotonic() + max(30.0, remaining_s - RESERVE_SECONDS),
        )
    except ScanError:
        raise
    except Exception as err:
        name = error_name(err)
        log_event("run.failed", error=name)
        raise ScanError(name) from None
    if doc is None:
        return {"status": "locked"}
    return {"status": "done", "runId": doc["runId"], "findings": doc["findingsTotal"]}
