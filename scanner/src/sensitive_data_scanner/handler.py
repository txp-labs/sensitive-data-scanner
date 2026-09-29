"""Lambda entry point for scheduled batch scans (EventBridge Scheduler).

    sensitive_data_scanner.handler.handler

The scan's configuration comes from environment variables (config.py). A
failed run raises `ScanError`, whose message is an error name only.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import boto3

from .config import read_config
from .runner import Clients, run_scan
from .safety import ScanError, error_name, log_event

# Time kept back from the Lambda timeout to write results and release the lock.
RESERVE_SECONDS = 90

# Third-party libraries log nothing the scanner has not vetted.
for _name in ("presidio-analyzer", "botocore", "boto3", "urllib3"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)


def handler(event: Any, context: Any) -> dict[str, Any]:
    region = os.environ.get("AWS_REGION", "us-east-1")
    account = str(context.invoked_function_arn).split(":")[4]
    remaining_s = context.get_remaining_time_in_millis() / 1000
    try:
        config = read_config()
        clients = Clients(
            s3=boto3.client("s3", region_name=region),
            logs=boto3.client("logs", region_name=region),
            events=boto3.client("events", region_name=region) if config.event_bus_arn else None,
            dynamodb=(
                boto3.client("dynamodb", region_name=region) if config.dynamodb_targets else None
            ),
        )
        doc = run_scan(
            config,
            clients,
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
