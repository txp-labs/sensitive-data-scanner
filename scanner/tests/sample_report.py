"""The sample report in docs/sample-report/, made from the accuracy benchmark's corpus (#117).

    uv run python tests/sample_report.py            # from scanner/: rewrite the sample
    uv run python tests/sample_report.py --png      # and its screenshot (headless Chrome)

Every document of the made-up corpus (`bench_corpus.build_corpus`) is put in a simulated
S3 bucket (moto), with a second bucket the configuration leaves out and a log group, and
the AWS runner scans the account with discovery on, exactly as a deployed function would.
The run's `report.html` and `findings.csv` are copied to docs/sample-report/. The run id
and times are fixed; the S3 version ids in the console links are moto's, so a rerun
differs only there.

Nothing in it is real: every value is made up, and `tests/test_no_leak.py` checks that no
value planted in the corpus appears in either file.
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import boto3
from moto import mock_aws

from bench_corpus import NOW as CORPUS_DATE
from bench_corpus import build_corpus
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.report import report_files
from sensitive_data_scanner.config import Config, store_rules
from sensitive_data_scanner.runner import Clients, run_scan

REGION = "us-west-2"
ACCOUNT = "123456789012"
DATA = "example-benchmark-corpus"
LEFT_OUT = "example-legacy-exports"
RESULTS = "example-scanner-results"
STARTED = dt.datetime(2026, 9, 29, 6, 0, 0, tzinfo=dt.UTC)
OUT = Path(__file__).resolve().parents[2] / "docs" / "sample-report"
CHROME = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
)


def sample_doc() -> dict[str, Any]:
    """The findings document of one run over the corpus."""
    import os

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        os.environ[k] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = REGION
    docs = build_corpus()
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        for b in (DATA, LEFT_OUT, RESULTS):
            s3.create_bucket(
                Bucket=b, CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
            )
        s3.put_bucket_versioning(Bucket=DATA, VersioningConfiguration={"Status": "Enabled"})
        for d in docs:
            s3.put_object(Bucket=DATA, Key=f"corpus/{d.name}", Body=d.data)
        s3.put_object(Bucket=LEFT_OUT, Key="old.csv", Body=b"nothing here")
        logs = boto3.client("logs", region_name=REGION)
        logs.create_log_group(logGroupName="/aws/lambda/checkout")
        ticks = iter(range(10_000))
        doc = run_scan(
            Config(
                results_bucket=RESULTS,
                discover=frozenset({"s3", "cloudwatch_logs"}),
                deny=store_rules(f"s3:{LEFT_OUT}"),
                max_items_per_run=100_000,
            ),
            Clients(s3=s3, logs=logs),
            account=ACCOUNT,
            region=REGION,
            deadline=time.monotonic() + 3600,
            now=lambda: STARTED + dt.timedelta(seconds=next(ticks)),
            detector=Detector(now=CORPUS_DATE),
        )
    assert doc is not None
    doc["runId"] = STARTED.strftime("%Y%m%dT%H%M%SZ") + "-5a3b1e00"
    return doc


def screenshot(page: Path, png: Path) -> None:
    chrome = next((c for c in CHROME if shutil.which(c) or Path(c).exists()), None)
    if chrome is None:
        raise SystemExit("no Chrome or Chromium for the screenshot")
    png.unlink(missing_ok=True)
    try:
        subprocess.run(  # noqa: S603 - a fixed local browser on a local file
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--force-color-profile=srgb",
                "--blink-settings=preferredColorScheme=1",  # light
                "--window-size=1280,1900",
                f"--screenshot={png}",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:  # some builds linger after writing the file
        if not png.exists():
            raise


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, body, _ in report_files(sample_doc()):
        (OUT / name).write_bytes(body)
    if "--png" in argv:
        screenshot(OUT / "report.html", OUT / "report.png")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
