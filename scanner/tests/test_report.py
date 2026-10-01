"""The standalone report (#117): report.html and findings.csv, made by the core.

- Snapshots of both, from a fixed findings document (`fixtures/report/findings.json`).
  Regenerate after a deliberate change with `SDS_UPDATE_SNAPSHOTS=1 uv run pytest
  tests/test_report.py` and read the diff.
- An accessibility check of the page: language, one h1 and no skipped heading level,
  every table captioned with scoped headers, links with text, and every text color's
  contrast against its background in both schemes, measured from the rendered CSS.
- Self-contained: no script, no external request of any kind, a CSP that forbids them.
- The AWS runner writes both next to the findings document; `REPORT_CTA` turns the
  footer's call to action off.

That neither output holds a value is `test_no_leak.py`'s.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from aws_fixtures import RESULTS, Env, config
from sensitive_data_core import report
from sensitive_data_core.report import (
    CSV_COLUMNS,
    CTA_URL,
    PALETTE,
    TEXT_COLORS,
    findings_csv,
    report_html,
)
from sensitive_data_scanner.config import read_config
from synthetic import CARDS

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FIXTURES = HERE / "fixtures" / "report"
SAMPLE = REPO / "docs" / "sample-report"


def fixture_doc() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "findings.json").read_text())
    return data


def snapshot(name: str, got: str) -> None:
    path = FIXTURES / name
    if os.environ.get("SDS_UPDATE_SNAPSHOTS") == "1":
        path.write_text(got)
    assert path.read_text() == got, f"{name} changed: SDS_UPDATE_SNAPSHOTS=1 to accept"


# ------------------------------------------------------------------ snapshots


def test_the_fixture_is_a_valid_findings_document() -> None:
    schema = json.loads((REPO / "schema" / "findings.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(fixture_doc())


def test_html_snapshot() -> None:
    snapshot("report.html", report_html(fixture_doc()))


def test_html_snapshot_without_the_call_to_action() -> None:
    snapshot("report-no-cta.html", report_html(fixture_doc(), cta=False))


def test_csv_snapshot() -> None:
    snapshot("findings.csv", findings_csv(fixture_doc()))


def test_rendering_is_deterministic_and_does_not_change_the_document() -> None:
    doc = fixture_doc()
    before = json.dumps(doc, sort_keys=True)
    assert report_html(doc) == report_html(doc)
    assert findings_csv(doc) == findings_csv(doc)
    assert json.dumps(doc, sort_keys=True) == before


# ------------------------------------------------------------------ what it shows


def test_the_page_shows_gaps_with_their_settings_storage_classes_and_provenance() -> None:
    page = report_html(fixture_doc())
    for setting in (
        "REDSHIFT_READ",
        "DYNAMODB_EXPORT",
        "S3_READ_GLACIER_IR",
        "S3_RESTORE_ARCHIVED",
    ):
        assert f"<code>{setting}</code>" in page, setting
    for text in (
        "the run&#x27;s budget ran out first",  # a deferred store, and why
        "the scanner may not use its KMS key",
        "Parquet, ORC or compressed Avro",  # a skip kind
        "AccessDeniedException",  # a listing that failed
        "GLACIER_IR",
        "DEEP_ARCHIVE",
        "$0.18",  # what turning Glacier IR reads on would cost
        "Payment card number",
        "/aws/lambda/payments",
        "orders-db",
        "app.customers.dob",
        "pk=CUST#t_#########, sk=PROFILE / profile.ssn",
        "archive/old.zip &gt; inner/notes.txt",
        "20260929T060000Z-1a2b3c4d",
        "releases/0.5.0/signing.json",
        "https://txp-labs-sensitive-data-scanner-us-west-2.s3.us-west-2.amazonaws.com/",
        "/releases/tag/v0.5.0",
        "Apache License 2.0",
        "without warranty",
    ):
        assert text in page, text


def test_the_call_to_action_is_on_by_default_and_can_be_turned_off() -> None:
    doc = fixture_doc()
    assert f'href="{CTA_URL}"' in report_html(doc)
    assert "Join the Mermera early-access list" in report_html(doc)
    off = report_html(doc, cta=False)
    assert CTA_URL not in off
    assert "Mermera" not in off


def test_an_empty_run_renders() -> None:
    doc = {
        "schema": "sensitive-data-scanner.findings",
        "schemaVersion": "1.13",
        "scannerVersion": "0.5.0",
        "specVersion": "0.7",
        "runId": "20260929T060000Z-1a2b3c4d",
        "platform": "database",
        "site": "dc-1",
        "startedAt": "2026-09-29T06:00:00+00:00",
        "finishedAt": "2026-09-29T06:00:01+00:00",
        "classes": [],
        "coverage": [],
        "findings": [],
        "findingsTotal": 0,
        "findingsTruncated": False,
        "totals": {},
    }
    page = report_html(doc)
    assert "no sensitive data was found" in page
    assert "Discovery was off" in page
    assert "Databases, site dc-1" in page
    assert findings_csv(doc) == ",".join(CSV_COLUMNS) + "\n"


# ------------------------------------------------------------------ the CSV


def test_the_csv_has_one_row_per_finding_and_no_formulas() -> None:
    doc = fixture_doc()
    rows = list(csv.DictReader(io.StringIO(findings_csv(doc))))
    assert len(rows) == len(doc["findings"])
    assert tuple(rows[0]) == CSV_COLUMNS
    assert {r["finding_id"] for r in rows} == {f["id"] for f in doc["findings"]}
    # Most severe and largest first.
    assert [r["severity"] for r in rows] == sorted(
        (r["severity"] for r in rows), key=["high", "medium", "low"].index
    )
    first = rows[0]
    assert (first["data_type"], first["count"], first["store_kind"]) == ("card", "42", "s3")
    assert (first["store"], first["location"]) == ("example-exports", "billing/2026/09/cards.csv")
    assert (first["region"], first["confidence"]) == ("us-west-2", "high")
    assert first["first_seen"] == "2026-09-28T06:00:00+00:00"
    assert first["console_link"].startswith("https://us-west-2.console.aws.amazon.com/s3/")
    # A name that starts like a formula is quoted, so a spreadsheet shows it as text.
    for r in rows:
        for v in r.values():
            assert not v.startswith(("=", "+", "-", "@")), v
    assert any(r["location"].startswith("'=cmd") for r in rows)


def test_finding_ids_and_links_are_kept_as_the_document_has_them() -> None:
    """An id is a hash, and a hash can hold a nine-digit run: masking it would break the key
    a reviewer triages on. A link is the document's, which drops any built from a mask."""
    doc = fixture_doc()
    doc["findings"][0]["id"] = "fccf3de123456789efe9651c325b556c"
    doc["findings"][1]["link"] = 'javascript:alert("x")'
    rows = list(csv.DictReader(io.StringIO(findings_csv(doc))))
    assert "fccf3de123456789efe9651c325b556c" in {r["finding_id"] for r in rows}
    assert "javascript:" not in findings_csv(doc) + report_html(doc)


# ------------------------------------------------------------------ self-contained


def test_the_page_is_self_contained() -> None:
    page = report_html(fixture_doc())
    for forbidden in ("<script", "<link", "<img", "<iframe", "<object", "src=", "@import", "url("):
        assert forbidden not in page.lower(), forbidden
    assert "data:" not in page
    assert "default-src 'none'" in page
    # Every link is an anchor a reader follows; nothing is fetched.
    style = re.search(r"<style>(.*?)</style>", page, re.S)
    assert style is not None
    assert "http" not in style[1]


# ------------------------------------------------------------------ accessibility


class Audit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.lang: str | None = None
        self.headings: list[int] = []
        self.tables = 0
        self.captions = 0
        self.ths: list[dict[str, str | None]] = []
        self.links: list[list[str]] = []
        self.title = ""
        self._in: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        self._in.append(tag)
        if tag == "html":
            self.lang = a.get("lang")
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if tag == "table":
            self.tables += 1
        if tag == "caption":
            self.captions += 1
        if tag == "th":
            self.ths.append(a)
        if tag == "a":
            self.links.append([])

    def handle_endtag(self, tag: str) -> None:
        if self._in and self._in[-1] == tag:
            self._in.pop()

    def handle_data(self, data: str) -> None:
        if "a" in self._in and self.links:
            self.links[-1].append(data)
        if self._in and self._in[-1] == "title":
            self.title += data


def audit(page: str) -> Audit:
    a = Audit()
    a.feed(page)
    return a


def _luminance(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def schemes(page: str) -> dict[str, dict[str, str]]:
    """The color variables of each scheme, read from the page's own CSS."""
    style = re.search(r"<style>(.*?)</style>", page, re.S)
    assert style is not None
    css = style[1]
    light = re.match(r":root\{color-scheme:light dark;(.*?)\}", css)
    dark = re.search(r"prefers-color-scheme: dark\)\{:root\{(.*?)\}\}", css)
    assert light and dark
    return {
        name: dict(re.findall(r"--([a-z]+):(#[0-9a-f]{6});", block))
        for name, block in (("light", light[1]), ("dark", dark[1]))
    }


@pytest.mark.parametrize("cta", [True, False])
def test_the_page_is_accessible(cta: bool) -> None:
    check_accessible(report_html(fixture_doc(), cta=cta))


def check_accessible(page: str) -> None:
    a = audit(page)
    assert a.lang == "en"
    assert a.title.strip()
    assert a.headings.count(1) == 1 and a.headings[0] == 1
    for prev, cur in zip(a.headings, a.headings[1:], strict=False):
        assert cur <= prev + 1, f"a heading skips from h{prev} to h{cur}"
    assert a.tables > 0 and a.captions == a.tables, "every table has a caption"
    assert a.ths and all(th.get("scope") in ("col", "row") for th in a.ths)
    assert all("".join(t).strip() for t in a.links), "every link has text"
    assert re.search(r'<meta name="viewport"', page)
    css_schemes = schemes(page)
    for scheme, colors in css_schemes.items():
        assert colors == PALETTE[scheme], scheme
        for fg in TEXT_COLORS:
            for bg in ("bg", "surface"):
                ratio = contrast(colors[fg], colors[bg])
                assert ratio >= 4.5, f"{scheme}: {fg} on {bg} is {ratio:.2f}:1"


def test_the_committed_sample_report_is_accessible_and_current_in_shape() -> None:
    page = (SAMPLE / "report.html").read_text()
    check_accessible(page)
    rows = list(csv.DictReader(io.StringIO((SAMPLE / "findings.csv").read_text())))
    assert rows and tuple(rows[0]) == CSV_COLUMNS
    assert (SAMPLE / "report.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


# ------------------------------------------------------------------ the AWS runner


def test_the_aws_runner_writes_both_next_to_the_findings_document(env: Env) -> None:
    env.put("exports/a.csv", f"name,card_number\nx,{CARDS['visa']}\n")
    doc = env.run(config())
    assert doc is not None and doc["findingsTotal"] >= 1
    s3 = env.clients.s3
    page = s3.get_object(Bucket=RESULTS, Key="findings/report.html")
    assert page["ContentType"] == "text/html; charset=utf-8"
    body = page["Body"].read().decode()
    assert doc["runId"] in body and CTA_URL in body
    sheet = s3.get_object(Bucket=RESULTS, Key="findings/findings.csv")
    assert sheet["ContentType"] == "text/csv; charset=utf-8"
    rows = list(csv.DictReader(io.StringIO(sheet["Body"].read().decode())))
    assert len(rows) == doc["findingsTotal"]


def test_report_cta_false_leaves_the_call_to_action_out(env: Env) -> None:
    env.put("exports/a.csv", f"name,card_number\nx,{CARDS['visa']}\n")
    assert env.run(config(report_cta=False)) is not None
    body = env.clients.s3.get_object(Bucket=RESULTS, Key="findings/report.html")["Body"].read()
    assert CTA_URL.encode() not in body


@pytest.mark.parametrize(
    ("value", "setting"),
    [(None, None), ("", None), (" ", None), ("true", True), ("false", False), ("off", False)],
)
def test_report_cta_setting(value: str | None, setting: bool | None) -> None:
    env = {"RESULTS_BUCKET": "b"} | ({"REPORT_CTA": value} if value is not None else {})
    assert read_config(env).report_cta is setting


MERMERA_URL = "https://mermera.example/v1/sites/0f0e0d0c-0b0a-4909-8807-060504030201/findings"
MERMERA_KEY = "k" * 40
PULL_OK = {"configPull": {"status": "ok", "contract": "1"}}
PULL_FAILED = {"configPull": {"status": "failed", "contract": "1"}}


@pytest.mark.parametrize(
    ("env", "settings", "on"),
    [
        # Not connected: on by default; REPORT_CTA decides when set.
        ({}, {}, True),
        ({"REPORT_CTA": "false"}, {}, False),
        ({"REPORT_CTA": "true"}, {}, True),
        # FINDINGS_HTTPS_URL set: off by default; an explicit on or off still wins.
        ({"FINDINGS_HTTPS_URL": MERMERA_URL, "FINDINGS_HMAC_KEY": MERMERA_KEY}, {}, False),
        (
            {
                "FINDINGS_HTTPS_URL": MERMERA_URL,
                "FINDINGS_HMAC_KEY": MERMERA_KEY,
                "REPORT_CTA": "true",
            },
            {},
            True,
        ),
        (
            {
                "FINDINGS_HTTPS_URL": MERMERA_URL,
                "FINDINGS_HMAC_KEY": MERMERA_KEY,
                "REPORT_CTA": "false",
            },
            {},
            False,
        ),
        # A settings pull that succeeded: off by default; one that failed changes nothing.
        ({}, PULL_OK, False),
        ({"REPORT_CTA": "true"}, PULL_OK, True),
        ({}, PULL_FAILED, True),
    ],
)
def test_the_call_to_action_is_dropped_for_a_run_connected_to_mermera(
    env: dict[str, str], settings: dict[str, Any], on: bool
) -> None:
    config_ = dataclasses.replace(
        read_config({"RESULTS_BUCKET": "b"} | env), settings_report=settings
    )
    assert config_.report_cta_on is on


@pytest.mark.parametrize(
    ("kw", "shown"),
    [
        ({}, True),
        ({"mermera_pull": True}, False),
        ({"settings_report": PULL_OK}, False),
        ({"mermera_pull": True, "report_cta": True}, True),
        ({"report_cta": False}, False),
    ],
)
def test_the_runner_writes_the_call_to_action_only_when_it_should(
    env: Env, kw: dict[str, Any], shown: bool
) -> None:
    env.put("exports/a.csv", f"name,card_number\nx,{CARDS['visa']}\n")
    assert env.run(config(**kw)) is not None
    body = env.clients.s3.get_object(Bucket=RESULTS, Key="findings/report.html")["Body"].read()
    assert (CTA_URL.encode() in body) is shown


def test_a_report_that_cannot_be_written_does_not_fail_the_run(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(doc: Any, *, cta: bool) -> Any:
        raise RuntimeError("no")

    monkeypatch.setattr("sensitive_data_scanner.runner.report_files", broken)
    doc = env.run(config())
    assert doc is not None
    assert env.latest()["runId"] == doc["runId"]
    assert '"event":"report.failed"' in capsys.readouterr().out


def test_the_core_names_the_files() -> None:
    names = [n for n, _, _ in report.report_files(fixture_doc())]
    assert names == ["report.html", "findings.csv"]
