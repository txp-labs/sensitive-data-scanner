"""What the findings may mean (findings schema 1.15): the rules and laws they may bring into
scope, in the findings document (`scopeHints`) and in report.html.

- Card data raises PCI DSS; a card verification code or a PIN adds the never-kept sentence.
- Social Security numbers, ITINs, account and card numbers raise the US breach laws.
- HIPAA only with `HEALTH_DATA` on, since the scanner detects no health information; with
  it off, a report holding a class HIPAA would name says how to turn it on.
- Locations are counted once each, and those stored unencrypted are counted apart.
- A hint never holds a value: its strings are constants and its numbers are counts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from sensitive_data_core.findings import findings_document
from sensitive_data_core.report import report_html
from sensitive_data_core.scope import (
    HEALTH_DATA,
    PCI_NEVER_KEPT,
    health_data_declared,
    scope_hints,
)

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "schema" / "findings.schema.json").read_text())


def finding(cls: str, n: int, at_rest: str = "service_managed") -> dict[str, Any]:
    return {"id": f"{n:032x}", "class": cls, "atRestEncryption": at_rest}


def frameworks(hints: dict[str, Any]) -> list[str]:
    return [h["framework"] for h in hints["hints"]]


def by_framework(hints: dict[str, Any], framework: str) -> dict[str, Any]:
    return next(h for h in hints["hints"] if h["framework"] == framework)


def test_card_numbers_raise_pci_dss_and_the_us_breach_laws() -> None:
    got = scope_hints([finding("card", 1)], health_data=False)
    assert frameworks(got) == ["pci_dss", "us_breach_notification"]
    assert PCI_NEVER_KEPT not in by_framework(got, "pci_dss")["mayApply"]


@pytest.mark.parametrize("cls", ["cvv", "pin"])
def test_a_verification_code_or_pin_is_never_kept(cls: str) -> None:
    got = by_framework(scope_hints([finding(cls, 1)], health_data=False), "pci_dss")
    assert got["classes"] == [cls]
    assert got["mayApply"].endswith(PCI_NEVER_KEPT)


def test_hipaa_only_when_the_deployment_holds_health_information() -> None:
    rows = [finding("us_ssn", 1), finding("dob", 2)]
    assert frameworks(scope_hints(rows, health_data=False)) == ["us_breach_notification"]
    on = scope_hints(rows, health_data=True)
    assert on["healthData"] is True
    assert frameworks(on) == ["us_breach_notification", "hipaa"]
    assert by_framework(on, "hipaa")["classes"] == ["us_ssn", "dob"]


def test_a_date_of_birth_alone_raises_nothing_without_health_data() -> None:
    assert scope_hints([finding("dob", 1), finding("us_ssn_last4", 2)], health_data=False) == {
        "healthData": False,
        "hints": [],
    }


def test_locations_are_counted_once_and_unencrypted_ones_apart() -> None:
    rows = [
        finding("card", 1, "none"),
        finding("cvv", 1, "none"),  # the same location id: one location
        finding("card", 2, "customer_managed_key"),
        finding("card", 3, "unknown"),
    ]
    got = by_framework(scope_hints(rows, health_data=False), "pci_dss")
    assert got["classes"] == ["card", "cvv"]
    assert (got["locations"], got["unencryptedLocations"]) == (3, 1)


@pytest.mark.parametrize(
    ("value", "on"),
    [(None, False), ("", False), ("off", False), ("no", False), ("on", True), ("TRUE", True)],
)
def test_health_data_setting(value: str | None, on: bool) -> None:
    env = {} if value is None else {HEALTH_DATA: value}
    assert health_data_declared(env) is on


FIXTURE = json.loads(
    (REPO / "scanner" / "tests" / "fixtures" / "report" / "findings.json").read_text()
)


def doc(rows: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    # A valid finding from the report's fixture, given each row's id, class and encryption.
    full = [{**FIXTURE["findings"][0], **r} for r in rows]
    return findings_document(
        run_id="20261031T000000Z-0000abcd",
        account="123456789012",
        region="us-west-2",
        started_at="2026-10-31T00:00:00+00:00",
        finished_at="2026-10-31T00:01:00+00:00",
        classes=["card", "cvv", "us_ssn", "dob"],
        coverage=[],
        findings=full,
        **kw,
    )


def test_the_document_carries_the_hints_and_is_valid() -> None:
    got = doc([finding("card", 1, "none"), finding("us_ssn", 2)], health_data=True)
    assert got["schemaVersion"] == "1.15"
    assert frameworks(got["scopeHints"]) == ["pci_dss", "us_breach_notification", "hipaa"]
    jsonschema.Draft202012Validator(SCHEMA).validate(got)


def test_the_document_reads_health_data_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(HEALTH_DATA, "on")
    assert doc([finding("us_ssn", 1)])["scopeHints"]["healthData"] is True
    monkeypatch.delenv(HEALTH_DATA)
    assert doc([finding("us_ssn", 1)])["scopeHints"]["healthData"] is False


def test_a_hint_holds_no_digits_but_its_requirement_number() -> None:
    hints = scope_hints(
        [finding(c, i) for i, c in enumerate(["card", "cvv", "us_ssn", "dob"])],
        health_data=True,
    )
    for h in hints["hints"]:
        for key in ("name", "mayApply", "ifLeft", "decidedBy"):
            assert not re.search(r"\d{2,}", h[key]), (h["framework"], key)


def test_the_report_says_what_the_findings_may_mean() -> None:
    page = report_html(doc([finding("cvv", 1, "none"), finding("dob", 2)], health_data=False))
    section = page.split('<h2 id="may-mean">', 1)[1].split("<h2 ", 1)[0]
    assert section.startswith("What these findings may mean</h2>")
    assert "<h3>PCI DSS</h3>" in section
    assert "requirement 3.3.1" in section
    assert "1 location holds card verification code; 1 of them is not encrypted at rest." in section
    assert "<h3>HIPAA</h3>" not in section
    assert "<code>HEALTH_DATA</code> to <code>on</code>" in section
    # Right after the summary, before what was scanned.
    assert page.index('id="summary"') < page.index('id="may-mean"') < page.index('id="scanned"')


def test_the_report_with_health_data_on_names_hipaa_and_no_setting() -> None:
    page = report_html(doc([finding("dob", 1)], health_data=True))
    assert "<h3>HIPAA</h3>" in page
    assert "<code>HEALTH_DATA</code> to" not in page


def test_a_report_with_nothing_to_hint() -> None:
    page = report_html(doc([]))
    assert "No finding suggests a rule or law." in page


def test_a_document_older_than_1_15_still_gets_its_hints() -> None:
    old = doc([finding("card", 1)])
    del old["scopeHints"]
    assert "<h3>PCI DSS</h3>" in report_html(old)
