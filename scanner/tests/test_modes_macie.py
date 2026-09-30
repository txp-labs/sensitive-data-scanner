"""Scanner, vendor or both (#55): the core's modes, and Amazon Macie's findings imported.

Macie is a stub (no write method, no occurrence method at all); S3 is moto. Every value is
made up.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from botocore.exceptions import ClientError
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, Env, config
from conftest import REPO
from sensitive_data_core.modes import (
    ModeError,
    VendorCoverage,
    VendorDetection,
    link_duplicates,
    read_mode,
    vendor_class,
    vendor_finding,
)
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.sources.macie import TYPES, detections
from synthetic import CARDS, SSN_A, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def macie_finding(
    fid: str, key: str, *, types: dict[str, int], updated: str = "2026-09-28T10:00:00Z"
) -> dict[str, Any]:
    """A Macie finding as GetFindings returns it, with the occurrences Macie keeps (positions
    into the object) and a title and description that could quote anything."""
    return {
        "id": fid,
        "category": "CLASSIFICATION",
        "title": f"The S3 object contains {CARDS['visa']}",
        "description": f"sample {dashed(SSN_A)}",
        "updatedAt": updated,
        "severity": {"description": "High", "score": 3},
        "resourcesAffected": {
            "s3Bucket": {"name": DATA},
            "s3Object": {
                "key": key,
                "versionId": "v-1",
                "serverSideEncryption": {"encryptionType": "AES256"},
            },
        },
        "classificationDetails": {
            "result": {
                "sensitiveData": [
                    {
                        "category": "FINANCIAL_INFORMATION",
                        "detections": [
                            {
                                "type": t,
                                "count": n,
                                "occurrences": {
                                    "lineRanges": [{"start": 1, "end": 1, "startColumn": 5}],
                                    "cells": [{"row": 2, "column": 1, "columnName": CARDS["visa"]}],
                                },
                            }
                            for t, n in types.items()
                        ],
                    }
                ],
                "customDataIdentifiers": {
                    "detections": [
                        {
                            "arn": "arn:aws:macie2:us-west-2:123456789012:x/1",
                            "name": "employee-id",
                            "count": 3,
                        }
                    ]
                },
            }
        },
    }


class Macie:
    """ListFindings and GetFindings over made-up findings. No write method, and no
    GetSensitiveDataOccurrences: calling one would fail the test."""

    def __init__(self, findings: list[dict[str, Any]], *, enabled: bool = True) -> None:
        self.findings = findings
        self.enabled = enabled
        self.criteria: list[Any] = []

    def get_macie_session(self) -> dict[str, Any]:
        if not self.enabled:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Macie is not enabled"}},
                "GetMacieSession",
            )
        return {"status": "ENABLED"}

    def list_findings(self, **kw: Any) -> dict[str, Any]:
        self.criteria.append(kw["findingCriteria"])
        floor = kw["findingCriteria"]["criterion"]["updatedAt"]["gte"]
        ids = [
            f["id"]
            for f in self.findings
            if dt.datetime.fromisoformat(f["updatedAt"].replace("Z", "+00:00")).timestamp() * 1000
            >= floor
        ]
        return {"findingIds": ids}

    def get_findings(self, findingIds: list[str], **kw: Any) -> dict[str, Any]:
        return {"findings": [f for f in self.findings if f["id"] in findingIds]}


def test_modes_and_vendor_classes() -> None:
    assert read_mode(None) == "scanner" and read_mode(" Both ") == "both"
    with pytest.raises(ModeError):
        read_mode("sometimes")
    assert vendor_class("CREDIT_CARD_NUMBER", TYPES) == ("card", "CREDIT_CARD_NUMBER")
    assert vendor_class("AWS_CREDENTIALS", TYPES) == ("other", "AWS_CREDENTIALS")
    assert vendor_class(f"CUSTOM_{CARDS['visa']}", TYPES)[1] == "CUSTOM_################"
    assert vendor_class(None, TYPES) == ("other", None)
    got = detections(
        macie_finding("f1", "a.csv", types={"CREDIT_CARD_NUMBER": 2, "AWS_CREDENTIALS": 1})
    )
    assert {(d.cls, d.vendor_type, d.count) for d in got} == {
        ("card", "CREDIT_CARD_NUMBER", 2),
        ("other", "AWS_CREDENTIALS", 1),
        ("other", "custom:employee-id", 3),
    }


def test_linked_not_merged() -> None:
    resource = {"type": "s3_object", "bucket": "b", "key": "k", "versionId": "v"}
    ours = {
        "id": "a" * 32,
        "resource": resource,
        "class": "card",
        "source": "scanner",
    }
    theirs = vendor_finding(
        {**resource, "versionId": "other"},
        None,
        VendorDetection("card", "CREDIT_CARD_NUMBER", 2, 2),
        vendor="macie",
        seen_at="2026-09-29T00:00:00+00:00",
    )
    other_class = vendor_finding(
        resource,
        None,
        VendorDetection("us_ssn", "X", 1, 1),
        vendor="macie",
        seen_at="2026-09-29T00:00:00+00:00",
    )
    assert link_duplicates([ours, theirs, other_class]) == 2
    assert ours["linked"] == [theirs["id"]] and theirs["linked"] == [ours["id"]]
    assert "linked" not in other_class
    assert theirs["offsets"] == [] and theirs["via"] == ["vendor"] and theirs["format"] == "vendor"
    assert theirs["id"] != ours["id"]
    cov = VendorCoverage("macie", "aws", "both", limits=("s3_only", "made_up"))
    assert cov.as_json()["limits"] == ["s3_only"]


def _seed(env: Env) -> None:
    env.put("exports/cards.csv", f"name,card_number\nA,{CARDS['visa']}\n")
    env.put("notes/other.txt", "nothing")


def test_scanner_mode_says_so_and_every_finding_is_the_scanners(env: Env) -> None:
    _seed(env)
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    assert doc["scanMode"] == {"aws": "scanner"} and "vendorCoverage" not in doc
    assert {f["source"] for f in doc["findings"]} == {"scanner"}


def test_both_modes_read_import_and_link(env: Env) -> None:
    _seed(env)
    macie = Macie(
        [
            macie_finding("m-1", "exports/cards.csv", types={"CREDIT_CARD_NUMBER": 1}),
            macie_finding("m-2", "only/macie.parquet", types={"USA_SOCIAL_SECURITY_NUMBER": 4}),
        ]
    )
    env.clients.services["macie2"] = macie
    doc = env.run(config(scan_mode="both"))
    assert doc is not None
    valid(doc)
    assert doc["scanMode"] == {"aws": "both"}
    (cov,) = doc["vendorCoverage"]
    assert cov["vendor"] == "macie" and cov["status"] == "read" and cov["findings"] == 2
    assert cov["covers"] == ["s3"] and "s3_only" in cov["limits"]
    card = [f for f in doc["findings"] if f["class"] == "card"]
    sources = {f["source"] for f in card}
    assert sources == {"scanner", "vendor:macie"}
    ours = next(f for f in card if f["source"] == "scanner")
    theirs = next(f for f in card if f["source"] == "vendor:macie")
    assert ours["linked"] == [theirs["id"]] and theirs["linked"] == [ours["id"]]
    assert theirs["vendorType"] == "CREDIT_CARD_NUMBER" and theirs["vendorFindingId"] == "m-1"
    assert theirs["atRestEncryption"] == "service_managed" and theirs["pciNote"]
    ssn = next(f for f in doc["findings"] if f["class"] == "us_ssn")
    assert ssn["source"] == "vendor:macie" and "linked" not in ssn and ssn["count"] == 4
    other = [f for f in doc["findings"] if f["class"] == "other"]
    assert {f["vendorType"] for f in other} == {"custom:employee-id"}
    # Only category CLASSIFICATION findings, updated since the lookback.
    assert macie.criteria[0]["criterion"]["category"] == {"eq": ["CLASSIFICATION"]}
    # The next run asks only for what changed since, and keeps what was imported.
    again = env.run(config(scan_mode="both"))
    assert again is not None
    assert (
        macie.criteria[-1]["criterion"]["updatedAt"]["gte"]
        > macie.criteria[0]["criterion"]["updatedAt"]["gte"]
    )
    assert any(f["source"] == "vendor:macie" for f in again["findings"])


def test_vendor_mode_reads_nothing_and_says_what_macie_misses(env: Env) -> None:
    _seed(env)
    env.clients.services["macie2"] = Macie(
        [macie_finding("m-1", "exports/cards.csv", types={"CREDIT_CARD_NUMBER": 1})]
    )
    doc = env.run(config(scan_mode="vendor", discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    assert doc["coverage"] == []
    assert {f["source"] for f in doc["findings"]} == {"vendor:macie"}
    stores = {s["name"]: s for s in doc["discovery"]["stores"]}
    assert stores[DATA]["reason"] == "vendor_mode"


def test_macie_not_enabled_is_named(env: Env) -> None:
    _seed(env)
    env.clients.services["macie2"] = Macie([], enabled=False)
    doc = env.run(config(scan_mode="both"))
    assert doc is not None
    valid(doc)
    (cov,) = doc["vendorCoverage"]
    assert (cov["status"], cov["error"]) == ("not_enabled", "AccessDeniedException")
    assert {f["source"] for f in doc["findings"]} == {"scanner"}


def test_the_mode_is_read_from_the_environment() -> None:
    assert read_config({"RESULTS_BUCKET": "r", "SCAN_MODE": "vendor"}).scan_mode == "vendor"
    with pytest.raises(ValueError, match="mode"):
        read_config({"RESULTS_BUCKET": "r", "SCAN_MODE": "maybe"})
