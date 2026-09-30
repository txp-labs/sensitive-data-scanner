"""Context goes to the value it labels, and no further (#75, found by the benchmark).

- A CSV column's name is context for that column's cells only.
- A JSON value's context is its own key path and the labels of the objects that hold it,
  not every key in the document.
- A card number is never a slice of a longer run of digit groups.
- A date's context window stops at the nearest other date.

Every value is made up.
"""

from __future__ import annotations

import datetime as dt
import json

from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.scan.item import csv_cells, scan_item_text
from synthetic import CARDS, SSN_A, SSN_B, dashed, printed

DET = Detector(now=dt.date(2026, 9, 29))
ROUTING = "021000089"  # a made-up ABA-shaped number that is also a valid SSN shape
ITINISH = "912701234"


def classes(name: str, text: str) -> dict[str, int]:
    return {c: f.occurrences for c, f in scan_item_text(name, text, DET).findings.items()}


# ---------------------------------------------------------------- CSV


def test_a_csv_column_name_is_context_for_its_own_cells_only() -> None:
    text = (
        "employee_id,ssn,date_of_birth,hire_date,routing_number,account_number\n"
        f"E100001,{SSN_A},03/14/1985,04/01/2019,{ROUTING},{ITINISH}\n"
        f"E100002,{dashed(SSN_B)},1979-07-04,2021-10-11,{ROUTING},{ITINISH}\n"
    )
    item = scan_item_text("hr/employees.csv", text, DET)
    assert {c: f.occurrences for c, f in item.findings.items()} == {"us_ssn": 2, "dob": 2}
    assert item.findings["us_ssn"].confidence == "high"
    assert item.findings["dob"].confidence == "high"
    # The offsets point at the cells' values in the object's own text.
    for f in item.findings.values():
        for o in f.offsets:
            assert text[o.start : o.end] in (SSN_A, dashed(SSN_B), "03/14/1985", "1979-07-04")


def test_quoted_cells_tab_separated_and_crlf() -> None:
    card = CARDS["visa"]
    text = f'name,"card, number"\r\n"Placeholder, Testy","{printed(card)}"\r\n'
    item = scan_item_text("x.csv", text, DET)
    assert item.findings["card"].occurrences == 1
    assert item.findings["card"].confidence == "high"
    o = item.findings["card"].offsets[0]
    assert text[o.start : o.end] == printed(card)
    tsv = f"ssn\trouting\n{SSN_A}\t{ROUTING}\n"
    assert classes("x.tsv", tsv) == {"us_ssn": 1}


def test_a_value_never_spans_two_cells() -> None:
    # Two cells that together look like a card: each alone is not one.
    card = CARDS["mastercard"]
    assert classes("x.csv", f"a,b\n{card[:8]},{card[8:]}\n") == {}


def test_csv_cells_positions() -> None:
    text = 'a,"b ""q"", c",\nd\r\n"e\nf"'
    cells = [(r, c, text[s:e]) for r, c, s, e in csv_cells(text, ",")]
    assert cells == [
        (0, 0, "a"),
        (0, 1, 'b ""q"", c'),
        (0, 2, ""),
        (1, 0, "d"),
        (2, 0, "e\nf"),
    ]


# ---------------------------------------------------------------- JSON


def test_a_json_key_is_context_for_its_own_value_only() -> None:
    record = {
        "timestamp": "2026-09-28T03:00:00.123Z",
        "requestId": "made-up-request",
        "customer": {"dateOfBirth": "1985-03-14", "createdAt": "2024-05-01"},
        "ssn": SSN_A,
        "routingNumber": ROUTING,
    }
    assert classes("fn.jsonl", json.dumps(record)) == {"dob": 1, "us_ssn": 1}


def test_a_label_still_names_its_value() -> None:
    doc = {"fields": [{"label": "SSN", "value": SSN_A}, {"label": "Zip", "value": "837021234"}]}
    assert classes("form.json", json.dumps(doc)) == {"us_ssn": 1}
    doc2 = {"kind": "Date of birth", "data": {"text": "1985-03-14"}}
    assert classes("form.json", json.dumps(doc2)) == {"dob": 1}


# ---------------------------------------------------------------- card in a digit run


def test_a_card_is_not_a_slice_of_a_longer_run_of_groups() -> None:
    card = CARDS["visa"]
    groups = printed(card)
    for text in (
        f"USPS 9400 1111 {groups} 00",  # the middle of a 22-digit tracking number
        f"IBAN DE44 {groups} 31",
        f"Ref 12 {groups}",
        f"{groups} 0000",
        f"{groups}-0000 shipped",
    ):
        assert "card" not in classes("t.txt", text), text


def test_a_card_followed_by_its_expiry_or_code_still_counts() -> None:
    groups = printed(CARDS["visa"])
    for text in (f"card {groups} 12/27", f"card {groups} 123", f"card {groups}, exp 04/29"):
        assert classes("t.txt", text) == {"card": 1}, text


# ---------------------------------------------------------------- dates


def test_a_dob_word_belongs_to_the_nearest_date() -> None:
    text = "My date of birth is 03/14/1985, charged on 09/03/2026 and again 09/04/2026."
    assert classes("t.txt", text) == {"dob": 1}
    item = scan_item_text("t.txt", text, DET)
    o = item.findings["dob"].offsets[0]
    assert text[o.start : o.end] == "03/14/1985"
    # A DOB word after its date still counts.
    assert classes("t.txt", "Signed 09/01/2026. 1985-03-14 (date of birth)") == {"dob": 1}
