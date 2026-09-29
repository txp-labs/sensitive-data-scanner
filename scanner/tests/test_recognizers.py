"""Stored text through Presidio: the card, SSN, DOB and spoken-digit recognizers
and the context enhancer, on #1067's positives and near-misses."""

from __future__ import annotations

import datetime as dt

import pytest

from sensitive_data_scanner.detect.analyzer import Analysis, Detector
from sensitive_data_scanner.detect.recognizers import card_grouping
from synthetic import (
    CARDS,
    SSN_A,
    SSN_B,
    break_luhn,
    dashed,
    printed,
    spaced,
    spoken_groups,
    with_luhn,
)

NOW = dt.date(2026, 9, 29)


@pytest.fixture(scope="module")
def detector() -> Detector:
    return Detector(now=NOW)


def found(a: Analysis) -> list[tuple[str, str, str]]:
    return [(d.cls, d.via, d.confidence) for d in a.detections]


def test_card_grouping() -> None:
    assert card_grouping("4539148803436467") == "plain"
    assert card_grouping("4539 1488 0343 6467") == "printed"
    assert card_grouping("3487 610593 82174") == "printed"
    assert card_grouping("4 5 3 9") == "spaced_digits"
    assert card_grouping("453 914880 3436467") == "odd"
    assert card_grouping("4539-1488 0343-6467") == "odd"


class TestCards:
    def test_printed_number_counts_alone(self, detector: Detector) -> None:
        assert found(detector.analyze_text(f"note: {printed(CARDS['visa'])}")) == [
            ("card", "shape", "medium")
        ]

    def test_every_brand_with_a_card_word(self, detector: Detector) -> None:
        for brand, pan in CARDS.items():
            assert found(detector.analyze_text(f"card {pan}")) == [("card", "context", "high")], (
                brand
            )

    def test_dashes_amex_and_diners(self, detector: Detector) -> None:
        dashed_mc = "-".join(CARDS["mastercard"][i : i + 4] for i in range(0, 16, 4))
        assert found(detector.analyze_text(f"card {dashed_mc}")) == [("card", "context", "high")]
        assert found(detector.analyze_text(f"amex {printed(CARDS['amex'])}")) == [
            ("card", "context", "high")
        ]
        assert found(detector.analyze_text(f"diners {CARDS['diners']}")) == [
            ("card", "context", "high")
        ]

    def test_context_from_the_caller(self, detector: Detector) -> None:
        a = detector.analyze_text(CARDS["mastercard2"], context=["slots", "cardNumber", "value"])
        assert found(a) == [("card", "context", "high")]
        assert found(detector.analyze_text(f"value={CARDS['jcb']}")) == [
            ("card", "shape", "medium")
        ]

    @pytest.mark.parametrize(
        "text",
        [
            f"card {break_luhn(CARDS['visa'])}",
            f"card {CARDS['visa'][:12]}",
            f"card {CARDS['visa']}{CARDS['visa']}",
            f"card ts={with_luhn('172750000000')}",
            f"id=deadbeef{CARDS['visa']}cafe",
            f"id={CARDS['visa'][:8]}-{CARDS['visa'][8:12]}-4123-8123-123456789012",
            f"{CARDS['visa'][:3]} {CARDS['visa'][3:9]} {CARDS['visa'][9:]}",
            f"values {spaced(CARDS['visa'])}",
            "call +1 (415) 555-0132 or 415.555.0199",
        ],
    )
    def test_near_misses(self, detector: Detector, text: str) -> None:
        assert found(detector.analyze_text(text)) == []

    def test_suppressed_by_order_or_phone(self, detector: Detector) -> None:
        a = detector.analyze_text(f"phone: {with_luhn('441632960961234')}")
        assert (found(a), a.suppressed) == ([], 1)
        a = detector.analyze_text(f"order id {CARDS['visa']}")
        assert (found(a), a.suppressed) == ([], 1)
        assert found(detector.analyze_text(f"order paid by card {CARDS['visa']}")) == [
            ("card", "context", "high")
        ]

    def test_spaced_digits_need_a_card_word(self, detector: Detector) -> None:
        assert found(detector.analyze_text(f"card: {spaced(CARDS['visa'])}")) == [
            ("card", "context", "high")
        ]

    def test_published_test_numbers_are_counted_apart(self, detector: Detector) -> None:
        a = detector.analyze_text("card 4111 1111 1111 1111 and 4242424242424242")
        assert (found(a), a.test_values) == ([], 2)


class TestSsn:
    def test_dashed_with_and_without_a_word(self, detector: Detector) -> None:
        assert found(detector.analyze_text(f"SSN: {dashed(SSN_A)}")) == [
            ("us_ssn", "context", "high")
        ]
        assert found(detector.analyze_text(f"id {dashed(SSN_A)}")) == [
            ("us_ssn", "shape", "medium")
        ]

    def test_bare_nine_digits_only_with_a_word(self, detector: Detector) -> None:
        assert found(detector.analyze_text(f"social security number {SSN_B}")) == [
            ("us_ssn", "context", "high")
        ]
        assert found(detector.analyze_text(f"zip+4 {SSN_B}")) == []

    @pytest.mark.parametrize(
        "bad", ["000-12-3456", "666-12-3456", "912-34-5678", "512-00-7788", "512-43-0000"]
    )
    def test_structural_rules(self, detector: Detector, bad: str) -> None:
        assert found(detector.analyze_text(f"SSN {bad}")) == []

    def test_last_four_is_not_ssn_context_and_samples_are_test_data(
        self, detector: Detector
    ) -> None:
        assert found(detector.analyze_text(f"last four of your social is 7788, ref {SSN_A}")) == []
        a = detector.analyze_text("SSN 078-05-1120")
        assert (found(a), a.test_values) == ([], 1)


class TestDob:
    @pytest.mark.parametrize(
        "text", ["DOB: 04/12/1985", "Date of birth: March 3, 1979", "born 1990-07-21 in Boise"]
    )
    def test_date_next_to_a_dob_word(self, detector: Detector, text: str) -> None:
        assert found(detector.analyze_text(text)) == [("dob", "context", "high")]

    @pytest.mark.parametrize("text", ["invoice date 04/12/1985", "DOB: 04/12/2031"])
    def test_near_misses(self, detector: Detector, text: str) -> None:
        assert found(detector.analyze_text(text)) == []


class TestSpoken:
    def test_spoken_card_with_a_card_word(self, detector: Detector) -> None:
        a = detector.analyze_text(f"my visa is {spoken_groups(CARDS['visa'])}")
        assert found(a) == [("card", "context", "high")]

    def test_spoken_card_with_caller_context(self, detector: Detector) -> None:
        a = detector.analyze_text(spoken_groups(CARDS["visa"]), context=["inputTranscript card"])
        assert found(a) == [("card", "context", "high")]

    def test_spoken_test_card_is_not_a_finding(self, detector: Detector) -> None:
        assert found(detector.analyze_text(spoken_groups("4242424242424242"))) == []

    def test_digits_are_not_counted_twice(self, detector: Detector) -> None:
        a = detector.analyze_text(f"card {CARDS['visa']}")
        assert len(a.detections) == 1
