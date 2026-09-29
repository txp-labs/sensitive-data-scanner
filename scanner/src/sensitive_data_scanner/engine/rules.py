"""Shape rules named in spec/classes.yaml: Luhn, IIN, SSN structure, dates.

Pure functions over digit strings. They return booleans or a brand name,
never the digits they were given.
"""

from __future__ import annotations

import re

from .spec import BrandRule, ClassSpec, Spec

_DIGITS = re.compile(r"[0-9]+", re.A)


def luhn_valid(digits: str) -> bool:
    if not digits or not _DIGITS.fullmatch(digits):
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def card_brand(digits: str, brands: tuple[BrandRule, ...]) -> str | None:
    """The brand whose IIN range and length the number falls in, or None."""
    if not _DIGITS.fullmatch(digits) or not 13 <= len(digits) <= 19:
        return None
    for rule in brands:
        for length, lo, hi in rule.ranges:
            prefix = int(digits[:length])
            if lo <= prefix <= hi:
                return rule.brand if len(digits) in rule.lengths else None
    return None


def is_test_card(digits: str, card: ClassSpec) -> bool:
    if digits in card.test_numbers:
        return True
    limit = card.test_numbers_max_distinct_digits
    return limit > 0 and len(set(digits)) <= limit


def ssn_structure_valid(digits: str) -> bool:
    """AAA-GG-SSSS: area not 000, 666 or 900-999; group not 00; serial not 0000."""
    if len(digits) != 9 or not _DIGITS.fullmatch(digits):
        return False
    area = int(digits[:3])
    if area in {0, 666} or area >= 900:
        return False
    return digits[3:5] != "00" and digits[5:] != "0000"


def _leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def valid_date(year: int, month: int, day: int) -> bool:
    if not 1 <= month <= 12 or day < 1:
        return False
    days = [31, 29 if _leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return day <= days[month - 1]


def plausible_birth_date(year: int, month: int, day: int, now_year: int) -> bool:
    return 1900 <= year <= now_year and valid_date(year, month, day)


def _two_digit_year(yy: int, now_year: int) -> int:
    """A two-digit birth year: this century if not in the future, else last century."""
    century = now_year - now_year % 100
    year = century + yy
    return year if year <= now_year else year - 100


def date_digits_shape(digits: str, now_year: int) -> bool:
    """date_mmddyy (6 digits) or date_mmddyyyy (8 digits), a plausible birth date."""
    if len(digits) == 6:
        mm, dd, yy = int(digits[:2]), int(digits[2:4]), int(digits[4:])
        return plausible_birth_date(_two_digit_year(yy, now_year), mm, dd, now_year)
    if len(digits) == 8:
        mm, dd, yyyy = int(digits[:2]), int(digits[2:4]), int(digits[4:])
        return plausible_birth_date(yyyy, mm, dd, now_year)
    return False


ISO_DATE = re.compile(r"(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])", re.A)
SLASHED_DATE = re.compile(r"(?<![0-9])([0-9]{1,2})/([0-9]{1,2})/([0-9]{4}|[0-9]{2})(?![0-9])", re.A)


def date_token_shape(token: str, now_year: int) -> bool:
    """date_iso or date_slashed (m/d/yy or m/d/yyyy), a plausible birth date."""
    m = ISO_DATE.fullmatch(token)
    if m:
        return plausible_birth_date(int(m[1]), int(m[2]), int(m[3]), now_year)
    m = SLASHED_DATE.fullmatch(token)
    if m:
        year = int(m[3])
        if len(m[3]) == 2:
            year = _two_digit_year(year, now_year)
        return plausible_birth_date(year, int(m[1]), int(m[2]), now_year)
    return False


def digits_in_range(cls: ClassSpec, n: int) -> bool:
    lo, hi = cls.shape.digits_min, cls.shape.digits_max
    return lo is not None and hi is not None and lo <= n <= hi


def card_candidates(digits: str) -> list[int]:
    """Lengths to try for a card: the whole run if 13-19 digits, then shorter heads."""
    n = len(digits)
    out = [n] if 13 <= n <= 19 else []
    out.extend(range(min(19, n - 1), 12, -1))
    return out


def shape_pass(cls: ClassSpec, digits: str, spec: Spec, now_year: int) -> str:
    """How a digit run fits a class's shape: "full", "soft" (only soft rules fail) or "none"."""
    rules = cls.shape.rules
    if cls.shape.kinds:
        return "full" if date_digits_shape(digits, now_year) else "none"
    if cls.name == "card" or "luhn" in rules:
        best = "none"
        for length in card_candidates(digits):
            head = digits[:length]
            if not luhn_valid(head):
                continue
            if "iin_known" in rules and card_brand(head, spec.brands) is None:
                # Only the whole run can be a soft pass; a head must pass in full.
                if length == len(digits) and "iin_known" in cls.shape.soft_rules:
                    best = "soft"
                continue
            return "full"
        return best
    if not digits_in_range(cls, len(digits)):
        return "none"
    if any(r.startswith(("area_", "group_", "serial_")) for r in rules):
        return "full" if ssn_structure_valid(digits) else "none"
    return "full"
