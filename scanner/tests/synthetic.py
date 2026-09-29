"""Synthetic test values, ported from txp-labs/mermera-attestation-app#1067.

No number here is real. Card numbers are a made-up body plus a computed Luhn
check digit; SSNs are arbitrary structurally valid numbers chosen for tests.
"""

from __future__ import annotations


def with_luhn(body: str) -> str:
    total = 0
    double = True
    for ch in reversed(body):
        d = int(ch)
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return body + str((10 - total % 10) % 10)


def break_luhn(pan: str) -> str:
    return pan[:-1] + str((int(pan[-1]) + 1) % 10)


CARDS = {
    "visa": with_luhn("453914880343646"),
    "visa13": with_luhn("421873904152"),
    "mastercard": with_luhn("531760928841357"),
    "mastercard2": with_luhn("272005184733691"),
    "amex": with_luhn("34876105938217"),
    "discover": with_luhn("601187340591266"),
    "jcb": with_luhn("354981736250914"),
    "diners": with_luhn("3056418823975"),
    "unionpay": with_luhn("621485903377152"),
    "maestro": with_luhn("675928736145082"),
    "mir": with_luhn("220183749265103"),
}
SSN_A = "512437788"
SSN_B = "274583916"
WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]


def printed(pan: str) -> str:
    if len(pan) == 15:
        return f"{pan[:4]} {pan[4:10]} {pan[10:]}"
    return " ".join(pan[i : i + 4] for i in range(0, len(pan), 4))


def spoken_groups(digits: str, group: int = 4) -> str:
    chunks = [digits[i : i + group] for i in range(0, len(digits), group)]
    return ", ".join(" ".join(WORDS[int(c)] for c in chunk) for chunk in chunks)


def spaced(digits: str) -> str:
    return " ".join(digits)


def dashed(ssn: str) -> str:
    return f"{ssn[:3]}-{ssn[3:5]}-{ssn[5:]}"


def all_values() -> list[str]:
    """Every synthetic value, for the no-leak tests."""
    return [*CARDS.values(), SSN_A, SSN_B]
