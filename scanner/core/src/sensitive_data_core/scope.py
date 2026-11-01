"""What the findings may mean: the rules and laws they may bring into scope (1.15).

A hint is guidance for the people who decide, never a verdict: a card number found
in a call transcript suggests PCI DSS may apply to the systems that wrote and store
it; whether it does is the assessor's call. Each hint names the classes behind it,
how many locations hold them and how many of those are unencrypted at rest, what
may apply, what leaving the data in place may mean, and who decides. Every string
is a constant or a count: a hint never holds a value, a name or a location.

The scanner finds no health information, so HIPAA is never suggested from findings
alone. A deployment that holds health information says so with `HEALTH_DATA=on`,
and then Social Security numbers, dates of birth and account numbers also carry
the HIPAA hint.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

HEALTH_DATA = "HEALTH_DATA"
_ON = ("on", "true", "1", "yes")


@dataclass(frozen=True)
class Rule:
    framework: str
    name: str
    classes: tuple[str, ...]
    may_apply: str
    if_left: str
    decided_by: str
    needs_health_data: bool = False


PCI_DSS = Rule(
    framework="pci_dss",
    name="PCI DSS",
    classes=("card", "cvv", "pin"),
    may_apply=(
        "Payment card data was found. PCI DSS may apply to the systems that store it, to "
        "the systems that wrote it there, such as a contact center or an application, and "
        "to the systems connected to them."
    ),
    if_left=(
        "Left in place, every system and person that can read these locations may count as "
        "part of your cardholder data environment, which widens what an assessment covers. "
        "Removing the data, or masking it where it is written, can keep them out."
    ),
    decided_by=(
        "Your Qualified Security Assessor (QSA) or acquiring bank decides whether PCI DSS "
        "applies, and to which systems."
    ),
)
# Added to the PCI DSS hint when a card verification code or a PIN was found: the one case
# where the standard leaves no room, whatever the encryption.
PCI_NEVER_KEPT = (
    "Card verification codes or PINs were also found. PCI DSS does not allow keeping these "
    "after a payment is authorized, even encrypted (requirement 3.3.1)."
)
US_BREACH = Rule(
    framework="us_breach_notification",
    name="US breach-notification laws",
    classes=("us_ssn", "us_itin", "account_number", "card"),
    may_apply=(
        "Social Security numbers, ITINs, account numbers or card numbers were found. US state "
        "breach-notification laws generally treat a Social Security number or ITIN kept "
        "with a person's name as personal information, and an account or card number too "
        "when it is kept with the code or password that opens the account. If they were "
        "exposed, you may have to notify the people affected and, in some states, "
        "regulators. If your business is a financial "
        "institution under the Gramm-Leach-Bliley Act, which includes lenders and tax "
        "preparers, the FTC Safeguards Rule may also apply."
    ),
    if_left=(
        "Left in place, each copy is one more place an exposure could start, and one more "
        "place to search and report on if one happens. Many of these laws ease the duty to "
        "notify when the exposed data was encrypted and the key was not exposed with it."
    ),
    decided_by=(
        "Your legal counsel decides which laws apply. It depends on where the people "
        "affected live, not only on where your business is."
    ),
)
HIPAA = Rule(
    framework="hipaa",
    name="HIPAA",
    classes=("us_ssn", "dob", "account_number"),
    may_apply=(
        "This deployment says it holds health information (HEALTH_DATA is on). Social "
        "Security numbers, dates of birth and account numbers kept with health information "
        "are protected health information under HIPAA, if your organization is a covered "
        "entity or a business associate of one."
    ),
    if_left=(
        "Left in place, an exposure of these locations may be a breach you have to report "
        "to the people affected and to the US Department of Health and Human Services."
    ),
    decided_by="Your privacy officer or legal counsel decides whether HIPAA applies.",
    needs_health_data=True,
)
RULES = (PCI_DSS, US_BREACH, HIPAA)

# The classes that would carry the HIPAA hint with HEALTH_DATA on: when one is found and it
# is off, the report says how to turn it on.
HEALTH_CLASSES = frozenset(HIPAA.classes)

DISCLAIMER = (
    "These are hints for the people who decide, never a verdict, and not legal advice. They "
    "come only from the kinds of data found, not from what your business does."
)


def health_data_declared(env: Mapping[str, str] | None = None) -> bool:
    """Whether the deployment says it holds health information (`HEALTH_DATA`, off by
    default): on, off, true, false, 1, 0, yes or no."""
    value = (os.environ if env is None else env).get(HEALTH_DATA, "")
    return value.strip().lower() in _ON


def scope_hints(findings: Iterable[Mapping[str, Any]], *, health_data: bool) -> dict[str, Any]:
    """The document's `scopeHints` (1.15): `healthData`, as declared, and `hints`, one per
    rule whose classes were found, in the order of `RULES`."""
    rows = list(findings)
    hints: list[dict[str, Any]] = []
    for rule in RULES:
        if rule.needs_health_data and not health_data:
            continue
        hit = [f for f in rows if f.get("class") in rule.classes]
        if not hit:
            continue
        found = sorted({str(f["class"]) for f in hit}, key=rule.classes.index)
        may_apply = rule.may_apply
        if rule is PCI_DSS and {"cvv", "pin"} & set(found):
            may_apply = f"{may_apply} {PCI_NEVER_KEPT}"
        hints.append(
            {
                "framework": rule.framework,
                "name": rule.name,
                "classes": found,
                "locations": len({f.get("id") for f in hit}),
                "unencryptedLocations": len(
                    {f.get("id") for f in hit if f.get("atRestEncryption") == "none"}
                ),
                "mayApply": may_apply,
                "ifLeft": rule.if_left,
                "decidedBy": rule.decided_by,
            }
        )
    return {"healthData": health_data, "hints": hints}
