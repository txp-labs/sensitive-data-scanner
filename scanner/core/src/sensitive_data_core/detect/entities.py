"""Spec classes and Presidio entity names, and confidence and score levels."""

from __future__ import annotations

# Spec class -> Presidio entity type. CREDIT_CARD, US_SSN and US_ITIN are Presidio's own.
CLASS_TO_ENTITY: dict[str, str] = {
    "card": "CREDIT_CARD",
    "us_ssn": "US_SSN",
    "us_itin": "US_ITIN",
    "dob": "DATE_OF_BIRTH",
    "cvv": "CARD_SECURITY_CODE",
    "pin": "PIN",
    "account_number": "ACCOUNT_NUMBER",
    "us_ssn_last4": "US_SSN_LAST4",
}
ENTITY_TO_CLASS: dict[str, str] = {v: k for k, v in CLASS_TO_ENTITY.items()}

# Presidio scores for our confidence levels, and back.
SCORE: dict[str, float] = {"high": 0.85, "medium": 0.5, "low": 0.3}
# A result kept only to be counted (test data, suppressed): never a finding.
COUNT_ONLY_SCORE = 0.01


def confidence_of(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


# Keys in RecognizerResult.recognition_metadata this package sets.
META_VIA = "sds_via"
META_CONFIDENCE = "sds_confidence"
META_ENGINE = "sds_engine"  # set by the conversation engine: context already judged
META_NEEDS_CONTEXT = "sds_needs_context"
META_EXCLUDED = "sds_excluded"  # "test": published test or sample data
META_SUPPRESSED = "sds_suppressed"
META_VALUE_KEY = "sds_value_key"  # keyed hash of the value, for counting distinct values
META_MATCH_ID = "sds_match_id"  # parts of one value split across turns share it
META_TURN = "sds_turn"
