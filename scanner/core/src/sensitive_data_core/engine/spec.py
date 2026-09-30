"""Load the sensitive-data spec (spec/classes.yaml and spec/normalize.yaml).

The spec is the contract shared with the TypeScript package and with
Stugum's call engine. This module reads it into typed, immutable objects;
nothing here holds or logs a scanned value.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

SPEC_VERSION = "0.6"

WS = "[ \\t\\r\\n]+"

# What may separate the words of a retry prefix in a turn: whitespace and . , ! ? ; :
RETRY_SEP = "[ \\t\\r\\n.,!?;:]"

# Every prompt phrase matches only with neither a letter nor a digit on each side.
BOUNDARY_BEFORE = "(?<![A-Za-z0-9])"
BOUNDARY_AFTER = "(?![A-Za-z0-9])"


@dataclass(frozen=True)
class Shape:
    digits_min: int | None = None
    digits_max: int | None = None
    rules: tuple[str, ...] = ()
    soft_rules: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClassSpec:
    name: str
    severity: str
    prompt_phrases: tuple[str, ...]
    shape: Shape
    standalone: str = "never"
    context_words: tuple[str, ...] = ()
    context_exclusions: tuple[str, ...] = ()
    suppress_words: tuple[str, ...] = ()
    dummy_values: frozenset[str] = frozenset()
    test_numbers: frozenset[str] = frozenset()
    test_numbers_max_distinct_digits: int = 0
    prompt_res: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    context_re: re.Pattern[str] | None = field(default=None, repr=False)
    exclusion_res: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    suppress_re: re.Pattern[str] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class BrandRule:
    brand: str
    ranges: tuple[tuple[int, int, int], ...]  # (prefix length, from, to)
    lengths: frozenset[int]


@dataclass(frozen=True)
class DateTables:
    months: dict[str, int]
    ordinals: dict[str, int]
    units: dict[str, int]
    teens: dict[str, int]
    tens: dict[str, int]
    year_min: int
    year_max: int


@dataclass(frozen=True)
class NormalizeSpec:
    terminators: tuple[str, ...]
    dates: DateTables
    digit_words: dict[str, int]
    zero_only_next_to_digits: frozenset[str]
    multipliers: dict[str, int]
    fillers: frozenset[str]
    separators: frozenset[str]
    join_within_ms: int
    join_stop_when_complete: bool
    join_max_intervening: int
    # Channels whose values end at the next turn of another speaker (a keypad answer window).
    join_answer_window: frozenset[str]
    # A bot or agent turn matching one of these is a menu or a question: it ends
    # other speakers' values.
    menu_or_question_res: tuple[re.Pattern[str], ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class Spec:
    spec_version: str
    classes: dict[str, ClassSpec]
    class_order: tuple[str, ...]
    retry_prefixes: tuple[str, ...]
    retry_res: tuple[re.Pattern[str], ...] = field(repr=False)
    carryover_turns: int
    survive_retry: bool
    context_turns_before: int
    brands: tuple[BrandRule, ...]
    normalize: NormalizeSpec


def prompt_regex(phrase: str) -> re.Pattern[str]:
    """A prompt phrase with the spec's boundary: no letter or digit on either side."""
    return re.compile(BOUNDARY_BEFORE + "(?:" + phrase + ")" + BOUNDARY_AFTER, re.I | re.A)


def retry_regex(prefix: str) -> re.Pattern[str]:
    """A retry prefix at the start of a turn: its words, apart by whitespace or . , ! ? ; :"""
    words = [w for w in re.split(RETRY_SEP + "+", prefix.lower()) if w]
    body = (RETRY_SEP + "+").join(re.escape(w) for w in words)
    return re.compile("^" + RETRY_SEP + "*" + body + BOUNDARY_AFTER, re.I | re.A)


def phrase_regex(words: list[str] | tuple[str, ...]) -> re.Pattern[str] | None:
    """Context or suppress words as one regex: whole words, any whitespace between."""
    if not words:
        return None
    alts = []
    for w in sorted(words, key=lambda s: (-len(s), s)):
        parts = [re.escape(p) for p in w.split()]
        alts.append(WS.join(parts))
    return re.compile(r"\b(?:" + "|".join(alts) + r")\b", re.I | re.A)


def _digits(v: Any) -> tuple[int | None, int | None]:
    if v is None:
        return None, None
    if isinstance(v, int):
        return v, v
    lo, hi = v
    return int(lo), int(hi)


def _class(name: str, raw: dict[str, Any]) -> ClassSpec:
    shape_raw = raw.get("shape") or {}
    lo, hi = _digits(shape_raw.get("digits"))
    shape = Shape(
        digits_min=lo,
        digits_max=hi,
        rules=tuple(shape_raw.get("rules") or ()),
        soft_rules=tuple(shape_raw.get("softRules") or ()),
        kinds=tuple(shape_raw.get("kinds") or ()),
    )
    phrases = tuple(raw.get("promptPhrases") or ())
    exclusions = tuple(raw.get("contextExclusions") or ())
    return ClassSpec(
        name=name,
        severity=raw["severity"],
        prompt_phrases=phrases,
        shape=shape,
        standalone=raw.get("standalone", "never"),
        context_words=tuple(raw.get("contextWords") or ()),
        context_exclusions=exclusions,
        suppress_words=tuple(raw.get("suppressWords") or ()),
        dummy_values=frozenset(raw.get("dummyValues") or ()),
        test_numbers=frozenset(raw.get("testNumbers") or ()),
        test_numbers_max_distinct_digits=int(raw.get("testNumbersMaxDistinctDigits") or 0),
        prompt_res=tuple(prompt_regex(p) for p in phrases),
        context_re=phrase_regex(raw.get("contextWords") or []),
        exclusion_res=tuple(re.compile(p, re.I | re.A) for p in exclusions),
        suppress_re=phrase_regex(raw.get("suppressWords") or []),
    )


def _brand(raw: dict[str, Any]) -> BrandRule:
    ranges = []
    for p in raw["prefixes"]:
        lo, _, hi = str(p).partition("-")
        hi = hi or lo
        ranges.append((len(lo), int(lo), int(hi)))
    return BrandRule(raw["brand"], tuple(ranges), frozenset(int(n) for n in raw["lengths"]))


def _step(steps: list[dict[str, Any]], name: str) -> Any:
    for s in steps:
        if name in s:
            return s[name]
    raise ValueError("normalize.yaml is missing a step")


def _normalize(raw: dict[str, Any]) -> NormalizeSpec:
    steps = raw["steps"]
    d = _step(steps, "spoken_dates_to_iso")
    words = _step(steps, "number_words_to_digits")
    join = _step(steps, "join_same_speaker_turns")
    return NormalizeSpec(
        terminators=tuple(_step(steps, "strip_keypad_terminator")),
        dates=DateTables(
            months={k: int(v) for k, v in d["months"].items()},
            ordinals={k: int(v) for k, v in d["ordinals"].items()},
            units={k: int(v) for k, v in d["units"].items()},
            teens={k: int(v) for k, v in d["teens"].items()},
            tens={k: int(v) for k, v in d["tens"].items()},
            year_min=int(d["yearRange"][0]),
            year_max=int(d["yearRange"][1]),
        ),
        digit_words={k: int(v) for k, v in words["words"].items()},
        zero_only_next_to_digits=frozenset(words.get("zeroOnlyNextToDigits") or ()),
        multipliers={k: int(v) for k, v in words["multipliers"].items()},
        fillers=frozenset(_step(steps, "drop_fillers_between_digits")),
        separators=frozenset(_step(steps, "collapse_digit_separators")),
        join_within_ms=int(float(join["withinSeconds"]) * 1000),
        join_stop_when_complete=bool(join.get("stopWhenClassComplete", True)),
        join_max_intervening=int(join.get("maxInterveningTurns", 0)),
        join_answer_window=frozenset(join.get("answerWindowChannels") or ()),
        menu_or_question_res=tuple(
            re.compile(p, re.I | re.A) for p in join.get("menuOrQuestionTurns") or ()
        ),
    )


def spec_dir() -> Path:
    """Where the spec files are: $SDS_SPEC_DIR, the packaged copy, or the repository."""
    env = os.environ.get("SDS_SPEC_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    packaged = here.parent.parent / "spec_data"
    if (packaged / "classes.yaml").is_file():
        return packaged
    for parent in here.parents:
        candidate = parent / "spec"
        if (candidate / "classes.yaml").is_file():
            return candidate
    raise FileNotFoundError("spec/classes.yaml not found; set SDS_SPEC_DIR")


def parse_spec(classes_raw: dict[str, Any], normalize_raw: dict[str, Any]) -> Spec:
    for raw in (classes_raw, normalize_raw):
        if str(raw.get("specVersion")) != SPEC_VERSION:
            raise ValueError("unsupported specVersion")
    classes = {name: _class(name, c) for name, c in classes_raw["classes"].items()}
    carry = classes_raw.get("promptCarryover") or {}
    retry_prefixes = tuple(p.lower() for p in classes_raw.get("retryPrefixes") or ())
    return Spec(
        spec_version=SPEC_VERSION,
        classes=classes,
        class_order=tuple(classes),
        retry_prefixes=retry_prefixes,
        retry_res=tuple(retry_regex(p) for p in retry_prefixes),
        carryover_turns=int(carry.get("turns", 1)),
        survive_retry=bool(carry.get("surviveRetry", True)),
        context_turns_before=int((classes_raw.get("contextWindow") or {}).get("turnsBefore", 2)),
        brands=tuple(_brand(b) for b in classes_raw.get("cardBrands") or ()),
        normalize=_normalize(normalize_raw),
    )


@cache
def load_spec(directory: str | None = None) -> Spec:
    base = Path(directory) if directory else spec_dir()
    with (base / "classes.yaml").open(encoding="utf-8") as f:
        classes_raw = yaml.safe_load(f)
    with (base / "normalize.yaml").open(encoding="utf-8") as f:
        normalize_raw = yaml.safe_load(f)
    return parse_spec(classes_raw, normalize_raw)
