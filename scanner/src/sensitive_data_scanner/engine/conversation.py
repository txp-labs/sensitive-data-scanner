"""Classify a conversation: prompt carryover, split turns, shape and context.

This is the algorithm spec/README.md defines ("Classification"). The
TypeScript package implements the same algorithm, and both are tested
against every case in vectors/, and against each other.

A `Match` carries a class, a location and a confidence. It never carries
the matched text or its digits.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

from .normalize import Normalized, date_spans, normalize
from .rules import (
    card_brand,
    card_candidates,
    date_digits_shape,
    date_token_shape,
    is_test_card,
    itin_structure_valid,
    luhn_valid,
    shape_pass,
    ssn_structure_valid,
)
from .spec import ClassSpec, Spec

SPEAKERS = ("bot", "agent", "customer")
_FORMATTED_3_2_4 = re.compile(r"[0-9]{3}([ -])[0-9]{2}\1[0-9]{4}", re.A)
_ALNUM = re.compile(r"[A-Za-z0-9]", re.A)


@dataclass(frozen=True)
class Turn:
    speaker: str  # bot | agent | customer
    text: str
    channel: str | None = None  # speech | dtmf | chat
    begin_ms: int | None = None
    end_ms: int | None = None


@dataclass(frozen=True)
class MatchPart:
    """Where one piece of a value sits; a value split across turns has one part per turn."""

    turn: int
    start: int  # in the normalized text of `turn`
    end: int
    orig_start: int  # in the original text of `turn`: what to redact
    orig_end: int


@dataclass(frozen=True)
class Match:
    """One classified value. Offsets only; never the value."""

    cls: str
    via: str  # prompt | shape | context
    confidence: str  # high | medium | low
    turn: int
    start: int  # in the normalized text of `turn`
    end_turn: int
    end: int  # in the normalized text of `end_turn`
    orig_start: int  # in the original text of `turn`
    orig_end: int  # in the original text of `end_turn`
    parts: tuple[MatchPart, ...] = ()

    def __repr__(self) -> str:  # explicit, so no future field can leak a value
        return (
            f"Match(cls={self.cls!r}, via={self.via!r}, confidence={self.confidence!r}, "
            f"turn={self.turn}, start={self.start}, end_turn={self.end_turn}, end={self.end})"
        )


@dataclass(frozen=True)
class Excluded:
    """A value set aside as published test or sample data (counted, not a finding)."""

    cls: str
    turn: int


@dataclass
class Result:
    matches: list[Match] = field(default_factory=list)
    excluded: list[Excluded] = field(default_factory=list)
    suppressed: int = 0


@dataclass
class _Part:
    turn: int
    start: int
    end: int
    digits: str


@dataclass
class _Chain:
    speaker: str
    parts: list[_Part]
    prompted: tuple[str, ...]
    last_end_ms: int | None
    is_date: bool = False
    # A part was given in an answer-window channel (dtmf): the value ends at
    # another speaker's turn.
    answer_window: bool = False

    @property
    def digits(self) -> str:
        return "".join(p.digits for p in self.parts)

    @property
    def first_turn(self) -> int:
        return self.parts[0].turn

    @property
    def last_turn(self) -> int:
        return self.parts[-1].turn


@dataclass(frozen=True)
class _Token:
    start: int
    end: int
    text: str
    is_date: bool


def _glued(norm: str, start: int, end: int) -> bool:
    """A token with a letter or underscore right before or after it is part of a word or an id."""
    before = norm[start - 1] if start > 0 else ""
    after = norm[end] if end < len(norm) else ""
    return any(c == "_" or ("a" <= c.lower() <= "z") for c in (before, after) if c)


def _tokens(norm: str) -> list[_Token]:
    dates = date_spans(norm)
    out = [_Token(s, e, norm[s:e], True) for s, e in dates if not _glued(norm, s, e)]
    for m in re.finditer(r"[0-9]+", norm, re.A):
        if any(s < m.end() and m.start() < e for s, e in dates):
            continue
        if not _glued(norm, m.start(), m.end()):
            out.append(_Token(m.start(), m.end(), m[0], False))
    return sorted(out, key=lambda t: t.start)


def _at_start(norm: str, tok: _Token) -> bool:
    return _ALNUM.search(norm[: tok.start]) is None


def _at_end(norm: str, tok: _Token) -> bool:
    return _ALNUM.search(norm[tok.end :]) is None


def strip_retry(spec: Spec, text: str) -> tuple[str, bool]:
    """The turn text without a leading retry prefix, and whether it had one.

    A prefix's words may be apart by any run of whitespace and . , ! ? ; : in
    the turn, and it matches only at the start ("Sorry, I didn't get that!").
    """
    low = text.replace("\u2019", "'").lstrip(" \t\r\n").lower()
    for rx in spec.retry_res:
        m = rx.match(low)
        if m:
            return low[m.end() :].lstrip(" \t\r\n.,!?;:"), True
    return low, False


def prompt_classes(spec: Spec, text: str) -> tuple[tuple[str, ...], bool]:
    """Classes a bot or agent turn asks for, in the order it names them, and whether it was a retry.

    When phrase matches of two different classes overlap, only the longer one counts.
    """
    body, retry = strip_retry(spec, text)
    hits: list[tuple[int, int, str]] = []
    for name in spec.class_order:
        for rx in spec.classes[name].prompt_res:
            hits.extend(
                (m.start(), m.end(), name) for m in rx.finditer(body) if m.end() > m.start()
            )
    kept = [
        h
        for h in hits
        if not any(
            o[2] != h[2] and o[0] < h[1] and h[0] < o[1] and (o[1] - o[0]) > (h[1] - h[0])
            for o in hits
        )
    ]
    kept.sort(key=lambda h: (h[0], spec.class_order.index(h[2])))
    ordered: list[str] = []
    for _, _, name in kept:
        if name not in ordered:
            ordered.append(name)
    return tuple(ordered), retry


def is_menu_or_question(spec: Spec, text: str) -> bool:
    """Whether a bot or agent turn is a menu or a question ("Reply 1 for more.").

    Such a turn ends any value another speaker is still giving. Matched
    against the same text as prompt phrases.
    """
    body, _ = strip_retry(spec, text)
    return any(rx.search(body) for rx in spec.normalize.menu_or_question_res)


def _context(spec: Spec, turns: list[Turn], first: int, last: int) -> str:
    lo = max(0, first - spec.context_turns_before)
    return "\n".join(t.text for t in turns[lo : last + 1])


def has_context(cls: ClassSpec, context: str) -> bool:
    if cls.context_re is None:
        return False
    for rx in cls.exclusion_res:
        context = rx.sub(" ", context)
    return cls.context_re.search(context) is not None


class _Classifier:
    def __init__(self, spec: Spec, turns: list[Turn], now_year: int) -> None:
        self.spec = spec
        self.turns = turns
        self.now_year = now_year
        self.norms: list[Normalized] = [normalize(t.text, spec.normalize) for t in turns]
        self.result = Result()
        self.open: dict[str, _Chain] = {}

    # -------------------------------------------------------- helpers

    def _match(self, cls: str, via: str, conf: str, chain: _Chain, digit_len: int | None) -> Match:
        first = chain.parts[0]
        if digit_len is None:
            last_part, end = chain.parts[-1], chain.parts[-1].end
        else:
            remaining = digit_len
            last_part, end = chain.parts[0], chain.parts[0].start
            for p in chain.parts:
                last_part = p
                if remaining <= len(p.digits):
                    end = p.start + remaining
                    break
                remaining -= len(p.digits)
        parts: list[MatchPart] = []
        for p in chain.parts:
            p_end = end if p is last_part else p.end
            o_s, o_e = self.norms[p.turn].to_original(p.start, p_end)
            parts.append(MatchPart(p.turn, p.start, p_end, o_s, o_e))
            if p is last_part:
                break
        return Match(
            cls,
            via,
            conf,
            first.turn,
            first.start,
            last_part.turn,
            end,
            parts[0].orig_start,
            parts[-1].orig_end,
            tuple(parts),
        )

    def _complete(self, chain: _Chain) -> bool:
        d = chain.digits
        if chain.prompted:
            for name in chain.prompted:
                cls = self.spec.classes[name]
                if shape_pass(cls, d, self.spec, self.now_year) == "full":
                    return True
            return len(d) >= self._limit(chain)
        if len(d) == 9 and (ssn_structure_valid(d) or itin_structure_valid(d)):
            return True
        return 13 <= len(d) <= 19 and luhn_valid(d) and card_brand(d, self.spec.brands) is not None

    def _limit(self, chain: _Chain) -> int:
        """The most digits a joined value may have."""
        if chain.prompted:
            return max(self._max_digits(self.spec.classes[n]) for n in chain.prompted)
        return 19

    @staticmethod
    def _max_digits(class_spec: ClassSpec) -> int:
        if class_spec.shape.kinds:
            return 8
        return class_spec.shape.digits_max or 19

    # -------------------------------------------------------- evaluation

    def _evaluate(self, chain: _Chain) -> None:
        if chain.prompted and not (chain.is_date and "dob" not in chain.prompted):
            self._evaluate_prompted(chain)
            return
        match, excluded, suppressed = self._unprompted(chain)
        if match is not None:
            self.result.matches.append(match)
        if excluded is not None:
            self.result.excluded.append(excluded)
        if suppressed:
            self.result.suppressed += 1

    def _unprompted(self, chain: _Chain) -> tuple[Match | None, Excluded | None, bool]:
        """Shape and context rules: (match, excluded as test data, suppressed)."""
        spec = self.spec
        context = _context(spec, self.turns, chain.first_turn, chain.last_turn)
        if chain.is_date:
            dob = spec.classes.get("dob")
            part = chain.parts[0]
            token = self.norms[part.turn].text[part.start : part.end]
            if dob and date_token_shape(token, self.now_year) and has_context(dob, context):
                return self._match("dob", "context", "high", chain, None), None, False
            return None, None, False
        d = chain.digits
        card = spec.classes.get("card")
        if card is not None and len(d) >= 13:
            for length in card_candidates(d):
                head = d[:length]
                if not (luhn_valid(head) and card_brand(head, spec.brands)):
                    continue
                if card.test_numbers and is_test_card(head, card):
                    return None, Excluded("card", chain.first_turn), False
                if has_context(card, context):
                    return self._match("card", "context", "high", chain, length), None, False
                if card.suppress_re is not None and card.suppress_re.search(context):
                    return None, None, True
                if card.standalone == "any":
                    return self._match("card", "shape", "medium", chain, length), None, False
                return None, None, False
        ssn = spec.classes.get("us_ssn")
        if ssn is not None and len(d) == 9 and ssn_structure_valid(d):
            if d in ssn.dummy_values:
                return None, Excluded("us_ssn", chain.first_turn), False
            if has_context(ssn, context):
                return self._match("us_ssn", "context", "high", chain, None), None, False
            if ssn.standalone == "formatted" and self._formatted(chain):
                return self._match("us_ssn", "shape", "medium", chain, None), None, False
        itin = spec.classes.get("us_itin")
        if itin is not None and len(d) == 9 and itin_structure_valid(d):
            if d in itin.test_numbers:
                return None, Excluded("us_itin", chain.first_turn), False
            if has_context(itin, context):
                return self._match("us_itin", "context", "high", chain, None), None, False
            if itin.standalone == "formatted" and self._formatted(chain):
                return self._match("us_itin", "shape", "medium", chain, None), None, False
        dob = spec.classes.get("dob")
        if (
            dob is not None
            and len(d) in (6, 8)
            and date_digits_shape(d, self.now_year)
            and has_context(dob, context)
        ):
            return self._match("dob", "context", "high", chain, None), None, False
        return None, None, False

    def _formatted(self, chain: _Chain) -> bool:
        """The value sits in one turn whose original text is exactly ddd-dd-dddd or ddd dd dddd."""
        if len(chain.parts) != 1:
            return False
        part = chain.parts[0]
        o_s, o_e = self.norms[part.turn].to_original(part.start, part.end)
        return _FORMATTED_3_2_4.fullmatch(self.turns[part.turn].text[o_s:o_e]) is not None

    def _evaluate_prompted(self, chain: _Chain) -> None:
        spec = self.spec
        if chain.is_date:
            part = chain.parts[0]
            token = self.norms[part.turn].text[part.start : part.end]
            conf = "high" if date_token_shape(token, self.now_year) else "low"
            self.result.matches.append(self._match("dob", "prompt", conf, chain, None))
            return
        d = chain.digits
        passes = [
            (name, shape_pass(spec.classes[name], d, spec, self.now_year))
            for name in chain.prompted
        ]
        for wanted, conf in (("full", "high"), ("soft", "medium")):
            for name, p in passes:
                if p == wanted:
                    self.result.matches.append(self._match(name, "prompt", conf, chain, None))
                    return
        # Fits no prompted class: a complete value of another class keeps that class.
        other, _, _ = self._unprompted(chain)
        if other is not None:
            self.result.matches.append(other)
            return
        self.result.matches.append(self._match(chain.prompted[0], "prompt", "low", chain, None))

    # -------------------------------------------------------- driver

    def _finish(self, speaker: str) -> None:
        chain = self.open.pop(speaker, None)
        if chain is not None:
            self._evaluate(chain)

    def run(self) -> Result:
        spec = self.spec
        n = spec.normalize
        armed: tuple[str, ...] = ()
        last_armed: tuple[str, ...] = ()
        for idx, turn in enumerate(self.turns):
            prompted: tuple[str, ...] = ()
            if turn.speaker == "customer":
                prompted, armed = armed, ()
            else:
                classes, retry = prompt_classes(spec, turn.text)
                rearm = classes or (last_armed if retry and spec.survive_retry else ())
                if rearm:
                    armed = rearm
                    last_armed = rearm
                # A new prompt, a menu or a question ends any value still being given.
                if rearm or is_menu_or_question(spec, turn.text):
                    for sp in [s for s in self.open if s != turn.speaker]:
                        self._finish(sp)
            # A keypad answer ends at the next turn of another speaker.
            for sp in [s for s, c in self.open.items() if s != turn.speaker and c.answer_window]:
                self._finish(sp)
            norm = self.norms[idx].text
            toks = _tokens(norm)
            begin = turn.begin_ms
            end_ms = turn.end_ms if turn.end_ms is not None else turn.begin_ms
            in_window = turn.channel in n.join_answer_window
            start_at = 0
            carry = self.open.get(turn.speaker)
            if carry is not None:
                first = toks[0] if toks else None
                gap_ok = (
                    carry.last_end_ms is None
                    or begin is None
                    or begin - carry.last_end_ms <= n.join_within_ms
                )
                turns_ok = idx - carry.last_turn - 1 <= n.join_max_intervening
                # Within one answer window, no other speaker's turn may come between the parts.
                joinable = not (in_window or carry.answer_window) or idx == carry.last_turn + 1
                if (
                    joinable
                    and first is not None
                    and len(carry.digits) + len(first.text) <= self._limit(carry)
                    and not first.is_date
                    and _at_start(norm, first)
                    and gap_ok
                    and turns_ok
                    and not (n.join_stop_when_complete and self._complete(carry))
                ):
                    carry.parts.append(_Part(idx, first.start, first.end, first.text))
                    carry.last_end_ms = end_ms
                    carry.answer_window = carry.answer_window or in_window
                    start_at = 1
                    if not (len(toks) == 1 and _at_end(norm, first)):
                        self._finish(turn.speaker)
                else:
                    self._finish(turn.speaker)
            for i in range(start_at, len(toks)):
                tok = toks[i]
                chain = _Chain(
                    turn.speaker,
                    [_Part(idx, tok.start, tok.end, "" if tok.is_date else tok.text)],
                    prompted,
                    end_ms,
                    tok.is_date,
                    in_window,
                )
                if i == len(toks) - 1 and not tok.is_date and _at_end(norm, tok):
                    self.open[turn.speaker] = chain
                else:
                    self._evaluate(chain)
            for sp in [s for s, c in self.open.items() if s != turn.speaker]:
                if idx - self.open[sp].last_turn > n.join_max_intervening:
                    self._finish(sp)
        for sp in list(self.open):
            self._finish(sp)
        self.result.matches.sort(key=lambda m: (m.turn, m.start, m.end_turn, m.end))
        return self.result


def utf16_index(text: str, index: int) -> int:
    """A code-point index in `text` as a UTF-16 code-unit index (the spec's offset unit)."""
    return index + sum(1 for c in text[:index] if ord(c) > 0xFFFF)


def _to_utf16(result: Result, turns: list[Turn], norms: list[Normalized]) -> Result:
    if all(ord(c) <= 0xFFFF for t in turns for c in t.text):
        return result

    def part(p: MatchPart) -> MatchPart:
        n, o = norms[p.turn].text, turns[p.turn].text
        return MatchPart(
            p.turn,
            utf16_index(n, p.start),
            utf16_index(n, p.end),
            utf16_index(o, p.orig_start),
            utf16_index(o, p.orig_end),
        )

    matches = []
    for m in result.matches:
        parts = tuple(part(p) for p in m.parts)
        matches.append(
            Match(
                m.cls,
                m.via,
                m.confidence,
                m.turn,
                parts[0].start,
                m.end_turn,
                parts[-1].end,
                parts[0].orig_start,
                parts[-1].orig_end,
                parts,
            )
        )
    return Result(matches, result.excluded, result.suppressed)


def classify(
    spec: Spec,
    turns: list[Turn],
    now: _dt.date | None = None,
    *,
    utf16: bool = False,
) -> Result:
    """Classify every sensitive value in a conversation. Offsets only, never values.

    Offsets are code-point indexes into the Python strings, or UTF-16 code
    units (the spec's unit, used in findings and vectors) with `utf16=True`.
    """
    for t in turns:
        if t.speaker not in SPEAKERS:
            raise ValueError("speaker must be bot, agent or customer")
    year = (now or _dt.datetime.now(_dt.UTC).date()).year
    classifier = _Classifier(spec, list(turns), year)
    result = classifier.run()
    return _to_utf16(result, list(turns), classifier.norms) if utf16 else result
