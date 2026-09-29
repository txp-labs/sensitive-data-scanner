"""Normalization of one conversation turn (spec/normalize.yaml).

The output is the normalized text plus, for every normalized character, the
range of the original text it came from, so a span found in the normalized
text can be mapped back and redacted in the original. The steps, and the
exact behavior of each, are defined in spec/README.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import ISO_DATE, SLASHED_DATE, valid_date
from .spec import DateTables, NormalizeSpec

_WS_CHARS = " \t\r\n"
_WS = "[ \\t\\r\\n]+"


@dataclass(frozen=True)
class Char:
    c: str
    s: int  # original start (inclusive)
    e: int  # original end (exclusive)


@dataclass(frozen=True)
class Normalized:
    text: str
    chars: tuple[Char, ...]

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """The original range a normalized span [start, end) came from."""
        if start >= end:
            raise ValueError("empty span")
        return self.chars[start].s, self.chars[end - 1].e


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_alnum(c: str) -> bool:
    return _is_digit(c) or ("a" <= c <= "z") or ("A" <= c <= "Z")


def _text(chars: list[Char]) -> str:
    return "".join(ch.c for ch in chars)


def _replace(chars: list[Char], start: int, end: int, out: str) -> list[Char]:
    s, e = chars[start].s, chars[end - 1].e
    return [*chars[:start], *(Char(c, s, e) for c in out), *chars[end:]]


# ------------------------------------------------------------ step 1


def strip_keypad_terminator(chars: list[Char], terminators: tuple[str, ...]) -> list[Char]:
    out: list[Char] = []
    for i, ch in enumerate(chars):
        if ch.c in terminators and out and _is_digit(out[-1].c):
            nxt = chars[i + 1].c if i + 1 < len(chars) else ""
            if not nxt or not _is_alnum(nxt):
                continue
        out.append(ch)
    return out


# ------------------------------------------------------------ step 2


def _alt(words: list[str]) -> str:
    return "|".join(re.escape(w) for w in sorted(words, key=lambda w: (-len(w), w)))


class _DateGrammar:
    def __init__(self, t: DateTables) -> None:
        self.t = t
        ord19 = [w for w, v in t.ordinals.items() if v <= 9]
        tens_day = [w for w, v in t.tens.items() if v in (20, 30)]
        century = [w for w, v in {**t.teens, **t.tens}.items() if v in (19, 20)]
        month = f"(?:{_alt(list(t.months))})\\.?"
        day = (
            f"(?:(?:{_alt(tens_day)})(?:-|{_WS})(?:{_alt(ord19)}|{_alt(list(t.units))})"
            f"|{_alt(list(t.ordinals))}|{_alt(list(t.teens))}|{_alt(list(t.units))}"
            f"|{_alt(tens_day)}|[0-9]{{1,2}}(?:st|nd|rd|th)?)"
        )
        yy = (
            f"(?:{_alt(list(t.teens))}"
            f"|(?:{_alt(list(t.tens))})(?:(?:-|{_WS})(?:{_alt(list(t.units))}))?"
            f"|(?:oh|o)(?:-|{_WS})(?:{_alt(list(t.units))})|hundred)"
        )
        yy2 = (
            f"(?:{_alt(list(t.teens))}"
            f"|(?:{_alt(list(t.tens))})(?:(?:-|{_WS})(?:{_alt(list(t.units))}))?"
            f"|{_alt(list(t.units))})"
        )
        year = (
            f"(?:[0-9]{{4}}|(?:{_alt(century)})(?:-|{_WS}){yy}"
            f"|two{_WS}thousand(?:(?:{_WS}and)?{_WS}{yy2})?)"
        )
        sep = f"(?:,?{_WS})"
        a = f"({month}){sep}(?:the{_WS})?({day}){sep}({year})"
        b = f"(?:the{_WS})?({day}){_WS}(?:of{_WS})?({month}){sep}({year})"
        self.regex = re.compile(f"\\b(?:{a}|{b})\\b", re.I | re.A)

    def _words(self, s: str) -> list[str]:
        return [w for w in re.split(r"[ \t\r\n\-]+", s.lower()) if w]

    def month(self, s: str) -> int:
        return self.t.months[s.lower().rstrip(".")]

    def day(self, s: str) -> int:
        m = re.fullmatch(r"([0-9]{1,2})(?:st|nd|rd|th)?", s, re.I | re.A)
        if m:
            return int(m[1])
        total = 0
        for w in self._words(s):
            total += (
                self.t.ordinals.get(w)
                or self.t.units.get(w)
                or self.t.teens.get(w)
                or self.t.tens.get(w)
                or 0
            )
        return total

    def year(self, s: str) -> int:
        if re.fullmatch(r"[0-9]{4}", s, re.A):
            return int(s)
        words = self._words(s)
        if words[:2] == ["two", "thousand"]:
            rest = [w for w in words[2:] if w != "and"]
            return 2000 + self._small(rest)
        century = self.t.teens.get(words[0]) or self.t.tens.get(words[0]) or 0
        rest = words[1:]
        if rest == ["hundred"]:
            return century * 100
        if rest and rest[0] in ("oh", "o"):
            rest = rest[1:]
        return century * 100 + self._small(rest)

    def _small(self, words: list[str]) -> int:
        t = self.t
        return sum(t.teens.get(w) or t.tens.get(w) or t.units.get(w) or 0 for w in words)


_GRAMMARS: dict[int, _DateGrammar] = {}


def _grammar(t: DateTables) -> _DateGrammar:
    g = _GRAMMARS.get(id(t))
    if g is None:
        g = _DateGrammar(t)
        _GRAMMARS[id(t)] = g
    return g


def spoken_dates_to_iso(chars: list[Char], t: DateTables) -> list[Char]:
    g = _grammar(t)
    text = _text(chars)
    out: list[Char] = []
    pos = 0
    for m in g.regex.finditer(text):
        if m[1] is not None:
            month_s, day_s, year_s = m[1], m[2], m[3]
        else:
            day_s, month_s, year_s = m[4], m[5], m[6]
        month, day, year = g.month(month_s), g.day(day_s), g.year(year_s)
        if not (t.year_min <= year <= t.year_max and valid_date(year, month, day)):
            continue
        out.extend(chars[pos : m.start()])
        s, e = chars[m.start()].s, chars[m.end() - 1].e
        out.extend(Char(c, s, e) for c in f"{year:04d}-{month:02d}-{day:02d}")
        pos = m.end()
    out.extend(chars[pos:])
    return out


# ------------------------------------------------------------ step 3

_WORD = re.compile(r"[A-Za-z]+", re.A)


def number_words_to_digits(chars: list[Char], n: NormalizeSpec) -> list[Char]:
    text = _text(chars)
    tokens = [(m.start(), m.end(), m[0].lower()) for m in _WORD.finditer(text)]

    def skip_ws(i: int) -> int:
        while i < len(text) and text[i] in _WS_CHARS:
            i += 1
        return i

    def single_digit_at(i: int) -> bool:
        return (
            i < len(text)
            and _is_digit(text[i])
            and (i == 0 or not _is_digit(text[i - 1]))
            and (i + 1 >= len(text) or not _is_digit(text[i + 1]))
        )

    def word_at(i: int) -> tuple[int, int, str] | None:
        for tok in tokens:
            if tok[0] == i:
                return tok
        return None

    out: list[Char] = []
    pos = 0
    k = 0
    while k < len(tokens):
        start, end, w = tokens[k]
        replacement: str | None = None
        consumed_end = end
        if w in n.multipliers:
            j = skip_ws(end)
            nxt = word_at(j)
            if nxt is not None and nxt[2] in n.digit_words:
                replacement = str(n.digit_words[nxt[2]]) * n.multipliers[w]
                consumed_end = nxt[1]
                k += 1  # the digit word is consumed too
            elif single_digit_at(j):
                replacement = text[j] * n.multipliers[w]
                consumed_end = j + 1
        elif w in n.digit_words:
            if w in n.zero_only_next_to_digits:
                emitted = "".join(ch.c for ch in out) + text[pos:start]
                before = emitted.rstrip(_WS_CHARS)[-1:]
                j = skip_ws(end)
                nxt = word_at(j)
                next_is_digit = (j < len(text) and _is_digit(text[j])) or (
                    nxt is not None and (nxt[2] in n.digit_words or nxt[2] in n.multipliers)
                )
                if (before and _is_digit(before)) or next_is_digit:
                    replacement = "0"
            else:
                replacement = str(n.digit_words[w])
        if replacement is not None:
            out.extend(chars[pos:start])
            s, e = chars[start].s, chars[consumed_end - 1].e
            out.extend(Char(c, s, e) for c in replacement)
            pos = consumed_end
        k += 1
    out.extend(chars[pos:])
    return out


# ------------------------------------------------------------ step 4


def drop_fillers_between_digits(chars: list[Char], n: NormalizeSpec) -> list[Char]:
    text = _text(chars)
    words = [(m.start(), m.end(), m[0].lower()) for m in _WORD.finditer(text)]
    by_end = {e: (s, w) for s, e, w in words}
    by_start = {s: (e, w) for s, e, w in words}

    def left_is_digit(i: int) -> bool:
        while i > 0:
            c = text[i - 1]
            if c in n.separators:
                i -= 1
                continue
            if i in by_end and by_end[i][1] in n.fillers:
                i = by_end[i][0]
                continue
            return _is_digit(c)
        return False

    def right_is_digit(i: int) -> bool:
        while i < len(text):
            c = text[i]
            if c in n.separators:
                i += 1
                continue
            if i in by_start and by_start[i][1] in n.fillers:
                i = by_start[i][0]
                continue
            return _is_digit(c)
        return False

    drop: set[int] = set()
    for s, e, w in words:
        if w in n.fillers and left_is_digit(s) and right_is_digit(e):
            drop.update(range(s, e))
    return [ch for i, ch in enumerate(chars) if i not in drop]


# ------------------------------------------------------------ step 5


def date_spans(text: str) -> list[tuple[int, int]]:
    """ISO (1980-01-01) and slashed (7/4/1981) date tokens, in order, not overlapping."""
    spans = [(m.start(), m.end()) for m in ISO_DATE.finditer(text)]
    for m in SLASHED_DATE.finditer(text):
        if not any(s < m.end() and m.start() < e for s, e in spans):
            spans.append((m.start(), m.end()))
    return sorted(spans)


def collapse_digit_separators(chars: list[Char], n: NormalizeSpec) -> list[Char]:
    text = _text(chars)
    protected = [False] * len(text)
    for s, e in date_spans(text):
        for i in range(s, e):
            protected[i] = True
    drop: set[int] = set()
    i = 0
    while i < len(text):
        if text[i] in n.separators:
            j = i
            while j < len(text) and text[j] in n.separators:
                j += 1
            if (
                i > 0
                and j < len(text)
                and _is_digit(text[i - 1])
                and _is_digit(text[j])
                and not protected[i - 1]
                and not protected[j]
                and not any(protected[i:j])
            ):
                drop.update(range(i, j))
            i = j
        else:
            i += 1
    return [ch for k, ch in enumerate(chars) if k not in drop]


# ------------------------------------------------------------ all steps


def normalize(text: str, n: NormalizeSpec) -> Normalized:
    chars = [Char(c, i, i + 1) for i, c in enumerate(text)]
    chars = strip_keypad_terminator(chars, n.terminators)
    chars = spoken_dates_to_iso(chars, n.dates)
    chars = number_words_to_digits(chars, n)
    chars = drop_fillers_between_digits(chars, n)
    chars = collapse_digit_separators(chars, n)
    return Normalized(_text(chars), tuple(chars))
