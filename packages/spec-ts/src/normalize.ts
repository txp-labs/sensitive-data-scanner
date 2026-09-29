/**
 * Normalization of one conversation turn (spec/normalize.yaml). The output
 * is the normalized text plus, for every normalized character, the range of
 * the original text it came from, so a caller can redact the original. The
 * steps are defined in spec/README.md.
 */
import { validDate } from './rules.ts';
import { byLengthThenName, escapeRegExp, type DateTables, type NormalizeSpec } from './spec.ts';

const WS_CHARS = ' \t\r\n';
const WS = '[ \\t\\r\\n]+';

export interface Char {
  c: string;
  /** Original start (inclusive). */
  s: number;
  /** Original end (exclusive). */
  e: number;
}

export interface Normalized {
  text: string;
  chars: readonly Char[];
}

/** The original range a normalized span [start, end) came from. */
export function toOriginal(n: Normalized, start: number, end: number): [number, number] {
  if (start >= end) throw new Error('empty span');
  return [n.chars[start]!.s, n.chars[end - 1]!.e];
}

const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
const isAlnum = (c: string | undefined) =>
  c !== undefined && (isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));

const textOf = (chars: readonly Char[]) => chars.map((ch) => ch.c).join('');

/** One entry per UTF-16 code unit: the spec's offsets are UTF-16 code units. */
function charsOf(text: string): Char[] {
  const out: Char[] = [];
  for (let i = 0; i < text.length; i++) out.push({ c: text[i]!, s: i, e: i + 1 });
  return out;
}

function rstripWs(s: string): string {
  let end = s.length;
  while (end > 0 && WS_CHARS.includes(s[end - 1]!)) end--;
  return s.slice(0, end);
}

// ------------------------------------------------------------ step 1

export function stripKeypadTerminator(chars: Char[], terminators: readonly string[]): Char[] {
  const out: Char[] = [];
  chars.forEach((ch, i) => {
    if (terminators.includes(ch.c) && out.length > 0 && isDigit(out[out.length - 1]!.c)) {
      const next = chars[i + 1]?.c;
      if (next === undefined || !isAlnum(next)) return;
    }
    out.push(ch);
  });
  return out;
}

// ------------------------------------------------------------ step 2

const alt = (words: readonly string[]) => [...words].sort(byLengthThenName).map(escapeRegExp).join('|');

class DateGrammar {
  readonly regex: RegExp;
  private readonly t: DateTables;

  constructor(t: DateTables) {
    this.t = t;
    const keys = (m: Readonly<Record<string, number>>) => Object.keys(m);
    const ord19 = Object.entries(t.ordinals)
      .filter(([, v]) => v <= 9)
      .map(([w]) => w);
    const tensDay = Object.entries(t.tens)
      .filter(([, v]) => v === 20 || v === 30)
      .map(([w]) => w);
    const century = Object.entries({ ...t.teens, ...t.tens })
      .filter(([, v]) => v === 19 || v === 20)
      .map(([w]) => w);
    const month = `(?:${alt(keys(t.months))})\\.?`;
    const day =
      `(?:(?:${alt(tensDay)})(?:-|${WS})(?:${alt(ord19)}|${alt(keys(t.units))})` +
      `|${alt(keys(t.ordinals))}|${alt(keys(t.teens))}|${alt(keys(t.units))}` +
      `|${alt(tensDay)}|[0-9]{1,2}(?:st|nd|rd|th)?)`;
    const yy =
      `(?:${alt(keys(t.teens))}` +
      `|(?:${alt(keys(t.tens))})(?:(?:-|${WS})(?:${alt(keys(t.units))}))?` +
      `|(?:oh|o)(?:-|${WS})(?:${alt(keys(t.units))})|hundred)`;
    const yy2 =
      `(?:${alt(keys(t.teens))}` +
      `|(?:${alt(keys(t.tens))})(?:(?:-|${WS})(?:${alt(keys(t.units))}))?` +
      `|${alt(keys(t.units))})`;
    const year =
      `(?:[0-9]{4}|(?:${alt(century)})(?:-|${WS})${yy}` +
      `|two${WS}thousand(?:(?:${WS}and)?${WS}${yy2})?)`;
    const sep = `(?:,?${WS})`;
    const a = `(${month})${sep}(?:the${WS})?(${day})${sep}(${year})`;
    const b = `(?:the${WS})?(${day})${WS}(?:of${WS})?(${month})${sep}(${year})`;
    this.regex = new RegExp(`\\b(?:${a}|${b})\\b`, 'gi');
  }

  private words(s: string): string[] {
    return s
      .toLowerCase()
      .split(/[ \t\r\n-]+/)
      .filter(Boolean);
  }

  private get(map: Readonly<Record<string, number>>, w: string): number {
    return Object.hasOwn(map, w) ? map[w]! : 0;
  }

  month(s: string): number {
    return this.get(this.t.months, s.toLowerCase().replace(/\.+$/, ''));
  }

  day(s: string): number {
    const m = /^([0-9]{1,2})(?:st|nd|rd|th)?$/i.exec(s);
    if (m) return Number(m[1]);
    let total = 0;
    for (const w of this.words(s)) {
      total +=
        this.get(this.t.ordinals, w) ||
        this.get(this.t.units, w) ||
        this.get(this.t.teens, w) ||
        this.get(this.t.tens, w);
    }
    return total;
  }

  year(s: string): number {
    if (/^[0-9]{4}$/.test(s)) return Number(s);
    const words = this.words(s);
    if (words[0] === 'two' && words[1] === 'thousand') {
      return 2000 + this.small(words.slice(2).filter((w) => w !== 'and'));
    }
    const century = this.get(this.t.teens, words[0]!) || this.get(this.t.tens, words[0]!);
    let rest = words.slice(1);
    if (rest.length === 1 && rest[0] === 'hundred') return century * 100;
    if (rest[0] === 'oh' || rest[0] === 'o') rest = rest.slice(1);
    return century * 100 + this.small(rest);
  }

  private small(words: string[]): number {
    let total = 0;
    for (const w of words) {
      total += this.get(this.t.teens, w) || this.get(this.t.tens, w) || this.get(this.t.units, w);
    }
    return total;
  }
}

const grammars = new WeakMap<DateTables, DateGrammar>();

export function spokenDatesToIso(chars: Char[], t: DateTables): Char[] {
  let g = grammars.get(t);
  if (!g) {
    g = new DateGrammar(t);
    grammars.set(t, g);
  }
  const text = textOf(chars);
  const out: Char[] = [];
  let pos = 0;
  for (const m of text.matchAll(g.regex)) {
    const [monthS, dayS, yearS] =
      m[1] !== undefined ? [m[1], m[2]!, m[3]!] : [m[5]!, m[4]!, m[6]!];
    const month = g.month(monthS);
    const day = g.day(dayS);
    const year = g.year(yearS);
    if (!(year >= t.yearMin && year <= t.yearMax && validDate(year, month, day))) continue;
    const start = m.index;
    const end = start + m[0].length;
    out.push(...chars.slice(pos, start));
    const s = chars[start]!.s;
    const e = chars[end - 1]!.e;
    const iso = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    for (const c of iso) out.push({ c, s, e });
    pos = end;
  }
  out.push(...chars.slice(pos));
  return out;
}

// ------------------------------------------------------------ step 3

interface Word {
  start: number;
  end: number;
  w: string;
}

function wordsOf(text: string): Word[] {
  return [...text.matchAll(/[A-Za-z]+/g)].map((m) => ({
    start: m.index,
    end: m.index + m[0].length,
    w: m[0].toLowerCase(),
  }));
}

export function numberWordsToDigits(chars: Char[], n: NormalizeSpec): Char[] {
  const text = textOf(chars);
  const tokens = wordsOf(text);
  const byStart = new Map(tokens.map((t) => [t.start, t]));
  const has = (m: Readonly<Record<string, number>>, w: string) => Object.hasOwn(m, w);
  const skipWs = (i: number) => {
    while (i < text.length && WS_CHARS.includes(text[i]!)) i++;
    return i;
  };
  const singleDigitAt = (i: number) =>
    i < text.length && isDigit(text[i]) && !isDigit(text[i - 1]) && !isDigit(text[i + 1]);

  const out: Char[] = [];
  let pos = 0;
  for (let k = 0; k < tokens.length; k++) {
    const { start, end, w } = tokens[k]!;
    let replacement: string | null = null;
    let consumedEnd = end;
    if (has(n.multipliers, w)) {
      const j = skipWs(end);
      const next = byStart.get(j);
      if (next && has(n.digitWords, next.w)) {
        replacement = String(n.digitWords[next.w]).repeat(n.multipliers[w]!);
        consumedEnd = next.end;
        k++; // the digit word is consumed too
      } else if (singleDigitAt(j)) {
        replacement = text[j]!.repeat(n.multipliers[w]!);
        consumedEnd = j + 1;
      }
    } else if (has(n.digitWords, w)) {
      if (n.zeroOnlyNextToDigits.has(w)) {
        const emitted = textOf(out) + text.slice(pos, start);
        const before = rstripWs(emitted).slice(-1);
        const j = skipWs(end);
        const next = byStart.get(j);
        const nextIsDigit =
          isDigit(text[j]) ||
          (next !== undefined && (has(n.digitWords, next.w) || has(n.multipliers, next.w)));
        if (isDigit(before) || nextIsDigit) replacement = '0';
      } else {
        replacement = String(n.digitWords[w]);
      }
    }
    if (replacement !== null) {
      out.push(...chars.slice(pos, start));
      const s = chars[start]!.s;
      const e = chars[consumedEnd - 1]!.e;
      for (const c of replacement) out.push({ c, s, e });
      pos = consumedEnd;
    }
  }
  out.push(...chars.slice(pos));
  return out;
}

// ------------------------------------------------------------ step 4

export function dropFillersBetweenDigits(chars: Char[], n: NormalizeSpec): Char[] {
  const text = textOf(chars);
  const words = wordsOf(text);
  const byEnd = new Map(words.map((w) => [w.end, w]));
  const byStart = new Map(words.map((w) => [w.start, w]));
  const leftIsDigit = (i: number): boolean => {
    while (i > 0) {
      const c = text[i - 1]!;
      if (n.separators.has(c)) {
        i--;
        continue;
      }
      const w = byEnd.get(i);
      if (w && n.fillers.has(w.w)) {
        i = w.start;
        continue;
      }
      return isDigit(c);
    }
    return false;
  };
  const rightIsDigit = (i: number): boolean => {
    while (i < text.length) {
      const c = text[i]!;
      if (n.separators.has(c)) {
        i++;
        continue;
      }
      const w = byStart.get(i);
      if (w && n.fillers.has(w.w)) {
        i = w.end;
        continue;
      }
      return isDigit(c);
    }
    return false;
  };
  const drop = new Set<number>();
  for (const w of words) {
    if (n.fillers.has(w.w) && leftIsDigit(w.start) && rightIsDigit(w.end)) {
      for (let i = w.start; i < w.end; i++) drop.add(i);
    }
  }
  return chars.filter((_, i) => !drop.has(i));
}

// ------------------------------------------------------------ step 5

/** ISO (1980-01-01) and slashed (7/4/1981) date tokens, in order, not overlapping. */
export function dateSpans(text: string): [number, number][] {
  const spans: [number, number][] = [...text.matchAll(/(?<![0-9])[0-9]{4}-[0-9]{2}-[0-9]{2}(?![0-9])/g)].map(
    (m) => [m.index, m.index + m[0].length],
  );
  for (const m of text.matchAll(/(?<![0-9])[0-9]{1,2}\/[0-9]{1,2}\/(?:[0-9]{4}|[0-9]{2})(?![0-9])/g)) {
    const s = m.index;
    const e = s + m[0].length;
    if (!spans.some(([a, b]) => a < e && s < b)) spans.push([s, e]);
  }
  return spans.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
}

export function collapseDigitSeparators(chars: Char[], n: NormalizeSpec): Char[] {
  const text = textOf(chars);
  const prot = new Array<boolean>(text.length).fill(false);
  for (const [s, e] of dateSpans(text)) for (let i = s; i < e; i++) prot[i] = true;
  const drop = new Set<number>();
  let i = 0;
  while (i < text.length) {
    if (n.separators.has(text[i]!)) {
      let j = i;
      while (j < text.length && n.separators.has(text[j]!)) j++;
      if (
        i > 0 &&
        j < text.length &&
        isDigit(text[i - 1]) &&
        isDigit(text[j]) &&
        !prot[i - 1] &&
        !prot[j] &&
        !prot.slice(i, j).some(Boolean)
      ) {
        for (let k = i; k < j; k++) drop.add(k);
      }
      i = j;
    } else {
      i++;
    }
  }
  return chars.filter((_, k) => !drop.has(k));
}

// ------------------------------------------------------------ all steps

/** Normalize one turn's text. Pure; holds nothing after it returns. */
export function normalize(text: string, n: NormalizeSpec): Normalized {
  let chars = charsOf(text);
  chars = stripKeypadTerminator(chars, n.terminators);
  chars = spokenDatesToIso(chars, n.dates);
  chars = numberWordsToDigits(chars, n);
  chars = dropFillersBetweenDigits(chars, n);
  chars = collapseDigitSeparators(chars, n);
  return { text: textOf(chars), chars };
}
