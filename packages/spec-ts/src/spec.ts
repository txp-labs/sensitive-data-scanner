/**
 * The sensitive-data spec (spec/classes.yaml and spec/normalize.yaml) as
 * typed objects. The raw spec is compiled into this package
 * (spec.generated.ts, from the YAML by scripts/gen-spec.ts), so the package
 * has no runtime dependencies. `parseSpec` also accepts the raw objects, for
 * a caller that loads a newer spec itself.
 */
import { CLASSES_RAW, NORMALIZE_RAW } from './spec.generated.ts';

export const SPEC_VERSION = '0.7';

const WS = '[ \\t\\r\\n]+';

/** What may separate the words of a retry prefix in a turn: whitespace and . , ! ? ; : */
const RETRY_SEP = '[ \\t\\r\\n.,!?;:]';

/** Every prompt phrase matches only with neither a letter nor a digit on each side. */
const BOUNDARY_BEFORE = '(?<![A-Za-z0-9])';
const BOUNDARY_AFTER = '(?![A-Za-z0-9])';

export interface Shape {
  digitsMin: number | null;
  digitsMax: number | null;
  rules: readonly string[];
  softRules: readonly string[];
  kinds: readonly string[];
}

export interface ClassSpec {
  name: string;
  severity: 'high' | 'medium' | 'low';
  promptPhrases: readonly string[];
  shape: Shape;
  standalone: 'any' | 'formatted' | 'never';
  contextWords: readonly string[];
  contextExclusions: readonly string[];
  suppressWords: readonly string[];
  dummyValues: ReadonlySet<string>;
  testNumbers: ReadonlySet<string>;
  testNumbersMaxDistinctDigits: number;
  promptRes: readonly RegExp[];
  contextRe: RegExp | null;
  exclusionRes: readonly RegExp[];
  suppressRe: RegExp | null;
}

export interface BrandRule {
  brand: string;
  /** [prefix length, from, to] */
  ranges: readonly (readonly [number, number, number])[];
  lengths: ReadonlySet<number>;
}

export interface DateTables {
  months: Readonly<Record<string, number>>;
  ordinals: Readonly<Record<string, number>>;
  units: Readonly<Record<string, number>>;
  teens: Readonly<Record<string, number>>;
  tens: Readonly<Record<string, number>>;
  yearMin: number;
  yearMax: number;
}

export interface NormalizeSpec {
  terminators: readonly string[];
  dates: DateTables;
  digitWords: Readonly<Record<string, number>>;
  zeroOnlyNextToDigits: ReadonlySet<string>;
  multipliers: Readonly<Record<string, number>>;
  fillers: ReadonlySet<string>;
  separators: ReadonlySet<string>;
  joinWithinMs: number;
  joinStopWhenComplete: boolean;
  joinMaxIntervening: number;
  /** Channels whose values end at the next turn of another speaker (a keypad answer window). */
  joinAnswerWindow: ReadonlySet<string>;
  /** A bot or agent turn matching one of these is a menu or a question: it ends other speakers' values. */
  menuOrQuestionRes: readonly RegExp[];
}

export interface Spec {
  specVersion: string;
  classes: Readonly<Record<string, ClassSpec>>;
  classOrder: readonly string[];
  retryPrefixes: readonly string[];
  /** One per retry prefix: its words at the start of a turn, apart by whitespace or . , ! ? ; : */
  retryRes: readonly RegExp[];
  carryoverTurns: number;
  surviveRetry: boolean;
  contextTurnsBefore: number;
  brands: readonly BrandRule[];
  normalize: NormalizeSpec;
  /** (0.7) A date token followed at once by a match of this (sticky) is a timestamp: no value. */
  timeOfDayRe: RegExp;
  /** (0.7) Digit-run lengths that are epoch times: never dob. */
  epochDigits: ReadonlySet<number>;
}

/** Escape a literal for a RegExp (the same characters Python's re.escape needs here). */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
}

/** Longest first, then alphabetical: the order every alternation is built in. */
export function byLengthThenName(a: string, b: string): number {
  return b.length - a.length || (a < b ? -1 : a > b ? 1 : 0);
}

/** A prompt phrase with the spec's boundary: no letter or digit on either side. */
export function promptRegex(phrase: string): RegExp {
  return new RegExp(`${BOUNDARY_BEFORE}(?:${phrase})${BOUNDARY_AFTER}`, 'gi');
}

/** A retry prefix at the start of a turn: its words, apart by whitespace or . , ! ? ; : */
export function retryRegex(prefix: string): RegExp {
  const words = prefix.toLowerCase().split(new RegExp(`${RETRY_SEP}+`)).filter(Boolean);
  const body = words.map(escapeRegExp).join(`${RETRY_SEP}+`);
  return new RegExp(`^${RETRY_SEP}*${body}${BOUNDARY_AFTER}`, 'i');
}

/** Context or suppress words as one regex: whole words, any whitespace between. */
export function phraseRegex(words: readonly string[]): RegExp | null {
  if (words.length === 0) return null;
  const alts = [...words]
    .sort(byLengthThenName)
    .map((w) => w.split(/\s+/).filter(Boolean).map(escapeRegExp).join(WS));
  return new RegExp(`\\b(?:${alts.join('|')})\\b`, 'i');
}

type Raw = Record<string, unknown>;

function isRecord(v: unknown): v is Raw {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

function numberMap(v: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  if (isRecord(v)) for (const [k, x] of Object.entries(v)) out[k] = Number(x);
  return out;
}

function digitsRange(v: unknown): [number | null, number | null] {
  if (v == null) return [null, null];
  if (typeof v === 'number') return [v, v];
  if (Array.isArray(v)) return [Number(v[0]), Number(v[1])];
  throw new Error('shape.digits must be a number or [min, max]');
}

function parseClass(name: string, raw: Raw): ClassSpec {
  const shapeRaw = isRecord(raw.shape) ? raw.shape : {};
  const [digitsMin, digitsMax] = digitsRange(shapeRaw.digits);
  const promptPhrases = strings(raw.promptPhrases);
  const contextWords = strings(raw.contextWords);
  const contextExclusions = strings(raw.contextExclusions);
  const suppressWords = strings(raw.suppressWords);
  return {
    name,
    severity: String(raw.severity) as ClassSpec['severity'],
    promptPhrases,
    shape: {
      digitsMin,
      digitsMax,
      rules: strings(shapeRaw.rules),
      softRules: strings(shapeRaw.softRules),
      kinds: strings(shapeRaw.kinds),
    },
    standalone: (raw.standalone ?? 'never') as ClassSpec['standalone'],
    contextWords,
    contextExclusions,
    suppressWords,
    dummyValues: new Set(strings(raw.dummyValues)),
    testNumbers: new Set(strings(raw.testNumbers)),
    testNumbersMaxDistinctDigits: Number(raw.testNumbersMaxDistinctDigits ?? 0),
    promptRes: promptPhrases.map(promptRegex),
    contextRe: phraseRegex(contextWords),
    exclusionRes: contextExclusions.map((p) => new RegExp(p, 'gi')),
    suppressRe: phraseRegex(suppressWords),
  };
}

function parseBrand(raw: Raw): BrandRule {
  const ranges = strings(raw.prefixes).map((p) => {
    const [lo, hi] = p.split('-') as [string, string | undefined];
    return [lo.length, Number(lo), Number(hi ?? lo)] as const;
  });
  return {
    brand: String(raw.brand),
    ranges,
    lengths: new Set((raw.lengths as unknown[]).map(Number)),
  };
}

function step(steps: unknown[], name: string): unknown {
  for (const s of steps) if (isRecord(s) && name in s) return s[name];
  throw new Error(`normalize.yaml has no step ${name}`);
}

function parseNormalize(raw: Raw): NormalizeSpec {
  const steps = raw.steps as unknown[];
  const d = step(steps, 'spoken_dates_to_iso') as Raw;
  const words = step(steps, 'number_words_to_digits') as Raw;
  const join = step(steps, 'join_same_speaker_turns') as Raw;
  const yearRange = d.yearRange as [number, number];
  return {
    terminators: strings(step(steps, 'strip_keypad_terminator')),
    dates: {
      months: numberMap(d.months),
      ordinals: numberMap(d.ordinals),
      units: numberMap(d.units),
      teens: numberMap(d.teens),
      tens: numberMap(d.tens),
      yearMin: Number(yearRange[0]),
      yearMax: Number(yearRange[1]),
    },
    digitWords: numberMap(words.words),
    zeroOnlyNextToDigits: new Set(strings(words.zeroOnlyNextToDigits)),
    multipliers: numberMap(words.multipliers),
    fillers: new Set(strings(step(steps, 'drop_fillers_between_digits'))),
    separators: new Set(strings(step(steps, 'collapse_digit_separators'))),
    joinWithinMs: Math.trunc(Number(join.withinSeconds) * 1000),
    joinStopWhenComplete: join.stopWhenClassComplete !== false,
    joinMaxIntervening: Number(join.maxInterveningTurns ?? 0),
    joinAnswerWindow: new Set(strings(join.answerWindowChannels)),
    menuOrQuestionRes: strings(join.menuOrQuestionTurns).map((p) => new RegExp(p, 'i')),
  };
}

/** Parse the raw spec objects (as YAML-loaded). Refuses any other specVersion. */
export function parseSpec(classesRaw: unknown, normalizeRaw: unknown): Spec {
  if (!isRecord(classesRaw) || !isRecord(normalizeRaw)) throw new Error('spec must be objects');
  for (const raw of [classesRaw, normalizeRaw]) {
    if (String(raw.specVersion) !== SPEC_VERSION) {
      throw new Error(`unsupported specVersion ${JSON.stringify(raw.specVersion)}`);
    }
  }
  const classesObj = classesRaw.classes as Raw;
  const classes: Record<string, ClassSpec> = {};
  for (const [name, c] of Object.entries(classesObj)) classes[name] = parseClass(name, c as Raw);
  const carry = isRecord(classesRaw.promptCarryover) ? classesRaw.promptCarryover : {};
  const window = isRecord(classesRaw.contextWindow) ? classesRaw.contextWindow : {};
  const retryPrefixes = strings(classesRaw.retryPrefixes).map((p) => p.toLowerCase());
  if (!isRecord(classesRaw.timestamps)) throw new Error('spec is missing timestamps');
  const stamps = classesRaw.timestamps;
  return {
    specVersion: SPEC_VERSION,
    classes,
    classOrder: Object.keys(classes),
    retryPrefixes,
    retryRes: retryPrefixes.map(retryRegex),
    carryoverTurns: Number(carry.turns ?? 1),
    surviveRetry: carry.surviveRetry !== false,
    contextTurnsBefore: Number(window.turnsBefore ?? 2),
    brands: ((classesRaw.cardBrands as unknown[]) ?? []).map((b) => parseBrand(b as Raw)),
    normalize: parseNormalize(normalizeRaw),
    timeOfDayRe: new RegExp(String(stamps.timeOfDay), 'iy'),
    epochDigits: new Set(((stamps.epochDigits as unknown[]) ?? []).map(Number)),
  };
}

let cached: Spec | null = null;

/** The spec compiled into this package. */
export function loadSpec(): Spec {
  cached ??= parseSpec(CLASSES_RAW, NORMALIZE_RAW);
  return cached;
}
