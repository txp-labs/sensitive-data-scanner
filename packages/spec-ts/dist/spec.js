/**
 * The sensitive-data spec (spec/classes.yaml and spec/normalize.yaml) as
 * typed objects. The raw spec is compiled into this package
 * (spec.generated.ts, from the YAML by scripts/gen-spec.ts), so the package
 * has no runtime dependencies. `parseSpec` also accepts the raw objects, for
 * a caller that loads a newer spec itself.
 */
import { CLASSES_RAW, NORMALIZE_RAW } from './spec.generated.js';
export const SPEC_VERSION = '0.7';
const WS = '[ \\t\\r\\n]+';
/** What may separate the words of a retry prefix in a turn: whitespace and . , ! ? ; : */
const RETRY_SEP = '[ \\t\\r\\n.,!?;:]';
/** Every prompt phrase matches only with neither a letter nor a digit on each side. */
const BOUNDARY_BEFORE = '(?<![A-Za-z0-9])';
const BOUNDARY_AFTER = '(?![A-Za-z0-9])';
/** Escape a literal for a RegExp (the same characters Python's re.escape needs here). */
export function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
}
/** Longest first, then alphabetical: the order every alternation is built in. */
export function byLengthThenName(a, b) {
    return b.length - a.length || (a < b ? -1 : a > b ? 1 : 0);
}
/** A prompt phrase with the spec's boundary: no letter or digit on either side. */
export function promptRegex(phrase) {
    return new RegExp(`${BOUNDARY_BEFORE}(?:${phrase})${BOUNDARY_AFTER}`, 'gi');
}
/** A retry prefix at the start of a turn: its words, apart by whitespace or . , ! ? ; : */
export function retryRegex(prefix) {
    const words = prefix.toLowerCase().split(new RegExp(`${RETRY_SEP}+`)).filter(Boolean);
    const body = words.map(escapeRegExp).join(`${RETRY_SEP}+`);
    return new RegExp(`^${RETRY_SEP}*${body}${BOUNDARY_AFTER}`, 'i');
}
/** Context or suppress words as one regex: whole words, any whitespace between. */
export function phraseRegex(words) {
    if (words.length === 0)
        return null;
    const alts = [...words]
        .sort(byLengthThenName)
        .map((w) => w.split(/\s+/).filter(Boolean).map(escapeRegExp).join(WS));
    return new RegExp(`\\b(?:${alts.join('|')})\\b`, 'i');
}
function isRecord(v) {
    return v != null && typeof v === 'object' && !Array.isArray(v);
}
function strings(v) {
    return Array.isArray(v) ? v.map((x) => String(x)) : [];
}
function numberMap(v) {
    const out = {};
    if (isRecord(v))
        for (const [k, x] of Object.entries(v))
            out[k] = Number(x);
    return out;
}
function digitsRange(v) {
    if (v == null)
        return [null, null];
    if (typeof v === 'number')
        return [v, v];
    if (Array.isArray(v))
        return [Number(v[0]), Number(v[1])];
    throw new Error('shape.digits must be a number or [min, max]');
}
function parseClass(name, raw) {
    const shapeRaw = isRecord(raw.shape) ? raw.shape : {};
    const [digitsMin, digitsMax] = digitsRange(shapeRaw.digits);
    const promptPhrases = strings(raw.promptPhrases);
    const contextWords = strings(raw.contextWords);
    const contextExclusions = strings(raw.contextExclusions);
    const suppressWords = strings(raw.suppressWords);
    return {
        name,
        severity: String(raw.severity),
        promptPhrases,
        shape: {
            digitsMin,
            digitsMax,
            rules: strings(shapeRaw.rules),
            softRules: strings(shapeRaw.softRules),
            kinds: strings(shapeRaw.kinds),
        },
        standalone: (raw.standalone ?? 'never'),
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
function parseBrand(raw) {
    const ranges = strings(raw.prefixes).map((p) => {
        const [lo, hi] = p.split('-');
        return [lo.length, Number(lo), Number(hi ?? lo)];
    });
    return {
        brand: String(raw.brand),
        ranges,
        lengths: new Set(raw.lengths.map(Number)),
    };
}
function step(steps, name) {
    for (const s of steps)
        if (isRecord(s) && name in s)
            return s[name];
    throw new Error(`normalize.yaml has no step ${name}`);
}
function parseNormalize(raw) {
    const steps = raw.steps;
    const d = step(steps, 'spoken_dates_to_iso');
    const words = step(steps, 'number_words_to_digits');
    const join = step(steps, 'join_same_speaker_turns');
    const yearRange = d.yearRange;
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
export function parseSpec(classesRaw, normalizeRaw) {
    if (!isRecord(classesRaw) || !isRecord(normalizeRaw))
        throw new Error('spec must be objects');
    for (const raw of [classesRaw, normalizeRaw]) {
        if (String(raw.specVersion) !== SPEC_VERSION) {
            throw new Error(`unsupported specVersion ${JSON.stringify(raw.specVersion)}`);
        }
    }
    const classesObj = classesRaw.classes;
    const classes = {};
    for (const [name, c] of Object.entries(classesObj))
        classes[name] = parseClass(name, c);
    const carry = isRecord(classesRaw.promptCarryover) ? classesRaw.promptCarryover : {};
    const window = isRecord(classesRaw.contextWindow) ? classesRaw.contextWindow : {};
    const retryPrefixes = strings(classesRaw.retryPrefixes).map((p) => p.toLowerCase());
    if (!isRecord(classesRaw.timestamps))
        throw new Error('spec is missing timestamps');
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
        brands: (classesRaw.cardBrands ?? []).map((b) => parseBrand(b)),
        normalize: parseNormalize(normalizeRaw),
        timeOfDayRe: new RegExp(String(stamps.timeOfDay), 'iy'),
        epochDigits: new Set((stamps.epochDigits ?? []).map(Number)),
    };
}
let cached = null;
/** The spec compiled into this package. */
export function loadSpec() {
    cached ??= parseSpec(CLASSES_RAW, NORMALIZE_RAW);
    return cached;
}
