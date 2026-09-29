export declare const SPEC_VERSION = "0.4";
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
}
/** Escape a literal for a RegExp (the same characters Python's re.escape needs here). */
export declare function escapeRegExp(s: string): string;
/** Longest first, then alphabetical: the order every alternation is built in. */
export declare function byLengthThenName(a: string, b: string): number;
/** A prompt phrase with the spec's boundary: no letter or digit on either side. */
export declare function promptRegex(phrase: string): RegExp;
/** A retry prefix at the start of a turn: its words, apart by whitespace or . , ! ? ; : */
export declare function retryRegex(prefix: string): RegExp;
/** Context or suppress words as one regex: whole words, any whitespace between. */
export declare function phraseRegex(words: readonly string[]): RegExp | null;
/** Parse the raw spec objects (as YAML-loaded). Refuses any other specVersion. */
export declare function parseSpec(classesRaw: unknown, normalizeRaw: unknown): Spec;
/** The spec compiled into this package. */
export declare function loadSpec(): Spec;
