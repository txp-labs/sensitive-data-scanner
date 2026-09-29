import { type DateTables, type NormalizeSpec } from './spec.ts';
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
export declare function toOriginal(n: Normalized, start: number, end: number): [number, number];
export declare function stripKeypadTerminator(chars: Char[], terminators: readonly string[]): Char[];
export declare function spokenDatesToIso(chars: Char[], t: DateTables): Char[];
export declare function numberWordsToDigits(chars: Char[], n: NormalizeSpec): Char[];
export declare function dropFillersBetweenDigits(chars: Char[], n: NormalizeSpec): Char[];
/** ISO (1980-01-01) and slashed (7/4/1981) date tokens, in order, not overlapping. */
export declare function dateSpans(text: string): [number, number][];
export declare function collapseDigitSeparators(chars: Char[], n: NormalizeSpec): Char[];
/** Normalize one turn's text. Pure; holds nothing after it returns. */
export declare function normalize(text: string, n: NormalizeSpec): Normalized;
