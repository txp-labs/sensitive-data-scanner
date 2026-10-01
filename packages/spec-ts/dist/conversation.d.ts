import type { ClassSpec, Spec } from './spec.ts';
export type Speaker = 'bot' | 'agent' | 'customer';
export type Channel = 'speech' | 'dtmf' | 'chat';
export type Via = 'prompt' | 'shape' | 'context';
export type Confidence = 'high' | 'medium' | 'low';
export interface Turn {
    speaker: Speaker;
    text: string;
    channel?: Channel | null;
    beginMs?: number | null;
    endMs?: number | null;
}
/** Where one piece of a value sits: a value split across turns has one part per turn. */
export interface MatchPart {
    turn: number;
    /** In the normalized text of `turn`. */
    start: number;
    end: number;
    /** In the original text of `turn`: what to redact. */
    origStart: number;
    origEnd: number;
}
/** One classified value. Offsets only (UTF-16 code units); never the value. */
export interface Match {
    class: string;
    via: Via;
    confidence: Confidence;
    turn: number;
    /** In the normalized text of `turn`. */
    start: number;
    endTurn: number;
    /** In the normalized text of `endTurn`. */
    end: number;
    /** In the original text of `turn`. */
    origStart: number;
    /** In the original text of `endTurn`. */
    origEnd: number;
    /** Each piece of the value, one per turn. */
    parts: MatchPart[];
}
/** A value set aside as published test or sample data: counted, not a finding. */
export interface Excluded {
    class: string;
    turn: number;
}
export interface Result {
    matches: Match[];
    excluded: Excluded[];
    suppressed: number;
}
export interface ClassifyOptions {
    /** The date plausibility is judged against (birth years may not be later). Default: today. */
    now?: Date;
}
/** Each date token followed at once by a time of day, with the time (spec 0.7). */
export declare function timestampSpans(norm: string, timeOfDay: RegExp): [number, number][];
/**
 * The turn text without a leading retry prefix, and whether it had one. A
 * prefix's words may be apart by any run of whitespace and . , ! ? ; : in the
 * turn, and it matches only at the start ("Sorry, I didn't get that!").
 */
export declare function stripRetry(spec: Spec, text: string): [string, boolean];
/**
 * Classes a bot or agent turn asks for, in the order it names them, and
 * whether it was a retry. When phrase matches of two different classes
 * overlap, only the longer one counts.
 */
export declare function promptClasses(spec: Spec, text: string): [string[], boolean];
/**
 * Whether a bot or agent turn is a menu or a question ("Reply 1 for more.",
 * "Is that a Visa?"): such a turn ends any value another speaker is still
 * giving. Matched against the same text as prompt phrases.
 */
export declare function isMenuOrQuestion(spec: Spec, text: string): boolean;
export declare function hasContext(cls: ClassSpec, context: string): boolean;
/** Classify every sensitive value in a conversation. Offsets only, never values. */
export declare function classify(spec: Spec, turns: readonly Turn[], options?: ClassifyOptions): Result;
