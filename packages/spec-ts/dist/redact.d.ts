/**
 * In-memory redaction helpers for a call engine (Stugum): mask what
 * `classify` found in the original turn texts, and tell which classes the
 * last prompt has armed for the next customer turn.
 */
import { type ClassifyOptions, type Result, type Turn } from './conversation.ts';
import type { Spec } from './spec.ts';
/**
 * The turns' texts with every matched value masked in the ORIGINAL text:
 * each masked character becomes `mask` (spaces and punctuation between
 * spoken digits are masked too, since they are inside the value's range).
 */
export declare function redactTurns(spec: Spec, turns: readonly Turn[], options?: ClassifyOptions & {
    mask?: string;
    result?: Result;
}): string[];
/**
 * The classes armed for the next customer turn after these turns: what a
 * call engine should redact the next keypad or speech entry as, before it
 * arrives. Empty when nothing is armed.
 */
export declare function armedClasses(spec: Spec, turns: readonly Turn[]): string[];
