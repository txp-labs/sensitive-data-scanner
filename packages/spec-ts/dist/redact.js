/**
 * In-memory redaction helpers for a call engine (Stugum): mask what
 * `classify` found in the original turn texts, and tell which classes the
 * last prompt has armed for the next customer turn.
 */
import { classify, promptClasses } from './conversation.js';
/**
 * The turns' texts with every matched value masked in the ORIGINAL text:
 * each masked character becomes `mask` (spaces and punctuation between
 * spoken digits are masked too, since they are inside the value's range).
 */
export function redactTurns(spec, turns, options = {}) {
    const result = options.result ?? classify(spec, turns, options);
    const mask = options.mask ?? '#';
    const units = turns.map((t) => t.text.split(''));
    for (const m of result.matches) {
        for (const p of m.parts) {
            const u = units[p.turn];
            for (let i = p.origStart; i < p.origEnd; i++)
                u[i] = mask;
        }
    }
    return units.map((u) => u.join(''));
}
/**
 * The classes armed for the next customer turn after these turns: what a
 * call engine should redact the next keypad or speech entry as, before it
 * arrives. Empty when nothing is armed.
 */
export function armedClasses(spec, turns) {
    let armed = [];
    let last = [];
    for (const t of turns) {
        if (t.speaker === 'customer') {
            armed = [];
            continue;
        }
        const [classes, retry] = promptClasses(spec, t.text);
        const rearm = classes.length > 0 ? classes : retry && spec.surviveRetry ? last : [];
        if (rearm.length > 0) {
            armed = [...rearm];
            last = [...rearm];
        }
    }
    return armed;
}
