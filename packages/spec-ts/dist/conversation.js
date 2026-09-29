/**
 * Classify a conversation: prompt carryover, split turns, shape and context
 * (spec/README.md, "Classification"). The Python runner implements the same
 * algorithm; both are tested against every vector and against each other.
 *
 * A Match carries a class, a location and a confidence, never the matched
 * text or its digits.
 */
import { dateSpans, normalize, toOriginal } from './normalize.js';
import { cardBrand, cardCandidates, dateDigitsShape, dateTokenShape, isTestCard, itinStructureValid, luhnValid, shapePass, ssnStructureValid, } from './rules.js';
const FORMATTED_3_2_4 = /^[0-9]{3}([ -])[0-9]{2}\1[0-9]{4}$/;
const ALNUM = /[A-Za-z0-9]/;
const SPEAKERS = ['bot', 'agent', 'customer'];
const digitsOf = (c) => c.parts.map((p) => p.digits).join('');
const firstTurn = (c) => c.parts[0].turn;
const lastTurn = (c) => c.parts[c.parts.length - 1].turn;
function isLetterOrUnderscore(c) {
    if (c === undefined)
        return false;
    const l = c.toLowerCase();
    return c === '_' || (l >= 'a' && l <= 'z');
}
/** A token with a letter or underscore right before or after it is part of a word or an id. */
function glued(norm, start, end) {
    return isLetterOrUnderscore(norm[start - 1]) || isLetterOrUnderscore(norm[end]);
}
function tokensOf(norm) {
    const dates = dateSpans(norm);
    const out = dates
        .filter(([s, e]) => !glued(norm, s, e))
        .map(([s, e]) => ({ start: s, end: e, text: norm.slice(s, e), isDate: true }));
    for (const m of norm.matchAll(/[0-9]+/g)) {
        const s = m.index;
        const e = s + m[0].length;
        if (dates.some(([a, b]) => a < e && s < b))
            continue;
        if (!glued(norm, s, e))
            out.push({ start: s, end: e, text: m[0], isDate: false });
    }
    return out.sort((a, b) => a.start - b.start);
}
const atStart = (norm, t) => !ALNUM.test(norm.slice(0, t.start));
const atEnd = (norm, t) => !ALNUM.test(norm.slice(t.end));
function lstrip(s, chars) {
    let i = 0;
    while (i < s.length && chars.includes(s[i]))
        i++;
    return s.slice(i);
}
/**
 * The turn text without a leading retry prefix, and whether it had one. A
 * prefix's words may be apart by any run of whitespace and . , ! ? ; : in the
 * turn, and it matches only at the start ("Sorry, I didn't get that!").
 */
export function stripRetry(spec, text) {
    const low = lstrip(text.replaceAll('’', "'"), ' \t\r\n').toLowerCase();
    for (const rx of spec.retryRes) {
        const m = rx.exec(low);
        if (m)
            return [lstrip(low.slice(m[0].length), ' \t\r\n.,!?;:'), true];
    }
    return [low, false];
}
/**
 * Classes a bot or agent turn asks for, in the order it names them, and
 * whether it was a retry. When phrase matches of two different classes
 * overlap, only the longer one counts.
 */
export function promptClasses(spec, text) {
    const [body, retry] = stripRetry(spec, text);
    const hits = [];
    for (const name of spec.classOrder) {
        for (const rx of spec.classes[name].promptRes) {
            for (const m of body.matchAll(rx)) {
                if (m[0].length > 0)
                    hits.push([m.index, m.index + m[0].length, name]);
            }
        }
    }
    const kept = hits.filter((h) => !hits.some((o) => o[2] !== h[2] && o[0] < h[1] && h[0] < o[1] && o[1] - o[0] > h[1] - h[0]));
    kept.sort((a, b) => a[0] - b[0] || spec.classOrder.indexOf(a[2]) - spec.classOrder.indexOf(b[2]));
    const ordered = [];
    for (const [, , name] of kept)
        if (!ordered.includes(name))
            ordered.push(name);
    return [ordered, retry];
}
/**
 * Whether a bot or agent turn is a menu or a question ("Reply 1 for more.",
 * "Is that a Visa?"): such a turn ends any value another speaker is still
 * giving. Matched against the same text as prompt phrases.
 */
export function isMenuOrQuestion(spec, text) {
    const [body] = stripRetry(spec, text);
    return spec.normalize.menuOrQuestionRes.some((rx) => rx.test(body));
}
export function hasContext(cls, context) {
    if (!cls.contextRe)
        return false;
    let text = context;
    for (const rx of cls.exclusionRes)
        text = text.replace(rx, ' ');
    return cls.contextRe.test(text);
}
class Classifier {
    norms;
    result = { matches: [], excluded: [], suppressed: 0 };
    open = new Map();
    spec;
    turns;
    nowYear;
    constructor(spec, turns, nowYear) {
        this.spec = spec;
        this.turns = turns;
        this.nowYear = nowYear;
        this.norms = turns.map((t) => normalize(t.text, spec.normalize));
    }
    context(first, last) {
        const lo = Math.max(0, first - this.spec.contextTurnsBefore);
        return this.turns
            .slice(lo, last + 1)
            .map((t) => t.text)
            .join('\n');
    }
    match(cls, via, confidence, chain, digitLen) {
        const first = chain.parts[0];
        let lastPart = chain.parts[chain.parts.length - 1];
        let end = lastPart.end;
        if (digitLen !== null) {
            let remaining = digitLen;
            lastPart = chain.parts[0];
            end = lastPart.start;
            for (const p of chain.parts) {
                lastPart = p;
                if (remaining <= p.digits.length) {
                    end = p.start + remaining;
                    break;
                }
                remaining -= p.digits.length;
            }
        }
        const parts = [];
        for (const p of chain.parts) {
            const pEnd = p === lastPart ? end : p.end;
            const [os, oe] = toOriginal(this.norms[p.turn], p.start, pEnd);
            parts.push({ turn: p.turn, start: p.start, end: pEnd, origStart: os, origEnd: oe });
            if (p === lastPart)
                break;
        }
        return {
            class: cls,
            via,
            confidence,
            turn: first.turn,
            start: first.start,
            endTurn: lastPart.turn,
            end,
            origStart: parts[0].origStart,
            origEnd: parts[parts.length - 1].origEnd,
            parts,
        };
    }
    static maxDigits(cls) {
        if (cls.shape.kinds.length > 0)
            return 8;
        return cls.shape.digitsMax || 19;
    }
    /** The most digits a joined value may have. */
    limit(chain) {
        if (chain.prompted.length > 0) {
            return Math.max(...chain.prompted.map((n) => Classifier.maxDigits(this.spec.classes[n])));
        }
        return 19;
    }
    complete(chain) {
        const d = digitsOf(chain);
        if (chain.prompted.length > 0) {
            for (const name of chain.prompted) {
                if (shapePass(this.spec.classes[name], d, this.spec, this.nowYear) === 'full')
                    return true;
            }
            return d.length >= this.limit(chain);
        }
        if (d.length === 9 && (ssnStructureValid(d) || itinStructureValid(d)))
            return true;
        return d.length >= 13 && d.length <= 19 && luhnValid(d) && cardBrand(d, this.spec.brands) !== null;
    }
    evaluate(chain) {
        if (chain.prompted.length > 0 && !(chain.isDate && !chain.prompted.includes('dob'))) {
            this.evaluatePrompted(chain);
            return;
        }
        const [match, excluded, suppressed] = this.unprompted(chain);
        if (match)
            this.result.matches.push(match);
        if (excluded)
            this.result.excluded.push(excluded);
        if (suppressed)
            this.result.suppressed += 1;
    }
    /** Shape and context rules: [match, excluded as test data, suppressed]. */
    unprompted(chain) {
        const spec = this.spec;
        const context = this.context(firstTurn(chain), lastTurn(chain));
        if (chain.isDate) {
            const dob = spec.classes.dob;
            const part = chain.parts[0];
            const token = this.norms[part.turn].text.slice(part.start, part.end);
            if (dob && dateTokenShape(token, this.nowYear) && hasContext(dob, context)) {
                return [this.match('dob', 'context', 'high', chain, null), null, false];
            }
            return [null, null, false];
        }
        const d = digitsOf(chain);
        const card = spec.classes.card;
        if (card && d.length >= 13) {
            for (const length of cardCandidates(d)) {
                const head = d.slice(0, length);
                if (!(luhnValid(head) && cardBrand(head, spec.brands)))
                    continue;
                if (card.testNumbers.size > 0 && isTestCard(head, card)) {
                    return [null, { class: 'card', turn: firstTurn(chain) }, false];
                }
                if (hasContext(card, context))
                    return [this.match('card', 'context', 'high', chain, length), null, false];
                if (card.suppressRe && card.suppressRe.test(context))
                    return [null, null, true];
                if (card.standalone === 'any')
                    return [this.match('card', 'shape', 'medium', chain, length), null, false];
                return [null, null, false];
            }
        }
        const ssn = spec.classes.us_ssn;
        if (ssn && d.length === 9 && ssnStructureValid(d)) {
            if (ssn.dummyValues.has(d))
                return [null, { class: 'us_ssn', turn: firstTurn(chain) }, false];
            if (hasContext(ssn, context))
                return [this.match('us_ssn', 'context', 'high', chain, null), null, false];
            if (ssn.standalone === 'formatted' && this.formatted(chain)) {
                return [this.match('us_ssn', 'shape', 'medium', chain, null), null, false];
            }
        }
        const itin = spec.classes.us_itin;
        if (itin && d.length === 9 && itinStructureValid(d)) {
            if (itin.testNumbers.has(d))
                return [null, { class: 'us_itin', turn: firstTurn(chain) }, false];
            if (hasContext(itin, context))
                return [this.match('us_itin', 'context', 'high', chain, null), null, false];
            if (itin.standalone === 'formatted' && this.formatted(chain)) {
                return [this.match('us_itin', 'shape', 'medium', chain, null), null, false];
            }
        }
        const dob = spec.classes.dob;
        if (dob &&
            (d.length === 6 || d.length === 8) &&
            dateDigitsShape(d, this.nowYear) &&
            hasContext(dob, context)) {
            return [this.match('dob', 'context', 'high', chain, null), null, false];
        }
        return [null, null, false];
    }
    /** The value sits in one turn whose original text is exactly ddd-dd-dddd or ddd dd dddd. */
    formatted(chain) {
        if (chain.parts.length !== 1)
            return false;
        const part = chain.parts[0];
        const [os, oe] = toOriginal(this.norms[part.turn], part.start, part.end);
        return FORMATTED_3_2_4.test(this.turns[part.turn].text.slice(os, oe));
    }
    evaluatePrompted(chain) {
        const spec = this.spec;
        if (chain.isDate) {
            const part = chain.parts[0];
            const token = this.norms[part.turn].text.slice(part.start, part.end);
            const conf = dateTokenShape(token, this.nowYear) ? 'high' : 'low';
            this.result.matches.push(this.match('dob', 'prompt', conf, chain, null));
            return;
        }
        const d = digitsOf(chain);
        const passes = chain.prompted.map((name) => [name, shapePass(spec.classes[name], d, spec, this.nowYear)]);
        for (const [wanted, conf] of [
            ['full', 'high'],
            ['soft', 'medium'],
        ]) {
            for (const [name, p] of passes) {
                if (p === wanted) {
                    this.result.matches.push(this.match(name, 'prompt', conf, chain, null));
                    return;
                }
            }
        }
        // Fits no prompted class: a complete value of another class keeps that class.
        const [other] = this.unprompted(chain);
        if (other) {
            this.result.matches.push(other);
            return;
        }
        this.result.matches.push(this.match(chain.prompted[0], 'prompt', 'low', chain, null));
    }
    finish(speaker) {
        const chain = this.open.get(speaker);
        if (chain) {
            this.open.delete(speaker);
            this.evaluate(chain);
        }
    }
    run() {
        const spec = this.spec;
        const n = spec.normalize;
        let armed = [];
        let lastArmed = [];
        this.turns.forEach((turn, idx) => {
            let prompted = [];
            if (turn.speaker === 'customer') {
                prompted = armed;
                armed = [];
            }
            else {
                const [classes, retry] = promptClasses(spec, turn.text);
                const rearm = classes.length > 0 ? classes : retry && spec.surviveRetry ? lastArmed : [];
                if (rearm.length > 0) {
                    armed = rearm;
                    lastArmed = rearm;
                }
                // A new prompt, a menu or a question ends any value still being given.
                if (rearm.length > 0 || isMenuOrQuestion(spec, turn.text)) {
                    for (const sp of [...this.open.keys()])
                        if (sp !== turn.speaker)
                            this.finish(sp);
                }
            }
            // A keypad answer ends at the next turn of another speaker.
            for (const [sp, c] of [...this.open.entries()])
                if (sp !== turn.speaker && c.answerWindow)
                    this.finish(sp);
            const norm = this.norms[idx].text;
            const toks = tokensOf(norm);
            const begin = turn.beginMs ?? null;
            const endMs = turn.endMs ?? turn.beginMs ?? null;
            const channel = turn.channel ?? null;
            const inWindow = channel !== null && n.joinAnswerWindow.has(channel);
            let startAt = 0;
            const carry = this.open.get(turn.speaker);
            if (carry) {
                const first = toks[0];
                const gapOk = carry.lastEndMs === null || begin === null || begin - carry.lastEndMs <= n.joinWithinMs;
                const turnsOk = idx - lastTurn(carry) - 1 <= n.joinMaxIntervening;
                // Within one answer window, no other speaker's turn may come between the parts.
                const joinable = !(inWindow || carry.answerWindow) || idx === lastTurn(carry) + 1;
                if (joinable &&
                    first !== undefined &&
                    digitsOf(carry).length + first.text.length <= this.limit(carry) &&
                    !first.isDate &&
                    atStart(norm, first) &&
                    gapOk &&
                    turnsOk &&
                    !(n.joinStopWhenComplete && this.complete(carry))) {
                    carry.parts.push({ turn: idx, start: first.start, end: first.end, digits: first.text });
                    carry.lastEndMs = endMs;
                    carry.answerWindow ||= inWindow;
                    startAt = 1;
                    if (!(toks.length === 1 && atEnd(norm, first)))
                        this.finish(turn.speaker);
                }
                else {
                    this.finish(turn.speaker);
                }
            }
            for (let i = startAt; i < toks.length; i++) {
                const tok = toks[i];
                const chain = {
                    speaker: turn.speaker,
                    parts: [{ turn: idx, start: tok.start, end: tok.end, digits: tok.isDate ? '' : tok.text }],
                    prompted,
                    lastEndMs: endMs,
                    isDate: tok.isDate,
                    answerWindow: inWindow,
                };
                if (i === toks.length - 1 && !tok.isDate && atEnd(norm, tok))
                    this.open.set(turn.speaker, chain);
                else
                    this.evaluate(chain);
            }
            for (const [sp, c] of [...this.open.entries()]) {
                if (sp !== turn.speaker && idx - lastTurn(c) > n.joinMaxIntervening)
                    this.finish(sp);
            }
        });
        for (const sp of [...this.open.keys()])
            this.finish(sp);
        this.result.matches.sort((a, b) => a.turn - b.turn || a.start - b.start || a.endTurn - b.endTurn || a.end - b.end);
        return this.result;
    }
}
/** Classify every sensitive value in a conversation. Offsets only, never values. */
export function classify(spec, turns, options = {}) {
    for (const t of turns) {
        if (!SPEAKERS.includes(t.speaker))
            throw new Error('speaker must be bot, agent or customer');
    }
    const year = (options.now ?? new Date()).getUTCFullYear();
    return new Classifier(spec, turns, year).run();
}
