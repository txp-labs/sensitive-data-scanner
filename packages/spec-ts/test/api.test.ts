/** The public API beyond the vectors: spec loading, offsets, redaction, armed classes. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generated } from '../scripts/gen-spec.ts';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  SPEC_VERSION,
  armedClasses,
  classify,
  loadSpec,
  normalize,
  parseSpec,
  redactTurns,
  toOriginal,
  type Turn,
} from '../src/index.ts';
import { CLASSES_RAW, NORMALIZE_RAW } from '../src/spec.generated.ts';

const spec = loadSpec();

test('the compiled spec matches spec/*.yaml', () => {
  const file = readFileSync(join(import.meta.dirname, '..', 'src', 'spec.generated.ts'), 'utf8');
  assert.equal(file, generated());
});

test('spec version 0.1, and any other version is refused', () => {
  assert.equal(SPEC_VERSION, '0.1');
  assert.equal(spec.specVersion, '0.1');
  const wrong = { ...(CLASSES_RAW as Record<string, unknown>), specVersion: '0.2' };
  assert.throws(() => parseSpec(wrong, NORMALIZE_RAW), /unsupported specVersion/);
});

test('a normalized span maps back to the original words', () => {
  const text = 'my card is four five three nine';
  const n = normalize(text, spec.normalize);
  assert.equal(n.text, 'my card is 4539');
  const [s, e] = toOriginal(n, 11, 15);
  assert.equal(text.slice(s, e), 'four five three nine');
});

test('offsets are UTF-16 code units, also after an emoji', () => {
  const turns: Turn[] = [
    { speaker: 'agent', text: 'Your social security number?' },
    { speaker: 'customer', text: '\u{1F44D} five one two four three seven seven eight eight' },
  ];
  const [m] = classify(spec, turns, { now: new Date('2026-09-29') }).matches;
  assert.ok(m);
  assert.equal(m.start, 3); // the emoji is two code units, then a space
  assert.equal(turns[1]!.text.slice(m.origStart, m.origEnd).startsWith('five'), true);
});

test('redactTurns masks the original text of every part of a split value', () => {
  const turns: Turn[] = [
    { speaker: 'agent', text: 'And your social security number?' },
    { speaker: 'customer', text: 'five one two' },
    { speaker: 'agent', text: 'mm-hmm' },
    { speaker: 'customer', text: 'four three' },
    { speaker: 'customer', text: 'seven seven eight eight.' },
  ];
  const out = redactTurns(spec, turns, { now: new Date('2026-09-29') });
  assert.equal(out[0], turns[0]!.text);
  assert.equal(out[1], '############');
  assert.equal(out[2], 'mm-hmm');
  assert.equal(out[3], '##########');
  assert.equal(out[4], '#######################.');
});

test('armedClasses: what the next customer entry should be redacted as', () => {
  const prompt: Turn = { speaker: 'bot', text: 'Please enter your date of birth.' };
  assert.deepEqual(armedClasses(spec, [prompt]), ['dob']);
  assert.deepEqual(armedClasses(spec, [prompt, { speaker: 'customer', text: '0230' }]), []);
  assert.deepEqual(
    armedClasses(spec, [
      prompt,
      { speaker: 'customer', text: '0230' },
      { speaker: 'bot', text: "Sorry. I didn't get that." },
    ]),
    ['dob'],
  );
});

test('results carry no digits: every string field is a class, via or confidence', () => {
  const turns: Turn[] = [
    { speaker: 'bot', text: 'Please enter your credit card number.' },
    { speaker: 'customer', text: '5555666677778888#', channel: 'dtmf' },
  ];
  const r = classify(spec, turns);
  const strings: string[] = [];
  JSON.stringify(r, (_k, v: unknown) => {
    if (typeof v === 'string') strings.push(v);
    return v;
  });
  for (const s of strings) assert.doesNotMatch(s, /[0-9]/);
});
