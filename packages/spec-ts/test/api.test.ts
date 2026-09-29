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
  isMenuOrQuestion,
  itinStructureValid,
  loadSpec,
  normalize,
  parseSpec,
  promptClasses,
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

test('spec version 0.3, and any other version is refused', () => {
  assert.equal(SPEC_VERSION, '0.3');
  assert.equal(spec.specVersion, '0.3');
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

test('an SSN prompt arms us_itin too; an ITIN prompt arms only us_itin', () => {
  const ssn: Turn = { speaker: 'bot', text: 'Please enter or say your nine digit Social Security number.' };
  assert.deepEqual(armedClasses(spec, [ssn]), ['us_ssn', 'us_itin']);
  assert.deepEqual(armedClasses(spec, [{ speaker: 'agent', text: 'And your ITIN?' }]), ['us_itin']);
  assert.deepEqual(armedClasses(spec, [{ speaker: 'bot', text: 'The last four of your social?' }]), [
    'us_ssn_last4',
  ]);
});

test('ITIN structure: a 9xx area and a group in 50-65, 70-88, 90-92 or 94-99', () => {
  for (const ok of ['912501234', '912651234', '912701234', '912881234', '912901234', '912921234', '912941234', '912991234']) {
    assert.equal(itinStructureValid(ok), true, ok);
  }
  for (const bad of ['912491234', '912661234', '912691234', '912891234', '912931234', '812701234', '91270123']) {
    assert.equal(itinStructureValid(bad), false, bad);
  }
});

test('menu and question turns, and backchannels', () => {
  for (const t of ['Thanks. Reply 1 for more.', 'Is that a Visa?', 'Press 2 to repeat.', 'Please say or enter it again.']) {
    assert.equal(isMenuOrQuestion(spec, t), true, t);
  }
  for (const t of ['Mm-hmm.', 'Okay.', 'Thank you.', 'Got it, go on.']) {
    assert.equal(isMenuOrQuestion(spec, t), false, t);
  }
});

test('prompt phrases match only with no letter or digit on either side (spec 0.3)', () => {
  assert.deepEqual(promptClasses(spec, "I'm being stubborn about it.")[0], []);
  assert.deepEqual(promptClasses(spec, 'When were you born?')[0], ['dob']);
  assert.deepEqual(promptClasses(spec, 'Enter the 14 digit code.')[0], []);
  assert.deepEqual(promptClasses(spec, 'Enter the 4 digit code.')[0], ['cvv']);
  assert.deepEqual(promptClasses(spec, 'SSN:')[0], ['us_ssn', 'us_itin']);
});

test('retry prefixes ignore . , ! ? ; : and match only at the start (spec 0.3)', () => {
  for (const t of ["Sorry, I didn't get that!", 'Sorry. I didn’t get that.', "  sorry; i didn't   catch that?", "I'm sorry I didn't catch that."]) {
    assert.equal(promptClasses(spec, t)[1], true, t);
  }
  for (const t of ["Okay. Sorry, I didn't get that.", "Sorry I didn't get thatcher's file.", 'Sorry, I missed that.']) {
    assert.equal(promptClasses(spec, t)[1], false, t);
  }
});
