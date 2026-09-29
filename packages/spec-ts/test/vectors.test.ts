/** Every vector in vectors/ passes: normalization pairs and conversation cases. */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { classify, loadSpec, normalize, toOriginal } from '../src/index.ts';
import { VECTOR_DATE, conversationVectors, normalizeVectors } from './helpers.ts';

const spec = loadSpec();

describe('normalize.jsonl', () => {
  for (const v of normalizeVectors()) {
    test(v.id, () => {
      const n = normalize(v.text, spec.normalize);
      assert.equal(n.text, v.normalized);
      const runs = [...n.text.matchAll(/[0-9]+/g)].map((m) => {
        const [os, oe] = toOriginal(n, m.index, m.index + m[0].length);
        return [m.index, m.index + m[0].length, os, oe];
      });
      assert.deepEqual(runs, v.digitRuns);
    });
  }
});

describe('conversation vectors', () => {
  const all = conversationVectors();
  test('there are vectors to run', () => assert.ok(all.length >= 50));
  for (const { file, vector } of all) {
    test(`${file} ${vector.id}`, () => {
      const now = vector.now ? new Date(`${vector.now}T12:00:00Z`) : VECTOR_DATE;
      const got = classify(spec, vector.turns, { now }).matches.map((m) => ({
        turn: m.turn,
        ...(m.endTurn !== m.turn ? { endTurn: m.endTurn } : {}),
        class: m.class,
        start: m.start,
        end: m.end,
        via: m.via,
        confidence: m.confidence,
      }));
      const want = vector.expect.map((e) => ({
        turn: e.turn,
        ...(e.endTurn !== undefined && e.endTurn !== e.turn ? { endTurn: e.endTurn } : {}),
        class: e.class,
        start: e.start,
        end: e.end,
        via: e.via,
        confidence: e.confidence,
      }));
      assert.deepEqual(got, want);
    });
  }
});
