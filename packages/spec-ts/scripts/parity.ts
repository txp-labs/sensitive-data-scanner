/**
 * Print this package's results for every vector as JSON, for the Python
 * runner's parity test (scanner/tests/test_parity.py), which fails if the two
 * implementations disagree on anything: normalized text, digit-run offsets,
 * matches with their original offsets and parts, exclusions, suppressions.
 *
 *   node scripts/parity.ts [vectors-dir]
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classify, loadSpec, normalize, toOriginal, type Turn } from '../src/index.ts';

const dir = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'vectors');
const spec = loadSpec();
const DEFAULT_NOW = new Date('2026-09-29T12:00:00Z');

const lines = (f: string) =>
  readFileSync(join(dir, f), 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>);

const out: { normalize: Record<string, unknown>; conversations: Record<string, unknown> } = {
  normalize: {},
  conversations: {},
};
for (const v of lines('normalize.jsonl')) {
  const n = normalize(String(v.text), spec.normalize);
  out.normalize[String(v.id)] = {
    normalized: n.text,
    digitRuns: [...n.text.matchAll(/[0-9]+/g)].map((m) => [
      m.index,
      m.index + m[0].length,
      ...toOriginal(n, m.index, m.index + m[0].length),
    ]),
  };
}
for (const f of readdirSync(dir).filter((x) => x.endsWith('.jsonl') && x !== 'normalize.jsonl').sort()) {
  for (const v of lines(f)) {
    const turns = v.turns as Turn[];
    const now = typeof v.now === 'string' ? new Date(`${v.now}T12:00:00Z`) : DEFAULT_NOW;
    const r = classify(spec, turns, { now });
    out.conversations[String(v.id)] = {
      normalized: turns.map((t) => normalize(t.text, spec.normalize).text),
      matches: r.matches,
      excluded: r.excluded,
      suppressed: r.suppressed,
    };
  }
}
process.stdout.write(`${JSON.stringify(out)}\n`);
