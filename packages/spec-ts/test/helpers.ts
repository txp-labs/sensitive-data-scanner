import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Turn } from '../src/index.ts';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const VECTORS = join(REPO, 'vectors');
/** Vectors are evaluated as of this date (spec/README.md, "Vectors"). */
export const VECTOR_DATE = new Date('2026-09-29T12:00:00Z');

export interface Expect {
  turn: number;
  endTurn?: number;
  class: string;
  start: number;
  end: number;
  via: string;
  confidence: string;
}

export interface Vector {
  id: string;
  source: string;
  description?: string;
  now?: string;
  turns: Turn[];
  expect: Expect[];
  document?: { format: string; content: string };
}

export interface NormalizeVector {
  id: string;
  text: string;
  normalized: string;
  digitRuns: [number, number, number, number][];
}

function jsonl<T>(path: string): T[] {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as T);
}

export function conversationVectors(): { file: string; vector: Vector }[] {
  return readdirSync(VECTORS)
    .filter((f) => f.endsWith('.jsonl') && f !== 'normalize.jsonl')
    .sort()
    .flatMap((file) => jsonl<Vector>(join(VECTORS, file)).map((vector) => ({ file, vector })));
}

export function normalizeVectors(): NormalizeVector[] {
  return jsonl<NormalizeVector>(join(VECTORS, 'normalize.jsonl'));
}
