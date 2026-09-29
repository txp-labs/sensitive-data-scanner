/**
 * Compile spec/classes.yaml and spec/normalize.yaml into
 * src/spec.generated.ts, so the package needs no YAML parser at run time.
 *
 *   node scripts/gen-spec.ts          write the file
 *   node scripts/gen-spec.ts --check  fail if the file is out of date
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const specDir = join(here, '..', '..', '..', 'spec');
const target = join(here, '..', 'src', 'spec.generated.ts');

export function generated(): string {
  const classes: unknown = parse(readFileSync(join(specDir, 'classes.yaml'), 'utf8'));
  const normalize: unknown = parse(readFileSync(join(specDir, 'normalize.yaml'), 'utf8'));
  return [
    '// Generated from spec/classes.yaml and spec/normalize.yaml by scripts/gen-spec.ts.',
    '// Do not edit by hand: change the YAML and run `npm run gen:spec`.',
    '',
    `export const CLASSES_RAW: unknown = ${JSON.stringify(classes, null, 2)};`,
    '',
    `export const NORMALIZE_RAW: unknown = ${JSON.stringify(normalize, null, 2)};`,
    '',
  ].join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = generated();
  if (process.argv.includes('--check')) {
    const current = readFileSync(target, 'utf8');
    if (current !== text) {
      console.error('src/spec.generated.ts is out of date: run `npm run gen:spec`.');
      process.exit(1);
    }
  } else {
    writeFileSync(target, text);
  }
}
