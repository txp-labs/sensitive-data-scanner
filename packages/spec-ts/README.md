# @txp-labs/sensitive-data-spec

The [sensitive-data spec](../../spec/README.md) (version 0.7) and a classifier
for conversation turns, for **in-memory redaction** in a call engine. It has
no runtime dependencies. It never logs, stores or returns a detected value:
results are classes and offsets.

On npm: `npm install @txp-labs/sensitive-data-spec`. From 0.5.0 every
release publishes it from this repository's release workflow with npm
provenance; `npm audit signatures` verifies it.

> Between releases, depend on it by git commit. The compiled `dist/` is
> committed (package managers do not build git dependencies), so pin a
> commit on `main`, for example with pnpm:
>
> ```json
> "@txp-labs/sensitive-data-spec": "github:txp-labs/sensitive-data-scanner#<commit>&path:packages/spec-ts"
> ```

## Use

```ts
import { armedClasses, classify, loadSpec, redactTurns } from '@txp-labs/sensitive-data-spec';

const spec = loadSpec();
const turns = [
  { speaker: 'bot', text: 'Please enter or say your nine digit Social Security number.' },
  { speaker: 'customer', channel: 'dtmf', text: '123456789#' },
] as const;

classify(spec, [...turns]).matches;
// [{ class: 'us_ssn', via: 'prompt', confidence: 'high', turn: 1, start: 0, end: 9,
//    origStart: 0, origEnd: 9, parts: [...] , ... }]

redactTurns(spec, [...turns]);
// ['Please enter or say your nine digit Social Security number.', '#########']

// Before the answer arrives: what the next customer entry will be.
armedClasses(spec, [turns[0]]); // ['us_ssn', 'us_itin']
```

- **`classify(spec, turns, { now })`** returns every match in the conversation:
  - `class`, `via` (`prompt` / `context` / `shape`) and `confidence`
    (`high` / `medium` / `low`);
  - the span in the normalized text (`turn`, `start`, `endTurn`, `end`);
  - the span in the original text (`origStart`, `origEnd`);
  - `parts`, one per turn, for a value split across turns.

  It also returns the values set aside as published test data (`excluded`),
  and a count of numbers dropped because a word like "order" or "phone" was
  next to them (`suppressed`).
- **`redactTurns`** masks every part of every match in the original texts.
- **`armedClasses`** gives the classes the last prompt armed for the next
  customer turn (`promptCarryover.turns: 1`; a retry re-arms). An SSN prompt
  arms `us_ssn` and `us_itin`.
- **`isMenuOrQuestion`** tells whether a bot or agent turn is a menu or a
  question, which ends a value the caller is still giving.
- **`normalize(text, spec.normalize)`** and **`toOriginal`** expose the
  normalization and its offset map.
- **`promptRegex(phrase)`** wraps a phrase in the spec's prompt boundary
  (neither a letter nor a digit on either side; case-insensitive, global).
  Use it for a phrase of your own instead of copying the boundary.

Offsets are UTF-16 code units, the same as JavaScript string indexes.

## Versions: the package and the spec

These are two separate numbers:

- **The package version** (`version` in `package.json`) follows the
  repository's **releases**. It is the same as the scanner's version and
  changes only when a release is cut (`docs/RELEASING.md`). Between
  releases, a commit on `main` keeps the last release's version even when
  the spec under it has moved on. So the package said 0.2.0 at the spec 0.3
  commit, and it says 0.5.0 from release 0.5.0 on (0.3.0 was prepared and never published).
- **The spec version** (`SPEC_VERSION`, and `specVersion` in the spec files
  and in `loadSpec().specVersion`) follows the **spec**
  (`spec/README.md`, Stability). It changes whenever the contract does, in
  whatever commit changes it.

When you pin a commit, check `SPEC_VERSION` to know which contract you have.
Do not rely on the package version for that.

## Tested against the contract

`npm test` runs every case in [`vectors/`](../../vectors). The Python runner's
test suite runs this package too (`scripts/parity.ts`) and fails if the two
disagree on any vector.

The spec is compiled into `src/spec.generated.ts` from `spec/*.yaml` by
`npm run gen:spec`. CI fails if the compiled copy is out of date.

`dist/` is committed and built by `npm run build`. CI rebuilds it and fails if
the result differs from what is committed, so after any change under `src/`
run `npm run build` and commit `dist/` with it.
