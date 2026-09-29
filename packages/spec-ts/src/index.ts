/**
 * @txp-labs/sensitive-data-spec: the sensitive-data spec, normalization and
 * prompt-carryover classification of conversation turns, for in-memory
 * redaction. No runtime dependencies. Nothing here logs, stores or returns
 * a detected value: results are classes and offsets.
 */
export {
  SPEC_VERSION,
  loadSpec,
  parseSpec,
  type BrandRule,
  type ClassSpec,
  type NormalizeSpec,
  type Spec,
} from './spec.ts';
export { normalize, toOriginal, type Normalized } from './normalize.ts';
export { cardBrand, luhnValid, ssnStructureValid } from './rules.ts';
export {
  classify,
  promptClasses,
  type Channel,
  type ClassifyOptions,
  type Confidence,
  type Excluded,
  type Match,
  type MatchPart,
  type Result,
  type Speaker,
  type Turn,
  type Via,
} from './conversation.ts';
export { redactTurns, armedClasses } from './redact.ts';
