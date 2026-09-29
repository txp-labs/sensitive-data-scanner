/**
 * @txp-labs/sensitive-data-spec: the sensitive-data spec, normalization and
 * prompt-carryover classification of conversation turns, for in-memory
 * redaction. No runtime dependencies. Nothing here logs, stores or returns
 * a detected value: results are classes and offsets.
 */
export { SPEC_VERSION, loadSpec, parseSpec, } from './spec.js';
export { normalize, toOriginal } from './normalize.js';
export { cardBrand, itinStructureValid, luhnValid, ssnStructureValid } from './rules.js';
export { classify, isMenuOrQuestion, promptClasses, } from './conversation.js';
export { redactTurns, armedClasses } from './redact.js';
