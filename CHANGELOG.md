# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a breaking change
bumps the minor version. Spec changes are listed under **Spec**.

## Unreleased

### Spec
- The sensitive-data spec, version 0.1: `spec/classes.yaml` and
  `spec/normalize.yaml`, JSON Schemas for them and for the vectors, and the
  contract in `spec/README.md`, which lists every change from the v0 draft.
- Test vectors: every Stugum live-run case, and
  txp-labs/mermera-attestation-app#1067's fixtures as conversations (Connect
  chat, Contact Lens, Lex V2 logs, Connect flow logs, spoken and split-turn
  forms, near-misses, redacted turns), plus normalization pairs. An emoji case
  checks that offsets are UTF-16 code units in both implementations.

### Feature
- `@txp-labs/sensitive-data-spec` (`packages/spec-ts`, not yet published):
  loads the spec, normalizes turns with an offset map back to the original
  text, classifies conversations (prompt carryover, split turns, shape and
  context), and redacts matches in memory. No runtime dependencies. Tested
  against every vector.

- The Python runner's detection (`scanner/`): Presidio Analyzer with no NLP
  model. It adds the spec's card and SSN rules to Presidio's recognizers, and
  a DOB recognizer. Custom recognizers cover spoken digits and conversations:
  question-then-answer prompt carryover and split same-speaker turns. A
  context enhancer works without an NLP model. It is tested against every
  vector through the spec engine and through Presidio, and a parity test
  fails if the Python and TypeScript implementations disagree on any vector.

### Internal
- CI: Python (ruff, mypy, pytest), Node (typecheck, tests), gitleaks and
  zizmor, all SHA-pinned.
