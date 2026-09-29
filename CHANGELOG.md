# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a breaking change
bumps the minor version. Spec changes are listed under **Spec**.

## Unreleased

### Feature
- A DynamoDB source adapter (`SCAN_DYNAMODB`). It reads named tables with a
  paginated Query (a partition key value, optionally a sort-key prefix) or a
  Scan, read-only, with a projection on the configured attribute paths
  (`stepResults[].observedDtmf`, `[]` for list elements). Throttled requests
  back off and retry; a page cap and the run budget bound each run, and the
  next run resumes at the last item read. Each string leaf is read on its
  own. Keypad (DTMF) leaves are read as `dtmf` turns after the prompt that
  asked for them, with the spec's normalization, so `123456789#` after an
  SSN prompt is an SSN. Planted test inputs (`planted` paths) are marked in
  their findings. A finding names the table, a salted hash of the item key,
  the key masked like an S3 object key, and the attribute path; never a
  value. The no-leak suite covers the adapter, and positive and negative
  control fixtures in a call-test result's shape prove findings on one and
  none on the other.
- The findings schema gains the `dynamodb_item` resource and format and the
  `dynamodb` coverage kind. They are additive and appear only when a
  DynamoDB source is configured; `schemaVersion` stays `1.0`.
- `[REDACTED]` and `[REDACTED:<label>]` count as redaction markers in
  coverage, like `[PII]`.

### Docs
- README and `docs/ARCHITECTURE.md`: the DynamoDB source, its configuration
  and its IAM permissions (`dynamodb:Query`, `dynamodb:Scan`,
  `dynamodb:DescribeTable` on the named tables, and `kms:Decrypt` where a
  table uses a customer managed key). `docs/FINDINGS.md`: the DynamoDB
  resource.

### Internal
- Release: build the wheel only (the sdist could not carry the spec and
  licenses), and allow re-running the release of an existing tag by hand.

## 0.1.0 — 2026-09-29

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

- AWS adapters and the batch runner: an S3 source (incremental by
  LastModified, one version per item, budgets, stated sampling, partial reads)
  and a CloudWatch Logs source (FilterLogEvents with budgets, Lex records
  grouped by session). Parsers for Connect chat and Contact Lens transcripts,
  Lex V2 conversation logs, Connect flow logs and Lambda JSON logs. The
  runner holds a lock and carries state between runs.
- The findings contract, schema version 1.0 (`schema/findings.schema.json`,
  `docs/FINDINGS.md`). It covers account, region, resource (bucket/key and
  versionId, or log group/stream and timestamp, and the Connect contact),
  class, count, confidence, offsets, via, a console deep link and coverage.
  Never a value.
- Optional push of findings as EventBridge events (`sensitive-data-scanner`,
  `Findings v1`) to a consumer-owned bus (`FINDINGS_EVENT_BUS_ARN`).
- The no-leak suite scans every vector end to end and asserts that no value
  appears in findings, events, logs, exception messages or reprs. It also
  audits every logging call and every raised exception in the source.

- Packaging: a Lambda container image (Python 3.12 slim, runtime interface
  client, base images pinned by digest) and a Lambda zip (python3.12,
  x86_64). The release workflow builds both, attaches SPDX SBOMs and SHA-256
  checksums to the GitHub Release, and pushes the image to GHCR.
  `docs/RELEASING.md` describes the steps and what is pending (signing,
  hosting).

### Docs
- README usage, `docs/ARCHITECTURE.md` (batch mode, and the event-driven
  phase 2 design with push delivery to a consumer-owned EventBridge bus).
  `docs/FINDINGS.md` (the findings schema) and `docs/RELEASING.md`.

### Internal
- CI: Python (ruff, mypy, pytest), Node (typecheck, tests), gitleaks and
  zizmor, all SHA-pinned.
