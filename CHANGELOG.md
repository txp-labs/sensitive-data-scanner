# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a breaking change
bumps the minor version. Spec changes are listed under **Spec**.

## Unreleased

### Feature
- Discovery (`DISCOVER=all`, or any of `s3`, `logs`, `dynamodb`): each run
  lists the S3 buckets in its region, the CloudWatch log groups and the
  DynamoDB tables in its account, and reads each with the existing adapters.
  No list to write. The explicit configuration keeps working, and is read
  first; a store it names is read as configured.
- Allow and deny overrides (`DISCOVER_ALLOW`, `DISCOVER_DENY`) by name glob
  or by tag, optionally per kind (`s3:prod-*`, `tag:scan=false`). Deny wins,
  and a store whose tags cannot be read while a deny-by-tag rule exists is
  not read. The scanner's own bucket and log group are never read.
- Per-store sampling (`DISCOVER_SAMPLING`): a percentage, and for S3 a cap on
  objects per "directory" (`S3_MAX_OBJECTS_PER_PREFIX`); DynamoDB tables are
  sampled by parallel-scan segment (`DYNAMODB_SAMPLE_PERCENT`), and a table
  over `DYNAMODB_MAX_TABLE_BYTES` after sampling is skipped as too large.
- Per-run budget by kind (`MAX_OBJECTS_PER_RUN`, `MAX_LOG_EVENTS_PER_RUN`,
  `MAX_TABLE_ITEMS_PER_RUN`) and wall time (`MAX_RUN_SECONDS`), within the
  existing item and byte budget. Stores the budget does not reach are
  deferred, and the next run starts with them; each store resumes from its
  own cursor.
- The run summary: the findings document's `discovery` lists every store,
  read or not, and why (`denied`, `not_allowed`, `self`, `too_large`,
  `unsupported`, `unsupported_format`, `kms_access`, `access_denied`,
  `tags_unreadable`, deferred for `budget`), with counts of objects not read
  for KMS, unreadable or unsupported formats. A failed listing is named.

### Findings schema
- `schemaVersion` is now **1.2**, additive: the `discovery` summary,
  `kmsDenied` in coverage, and `#` allowed in a masked bucket or table name.
  EventBridge parts now also split `coverage` and `discovery.stores`.

### Security
- A bucket or table name holding a number that could be a card or an SSN is
  now masked in findings, like an object key, and a finding whose log group
  or stream name was masked no longer carries a console link (the link held
  the name unmasked). The no-leak suite covers discovery, with stores whose
  names hold values.

### Docs
- `docs/ARCHITECTURE.md`: discovery, the overrides, sampling, the budget,
  the run summary, and the read-only IAM each kind of discovery needs.
  `docs/FINDINGS.md`: schema 1.2 and the run summary.

## 0.2.0 — 2026-09-29

### Feature
- A DynamoDB source adapter (`SCAN_DYNAMODB`). It reads named tables with a
  paginated Query (a partition key value, optionally a sort-key prefix) or a
  Scan, read-only, with a projection on the configured attribute paths.
  Throttled requests back off and retry; a page cap and the run budget bound
  each run, and the next run resumes at the last item read.
- Attribute paths use `.` for map keys, `[]` for every list element, and
  `[name=value]` for the list elements whose attribute has that value
  (`stepResults[kind=sendDtmf].observedDtmf`), in `include`, `exclude`,
  `keypad`, `prompts` and `planted`.
- Each string leaf is read on its own. Each keypad (DTMF) leaf is paired
  with the nearest preceding prompt in the same list, in the order of the
  configured `orderBy` attribute (`stepIndex`) or else by position, and read
  as a `dtmf` turn after it with the spec's normalization, so `123456789#`
  after an SSN prompt is an SSN. Only configured prompt paths are prompts: an
  expected-prompt regular expression in a test script never classes an
  entry. Planted test inputs (`planted` paths) are marked in their findings.
- A DynamoDB finding names the table, a salted hash of the item key, the key
  masked like an S3 object key, and the attribute path; never a value. The
  no-leak suite covers the adapter. Fixtures in the shape of Stugum's
  call-test runs (made-up values) prove findings on a positive control and
  none on a negative control whose entries read
  `[REDACTED:ssn · asked for SSN]`.
- `[REDACTED]` and `[REDACTED:<label>]` count as redaction markers in
  coverage, like `[PII]`.

### Findings schema
- `schemaVersion` is now **1.1**, an additive change: the `dynamodb_item`
  resource and format, and the `dynamodb` coverage kind. A consumer that
  ignores what it does not know is unaffected; one that checks for exactly
  `"1.0"` must accept `"1.1"`.

### Docs
- README and `docs/ARCHITECTURE.md`: the DynamoDB source, its configuration
  (with Stugum's run items as the example) and its IAM permissions
  (`dynamodb:Query`, `dynamodb:Scan`, `dynamodb:DescribeTable` on the named
  tables, and `kms:Decrypt` where a table uses a customer managed key).
  `docs/FINDINGS.md`: schema 1.1 and the DynamoDB resource.

### Internal
- Release: build the wheel only (the sdist could not carry the spec and
  licenses), and allow re-running the release of an existing tag by hand.
- `@txp-labs/sensitive-data-spec` moves to 0.2.0 with the runner; the spec
  (0.1) and the package's behavior are unchanged.

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
