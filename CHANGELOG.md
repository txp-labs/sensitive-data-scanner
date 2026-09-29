# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a breaking change
bumps the minor version. Spec changes are listed under **Spec**.

## Unreleased

### Spec
- **Spec 0.4** ([#26](https://github.com/txp-labs/sensitive-data-scanner/issues/26), asked for as 0.3.1; the spec has
  no patch version, and a phrase that changes matches is a minor bump. Every
  change is listed for consumers in `spec/README.md`, "Changes from 0.3"):
  - `us_ssn` and `us_itin` gain `(?:nine|9)[- ]digit social(?: security)?(?:
    number)?(?! media)`, so "Please say your nine digit social." arms them.
    "social" alone still arms nothing, "nine digit social media account
    number" arms only `account_number`, and "19 digit social code" arms
    nothing.
  - The `us_ssn` comment in `classes.yaml` now describes the letter-and-digit
    boundary the implementations apply.
  - `specVersion` is `"0.4"`; the JSON Schemas follow.
- Vectors: five cases in `vectors/prompt-phrases.jsonl`, near-misses
  included, passed by the Python engine, the Presidio path and the
  TypeScript package alike.
- `@txp-labs/sensitive-data-spec` exports `promptRegex`, the spec's prompt
  boundary around a phrase, and its README explains why the package version
  follows releases while `SPEC_VERSION` follows the spec. `dist/` is rebuilt.
- **Spec 0.3** ([#11](https://github.com/txp-labs/sensitive-data-scanner/issues/11); every change is listed for consumers in
  `spec/README.md`, "Changes from 0.2", which Stugum mirrors):
  - Prompt phrases match only with neither a letter nor a digit on each
    side; the implementations apply the boundary, so phrases no longer carry
    `\b`. "stubborn" no longer arms `dob`.
  - Tolerant variants for dropped words: `social(?: security)? number`,
    `taxpayer id(?:entification)? number`, `birth ?date`, `cvc`,
    `(?:three|four|3|4)[- ]digit (?:security )?code`, the number on the
    front (card) or back (cvv) of your card, and one `us_ssn_last4` phrase
    that takes "last four digits of your Social Security number".
  - Retry prefixes are runs of words that may be apart by whitespace and
    `. , ! ? ; :` ("Sorry, I didn't get that!"), still only at the start of a
    turn; two "catch"/"get" variants are added.
  - `card.promptedWithoutShape` is removed: every class is `low` when a
    prompted value passes no shape.
  - `specVersion` is `"0.3"`; the JSON Schemas follow.
- Vectors: `vectors/prompt-phrases.jsonl`, a case for each rule with its
  near-misses, passed by the Python engine, the Presidio path and the
  TypeScript package alike.
- **Spec 0.2** ([#15](https://github.com/txp-labs/sensitive-data-scanner/issues/15); every change is listed for consumers in
  `spec/README.md`, "Changes from 0.1", which Stugum mirrors):
  - Keypad (`dtmf`) answers may be keyed in parts: `answerWindowChannels:
    [dtmf]` replaces `neverJoinChannels`. The parts join within one answer
    window and never across a turn of another speaker.
  - A menu or question turn (`menuOrQuestionTurns`: `?`, `press`, `reply`,
    `say`, `enter`, ...) ends a pending value, like a prompt; a backchannel
    still does not.
  - A new class, `us_itin` (severity `high`, the same as `us_ssn`): 9xx area,
    groups 50-65, 70-88, 90-92 and 94-99; armed by SSN and ITIN prompts;
    context words include the SSN words; standalone when formatted; the IRS
    advertising range 987-65-4320 to 4329 in `testNumbers`. `987654320`
    moves there from `us_ssn.dummyValues`.
  - `specVersion` is `"0.2"`; the JSON Schemas follow.
- Vectors: `vectors/answer-windows.jsonl` and `vectors/itin.jsonl`, passed by
  the Python engine, the Presidio path and the TypeScript package alike.

### Feature
- Redshift and Redshift Serverless ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5):
  discovery (`DISCOVER` kind `redshift`: `DescribeClusters`, `ListWorkgroups`,
  `ListNamespaces`) and, opt-in (`REDSHIFT_READ=iam` or `db_user`), sampled
  read-only SQL through the Redshift Data API with no stored password: the
  scanner's own IAM identity, or temporary credentials for an existing
  read-only database user. Column-level findings (`store_field`). Paused
  clusters, stores not configured for reading, and users that can see no
  table are reported (`paused`, `read_not_configured`, `no_grant`). The
  UNLOAD trade-off is documented in docs/ARCHITECTURE.md.
- OpenSearch ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5): managed domains
  (`ListDomainNames`, `DescribeDomains`) and Serverless collections are
  discovered (`DISCOVER` kind `opensearch`); each domain's open indices are
  sampled with signed HTTPS GETs only (`_cat/indices`, `_search?size=n`,
  `OPENSEARCH_DOCS_PER_INDEX`, `OPENSEARCH_MAX_INDICES`), and each document
  read field by field (`store_field`, `readBy: search`). VPC-only domains
  (`vpc_only`), refused domains (`access_denied`) and Serverless collections
  (opt-in, `OPENSEARCH_SERVERLESS_READ`) are reported.
- The adapter interface (`sources/base.py`, `Adapter`) and the generic
  sampled SQL pass (`scan/sql.py`): every new kind of store plugs into
  discovery, the budget and the run summary through them, with no cloud in
  the core. The RDS Data API mode now runs on the same SQL pass.
- Findings schema **1.3** (additive): the `store_field` resource, the
  `redshift` and `opensearch` kinds, the store reasons
  `read_not_configured`, `paused`, `no_grant` and `vpc_only`, and the store
  fields `deployment`, `database` and `state`.
- `deploy/scanner.yaml`: `RedshiftRead` and `RedshiftDbUser`; Redshift
  describe permissions, and, only when reading, the Data API on this
  account's clusters and workgroups, its own statements only, and the
  credential call for the mode chosen. User creation, `JoinGroup` and
  batch statements are denied. OpenSearch: describe and list,
  `es:ESHttpGet` on this account's domains (every other HTTP verb denied),
  and, only with `OpenSearchServerlessRead`, `aoss:APIAccessAll` on its
  collections.
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
- `SpecUsItinRecognizer` in the Presidio pipeline, and `us_itin` findings
  (severity `high`).
- `@txp-labs/sensitive-data-spec` exports `isMenuOrQuestion` and
  `itinStructureValid`.

- Columnar and data-lake formats in S3: Parquet and ORC (pyarrow, one row
  group or stripe at a time through ranged GETs, up to `COLUMNAR_MAX_ROWS`),
  Avro (a small reader of its own; every codec), and zstd as well as gzip
  CSV and JSON lines. Files without an extension are recognized by their
  magic bytes. Findings name the column, and offsets the row and column.
- Glue Data Catalog discovery (`DISCOVER` with `glue`): each table is read
  at its S3 location, and findings name the database, table and column.
  CSV tables are read with the catalog's columns and SerDe delimiter; views,
  non-S3 tables and resource links are reported, not read. A bucket leaves
  its tables' prefixes to them.
- Lake Formation is respected: the scanner reads with its own IAM only and
  never asks Lake Formation for access. A denial is reported as
  `lake_formation`; `GLUE_LAKE_FORMATION=skip` leaves registered tables
  unread and reported.

- RDS and Aurora by snapshot export (`DISCOVER` with `rds`): the latest
  automated snapshot of each cluster and standalone instance is exported to
  the results bucket's `exports/rds/` prefix with the customer's KMS key
  (`RDS_EXPORT_ROLE_ARN`, `RDS_EXPORT_KMS_KEY_ARN`), read as Parquet by
  column, and deleted. Findings name the engine, cluster, database and
  `schema.table.column`. At most `MAX_EXPORTS_PER_RUN` exports start per run,
  and a store is exported again after `EXPORT_MIN_INTERVAL_DAYS`. No
  database credentials and no load on the database.
- An opt-in read-only SQL mode for small Aurora databases (`RDS_DATA_API`,
  off by default): `SELECT … LIMIT n` per table through the Data API, in a
  transaction that is always rolled back (read-only on PostgreSQL), with
  quoted identifiers and bound parameters.
- DynamoDB Export to S3 for tables too large to Scan (`DYNAMODB_EXPORT`):
  point-in-time, no read capacity used, read like the DynamoDB source and
  deleted afterwards. A large table without point-in-time recovery is
  reported as `pitr_off`.

- Estate rollout: `deploy/scanner.yaml` puts the scanner in one account and
  region (results bucket, function, schedule, and least-privilege read-only
  IAM per source, with explicit denies on writes elsewhere and on Lake
  Formation), and `deploy/estate-stackset.yaml` deploys it through a
  service-managed StackSet to every account of the organizational units and
  every region named, including accounts that join later, with findings
  pushed to the existing central EventBridge bus. Releases attach both
  templates.

### Findings schema
- `schemaVersion` is now **1.2**, additive: the `discovery` summary,
  `kmsDenied` in coverage, `#` allowed in a masked bucket or table name,
  `column` and `catalog` on an S3 object, the `rds_column` resource, the
  `parquet`, `orc`, `avro` and `sql` formats, the `glue_table` and `rds`
  coverage kinds, the `columnar` skip kind, and the `lake_formation`,
  `export_not_configured`, `export_pending`, `export_failed`, `no_snapshot`
  and `pitr_off` reasons. EventBridge parts now also split `coverage` and
  `discovery.stores`.

### Internal
- CI lints the templates with cfn-lint, and `test_template.py` checks that the
  scanner's role allows only reads and aimed writes, that every AWS call the
  code makes is allowed, that every allowed action is documented, and that
  every environment variable the template sets is one the code reads.
- pyarrow joins as the `columnar` dependency group, installed in the
  container image and not in the Lambda zip, which it would push past
  Lambda's 250 MB unzipped limit. The zip counts the formats it cannot read
  as skipped `columnar`; CI checks the zip has no pyarrow and the image reads
  Parquet and ORC. fastavro is a test-only dependency, to write Avro
  fixtures with an implementation other than the scanner's.

### Security
- A bucket or table name holding a number that could be a card or an SSN is
  now masked in findings, like an object key, and a finding whose log group
  or stream name was masked no longer carries a console link (the link held
  the name unmasked). The no-leak suite covers discovery, with stores whose
  names hold values, the columnar formats and catalog, with values in cells,
  column names, nested keys and table names, and the RDS export and Data API
  paths, with values in cluster, database, table and column names.
- A nine-digit run in a name is now masked whatever separator and digits
  follow it (`orders-123456789-1`); before, a following `-1` let it through.
  RDS findings carry the snapshot's time, not its name, which repeats the
  cluster's.

### Docs
- `docs/ARCHITECTURE.md`: discovery, the overrides, sampling, the budget,
  the run summary, columnar formats, Glue and Lake Formation, RDS and
  DynamoDB exports, the estate rollout, and the IAM per source.
  `docs/FINDINGS.md`: schema 1.2, the run summary, and column and database
  findings. `docs/RELEASING.md`: which formats the image and the zip read,
  and the templates attached to a release.

### Internal
- `packages/spec-ts/dist/` is committed, so the package can be consumed by
  git commit (package managers do not build git dependencies). A CI job
  rebuilds it and fails if it differs. `exports` still points at `dist/`.

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
