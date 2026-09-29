# Architecture

The scanner runs **inside the AWS account it scans**. It reads the stores it
is given, and it reports **findings only** ([FINDINGS.md](FINDINGS.md)):
never a value. Detection is Microsoft Presidio with no NLP model, plus the
recognizers for the spec's classes ([spec/README.md](../spec/README.md)).

This document covers:

- **Batch mode**, which is built and is what releases 0.1.0 and 0.2.0 ship;
- **Event-driven mode (phase 2)**, which is a **design only**.

## Parts

| Part | Where | What |
|---|---|---|
| The spec | `spec/`, `vectors/` | Classes, prompt phrases, normalization rules, and the shared synthetic test cases: the contract |
| TypeScript package | `packages/spec-ts` | The spec as a zero-dependency classifier, for in-memory redaction in a live call (Stugum's call engine) |
| Python runner | `scanner/` | Presidio recognizers, source adapters, the batch runner, the findings contract |

The TypeScript package and the Python runner implement the same algorithm.
Both pass every vector, and a parity test fails if they disagree on any of
them.

## Batch mode (built)

```
EventBridge Scheduler (at least daily)
        │
        ▼
Lambda: sensitive_data_scanner.handler.handler   (container image or zip)
        │  reads (read-only)                        writes (its own bucket only)
        ├── S3: ListObjectsV2, GetObject ──────────► results bucket
        │     named buckets/prefixes                  findings/latest.json
        ├── CloudWatch Logs: FilterLogEvents          findings/runs/<runId>.json
        │     named log groups                        state/ (cursors, lock)
        ├── DynamoDB: DescribeTable, Query / Scan
        │     named tables
        │
        └── optional: events:PutEvents ────────────► consumer-owned EventBridge bus
                                                       (another account)
```

One run:

1. **Lock.** A conditional put of `state/lock.json` (`If-None-Match: *`)
   means one run at a time. A lock older than 20 minutes is stale and is
   taken over.
2. **State.** The run reads each source's cursor and the findings carried
   over from the previous run.
3. **Sources.** Each source gets an even share of the run's budget: items,
   bytes and time (the Lambda deadline minus 90 seconds).
   - **S3.** The source lists in key order and reads only objects modified
     since the last complete pass (less a five-minute skew). A pass that
     runs out of budget resumes after its last key. Each read is one object
     version, and the finding names that `VersionId`.
     - Sampling is stable (a hash of the key) and reported.
     - Large objects are read in part and counted as partial.
     - Audio, video, images, documents and archives are counted, not read.
     - Deleted objects drop out of the findings.
   - **CloudWatch Logs.** The source reads `FilterLogEvents` in windows of at
     most 24 hours from a watermark, up to two minutes ago. If a window
     exceeds the budget, it is cut and reported as partial, and the run
     moves on. Lex V2 records are grouped by session, so a bot's prompt in
     one record classes the customer's answer in the next.
   - **DynamoDB.** See [The DynamoDB source](#the-dynamodb-source).
4. **Items.**
   - Connect chat and Contact Lens transcripts, Lex V2 logs and Connect flow
     logs are read as **conversations**. That means prompt carryover, split
     turns and spoken digits.
   - Other JSON is read field by field, with the key path as context.
   - A DynamoDB item is read attribute by attribute (below).
   - CSV is read with its header as context. Everything else is read as text.
5. **Findings.**
   - The run writes the document to `findings/runs/<runId>.json` and
     `findings/latest.json`, then state for the next run.
   - With `FINDINGS_EVENT_BUS_ARN` set, it also sends the document to that
     bus as `Findings v1` events (see Delivery).
   - It then releases the lock.

**Failures.**
- An object that cannot be read counts as `unreadable`, and the pass goes
  on.
- A source that cannot be read at all records its AWS error name, and the
  other sources still run.
- A failed run raises `ScanError`, whose message is an error name. Logs are
  JSON lines with fixed event names, and every string in them is masked.

### Configuration

| Variable | Meaning | Default |
|---|---|---|
| `RESULTS_BUCKET` | The results bucket (required) | |
| `RESULTS_PREFIX` | A prefix inside it | none |
| `SCAN_BUCKETS` | Buckets to read, comma-separated | none |
| `SCAN_PREFIXES` | `bucket/prefix` pairs that narrow a bucket | the whole bucket |
| `SCAN_LOG_GROUPS` | Log groups to read, comma-separated | none |
| `S3_SAMPLE_PERCENT` | Percent of eligible objects to read | 100 |
| `LOGS_LOOKBACK_DAYS` | How far back the first run reads logs | 7 |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN` | The run budget | 20,000 items, 2 GiB |
| `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES` | Per-object read and gunzip limits | 20 MiB, 100 MiB |
| `S3_CLOCK_SKEW_SECONDS` | How far before the last pass an object is still re-read | 300 |
| `FINDINGS_EVENT_BUS_ARN` | Also push findings to this EventBridge bus | off |
| `SCAN_DYNAMODB` | DynamoDB tables to read, as a JSON list (below) | none |
| `DYNAMODB_PAGE_SIZE` | Items per Query or Scan page (`Limit`) | 100 |
| `DYNAMODB_MAX_PAGES` | Pages per table per run (the page cap) | 200 |

### The DynamoDB source

`SCAN_DYNAMODB` is a JSON list with one entry per read. This one reads
Stugum's call-test runs for one test:

```json
[
  {
    "table": "stugum",
    "partition": "T#t_0123abcd",
    "sortPrefix": "RUN#",
    "include": [
      "stepResults[kind=sendDtmf].observedDtmf",
      "stepResults[kind=waitForPrompt].observedText",
      "steps",
      "lastHeardText",
      "errorMessage"
    ],
    "keypad": ["stepResults[kind=sendDtmf].observedDtmf", "steps[kind=sendDtmf].digits"],
    "prompts": ["stepResults[kind=waitForPrompt].observedText"],
    "planted": ["steps"],
    "orderBy": "stepIndex"
  }
]
```

| Field | Meaning |
|---|---|
| `table` | The table name (required) |
| `partition` | A partition key value: the read is a `Query` of that partition. Without it, the read is a `Scan` of the table |
| `sortPrefix` | With `partition`: only items whose sort key begins with this (`begins_with`) |
| `include` | Attribute paths to read. The request projects their top-level attributes and the key; the paths then pick the leaves. Empty: every attribute |
| `exclude` | Attribute paths never read |
| `keypad` | Paths that hold keypad (DTMF) entries |
| `prompts` | Paths that hold what the IVR said: the prompts |
| `planted` | Paths that hold test inputs planted on purpose, such as a test script's steps |
| `orderBy` | The list-element attribute that orders a list (`stepIndex`), for pairing an entry with its prompt. Elements without it, or without `orderBy`, go by position |

**Paths.**
- A `.` goes between map keys: `result.status`.
- `[]` stands for every element of a list (or set): `stepResults[].observedDtmf`.
- `[name=value]` stands for the list elements that are maps whose attribute
  `name` is the string or number `value`:
  `stepResults[kind=sendDtmf].observedDtmf`. Several conditions, all of
  which must hold, are separated by commas: `[kind=sendDtmf,status=passed]`.
- A path covers everything under it, so `steps` covers
  `steps[kind=sendDtmf].digits`.
- Paths with conditions work in `include`, `exclude`, `keypad`, `prompts`
  and `planted`. The projection asks for the top-level attribute; the
  conditions are applied to what comes back.
- The key names and types come from `DescribeTable`, so the entry names
  values only.

**How an item is read.**
- Each string or number leaf is read **on its own**. A finding names the
  leaf's path with `[]` for each list index (`stepResults[].observedDtmf`),
  and its offsets carry the exact leaf as a JSON Pointer
  (`/stepResults/5/observedDtmf`). Binary values, booleans and nulls are
  not read.
- A **keypad** leaf is a customer turn on the `dtmf` channel. It goes
  through the spec's normalization like every other source (`123456789#`
  loses its terminator), and it is never joined to another turn.
- Each keypad leaf is **paired with the nearest preceding prompt leaf in the
  same list**, in `orderBy` order (a prompt in the same element counts as
  preceding). The pair is read as a bot turn then a customer turn, so the
  prompt classes the entry, as in a Connect flow log: `010180#` after
  "enter your date of birth" is a date of birth, and a Luhn-failing number
  after a card prompt is a card with low confidence.
- **Only a configured prompt path is a prompt.** Other text is never used to
  class an entry: in Stugum's runs, the `text` of an `assertPromptContains`
  step is an expected-prompt regular expression, and the repeated
  `observedText` of an `assertPromptContains` result is read only as text.
- A keypad leaf, when no prompt path is configured at all, takes its own
  map's other short strings and key names as its prompt (a step labeled
  "Enter SSN").
- Every leaf that is not a keypad entry, prompts included, is read as stored
  text, with its path and its map's short strings as context. That covers
  free text such as Stugum's `lastHeardText` and `errorMessage`, present on
  failed or errored runs.
- A **planted** path's findings carry `planted: true`, so a reviewer can
  tell data a test put there on purpose from a leak. Leave `planted` paths
  out with `exclude` to see leaks only.
- `[REDACTED]` and `[REDACTED:<label>]` count as redaction markers, not
  findings, whatever the label says (`[REDACTED:ssn · asked for SSN]`). A
  negative-control run whose entries are redacted labels has zero findings.

**Paging, rate limits and budget.**
- Each run reads at most `DYNAMODB_MAX_PAGES` pages of `DYNAMODB_PAGE_SIZE`
  items per entry, within its share of the run's budget. The cursor keeps
  the last item read, and the next run resumes there, so a large table is
  covered over several runs (`backlog` says so).
- A throttled request (`ProvisionedThroughputExceededException`,
  `ThrottlingException`, `RequestLimitExceeded`) is retried with exponential
  backoff and jitter, up to five times. Past that, the source records the
  error name and the next run resumes at the same key.
- When a pass reaches the last page, findings for items the pass no longer
  found (deleted, or clean now) drop out. There is no change feed: every
  pass reads the whole partition or table again.
- Reads are eventually consistent, the cheaper kind.

**Keys.** A finding names the item by `keyHash`, an HMAC-SHA256 of its key
under a random salt kept in the scanner's state, so a short key (a nine-digit
number) cannot be recovered by hashing guesses. It also gives the key's
values masked the way S3 object keys are. Like the S3 source's resume key,
the cursor in `state/` holds the last key read, and `state/` is the
scanner's own.

### Permissions (least privilege)

- **Read**, on the named stores only:
  - `s3:ListBucket`, conditioned on the named prefixes;
  - `s3:GetObject` and `s3:GetObjectVersion` on those prefixes;
  - `kms:Decrypt` where the objects use SSE-KMS;
  - `logs:FilterLogEvents` on the named log groups;
  - `dynamodb:DescribeTable`, `dynamodb:Query` and `dynamodb:Scan` on the
    named tables (grant `Scan` only where an entry names no partition);
  - `kms:Decrypt` on a table's customer managed key, where it has one,
    conditioned on `kms:ViaService` `dynamodb.<region>.amazonaws.com`.
    Tables with an AWS owned or AWS managed key need no KMS permission.
- **Write**: `s3:PutObject`, `s3:GetObject` and `s3:DeleteObject` on the
  results bucket only.
- **Optional**: `events:PutEvents` on the one consumer bus ARN.
- **No inbound access.** A consumer reads `findings/*` in the results
  bucket, or receives events. It never needs `state/*`.

For DynamoDB, the statements look like this (a table `stugum` in
`us-west-2`, with a customer managed key):

```json
[
  {
    "Sid": "ReadNamedTables",
    "Effect": "Allow",
    "Action": ["dynamodb:DescribeTable", "dynamodb:Query", "dynamodb:Scan"],
    "Resource": "arn:aws:dynamodb:us-west-2:111122223333:table/stugum"
  },
  {
    "Sid": "DecryptCustomerKeyThroughDynamoDB",
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "arn:aws:kms:us-west-2:111122223333:key/<key-id>",
    "Condition": {
      "StringEquals": { "kms:ViaService": "dynamodb.us-west-2.amazonaws.com" }
    }
  }
]
```

No write action (`PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem`)
and no index ARN is needed. The scanner reads the base table only.

The IAM policy and the schedule belong to whoever deploys the scanner, for
example Mermera's customer template. This repository creates no AWS
resources, and it holds no CloudFormation or Terraform.

## Event-driven mode (phase 2, design only)

**Goal:** findings about a minute after the data is written, using the same
runner code with a second trigger. The daily batch pass stays as the
backstop: it catches anything an event missed, and it scans what existed
before the triggers were turned on.

### S3: object created, then EventBridge, then SQS, then the scanner

```
S3 (EventBridge notifications on) ── Object Created ──► EventBridge rule
                                                        (bucket + prefix filter)
                                                              │
                                                              ▼
                                                   SQS queue (+ DLQ)
                                                              │  batch ≤ 10, window ~30 s
                                                              ▼
                                        Lambda (same image), event handler
                                        scans exactly that key + versionId
```

- **Filtering.** The rule matches `detail.bucket.name` and
  `detail.object.key` with `prefix`, for the configured targets only.
- **SQS** between the rule and the Lambda gives:
  - buffering and retry, with a dead-letter queue;
  - batching;
  - a concurrency cap (`maximumConcurrency` on the event source mapping), so
    a burst of transcripts cannot starve the account's Lambda concurrency.
- **One version per event.** The handler reads `detail.object.version-id`
  and scans that version with `GetObject(VersionId=…)`. The finding id
  already includes the version, so a redelivered event is idempotent.
  Findings for a new version replace the old ones, as in batch mode.
- **Contention.** The same results bucket and state are used, but not the
  run lock. Event findings are written per object as small documents
  (`findings/objects/<hash>.json`) and folded into `findings/latest.json`
  by the next batch pass. The batch lock is never held by an event
  invocation.
- **Turning it on** means enabling EventBridge notifications on each bucket
  (a bucket-level setting), so the template makes it opt-in per bucket.

### CloudWatch Logs: a subscription filter, then the scanner

```
Log group ── subscription filter (pattern "" or a narrow one) ──► Lambda (same image)
                                                              gzip+base64 batch of events
```

- **Two subscription filters per log group** is an AWS limit. The scanner's
  filter must coexist with the customer's own (for example, a SIEM
  forwarder), so the template makes it **opt-in per log group**, and it
  refuses to replace an existing filter.
- **Batches arrive in about a minute.** The handler decodes the batch,
  scans each event as batch mode would, and groups Lex records by session
  within the batch.
- **It never re-logs a batch.** Its own logs are counts and error names, as
  in batch mode. The scanner's own log group is never a scan target (the
  template refuses it), so there is no feedback loop.
- **Failures.** A failed invocation is retried by CloudWatch Logs. Events
  it cannot process are counted and left to the batch backstop, which reads
  the same group by watermark.

### Delivery: push (decided 29 Sep 2026)

Findings go to the consumer by **push**:

- **How.** The runner calls `events:PutEvents` from the scanned account onto
  a **consumer-owned** EventBridge bus. The bus ARN is a runner configuration
  parameter (`FINDINGS_EVENT_BUS_ARN`), so any consumer can receive findings,
  not only Mermera.
- **What.** The events carry `source: "sensitive-data-scanner"` and
  `detail-type: "Findings v1"`. The detail is a findings document (the
  schema in FINDINGS.md), split under 256 KB. It never holds a value.
- **Access.** The consumer's bus policy allows `events:PutEvents` from the
  scanned account. The consumer receives events and never calls into the
  scanned account.
- **Status.** Batch mode already supports this, as an option, after writing
  the results bucket. In phase 2 the event handlers send a per-object or
  per-batch document the same way.

The option not taken was **pull**: the consumer reads each results bucket
every few minutes. It is simpler, with no traffic from the customer to the
consumer, but slower and costlier at scale. The results bucket remains
readable, so pull still works as a fallback.

### What phase 2 changes in the code

- A second handler entry point for SQS batches and log subscription
  payloads. The S3 and log-event scanning code is unchanged.
- Per-object findings documents, folded in by the batch pass.
- In the template: the EventBridge rule, the queue and DLQ, the subscription
  filters (opt-in), and the event source mapping with a concurrency cap.
