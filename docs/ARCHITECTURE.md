# Architecture

The scanner runs **inside the AWS account it scans**. It reads the stores it
is given, and it reports **findings only** ([FINDINGS.md](FINDINGS.md)):
never a value. Detection is Microsoft Presidio with no NLP model, plus the
recognizers for the spec's classes ([spec/README.md](../spec/README.md)).

This document covers:

- **Batch mode**, which is built and is what release 0.1.0 ships;
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
4. **Items.**
   - Connect chat and Contact Lens transcripts, Lex V2 logs and Connect flow
     logs are read as **conversations**. That means prompt carryover, split
     turns and spoken digits.
   - Other JSON is read field by field, with the key path as context.
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

### Permissions (least privilege)

- **Read**, on the named stores only:
  - `s3:ListBucket`, conditioned on the named prefixes;
  - `s3:GetObject` and `s3:GetObjectVersion` on those prefixes;
  - `kms:Decrypt` where the objects use SSE-KMS;
  - `logs:FilterLogEvents` on the named log groups.
- **Write**: `s3:PutObject`, `s3:GetObject` and `s3:DeleteObject` on the
  results bucket only.
- **Optional**: `events:PutEvents` on the one consumer bus ARN.
- **No inbound access.** A consumer reads `findings/*` in the results
  bucket, or receives events. It never needs `state/*`.

The IAM policy and the schedule belong to whoever deploys the scanner, for
example Mermera's customer template. This repository creates no AWS
resources.

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
