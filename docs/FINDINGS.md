# Findings, schema version 1.0

The scanner reports **findings only**: which locations hold which classes of
sensitive data, how many, how confident, where in the item, and how much it
scanned. **It never reports a value.** A test suite
(`scanner/tests/test_no_leak.py`) scans every test vector and fails if any
value shows up in findings, events, logs, exception messages or object reprs.

- JSON Schema: [`schema/findings.schema.json`](../schema/findings.schema.json)
  (it also ships inside the Python package).
- `schema`: `"sensitive-data-scanner.findings"`, `schemaVersion`: `"1.0"`.

## Where findings go

**Batch mode (now).** Each scheduled run writes to the results bucket in the
scanned account:

| Key | What |
|---|---|
| `findings/latest.json` | The findings document for the latest run |
| `findings/runs/<runId>.json` | One document per run |
| `state/…` | The scanner's own cursors and lock. A consumer never needs these; grant it `findings/*` only |

Findings carry over between runs. An S3 object's findings are replaced when a
new version of it is read, and dropped when the object is deleted. A log
event's findings stay (log events do not change) up to a cap of 20,000
stored findings.

**Push: optional in batch mode, and the phase 2 design.** Set
`FINDINGS_EVENT_BUS_ARN` to a consumer-owned EventBridge bus (Mermera's, or
anyone's). After writing the results bucket, the runner calls `PutEvents` from
the scanned account onto that bus:

```json
{
  "Source": "sensitive-data-scanner",
  "DetailType": "Findings v1",
  "EventBusName": "arn:aws:events:us-west-2:<consumer-account>:event-bus/<bus>",
  "Detail": "{ …a findings document, plus \"part\" and \"parts\"… }"
}
```

- The `detail` is a findings document (the same schema) holding a slice of
  the run's findings.
- Each event stays under EventBridge's 256 KB limit, so a large run is split:
  `part` counts from 1 up to `parts`.
- The consumer's bus policy allows `events:PutEvents` from the scanned
  account. The consumer receives events and never calls in.
- `source` and `detail-type` are versioned with the schema: a breaking change
  to the document becomes `Findings v2`.

## The document

```json
{
  "schema": "sensitive-data-scanner.findings",
  "schemaVersion": "1.0",
  "scannerVersion": "0.1.0",
  "specVersion": "0.1",
  "runId": "20260929T060000Z-1a2b3c4d",
  "account": "123456789012",
  "region": "us-west-2",
  "startedAt": "2026-09-29T06:00:00+00:00",
  "finishedAt": "2026-09-29T06:04:10+00:00",
  "classes": ["us_ssn", "card", "dob", "cvv", "pin", "account_number", "us_ssn_last4"],
  "coverage": [ "… one per source …" ],
  "findings": [ "…" ],
  "findingsTotal": 3,
  "findingsTruncated": false,
  "totals": { "card": 2, "us_ssn": 1 }
}
```

`findings` holds at most 5,000 findings, the most severe and largest first.
`findingsTotal` and `findingsTruncated` say whether any were left out.
`totals` counts distinct values per class across all findings.

### A finding

One class of data at one location.

```json
{
  "id": "c87765820340c54300edbe0ae2bb0bfc",
  "resource": {
    "type": "s3_object",
    "bucket": "example-connect-data",
    "key": "connect/x/Analysis/Voice/2026/09/28/lens.json",
    "versionId": "f8eefbc2-5886-468e-9fc6-d6d738f57381"
  },
  "format": "contact_lens",
  "class": "us_ssn",
  "severity": "high",
  "count": 1,
  "occurrences": 1,
  "confidence": "high",
  "confidenceCounts": { "high": 1 },
  "via": ["prompt"],
  "offsets": [
    { "pointer": "/Transcript/1/Content", "start": 0, "end": 12 },
    { "pointer": "/Transcript/3/Content", "start": 0, "end": 10 },
    { "pointer": "/Transcript/4/Content", "start": 0, "end": 23 }
  ],
  "offsetsTruncated": false,
  "link": "https://us-west-2.console.aws.amazon.com/s3/object/example-connect-data?region=us-west-2&bucketType=general&prefix=…&versionId=…",
  "connect": { "contactId": "11111111-2222-3333-4444-555555555555", "instanceId": "…" },
  "firstSeenAt": "2026-09-29T06:00:00+00:00",
  "lastSeenAt": "2026-09-29T06:00:00+00:00"
}
```

| Field | Meaning |
|---|---|
| `id` | A stable hash of the resource and class. It stays the same across runs for the same location (and object version). Key triage decisions on it. |
| `resource` | `s3_object`: `bucket`, `key` and the `versionId` that was read (`"null"` when versioning is off). `log_event`: `logGroup`, `logStream` and the event `timestamp` (ms). |
| `connect` | The Amazon Connect contact and instance, when the item names one: a chat or Contact Lens transcript, or a flow log event. |
| `format` | How the item was read: `contact_lens`, `connect_chat`, `lex_v2_log`, `connect_flow_log`, `lambda_log`, `json`, `csv` or `text`. |
| `class`, `severity` | The spec class (`card`, `us_ssn`, `dob`, `cvv`, `pin`, `account_number`, `us_ssn_last4`) and its severity. |
| `count` | Distinct values of the class in the item. The same card read out by a caller and read back by the agent counts once. |
| `occurrences` | Every place a value appears in the item. |
| `confidence` | The highest confidence among the occurrences; `confidenceCounts` gives them all. |
| `via` | How the values were found: `prompt` (a bot or agent asked for this class), `context` (a context word was nearby) or `shape` (the value alone looks like it). |
| `offsets` | Where each occurrence is, at most 50 (`offsetsTruncated` says if more exist). `start` and `end` are UTF-16 code units. For a JSON item, `pointer` (RFC 6901) names the string they are in. A value split across a caller's turns has one offset per turn. |
| `link` | A deep link into the account's own AWS console: the S3 object version, or the log event. A reviewer follows it with their own access. It is `null` when the key had to be masked. |

### Names are masked

In a bucket key, log group or log stream name, any run of digits that could
be a card number or an SSN is replaced with `#`:

- a Luhn-valid run of 13-19 digits;
- a 3-2-4 or bare nine-digit run;
- any run of 13 or more digits.

The resource then carries `keyMasked: true` (or `nameMasked: true`). Object
keys, log stream names, source targets and error names all go through the
same masking.

### Coverage

One entry per source says what was, and was not, read:

| Field | Meaning |
|---|---|
| `kind`, `target` | `s3` with `bucket/prefix`, or `cloudwatch_logs` with the log group |
| `listed`, `eligible`, `scanned` | Objects listed or events returned; the new or changed ones; the ones read this run |
| `sampledOut`, `samplePercent` | Left out by sampling. Sampling is stated, never silent |
| `partial` | Read only in part: the head of a large object, or a log window cut short by the run's budget |
| `unreadable` | Listed but could not be read (a KMS key the scanner may not use, or an object deleted mid-run) |
| `bytesScanned` | Bytes read |
| `skipped` | Not read, by kind: audio, video, image, document, archive, binary |
| `formats` | Items by format |
| `testValues` | Published test card numbers and sample SSNs, set apart and never findings |
| `suppressed` | Numbers next to a word like "order" or "phone", with no card word |
| `redactionMarkers` | Contact Lens and Comprehend markers (`[PII]`, `[SSN]`, …): redaction at work, not a finding |
| `passComplete`, `backlog` | Whether everything eligible has been read, or work carries over to the next run |
| `error` | The AWS error name when the source could not be read (`AccessDenied`, `NoSuchBucket`), else `null` |

## Versioning

- `schemaVersion` is `major.minor`.
- Adding an optional field is a minor change (1.0 to 1.1).
- Removing or changing a field is a major change (2.0), and it comes with a
  new event `detail-type` (`Findings v2`).
- Consumers should ignore fields they do not know.
