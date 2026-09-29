# Findings, schema version 1.3

The scanner reports **findings only**: which locations hold which classes of
sensitive data, how many, how confident, where in the item, and how much it
scanned. **It never reports a value.** A test suite
(`scanner/tests/test_no_leak.py`) scans every test vector and fails if any
value shows up in findings, events, logs, exception messages or object reprs.

- JSON Schema: [`schema/findings.schema.json`](../schema/findings.schema.json)
  (it also ships inside the Python package).
- `schema`: `"sensitive-data-scanner.findings"`, `schemaVersion`: `"1.3"`.
- Version 1.1 (scanner 0.2.0) adds the DynamoDB source: the `dynamodb_item`
  resource and format, and the `dynamodb` coverage kind. Nothing in 1.0 changed,
  so a 1.0 consumer that ignores what it does not know keeps working.
- Version 1.2 adds discovery and data-lake formats: the `discovery` run
  summary (every store, read or not, and why), `kmsDenied` in coverage, `#`
  in a masked bucket or table name, `column` and `catalog` on an S3 object,
  the `parquet`, `orc`, `avro` and `sql` formats, the `rds_column` resource,
  the `glue_table` and `rds` coverage kinds and the `columnar` skip kind. All
  additive.
- Version 1.3 adds the stores found by the adapters: the `store_field`
  resource (one field of a store that is not S3, logs, DynamoDB or RDS, such
  as a Redshift column, an OpenSearch field or an EBS volume's blocks), the
  `redshift`, `opensearch`, `ebs`, `backup`, `documentdb`, `neptune`, `efs`
  and `fsx` kinds, the `block` format, the store reasons
  `read_not_configured`, `paused`, `no_grant`, `vpc_only`,
  `no_snapshot_export`, `needs_task`, `backup_copy` and `archived`, and the
  store fields `deployment`, `database`, `state`, `resource`,
  `olderSnapshots`, `recoveryPoints` and `fileSystemType`. The kinds are one list
  (`$defs/storeKind`) for coverage, the run summary and listing errors. All
  additive.

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
  the run's findings, coverage and discovered stores. The union of the
  parts is the document.
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
  "schemaVersion": "1.3",
  "scannerVersion": "0.2.0",
  "specVersion": "0.3",
  "runId": "20260929T060000Z-1a2b3c4d",
  "account": "123456789012",
  "region": "us-west-2",
  "startedAt": "2026-09-29T06:00:00+00:00",
  "finishedAt": "2026-09-29T06:04:10+00:00",
  "classes": ["us_ssn", "us_itin", "card", "dob", "cvv", "pin", "account_number", "us_ssn_last4"],
  "coverage": [ "… one per source …" ],
  "findings": [ "…" ],
  "findingsTotal": 3,
  "findingsTruncated": false,
  "totals": { "card": 2, "us_ssn": 1 },
  "discovery": { "…": "present when discovery is on (below)" }
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
| `resource` | `s3_object`: `bucket`, `key` and the `versionId` that was read (`"null"` when versioning is off). `log_event`: `logGroup`, `logStream` and the event `timestamp` (ms). `dynamodb_item`: `table`, `keyHash`, `key` and `attributePath` (below). |
| `connect` | The Amazon Connect contact and instance, when the item names one: a chat or Contact Lens transcript, or a flow log event. |
| `format` | How the item was read: `contact_lens`, `connect_chat`, `lex_v2_log`, `connect_flow_log`, `lambda_log`, `json`, `csv`, `text`, `dynamodb_item`, or (1.2) `parquet`, `orc`, `avro`, `sql`, or (1.3) `block` (raw EBS blocks). |
| `class`, `severity` | The spec class (`card`, `us_ssn`, `us_itin`, `dob`, `cvv`, `pin`, `account_number`, `us_ssn_last4`) and its severity. |
| `count` | Distinct values of the class in the item. The same card read out by a caller and read back by the agent counts once. |
| `occurrences` | Every place a value appears in the item. |
| `confidence` | The highest confidence among the occurrences; `confidenceCounts` gives them all. |
| `via` | How the values were found: `prompt` (a bot or agent asked for this class), `context` (a context word was nearby) or `shape` (the value alone looks like it). |
| `offsets` | Where each occurrence is, at most 50 (`offsetsTruncated` says if more exist). `start` and `end` are UTF-16 code units. For a JSON item, `pointer` (RFC 6901) names the string they are in. A value split across a caller's turns has one offset per turn. |
| `link` | A deep link into the account's own AWS console: the S3 object version, the log event, or the DynamoDB table's item explorer (it names no key; query by the masked key). A reviewer follows it with their own access. It is `null` when the key had to be masked. |

### A table finding: a column (1.2)

A Parquet, ORC or Avro file, or an object of a Glue table, gives one finding
per class per column:

```json
{
  "resource": {
    "type": "s3_object",
    "bucket": "example-lake",
    "key": "curated/customers/dt=2026-09-28/part-00000.snappy.parquet",
    "versionId": "null",
    "column": "card_number",
    "catalog": { "database": "curated", "table": "customers" }
  },
  "format": "parquet",
  "class": "card",
  "count": 2,
  "offsets": [
    { "pointer": "/0/card_number", "start": 0, "end": 16 },
    { "pointer": "/1/card_number", "start": 0, "end": 16 }
  ]
}
```

| Field | Meaning |
|---|---|
| `column` | The column the values are in, masked like a key. A nested column's offsets point inside it (`/0/payment/pan`) |
| `catalog` | For an object read as part of a Glue table: its `database` and `table`, masked like keys |
| `offsets[].pointer` | `/<row>/<column>`: the row within the file (from 0), and the column |

### An RDS or Aurora finding: a database column (1.2)

```json
{
  "resource": {
    "type": "rds_column",
    "engine": "aurora-postgresql",
    "dbType": "cluster",
    "cluster": "orders",
    "database": "app",
    "table": "public.customers",
    "column": "card_number",
    "readBy": "snapshot_export",
    "snapshotTime": "2026-09-29T06:10:00+00:00"
  },
  "format": "parquet",
  "class": "card",
  "count": 2,
  "offsets": [],
  "link": "https://us-west-2.console.aws.amazon.com/rds/home?region=us-west-2#database:id=orders;is-cluster=true"
}
```

| Field | Meaning |
|---|---|
| `engine`, `dbType`, `cluster` | The engine, and the DB cluster (or, with `dbType: instance`, DB instance) identifier |
| `database`, `table`, `column` | Where the values are: `table` is `schema.table` (for MySQL, `database.table`), so the location reads `schema.table.column` |
| `readBy` | `snapshot_export` (an export of the latest automated snapshot, deleted after reading) or `data_api` (opt-in read-only SQL; format `sql`) |
| `snapshotTime` | When the exported snapshot was taken. The id does not include it, so a finding keeps its id from one snapshot to the next |
| `offsets` | Empty: the rows are not addressable once the export is deleted. `count` adds up across the table's files |

### Any other store: a field (1.3)

Stores other than S3, CloudWatch Logs, DynamoDB and RDS report one class in
one field of one store as `store_field`. A Redshift column:

```json
{
  "resource": {
    "type": "store_field",
    "service": "redshift",
    "store": "warehouse",
    "database": "dev",
    "table": "public.customers",
    "field": "card_number",
    "readBy": "data_api"
  },
  "format": "sql",
  "class": "card",
  "count": 1,
  "offsets": [],
  "link": "https://us-west-2.console.aws.amazon.com/redshiftv2/home?region=us-west-2#cluster-details?cluster=warehouse"
}
```

| Field | Meaning |
|---|---|
| `service` | The product: `redshift` (a provisioned cluster), `redshift_serverless` (a workgroup), `opensearch` (a managed domain), `opensearch_serverless` (a collection) or `ebs` (a volume, or a snapshot whose volume is gone) |
| `store` | The cluster or workgroup (and, for later kinds, the domain, stream, queue, parameter or secret), masked like a key |
| `database`, `table`, `field` | Where the values are, as far as the store has them: for Redshift the database, `schema.table` and the column; for OpenSearch the index (`table`) and the document's top-level field; for EBS `field: blocks` (the raw blocks; no file path) |
| `readBy` | How it was read: `data_api` for Redshift, `search` for OpenSearch, `ebs_direct` for EBS |
| `snapshotTime` | For EBS: when the snapshot read was taken. Not part of the id |
| `offsets` | Empty: a sampled row is not addressable later. `count` is distinct values in the sample |

The shape names no cloud, so a store elsewhere (a database hosted anywhere)
reports the same way.

### A DynamoDB finding

One class of data in one attribute path of one item:

```json
{
  "resource": {
    "type": "dynamodb_item",
    "table": "stugum",
    "keyHash": "3f1c…(64 hex)",
    "key": { "pk": "T#t_0123abcd", "sk": "RUN#2026-09-29T15:00:00Z#r_0123" },
    "attributePath": "stepResults[].observedDtmf"
  },
  "format": "dynamodb_item",
  "class": "us_ssn",
  "via": ["prompt"],
  "offsets": [{ "pointer": "/stepResults/3/observedDtmf", "start": 0, "end": 9 }],
  "link": "https://us-west-2.console.aws.amazon.com/dynamodbv2/home?region=us-west-2#item-explorer?table=stugum"
}
```

(Other fields as above.)

| Field | Meaning |
|---|---|
| `keyHash` | HMAC-SHA256 of the item's key under a random salt in the scanner's state. Stable across runs; never the key. |
| `key` | The key attributes, each value masked like an S3 object key; `keyMasked: true` when anything was masked. |
| `attributePath` | The attribute, with `[]` for every list element, whatever condition (`[kind=sendDtmf]`) the configuration selected it by. Each offset's `pointer` names the exact element. Findings in different paths are different findings. |
| `planted` | `true` when the path is configured as planted test input (a test script's steps), not a leak. |

The DynamoDB resource, format and coverage kind are new in schema 1.1
(additive): they appear only when a DynamoDB source is configured.

### Names are masked

In a bucket name or key, log group or log stream name, DynamoDB table name,
or a discovered store's name, any run of digits that could be a card number
or an SSN is replaced with `#`:

- a Luhn-valid run of 13-19 digits;
- a 3-2-4 or bare nine-digit run;
- any run of 13 or more digits.

The resource then carries `keyMasked: true` (or `nameMasked: true`), and
its `link` is `null`: a console link would carry the name unmasked. Object
keys, log stream names, DynamoDB key values and attribute paths, source
targets and error names all go through the same masking.

### Coverage

One entry per source says what was, and was not, read:

| Field | Meaning |
|---|---|
| `kind`, `target` | `s3` with `bucket/prefix`, `cloudwatch_logs` with the log group, `dynamodb` with the table (`<table> (query)` for a partition Query, `<table> (export)` for an Export to S3), `glue_table` with `database.table`, `rds` with `cluster:<id>`, `instance:<id>` or `data_api:<cluster>/<database>` (1.2), `redshift` with `cluster:<id>` or `workgroup:<name>`, `opensearch` with `domain:<name>` or `collection:<name>`, or `ebs` with the volume or snapshot id (1.3) |
| `listed`, `eligible`, `scanned` | Objects listed, events returned, or DynamoDB items evaluated (`ScannedCount`); the new or changed ones (for DynamoDB, the items returned); the ones read this run |
| `sampledOut`, `samplePercent` | Left out by sampling. Sampling is stated, never silent |
| `partial` | Read only in part: the head of a large object, or a log window cut short by the run's budget |
| `unreadable` | Listed but could not be read (a KMS key the scanner may not use, or an object deleted mid-run) |
| `bytesScanned` | Bytes read |
| `skipped` | Not read, by kind: audio, video, image, document, archive, binary, or (1.2) `columnar`: a Parquet, ORC, zstd or snappy/zstandard Avro file this build cannot read (the Lambda zip; the container image reads them), or one whose byte cap fell before its first rows |
| `formats` | Items by format |
| `testValues` | Published test card numbers and sample SSNs, set apart and never findings |
| `suppressed` | Numbers next to a word like "order" or "phone", with no card word |
| `redactionMarkers` | Contact Lens and Comprehend markers (`[PII]`, `[SSN]`, …) and `[REDACTED]` / `[REDACTED:<label>]` labels: redaction at work, not a finding |
| `passComplete`, `backlog` | Whether everything eligible has been read, or work carries over to the next run |
| `error` | The AWS error name when the source could not be read (`AccessDenied`, `NoSuchBucket`), else `null` |
| `kmsDenied` | Items not read because the scanner may not use their KMS key (1.2; present when not zero) |

### Discovery: the run summary (1.2)

With discovery on (`DISCOVER`), the document carries `discovery`: every
store in the account and region, discovered or named in the configuration,
and what the run did with it. A store that was not read says why, so a
coverage gap is visible rather than silent.

```json
"discovery": {
  "stores": [
    { "kind": "dynamodb", "name": "events", "origin": "discovery", "status": "skipped",
      "reason": "too_large", "sizeBytes": 53687091200 },
    { "kind": "s3", "name": "example-archive", "origin": "discovery", "status": "error",
      "reason": "kms_access", "error": "AccessDenied", "gaps": { "kmsDenied": 12, "unreadable": 12 } },
    { "kind": "s3", "name": "example-connect-data", "origin": "config", "status": "scanned" }
  ],
  "storesTotal": 3,
  "storesTruncated": false,
  "byStatus": { "error": 1, "scanned": 1, "skipped": 1 },
  "byReason": { "kms_access": 1, "too_large": 1 },
  "listErrors": {}
}
```

| Field | Meaning |
|---|---|
| `kind`, `name` | `s3`, `cloudwatch_logs`, `dynamodb`, `glue_table` (`database.table`, or `database.*` for a database whose tables could not be listed), `rds`, or (1.3) `redshift`, `opensearch`, `ebs`, `backup`, `documentdb`, `neptune`, `efs`, `fsx`; and the store's name, masked like a key (`nameMasked: true`) |
| `origin` | `discovery`, or `config` for a store named in the configuration |
| `status` | `scanned`, `deferred` (the budget did not reach it; the next run starts with it), `skipped` or `error` |
| `reason` | Why it was not read, or read with nothing readable: `denied`, `not_allowed`, `self`, `too_large`, `unsupported`, `unsupported_format`, `kms_access`, `access_denied`, `lake_formation`, `tags_unreadable`, `budget`, `error`; for exports, `export_not_configured`, `export_pending` (status `deferred`), `export_failed`, `no_snapshot` and `pitr_off` (a large DynamoDB table without point-in-time recovery); (1.3) `read_not_configured` (reading the kind is opt-in and off), `paused` (a paused Redshift cluster), `no_grant` (the database user can see no table), `vpc_only` (an OpenSearch domain inside a VPC), `no_snapshot_export` (DocumentDB, Neptune), `needs_task` (EFS, FSx), `backup_copy` (a Backup vault) and `archived` (an archived EBS snapshot) |
| `error` | The AWS error name, for `error` |
| `sizeBytes` | The table's or log group's size, when AWS reports it |
| `samplePercent`, `maxObjectsPerPrefix` | The store's sampling, when it is sampled |
| `gaps` | Counts listed but not read: `kmsDenied`, `unreadable`, `unsupportedFormat` |
| `backlog` | More to read on the next run |
| `logGroupClass`, `tableStatus`, `catalogObject` | Why an `unsupported` store is unsupported (`catalogObject`: `view`, `not_s3`, `resource_link`) |
| `location` | A Glue table's S3 location, `bucket/prefix`, masked |
| `lakeFormation` | The Glue table is registered with Lake Formation |
| `engine`, `dbType`, `snapshotTime`, `exportStatus` | For RDS: the engine, cluster or instance, the snapshot read, and the export's state |
| `readBy`, `pitr` | For DynamoDB: `export` when the table is read from an Export to S3; `pitr: false` when it is too large and has no point-in-time recovery |
| `deployment`, `database`, `state` | (1.3) `provisioned` or `serverless` (Redshift), `managed` or `serverless` (OpenSearch); the database connected to by default; and the store's state when that is why it was not read |
| `resource`, `olderSnapshots` | (1.3) For EBS: `volume` or `snapshot`, and the earlier snapshots counted, not read |
| `recoveryPoints` | (1.3) For a Backup vault: its recovery points by resource type |
| `fileSystemType` | (1.3) For FSx: `LUSTRE`, `WINDOWS`, `ONTAP` or `OPENZFS` |

`stores` lists the stores not read first, and holds at most 5,000
(`storesTruncated`). `listErrors` names a listing that failed, by kind
(`{"s3": "AccessDenied"}`).

## Versioning

- `schemaVersion` is `major.minor`.
- Adding an optional field is a minor change (1.0 to 1.1).
- Removing or changing a field is a major change (2.0), and it comes with a
  new event `detail-type` (`Findings v2`).
- Consumers should ignore fields they do not know.
