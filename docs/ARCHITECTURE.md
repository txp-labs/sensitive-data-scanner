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
        │  lists (with DISCOVER): ListBuckets, DescribeLogGroups, ListTables
        │  reads (read-only)                        writes (its own bucket only)
        ├── S3: ListObjectsV2, GetObject ──────────► results bucket
        │     named or discovered buckets             findings/latest.json
        ├── CloudWatch Logs: FilterLogEvents          findings/runs/<runId>.json
        │     named or discovered log groups          state/ (cursors, lock)
        ├── DynamoDB: DescribeTable, Query / Scan
        │     named or discovered tables
        ├── RDS, Aurora, Glue tables, Redshift, ... (discovered; see Discovery)
        │
        └── optional: events:PutEvents ────────────► consumer-owned EventBridge bus
                                                       (another account)
```

One run:

1. **Lock.** A conditional put of `state/lock.json` (`If-None-Match: *`)
   means one run at a time. A lock older than 20 minutes is stale and is
   taken over.
2. **State.** The run reads each source's cursor and the findings carried
   over from the previous run. With `DISCOVER`, it first lists the stores in
   the account and region ([Discovery](#discovery)).
3. **Sources.** Each source gets an even share of the run's budget: items,
   bytes and time (the Lambda deadline minus 90 seconds, or
   `MAX_RUN_SECONDS`), within any per-kind cap. Sources the budget does not
   reach are deferred to the next run, which starts with them.
   - **S3.** The source lists in key order and reads only objects modified
     since the last complete pass (less a five-minute skew). A pass that
     runs out of budget resumes after its last key. Each read is one object
     version, and the finding names that `VersionId`.
     - Sampling is stable (a hash of the key) and reported.
     - Large objects are read in part and counted as partial.
     - Parquet, ORC and Avro files are read by column
       ([Columnar and data-lake formats](#columnar-and-data-lake-formats)),
       and gzip or zstd text is inflated first.
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
   - A table (Parquet, ORC, Avro, or a Glue table's CSV or JSON) is read
     column by column, with the column's name as context.
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
| `DISCOVER` | Kinds of store to discover: `all`, or any of `s3`, `logs`, `dynamodb` ([Discovery](#discovery)) | off |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | Allow and deny rules for discovered stores, comma-separated | none |
| `DISCOVER_SAMPLING` | Per-store sampling rules, as a JSON list | none |
| `S3_MAX_OBJECTS_PER_PREFIX` | Objects read per "directory" per pass (0: no cap) | 0 |
| `DYNAMODB_SAMPLE_PERCENT` | Percent of a scanned table to read (one parallel-scan segment) | 100 |
| `DYNAMODB_MAX_TABLE_BYTES` | A discovered table larger than this, after sampling, is skipped as `too_large` (0: no cap) | 10 GiB |
| `MAX_OBJECTS_PER_RUN`, `MAX_LOG_EVENTS_PER_RUN`, `MAX_TABLE_ITEMS_PER_RUN` | Per-kind caps inside `MAX_ITEMS_PER_RUN` (0: no separate cap) | 0 |
| `MAX_RUN_SECONDS` | Wall-time cap on a run, below the Lambda deadline (0: the deadline only) | 0 |
| `COLUMNAR_MAX_ROWS` | Rows read per Parquet, ORC or Avro file (or catalog CSV/JSON object); the rest is `partial` | 10,000 |
| `RDS_EXPORT_ROLE_ARN`, `RDS_EXPORT_KMS_KEY_ARN` | The role RDS assumes to write snapshot exports, and the customer's KMS key to encrypt them. Both are needed to read RDS and Aurora | none: RDS stores are reported `export_not_configured` |
| `MAX_EXPORTS_PER_RUN` | Export tasks (RDS and DynamoDB) a run may start | 1 |
| `EXPORT_MIN_INTERVAL_DAYS` | Days before a store is exported again | 7 |
| `DYNAMODB_EXPORT` | Read a table too large to Scan from an Export to S3 (needs PITR) | off |
| `DYNAMODB_EXPORT_KMS_KEY_ARN` | Encrypt DynamoDB exports with this key (`SSE-KMS`) | SSE-S3 |
| `RDS_DATA_API` | Opt-in: Aurora clusters to read with read-only SQL through the Data API, as a JSON list | none (off) |
| `GLUE_LAKE_FORMATION` | For Glue tables registered with Lake Formation: `read` (with the scanner's own IAM; a denial is a gap) or `skip` (report them, read nothing) | `read` |
| `REDSHIFT_READ` | Read Redshift clusters and Serverless workgroups through the Data API: `off`, `iam` or `db_user` ([below](#redshift-and-redshift-serverless)) | `off`: discovered and reported `read_not_configured` |
| `REDSHIFT_DB_USER` | With `REDSHIFT_READ=db_user`: the existing read-only database user | none |
| `REDSHIFT_MAX_ROWS_PER_TABLE`, `REDSHIFT_MAX_TABLES` | Rows sampled per table (`LIMIT`), and tables per database | 1,000 and 500 |
| `REDSHIFT_STATEMENT_TIMEOUT_SECONDS` | How long the run waits for one Data API statement before counting the table unreadable | 60 |

### Discovery

With `DISCOVER` set, the run lists the stores in its own account and region
and reads each one, with no list for the user to write. The scanner is
deployed once per account and region, so each deployment discovers its own
region, and a bucket in another region is left to that region's scanner.

| Kind | Listed with | Read as |
|---|---|---|
| `s3` | `ListBuckets` with `BucketRegion` set to the run's region | the whole bucket, by the S3 source |
| `logs` | `DescribeLogGroups` | each group, by the CloudWatch Logs source |
| `dynamodb` | `ListTables`, then `DescribeTable` | a Scan of all attributes, sampled by `DYNAMODB_SAMPLE_PERCENT` |
| `glue` | `GetDatabases`, then `GetTables` | each table's S3 location, by column ([below](#glue-data-catalog-and-lake-formation)) |
| `rds` | `DescribeDBClusters`, `DescribeDBInstances` | the latest automated snapshot, exported to Parquet ([below](#rds-and-aurora-by-snapshot-export)) |
| `redshift` | `DescribeClusters`; Serverless `ListWorkgroups`, `ListNamespaces` | sampled read-only SQL through the Data API, opt-in ([below](#redshift-and-redshift-serverless)) |

**The explicit configuration keeps working.** `SCAN_BUCKETS`,
`SCAN_PREFIXES`, `SCAN_LOG_GROUPS` and `SCAN_DYNAMODB` are read as before,
first in every run, whether discovery is on or off. A discovered store that
the configuration also names is read once, as configured: its prefixes, its
DynamoDB paths. The allow and deny lists apply to discovered stores only.

**Allow and deny.** `DISCOVER_ALLOW` and `DISCOVER_DENY` take
comma-separated rules:

| Rule | Matches |
|---|---|
| `s3:prod-*` | S3 buckets whose name matches the glob |
| `logs:/aws/lambda/*` | Log groups (`*` also matches `/`) |
| `dynamodb:orders` | One table |
| `*-archive` | A name of any kind |
| `tag:scan=false` | Stores with that tag and value (a glob) |
| `tag:pii` | Stores with that tag, any value |
| `s3:tag:team=data*` | A tag rule for one kind |

- A deny rule wins over an allow rule. With an allow list, only the stores it
  matches are read.
- Tags are read only when a rule needs them (`s3:GetBucketTagging`,
  `logs:ListTagsForResource`, `dynamodb:ListTagsOfResource`). If a store's
  tags cannot be read and a deny-by-tag rule exists, the store is skipped as
  `tags_unreadable`: a store that might be denied is never read.
- The scanner's own results bucket and its own log group
  (`AWS_LAMBDA_LOG_GROUP_NAME`) are never read (`self`).

**Per-store sampling.** `DISCOVER_SAMPLING` is a JSON list; the first entry
whose `match` (a rule as above) fits a store sets its sampling:

```json
[
  { "match": "s3:datalake-*", "samplePercent": 10, "maxObjectsPerPrefix": 20 },
  { "match": "dynamodb:tag:size=huge", "samplePercent": 5 }
]
```

- S3: `samplePercent` is the stable key-hash sample; `maxObjectsPerPrefix`
  reads at most that many objects per "directory" (the key up to its last
  `/`) in a pass, so a partitioned data lake is represented by the first few
  files of each partition. The rest are counted as `sampledOut`.
- DynamoDB: `samplePercent` reads one parallel-scan segment
  (`Segment` 0 of `TotalSegments = round(100 / samplePercent)`), which
  DynamoDB spreads over the whole key space. `sampledOut` is an estimate.
  A table whose size times its sample is over `DYNAMODB_MAX_TABLE_BYTES` is
  skipped as `too_large`.

**Budget and resume.** The run's budget is `MAX_ITEMS_PER_RUN` and
`MAX_BYTES_PER_RUN`, with optional per-kind caps (`MAX_OBJECTS_PER_RUN`,
`MAX_LOG_EVENTS_PER_RUN`, `MAX_TABLE_ITEMS_PER_RUN`) and a wall-time cap
(`MAX_RUN_SECONDS`, and always the Lambda deadline). Each source gets an even
share of what is left. When the budget runs out, the stores not reached are
reported as `deferred` (reason `budget`), and the next run starts with the
first of them (`rotation` in the state), so every store is reached over a
few runs. Each store's own cursor resumes where its last read stopped.

**The run summary.** The findings document's `discovery` object lists every
store, discovered or configured, with what happened to it:

| `status` | `reason` | Meaning |
|---|---|---|
| `scanned` | | Read this run (`backlog` if it has more to read) |
| `scanned` | `unsupported_format` | Listed, but every object was a kind the scanner cannot read |
| `deferred` | `budget` | Not reached this run; the next run starts here |
| `skipped` | `denied`, `not_allowed` | The deny list, or not on the allow list |
| `skipped` | `self` | The scanner's own bucket or log group |
| `skipped` | `too_large` | Over the size cap, after sampling |
| `skipped` | `unsupported` | A log group of the `DELIVERY` class, or a table not `ACTIVE` |
| `skipped` | `kms_access` | A table whose KMS key is out of reach |
| `skipped` | `tags_unreadable` | Tags could not be read while a deny-by-tag rule exists |
| `error` | `kms_access`, `access_denied`, `error` | The store could not be read; `error` names the AWS error |
| `skipped` | `read_not_configured` | Discovered, but reading this kind is opt-in and off (Redshift) |
| `skipped` | `paused` | A paused Redshift cluster: a query would not resume it |
| `skipped` | `no_grant` | Signed in, but the database user can see no table: grant it `SELECT` |

Each store's `gaps` counts what was listed but not read: `kmsDenied`
(objects under a KMS key the scanner may not use), `unreadable` and
`unsupportedFormat`. A listing that fails (`ListBuckets` denied) is named in
`listErrors`, and the other kinds are still listed. Store names are masked
like object keys.

### Columnar and data-lake formats

The S3 source reads data-lake files by column, whether it reached them by a
bucket, a prefix or a Glue table:

| Format | Recognized by | Read with |
|---|---|---|
| Parquet | `.parquet` (`x.snappy.parquet`, `x.gz.parquet`), or the `PAR1` magic bytes | pyarrow, one row group at a time, through ranged GETs |
| ORC | `.orc`, or `ORC` magic bytes | pyarrow, one stripe at a time, through ranged GETs |
| Avro | `.avro`, or `Obj\x01` magic bytes | the scanner's own reader (`scan/avro.py`); snappy and zstandard codecs through pyarrow |
| gzip or zstd CSV and JSON lines | `.csv.gz`, `.jsonl.zst` and the like | inflated (`MAX_INFLATED_BYTES`), then read as CSV or JSON lines |

- **Ranged reads.** Parquet and ORC keep their footer at the end: the
  scanner seeks there, reads the footer, then the first row groups, up to
  `COLUMNAR_MAX_ROWS` rows and `MAX_OBJECT_BYTES` bytes. A 1 GB file costs
  its footer and one row group, not 1 GB. A file with more rows is counted
  as `partial`.
- **By column.** Each column's cells are read with the column's name as
  context: `card_number`, `ssn`, `date_of_birth`. Integers and decimals are
  read as their digits, dates as ISO dates, and text stored as bytes as
  text. Nested columns (structs, lists, maps) are read leaf by leaf, like
  JSON. Floats and booleans are not read.
- **Findings name the column.** A finding is one class in one column of one
  object version (`resource.column`). Its offsets carry the cell as
  `/<row>/<column>` (and deeper for nested cells).
- **Which build.** pyarrow is in the container image, not the Lambda zip:
  with it, the zip passes Lambda's 250 MB unzipped limit. The zip reads
  Avro with the standard library's codecs (null, deflate, bzip2, xz), and
  counts Parquet, ORC, zstd and snappy or zstandard Avro as skipped
  `columnar`. **Use the image to scan a data lake.**

### Glue Data Catalog and Lake Formation

With `DISCOVER` including `glue`, the run lists the Data Catalog's
databases and tables and reads each table at its S3 location:

- Findings name the **database, table and column** (`resource.catalog`,
  `resource.column`), as well as the object.
- A **CSV table** is read with the catalog's columns, so a headerless file
  still gets column-level findings. The delimiter comes from the SerDe
  (`field.delim`, `separatorChar`; Hive's default is Ctrl-A), and
  `skip.header.line.count` is honored. A **JSON table** is read by its
  top-level keys. Parquet, ORC and Avro tables are read by their own schema.
- **Each object is read once.** A discovered bucket leaves the prefixes of
  its catalog tables to the tables' own sources.
- **Not read, and reported:** views (`catalogObject: view`), tables whose
  location is not S3 (`not_s3`, such as JDBC), and resource links to another
  account's catalog (`resource_link`; that account's scanner reads them).
- **Lake Formation is respected.** The scanner reads with its own IAM
  permissions only. It never asks Lake Formation for credentials
  (`GetTemporaryGlueTableCredentials`, `GetDataAccess`) or grants itself
  anything, and a test checks that the code has no way to. When Lake
  Formation denies it (a database's tables cannot be listed, or a governed
  table's data cannot be read), the store is reported with reason
  `lake_formation`: a coverage gap, never escalated. Tables registered with
  Lake Formation carry `lakeFormation: true`. `GLUE_LAKE_FORMATION=skip`
  leaves every registered table unread and reported.
- Partitions whose location lies outside the table's location are not yet
  read (`GetPartitions` is a later change).

### Adapters: one interface for every other kind of store

Every kind of store after RDS is an **adapter** (`sources/base.py`,
`Adapter`), registered by its kind in `sources/aws.py`. An adapter lists its
stores into the run summary, decides each with the shared allow, deny and
sampling rules (`discovery.decide`), and gives the runner a source per store
it can read. The budget, the findings store, the coverage and the run
summary stay the core's, and none of them names a cloud: an adapter gets its
clients by service name (`clients.client("redshift-data")`), made on first
use, so a kind that is not discovered makes no client.

Reading SQL is generic too (`scan/sql.py`): a dialect (quoting, the table
listing) and a pass that lists the base tables with bound parameters, then
runs `SELECT * FROM "schema"."table" LIMIT n` on each with quoted
identifiers, resumable by `[schema, table]`, within the budget. The caller
gives it `execute(sql, params)`. Redshift and the RDS Data API mode both use
it, and a database hosted anywhere can.

Their findings are the `store_field` resource ([FINDINGS.md](FINDINGS.md)):
`service`, `store`, and where it applies `database`, `table` and `field`,
with counts and no offsets (a sampled row is not addressable later).

### RDS and Aurora by snapshot export

With `DISCOVER` including `rds`, the run lists the DB clusters and the DB
instances that are not in a cluster, and reads each by **snapshot export**:
no database credentials, no connection, no load on the database.

1. **Snapshot.** The latest `available` automated snapshot
   (`DescribeDBClusterSnapshots` or `DescribeDBSnapshots`).
2. **Export.** `StartExportTask` of that snapshot to the results bucket,
   prefix `exports/rds/<task>/`, written by the export role
   (`RDS_EXPORT_ROLE_ARN`) and encrypted with the customer's KMS key
   (`RDS_EXPORT_KMS_KEY_ARN`). A run starts at most `MAX_EXPORTS_PER_RUN`
   exports (RDS and DynamoDB together), and a store is exported again no
   sooner than `EXPORT_MIN_INTERVAL_DAYS`. RDS bills an export by the
   snapshot's size.
3. **Wait.** Later runs ask `DescribeExportTasks`. Meanwhile the store is
   `deferred` with reason `export_pending`.
4. **Read.** The export's Parquet files (`<database>/<schema.table>/…`) are
   read by column, as in [Columnar formats](#columnar-and-data-lake-formats),
   across as many runs as the budget needs.
5. **Clean up.** When every file is read, the export is deleted, and
   findings the new snapshot no longer has drop out. A failed export is
   deleted too, reported (`export_failed`), and not retried for the same
   snapshot.

A finding is one class in one column: `resource.type` `rds_column`, with the
`engine`, the `cluster` (or instance) identifier, the `database`, the
`table` (`schema.table`) and the `column`, and the time of the snapshot.
The rows are gone with the export, so the finding has counts, not offsets.
Across a table's files, `count` adds up (an upper bound on distinct values).

Engines: Aurora MySQL and PostgreSQL, RDS for MySQL, MariaDB and
PostgreSQL. Oracle, SQL Server, Db2, Neptune and DocumentDB are reported as
`unsupported`. A store without the role and key is `export_not_configured`,
and one with no automated snapshot yet is `no_snapshot`.

### Aurora by read-only SQL (opt-in)

For a small Aurora database where an export is too slow or too costly,
`RDS_DATA_API` names clusters to read through the RDS Data API. **Off by
default.**

```json
[
  {
    "clusterArn": "arn:aws:rds:us-west-2:111122223333:cluster:orders",
    "secretArn": "arn:aws:secretsmanager:us-west-2:111122223333:secret:orders-readonly-AbCdEf",
    "database": "app",
    "engine": "postgresql",
    "schemas": ["public"],
    "maxRowsPerTable": 1000,
    "maxTables": 200
  }
]
```

- The run lists base tables from `information_schema` (schemas as bound
  parameters), then runs `SELECT * FROM "schema"."table" LIMIT n` for each.
  Identifiers are quoted, and these are the only statements.
- Everything runs in one Data API transaction that is **always rolled
  back**, and on PostgreSQL begins with `SET TRANSACTION READ ONLY`.
- The secret should belong to a database user with `SELECT` only. The
  scanner cannot check that, so it is the deployer's part.
- Findings are `rds_column` with `readBy: "data_api"` and format `sql`.

### Redshift and Redshift Serverless

With `DISCOVER` including `redshift`, the run lists provisioned clusters
(`DescribeClusters`) and Serverless workgroups (`ListWorkgroups`, with each
namespace's database from `ListNamespaces`). A paused cluster is reported as
`paused` (a query would not resume it), and one in another state (resizing,
modifying) as `unsupported` with its `state`.

**Reading is off by default** (`REDSHIFT_READ=off`): every store is then
reported as `read_not_configured`. To read, choose how the scanner signs in.
Neither way stores a password:

| `REDSHIFT_READ` | Provisioned cluster | Serverless workgroup | The database user |
|---|---|---|---|
| `iam` | `redshift:GetClusterCredentialsWithIAM` | `redshift-serverless:GetCredentials` | `IAMR:<the scanner's role name>`. Redshift creates it on first use with PUBLIC privileges only; grant it `SELECT` (or a role with `SELECT`) on what should be scanned |
| `db_user` | `redshift:GetClusterCredentials` for `REDSHIFT_DB_USER` | as `iam` (Serverless has no db-user mode) | An existing user with `SELECT` only. Never created: `AutoCreate` needs `redshift:CreateClusterUser`, which is denied |

Then, for each database (`ListDatabases`, less `padb_harvest`, `sys:internal`
and `awsdatacatalog`), the run lists local base tables from `svv_tables`
(external Spectrum tables are S3 data, read by the Glue and S3 sources) and
runs `SELECT * FROM "schema"."table" LIMIT n` on each through the Data API
(`ExecuteStatement`, `DescribeStatement` until it finishes, then
`GetStatementResult` page by page). Those are the only statements. A pass
resumes at `[database, schema, table]` across runs, within the budget.

- Findings are `store_field` with `service` `redshift` or
  `redshift_serverless`, the cluster or workgroup as `store`, the
  `database`, `schema.table` as `table`, the column as `field`, and
  `readBy: data_api`; format `sql`.
- A user that can see no table at all is reported as `no_grant`: a coverage
  gap, not a clean pass. A table the user may not read is counted
  `unreadable`, and the pass goes on.
- A statement that does not finish in `REDSHIFT_STATEMENT_TIMEOUT_SECONDS` is
  left to run out on the cluster (the scanner has no `CancelStatement`), and
  the table counts as unreadable.
- **Cost.** A Serverless workgroup bills RPU-seconds for each statement (at
  least 60 seconds of base capacity when it wakes). A provisioned cluster's
  sampled `LIMIT` queries use its own capacity.

**Why the Data API, and not UNLOAD.** `UNLOAD ('SELECT ... LIMIT n') TO
's3://…'` writes a sample to S3 in Parquet, and suits large samples. It
needs the same database sign-in to run the UNLOAD, plus an IAM role attached
to the cluster that can write to the scanner's bucket: a write path out of
the cluster, and a change to the cluster's roles. At sample sizes the Data
API reads the same rows with less: no cluster role, nothing written. The
read-only guarantee is the database user's grants in both cases, because
`redshift-data:ExecuteStatement` cannot be narrowed to `SELECT` in IAM.

### DynamoDB Export to S3 (large tables)

With `DYNAMODB_EXPORT=on`, a discovered table too large to Scan
(`DYNAMODB_MAX_TABLE_BYTES`) is read from an Export to S3 instead. An export
uses no read capacity and is a point-in-time copy. It needs point-in-time
recovery (PITR) on the table. A large table without PITR is reported as
`pitr_off` and not read. The export (DynamoDB JSON, to
`exports/dynamodb/…`, SSE-S3 or `DYNAMODB_EXPORT_KMS_KEY_ARN`) is started
within `MAX_EXPORTS_PER_RUN`, read item by item exactly like the DynamoDB
source (the same `dynamodb_item` findings), and deleted afterwards.

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
    named tables (with discovery, see the table after the example) (grant `Scan` only where an entry names no partition);
  - `kms:Decrypt` on a table's customer managed key, where it has one,
    conditioned on `kms:ViaService` `dynamodb.<region>.amazonaws.com`.
    Tables with an AWS owned or AWS managed key need no KMS permission.
- **Write**: `s3:PutObject`, `s3:GetObject` and `s3:DeleteObject` on the
  results bucket only: `findings/`, `state/`, and the exports the scanner
  starts under `exports/`, which it deletes once read. Nothing else is ever
  written. A test holds `delete` to the `exports/` prefix.
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

**Discovery** adds list and describe actions, which cannot be narrowed to
named resources because the stores are not known in advance. They are read-only:

| Kind | Actions | Resource |
|---|---|---|
| `s3` | `s3:ListAllMyBuckets`; `s3:ListBucket`, `s3:GetObject`, `s3:GetObjectVersion`; `s3:GetBucketTagging` only with tag rules | `*` (buckets `arn:aws:s3:::*`, objects `arn:aws:s3:::*/*`) |
| `logs` | `logs:DescribeLogGroups`, `logs:FilterLogEvents`; `logs:ListTagsForResource` only with tag rules | `*` |
| `dynamodb` | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:Scan`; `dynamodb:ListTagsOfResource` only with tag rules | `*` |
| `glue` | `glue:GetDatabases`, `glue:GetTables`; `glue:GetTags` only with tag rules; plus the S3 read actions on each table's location | `*` (catalog, databases and tables) |
| `rds` (snapshot export) | `rds:DescribeDBClusters`, `rds:DescribeDBInstances`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBSnapshots`, `rds:StartExportTask`, `rds:DescribeExportTasks`; `iam:PassRole` on the export role only, conditioned on `iam:PassedToService` `export.rds.amazonaws.com`; `kms:CreateGrant` and `kms:DescribeKey` on the export key, conditioned on `kms:ViaService` `rds.<region>.amazonaws.com` and `kms:GrantIsForAWSResource`; `kms:Decrypt` on that key via S3, to read the export | `*` for describe; the export role and key ARNs |
| RDS export role (assumed by `export.rds.amazonaws.com`) | `s3:PutObject*`, `s3:GetObject*`, `s3:ListBucket`, `s3:DeleteObject*`, `s3:GetBucketLocation` on the results bucket's `exports/rds/` prefix only | the results bucket |
| `rds` (Data API, opt-in) | `rds-data:BeginTransaction`, `rds-data:ExecuteStatement`, `rds-data:RollbackTransaction` on the named clusters; `secretsmanager:GetSecretValue` on the named secrets | the named ARNs |
| DynamoDB export | `dynamodb:DescribeContinuousBackups`, `dynamodb:ExportTableToPointInTime`, `dynamodb:DescribeExport`; `s3:PutObject` and `s3:AbortMultipartUpload` on `exports/dynamodb/`; with a key, `kms:GenerateDataKey` and `kms:Decrypt` via S3 | tables `*`; the results bucket |
| `redshift` | `redshift:DescribeClusters`, `redshift-serverless:ListWorkgroups`, `redshift-serverless:ListNamespaces`; `redshift-serverless:ListTagsForResource` only with tag rules | `*` |
| `redshift` (reads, opt-in) | `redshift-data:ExecuteStatement`, `redshift-data:ListDatabases` on this account's clusters and workgroups; `redshift-data:DescribeStatement`, `redshift-data:GetStatementResult` on its own statements; `redshift-serverless:GetCredentials`; `redshift:GetClusterCredentialsWithIAM` (`iam`) or `redshift:GetClusterCredentials` on the one database user (`db_user`) | the ARNs named |
| Lake Formation | **none**: no `lakeformation:GetDataAccess` and no grants. Where Lake Formation governs a table, grant the scanner's role `SELECT` (and `DESCRIBE`) in Lake Formation to include it; otherwise it is reported as `lake_formation` | |
| KMS | `kms:Decrypt`, conditioned on `kms:ViaService` `s3.<region>.amazonaws.com` and `dynamodb.<region>.amazonaws.com` | the customer managed keys to be read through; without it, those stores are reported as `kms_access` |

A deny list in configuration is not an IAM boundary. To keep the scanner
out of a store for certain, deny it in IAM as well (an explicit `Deny` on
the bucket, table or log group), and it is then reported as `access_denied`.

The IAM policy and the schedule belong to whoever deploys the scanner. For
a single account, that can be your own template (Mermera's customer template,
for example). For an estate, use the two templates in `deploy/`
([Estate rollout](#estate-rollout)). This repository creates no AWS resources
by itself; the templates are for you to deploy.

## Estate rollout

Two CloudFormation templates put the scanner in **every account and every
region** of an AWS Organization, and send every finding to **one place**:

| Template | Deployed | What it holds |
|---|---|---|
| `deploy/scanner.yaml` | By the StackSet, into each account and region | The scanner: results bucket, Lambda function, schedule, log group, and the IAM below |
| `deploy/estate-stackset.yaml` | Once, in the management account or a CloudFormation delegated administrator | A **service-managed** StackSet (`AWS::CloudFormation::StackSet`) that deploys `scanner.yaml` to the organizational units and regions named, with automatic deployment to accounts that join them later |

```
management or delegated-admin account
  estate-stackset.yaml ─► StackSet "sensitive-data-scanner" (SERVICE_MANAGED, auto-deploy)
                               │  OUs × regions
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   account A / us-east-1  account A / us-west-2  account B / eu-west-1 …
   scanner.yaml:          scanner.yaml:          scanner.yaml:
   discover, read,        discover, read,        discover, read,
   findings to its own    findings to its own    findings to its own
   results bucket         results bucket         results bucket
          │                    │                    │
          └──── events:PutEvents (Findings v1) ─────┘
                               ▼
              the central sink: a consumer-owned EventBridge bus
```

**Rolling it out.**

1. **The central sink.** Use the existing consumer-owned EventBridge bus
   (see [Delivery](#delivery-push-decided-29-sep-2026)). Its resource policy
   allows the whole organization to put events:

   ```json
   {
     "Sid": "FindingsFromTheOrganization",
     "Effect": "Allow",
     "Principal": "*",
     "Action": "events:PutEvents",
     "Resource": "arn:aws:events:us-west-2:111122223333:event-bus/findings",
     "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-exampleorgid" } }
   }
   ```

2. **The code, in every region.** Lambda pulls images only from ECR in the
   function's own region. Push the release image to an ECR repository,
   replicate it to every region scanned, and give the organization pull
   access (the repository policy with `aws:PrincipalOrgID`). Pass it as
   `ImageUri`. The image is recommended because it reads Parquet and ORC.
   For the zip instead, put it in one bucket per region, named
   `<CodeS3BucketPrefix>-<region>`, readable by the organization.
3. **Trusted access.** Turn on trusted access for CloudFormation StackSets
   in AWS Organizations. To deploy from a delegated administrator, register
   it and set `CallAs: DELEGATED_ADMIN`.
4. **Deploy `estate-stackset.yaml`** with `ScannerTemplateUrl` (the release's
   `scanner.yaml` in S3), `OrganizationalUnitIds` (an OU or the root),
   `Regions`, and `FindingsEventBusArn`. Or do the same from the CLI:

   ```sh
   aws cloudformation create-stack-set --stack-set-name sensitive-data-scanner \
     --template-url https://example-bucket.s3.us-east-1.amazonaws.com/scanner.yaml \
     --permission-model SERVICE_MANAGED \
     --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
     --capabilities CAPABILITY_IAM \
     --parameters ParameterKey=FindingsEventBusArn,ParameterValue=arn:aws:events:us-west-2:111122223333:event-bus/findings \
                  ParameterKey=ImageUri,ParameterValue=111122223333.dkr.ecr.us-east-1.amazonaws.com/sensitive-data-scanner@sha256:…
   aws cloudformation create-stack-instances --stack-set-name sensitive-data-scanner \
     --deployment-targets OrganizationalUnitIds=ou-exam-ple12345 \
     --regions us-east-1 us-west-2 eu-west-1 \
     --operation-preferences RegionConcurrencyType=PARALLEL,MaxConcurrentPercentage=25,FailureTolerancePercentage=10
   ```

5. **The management account** is never a target of a service-managed
   StackSet. If it holds data, deploy `scanner.yaml` there as an ordinary
   stack.

**Per account and region.**

- `ImageUri` must name the region's own registry (`<account>.dkr.ecr.<region>.amazonaws.com/…`).
  For many regions, set it per region with a stack-instance parameter
  override (`--parameter-overrides` on `create-stack-instances`, or
  `update-stack-instances`).
- `RdsExportKmsKeyArn` names a key in each account and region, so it is
  usually set per account. Without it, RDS and Aurora are discovered and
  reported as `export_not_configured`.
- IAM resources have no fixed names, so one account holds a stack in many
  regions without collisions. The results bucket is
  `sds-results-<account>-<region>`, and its policy refuses anything but TLS.
- There is no reserved concurrency: the results bucket's lock allows one run
  at a time, and reserving concurrency would fail in accounts still at the
  default Lambda quota.

### IAM per source

The scanner's role (`ScannerRole` in `scanner.yaml`) holds exactly this,
statement by statement. A test (`scanner/tests/test_template.py`) checks
several things:
- every allowed action is a read, or a write aimed at the scanner's own
  bucket, log group, bus or exports;
- every AWS call in the code is allowed;
- every allowed action is named in this table;
- nothing allowed is also denied.

| Source | Actions | Resource | Condition |
|---|---|---|---|
| Its own results bucket | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:AbortMultipartUpload`; `s3:ListBucket` | the results bucket and its objects | |
| Its own logs | `logs:CreateLogStream`, `logs:PutLogEvents` | its log group | |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketTagging`; `s3:ListBucket`; `s3:GetObject`, `s3:GetObjectVersion` | `*`, every bucket, every object | |
| CloudWatch Logs | `logs:DescribeLogGroups`, `logs:FilterLogEvents`, `logs:ListTagsForResource` | `*` | |
| DynamoDB | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:Scan`, `dynamodb:Query`, `dynamodb:ListTagsOfResource` | `*` | |
| Glue Data Catalog | `glue:GetDatabases`, `glue:GetTables`, `glue:GetTags` | `*` | |
| RDS and Aurora (discovery) | `rds:DescribeDBClusters`, `rds:DescribeDBInstances`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBSnapshots`, `rds:DescribeExportTasks` | `*` | |
| KMS (customer managed keys) | `kms:Decrypt` | `*` | `kms:ViaService` is `s3.<region>` or `dynamodb.<region>` (`AllowKmsDecrypt`) |
| Central sink | `events:PutEvents` | the bus | only with `FindingsEventBusArn` |
| RDS snapshot export | `rds:StartExportTask` | this account's cluster and DB snapshots | only with `RdsExportKmsKeyArn` |
| | `iam:PassRole` | the export role only | `iam:PassedToService` is `export.rds.amazonaws.com` |
| | `kms:CreateGrant` | the export key | `kms:ViaService` is `rds.<region>`, and `kms:GrantIsForAWSResource` |
| | `kms:DescribeKey` | the export key | `kms:ViaService` is `rds.<region>` |
| | `kms:Decrypt` | the export key | `kms:ViaService` is `s3.<region>` (to read the export) |
| DynamoDB export | `dynamodb:DescribeContinuousBackups`, `dynamodb:ExportTableToPointInTime`, `dynamodb:DescribeExport` | `*` | only with `EnableDynamoDBExport` |
| | `kms:GenerateDataKey`, `kms:Decrypt` | the export key | `kms:ViaService` is `s3.<region>`; only with `DynamoDBExportKmsKeyArn` |
| Data API (opt-in) | `rds-data:BeginTransaction`, `rds-data:ExecuteStatement`, `rds-data:RollbackTransaction` | the named clusters | only with `DataApiTargets` |
| | `secretsmanager:GetSecretValue` | the named secrets | |
| Redshift (discovery) | `redshift:DescribeClusters`, `redshift-serverless:ListWorkgroups`, `redshift-serverless:ListNamespaces`, `redshift-serverless:ListTagsForResource` | `*` | |
| Redshift reads (opt-in) | `redshift-data:ExecuteStatement`, `redshift-data:ListDatabases` | this account's clusters (`cluster:*`) and workgroups (`workgroup/*`) in the region | only with `RedshiftRead` `iam` or `db-user` |
| | `redshift-data:DescribeStatement`, `redshift-data:GetStatementResult` | `*` | `redshift-data:statement-owner-iam-userid` is the scanner's own (`${aws:userid}`) |
| | `redshift-serverless:GetCredentials` | this account's workgroups | |
| | `redshift:GetClusterCredentialsWithIAM` | this account's `dbname:*/*` | only with `RedshiftRead` `iam` |
| | `redshift:GetClusterCredentials` | the one `dbuser:*/<RedshiftDbUser>`, and `dbname:*/*` | only with `RedshiftRead` `db-user` |

And three explicit denies, as defense in depth against any other policy the
role might gain:

| Deny | What |
|---|---|
| `NoWritesOutsideOwnBucket` | S3 object and bucket writes and deletes anywhere but the results bucket |
| `NoDataStoreWrites` | DynamoDB item, table and restore writes; RDS create, delete, modify, reboot, restore, stop and export cancel; Glue catalog writes; log deletes, retention, subscription and data-protection changes; Redshift user creation (`CreateClusterUser`, so `GetClusterCredentials` can never auto-create a user), `JoinGroup`, and cluster and workgroup create, modify, delete, pause, resume, reboot and restore; `redshift-data:BatchExecuteStatement` |
| `NeverAskLakeFormation` | `lakeformation:*`: no data access, no credential vending, no grants. A governed table is read only if Lake Formation has granted the role `SELECT`; otherwise it is reported as `lake_formation` |

The RDS **export role** (`RdsExportRole`, trusted by
`export.rds.amazonaws.com` for this account only) can write, read and delete
under `exports/rds/` in the results bucket, and list the bucket, nothing
else. The schedule's role can invoke the function, nothing else.

**Stores kept out.** The deny list (`DiscoverDeny`) is configuration, not a
boundary. To keep the scanner out of a store for certain, add an explicit
`Deny` for the scanner's role in that bucket's, table's or key's own
policy; the store is then reported as `access_denied`.

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
