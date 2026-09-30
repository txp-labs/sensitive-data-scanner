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
| Python core | `scanner/core/` | `sensitive_data_core`, which names no cloud: the spec engine and Presidio recognizers, the findings contract, budgets and sampling, the allow, deny and sampling rules, the coverage summary, the findings push interface and the signed HTTPS sink, the sampled SQL pass (`scan/sql.py`), the object reader every blob store shares (`scan/objects.py`, with Word, Excel and PowerPoint files read as text by `scan/office.py`), the state location a container runner keeps (`state.py`) and the `Adapter` interface |
| AWS scanner | `scanner/` | `sensitive_data_scanner`, built on the core: every boto3 adapter, discovery, the batch runner, the Lambda handler, EventBridge as the findings sink; and `deploy/` |
| Databases runner | `scanner/db/` | `sensitive_data_db`, built on the core: a container that samples PostgreSQL, MySQL and MariaDB, SQL Server, Oracle, MongoDB, Snowflake and Databricks SQL with a read-only user it checks first ([DATABASES.md](DATABASES.md)); its own image target (`docker build --target db`) |
| Azure scanner | `scanner/azure/` | `sensitive_data_azure`, built on the core: a Container Apps job with a managed identity that discovers every subscription under a management group (Resource Graph) and reads its stores read-only ([AZURE.md](AZURE.md)); its own image target (`docker build --target azure`), and `deploy/azure/` (Bicep at a management group) |
| Google Cloud scanner | `scanner/gcp/` | `sensitive_data_gcp`, built on the core: a Cloud Run job with its own service account that discovers every project under an organization or folder (Cloud Asset Inventory) and reads its stores read-only over REST ([GCP.md](GCP.md)); its own image target (`docker build --target gcp`), and `deploy/gcp/` (Terraform at an organization or folders) |
| SaaS scanner | `scanner/saas/` | `sensitive_data_saas`, built on the core: a container the customer runs in its own environment with read-only grants to its SaaS tenants (Microsoft 365, Google Workspace, Slack, Jira and Confluence), reading mail, files and messages incrementally over HTTPS with no vendor SDK ([SAAS.md](SAAS.md)); its own image target (`docker build --target saas`), and `deploy/saas/` (examples for ECS, Azure Container Apps, Cloud Run and Kubernetes) |

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
     - **What an object is comes from its first bytes, not its name**
       ([What an object is: content, archives and PDFs](#what-an-object-is-content-archives-and-pdfs)).
       A renamed file is read by content and its findings say `disguised`.
     - Parquet, ORC and Avro files are read by column
       ([Columnar and data-lake formats](#columnar-and-data-lake-formats)).
     - Word, Excel and PowerPoint's Open XML files are read as their text by
       the core's reader (`scan/office.py`) through ranged GETs of one
       version, within the byte and inflate caps; a rights-managed one is
       counted as `encrypted`. PDFs are read as their text layer.
     - zip, tar, gzip, bzip2 and xz archives are read entry by entry, in
       memory; 7z is counted as `archive_unsupported`.
     - Audio, video, images and the older binary Office formats are counted,
       not read. CodeCommit files and ECR layer files are read the same way.
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
| `SCAN_MODE` | Who finds the data (#55): `scanner` (this scanner reads), `vendor` (Amazon Macie's own findings are imported, S3 only; nothing is read), or `both` (findings at the same object and class are linked) ([FINDINGS.md](FINDINGS.md#sources-and-modes-18)) | `scanner` |
| `MACIE_LOOKBACK_DAYS` | How far back the first Macie import goes | 90 |
| `DISCOVER` | Kinds of store to discover: `all`, or any of `s3`, `logs`, `dynamodb` ([Discovery](#discovery)) | off |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | Allow and deny rules for discovered stores, comma-separated | none |
| `DISCOVER_SAMPLING` | Per-store sampling rules, as a JSON list | none |
| `S3_MAX_OBJECTS_PER_PREFIX` | Objects read per "directory" per pass (0: no cap) | 0 |
| `DYNAMODB_SAMPLE_PERCENT` | Percent of a scanned table to read (one parallel-scan segment) | 100 |
| `DYNAMODB_MAX_TABLE_BYTES` | A discovered table larger than this, after sampling, is skipped as `too_large` (0: no cap) | 10 GiB |
| `MAX_OBJECTS_PER_RUN`, `MAX_LOG_EVENTS_PER_RUN`, `MAX_TABLE_ITEMS_PER_RUN` | Per-kind caps inside `MAX_ITEMS_PER_RUN` (0: no separate cap) | 0 |
| `MAX_RUN_SECONDS` | Wall-time cap on a run, below the Lambda deadline (0: the deadline only) | 0 |
| `OBJECT_INDEX` | The per-object index in the results bucket (`state/index/`, [below](#the-object-index-and-component-versions)) | on |
| `INDEX_MAX_OBJECTS` | The most objects one source indexes; past it, objects are read by their change at the source only | 10,000,000 |
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
| `OPENSEARCH_DOCS_PER_INDEX`, `OPENSEARCH_MAX_INDICES` | Documents sampled per index (`_search?size=`), and indices per domain or collection | 100 and 500 |
| `OPENSEARCH_SERVERLESS_READ` | Read OpenSearch Serverless collections ([below](#opensearch-domains-and-serverless-collections)) | off: reported `read_not_configured` |
| `EBS_DIRECT_READ` | Sample each EBS volume's latest snapshot with the EBS direct APIs ([below](#ebs-snapshots-backups-and-file-systems)) | off: reported `read_not_configured` |
| `EBS_BLOCKS_PER_SNAPSHOT` | 512 KiB blocks read per snapshot, in runs of four spread across the volume | 256 (128 MiB) |
| `KINESIS_RECORDS_PER_SHARD`, `KINESIS_MAX_SHARDS` | Records sampled per shard from `TRIM_HORIZON`, and shards per stream | 100 and 50 |
| `SQS_DLQ_READ` | Receive from dead-letter queues ([below](#streams-and-queues)) | off: reported `read_not_configured` |
| `SQS_MESSAGES_PER_QUEUE` | Messages received per dead-letter queue per run | 100 |
| `SSM_DECRYPT` | Read `SecureString` parameters, decrypted through SSM ([below](#parameter-store-and-secrets-manager)) | on |
| `SECRETS_READ` | Read Secrets Manager secrets' values for sensitive data | off: listed and reported `read_not_configured` |
| `TIMESTREAM_MAX_ROWS`, `TIMESTREAM_LOOKBACK_DAYS` | Rows sampled per Timestream table, and how far back (`WHERE time > ago(Nd)`) | 1,000 and 1 |
| `KEYSPACES_MAX_ROWS` | Rows sampled per Keyspaces table (`LIMIT`) | 1,000 |
| `STEPFUNCTIONS_EXECUTIONS`, `STEPFUNCTIONS_EVENTS` | Executions sampled per Standard state machine (the most recent), and history events read per execution | 20 and 500 |
| `XRAY_MAX_TRACES`, `XRAY_LOOKBACK_HOURS` | Traces read per run, and how far back the first run (and a long gap) reaches | 100 and 24 |
| `CODECOMMIT_MAX_FILES`, `CODECOMMIT_MAX_FOLDERS` | Files read per repository per head, and folders walked to find them | 200 and 500 |
| `MSK_READ` | Sample MSK topics ([below](#msk-and-amazon-mq)) | off: reported `read_not_configured` |
| `MSK_RECORDS_PER_PARTITION`, `MSK_MAX_TOPICS`, `MSK_MAX_PARTITIONS` | Records read per partition from its earliest offset, topics per cluster, partitions per topic | 100, 50 and 50 |
| `MQ_READ`, `MQ_BROKERS` | Browse ActiveMQ queues: a JSON list of `{"broker", "secretArn", "queues"}`, the secret holding a read-only broker user's `username` and `password` | off; none |
| `MQ_MESSAGES_PER_QUEUE` | Messages browsed per queue | 100 |
| `ECR_READ` | Sample ECR images' layers ([below](#ecr-sagemaker-and-neptune-analytics)) | off: reported `read_not_configured` |
| `ECR_MAX_LAYERS`, `ECR_MAX_LAYER_BYTES`, `ECR_MAX_FILES_PER_LAYER` | The latest image's top layers read, bytes downloaded per layer, files read per layer | 5, 256 MiB and 200 |
| `SAGEMAKER_READ` | Read feature groups' offline stores | off |
| `NEPTUNE_ANALYTICS_EXPORT_ROLE_ARN`, `NEPTUNE_ANALYTICS_EXPORT_KMS_KEY_ARN` | The role Neptune Analytics assumes to write graph exports, and the customer's key for them. Both are needed to read graphs | none: graphs reported `export_not_configured` |
| `EVENTBRIDGE_REPLAY`, `EVENTBRIDGE_REPLAY_QUEUE_URL`, `EVENTBRIDGE_REPLAY_QUEUE_ARN` | Read archives by a replay to the scanner's own queue (the template creates it) | off |
| `EVENTBRIDGE_REPLAY_HOURS`, `EVENTBRIDGE_REPLAY_MAX_EVENTS` | How much of an archive a replay covers (the most recent hours), and events read from it | 24 and 1,000 |
| `CONFIG_LOCATION` | A configuration document to read at the start of each run: `s3://bucket/key`, or an SSM parameter as `ssm:<name>` or its ARN ([below](#configuration-beyond-4-kb)) | none |

#### Configuration beyond 4 KB

Lambda holds at most 4 KB of environment variables, and a list of DynamoDB
tables passes that quickly: 16 entries came to about 7.2 KB in the first
real-account run. So the same settings can also come from a **configuration
document**, a JSON object whose keys are the variable names above:

```json
{
  "SCAN_DYNAMODB": [{ "table": "example-calls", "partition": "T#t_0000example" }],
  "DISCOVER": ["s3", "dynamodb"],
  "MAX_RUN_SECONDS": 600,
  "DYNAMODB_EXPORT": true
}
```

- `SCAN_DYNAMODB`, `DISCOVER_SAMPLING` and `RDS_DATA_API` take their JSON
  directly; a list of strings is joined with commas; numbers and booleans are
  written as themselves; `null` unsets.
- A name the scanner does not read is an error, so a typo is never silently
  ignored. A document cannot set `CONFIG_LOCATION` or
  `AWS_LAMBDA_LOG_GROUP_NAME`.

It can come from three places. Each one wins over the ones before it:

1. **Environment variables**, as before.
2. **A file**, named by `CONFIG_LOCATION` or by the invoke payload's
   `configLocation`:
   - an S3 object (`s3://bucket/key`, up to 1 MiB), read with `s3:GetObject`;
   - or an SSM parameter (`ssm:/sensitive-data-scanner/config`, or its ARN),
     read with `ssm:GetParameter`. A standard parameter holds 4 KB and an
     advanced one 8 KB, so S3 is the place for anything larger.
3. **The invoke payload's `config`**: `{"config": {...}}`, for example as the
   EventBridge Scheduler target's input. Several schedules can then share one
   function, each with its own batch of tables.

The payload's other keys are ignored, so a schedule that sends nothing, or
sends its own event, leaves the configuration as it was. Nothing in the
configuration is secret.

`scanner.yaml` takes `ConfigLocation`. It grants `ssm:GetParameter` only on
parameters under `/sensitive-data-scanner/`, and only when the location is
in SSM. An S3 location is read with the same `s3:GetObject` the S3 source
already holds.

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
| `opensearch` | `ListDomainNames`, `DescribeDomains`; Serverless `ListCollections`, `BatchGetCollection` | sampled documents per index over signed HTTPS GETs ([below](#opensearch-domains-and-serverless-collections)) |
| `ebs` | `DescribeVolumes`, `DescribeSnapshots` (this account's) | each volume's latest snapshot, sampled block by block with the EBS direct APIs, opt-in ([below](#ebs-snapshots-backups-and-file-systems)) |
| `backup` | `ListBackupVaults`, `ListRecoveryPointsByBackupVault` | reported with its recovery points by type (`backup_copy`) |
| `documentdb`, `neptune` | `DescribeDBClusters` by engine; DocumentDB elastic `ListClusters` | reported (`no_snapshot_export`) |
| `efs`, `fsx` | `DescribeFileSystems` | reported (`needs_task`) |
| `kinesis` | `ListStreams`, `ListShards` | each shard sampled from `TRIM_HORIZON`, never checkpointed ([below](#streams-and-queues)) |
| `firehose` | `ListDeliveryStreams`, `DescribeDeliveryStream` | each S3 location it delivers to, by the S3 source |
| `sqs` | `ListQueues`, `GetQueueAttributes` | dead-letter queues only, received from and left in place, opt-in |
| `ssm` | `DescribeParameters` | one store, `parameter-store`: each parameter's value (`GetParameters`, ten at a time) |
| `secretsmanager` | `ListSecrets` | one store, `secrets-manager`: each secret's value, opt-in (`GetSecretValue`) |
| `elasticache`, `memorydb` | `DescribeReplicationGroups`, `DescribeCacheClusters`, `DescribeServerlessCaches` (and their snapshots); MemoryDB `DescribeClusters`, `DescribeSnapshots` | reported (`in_memory`); an exported snapshot in S3 is read by the S3 source |
| `timestream` | `ListDatabases`, `ListTables`; InfluxDB `ListDbInstances` | one sampled query per table; InfluxDB reported (`no_read_path`) |
| `keyspaces` | `ListKeyspaces`, `ListTables` | one sampled CQL query per table, signed with the role |
| `stepfunctions` | `ListStateMachines`, `DescribeStateMachine` | each Standard state machine's recent executions' history, sampled ([below](#step-functions-lambda-environment-variables-and-x-ray)) |
| `lambda` | `ListFunctions` | each function's environment variables (`GetFunctionConfiguration`), counts only |
| `xray` | `GetEncryptionConfig` | one store, `xray-traces`: sampled traces since the last run, annotations and metadata |
| `codecommit` | `ListRepositories`, `GetRepository` | a stable sample of the default branch's files at its head ([below](#codecommit-and-s3-directory-buckets)) |
| `s3express` | `ListDirectoryBuckets` | each directory bucket, by the S3 source, through read-only S3 Express sessions |
| `msk` | `ListClustersV2` | each topic's partitions sampled from the earliest offset with IAM authentication, never committed, opt-in ([below](#msk-and-amazon-mq)) |
| `mq` | `ListBrokers`, `DescribeBroker` | an ActiveMQ broker's named queues browsed (never consumed) by a checked read-only user, opt-in; RabbitMQ reported |
| `ecr` | `DescribeRepositories` | files sampled from the latest image's top layers, opt-in ([below](#ecr-sagemaker-and-neptune-analytics)) |
| `sagemaker` | `ListFeatureGroups`, `DescribeFeatureGroup`, `ListNotebookInstances` | each feature group's offline store, by the S3 source, opt-in; the rest reported |
| `neptune-analytics` | `ListGraphs` | each graph by an export to CSV in the results bucket, read by column and deleted |
| `eventbridge` | `ListArchives`, `DescribeArchive` | reported with size and retention; opt-in, a replay to the scanner's own rule and queue ([below](#eventbridge-archives-and-glacier-vaults)) |
| `glacier` | `ListVaults` | reported (`archive_retrieval`) |

#### Coverage by store

Every kind the scanner discovers, and how far it reads it. Nothing listed
is ever a silent pass: what is not read is in the run summary with its
reason.

| Store | Read | How | Otherwise reported as |
|---|---|---|---|
| S3, CloudWatch Logs, DynamoDB, Glue tables | **Scanned** | objects, events, items, columns | `denied`, `kms_access`, `too_large`, ... |
| RDS and Aurora | **Scanned** with the export role and key | snapshot export to Parquet | `export_not_configured`, `no_snapshot` |
| Aurora (small databases) | **Opt-in** (`RDS_DATA_API`) | sampled read-only SQL | |
| Redshift, Redshift Serverless | **Opt-in** (`REDSHIFT_READ`) | sampled read-only SQL (Data API) | `read_not_configured`, `paused`, `no_grant` |
| OpenSearch domains | **Scanned** | sampled `_search` per index, GETs only | `vpc_only`, `access_denied` |
| OpenSearch Serverless | **Opt-in** (`OPENSEARCH_SERVERLESS_READ`) | the same | `read_not_configured` |
| EBS volumes and snapshots | **Opt-in** (`EBS_DIRECT_READ`) | sampled blocks' text, EBS direct APIs | `read_not_configured`, `no_snapshot`, `archived` |
| Kinesis Data Streams | **Scanned** | sampled from `TRIM_HORIZON`, never checkpointed | `unsupported` |
| Firehose | **Scanned** | its S3 locations, by the S3 source | `no_s3_destination` |
| SQS dead-letter queues | **Opt-in** (`SQS_DLQ_READ`) | received with `VisibilityTimeout=0` | `read_not_configured`, `redrive_would_change`; live queues `live_queue` |
| SSM Parameter Store | **Scanned** (`SecureString` via `SSM_DECRYPT`, on) | `GetParameters` | `excluded` counts |
| Secrets Manager | **Opt-in** (`SECRETS_READ`) | `GetSecretValue`, counts only | `read_not_configured` |
| Timestream for LiveAnalytics | **Scanned** | one sampled query per table | `unsupported` |
| Keyspaces | **Scanned** | one sampled CQL query per table | `access_denied` |
| ElastiCache, MemoryDB snapshots exported to S3 | **Scanned** | `.rdb` files read by the S3 source | |
| ElastiCache, MemoryDB | Coverage only | | `in_memory` |
| AWS Backup vaults | Coverage only (EBS points read as EBS) | | `backup_copy` |
| DocumentDB, Neptune | Coverage only | | `no_snapshot_export` |
| EFS, FSx | Coverage only; opt-in task designed | | `needs_task` |
| Timestream for InfluxDB | Coverage only | | `no_read_path` |
| Step Functions (Standard) | **Scanned** | recent executions' history, sampled | `unsupported` (Express: `workflowType: express`) |
| Lambda environment variables | **Scanned** | `GetFunctionConfiguration`, counts only | `self`; a variable under an unusable key is `unreadable` |
| X-Ray traces | **Scanned** | sampled traces' annotations and metadata | |
| CodeCommit | **Scanned** | a sample of the default branch's files at its head | `unsupported` (`state: empty`) |
| S3 directory buckets | **Scanned** | the S3 source, read-only S3 Express sessions | `self` |
| MSK, provisioned and Serverless | **Opt-in** (`MSK_READ`) | sampled from the earliest offset, IAM authentication, a throwaway group id, never committed | `read_not_configured`, `vpc_only`, `no_read_path` (no IAM authentication), `unsupported` |
| Amazon MQ for ActiveMQ | **Opt-in** (`MQ_READ`, `MQ_BROKERS`) | named queues browsed over STOMP (`browser:true`) by a checked read-only user | `read_not_configured`, `user_can_write`, `vpc_only` |
| Amazon MQ for RabbitMQ | Coverage only | | `no_read_path` |
| ECR images | **Opt-in** (`ECR_READ`) | files sampled from the latest image's top layers | `read_not_configured` |
| SageMaker Feature Store (offline) | **Opt-in** (`SAGEMAKER_READ`) | its S3 objects, by the S3 source | `read_not_configured`; an online-only group `no_read_path` |
| SageMaker notebook instances | Coverage only | | `no_read_path` |
| Neptune Analytics | **Scanned** with the export role and key | export to CSV, read by column, deleted | `export_not_configured`, `export_pending` |
| EventBridge archives | Coverage only; **opt-in** replay (`EVENTBRIDGE_REPLAY`) | a replay to the scanner's own rule and queue | `read_not_configured` |
| S3 Glacier vaults | Coverage only | | `archive_retrieval` |

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
| `skipped` | `vpc_only` | An OpenSearch domain reachable only inside its VPC, which the scanner's Lambda is not in |
| `skipped` | `no_snapshot_export` | DocumentDB or Neptune: no snapshot export to S3 exists, and the scanner holds no database credentials |
| `skipped` | `needs_task` | EFS or FSx: read only by mounting it inside its VPC (the opt-in file-system task) |
| `skipped` | `archived` | An EBS snapshot in the archive tier, which the EBS direct APIs cannot read |
| `skipped` | `no_snapshot` | (EBS) a volume with no completed snapshot; creating one would be a write |
| `skipped` | `backup_copy` | An AWS Backup vault: its EBS points are read as EBS snapshots, the rest are copies of stores read where they live |
| `skipped` | `live_queue` | An SQS queue that is not a dead-letter queue: never read, a receive would reach live consumers |
| `skipped` | `redrive_would_change` | A dead-letter queue with its own redrive policy: a receive raises the receive count, which could move messages on |
| `skipped` | `no_s3_destination` | A Firehose stream with no S3 location (its destination's own kind reads it, or it is outside AWS) |
| `skipped` | `in_memory` | ElastiCache or MemoryDB: data in memory, inside the VPC, behind the cache's own credentials; exported snapshots in S3 are read there |
| `skipped` | `no_read_path` | Timestream for InfluxDB: reached inside a VPC with an InfluxDB token |

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
| Parquet | the `PAR1` magic bytes (`PARE`, modular encryption, is counted as `encrypted`) | pyarrow, one row group at a time, through ranged GETs |
| ORC | the `ORC` magic bytes | pyarrow, one stripe at a time, through ranged GETs |
| Avro | the `Obj\x01` magic bytes | the scanner's own reader (`scan/avro.py`); snappy and zstandard codecs through pyarrow |
| gzip, bzip2, xz or zstd CSV and JSON lines | their magic bytes (`.csv.gz`, `.jsonl.zst` and the like) | inflated (`MAX_INFLATED_BYTES`), then read as what they hold |

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

### What an object is: content, archives and PDFs

Every object store (S3, Azure Blob Storage and Files, Cloud Storage, SaaS
files and attachments, CodeCommit files, ECR layer files) reads an object
with the core's reader (`scan/objects.py`,
[#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65)). A name
is a claim anyone can change, so the reader decides by the bytes:

1. **Sniff.** The first 8 KiB (or the whole object, up to 256 KiB, in the one
   read) are matched against magic bytes (`scan/sniff.py`): zip, OLE,
   `%PDF`, gzip, bzip2, xz, zstd, tar (`ustar` at 257), 7z, Parquet, ORC,
   Avro, a Redis snapshot, images, audio and video; else text when at least
   85% decodes as printable UTF-8, else binary. A zip is Word, Excel or
   PowerPoint when it has `[Content_Types].xml` and `word/`, `xl/` or
   `ppt/` parts, whatever it is named.
2. **Route by content.** Audio, video, images and binary are counted by kind
   after the sniff and never fetched further (the budget is charged the sniff
   for a name that says image, audio or video). Office files are read as
   their text through ranged reads of the zip; an OLE container is a
   rights-managed Office file (`encrypted`, by its `EncryptedPackage`
   stream) or an older binary Office file (`document`). PDFs are read with
   pypdf (pure Python): each page's text layer and the document
   information, up to 500 pages; no text layer is `pdf_image_only`, a user
   password `encrypted`. Tables are read by column; everything else as text.
3. **Compare with the name.** When the extension claims another kind
   (`.jpg` over a Word file, `.csv` over a zip), the finding carries
   `disguised: true`, `declaredType` and `detectedType`, and coverage counts
   it (`disguised`) whether or not anything was found.
4. **Archives, entry by entry.** zip (through ranged reads of its
   directory), tar, and gzip, bzip2, xz and zstd streams are opened in memory
   and never extracted, so a `../../x` entry (ZipSlip) is only a name. Each
   entry is sniffed and routed like an object: an archive in an archive is
   opened up to three levels (a `.tar.gz` is one), an entry that is media or
   binary is counted without being inflated. The caps: `MAX_INFLATED_BYTES`
   for all that one object inflates, 1,000 entries per archive, and 200 times
   an entry's compressed size past 1 MiB (the zip-bomb guard); a capped read
   is `partial`. A password-protected entry is counted as `encrypted` (the
   archive, when every entry is). 7z needs `py7zr`, which brings compiled
   codecs (pyzstd, pybcj, pyppmd, Brotli, PyCryptodome) into the customer's
   account, so it is counted as `archive_unsupported`. A finding names the
   entry (`archivePath`, masked like a key; its position, `archiveEntry`,
   when the mask changed it).

pypdf adds about 4 MB to each image and the Lambda zip; it has no
dependencies of its own. Its log and warnings are silenced, since a message
about a malformed object could quote it.

### The object index and component versions

A run needs to know more than "changed since the last pass" to read the right
objects ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)):
what each object was read **with**. Two parts give it that.

**Component versions.** Every part that decides what a read finds has a
version. The version is the first 12 hex characters of a SHA-256 over the
part's source. Nobody sets it by hand. `scripts/components.py` computes the
versions and writes them to a manifest,
`scanner/core/src/sensitive_data_core/components.json`, which ships in the
core package:

| Component | Made of |
|---|---|
| `adapter:<kind>` | The source module that reads a kind of store (`adapter:s3`, `adapter:m365_sharepoint`, `adapter:dynamodb`, `adapter:postgresql`, ...). The kinds are found from the `kind = "..."` names in every platform's `sources/` modules, plus the kinds a module sets at run time. A vendor's importer is its own (`adapter:macie`) |
| `reader:<name>` | One of the core's readers: `text`, `transcript`, `docx`, `xlsx`, `pptx`, `pdf`, `archive-zip`, `archive-tar`, `archive-stream` (gzip, bzip2, xz, zstd), `columnar` (Parquet, ORC), `avro`, `rdb`, and for tables `sql` and `attributes`. A reader can be made of named functions of a shared file, so a change to `_pptx` in `scan/office.py` moves `reader:pptx` and not `reader:docx`. The manifest also lists the kinds of object each reader reads (`readerKinds`) |
| `sniffer` | `scan/sniff.py`, and the routing in `scan/objects.py` that sends bytes to a reader |
| `spec-standalone` | The unprompted engine: shape and context rules, the recognizers, the spec loader |
| `spec-standalone/<class>` | One class's own rules in `spec/classes.yaml` (its shape, `standalone`, context words and exclusions, test numbers, and for `card` the brand table), so a change to one class, or a new class, is named |
| `spec-conversation` | The prompts (`promptPhrases`), retry prefixes, carryover, the context window, `spec/normalize.yaml`, and the conversation and normalization engines |

CI runs `uv run python ../scripts/components.py --check`, and
`tests/test_components.py` runs it too. The check fails when a component's
source changed and the manifest was not regenerated, so a version is never
forgotten. It also fails when a new `sources/` module names no kind and is not
a listed helper. To regenerate, run
`uv run python ../scripts/components.py --write` in `scanner/` and commit the
manifest.

**The per-object index.** Each source that reads objects keeps one index in
the scanner's own state location:

- the AWS results bucket's `state/index/`;
- the Azure state container's `state/index/`;
- the Google Cloud state bucket's `state/index/`;
- for a container runner, beside `STATE_LOCATION` (`<path>.index/`,
  `s3://bucket/<key>.index/`, or `<URL>.index/<file>` with the state's signed
  PUTs).

Per object, it holds:

- the object's key, as an HMAC-SHA256 (12 bytes). The salt is random, and it
  is kept in the runner's state document (`indexSalt`), not in the index file,
  the same rule as the DynamoDB source's item keys;
- an HMAC of the source's change marker: the ETag, size and time for S3 and
  Azure blobs, the generation for Cloud Storage, the `cTag` for OneDrive and
  SharePoint, the version for Drive;
- an HMAC of the content fingerprint, when the listing gives one: a
  single-part S3 object's ETag, a blob's `Content-MD5`, a Cloud Storage
  object's `md5Hash`, a Drive file's `md5Checksum`, a OneDrive or SharePoint
  file's SHA-1 or QuickXorHash;
- the detected type, the readers used (an archive's entries' readers too), the
  kinds met that no reader in the build reads (images, 7z, older Office files,
  and Parquet in the Lambda zip), and the skip reason;
- flags (disguised, conversation, text-bearing, unreadable);
- the **component-version vector** it was read with: its adapter's version,
  each of its readers', the sniffer's, `spec-standalone`'s and each class's,
  and `spec-conversation`'s.

Many objects share one profile (the vector with the type, readers and skip),
so a shard stores each profile once. **Nothing in the index is a value.** The
no-leak suite plants values in object keys, in archive entries' names and in
the objects themselves, then searches every byte of the index files (and each
shard's SQL dump) for them.

The index is SQLite (the standard library's), held in memory and stored
gzipped. Each source starts with one shard (`<source>/000.db.gz` beside
`<source>/meta.json`). A source splits by the key hash when it passes 250,000
rows a shard, up to 256 shards. A run loads only the shards it touches and
writes only the ones it changed.

| | Per million objects |
|---|---|
| Stored (gzipped) | about **35 MB** (34.4 bytes a row, measured by `tests/test_index.py` on made-up keys with fingerprints) |
| Building it (one row per object read) | about 8 s of CPU |
| Saving it | about 5 s |
| Loading a shard and looking up a key | well under a second |

The index is bounded:

- A source indexes at most `INDEX_MAX_OBJECTS` objects (10 million, about
  350 MB). Past that, objects are read as before, by their change at the
  source only.
- A complete listing pass drops the rows of objects it did not list (objects
  gone), and a delta feed's deletions drop theirs.
- An index that cannot be read, or was written under another salt (the state
  was reset), is no index: the run starts a fresh one.
- Saving is best effort. A failed save is logged (`index.failed`) and costs
  the next run its decisions, never findings.

`OBJECT_INDEX=off` turns the index off.

Today the index records S3 (and Glue tables and directory buckets), Azure Blob
Storage and Files, Cloud Storage, and OneDrive, SharePoint and Drive files.
Rescans chosen from it, change detection for tables and duplicate skipping
build on it (#67).

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

Every kind of store after RDS is an **adapter** (the core's
`sensitive_data_core.adapter.Adapter`), registered by its kind in
`sources/aws.py` and given an AWS `Context` (`sources/base.py`). An adapter
lists its stores into the run summary (`sensitive_data_core.coverage`),
decides each with the shared allow, deny and sampling rules
(`discovery.decide`, on the core's `rules` and `coverage.apply_rules`), and
gives the runner a source per store it can read. The budget, the findings store, the coverage and the run
summary stay the core's, and none of them names a cloud: an adapter gets its
clients by service name (`clients.client("redshift-data")`), made on first
use, so a kind that is not discovered makes no client.

Reading SQL is generic too (the core's `scan/sql.py`): a dialect (quoting, the table
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
- **The user is checked first**, with the databases runner's own check (the
  core's `grants`): PostgreSQL's superuser, CREATEROLE, CREATEDB, CREATE on
  the database or any schema (before PostgreSQL 15 that includes `public`
  through PUBLIC: run `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` once), and
  INSERT, UPDATE, DELETE or TRUNCATE on any table; MySQL's `SHOW GRANTS`,
  every granted role included, against an allow list of reads. A user that
  can write is refused as `db_user_can_write` (with `writeGrants`), and one
  whose privileges cannot be read as `grants_unverifiable`; nothing is read,
  and the coverage names it (`DbUserCanWrite`, `GrantsUnverifiable`).
- The secret should belong to a database user with `SELECT` only.
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

### OpenSearch domains and Serverless collections

With `DISCOVER` including `opensearch`, the run lists the managed domains
(`ListDomainNames`, then `DescribeDomains` five at a time; OpenSearch and
Elasticsearch engines alike) and the Serverless collections
(`ListCollections`, `BatchGetCollection` for their endpoints).

Each domain is read with **signed HTTPS GETs only** (SigV4, the scanner's
own role):

1. `GET /_cat/indices?format=json` lists the open indices. System indices
   (names starting with `.`) are left out; data-stream backing indices
   (`.ds-*`) are read.
2. `GET /<index>/_search?size=n` samples up to `OPENSEARCH_DOCS_PER_INDEX`
   documents of each index, up to `OPENSEARCH_MAX_INDICES` indices. An index
   with more documents than the sample counts as `partial`.
3. Each document's `_source` is read field by field, with the field's name as
   context, nested objects leaf by leaf.

Findings are `store_field` with `service` `opensearch` (or
`opensearch_serverless`), the domain as `store`, the index as `table`, the
top-level field as `field`, and `readBy: search`; format `json`. A pass
resumes at the next index across runs, within the budget.

Not read, and reported:
- **A VPC domain** (`vpc_only`): the scanner's Lambda does not run in the
  domain's VPC, so its endpoint is out of reach.
- **A domain being created or deleted** (`unsupported`, with its `state`).
- **A domain that refuses the role** (`access_denied`): its access policy,
  or fine-grained access control without a mapping. To include it, map the
  scanner's role to a backend role with read-only permissions
  (`indices:data/read/search`, `indices:monitor/stats` for `_cat/indices`).
- **Serverless collections**, unless `OPENSEARCH_SERVERLESS_READ` is on
  (`read_not_configured`). IAM's `aoss:APIAccessAll` cannot be narrowed to
  reads, so each collection's data access policy is what keeps the scanner
  read-only: grant its role `aoss:ReadDocument` (and `aoss:DescribeIndex`)
  and nothing else. A collection whose policy does not is `access_denied`.

### EBS snapshots, backups and file systems

**EBS.** With `DISCOVER` including `ebs`, the run lists the volumes
(`DescribeVolumes`) and this account's completed snapshots
(`DescribeSnapshots`, `OwnerIds=self`). Each volume is one store, read
through its latest snapshot. The latest snapshot of a volume that no longer
exists is a store of its own (`resource: snapshot`). Earlier snapshots of a
volume are copies of it, counted (`olderSnapshots`) and not read. AWS Backup's
EBS recovery points are EBS snapshots in the account, so they are covered
here.

- **Reading is opt-in** (`EBS_DIRECT_READ`). The EBS direct APIs read a
  snapshot's blocks with no volume created or attached and nothing written:
  `ListSnapshotBlocks` from evenly spread starting points, then
  `GetSnapshotBlock` for four consecutive blocks at each, up to
  `EBS_BLOCKS_PER_SNAPSHOT` (512 KiB each) per snapshot. A snapshot is read
  across as many runs as the budget needs, and read again only when a newer
  snapshot appears.
- **What is read.** The runs of printable text in the raw blocks (ASCII and
  UTF-16), those that could hold a value, read as text. The file system is
  not parsed: a file compressed or encrypted on disk is not read, and a
  finding names the volume (`store_field`, `service: ebs`, `field: blocks`,
  `readBy: ebs_direct`, with the snapshot's time), not a file. A sample is
  counted as `partial`.
- **Within Lambda's limits.** Each block is 512 KiB in memory, and the
  budget's bytes cap the run. The default reads 128 MiB of a volume.
- **Not read, and reported:** a volume with no completed snapshot
  (`no_snapshot`; creating one would be a write), a snapshot in the archive
  tier (`archived`), and everything while reading is off
  (`read_not_configured`). An encrypted snapshot needs `kms:Decrypt` through
  EBS; without it the store is `kms_access`.

**AWS Backup.** With `backup`, each vault is listed with its recovery points
counted by resource type (`recoveryPoints`), and reported as `backup_copy`.
Its EBS points are read as EBS snapshots (above). The rest are copies of
stores the other adapters read where they live (S3, DynamoDB, RDS, EFS, ...).
Restoring a copy to read it would be a write, and the scanner makes none.

**DocumentDB and Neptune.** With `documentdb` or `neptune`, the clusters are
listed (`DescribeDBClusters` by engine, and DocumentDB elastic clusters by
`ListClusters`) and reported as `no_snapshot_export`. RDS's snapshot export
takes Aurora MySQL and PostgreSQL, and RDS MySQL, MariaDB and PostgreSQL,
only, and the scanner holds no database credentials. When these kinds are
discovered, the `rds` listing leaves their clusters to them.

**EFS and FSx.** With `efs` or `fsx`, each file system is listed
(`DescribeFileSystems`, with its size) and reported as `needs_task`: a file
system is read by mounting it inside its VPC, which the scanner's Lambda
does not do.

#### The opt-in file-system task (design, not built)

EFS, FSx, and EBS read by file rather than by block, need a mount. The
design is an ECS task on Fargate, deployed only where it is turned on:

- **Where.** One task definition per account and region, run in the VPC and
  subnets of the file system (a parameter per file system), with a security
  group that allows NFS (2049) or SMB (445) outbound to it only.
- **How it mounts.** EFS: a Fargate EFS volume with an access point whose
  POSIX user can only read, `readOnly: true`, and IAM authorization with
  `elasticfilesystem:ClientMount` only (never `ClientWrite` or
  `ClientRootAccess`, which the scanner's role denies). FSx for OpenZFS and
  ONTAP (NFS): a read-only mount. FSx for Windows and ONTAP (SMB): a domain
  account with read permissions, kept in Secrets Manager. FSx for Lustre: the
  Lustre client, read-only. EBS by file: a volume created from the snapshot
  in the task's zone and attached read-only; this is a write
  (`ec2:CreateVolume`, `AttachVolume`, then `DeleteVolume`), so it is its own
  opt-in and its own role.
- **What it runs.** The same image and scanner code, with a file-tree source
  in place of the S3 source: it walks the mount by path, reads each file as
  an S3 object is read (formats, sizes, sampling per directory), and writes
  findings to the same results bucket, named by path.
- **Triggered** by the batch run, one task per file system at most per
  `EXPORT_MIN_INTERVAL_DAYS`, like the exports.

Until it is built, these stores stay in the run summary as `needs_task`.

##### Hosting it in the databases runner's image (design, not built)

The databases runner's image ([DATABASES.md](DATABASES.md), `docker build
--target db`) already runs anywhere a container runs, with the core, the
budget, the coverage summary and the signed sinks. The file-system task can
be the same image with a second command, so one image serves databases and
file shares, in AWS and outside it:

- **A package and a command.** `scanner/fs` (`sensitive_data_fs`), on the
  core only (the standard library walks a tree), installed in the `db` image
  by an `fs` extra; `python -m sensitive_data_db files` (or an entry point of
  its own) scans the mounts named by `FS_MOUNTS` (`name=/mnt/path`, one per
  store). pyarrow, for Parquet and ORC on a share, is a further extra, since
  it adds about 150 MB.
- **Read-only, checked first.** Like `db_user_can_write`: before walking, the
  runner checks the mount is read-only (`statvfs` `ST_RDONLY`, and
  `os.access(..., W_OK)` false) and refuses a writable one as a coverage gap
  (`mount_writable`). Files are opened read-only with `O_NOATIME` where the
  kernel allows it, symlinks are not followed out of the mount, and device
  files, FIFOs and sockets are skipped.
- **Mounting, by where it runs.**
  - EFS: a Fargate task (as above) with an EFS volume, `readOnly: true`, an
    access point whose POSIX user can only read, and IAM authorization
    allowing `elasticfilesystem:ClientMount` only.
  - FSx for Windows: an ECS task on EC2 (Fargate cannot mount it) with
    `fsxWindowsFileServerVolumeConfiguration`, the container's mount point
    `readOnly`, and a domain account that can only read, in Secrets Manager.
  - FSx for ONTAP, OpenZFS and Lustre: NFS or Lustre mounted read-only on an
    ECS container instance or an EKS node (a `PersistentVolume` with
    `readOnly: true`), bind-mounted read-only into the task or pod. Fargate
    mounts only EFS, so these need EC2 capacity, which is part of the opt-in.
  - Outside AWS: any share the host or cluster mounts (NFS, SMB, Azure
    Files, Filestore), passed to the container read-only (`docker run -v
    /mnt/share:/data:ro`, a Kubernetes volume with `readOnly: true`).
- **Reading.** A file-tree source that walks by path in sorted order, reads
  each file as the S3 source reads an object (the same formats, size caps and
  decompression limits, sampling per directory with `FS_MAX_FILES_PER_DIR`,
  and a budget of files, bytes and time), and resumes after its last path.
  Findings name the store and the path, masked like an object key: a new
  `file` resource (a findings schema minor bump when it is built).
- **State and findings.** In AWS, the batch run starts the task
  (`ecs:RunTask`), and the task writes its findings document and cursor
  under the results bucket (`fs/<file system>/`), which the next batch run
  reads to settle the store (`scanned`, or its gap); its findings also go to
  the central EventBridge bus. Outside AWS, the cursor lives in a small
  mounted state volume (or none: each run samples afresh), and findings go
  to the HTTPS or file sinks, as for databases.

### Streams and queues

**Kinesis Data Streams.** With `DISCOVER` including `kinesis`, the run lists
the streams (`ListStreams`; one not `ACTIVE` or `UPDATING` is `unsupported`),
and for each stream its shards (`ListShards`, up to `KINESIS_MAX_SHARDS`).
For each shard it gets an iterator at `TRIM_HORIZON` and makes at most three
`GetRecords` calls, up to `KINESIS_RECORDS_PER_SHARD` records.

- **Never a consumer.** No lease table, no checkpoint, and no sequence
  number is kept: the cursor names only the next shard of the pass. Each
  pass samples the oldest records the stream still holds.
- **Shared limits.** A shard serves five `GetRecords` calls and 2 MB a
  second to all its consumers together. The scanner makes at most three
  calls per shard per run, so a consumer near the limit may see a throttle.
  Enhanced fan-out consumers are not affected.
- Each record is read as text (gunzipped when it is gzip, as CloudWatch Logs
  subscriptions are; binary records counted as skipped). Findings are
  `store_field` with `service: kinesis`, the stream as `store`,
  `field: records` and `readBy: shard_sample`, counted across the pass.
- A stream encrypted with a customer managed key needs `kms:Decrypt` through
  Kinesis (`AllowKmsDecrypt` includes it).

**Firehose.** With `firehose`, the run lists the delivery streams and reads
every S3 location each one writes to: the destination prefix, the error
output prefix, and the S3 backup of a Redshift, OpenSearch, Splunk, HTTP
endpoint or Snowflake destination. A prefix is cut at its first expression
(`fh/!{timestamp:yyyy}/` is read as `fh/`). Each location is an S3 source,
so findings name the objects, and a discovered bucket's own source leaves
those prefixes to the stream: each object is read once. The stream's
`destinations` are listed in the summary. Redshift and OpenSearch
destinations are read by their own kinds. A stream with no S3 location is
`no_s3_destination`.

**SQS dead-letter queues.** With `sqs`, the run lists the queues and their
attributes. A queue that another queue's redrive policy names as its
`deadLetterTargetArn` is a dead-letter queue (`deadLetterQueue: true`).
Every other queue is live traffic and is **never read** (`live_queue`).

- **Off by default** (`SQS_DLQ_READ`), because a receive is not invisible:
  every `ReceiveMessage` raises each message's `ApproximateReceiveCount`.
- **When on**, the run calls `ReceiveMessage` with `VisibilityTimeout=0`
  (each message is visible again at once) and `WaitTimeSeconds=0`, up to
  `SQS_MESSAGES_PER_QUEUE` messages, and stops at the first batch it has
  already seen. It never deletes a message or changes its visibility; the
  role denies both.
- **A DLQ with a redrive policy of its own is never read**
  (`redrive_would_change`): past its `maxReceiveCount`, SQS would move the
  message to the next queue. A redrive back to the source queue
  (`StartMessageMoveTask`) moves all messages whatever their receive count,
  so it is unchanged.
- **FIFO.** A receive briefly holds the message group of a FIFO queue. With
  `VisibilityTimeout=0` the hold ends at once.
- The body and the message attributes' string values are read. Findings are
  `store_field` with `service: sqs`, the queue as `store`,
  `field: messages` and `readBy: receive`.

### Parameter Store and Secrets Manager

Each is **one store** per account and region (`parameter-store`,
`secrets-manager`) holding many values, so the run summary stays short. The
allow and deny rules apply to **each parameter or secret by its name** or
its tags (`ssm:/prod/*`, `secretsmanager:rds!*`, `secretsmanager:tag:pii=no`),
and the store's `excluded` counts what they left out by reason. `items`
counts what was listed, and `itemTypes` counts parameters by type or secrets
managed by another service (RDS, for example) against the account's own.

A finding names **one parameter or secret** (`store_field` with the name as
`store`, `field: value`) with counts only, and never the value, a key or a
fragment of it.

- **SSM Parameter Store** (`ssm`): `DescribeParameters`, then
  `GetParameters` ten names at a time, resumable by name within the budget.
  `SecureString` values are decrypted through SSM (`SSM_DECRYPT`, on by
  default: `kms:Decrypt` with `kms:ViaService` `ssm.<region>`). With it off,
  they are counted as `excluded.secure_string` and not read. Only the current
  version is read, not the history. The scanner's own configuration
  parameters (under `/sensitive-data-scanner/`, see `CONFIG_LOCATION`) are
  never read as data (`excluded.self`).
- **Secrets Manager** (`secretsmanager`): `ListSecrets` always, so every
  secret is counted in the summary. Reading is **off by default**
  (`SECRETS_READ`), because a secret holds credentials and each read is an
  event its owner audits in CloudTrail. When on, `GetSecretValue` is called
  for each secret the rules let through, and its value (JSON by key, or
  text) is read for sensitive data: a card number or an SSN kept in a secret
  is a finding. A secret the scanner may not read (its resource policy, its
  key) is counted `unreadable`, and the pass goes on. Binary secrets that are
  not text are counted `unreadable`.

### Caches, Timestream and Keyspaces

**ElastiCache and MemoryDB** (`elasticache`, `memorydb`). The run lists
replication groups (their member clusters are not listed again), standalone
cache clusters, serverless caches and MemoryDB clusters, counts each one's
snapshots (`snapshots`), and reports them as `in_memory`. The data lives in
memory inside the VPC, behind the cache's own authentication, and a snapshot
has no read path while it stays in the service. A snapshot **exported to
S3** (`CopySnapshot` with a target bucket, or
`ExportServerlessCacheSnapshot`) is an RDB file in a bucket. The S3 source
reads it: an object that starts with `REDIS` or ends in `.rdb` is read as
the runs of printable text in it (strings of 20 bytes or more may be
LZF-compressed in an RDB, and are then not read), with format `rdb` and no
offsets. The scanner never exports a snapshot itself (`CopySnapshot` is
denied).

**Timestream for LiveAnalytics** (`timestream`). The run lists databases and
tables (`ListDatabases`, `ListTables`; Timestream's endpoint discovery needs
`DescribeEndpoints`), and for each active table runs one query:

```sql
SELECT * FROM "db"."table" WHERE time > ago(1d) LIMIT 1000
```

The quoted names come from the generic SQL dialect, and pages are followed
up to the row limit. The rows are read by column (`store_field`,
`service: timestream`, the database as `store`, the table, the measure or
dimension as `field`, `readBy: query`, format `sql`). A query is billed by
the data it scans, so the time filter (`TIMESTREAM_LOOKBACK_DAYS`) keeps it
to recent data. Timestream for InfluxDB instances are listed and reported as
`no_read_path`.

**Keyspaces** (`keyspaces`). The run lists keyspaces and tables (the system
keyspaces are left out), and for each table runs one CQL query over TLS to
`cassandra.<region>.amazonaws.com:9142`, signed with the scanner's own role
(the SigV4 plugin; no service-specific password):

```sql
SELECT * FROM "keyspace"."table" LIMIT 1000
```

The consistency is `LOCAL_ONE`, and the rows are read by column
(`service: keyspaces`, format `cql`). One session is kept per run; a session
left from an earlier invocation that has gone dead is replaced once. The
only permission is `cassandra:Select`, which Keyspaces checks for both the
listing (the system keyspaces) and the read. A sampled `LIMIT` read uses the
table's read capacity. The Cassandra driver is a dependency of both the
image and the zip.

### Step Functions, Lambda environment variables and X-Ray

Read by default when discovered: each is where an application leaves data in
passing, and each read is a describe or a get.

- **Step Functions.** `ListStateMachines`, then `DescribeStateMachine` for
  its encryption. For each Standard state machine, the most recent
  `STEPFUNCTIONS_EXECUTIONS` executions (`ListExecutions`) and each one's
  history (`GetExecutionHistory` with `includeExecutionData`, up to
  `STEPFUNCTIONS_EVENTS` events): the `input`, `output`, `parameters`,
  `result`, `error` and `cause` of every event are read as JSON or text.
  Findings are `store_field` with the state machine as `store`, that part as
  `field`, and `readBy: execution_history`. A pass that runs out of budget
  resumes with the executions it has not read (kept in the state as hashes,
  never names). An **Express** state machine keeps no history in the service
  (its runs go to CloudWatch Logs, read by the logs source), so it is reported
  `unsupported` with `workflowType: express`. Nothing is started, stopped,
  redriven or answered (`SendTask*`): the role denies it.
- **Lambda environment variables.** `ListFunctions`, then
  `GetFunctionConfiguration` for each function (never `GetFunction`, which
  would hand out the code's download link). Each variable's value is read with
  its name as context, like a column, and reported **as counts only**, like a
  secret: `store_field` with the function as `store`, the variable's name as
  `field`, `readBy: get_function_configuration`. Variables encrypted with a
  customer managed key the scanner may not use come back as an error, not
  values: counted `unreadable` (`kmsDenied`). The scanner's own function
  (`AWS_LAMBDA_FUNCTION_NAME`) is `self`. Nothing is invoked.
- **X-Ray.** One store per account and region, `xray-traces`, with its
  encryption from `GetEncryptionConfig` (`NONE` is X-Ray's default AWS-held
  key). Each run asks for sampled trace summaries (`GetTraceSummaries` with
  `Sampling`) from where the last run ended (at most `XRAY_LOOKBACK_HOURS`
  back), six hours at a time, then `BatchGetTraces` five at a time, up to
  `XRAY_MAX_TRACES`. Each segment's and subsegment's `annotations` and
  `metadata` are read; a finding names the segment's service as `store`.

### CodeCommit and S3 directory buckets

- **CodeCommit.** `ListRepositories`, `GetRepository` (the default branch
  and the key). For each repository, the branch's head (`GetBranch`) is walked
  with `GetFolder` (at most `CODECOMMIT_MAX_FOLDERS`), and a stable sample of
  its files, ordered by a hash of the path so it spreads across the tree, is
  read with `GetFile` (at most `CODECOMMIT_MAX_FILES`, each to
  `MAX_OBJECT_BYTES`), by the core's reader as S3 reads them: by content, so
  audio, video, images and binary files are counted, not read, and Office
  files, PDFs and archives are read as their text and by entry. Findings name the repository and the file's
  path (`readBy: get_file`). A pass resumes across runs, and a head already
  read in full is not read again until the branch moves. An empty repository
  is `unsupported` (`state: empty`). Nothing is pushed or merged.
- **S3 directory buckets** (S3 Express One Zone). `ListDirectoryBuckets`,
  then each bucket read by the S3 source. A directory bucket is reached only
  through an S3 Express session, and every session the scanner's client
  creates asks for `SessionMode=ReadOnly` (a botocore hook on
  `CreateSession`); the role allows `s3express:CreateSession` only with that
  mode and denies any other. A directory bucket lists in no key order and
  takes no `StartAfter`, so a pass resumes at its page's continuation token,
  after the objects of that page already read. Links open the directory
  bucket's page (`bucketType=directory`).

### MSK and Amazon MQ

Both are discovered and reported always, and read only when turned on. A
broker lives inside a VPC: the scanner reaches it only through a public
endpoint or when its function runs in that VPC, and a broker it cannot reach
is `vpc_only`, a coverage gap.

**MSK** (`msk`, `MSK_READ`). `ListClustersV2` lists provisioned and
Serverless clusters, with their encryption (a provisioned cluster's data
volume key; Serverless always an AWS key). A cluster is read only with IAM
authentication (Serverless always has it; a provisioned cluster without it is
`no_read_path`, since the scanner keeps no SASL/SCRAM password or client
certificate):

- `GetBootstrapBrokers`, preferring the public IAM endpoint;
- a Kafka consumer (`kafka-python`, its `AWS_MSK_IAM` mechanism signed with
  the scanner's role) under a **throwaway group id**,
  `sensitive-data-scanner-<random>`, with auto-commit off. It never joins the
  group: partitions are assigned by hand. It never commits: no commit is ever
  called, and the role denies `kafka-cluster:AlterGroup`, so none could be.
  The only group permission is `DescribeGroup` on the scanner's own
  throwaway groups (the consumer asks for their committed offsets; there are
  none);
- for each topic (internal `__*` topics left out, up to `MSK_MAX_TOPICS`),
  its partitions (up to `MSK_MAX_PARTITIONS`) seeked to the beginning and
  polled up to `MSK_RECORDS_PER_PARTITION` records each. Records are read as
  text, gunzipped when gzip; binary records are counted, tombstones skipped.
  A pass resumes at the next topic, and keeps no offset.

Findings are `store_field` with the cluster as `store`, the topic as
`table`, `field: records` and `readBy: consumer_sample`.

**Amazon MQ** (`mq`, `MQ_READ` and `MQ_BROKERS`). `ListBrokers` and
`DescribeBroker` list every broker with its encryption (an AWS owned key or
the broker's KMS key).

- **RabbitMQ** has no read that leaves a queue as it was: a get (or the
  management API's "get messages") takes the message and requeues it,
  redelivered. It is reported `no_read_path`.
- **ActiveMQ** queues are **browsed**: STOMP 1.2 over TLS (`stomp+ssl`,
  port 61614) with `SUBSCRIBE ... browser:true`, which ActiveMQ serves with a
  queue browser. Messages are sent to the scanner and stay on the queue; the
  scanner never sends `ACK`, then `UNSUBSCRIBE` and `DISCONNECT`. Up to
  `MQ_MESSAGES_PER_QUEUE` per queue, for the queues named in the broker's
  `MQ_BROKERS` entry (listing a broker's queues needs its web console, an
  administrator's).
- **The user is checked first**, as the databases runner checks its own.
  The broker has no IAM for its data, so the entry names a Secrets Manager
  secret with a broker user's `username` and `password`. Before connecting,
  `DescribeUser` and the broker's current configuration
  (`DescribeConfigurationRevision`) are read, and the user is refused as
  `user_can_write` (with `writeGrants`) when it has web console access (an
  administrator: `console_access`), when the broker has no authorization map
  (every user can do everything: `no_authorization_map`), or when a queue
  authorization entry gives one of its groups `write` or `admin`
  (`queue_write`, `queue_admin`). Nothing is read from a refused broker.
  Findings are `store_field` with the broker as `store`, the queue as
  `table`, `field: messages` and `readBy: browse`.

### ECR, SageMaker and Neptune Analytics

**ECR** (`ecr`, `ECR_READ`). Opt-in because a layer is downloaded. For
each repository (`DescribeRepositories`, with its encryption), the most
recently pushed image (`DescribeImages`), its manifest (`BatchGetImage`; for a
multi-platform index, `linux/amd64`, else the first), and its top
`ECR_MAX_LAYERS` layers, where an application's own files are. Each layer is
fetched from the URL ECR signs for it (`GetDownloadUrlForLayer`), at most
`ECR_MAX_LAYER_BYTES`, and read as a stream (gzip or plain tar; a zstd layer
is counted as an archive, not read): up to `ECR_MAX_FILES_PER_LAYER` regular
files outside the operating system's own directories (`usr/`, `lib/`,
`bin/`, ...), each to `MAX_OBJECT_BYTES`, by the core's reader as S3 reads
them: each member's first bytes say what it is, so media and binaries are
counted (and do not count toward the files cap), and Office files, PDFs and
archives (a `.jar`, a `.whl`) are read as their text and by entry.
Nothing is extracted to disk. Findings are `store_field` with the
repository, the layer's digest as `table`, the path as `field`, and `readBy:
layer_sample`. An image read in full is not read again until a newer push.

**SageMaker** (`sagemaker`, `SAGEMAKER_READ`).
- A **feature group's offline store** is S3 (Parquet under its resolved URI):
  it is read there by the S3 source, as a Firehose destination is, and the
  bucket's own source leaves that prefix to it.
- The **online store** has no API that lists its records (`GetRecord` needs
  each record's identifier), so an online-only group is `no_read_path`; the
  offline store, when there is one, holds the same records' history.
- A **notebook instance** is `no_read_path`: its ML storage volume lives in
  SageMaker's own account, where no snapshot or EBS direct read reaches it.

**Neptune Analytics** (`neptune-analytics`). Like RDS, a graph is read by an
**export**, never by a query: `StartExportTask` to CSV in the results
bucket's `exports/neptune-graph/`, written by the export role
(`NEPTUNE_ANALYTICS_EXPORT_ROLE_ARN`, trusted by `neptune-graph.amazonaws.com`)
and encrypted with the customer's key, within `MAX_EXPORTS_PER_RUN` (shared
with RDS and DynamoDB) and `EXPORT_MIN_INTERVAL_DAYS`. Later runs wait
(`GetExportTask`), read each CSV file by column (the openCypher headers name
the properties), then delete the export. Findings are `store_field` with the
graph, `nodes` or `edges` as `table`, the property as `field`, and `readBy:
export`. Queries that write (`WriteDataViaQuery`, `DeleteDataViaQuery`) are
denied.

### EventBridge archives and Glacier vaults

**EventBridge archives** (`eventbridge`). Every archive is reported with its
size (`sizeBytes`), its events (`eventCount`) and its retention
(`retentionDays`), and its encryption. An archive has no read API: its
events come back only by a replay, and a replay can only go to the bus the
archive belongs to. So reading is opt-in (`EVENTBRIDGE_REPLAY`), and aimed
at the scanner's own resources only:

1. On the archive's bus, a rule of the scanner's own for that archive,
   `sensitive-data-scanner-replay-<hash>`, matches only events the scanner
   replays from it (`replay-name` starting `sds-<hash>-`) and targets the
   scanner's own queue, `sensitive-data-scanner-replay` (created by the
   template, SQS-managed encryption, a policy that lets only those rules
   send to it).
2. `StartReplay` of the last `EVENTBRIDGE_REPLAY_HOURS`, with `FilterArns`
   naming only that rule: **none of the bus's other rules, the customer's,
   receives a replayed event.**
3. Later runs wait (`DescribeReplay`), then receive the replayed events from
   the queue (up to `EVENTBRIDGE_REPLAY_MAX_EVENTS`), read each event's
   `detail`, and delete them from that queue: the scanner's own.
4. When the queue is empty, the rule's target and the rule are removed.

The role may put, target and delete only rules named
`sensitive-data-scanner-replay-*`, start and describe only replays named
`sds-*`, and delete messages only from its own queue (each with a matching
Deny for everything else). A replay counts as an export against
`MAX_EXPORTS_PER_RUN` and `EXPORT_MIN_INTERVAL_DAYS`. Findings are
`store_field` with the archive as `store`, `field: events` and `readBy:
replay`.

**S3 Glacier vaults** (`glacier`, the legacy vault API). `ListVaults`: each
vault is reported with its archives (`archives`) and size as
`archive_retrieval`. Reading an archive needs a retrieval job, which takes
hours and is billed; the scanner starts none, and the role denies
`glacier:InitiateJob`. (Objects in the S3 Glacier storage classes are S3,
read by the S3 source where they can be; archived ones are skipped by S3.)

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

### At-rest encryption on every finding

Each store's adapter reads the storage encryption its data sits under from
the listing it already makes, and every finding carries it
(`atRestEncryption`: `none`, `service_managed`, `customer_managed_key` or
`unknown`; a customer's key named only by `atRestKeyHash`, the SHA-256 of its
key id), with a PCI DSS note for the assessor on `card` and `cvv` findings
([FINDINGS.md](FINDINGS.md#at-rest-encryption-and-pci-dss-notes-15) has the
table of where each store's value comes from, and the notes).

- **S3** reads it per object, from the `x-amz-server-side-encryption` header
  of the GET that read it, because an object stored before its bucket's
  default encryption is still unencrypted. The bucket's default
  (`GetBucketEncryption`) is on the store in the run summary.
- **AWS managed or the customer's.** An AWS managed key (`aws/s3`,
  `aws/ebs`, ...) and a customer managed key look alike in most services'
  descriptions. One `kms:ListAliases` per run and region lists the key ids
  behind the `alias/aws/*` aliases; any other key is the customer's. Without
  it, a key is `unknown`, with its hash. No key is described or used.
- **Configured stores** look theirs up once: a DynamoDB table in its own
  `DescribeTable`, a log group with `DescribeLogGroups`, a Data API cluster
  with `DescribeDBClusters`. A lookup that fails leaves the findings without
  the field; the read goes on.
- The core (`sensitive_data_core.findings`) adds `pciNote` from the class
  and the store's value; the databases runner fills the value from what each
  engine reports ([DATABASES.md](DATABASES.md)).

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
- **List**: `s3:ListBucket` on the results bucket, conditioned on the results
  prefix if it has one (`s3:prefix` `<prefix>/*`).
  - The scanner lists its own `exports/`.
  - Without this permission, S3 answers a missing object with 403
    AccessDenied instead of 404. The first run's state file is missing.
  - The runner copes: a 403 on the state file counts as "no state yet" when
    the lock the run has just written can be read, which shows its access is
    otherwise fine.
  - Grant it anyway, so a real denial is never confused with a missing file.
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
| `s3` | `s3:ListAllMyBuckets`; `s3:ListBucket`, `s3:GetObject`, `s3:GetObjectVersion`; `s3:GetEncryptionConfiguration` (the bucket's default encryption, for the run summary); `s3:GetBucketTagging` only with tag rules | `*` (buckets `arn:aws:s3:::*`, objects `arn:aws:s3:::*/*`) |
| `logs` | `logs:DescribeLogGroups`, `logs:FilterLogEvents`; `logs:ListTagsForResource` only with tag rules | `*` |
| `dynamodb` | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:Scan`; `dynamodb:ListTagsOfResource` only with tag rules | `*` |
| `glue` | `glue:GetDatabases`, `glue:GetTables`; `glue:GetTags` only with tag rules; plus the S3 read actions on each table's location | `*` (catalog, databases and tables) |
| `rds` (snapshot export) | `rds:DescribeDBClusters`, `rds:DescribeDBInstances`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBSnapshots`, `rds:StartExportTask`, `rds:DescribeExportTasks`; `iam:PassRole` on the export role only, conditioned on `iam:PassedToService` `export.rds.amazonaws.com`; `kms:CreateGrant` and `kms:DescribeKey` on the export key, conditioned on `kms:ViaService` `rds.<region>.amazonaws.com` and `kms:GrantIsForAWSResource`; `kms:Decrypt` on that key via S3, to read the export | `*` for describe; the export role and key ARNs |
| RDS export role (assumed by `export.rds.amazonaws.com`) | `s3:PutObject*`, `s3:GetObject*`, `s3:ListBucket`, `s3:DeleteObject*`, `s3:GetBucketLocation` on the results bucket's `exports/rds/` prefix only | the results bucket |
| `rds` (Data API, opt-in) | `rds-data:BeginTransaction`, `rds-data:ExecuteStatement`, `rds-data:RollbackTransaction` on the named clusters; `secretsmanager:GetSecretValue` on the named secrets | the named ARNs |
| DynamoDB export | `dynamodb:DescribeContinuousBackups`, `dynamodb:ExportTableToPointInTime`, `dynamodb:DescribeExport`; `s3:PutObject` and `s3:AbortMultipartUpload` on `exports/dynamodb/`; with a key, `kms:GenerateDataKey` and `kms:Decrypt` via S3 | tables `*`; the results bucket |
| `redshift` | `redshift:DescribeClusters`, `redshift-serverless:ListWorkgroups`, `redshift-serverless:ListNamespaces`; `redshift-serverless:ListTagsForResource` only with tag rules | `*` |
| `opensearch` | `es:ListDomainNames`, `es:DescribeDomains`, `aoss:ListCollections`, `aoss:BatchGetCollection`; `es:ListTags`, `aoss:ListTagsForResource` only with tag rules; `es:ESHttpGet` on the domains; with `OpenSearchServerlessRead`, `aoss:APIAccessAll` on the collections | `*`; this account's domains and collections |
| `ebs`, `backup`, `documentdb`, `neptune`, `efs`, `fsx` | `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `backup:ListBackupVaults`, `backup:ListRecoveryPointsByBackupVault`, `backup:ListTags`, `rds:DescribeDBClusters`, `docdb-elastic:ListClusters`, `docdb-elastic:ListTagsForResource`, `elasticfilesystem:DescribeFileSystems`, `fsx:DescribeFileSystems`; with `EbsDirectRead`, `ebs:ListSnapshotBlocks` and `ebs:GetSnapshotBlock` on this region's snapshots, and `kms:Decrypt` through EBS | `*`; `snapshot/*` |
| `kinesis`, `firehose`, `sqs` | `kinesis:ListStreams`, `kinesis:DescribeStreamSummary` (the stream's encryption), `kinesis:ListShards`, `kinesis:GetShardIterator`, `kinesis:GetRecords`, `firehose:ListDeliveryStreams`, `firehose:DescribeDeliveryStream`, `sqs:ListQueues`, `sqs:GetQueueAttributes`; `kinesis:ListTagsForStream`, `firehose:ListTagsForDeliveryStream`, `sqs:ListQueueTags` only with tag rules; with `SqsDlqRead`, `sqs:ReceiveMessage` | `*`; this account's queues |
| `stepfunctions`, `lambda`, `xray`, `codecommit` | `states:ListStateMachines`, `states:DescribeStateMachine`, `states:ListTagsForResource`, `states:ListExecutions`, `states:GetExecutionHistory`, `lambda:ListFunctions`, `lambda:ListTags`, `lambda:GetFunctionConfiguration`, `xray:GetEncryptionConfig`, `xray:GetTraceSummaries`, `xray:BatchGetTraces`, `codecommit:ListRepositories`, `codecommit:GetRepository`, `codecommit:ListTagsForResource`, `codecommit:GetBranch`, `codecommit:GetFolder`, `codecommit:GetFile` | `*` |
| `msk`, `mq` | `kafka:ListClustersV2`, `mq:ListBrokers`, `mq:DescribeBroker`; with `MskRead`, `kafka:GetBootstrapBrokers`, `kafka-cluster:Connect`, `kafka-cluster:DescribeCluster`, `kafka-cluster:DescribeTopic`, `kafka-cluster:ReadData`, and `kafka-cluster:DescribeGroup` on the scanner's own `sensitive-data-scanner-*` groups only; with `MqRead`, `mq:DescribeUser`, `mq:DescribeConfigurationRevision` and `secretsmanager:GetSecretValue` on the named secrets | `*`; this account's clusters, topics and groups; the ARNs named |
| `ecr`, `sagemaker`, `neptune-analytics`, `eventbridge`, `glacier` | `ecr:DescribeRepositories`, `ecr:ListTagsForResource`, `sagemaker:ListFeatureGroups`, `sagemaker:DescribeFeatureGroup`, `sagemaker:ListNotebookInstances`, `sagemaker:ListTags`, `neptune-graph:ListGraphs`, `neptune-graph:ListTagsForResource`, `events:ListArchives`, `events:DescribeArchive`, `glacier:ListVaults`, `glacier:ListTagsForVault`; with `EcrRead`, `ecr:DescribeImages`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`; with the graph export key, `neptune-graph:StartExportTask`, `neptune-graph:GetExportTask`, `iam:PassRole` on its role, `kms:Decrypt` through S3; with `EventBridgeReplay`, `events:PutRule`, `events:PutTargets`, `events:RemoveTargets`, `events:DeleteRule` on its own rules, `events:StartReplay`, `events:DescribeReplay` on its own replays, `sqs:ReceiveMessage`, `sqs:DeleteMessage` on its own queue | `*`; the ARNs named |
| `s3express` | `s3express:ListAllMyDirectoryBuckets`; `s3express:CreateSession` with `s3express:SessionMode` `ReadOnly` only | `*`; this account's directory buckets |
| `ssm`, `secretsmanager` | `ssm:DescribeParameters`, `ssm:GetParameters` (on this account's parameters), `secretsmanager:ListSecrets`; `ssm:ListTagsForResource` only with tag rules; with `SsmDecrypt`, `kms:Decrypt` through SSM; with `SecretsRead`, `secretsmanager:GetSecretValue` on this account's secrets and `kms:Decrypt` through Secrets Manager | `*`; the ARNs named |
| `elasticache`, `memorydb`, `timestream`, `keyspaces` | `elasticache:DescribeReplicationGroups`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeServerlessCaches`, `elasticache:DescribeSnapshots`, `elasticache:DescribeServerlessCacheSnapshots`, `memorydb:DescribeClusters`, `memorydb:DescribeSnapshots`, `timestream:DescribeEndpoints`, `timestream:ListDatabases`, `timestream:ListTables`, `timestream-influxdb:ListDbInstances`; `timestream:ListTagsForResource` only with tag rules; `timestream:Select` on the tables; `cassandra:Select` on the keyspaces | `*`; the ARNs named |
| `redshift` (reads, opt-in) | `redshift-data:ExecuteStatement`, `redshift-data:ListDatabases` on this account's clusters and workgroups; `redshift-data:DescribeStatement`, `redshift-data:GetStatementResult` on its own statements; `redshift-serverless:GetCredentials`; `redshift:GetClusterCredentialsWithIAM` (`iam`) or `redshift:GetClusterCredentials` on the one database user (`db_user`) | the ARNs named |
| Lake Formation | **none**: no `lakeformation:GetDataAccess` and no grants. Where Lake Formation governs a table, grant the scanner's role `SELECT` (and `DESCRIBE`) in Lake Formation to include it; otherwise it is reported as `lake_formation` | |
| KMS | `kms:Decrypt`, conditioned on `kms:ViaService` `s3.<region>.amazonaws.com` and `dynamodb.<region>.amazonaws.com` | the customer managed keys to be read through; without it, those stores are reported as `kms_access` |
| Encryption facts (1.5) | `kms:ListAliases`, once per run: which key ids are AWS managed (`alias/aws/*`), so each store's key is told apart ([At-rest encryption](#at-rest-encryption-on-every-finding)). No key is described or used | `*` |

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
| Its own results bucket | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:AbortMultipartUpload`; `s3:ListBucket` (it lists `exports/`, and it makes a missing state file a 404, not a 403) | the results bucket and its objects | |
| Its configuration document, with `ConfigLocation` in SSM | `ssm:GetParameter` | parameters under `/sensitive-data-scanner/` in this account and region | |
| Its own logs | `logs:CreateLogStream`, `logs:PutLogEvents` | its log group | |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketTagging`, `s3:GetEncryptionConfiguration`; `s3:ListBucket`; `s3:GetObject`, `s3:GetObjectVersion` | `*`, every bucket, every object | |
| CloudWatch Logs | `logs:DescribeLogGroups`, `logs:FilterLogEvents`, `logs:ListTagsForResource` | `*` | |
| DynamoDB | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:Scan`, `dynamodb:Query`, `dynamodb:ListTagsOfResource` | `*` | |
| Glue Data Catalog | `glue:GetDatabases`, `glue:GetTables`, `glue:GetTags` | `*` | |
| RDS and Aurora (discovery) | `rds:DescribeDBClusters`, `rds:DescribeDBInstances`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBSnapshots`, `rds:DescribeExportTasks` | `*` | |
| KMS (customer managed keys) | `kms:Decrypt` | `*` | `kms:ViaService` is `s3.<region>`, `dynamodb.<region>`, `kinesis.<region>`, or (#35) `states.<region>`, `lambda.<region>`, `xray.<region>` or `codecommit.<region>` (`AllowKmsDecrypt`) |
| Workflows, functions, traces and code (#35) | `states:ListStateMachines`, `states:DescribeStateMachine`, `states:ListTagsForResource`, `states:ListExecutions`, `states:GetExecutionHistory`, `lambda:ListFunctions`, `lambda:ListTags`, `lambda:GetFunctionConfiguration`, `xray:GetEncryptionConfig`, `xray:GetTraceSummaries`, `xray:BatchGetTraces`, `codecommit:ListRepositories`, `codecommit:GetRepository`, `codecommit:ListTagsForResource`, `codecommit:GetBranch`, `codecommit:GetFolder`, `codecommit:GetFile` | `*` | Read by default |
| S3 directory buckets (#35) | `s3express:ListAllMyDirectoryBuckets` | `*` | |
| | `s3express:CreateSession` | this account's `bucket/*` in the region | `s3express:SessionMode` is `ReadOnly`; `NoReadWriteExpressSessions` denies any other mode |
| Brokers (discovery) | `kafka:ListClustersV2`, `mq:ListBrokers`, `mq:DescribeBroker` | `*` | |
| MSK reads (opt-in) | `kafka:GetBootstrapBrokers`; `kafka-cluster:Connect`, `kafka-cluster:DescribeCluster` | this account's `cluster/*/*` in the region | only with `MskRead` |
| | `kafka-cluster:DescribeTopic`, `kafka-cluster:ReadData` | this account's `topic/*/*/*` | only with `MskRead` |
| | `kafka-cluster:DescribeGroup` | this account's `group/*/*/sensitive-data-scanner-*` | only with `MskRead`; the scanner's own throwaway groups |
| Amazon MQ reads (opt-in) | `mq:DescribeUser`, `mq:DescribeConfigurationRevision` | this account's brokers and configurations | only with `MqRead` and `MqSecretArns` |
| | `secretsmanager:GetSecretValue` | the named secrets (`MqSecretArns`) | the read-only broker users |
| Images, ML, graphs and archives (discovery) | `ecr:DescribeRepositories`, `ecr:ListTagsForResource`, `sagemaker:ListFeatureGroups`, `sagemaker:DescribeFeatureGroup`, `sagemaker:ListNotebookInstances`, `sagemaker:ListTags`, `neptune-graph:ListGraphs`, `neptune-graph:ListTagsForResource`, `events:ListArchives`, `events:DescribeArchive`, `glacier:ListVaults`, `glacier:ListTagsForVault` | `*` | A feature group's offline store is read with the S3 statements |
| ECR layers (opt-in) | `ecr:DescribeImages`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` | this account's `repository/*` in the region | only with `EcrRead` |
| Neptune Analytics export | `neptune-graph:StartExportTask` | this account's `graph/*` | only with `NeptuneAnalyticsExportKmsKeyArn` |
| | `neptune-graph:GetExportTask` | this account's `export-task/*` | |
| | `iam:PassRole` | the graph export role only | `iam:PassedToService` is `neptune-graph.amazonaws.com` |
| | `kms:Decrypt` | the graph export key | `kms:ViaService` is `s3.<region>` (to read the export) |
| EventBridge replays (opt-in) | `events:PutRule`, `events:PutTargets`, `events:RemoveTargets`, `events:DeleteRule` | this account's `rule/sensitive-data-scanner-replay-*` and `rule/*/sensitive-data-scanner-replay-*` | only with `EventBridgeReplay`; `NoRulesButOwnReplayRules` denies every other rule |
| | `events:StartReplay`, `events:DescribeReplay` | this account's `replay/sds-*` | `NoReplaysButOwn` denies any other replay |
| | `sqs:ReceiveMessage`, `sqs:DeleteMessage` | the scanner's own queue, `sensitive-data-scanner-replay` | `NoMessageDeletesButOwnQueue` denies deletes anywhere else |
| Amazon Macie findings (#55) | `macie2:GetMacieSession`, `macie2:ListFindings`, `macie2:GetFindings` | `*` | only with `ScanMode` `vendor` or `both`; `NeverRevealOrChangeMacie` denies `macie2:GetSensitiveDataOccurrences*` (the value samples Macie can reveal), the reveal configuration and every Macie change |
| KMS aliases (1.5) | `kms:ListAliases` | `*` | The one KMS action with no `kms:ViaService`: it lists names and names no key material (`ListKmsAliases`) |
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
| OpenSearch (discovery) | `es:ListDomainNames`, `es:DescribeDomains`, `es:ListTags`, `aoss:ListCollections`, `aoss:BatchGetCollection`, `aoss:ListTagsForResource` | `*` | |
| OpenSearch domains | `es:ESHttpGet` (the read verb; `ESHttpPost`, `Put`, `Patch` and `Delete` are denied) | this account's `domain/*/*` in the region | |
| Snapshots, backups, file systems (discovery) | `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `backup:ListBackupVaults`, `backup:ListRecoveryPointsByBackupVault`, `backup:ListTags`, `elasticfilesystem:DescribeFileSystems`, `fsx:DescribeFileSystems`, `docdb-elastic:ListClusters`, `docdb-elastic:ListTagsForResource` (DocumentDB and Neptune clusters use `rds:DescribeDBClusters`, above) | `*` | |
| EBS snapshot blocks (opt-in) | `ebs:ListSnapshotBlocks`, `ebs:GetSnapshotBlock` | this region's `snapshot/*` | only with `EbsDirectRead` |
| | `kms:Decrypt` | `*` | `kms:ViaService` is `ebs.<region>` or `ec2.<region>`; only with `EbsDirectRead` |
| Streams and queues | `kinesis:ListStreams`, `kinesis:DescribeStreamSummary`, `kinesis:ListShards`, `kinesis:ListTagsForStream`, `kinesis:GetShardIterator`, `kinesis:GetRecords`, `firehose:ListDeliveryStreams`, `firehose:DescribeDeliveryStream`, `firehose:ListTagsForDeliveryStream`, `sqs:ListQueues`, `sqs:GetQueueAttributes`, `sqs:ListQueueTags` | `*` | Firehose destinations are read with the S3 statements |
| SQS dead-letter queues (opt-in) | `sqs:ReceiveMessage` | this account's queues in the region (`sqs:<region>:<account>:*`) | only with `SqsDlqRead`; the code receives from dead-letter queues only |
| | `kms:Decrypt` | `*` | `kms:ViaService` is `sqs.<region>`; only with `SqsDlqRead` |
| Parameter Store and Secrets Manager (listing) | `ssm:DescribeParameters`, `ssm:ListTagsForResource`, `secretsmanager:ListSecrets` | `*` | |
| Parameter values | `ssm:GetParameters` | this account's `parameter/*` in the region | |
| | `kms:Decrypt` | `*` | `kms:ViaService` is `ssm.<region>`; only with `SsmDecrypt` (on by default) |
| Secret values (opt-in) | `secretsmanager:GetSecretValue` | this account's `secret:*` in the region | only with `SecretsRead` |
| | `kms:Decrypt` | `*` | `kms:ViaService` is `secretsmanager.<region>`; only with `SecretsRead` |
| Caches and time series (discovery) | `elasticache:DescribeReplicationGroups`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeServerlessCaches`, `elasticache:DescribeSnapshots`, `elasticache:DescribeServerlessCacheSnapshots`, `memorydb:DescribeClusters`, `memorydb:DescribeSnapshots`, `timestream:DescribeEndpoints`, `timestream:ListDatabases`, `timestream:ListTables`, `timestream:ListTagsForResource`, `timestream-influxdb:ListDbInstances` | `*` | |
| Timestream tables | `timestream:Select` (the `Query` API) | this account's `database/*/table/*` in the region | |
| Keyspaces | `cassandra:Select` (listing, through the system keyspaces, and reading) | this account's `/keyspace/*` in the region | |
| OpenSearch Serverless (opt-in) | `aoss:APIAccessAll` | this account's `collection/*` in the region | only with `OpenSearchServerlessRead`; the collection's data access policy grants `aoss:ReadDocument` only |

And eight explicit denies, as defense in depth against any other policy the
role might gain:

| Deny | What |
|---|---|
| `NeverRevealOrChangeMacie` | (#55) Macie's occurrence samples (`GetSensitiveDataOccurrences*`) and reveal configuration, and every Macie create, update, delete, put, enable, disable, invitation and tag |
| `NoWritesOutsideOwnBucket` | S3 object and bucket writes and deletes anywhere but the results bucket |
| `NoDataStoreWrites` | DynamoDB item, table and restore writes; RDS create, delete, modify, reboot, restore, stop and export cancel; Glue catalog writes; log deletes, retention, subscription and data-protection changes; Redshift user creation (`CreateClusterUser`, so `GetClusterCredentials` can never auto-create a user), `JoinGroup`, and cluster and workgroup create, modify, delete, pause, resume, reboot and restore; `redshift-data:BatchExecuteStatement`; OpenSearch `ESHttpPost`, `ESHttpPut`, `ESHttpPatch`, `ESHttpDelete` and domain and collection create, update and delete; EBS snapshot writes (`StartSnapshot`, `PutSnapshotBlock`, `CompleteSnapshot`), snapshot and volume create, copy, modify, attach, detach and delete; Backup create, delete, put, start (restore and copy jobs) and update; EFS create, delete, put, update, `ClientWrite` and `ClientRootAccess`; FSx and DocumentDB elastic create, update and delete; Kinesis record writes, stream create, update, delete, reshard, consumer registration, encryption and retention changes; Firehose create, delete, update, put, start and stop; SQS `DeleteMessage*`, `ChangeMessageVisibility*`, `SendMessage*`, `PurgeQueue`, `SetQueueAttributes`, create, delete, and message-move tasks; SSM parameter put, delete and labels; Secrets Manager create, put, update, delete, restore, rotate, resource policies and replication; ElastiCache and MemoryDB create, delete, modify, reboot, failover and snapshot copy or export; Timestream `WriteRecords` and create, update and delete; Keyspaces `Create`, `Alter`, `Drop`, `Modify`, `Restore*` and `UpdatePartitioner`; (#35) Step Functions `Start*`, `Stop*`, `SendTask*`, `RedriveExecution`, `Publish*`, create, update, delete and tags; Lambda `Invoke*`, create, update, delete, `Put*`, `Publish*`, permissions and tags; X-Ray `Put*`, create, update, delete and tags; CodeCommit `GitPush`, `Put*`, `Merge*`, `Post*`, `Override*`, associations, create, update, delete and tags; S3 directory bucket create, delete, policy, encryption and lifecycle changes; MSK `WriteData`, `WriteDataIdempotently`, `AlterGroup`, `DeleteGroup`, topic and cluster create, alter and delete, `AlterTransactionalId`, and cluster create, update, reboot and tags; Amazon MQ create, update, delete, reboot and promote; ECR pushes, image deletes, uploads, create, delete, set, start, replicate and tags; SageMaker create, update, delete, put (feature records included), start, stop and tags; Neptune Analytics create, update, delete, reset, restore, import, export cancel, `WriteDataViaQuery`, `DeleteDataViaQuery` and tags; EventBridge archive create, update and delete, replay cancel, bus create, update and delete, and bus permissions; Glacier `InitiateJob` (retrieval), uploads, deletes, vault locks, notifications and tags |
| `NoMessageDeletesButOwnQueue` | `sqs:DeleteMessage*` anywhere but the scanner's own replay queue (every other queue's messages stay; the dead-letter reads never delete) |
| `NoRulesButOwnReplayRules` | EventBridge rule and target changes anywhere but the scanner's own `sensitive-data-scanner-replay-*` rules |
| `NoReplaysButOwn` | `events:StartReplay` of any replay not named `sds-*` |
| `NoReadWriteExpressSessions` | `s3express:CreateSession` unless `s3express:SessionMode` is `ReadOnly`: a directory bucket session that could write is never created |
| `NeverAskLakeFormation` | `lakeformation:*`: no data access, no credential vending, no grants. A governed table is read only if Lake Formation has granted the role `SELECT`; otherwise it is reported as `lake_formation` |

The **graph export role** (`NeptuneGraphExportRole`, trusted by
`neptune-graph.amazonaws.com` for this account only) can write, read and
delete under `exports/neptune-graph/` in the results bucket, list it, and use
the graph export key. The **replay queue** (`ReplayQueue`) accepts messages
only from the scanner's own replay rules.

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
