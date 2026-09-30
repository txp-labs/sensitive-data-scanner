# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a breaking change
bumps the minor version. Spec changes are listed under **Spec**.

## Unreleased

### Feature
- **Azure, step 1: the package, Blob Storage and ADLS Gen2** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  `sensitive-data-scanner-azure` (`scanner/azure`), a Container Apps job's
  image (`docker build --target azure`) that runs in the customer's tenant
  with a system-assigned managed identity (`DefaultAzureCredential`, no
  secret) ([docs/AZURE.md](docs/AZURE.md)):
  - Discovery across every subscription under a management group
    (`AZURE_MANAGEMENT_GROUP`, or `AZURE_SUBSCRIPTIONS`) with one Resource
    Graph query per kind; a storage account's containers and encryption
    scopes from Resource Manager with Reader, so a container the job cannot
    reach is still in the run summary.
  - Blob Storage and ADLS Gen2 (`azure_blob`), read with Storage Blob Data
    Reader by the core's readers: Parquet, ORC and Avro by column, gzip and
    zstd, JSON, CSV, transcripts and text; incremental, resumable within a
    listing page, sampled by name and per directory, within the run's budget.
    Archive-tier blobs (`archive_tier`) and customer-provided-key blobs
    (`kmsDenied`) are counted, never rehydrated or read.
  - `atRestEncryption` per blob from its encryption scope, its container's
    default, or the account: Microsoft-managed keys are `service_managed`,
    Key Vault and Managed HSM keys `customer_managed_key` (hash of the
    versionless key identifier only).
  - A firewall or private-only account the job cannot reach is the `network`
    gap; a missing data role is `access_denied`.
  - Findings go to the job's own state container (`findings/latest.json`),
    the core's signed HTTPS sink, Event Grid as the managed identity
    (optional), or a file. `python -m sensitive_data_azure check` lists
    without reading or sending.
- **Azure, step 2: Azure SQL, SQL Managed Instance, PostgreSQL and MySQL
  flexible servers, Synapse dedicated SQL pools** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  - Discovered by default (Resource Graph, and Resource Manager for a flexible
    server's databases and a SQL server's TDE protector); paused databases,
    pools and stopped servers are `paused`; system databases are not stores.
  - Read when opted in (`AZURE_DB_READ`) as the managed identity with an Entra
    token: `mssql-python` for SQL (`ApplicationIntent=ReadOnly`, encrypted,
    certificate verified), psycopg and PyMySQL with the token as the password
    over verified TLS (`AZURE_DB_PRINCIPAL`). The customer creates the
    identity's read-only user; docs/AZURE.md has the T-SQL and SQL.
  - The core's user check first (`db_user_can_write` with `writeGrants`,
    `grants_unverifiable`), then the core's sampled pass (`scan/sql.py`) in a
    read-only transaction, resumable by table.
  - `network` for a database the job cannot reach, `access_denied` for a
    refused login, `no_read_path` for PostgreSQL with Entra authentication
    off, `driver_missing`.
  - `atRestEncryption` from the TDE protector, a flexible server's
    `dataEncryption`, or a Synapse workspace's key.
- **Azure, step 3: Cosmos DB, Table Storage and Queue Storage** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  - Cosmos DB for NoSQL (`cosmosdb`), read by default: containers listed from
    Resource Manager, then one `SELECT TOP @n * FROM c` per container as the
    identity, with the Cosmos DB Built-in Data Reader role (a per-account
    Cosmos role assignment; docs/AZURE.md has the command). RU accounts on
    the MongoDB, Cassandra, Gremlin or Table API are `no_read_path` with their
    `api`: only the account's keys read them, and those can write.
  - Cosmos DB for MongoDB vCore (`cosmosdb_mongo`), opt-in with
    `AZURE_DB_READ`: MONGODB-OIDC as the identity, the core's MongoDB user
    check first, then `$sample` per collection (the databases runner's
    session).
  - Table Storage (`azure_table`): the first `TABLE_MAX_ENTITIES` entities
    per table, by property, with Storage Table Data Reader. Queue Storage
    (`azure_queue`): **peek only**, up to 32 messages, never dequeued, with
    Storage Queue Data Reader; base64 messages decoded when they are text.
- **Azure, step 4: Azure Monitor logs** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  every Log Analytics workspace (`log_analytics`), read by default with Log
  Analytics Reader: `Usage` picks the tables with data in the window
  (`LOGS_LOOKBACK_DAYS`), each sampled with one quoted `take n` query
  (`LOGS_MAX_ROWS_PER_TABLE`) and read by column (format `kql`); Basic and
  Auxiliary tables, billed per query, are counted as `billed_plan` and not
  read; a workspace resumes at its next table.
- **Databases hosted anywhere** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 3):
  `sensitive-data-scanner-db` (`scanner/db`), a container you run in your
  own network, with its own image target (`docker build --target db`):
  - Engines: PostgreSQL, MySQL and MariaDB, SQL Server (and Azure SQL),
    Oracle (thin mode), MongoDB (including Atlas), Snowflake and Databricks
    SQL (Unity Catalog). SQL engines use the core's sampled pass
    (`scan/sql.py`, which gains the SQL Server, Oracle, Snowflake and
    Databricks dialects); MongoDB is read with `$sample` per collection.
  - Connection strings come from `DATABASE_URL_<NAME>`,
    `DATABASE_URL_FILE_<NAME>` or a mounted `DATABASE_URLS_DIR`, are held so
    no repr shows them, and are never logged; a wrong setting is reported by
    a fixed code.
  - **The user is checked before anything is read**: from each engine's
    catalog, against an allow list of read privileges, including every role
    granted to a MySQL or MariaDB user, active or not, and Snowflake's role
    hierarchy. A user that can write is refused as `db_user_can_write`, with
    its write privileges by name (`writeGrants`); one whose privileges cannot
    be read is `grants_unverifiable`. Sessions and transactions are read-only
    where the engine has them, and always rolled back. This settles the open
    question of MySQL's read-only access for this runner.
  - Findings go to the core's sink interface: an HTTPS endpoint with an
    HMAC-SHA256 signature over a timestamp and the body, an EventBridge bus
    (the `aws` extra), or a file.
  - Drivers are optional extras per engine (`[postgresql]`, `[mysql]`, ...,
    `[all]`); the image takes `DB_EXTRAS` for a slimmer build, and a missing
    driver is a coverage gap (`driver_missing`).
  - `python -m sensitive_data_db check` connects and checks every user
    without reading or sending anything.
- The core's findings take per-store facts (`finding_json(..., facts=)`),
  added to each finding and never replacing a field: the hook for recording
  at-rest encryption ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35)).
- **At-rest encryption on every finding** ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35)): each finding
  says what storage encryption its data sat under, from the store's own
  configuration: `atRestEncryption` is `none`, `service_managed`,
  `customer_managed_key` or `unknown`, and a customer managed key is named
  only by `atRestKeyHash`, the SHA-256 of its key id (never the id, the ARN
  or an alias). Every existing AWS adapter fills it: an S3 object from its
  own `x-amz-server-side-encryption` header (the bucket's default is in the
  run summary), CloudWatch Logs, DynamoDB (and its exports), RDS and Aurora
  (export and Data API), Redshift and Serverless, OpenSearch domains and
  collections, EBS, Kinesis, SQS, Parameter Store (per parameter), Secrets
  Manager (per secret), Timestream and Keyspaces; Firehose destinations and
  Glue tables through their S3 objects. AWS managed keys are told from the
  customer's by one `kms:ListAliases` per run. The databases runner fills it
  where the engine can tell: SQL Server's TDE and its encryptor, MySQL and
  MariaDB tables all created encrypted, Snowflake and Atlas; anything else is
  `unknown`, since TDE off does not mean the disk is unencrypted.
- **PCI DSS notes** ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35)): `pciNote` on every `cvv` finding
  (3.3.1, prohibited storage after authorization, whatever the encryption)
  and on every `card` finding under storage-level encryption (3.5.1.2,
  storage-level encryption alone does not render PAN unreadable), worded as
  guidance for the customer's QSA, who decides.

- **More AWS stores, read by default** ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35), step 2):
  - **Step Functions** (`stepfunctions`): the most recent executions of each
    Standard state machine (`STEPFUNCTIONS_EXECUTIONS`, 20) and their history
    with its data (`STEPFUNCTIONS_EVENTS`, 500 events), every event's input,
    output, parameters, result, error and cause. Express state machines keep no
    history in the service and are reported `unsupported` (`workflowType`).
  - **Lambda environment variables** (`lambda`): `GetFunctionConfiguration`
    per function, each variable read with its name as context and reported as
    counts only, like a secret. A variable under a key the scanner may not use
    is counted unreadable; the scanner's own function is `self`.
  - **X-Ray** (`xray`): sampled trace summaries since the last run
    (`XRAY_LOOKBACK_HOURS`, 24), then `BatchGetTraces` up to `XRAY_MAX_TRACES`
    (100): every segment's and subsegment's annotations and metadata.
  - **CodeCommit** (`codecommit`): a stable, hash-spread sample of the default
    branch's files at its head (`CODECOMMIT_MAX_FILES`, 200, over at most
    `CODECOMMIT_MAX_FOLDERS`, 500), read once per head.
  - **S3 directory buckets** (`s3express` in `DISCOVER`, kind `s3_directory`):
    read by the S3 source through S3 Express sessions that are always
    read-only (`SessionMode=ReadOnly`, set on every `CreateSession` botocore
    makes), resuming by continuation token, since a directory bucket lists in
    no key order.

- **MSK and Amazon MQ, opt-in** ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35), step 3):
  - **MSK** (`msk`, `MSK_READ`): provisioned and Serverless clusters with
    IAM authentication, sampled per partition from the earliest offset
    (`MSK_RECORDS_PER_PARTITION`, 100; `MSK_MAX_TOPICS`, 50;
    `MSK_MAX_PARTITIONS`, 50) by a consumer under a throwaway group id that
    never joins or commits. A cluster without IAM authentication is
    `no_read_path`; one out of reach is `vpc_only`. `kafka-python` is a new
    dependency of the image and the zip (about 5 MB).
  - **Amazon MQ** (`mq`, `MQ_READ`, `MQ_BROKERS`): ActiveMQ queues named per
    broker are browsed over STOMP (`browser:true`), never consumed or acked,
    up to `MQ_MESSAGES_PER_QUEUE` (100). The broker user, from a Secrets
    Manager secret, is checked first and refused as `user_can_write` (new
    reason) when it has console access, when the broker has no authorization
    map, or when its groups may write to or administer queues. RabbitMQ has no
    safe peek and is reported `no_read_path`.

- **ECR, SageMaker, Neptune Analytics, EventBridge archives and Glacier** ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35), step 4):
  - **ECR** (`ecr`, opt-in `ECR_READ`): files sampled from each repository's
    latest image's top layers (`ECR_MAX_LAYERS`, 5; `ECR_MAX_LAYER_BYTES`,
    256 MiB; `ECR_MAX_FILES_PER_LAYER`, 200), streamed from the layer URL ECR
    signs, gzip or plain tar, the operating system's own directories left
    out. An image is read once per push.
  - **SageMaker** (`sagemaker`, opt-in `SAGEMAKER_READ`): each feature group's
    offline store read as S3. Online-only groups (no API lists their records)
    and notebook instances (their volume is in SageMaker's own account) are
    `no_read_path`.
  - **Neptune Analytics** (`neptune-analytics`): graphs read by an export to
    CSV in the results bucket, with its own role and key
    (`NEPTUNE_ANALYTICS_EXPORT_ROLE_ARN`, `NEPTUNE_ANALYTICS_EXPORT_KMS_KEY_ARN`;
    the template's `NeptuneAnalyticsExportKmsKeyArn`), within the export quota,
    read by column and deleted; `export_not_configured` without them.
  - **EventBridge archives** (`eventbridge`): reported with `sizeBytes`,
    `eventCount` and `retentionDays`. Opt-in (`EVENTBRIDGE_REPLAY`): a replay of
    the last day to a rule of the scanner's own on the archive's bus, sent
    only to that rule (`FilterArns`) and on to the scanner's own queue
    (created by the template), read and emptied, then the rule removed.
  - **S3 Glacier vaults** (`glacier`): reported as `archive_retrieval` (new
    reason) with their archives (`archives`) and size; no retrieval job is
    ever started.

- **The databases runner keeps state, optionally** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21)):
  `STATE_LOCATION` (a local path, `s3://bucket/key`, or an HTTPS URL written
  with a signed PUT) keeps which database the next run starts with, so the
  databases a run's budget does not reach go first next time. It holds only
  a database's name. Without it, runs sample afresh as before.
- **Releases publish the databases runner** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21)): the
  `ghcr.io/txp-labs/sensitive-data-scanner-databases:X.Y.Z` image (every
  engine), its SBOM, and the `sensitive_data_scanner_db` wheel, from a job of
  their own, with `SHA256SUMS` naming every file as GitHub serves it.

### Changed
- **The RDS Data API mode refuses a user that can write** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21)):
  the opt-in `RDS_DATA_API` read now runs the databases runner's own user
  check (moved to the core as `sensitive_data_core.grants`) before listing a
  table, and refuses a MySQL or PostgreSQL user that can write as
  `db_user_can_write` (with `writeGrants`), or one whose privileges cannot be
  read as `grants_unverifiable`. **This is intended:** a Data API target whose
  secret belongs to a user with more than reads, which used to be read, is
  now refused, and nothing is read from it. On PostgreSQL before 15, where
  PUBLIC may create in `public`, run `REVOKE CREATE ON SCHEMA public FROM
  PUBLIC;` once. The mode is off by default.
- The PostgreSQL check (both runners) names PUBLIC's `CREATE` on `public`
  apart (`public_schema_create`), and stays strict before PostgreSQL 15; the
  docs show the one-line `REVOKE`.

### Security
- Step 4's IAM: listing for ECR, SageMaker, Neptune Analytics, EventBridge
  archives and Glacier; opt-in ECR pulls (`BatchGetImage`,
  `GetDownloadUrlForLayer`); the graph export (`StartExportTask` on graphs,
  its own role, `kms:Decrypt` through S3); and for replays, rule changes only on
  `sensitive-data-scanner-replay-*`, replays only named `sds-*`, and message
  deletes only on the scanner's own queue, each with a Deny for everything
  else. `sqs:DeleteMessage*` moves from `NoDataStoreWrites` into its own Deny
  on every queue but the scanner's. Every write of the new services is denied,
  including Glacier `InitiateJob` and Neptune Analytics' writing queries.
- The brokers' reads (step 3) are opt-in statements: `kafka:GetBootstrapBrokers`,
  `kafka-cluster:Connect`, `DescribeCluster`, `DescribeTopic`, `ReadData`, and
  `DescribeGroup` on the scanner's own throwaway groups only; `mq:DescribeUser`,
  `mq:DescribeConfigurationRevision` and the named broker-user secrets. Listing
  (`kafka:ListClustersV2`, `mq:ListBrokers`, `mq:DescribeBroker`) is always on.
  Denied: every MSK data and group write (`WriteData*`, `AlterGroup`,
  `DeleteGroup`, topic and cluster changes) and every MSK and MQ control-plane
  change.
- Group 7's reads (step 2) are one statement of read actions
  (`ReadWorkflowsFunctionsTracesAndCode`), `s3express:ListAllMyDirectoryBuckets`,
  and `s3express:CreateSession` allowed only with `s3express:SessionMode`
  `ReadOnly`, with a matching Deny for any other mode. Every write is denied:
  Step Functions start, stop, redrive, send-task and changes; Lambda invoke,
  create, update, publish, permissions and tags; X-Ray puts and changes;
  CodeCommit pushes, merges, comments and changes; directory bucket create,
  delete and policy or encryption changes. `kms:Decrypt` through S3 and
  DynamoDB (`AllowKmsDecrypt`) now also covers Step Functions, Lambda, X-Ray
  and CodeCommit.
- The scanner's role gains three read actions, each for the encryption
  facts: `s3:GetEncryptionConfiguration` (a bucket's default),
  `kinesis:DescribeStreamSummary` (a stream's `EncryptionType`) and
  `kms:ListAliases` (which keys are AWS managed; metadata only, the one KMS
  action not conditioned on `kms:ViaService`, and the template test holds it
  to that). Keyspaces' `GetTable` is the `cassandra:Select` it already had.

### Findings schema
- `schemaVersion` is now **1.6**, additive: the Azure scanner's
  `platform: azure`, the `blob_object` resource, `subscription`,
  `resourceGroup` and `resourceIdHash` (the SHA-256 of the lower-cased
  resource ID) on Azure findings and stores, the `azure_blob`, `azure_sql`,
  `azure_sql_mi`, `azure_postgresql`, `azure_mysql`, `synapse_sql`,
  `cosmosdb`, `cosmosdb_mongo`, `azure_table`, `azure_queue` and
  `log_analytics` kinds, the `kql` format and the `billed_plan` skip kind, the
  store field `api`, the `network` reason, `hierarchicalNamespace`, `networkRestricted`, the
  `archive_tier` skip kind and Azure portal links.
- Version **1.5**, additive: `atRestEncryption`,
  `atRestKeyHash` and `pciNote` on a finding, and `atRestEncryption` and
  `atRestKeyHash` on a store in the run summary.
- Version **1.4**, additive: `platform` and `site` (a
  databases document names its site in place of an AWS account and
  region), the `postgresql`, `mysql`, `sqlserver`, `oracle`, `mongodb`,
  `snowflake` and `databricks` kinds, the reasons `db_user_can_write`,
  `grants_unverifiable` and `driver_missing`, and the store field
  `writeGrants`.

### Docs
- `docs/AZURE.md`: the Azure scanner, its stores and roles, findings and
  settings.
- `docs/DATABASES.md`: the engines and how each is kept read-only, settings,
  a read-only user per engine, verifying a signed push, and deployment with
  docker run, a Kubernetes CronJob, an ECS task and Azure Container
  Instances, with the image sizes. `docs/ARCHITECTURE.md`: the design for
  hosting the EFS and FSx file-system task in the same image.

### Internal
- The core gains the object reader every blob store shares
  (`sensitive_data_core.scan.objects`: sampling by name, compression, ranged
  reads of table files, `read_object`), which the AWS S3 source's helpers now
  come from, and the signed HTTPS sink (`push.HttpsSink`, with `sign` and
  `verify`) and `safety.Secret`, which the databases runner re-exports. No
  change in behavior. `safety.error_name` also reads Azure's `error_code`.
- The databases runner's user checks move to the core
  (`sensitive_data_core.grants`), so the AWS scanner's RDS Data API mode
  shares them; `sensitive_data_db.grants` still imports as before.
- CI runs the databases runner's PostgreSQL 16 and MySQL 8.4 tests in Docker
  (testcontainers, images pinned by digest; `SDS_REQUIRE_DOCKER=1`, so a
  missing Docker fails rather than skips), builds the `db` image with every
  engine and with PostgreSQL and MySQL only, and smoke-tests both with no
  network. The no-leak suite covers the runner, with values in cells and in
  schema, table, column, collection and field names, a password and a host.
- The Python runner is two packages in one uv workspace
  ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 2), with no change in
  behavior:
  - **the cloud-neutral core**, `sensitive-data-scanner-core` (`scanner/core/`,
    import `sensitive_data_core`): the spec engine and Presidio detection,
    the findings contract, budgets and sampling, the allow, deny and sampling
    rules, the coverage summary, the findings push interface
    (`push.FindingsSink`), the sampled SQL pass (`scan/sql.py`), the readers,
    the no-values rule (`safety`) and the `Adapter` interface, now generic in
    the context each platform gives its adapters. It depends on no cloud SDK,
    and a test fails if it imports one;
  - **the AWS scanner**, `sensitive-data-scanner` (`scanner/src/`, import
    `sensitive_data_scanner`): every boto3 adapter, discovery, the runner, the
    Lambda handler, EventBridge as the findings sink (`events.EventBridgeSink`),
    and the AWS resources and console links (`resources.py`).
  - The Lambda handler (`sensitive_data_scanner.handler.handler`), every
    setting's name, the findings document and `deploy/` are unchanged. The
    Lambda zip and the container image carry both packages.
  - **For Python callers:** the detection modules moved with the core, so
    `sensitive_data_scanner.detect`, `.engine`, `.scan`, `.safety` and
    `.findings` are now `sensitive_data_core.detect`, and so on.
  - Releases attach the core's wheel beside the scanner's; the release's
    version check covers every package in the workspace. The no-leak suite's
    source audit reads every package.

## 0.3.0 — 2026-09-29

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
- Snapshots, backups and file systems ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5):
  - EBS (`DISCOVER` kind `ebs`): volumes and this account's snapshots; each
    volume read through its latest snapshot with the EBS direct APIs
    (`EBS_DIRECT_READ`, opt-in; `EBS_BLOCKS_PER_SNAPSHOT`), sampled blocks'
    printable text, no volume created or attached. Volumes with no snapshot,
    archived snapshots and older snapshots are reported.
  - AWS Backup (`backup`): vaults with their recovery points by type, reported
    as `backup_copy` (EBS points are read as EBS snapshots).
  - DocumentDB (including elastic clusters) and Neptune (`documentdb`,
    `neptune`): reported as `no_snapshot_export`.
  - EFS and FSx (`efs`, `fsx`): reported as `needs_task`; the opt-in Fargate
    file-system task is designed in docs/ARCHITECTURE.md, not built.
- Streams and queues ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5):
  - Kinesis Data Streams (`kinesis`): each shard sampled from `TRIM_HORIZON`
    (`KINESIS_RECORDS_PER_SHARD`, `KINESIS_MAX_SHARDS`), never checkpointed:
    no lease, no sequence number kept.
  - Firehose (`firehose`): every S3 location a delivery stream writes to
    (destination, error output, backup) is read by the S3 source, once; the
    bucket's own source leaves those prefixes to it.
  - SQS (`sqs`): dead-letter queues only, opt-in (`SQS_DLQ_READ`), received
    with `VisibilityTimeout=0` and never deleted; a DLQ with its own redrive
    policy is never read (`redrive_would_change`), and live queues never
    (`live_queue`).
- Parameter Store and Secrets Manager ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5):
  one store each per account and region, with the allow and deny rules
  applied to each parameter or secret by name or tag. Parameter values are
  read ten at a time, `SecureString` decrypted through SSM (`SSM_DECRYPT`, on
  by default). Secrets are always listed, and read only with `SECRETS_READ`
  (off by default); sensitive data in a secret is a finding, and the secret
  is never reported.
- Other stores ([#14](https://github.com/txp-labs/sensitive-data-scanner/issues/14), step 5):
  - Timestream for LiveAnalytics (`timestream`): one sampled read-only query
    per table (`TIMESTREAM_MAX_ROWS`, `TIMESTREAM_LOOKBACK_DAYS`), by column;
    InfluxDB instances reported (`no_read_path`).
  - Keyspaces (`keyspaces`): one sampled CQL query per table over TLS, signed
    with the role (`cassandra-driver` and `cassandra-sigv4`, new
    dependencies; `KEYSPACES_MAX_ROWS`), by column.
  - ElastiCache and MemoryDB (`elasticache`, `memorydb`): reported as
    `in_memory` with their snapshots counted; an exported snapshot in S3 (an
    `.rdb` file) is read by the S3 source as its text runs (format `rdb`).
- The run summary's coverage table by store (docs/ARCHITECTURE.md): what is
  scanned, what is opt-in, what is coverage only, and why.
- The adapter interface (`sources/base.py`, `Adapter`) and the generic
  sampled SQL pass (`scan/sql.py`): every new kind of store plugs into
  discovery, the budget and the run summary through them, with no cloud in
  the core. The RDS Data API mode now runs on the same SQL pass.
- Findings schema **1.3** (additive): the `store_field` resource, the
  `redshift`, `opensearch`, `ebs`, `backup`, `documentdb`, `neptune`, `efs`,
  `fsx`, `kinesis`, `firehose`, `sqs`, `ssm`, `secretsmanager`,
  `elasticache`, `memorydb`, `timestream` and `keyspaces` kinds, the `block`,
  `cql` and `rdb` formats, the store reasons `read_not_configured`, `paused`, `no_grant`, `vpc_only`,
  `no_snapshot_export`, `needs_task`, `backup_copy`, `archived`,
  `live_queue`, `redrive_would_change`, `no_s3_destination`, `in_memory` and
  `no_read_path`, and the store
  fields `deployment`, `database`, `state`, `resource`, `olderSnapshots`,
  `recoveryPoints`, `fileSystemType`, `destinations`, `deadLetterQueue`,
  `approximateMessages`, `items`, `itemTypes`, `excluded` and `snapshots`.
- `deploy/scanner.yaml`: `RedshiftRead` and `RedshiftDbUser`; Redshift
  describe permissions, and, only when reading, the Data API on this
  account's clusters and workgroups, its own statements only, and the
  credential call for the mode chosen. User creation, `JoinGroup` and
  batch statements are denied. OpenSearch: describe and list,
  `es:ESHttpGet` on this account's domains (every other HTTP verb denied),
  and, only with `OpenSearchServerlessRead`, `aoss:APIAccessAll` on its
  collections. Snapshots, backups and file systems: describe and list, and,
  only with `EbsDirectRead`, `ebs:ListSnapshotBlocks`/`GetSnapshotBlock` on
  this region's snapshots and `kms:Decrypt` through EBS; every snapshot,
  volume, backup and file-system write is denied. Streams and queues: list,
  describe and Kinesis `GetShardIterator`/`GetRecords`; `kms:Decrypt` through
  Kinesis; only with `SqsDlqRead`, `sqs:ReceiveMessage` and `kms:Decrypt`
  through SQS; message deletes, visibility changes, sends, purges and every
  stream and queue write are denied. Parameter Store and Secrets Manager:
  list; `ssm:GetParameters` on this account's parameters and, with
  `SsmDecrypt`, `kms:Decrypt` through SSM; only with `SecretsRead`,
  `secretsmanager:GetSecretValue` on this account's secrets and
  `kms:Decrypt` through Secrets Manager; parameter and secret writes denied.
  Caches and time series: describe and list; `timestream:Select` on this
  account's tables and `cassandra:Select` on its keyspaces; cache, snapshot
  copy and export, Timestream and Keyspaces writes denied.
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

### Fixed
From the first run in a real account (stugum-dev,
[#24](https://github.com/txp-labs/sensitive-data-scanner/issues/24)):
- **A missing state file on the first run.** Without `s3:ListBucket`, S3
  answers a missing object with 403, not 404, and the first run failed.
  - The runner now counts a 403 on the state file as "no state yet" when the
    lock it has just written can be read. A KMS denial, or a denial that also
    covers the lock, still fails the run.
  - `docs/ARCHITECTURE.md` now lists `s3:ListBucket` on the results bucket
    (on the results prefix, if there is one). `scanner.yaml` already
    granted it; `test_template.py` now keeps it there.
- **Configuration beyond Lambda's 4 KB of environment variables.** The
  settings can also come from a JSON document: the invoke payload's
  `config`, or a file named by `CONFIG_LOCATION` (or the payload's
  `configLocation`), either an S3 object or an SSM parameter.
  - The document uses the variable names. The payload wins over the file,
    and the file over the environment.
  - A name the scanner does not read is an error.
  - Environment variables alone work as before.
  - `scanner.yaml` takes `ConfigLocation`, with `ssm:GetParameter` only
    under `/sensitive-data-scanner/`.
- **Console links on findings with a masked key.** A finding now loses its
  link only when a name the link carries was masked.
  - A DynamoDB item keyed by a tenant id with a bare nine-digit run keeps
    its link to the table. The link names the table, never the key.
  - The same holds for a masked column (S3 table objects, RDS, Redshift) or
    index (OpenSearch).
  - The no-leak suite covers a `T#t_…` key.
- **`SHA256SUMS` names every asset as GitHub serves it.** buildx's
  `owner~repo~id.dockerbuild` record is served as
  `owner.repo.id.dockerbuild`, so `sha256sum -c` reported it missing. The
  release workflow renames such files before checksumming, then checks the
  published names against the list.

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
- `packages/spec-ts/dist/` is committed, so the package can be consumed by
  git commit (package managers do not build git dependencies). A CI job
  rebuilds it and fails if it differs. `exports` still points at `dist/`.

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
