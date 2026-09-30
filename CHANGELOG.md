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
- **Azure, step 5: disk snapshots and Key Vault** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  - Managed disk snapshots (`azure_disk_snapshot`), coverage only: grouped by
    disk, with the latest snapshot's time, size, older count and encryption
    (a disk encryption set's key hashed). Reading needs a SAS export, which
    changes the snapshot, so each is `needs_sas_export`; the opt-in export
    reader is designed in docs/AZURE.md and not built.
  - Key Vault secrets (`key_vault`), **off by default**
    (`read_not_configured`): with `KEYVAULT_SECRETS_READ=on` and Key Vault
    Secrets User, each enabled secret's current value is read and reported
    as counts only, like Secrets Manager; disabled, expired and certificate
    secrets are counted, not read.
- **Azure, step 6: deployment and release** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 4):
  `deploy/azure/main.bicep`, at a management group, deploys the scheduled
  Container Apps job with a system-assigned identity, centrally (one job,
  roles at the management group) or per subscription (a job per
  subscription, roles at each), with its own state storage (no shared keys).
  It assigns Reader and the Storage Blob, Table and Queue Data Readers; Key
  Vault Secrets User only with `readKeyVaultSecrets`; Cosmos DB Built-in Data
  Reader on the accounts named; and Storage Blob Data Contributor on the
  job's own container only. `deploy/azure/main.json` is it compiled.
  Releases publish `ghcr.io/txp-labs/sensitive-data-scanner-azure:X.Y.Z`
  (with its SBOM and `AZURE_IMAGE_DIGEST`), the Azure wheel and the compiled
  template.
- **Google Cloud, step 1: the package and Cloud Storage** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5):
  `sensitive-data-scanner-gcp` (`scanner/gcp`), a Cloud Run job's image
  (`docker build --target gcp`) that runs in the customer's organization as
  its own service account (Application Default Credentials, no key)
  ([docs/GCP.md](docs/GCP.md)):
  - Every Google API over REST through google-auth's authorized session: no
    gRPC stack in the image.
  - Discovery across every project under an organization
    (`GCP_ORGANIZATION`), folders (`GCP_FOLDERS`) or projects
    (`GCP_PROJECTS`) with Cloud Asset Inventory's `searchAllResources`, one
    paged search per kind; project numbers resolved to ids.
  - Cloud Storage (`gcs`), read by the core's readers through the JSON API:
    Parquet, ORC and Avro by column, gzip and zstd, JSON, CSV, transcripts
    and text; incremental, resumable within a listing page, sampled by name
    and per directory, within the run's budget. Objects under a
    customer-supplied key (CSEK) are counted in `kmsDenied`, never read.
  - `atRestEncryption` per object: its Cloud KMS key (CMEK) is
    `customer_managed_key`, hashed from the key's versionless resource name;
    otherwise `service_managed`.
  - A VPC Service Controls perimeter that keeps the job out is the `network`
    gap; a requester-pays bucket is `requester_pays` (new reason); a missing
    permission is `access_denied`.
  - Findings go to the job's own state bucket (`findings/latest.json`; the
    lock is created only if absent), the core's signed HTTPS sink, Pub/Sub
    as the service account (optional), or a file.
    `python -m sensitive_data_gcp check` lists without reading or sending.
- **Google Cloud, step 2: BigQuery** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5):
  every table of every dataset (`bigquery`, `project.dataset.table`), read by
  default with `tabledata.list`: the first `BIGQUERY_MAX_ROWS` rows, by column,
  with no query and no bytes billed (preferred over `TABLESAMPLE`, which bills
  bytes and needs `bigquery.jobs.create`); a table unchanged since its last
  read is not read again. Never escalating: views are never read
  (`unsupported` with `tableType`), authorized views are `authorized_view`
  (new reason), tables with row-level access policies are `row_level_policy`
  (new reason), policy-tagged columns are left out (`protectedColumns`), and
  external tables are `unsupported`. `atRestEncryption` from the table's or
  its dataset's Cloud KMS key.
- **Google Cloud, step 3: Cloud SQL and AlloyDB** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5):
  - Discovered by default: Cloud SQL for PostgreSQL, MySQL and SQL Server
    (`cloudsql_postgresql`, `cloudsql_mysql`, `cloudsql_sqlserver`, one store
    per `instance/database`) and AlloyDB clusters (`alloydb`), from Cloud Asset
    Inventory and the Cloud SQL Admin and AlloyDB APIs; stopped instances are
    `paused`; system databases are not stores.
  - Read when opted in (`GCP_DB_READ`, `GCP_DB_PRINCIPAL`) as the service
    account with IAM database authentication: its access token as the
    password over TLS verified against the instance's own CA, never a
    password. The databases runner's `SqlSession`, the core's user check
    first (`db_user_can_write`, `grants_unverifiable`), then the core's
    sampled pass (`scan/sql.py`) in a read-only transaction. AlloyDB is read
    through a read pool when there is one, its databases listed by SQL.
  - `network` for an instance out of reach, `access_denied` for a refused
    login, `no_read_path` for SQL Server (no IAM authentication) and for an
    instance with the IAM flag off, `driver_missing`. `atRestEncryption` from
    the instance's or cluster's Cloud KMS key.
- **Google Cloud, step 4: Firestore and Datastore, Spanner, Bigtable** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5),
  each read by default with its viewer or reader role:
  - Firestore in Native mode (`firestore`): root collections, the first
    `DOCUMENTS_MAX_PER_COLLECTION` documents of each with one `runQuery`, by
    field; Datastore mode (`datastore`): the default namespace's kinds (a
    `__kind__` query), then entities per kind. Resumable by collection.
  - Spanner (`spanner`): the core's sampled SQL pass through `executeSql`,
    every statement in a single-use read-only transaction; GoogleSQL and
    PostgreSQL dialects. The core gains the Spanner dialects and names a
    table in an unnamed default schema alone.
  - Bigtable (`bigtable`): one `readRows` per table (`BIGTABLE_MAX_ROWS`,
    latest cell per column), by `family:qualifier`, the row key read too.
  - `atRestEncryption` from each database's (or Bigtable cluster's) Cloud
    KMS key.
- **Google Cloud, step 5: Cloud Logging, Pub/Sub, disk snapshots, Secret Manager** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5):
  - Cloud Logging (`cloud_logging`, one store per project), read by default
    with Logs Viewer: one `entries.list` per log (`LOGGING_LOOKBACK_DAYS`,
    `LOGGING_MAX_ENTRIES_PER_LOG`, `LOGGING_MAX_LOGS`), the log's name quoted
    in the filter, read by column. Data Access audit logs need Private Logs
    Viewer and are opt-in (`LOGGING_PRIVATE_READ`); otherwise skipped
    `private_log` (new skip kind). The read quota stops a pass, which resumes
    at that log.
  - Pub/Sub topics (`pubsub`), coverage only: dead-letter topics are
    `needs_subscription` (new reason; reading needs a subscription, a write),
    other topics `live_queue`. The opt-in dead-letter reader (a subscription
    the deployment creates, pulled only by the scanner) is designed in
    docs/GCP.md, not built.
  - Persistent disk snapshots (`gce_snapshot`), coverage only, grouped by
    disk: `needs_disk_restore` (new reason; reading needs a disk made from the
    snapshot, a write).
  - Secret Manager (`secret_manager`), **off by default**
    (`read_not_configured`): with `SECRET_MANAGER_READ=on`, each secret's
    latest version is read and reported as counts only.
- **Google Cloud, step 6: deployment and release** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 5):
  `deploy/gcp`, a Terraform module at an organization (or its folders, or
  projects): the scanner's service account (no key), read-only custom roles
  bound at the scope, a Cloud Run job (one task, no retries) that runs as it,
  a Cloud Scheduler job whose own account may only start the job, the job's
  own state bucket (uniform access, public access prevention), the push's URL
  and key in Secret Manager secrets of its own, optional Direct VPC egress,
  and the APIs it calls. Opt-ins (`read_databases`, `read_private_logs`,
  `read_secrets`) each add their own role. Releases publish
  `ghcr.io/txp-labs/sensitive-data-scanner-gcp:X.Y.Z` (with its SBOM and
  `GCP_IMAGE_DIGEST`), the Google Cloud wheel and the module
  (`sensitive-data-scanner-gcp-terraform.tar.gz`).
- **Azure Files shares** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21)):
  every share is discovered (`azure_files`, `account/share`, FileStorage
  accounts included) and reported; reading is **opt-in**
  (`AZURE_FILES_READ=on`, the Bicep parameter `readFileShares`): the File
  service's REST API with an Entra token and the backup intent, as the
  identity with Storage File Data Privileged Reader, whose data actions both
  read (it reads past a file's NTFS ACL, hence opt-in). Files are listed
  directory by directory and read like blobs, incremental and resumable in
  path order. An NFS share is `no_read_path`; a firewall is `network`.
  `azure-storage-file-share` joins the Azure package.
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

- **SaaS, step 1: the package and Microsoft 365** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  `sensitive-data-scanner-saas` (`scanner/saas`), a container the customer
  runs in its own environment (`docker build --target saas`) with read-only
  grants to its tenants; only findings reach Mermera, whose servers never read
  SaaS content ([docs/SAAS.md](docs/SAAS.md)):
  - Exchange Online mail (`m365_mail`), with Graph's `Mail.Read` limited by
    Exchange (RBAC for Applications, or an application access policy) and
    **proved limited before any mail is read**: a mailbox outside the scope
    (`M365_MAIL_SCOPE_CHECK`) must be refused, else every mailbox is
    `unscoped_grant` (or `scope_unverified` without the check). Subjects,
    bodies as text and file attachments are read; attached items and links
    are `linked_item`, oversized attachments `too_large`.
  - SharePoint (`m365_sharepoint`, `Sites.Selected` with a per-site `read`
    grant, or `Files.Read.All`) and OneDrive (`m365_onedrive`), each drive read
    from its delta query with ranged content GETs by the core's readers;
    rights-managed Office files are `encrypted`.
  - Teams channel messages and replies (`m365_teams_channel`) and chats
    (`m365_teams_chat`), opt-in: protected APIs Microsoft must approve, so a
    `protected_api` gap until it has.
  - Sign-in with a certificate (a `PS256` client assertion) or a federated
    workload identity (a projected token file, AWS `sts:GetWebIdentityToken`,
    the GCP metadata server, or an Azure managed identity); a client secret
    only from a mounted file, never the environment. Tokens go to Graph only.
  - Delta queries for incremental runs, resumable mid-page, with the cursors
    and carried findings at `STATE_LOCATION` (the core's new state location:
    a mounted path, S3 or signed HTTPS). Per mailbox, drive and channel caps,
    stable sampling by item id, and Graph's `Retry-After` honored (a wait past
    `MAX_THROTTLE_WAIT_SECONDS` or the run's end defers the store as
    `throttled`).
  - People are named only by the SHA-256 of their principal name
    (`ownerHash`); tenants by `tenantHash`; site, library, team, channel,
    file and attachment names masked like keys; links into Outlook on the
    web, SharePoint and Teams built from ids only. `M365_CUSTOMER_KEY_ID`
    (Microsoft Purview Customer Key) makes findings `customer_managed_key`,
    hashed; otherwise `service_managed`.
- **SaaS, step 2: Google Workspace** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  Gmail (`gws_gmail`), My Drive (`gws_drive`) and shared drives
  (`gws_shared_drive`), read through domain-wide delegation to a service
  account for read-only scopes only (`gmail.readonly`, `drive.readonly`, and
  the directory's `user.readonly` and `group.member.readonly` to list the
  people in `GWS_USERS`, `GWS_GROUPS` and `GWS_ORG_UNITS`):
  - The delegation's JWTs are signed keylessly where possible: IAM
    Credentials' `signJwt` with the Cloud Run job's own token, or with a
    workload identity federated through Google's STS (a token file, AWS or
    Azure); a service account key file is the fallback.
  - Gmail: the first run lists the lookback window, later runs read only the
    history since; subjects, text (or HTML's text) and attachments.
  - Drive: files listed, then only changes; Google Docs, Sheets and Slides
    exported as text or CSV; ranged media reads; each file read in its
    owner's store; shared drives read as a member administrator.
  - Every Gmail and Drive call is to `users/me`: no address in a URL, a
    cursor or a log. Links to Drive files by id; Gmail has none.
- **SaaS, step 3: Slack** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  channels (`slack_channel`), with their threads, legacy attachments' text and
  files, read with a Slack app of the customer's own holding only
  `channels:read`, `groups:read`, `channels:history`, `groups:history` and
  `files:read` (docs/SAAS.md has the manifest). The bot reads the channels it
  was invited to; the others are `not_a_member` (joining would be a write).
  Direct and group messages (`slack_dm`, opt-in) through the Discovery API on
  Enterprise Grid (`discovery:read`). The token comes from a mounted file only
  (`SLACK_TOKEN_FILE`) and goes to `slack.com` and `files.slack.com` only;
  Slack's `{"ok": false, "error"}` names a failure; `Retry-After` is honored;
  channels are read newest first down to the last complete read, capped per
  channel and resumed below where a run stopped. `SLACK_EKM_KEY_ID` (Slack
  EKM) makes findings `customer_managed_key`, hashed. An opt-in kind of a
  configured vendor left out of `DISCOVER` is now reported
  `read_not_configured` (one store, `*`), not left silent.
- **SaaS, step 4: Atlassian** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  Jira issues (`jira_project`: summary, description, comments, attachments)
  and Confluence pages and blog posts (`confluence_space`: title, body, footer
  comments, attachments), read with a read-only account's API token (from a
  file) or OAuth 2.0 (3LO) with `read:jira-work`,
  `read:confluence-content.all`, `read:confluence-space.summary`,
  `readonly:content.attachment:confluence` and `offline_access` only; the
  rotating refresh token is written back to its own file, and a token that
  cannot be saved stops the run. JQL and CQL in update order; the first run
  reads everything, later runs only what changed (skipping what was read);
  gone items drop their findings; capped per project and space. Links to
  issues by key and pages by id. `ATLASSIAN_BYOK_KEY_ID` (Atlassian Cloud BYOK)
  makes findings `customer_managed_key`, hashed.
- **SaaS, step 5: release and deploy** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  releases publish `ghcr.io/txp-labs/sensitive-data-scanner-saas` (its SBOM and
  `SAAS_IMAGE_DIGEST`), the `sensitive_data_scanner_saas` wheel, and
  `deploy/saas` as `sensitive-data-scanner-saas-deploy.tar.gz`: examples for ECS
  Fargate (CloudFormation, EventBridge Scheduler, the task role's web identity,
  Secrets Manager copied to a task-local volume, an S3 state object), Azure
  Container Apps (a scheduled job, a managed identity, Key Vault secrets as
  files), Cloud Run (a job, keyless Workspace signing, Secret Manager files, a
  Cloud Storage state volume) and Kubernetes (a CronJob, a projected token,
  Secret files, a persistent volume). docs/SAAS.md gains Deploying, and every
  grant by vendor in one table.
- **Scanner, vendor or both, and Amazon Macie's findings** ([#55](https://github.com/txp-labs/sensitive-data-scanner/issues/55)):
  the core's modes (`sensitive_data_core.modes`: `scanner`, `vendor`,
  `both`), and a finding's `source` on every finding. `SCAN_MODE` (and the
  template's `ScanMode`) chooses for AWS: `vendor` imports Amazon Macie's
  classification findings (`macie2:ListFindings`, `GetFindings`, incremental)
  and reads nothing (stores are `vendor_mode` for S3, `vendor_not_covered`
  for every other kind); `both` reads and imports, and links a finding of one
  to the other's at the same object and class. A Macie finding keeps the
  object's masked key, each detection's type and count, the object's
  encryption and Macie's id; its occurrences, title and description are never
  read into it. Macie's managed identifiers map to the spec's classes; any
  other type is `other`. The document names the mode (`scanMode`) and the
  import's coverage and limits (`vendorCoverage`, `s3_only`).
- **Google Cloud Sensitive Data Protection's profiles** ([#55](https://github.com/txp-labs/sensitive-data-scanner/issues/55)):
  with `SCAN_MODE` `vendor` or `both` (Terraform `scan_mode`), the Google
  Cloud scanner imports SDP's BigQuery column profiles (on the same resource
  as its own BigQuery findings, so `both` links them) and Cloud Storage file
  store profiles (per bucket), in each of `SDP_LOCATIONS`, keeping only the
  location, the info types' names and the profile's hashed name; quotes and
  samples are never read. `vendor` reads nothing (`vendor_mode` for BigQuery
  and Cloud Storage, `vendor_not_covered` for the rest). A vendor finding's
  id now includes its `vendorType`, so two `other` types at one place stay
  two findings.
- **SaaS vendor detection: Purview DLP, the Workspace Alert Center, Slack DLP** ([#55](https://github.com/txp-labs/sensitive-data-scanner/issues/55)):
  `SCAN_MODE_M365`, `SCAN_MODE_GOOGLE_WORKSPACE` and `SCAN_MODE_SLACK` (each
  defaulting to `SCAN_MODE`) choose per vendor; Atlassian is `scanner` only.
  Purview DLP's Graph security alerts (`SecurityAlert.Read.All`; imported in
  the SaaS package, which holds the Microsoft 365 sign-in and Graph client),
  the Alert Center's `DlpRuleViolation` alerts (`apps.alerts` as a View-only
  administrator; a Drive document links to the scanner's finding for it) and
  Slack's DLP audit events (`auditlogs:read`, an org token from a file) become
  findings with their source; titles, descriptions, subjects, file names,
  addresses, rule names and matched text are never read into them. A vendor
  that names no kind of data gives class `other`, never linked
  (`no_data_class`).
- **The core reads Word, Excel and PowerPoint files** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21), step 6):
  `.docx`, `.xlsx` and `.pptx` (and `.docm`, `.xlsm`) are read as their text
  (`scan/office.py`, the standard library only), through ranged reads of the
  zip; a DTD is never expanded, inflated text is capped, and a rights-managed
  file is counted as `encrypted`. Every reader built on `scan/objects.py`
  (Azure Blob Storage and Files, Cloud Storage, the SaaS scanner) now reads
  them instead of counting them as `document`; the AWS S3 source still counts
  them. PDFs and the older binary formats are still counted.
- **Content, not name, decides the reader; archives and PDFs are read** ([#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65)):
  - Every object's first bytes are sniffed (`scan/sniff.py`, one small
    ranged read, the object's only read when it is small): zip, and Word,
    Excel and PowerPoint told apart by their parts; OLE; PDF; gzip, bzip2,
    xz, zstd; tar; 7z; Parquet, ORC, Avro; images, audio and video; text by
    a printable UTF-8 ratio. A `.docx` renamed `.fff` or `.jpg` used to be
    read as compressed text or skipped; it is now read as Word, and its
    findings carry `disguised: true`, `declaredType` and `detectedType`
    (kinds, never a name). Mismatches are counted in coverage and the run
    summary even when nothing is found. Genuine images, audio and video are
    still counted, not read, after the sniff.
  - Archives are read entry by entry, in memory, never extracted: zip, tar,
    and gzip, bzip2, xz and zstd streams, nested up to three levels (a
    `.tar.gz` is one), each entry sniffed and routed like an object. Caps:
    `MAX_INFLATED_BYTES` per object, 1,000 entries per archive, 200 times an
    entry's compressed size (the zip-bomb guard); a capped read is
    `partial`. An encrypted entry or archive is `encrypted`; 7z is
    `archive_unsupported` (py7zr brings compiled codecs). Findings name the
    entry (`archivePath`, masked like a key, with its position when masked).
  - PDFs are read as their text layer and document information with pypdf
    (pure Python, no dependencies; about 4 MB), up to 500 pages; a PDF with
    no text layer is `pdf_image_only`, one behind a user password
    `encrypted`.
  - Everywhere objects are read: S3 (every object now goes through the core's
    reader), Azure Blob Storage and Files, Cloud Storage, SaaS files and
    attachments (OneDrive, SharePoint, Google Drive, Gmail, Slack, Jira and
    Confluence), CodeCommit files and ECR layer files. Callers share the
    core's `record` for coverage and findings; the listing no longer skips by
    extension (`skip_kind` is gone), and a name that says image, audio or
    video is charged to the budget as its sniff only.
- **Component versions and the per-object index** ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 1):
  - Every adapter, every reader (`text`, `transcript`, `docx`, `xlsx`, `pptx`,
    `pdf`, `archive-zip`, `archive-tar`, `archive-stream`, `columnar`, `avro`,
    `rdb`, `sql`, `attributes`), the sniffer, `spec-standalone` (and each
    class's rules) and `spec-conversation` has a version: a hash of its
    source, written by `scripts/components.py` into
    `sensitive_data_core/components.json`, which ships in the core. CI fails
    when a component's source changes and the manifest is not regenerated.
  - Each source that reads objects keeps an index in the scanner's own state
    location (the results bucket's, the Azure state container's or the
    Google Cloud state bucket's `state/index/`, or beside a container
    runner's `STATE_LOCATION`). Per object, it holds an HMAC of the key, of
    the change marker and of the content fingerprint, the detected type, the
    readers used, the kinds no reader read, the skip reason, and the
    component-version vector it was read with. It never holds a value. The
    salt is kept in the state document, not in the index.
  - SQLite, gzipped, one file per shard; about 35 MB per million objects;
    `INDEX_MAX_OBJECTS` (10 million) per source; objects gone are swept at the
    end of a complete pass. `OBJECT_INDEX=off` turns it off.
  - Recorded today: S3 (with Glue tables and directory buckets), Azure Blob
    Storage and Files, Cloud Storage, and OneDrive, SharePoint and Drive
    files. The core's `read_object` now reports the detected type, the
    readers used, the kinds it could not read and whether any part was a
    conversation. Nothing changes in what a run reads or finds yet.
- **Smart rescans** ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 2):
  - An object that did not change at its source is read again only when a
    component it was read with changed and could change its result:
    - its adapter changed: that adapter's objects only;
    - a reader it was read with changed: on every platform, archives with an
      entry it read included;
    - a new reader (or pyarrow in the build) reads a kind it held unread;
    - the sniffer changed: only objects whose kind was undetermined or
      disputed;
    - `spec-standalone` changed: text-bearing objects only, with the classes
      named when only their rules changed or they are new;
    - `spec-conversation` changed: transcripts only;
    - no row in the index: read once (`unindexed`), the objects read before it.
  - Source changes come first. Rescans follow in listing order within
    `RESCAN_PERCENT` (25%) of each source's budget, so an upgrade is spread
    over runs and never spikes one. `RESCAN_PERCENT=0` turns rescans off.
  - Findings of a rescan carry `rescanReason` (and `rescanClasses`). Coverage
    reports `indexed`, `rescanned` by reason and `rescanBacklog`.
  - With a row in the index, the recorded change marker decides whether an
    object changed, so an object inside the five-minute skew window is no
    longer read twice.
  - OneDrive, SharePoint and Drive find stale files by listing every item
    again after the delta feed, resumably.
  - CodeCommit reads only the files whose blob changed on a new head.
  - ECR does not download a layer it has read again for a newer image.
  - A head or image already read is read again only for the files or layers
    a changed component could read differently.
- **Tables unchanged since their last read are skipped; DynamoDB reads only
  what changed** ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 3):
  - From the second pass on, the core's sampled SQL pass asks each engine
    what changed, with one catalog query and never data. A table whose marker
    has not moved is not sampled, and its findings stay. The markers:
    - PostgreSQL: `pg_stat_user_tables`, on a primary only;
    - MySQL and MariaDB: `UPDATE_TIME`;
    - SQL Server: `sys.dm_db_index_usage_stats.last_user_update`;
    - Oracle: `ALL_TAB_MODIFICATIONS` and `LAST_ANALYZED`;
    - Snowflake and Databricks: `last_altered`;
    - Redshift, Spanner and MongoDB have none and are sampled as before.
  - Every table is sampled at least every 7 days. A catalog the user may not
    read means no markers.
  - This covers the databases runner, the RDS Data API, and Azure's and Google
    Cloud's databases. The databases runner now carries findings between runs
    beside its `STATE_LOCATION` (`findings.json.gz`), and its state document
    gains `indexSalt`.
  - The rescan rules apply to tables (the `sql` reader, the adapter, the
    spec), and to BigQuery tables, which were already skipped when
    unchanged.
  - DynamoDB tables read by export use incremental exports after the first
    full one (`DYNAMODB_INCREMENTAL`, on: `INCREMENTAL_EXPORT`, `NEW_IMAGE`,
    at most 24 hours a window). They read only the items written since, and
    drop the findings of deleted items. A full export comes again only as a
    rescan, or after the point-in-time recovery window. The run summary
    names an incremental export (`exportType`).
- **S3 Inventory for large buckets** ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 4):
  - A bucket whose last complete pass saw at least `S3_INVENTORY_MIN_OBJECTS`
    (1,000,000) objects is read from its own S3 Inventory report instead of
    a `ListObjectsV2` of every key (`S3_INVENTORY`, on). The scanner looks
    for an enabled configuration of current versions covering the prefix,
    with `Size` and `LastModifiedDate`.
  - It reads the latest report no more than eight days old: CSV streamed,
    Parquet and ORC with pyarrow. Each row is decided like a listed object
    (watermark, index, sampling, rescans).
  - A pass resumes at a file and row, and its watermark is the report's time.
    Until the next report arrives, nothing is listed.
  - A large bucket with no configuration is named `recommendation:
    s3_inventory` in the run summary and listed as before. The scanner never
    creates one.
  - The role gains `s3:GetInventoryConfiguration`, a read.
  - Azure Blob Inventory and Cloud Storage inventory reports are designed in
    `docs/ARCHITECTURE.md` and not built.
- **Duplicates are not read again** ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 5):
  - An object whose content fingerprint matches an object the same source
    already read is not fetched, provided the name is of the same kind (its
    known extensions) and the original was read with components that are
    still current. The fingerprint is a single-part S3 ETag, Azure
    `Content-MD5`, Cloud Storage `md5Hash`, Drive `md5Checksum`, or OneDrive
    and SharePoint SHA-1 or QuickXorHash. It is also the MD5 of bytes read
    whole.
  - Its findings are the original's as its own (resource, id, link, and its
    own storage encryption, from one `HeadObject` on S3), each with
    `duplicateOf`. Coverage counts `duplicates`.
  - Applies to S3, Azure Blob Storage, Cloud Storage, and OneDrive,
    SharePoint and Drive files.

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

- The Azure and Google Cloud scanners now read `.docx`, `.xlsx` and `.pptx`
  objects (they were counted as `document`), so findings can appear in files
  that were skipped before.
- **The AWS scanner reads Word, Excel and PowerPoint files too** ([#21](https://github.com/txp-labs/sensitive-data-scanner/issues/21)):
  S3 objects (general purpose and directory buckets, and Glue tables'
  locations), CodeCommit files and ECR layer files named `.docx`, `.xlsx` or
  `.pptx` (and `.docm`, `.xlsm`) are read as their text by the core's Office
  reader (`scan/office.py`), the one the Azure, Google Cloud and SaaS scanners
  use, instead of being counted as `document`. An S3 object is read through
  ranged GETs of one version (the zip's directory and its text parts), within
  `MAX_OBJECT_BYTES` fetched and `MAX_INFLATED_BYTES` inflated; a CodeCommit
  or ECR file from the bytes already read, within the same caps. A
  rights-managed file is counted as `encrypted`; one that is not a readable
  zip, or whose directory is past the byte cap, still as `document`. Findings
  can appear in files that were skipped before, with the formats `docx`,
  `xlsx` and `pptx`. Standard library only: the Lambda zip gains no
  dependency. The no-leak suite covers all three.

### Security
- (#55) The SaaS importers add `SecurityAlert.Read.All`, `auditlogs:read` and
  the Alert Center's `apps.alerts`, each only in `vendor` or `both`. The
  Alert Center has no read-only scope: the strict test names it as its one
  exception, with its reason (the scanner only lists, and the delegated
  administrator's role holds Alert Center View only).
- (#55) The Google Cloud module lists SDP's data profiles with a role of its
  own, made only when `scan_mode` is not `scanner`, holding
  `dlp.columnDataProfiles.list` and `dlp.fileStoreProfiles.list` only; the
  strict test holds it to that and keeps DLP jobs and inspection results out.
- (#55) Macie is read only with `ScanMode` `vendor` or `both`
  (`macie2:GetMacieSession`, `ListFindings`, `GetFindings`), and a new deny,
  `NeverRevealOrChangeMacie`, keeps the scanner's role from Macie's occurrence
  samples (`GetSensitiveDataOccurrences*`), its reveal configuration and every
  Macie change, whatever the mode.
- The SaaS scanner's grants are held to read-only by a strict test
  (`scanner/tests/test_saas_scopes.py`): every permission or scope it requests,
  or that its code, docs/SAAS.md or deploy/saas names, is on its vendor's
  read-only list and reads by its own name; it sends only GETs to the vendors
  except the named token exchanges (no PUT, PATCH or DELETE anywhere), and only
  Slack's read methods; the deploy examples set no secret in the environment
  and only settings the code reads; the ECS template's roles hold only their
  own actions, none with a wildcard. The keyless Google signer's federated
  token now asks for the `iam` scope only (was `cloud-platform`).
- The SaaS scanner's Microsoft 365 grants read only, and mail is read only
  once the scanner has proved Exchange limits the app's `Mail.Read` to the
  mailboxes in scope. A client secret is never taken from the environment;
  no token, assertion, secret or address is logged; the app's token is sent
  to `graph.microsoft.com` only (a file download's redirect goes without it).
- Google Workspace is read through domain-wide delegation of read-only
  scopes only; the delegated service account holds no IAM role, and its
  signer only `iam.serviceAccounts.signJwt` on it. Google tokens go to
  Gmail, Drive and the Directory API only.
- The Azure deployment assigns Storage File Data Privileged Reader only with
  `readFileShares` (off by default); the strict test lists its data actions
  (`fileshares/files/read`, `readFileBackupSemantics/action`) and holds it to
  that parameter.
- The Google Cloud deployment's roles are read-only, held so by a strict test
  (`scanner/tests/test_gcp_template.py`): every permission in its custom roles
  reads by its verb, or is a named exception with its reason
  (`spanner.sessions.create` and `.delete`,
  `alloydb.clusters.generateClientCertificate`, `serviceusage.services.use`);
  secret access and database logins sit only in opt-in roles, off by
  default; the only predefined roles are Storage Object User on the job's own
  bucket, Secret Accessor on its own two secrets and Run Invoker on the job
  for the schedule's account; nothing is bound authoritatively and no key is
  made. Predefined viewer roles are not used, since several carry writes
  (`bigquery.tables.export`, `bigquery.tables.createSnapshot`).
- The Azure deployment's roles are all read-only, held so by a strict test
  (`scanner/tests/test_azure_template.py`) that checks every role id in the
  template against the built-in roles' published actions and allows one write
  role, Storage Blob Data Contributor, on the job's own state container only;
  no custom role, no `listKeys`. Log Analytics Reader is not assigned (it
  carries `Microsoft.Support/*`); Reader covers the queries.
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
- `schemaVersion` is now **1.10**, additive ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)):
  `rescanReason` (`adapter`, `reader`, `new_reader`, `sniffer`,
  `spec_standalone`, `spec_conversation`, `unindexed`) and `rescanClasses` on
  a finding; `indexed`, `rescanned` and `rescanBacklog` in coverage; the
  store fields `exportType`, `listedBy` and `recommendation`; `duplicateOf`
  on a finding and `duplicates` in coverage.
- Version **1.9**, additive ([#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65)): `disguised`,
  `declaredType` and `detectedType` on a finding; `archivePath`,
  `archivePathMasked` and `archiveEntry` on an `s3_object`, `blob_object`,
  `azure_file`, `gcs_object`, `saas_item` or `store_field` resource; the
  `pdf` format; the `archive_unsupported` and `pdf_image_only` skip kinds;
  `disguised` in coverage and the `disguised` gap on a store.
- Version **1.8**, additive: the SaaS scanner's
  `platform: saas`, the `saas_item` resource (`vendor`, `service`,
  `tenantHash`, `ownerHash`, `container`, `channel`, `itemId`, `itemHash`,
  `part`, `name`, `column`), `vendor`, `tenantHash` and `ownerHash` on a
  store, the `m365_mail`, `m365_onedrive`, `m365_sharepoint`,
  `m365_teams_channel`, `m365_teams_chat`, `gws_gmail`, `gws_drive`,
  `gws_shared_drive`, `slack_channel`, `slack_dm`, `jira_project` and
  `confluence_space` kinds, the `google_workspace`, `slack` and `atlassian`
  vendors, the `issue` and `page` parts, the `docx`, `xlsx`
  and `pptx` formats, the `encrypted`, `too_large` and `linked_item` skip kinds,
  the `scope_unverified`, `unscoped_grant`, `protected_api`,
  `not_provisioned`, `throttled` and `not_a_member` reasons, and Outlook on the web,
  SharePoint, Teams, Google Drive, Slack, Jira and Confluence links; and (#55)
  `source`, `vendorType`, `vendorFindingId` and `linked` on a finding, the
  `vendor` format and `via`, the `other` class, `scanMode` and
  `vendorCoverage` on the document, and the `vendor_mode` and
  `vendor_not_covered` reasons.
- `schemaVersion` is now **1.7**, additive: Azure Files' `azure_files` kind
  and `azure_file` resource, and the Google Cloud scanner's
  `platform: gcp`, the `gcs_object` resource, `project` and
  `resourceNameHash` (the SHA-256 of the store's full resource name) on
  Google Cloud findings and stores, the `gcs`, `bigquery`, `firestore`,
  `datastore`, `spanner`, `bigtable`, `cloud_logging`, `pubsub`, `gce_snapshot`,
  `secret_manager`,
  `cloudsql_postgresql`, `cloudsql_mysql`, `cloudsql_sqlserver` and `alloydb`
  kinds, the
  `requester_pays`, `row_level_policy`, `authorized_view`,
  `needs_subscription` and `needs_disk_restore` reasons, the `private_log`
  skip kind, the
  store fields `tableType` and `protectedColumns`, and Google Cloud console
  links.
- Version **1.6**, additive: the Azure scanner's
  `platform: azure`, the `blob_object` resource, `subscription`,
  `resourceGroup` and `resourceIdHash` (the SHA-256 of the lower-cased
  resource ID) on Azure findings and stores, the `azure_blob`, `azure_sql`,
  `azure_sql_mi`, `azure_postgresql`, `azure_mysql`, `synapse_sql`,
  `cosmosdb`, `cosmosdb_mongo`, `azure_table`, `azure_queue`,
  `log_analytics`, `azure_disk_snapshot` and `key_vault` kinds, the `kql`
  format and the `billed_plan` skip kind, the store field `api`, the
  `network` and `needs_sas_export` reasons, `hierarchicalNamespace`, `networkRestricted`, the
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
- `docs/ARCHITECTURE.md` (Duplicates, in How rescans are chosen) and `docs/FINDINGS.md`
  (`duplicateOf`, `duplicates`) ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 5).
- `docs/ARCHITECTURE.md` (Large buckets: S3 Inventory, with the Azure and
  Cloud Storage designs), `docs/FINDINGS.md`, `docs/AZURE.md` and `docs/GCP.md`
  ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 4).
- `docs/DATABASES.md` (Tables unchanged since the last read), `docs/ARCHITECTURE.md`
  (DynamoDB incremental exports, tables in How rescans are chosen), `docs/AZURE.md`
  and `docs/GCP.md` ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67), part 3).
- `docs/ARCHITECTURE.md` (How rescans are chosen), `docs/FINDINGS.md`
  (Rescans, schema 1.10), and `RESCAN_PERCENT` in `docs/AZURE.md`,
  `docs/GCP.md` and `docs/SAAS.md` ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)).
- `docs/ARCHITECTURE.md`: the object index and component versions, and its
  size per million objects; `OBJECT_INDEX` and `INDEX_MAX_OBJECTS` in
  `docs/AZURE.md`, `docs/GCP.md` and `docs/SAAS.md` ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)).
- `docs/FINDINGS.md` (Archives, PDFs and disguised files), `docs/ARCHITECTURE.md`
  (What an object is: content, archives and PDFs), and `docs/AZURE.md`,
  `docs/GCP.md` and `docs/SAAS.md`: objects are read by content, archives by
  entry, PDFs as text ([#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65)).
- `docs/GCP.md`: the Google Cloud scanner, its stores and permissions,
  findings and settings.
- `docs/AZURE.md`: the Azure scanner, its stores and roles, findings,
  settings and deployment (the Bicep parameters, the roles and why each is a
  read, what the template cannot grant).
- `docs/DATABASES.md`: the engines and how each is kept read-only, settings,
  a read-only user per engine, verifying a signed push, and deployment with
  docker run, a Kubernetes CronJob, an ECS task and Azure Container
  Instances, with the image sizes. `docs/ARCHITECTURE.md`: the design for
  hosting the EFS and FSx file-system task in the same image.

### Internal
- CI checks that the component manifest is current (`scripts/components.py
  --check`, [#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)); the no-leak suite
  plants values in object keys and archive entries' names and searches every
  byte of the object index, and each shard's SQL dump, for them. New log
  events: `index.saved`, `index.failed`.
- The databases runner's state location (a path, S3, signed HTTPS) moved to the
  core (`sensitive_data_core.state`), which the SaaS scanner uses too; the
  databases runner keeps its 64 KiB document and its API.
- CI checks the Google Cloud deployment: `terraform fmt`, `validate` and
  `terraform test` (offline plans and applies against a mock provider) with a
  pinned, checksum-verified Terraform and the provider pinned by its lock
  file. `python-hcl2` joins the dev dependencies, for the strict test.
- CI builds the `gcp` image and smoke-tests it with no network (a wrong
  setting by its code, no gRPC, AWS or Azure SDK in it). The no-leak suite
  covers the Google Cloud scanner, with values in project, bucket, object,
  column and key names, a label and Google's error messages; a test keeps
  Google's libraries in `sensitive_data_gcp`. The core counts Google's
  `PERMISSION_DENIED` as `access_denied`.
- CI checks the Azure template: Bicep lint, and `main.json` matches a fresh
  build with a pinned, checksum-verified Bicep; the `azure` image is built
  and smoke-tested with no network.
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
