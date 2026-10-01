# Intentional limitations, and the setting for each

The scanner reads with read-only access and never writes to a customer's
stores. Some data cannot be read that way, costs money to read, or needs a
grant we judge most customers should not give by default. Each of those is a
**deliberate limitation**. This page lists every one, on every platform
([#105](https://github.com/txp-labs/sensitive-data-scanner/issues/105)):

- what is not read, and why;
- the setting (toggle) that changes it, as the environment variable the
  scanner reads and the deploy template's parameter that sets it;
- its default;
- how a store left unread shows up in the run summary
  ([FINDINGS.md](FINDINGS.md)).

**Nothing is a silent pass.** A store left unread is in the run summary with
its `status` and `reason`. Since findings schema 1.12, a store left unread
because a setting is off also names that setting (`toggle`), so the customer
sees what turns the read on. Some settings are **hooks**: the setting exists,
but the reader it would turn on is designed and not built. Turned on, a hook
gives the reason `not_implemented` and names itself, never a silent no-op.

Where a row has no setting, the limitation is a hard gap (no read-only way
exists) or not a read at all, and the page says which.

## AWS (`deploy/scanner.yaml`)

| # | What is not read, and why | Setting (env / template parameter) | Default | How it shows up |
|---|---|---|---|---|
| A1 | Database exports (RDS and Aurora snapshots, large DynamoDB tables, Neptune Analytics graphs, EventBridge replays) are started at most a few per run, and the same store at most every few days: each export costs, and exports land in the results bucket before they are read | `MAX_EXPORTS_PER_RUN` / `MaxExportsPerRun`; `EXPORT_MIN_INTERVAL_DAYS` / `ExportMinIntervalDays` (the names shipped before #105, kept) | 1 per run; 7 days | Past the per-run limit: `deferred`, reason `budget`, `toggle: MAX_EXPORTS_PER_RUN`; read on a later run. Between exports, the last export's findings stand (not a gap) |
| A2 | Tables registered with Lake Formation are read with the scanner's own IAM; a table Lake Formation denies is reported, not read. The scanner never asks Lake Formation for a grant (`NeverAskLakeFormation` denies it) | `GLUE_LAKE_FORMATION` / `GlueLakeFormation`: `read` or `skip` | `read` | A denied table: `error`, reason `lake_formation` (a blind spot: grant the scanner's role `SELECT` in Lake Formation). With `skip`: `skipped`, reason `lake_formation`, `toggle: GLUE_LAKE_FORMATION` |
| A3 | Customer managed keys are used only through each service (`kms:ViaService`); optionally only the keys on an allow-list | `KMS_ALLOWED_KEY_ARNS` / `KmsAllowedKeyArns` (and `AllowKmsDecrypt` turns key use through a service off altogether) | empty: any key the key policy allows, through a service only | A store under a key out of reach: `kms_access` (or `kmsDenied` in its `gaps`); with an allow-list set, `toggle: KMS_ALLOWED_KEY_ARNS` |
| A4 | SSM Parameter Store `SecureString` values are not decrypted | `SSM_DECRYPT` / `SsmDecrypt` | **off** (it was on before #105) | Counted in the store's `excluded.secure_string`, with `toggle: SSM_DECRYPT`; a store of nothing but `SecureString`s is `skipped`, `read_not_configured` |
| A4b | Secrets Manager values are not read (a secret holds credentials; each read is an event its owner audits) | `SECRETS_READ` / `SecretsRead` | off | `skipped`, `read_not_configured`, `toggle: SECRETS_READ` |
| A4c | Timestream for LiveAnalytics and Keyspaces tables are sampled with one read-only query each | `TIMESTREAM_READ` / `TimestreamRead`; `KEYSPACES_READ` / `KeyspacesRead` (new in #105: no setting existed) | on | Off: `skipped`, `read_not_configured`, naming the setting; the template also leaves out `timestream:Select` or `cassandra:Select` |
| A5 | EFS, FSx and EBS read by file: a file system is read by mounting it, and attaching a volume is a write, so it needs a separate read-only file-system task with its own role ([ARCHITECTURE.md](ARCHITECTURE.md#the-opt-in-file-system-task-design-not-built)) | `FILESYSTEM_TASK_ENABLED` / `FilesystemTaskEnabled`: **a hook** | **off** | Off: `skipped`, `needs_task`, `toggle: FILESYSTEM_TASK_ENABLED`. On: `skipped`, `not_implemented` (the task is not built) |
| A6 | Stores reachable only inside a VPC (an OpenSearch domain in a VPC, ElastiCache and MemoryDB, Timestream for InfluxDB, MSK and MQ brokers without public access): the function is not in the VPC | `VPC_SUBNET_IDS` and `VPC_SECURITY_GROUP_IDS` / `VpcSubnetIds` and `VpcSecurityGroupIds` (per account: set them per stack instance) | empty | Without a VPC: `vpc_only` (or `in_memory`, `no_read_path` for caches and InfluxDB), `toggle: VPC_SUBNET_IDS`. With one: an OpenSearch domain's VPC endpoint is read; MSK and MQ brokers are tried; caches and InfluxDB are `not_implemented` (no reader is built). The subnets need a route to AWS's APIs (a NAT gateway or VPC endpoints) |
| A8 | S3 Glacier Instant Retrieval objects: reading one has a retrieval fee per GB (#109). Standard-IA and One Zone-IA are read, within the byte budget; the run's `costEstimate` says what they cost | `S3_READ_GLACIER_IR` / `S3ReadGlacierIr` | **off** | Decided from the listing, never fetched: counted in the bucket's coverage as `notAllowed: {"archive_class": n}` and the store's `gaps.notAllowed`; `storageClasses.GLACIER_IR` says `read: false`, `reason: archive_class`, `toggle: S3_READ_GLACIER_IR`, and `costEstimate.byClass.GLACIER_IR` what turning it on would cost |
| A9 | S3 Glacier Flexible Retrieval, Glacier Deep Archive, and Intelligent-Tiering's Archive and Deep Archive Access tiers: no read-only way in. A restore is a write (`s3:RestoreObject` stays denied) that takes hours and costs the customer; a restored copy (the listing's `RestoreStatus`) is read (#109) | `S3_RESTORE_ARCHIVED` / `S3RestoreArchived`: **a hook** | **off** | The gap `needs_restore` (coverage `archived`, the store's `gaps.needsRestore`), never `unreadable`; `storageClasses` gives counts and bytes, and no estimate. On: the class says `not_implemented` |
| A7 | Live MySQL (and every other engine) is read only by the databases container ([DATABASES.md](DATABASES.md)), and only as a user that cannot write | none: the refusal is always on | n/a | A user that can write: `skipped`, `db_user_can_write` (its privileges by name); unverifiable grants: `grants_unverifiable` |

## Azure (`deploy/azure/main.bicep`)

| # | What is not read, and why | Setting (env / Bicep parameter) | Default | How it shows up |
|---|---|---|---|---|
| B1 | Log Analytics workspaces are read with Reader (`workspaces/query/read`) | `AZURE_LOG_ANALYTICS` / `readLogAnalytics` | on | Off: `skipped`, `read_not_configured`, `toggle: AZURE_LOG_ANALYTICS` |
| B2 | Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible servers, Synapse SQL pools and Cosmos DB for MongoDB vCore are read only as a database user the customer creates for the job's identity first ([AZURE.md](AZURE.md#creating-the-identitys-user)) | `AZURE_DB_READ` / `readDatabases` (the name shipped before #105, kept) | **off** (empty) | `skipped`, `read_not_configured`, `toggle: AZURE_DB_READ` |
| B3 | Cosmos DB for NoSQL is read with Cosmos DB Built-in Data Reader, a data-plane role assigned per account (`cosmosAccountIds`). An Azure Policy that would assign it on every account is a **hook**: its remediation identity would need a role that writes | `AZURE_COSMOS_READER_POLICY` / `assignCosmosReaderPolicy`: **a hook** | off | An account the identity cannot read: `error`, `access_denied`, `toggle: assignCosmosReaderPolicy`. On: `skipped`, `not_implemented` (add the account to `cosmosAccountIds` instead) |
| B4 | Managed disk snapshots are reported, not read: their bytes are reachable only through a SAS export (`beginGetAccess`), which changes the snapshot | `AZURE_READ_SNAPSHOTS` / `readDiskSnapshots`: **a hook** | **off** | Off: `skipped`, `needs_sas_export`, `toggle: AZURE_READ_SNAPSHOTS`. On: `skipped`, `not_implemented` |
| B5 | Cosmos DB for MongoDB on an RU account (and the Cassandra, Gremlin and Table APIs): only the account's keys read it, and those keys can write | none: a hard gap | n/a | `skipped`, `no_read_path`, with its `api` |
| C6 | Azure Files shares: Storage File Data Privileged Reader reads every file, bypassing the shares' ACLs | `AZURE_FILES_READ` / `readFileShares` (the name shipped before #105, kept) | **off** | `skipped`, `read_not_configured`, `toggle: AZURE_FILES_READ` |
| | Key Vault secrets' values | `KEYVAULT_SECRETS_READ` / `readKeyVaultSecrets` | off | `skipped`, `read_not_configured`, `toggle: KEYVAULT_SECRETS_READ` |
| B6 | Blob Storage and ADLS Gen2 Cold-tier blobs: reading one has a read fee per GB, about three times Cool's (#109). Hot and Cool are read (Cool within the byte budget) | `AZURE_READ_COLD_TIER` / `readColdTier` | **off** | Decided from the listing: `notAllowed: {"cold_tier": n}`; `storageClasses.Cold` says `reason: cold_tier`, `toggle: AZURE_READ_COLD_TIER`, and `costEstimate.byClass.Cold` what turning it on would cost |
| B7 | Archive-tier blobs (and blobs whose rehydration is in progress): only a rehydration (Set Blob Tier or Copy Blob to Hot or Cool, a write, hours, at the customer's cost) makes them readable (#109) | `AZURE_REHYDRATE_ARCHIVE` / `rehydrateArchive`: **a hook** | **off** | The gap `needs_rehydration` (coverage `archived`, the store's `gaps.needsRehydration`), never `unreadable`; counts and bytes, no estimate. On: the tier says `not_implemented` |

## Google Cloud (`deploy/gcp`, Terraform)

| # | What is not read, and why | Setting (env / Terraform variable) | Default | How it shows up |
|---|---|---|---|---|
| C1 | The scanner reads with custom read-only roles, not the predefined viewer roles (several carry writes). The person deploying needs Organization Role Administrator to create them | none: a deployment requirement | n/a | Not a gap: without the roles the deployment fails |
| C2 | Four permissions are not reads by their verb, and are allowed by name: Spanner's session (`spanner.sessions.create`, `.delete`), AlloyDB's cluster CA (`alloydb.clusters.generateClientCertificate`) and the quota project (`serviceusage.services.use`) | `GCP_SPANNER` / `read_spanner`; `GCP_ALLOYDB` / `read_alloydb` | on | Off: the role holding them is not made, and the stores are `skipped`, `read_not_configured`, naming the setting (AlloyDB is read only with `GCP_DB_READ` too) |
| C3 | Archive-class Cloud Storage objects are skipped: reading one has a retrieval fee. Nearline and Coldline are read, within the byte budget, and their fees are in the run's `costEstimate` (#109) | `GCS_READ_ARCHIVE` / `read_archive_objects` | **off** (they were read before #105) | Counted in the bucket's coverage, `notAllowed: {"archive_class": n}`, and the store's `gaps.notAllowed`, with `toggle: GCS_READ_ARCHIVE`; `storageClasses.ARCHIVE` and `costEstimate.byClass.ARCHIVE` (1.13) |
| C4 | Cloud SQL for SQL Server: it has no IAM database authentication, so reading it would take a password | `GCP_SQLSERVER` / `read_sqlserver`: **a hook** | **off** | Off: `skipped`, `no_read_path`, `toggle: GCP_SQLSERVER`. On: `skipped`, `not_implemented` |
| C5 | Pub/Sub dead-letter topics are reported, not read: reading needs a subscription, a write | `GCP_READ_PUBSUB_DLQ` / `read_pubsub_dead_letters`: **a hook** | **off** | Off: `skipped`, `needs_subscription`, `deadLetterQueue: true`, `toggle: GCP_READ_PUBSUB_DLQ`. On: `skipped`, `not_implemented`. Other topics are `live_queue`, never read |
| C7 | The image is published to `ghcr.io`; Cloud Run pulls from Artifact Registry, so the customer mirrors it there until the release pipeline does, once the artifacts account exists | none: a release step | n/a | Not a gap: [GCP.md](GCP.md#deploying) shows the mirror |
| | Secret Manager values | `SECRET_MANAGER_READ` / `read_secrets` | off | `skipped`, `read_not_configured`, `toggle: SECRET_MANAGER_READ` |

Azure Files (C6) is listed under Azure above.

## SaaS (`deploy/saas`)

| # | What is not read, and why | Setting (env) | Default | How it shows up |
|---|---|---|---|---|
| D1 | The Google Workspace Alert Center's DLP alerts are imported through `apps.alerts`, which Google offers only with change rights; the delegated administrator's role is held to View | `GWS_ALERT_CENTER` | on (in `vendor` or `both` mode only) | Off: nothing is imported, and `vendorCoverage` says `status: not_enabled`, `toggle: GWS_ALERT_CENTER`; in `vendor` mode the Workspace stores are `vendor_not_covered` |
| D2 | Purview's and Slack DLP's alerts name no kind of data (class `other`), so in `both` mode they cannot be linked to the scanner's findings by class | `LINK_VENDOR_ALERTS_BY_LOCATION` | on | On: linked to the scanner's findings at the same item, and both say `linkedBy: location`. Purview's alerts name no item this scanner reads, so they stay unlinked either way. Off: never linked |
| D3 | Mail is read only once the scanner proves the mail grant is scoped: a mailbox outside the scope (`M365_MAIL_SCOPE_CHECK`) must be refused. The app holds no `Application.Read.All` | `M365_MAIL` (the scope check is always on) | on (read per the grant) | Off: each mailbox `skipped`, `read_not_configured`, `toggle: M365_MAIL`. Without a proved scope: `scope_unverified` or `unscoped_grant` |
| D4 | Atlassian: an API token of a read-only service account is recommended; OAuth 2.0 (3LO) rotates its refresh token, so its token file must be writable | `ATLASSIAN_AUTH_MODE`: `token` or `oauth` | `token` | Not a gap: the other mode's settings are refused (`atlassian_auth_mode`), so neither is used by accident |
| D5 | Customer-managed keys (Microsoft 365 Customer Key, Slack EKM, Atlassian BYOK) cannot be seen through read-only APIs: the customer declares them | `M365_CUSTOMER_KEY_ID`, `SLACK_EKM_KEY_ID`, `ATLASSIAN_BYOK_KEY_ID` | none | Not a gap: findings say `service_managed` unless a key is declared, then `customer_managed_key` with its hash |
| | Opt-in kinds (Teams channels and chats, Slack DMs) | `DISCOVER` | off | `skipped`, `read_not_configured`, `toggle: DISCOVER` (one store per kind, named `*`) |

## Databases anywhere (the databases container)

The databases runner has no toggle for a limitation: it reads only the
databases named in its settings, as a user it checks first, and refuses a
user that can write (A7). See [DATABASES.md](DATABASES.md).

## Storage classes and the cost to scan (#109)

Every S3 bucket, Azure container and Cloud Storage bucket the scanner lists
gets, in the run summary (findings schema 1.13):

- `storageClasses`: objects and bytes per storage class or tier over the last
  complete listing pass, whether the class is read, and why not (rows A8, A9,
  B6, B7, C3). The class comes from the listing the scanner already does; an
  object left out is never fetched.
- `costEstimate`: what reading every object of the classes that charge per
  byte would cost once, from a dated price table in the scanner, never a
  pricing API at run time. See [COST.md](COST.md#reading-cold-storage-classes).

Classes that need a restore or a rehydration have counts only: *we can't read
these without a manual restore* (or rehydration). The restore is the
customer's action, at the customer's cost; the next scan reads the restored
copy.

## Changing a default

Each setting is an environment variable the scanner reads, set by its deploy
template. A run's configuration document (AWS: `CONFIG_LOCATION`) may set it
too. Turning a read on can need a grant the template adds only with it (the
template's description of the parameter says which); a hook needs nothing,
since it reads nothing yet.

**From Mermera (#109).** A runner that pushes to Mermera pulls its settings
from it before each run ([mermera-config.md](mermera-config.md)): an explicit
environment variable or template parameter wins, then Mermera's setting, then
the default, and the run records where each came from (`settingsSource`).
The deploy templates leave these settings unset by default (an empty
CloudFormation parameter, a null Bicep parameter or Terraform variable), so
Mermera's setting applies. A setting that needs a grant the template made
only with its own parameter (Parameter Store decryption, Secrets Manager,
Macie's reads, Key Vault secrets, Azure Files, Secret Manager, ...) cannot be
turned on from Mermera alone: the run keeps it off and reports `gate: iam`
with the template parameter to set.
