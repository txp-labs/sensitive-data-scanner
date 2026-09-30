# Google Cloud

The Google Cloud scanner runs **in your own Google Cloud organization**, as a
Cloud Run job with a **dedicated service account**. It discovers the data
stores of every project under an organization or folder, reads them
**read-only**, and sends **findings only, never values**
([FINDINGS.md](FINDINGS.md), schema 1.7). It is the same detection, findings
contract, budgets, sampling, readers and coverage summary as the AWS and Azure
scanners (the cloud-neutral core, `scanner/core`), in its own package
(`scanner/gcp`, `sensitive_data_gcp`) and its own image
(`docker build --target gcp`).

- **No key.** Every request is signed by the job's service account through
  Application Default Credentials: on Cloud Run, the metadata server. No
  service account key is created, mounted or configured.
- **Read-only.** The service account holds viewer and reader permissions
  only, except on the job's own state bucket.
- **Discovery across the organization or folder.** Cloud Asset Inventory's
  `searchAllResources` lists every store of each kind in every project under
  the organization (or the folders, or the projects, you name) in one paged
  search per kind.
- **Only findings leave.** Bucket, object and column names are masked like S3
  keys; a store's full resource name is hashed (`resourceNameHash`); no value
  is ever written, logged or sent.
- **Every store it cannot read is in the run summary with a reason**:
  `access_denied` (a permission is missing), `network` (a VPC Service
  Controls perimeter keeps the job out), `requester_pays`, `self`, `denied`
  or `not_allowed` (your rules), `deferred` (the budget; the next run starts
  there).
- **Budgets and sampling**: the core's run budget (items, bytes, time, and a
  cap on objects), a stable per-name sample, and at most n objects per
  directory.
- **REST only.** Every Google API is called over REST through google-auth's
  authorized session, so the image carries no gRPC stack.

## Stores

| Kind (`DISCOVER`) | Store | Read with | Default |
|---|---|---|---|
| `gcs` (`storage`, `bucket`) | A Cloud Storage bucket | `cloudasset.assets.searchAllResources` (discovery); `storage.objects.list` and `storage.objects.get` (List Objects, ranged media reads) | read |
| `bigquery` (`bq`) | A BigQuery table, `project.dataset.table` | `bigquery.datasets.get` and `bigquery.tables.list` (discovery), `bigquery.tables.get`, `bigquery.rowAccessPolicies.list` and `bigquery.tables.getData` (`tabledata.list`): BigQuery Data Viewer's reads | read; views, external tables, tables with row-level policies are gaps |
| `firestore` (`documents`) | A Firestore database in Native mode, `project/database` | `datastore.databases.getMetadata` (discovery, key); `datastore.entities.list`, `datastore.entities.get` (`listCollectionIds`, `runQuery`): Cloud Datastore Viewer's reads | read |
| `datastore` | A Firestore database in Datastore mode, `project/database` | the same (a `__kind__` query, then `runQuery` per kind) | read |
| `spanner` | A Spanner database, `instance/database` | `spanner.databases.get` (discovery, key); `spanner.databases.select`, `spanner.sessions.create`, `spanner.sessions.delete`: Cloud Spanner Database Reader | read |
| `bigtable` | A Bigtable table, `instance/table` | `bigtable.clusters.list` (the key); `bigtable.tables.readRows`: Bigtable Reader | read |
| `cloud_logging` (`logging`, `logs`) | A project's logs (the project id) | `logging.buckets.list` (the key); `logging.logs.list`, `logging.logEntries.list`: Logs Viewer | read; Data Access audit logs with `LOGGING_PRIVATE_READ` (Private Logs Viewer) |
| `pubsub` (`topics`) | A Pub/Sub topic, `project/topic` | `pubsub.subscriptions.list` (which topics are dead-letter topics) | gap: `needs_subscription` (dead-letter topics) or `live_queue`: reading needs a subscription, a write |
| `gce_snapshot` (`snapshots`) | A persistent disk's snapshots (the disk's name) | `compute.snapshots.list` | gap: `needs_disk_restore` (reading needs a disk made from it, a write) |
| `secret_manager` (`secrets`) | A project's secrets (the project id) | discovery only; with `SECRET_MANAGER_READ`, `secretmanager.versions.access` (Secret Accessor) and `secretmanager.secrets.get` | **off**: `read_not_configured`; `SECRET_MANAGER_READ=on` reads, counts only |
| `cloudsql_postgresql` (`postgresql`, `cloudsql`) | A Cloud SQL for PostgreSQL database, `instance/database` | `cloudsql.instances.get`, `cloudsql.databases.list` (discovery, TLS CA, key); `cloudsql.instances.login` and an IAM database user with read grants (below) | discovered; read with `GCP_DB_READ` |
| `cloudsql_mysql` (`mysql`) | A Cloud SQL for MySQL database, `instance/database` | the same | discovered; read with `GCP_DB_READ` |
| `cloudsql_sqlserver` (`sqlserver`) | A Cloud SQL for SQL Server database, `instance/database` | `cloudsql.instances.get`, `cloudsql.databases.list` | gap: `no_read_path` (no IAM database authentication; only a password could read it) |
| `alloydb` (`alloy`) | An AlloyDB cluster (its databases, listed by SQL) | `alloydb.clusters.get`, `alloydb.instances.list` (discovery); `alloydb.clusters.generateClientCertificate` (the cluster's CA), `alloydb.users.login` and an IAM database user with read grants | discovered; read with `GCP_DB_READ` |

### Cloud Storage

- **Discovery.** Cloud Asset Inventory lists every bucket in scope
  (`storage.googleapis.com/Bucket`) with its labels and its default Cloud KMS
  key, so a bucket shows in the run summary even when a service perimeter
  keeps the job away from its objects. The job's own state bucket is `self`.
- **Reading** is the JSON API: objects listed in name order, then ranged
  media reads of the generation listed. Objects are read the way the AWS
  scanner reads S3 objects, with the core's readers
  (`sensitive_data_core.scan.objects`): Parquet and ORC by column through
  ranged reads (footer first), Avro, gzip and zstd inflated, JSON and JSON
  lines, CSV, conversation transcripts and text, Word, Excel and PowerPoint
  files and PDFs as their text, and zip, tar, gzip, bzip2 and xz archives
  entry by entry. What an object is comes from its first bytes, not its name:
  a renamed file is read by content and its findings say `disguised`
  ([FINDINGS.md](FINDINGS.md#archives-pdfs-and-disguised-files-19)). Audio,
  video, images and the older binary Office formats are counted, not read;
  7z is `archive_unsupported`. Every storage class is read
  in place (Nearline, Coldline and Archive objects are online; their
  retrieval fee falls within the run's bytes budget).
- **Incremental.** A pass reads only the objects updated since the previous
  complete pass started (less `skew`), and a pass cut short by the budget
  resumes at the listing page it stopped in. With the object index
  ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)), an
  object whose generation is the one recorded is not read twice. An unchanged
  object is read again only when a component that could change what it gives
  changed ([ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)). Every
  bucket is still listed each pass: reading a Storage Insights inventory
  report in place of a listing is designed, not built
  ([ARCHITECTURE.md](ARCHITECTURE.md#large-buckets-s3-inventory)).
- **Never a write.** Nothing is rewritten, copied, composed or restored. An
  object under a **customer-supplied key** (CSEK) cannot be read without that
  key, which the scanner never has: it is counted in `kmsDenied`.
- **Gaps.** A bucket inside a VPC Service Controls perimeter the job is
  outside of is `network`. A requester-pays bucket is `requester_pays`: its
  reads would be billed to the job's project, so it is never read. A missing
  permission is `access_denied`.
- **Encryption** (`atRestEncryption`). Google Cloud encrypts every object at
  rest. A finding says under which key: the object's own `kmsKeyName` (a
  CMEK) is `customer_managed_key`, named only by `atRestKeyHash`, the SHA-256
  of the key's resource name without its version; otherwise Google's own keys
  apply, `service_managed`. To match yours:

  ```sh
  printf %s projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key> | shasum -a 256
  ```

### BigQuery

- **Discovery.** Cloud Asset Inventory lists every dataset in scope. Each
  dataset's record (its access list and default key, `datasets.get`) and its
  tables (`tables.list`) come from the BigQuery API. A store is one table,
  `project.dataset.table`, so each gap has its own reason. A dataset that
  cannot be read is one store, `project.dataset.*`, with its error.
- **Reading** is `tabledata.list`: the first `BIGQUERY_MAX_ROWS` (1000) rows of
  each table, read by column; a `RECORD` column is read inside, and `BYTES`
  are not read. `tabledata.list` **runs no query and bills no bytes**, so it is
  used rather than a `TABLESAMPLE` query, which would bill the bytes of the
  blocks it samples and needs `bigquery.jobs.create` (creating a job is a
  write the service account does not hold). A table unchanged since its last
  complete read (`lastModifiedTime`) is not read again; its findings stay. A
  finding is a `store_field` with `service: bigquery`, the dataset as `store`,
  the table as `table` and the column as `field`, `readBy: tabledata_list`,
  format `json`.
- **Gaps, never escalating:**
  - **Views and materialized views** are never read: reading one is a query.
    A plain view is `unsupported` with `tableType: VIEW`.
  - An **authorized view** (one that a dataset's access list authorizes) is
    `authorized_view`. It can read tables the service account may not, so
    the scanner never reads through it. The tables it reads are stores of
    their own, read directly when the service account may, `access_denied`
    otherwise.
  - A table with **row-level access policies** is `row_level_policy`. A sample
    would hold only the rows the service account is granted, which says
    nothing about the rest, and the scanner is never granted more.
  - **Columns under a policy tag** (column-level security) are left out of the
    read (`selectedFields`) and counted as `protectedColumns`. The service
    account is never given Fine-Grained Reader.
  - **External tables** (Cloud Storage, Drive, Bigtable, BigLake) are
    `unsupported` with `tableType: EXTERNAL`: their data is read where it
    lives.
  - A dataset inside a VPC Service Controls perimeter the job is outside of is
    `network`.
- **Encryption.** The table's own Cloud KMS key, else its dataset's default
  key, is `customer_managed_key` (hashed as above); otherwise
  `service_managed`.

### Firestore and Datastore

- **Discovery.** Cloud Asset Inventory lists every Firestore database; its
  record (its mode and CMEK) comes from the Firestore API. A database in
  Native mode is a `firestore` store; one in Datastore mode a `datastore`
  store.
- **Firestore** (Native mode): the root collections (`listCollectionIds`),
  then the first `DOCUMENTS_MAX_PER_COLLECTION` (500) documents of each with
  one `runQuery` (`limit n`), read by top-level field, as columns: a map is
  read inside its field. Subcollections are not listed.
- **Datastore** (Datastore mode): the kinds of the default namespace (a
  `__kind__` query), then the first entities of each kind with one
  `runQuery`, read by property.
- Only queries are sent; a query cannot write. Bytes and blobs are not read.
  At most `DOCUMENTS_MAX_COLLECTIONS` (200) collections or kinds per database;
  a database the budget does not finish resumes at its next one. A finding
  names the database as `store`, the collection or kind as `table` and the
  field as `field`, `readBy: query`, format `json`.
- **Encryption.** The database's CMEK is `customer_managed_key` (hashed);
  otherwise `service_managed`.

### Spanner

- **Discovery.** Cloud Asset Inventory lists every database; its record (its
  dialect, state and key) comes from the Spanner API. A database still being
  created or restored is `paused`.
- **Reading** is the core's sampled SQL pass (`scan/sql.py`) through one
  session: the base tables from `information_schema.tables`, then
  `SELECT * FROM <table> LIMIT n` with quoted identifiers, read by column.
  **Every statement runs in a single-use read-only transaction**
  (`readOnly: {strong: true}`), which cannot write. The session is deleted
  after the pass. GoogleSQL and PostgreSQL-dialect databases are both read;
  `DB_SCHEMAS` applies to GoogleSQL only. `BYTES` and `PROTO` columns are not
  read. The service account's access is its IAM role (Database Reader), which
  the deployment's strict test holds to reads; there is no SQL user to check.
  A finding names the instance as `store`, the database, the table (with its
  schema, when it has one) and the column, `readBy: sample`, format `sql`.
- **Encryption.** The database's Cloud KMS key is `customer_managed_key`
  (hashed); otherwise `service_managed`.

### Bigtable

- **Discovery.** Cloud Asset Inventory lists every table; each instance's
  clusters say which key encrypts it.
- **Reading** is one `readRows` per table: the first `BIGTABLE_MAX_ROWS`
  (1000) rows, the latest cell of each column only
  (`cellsPerColumnLimitFilter: 1`), read by column, `family:qualifier`. The
  row key is read too, as the column `rowKey`, since a key can hold a value.
  Cells that are not text are not read. A finding names the instance as
  `store` and the table as `table`, `readBy: read_rows`, format `json`.
- **Encryption.** A cluster's Cloud KMS key is `customer_managed_key`
  (hashed); otherwise `service_managed`.

### Cloud Logging

- Every project in scope is one store. Its logs are listed (`logs.list`, at
  most `LOGGING_MAX_LOGS`, 200), and each is sampled with **one
  `entries.list`**: that log, the lookback window (`LOGGING_LOOKBACK_DAYS`,
  1), newest first, at most `LOGGING_MAX_ENTRIES_PER_LOG` (500). The log's
  name is quoted in the filter, so nothing in it is filter syntax. An entry
  is read by column: `textPayload`, the top-level fields of `jsonPayload` and
  `protoPayload` (`jsonPayload.<field>`, read inside), and `labels`. A
  finding names the project as `store`, the log as `table` and the column as
  `field`, `readBy: entries_list`, format `json`.
- **Data Access audit logs** (and Access Transparency's) are private: reading
  them needs Private Logs Viewer (`logging.privateLogEntries.list`), which is
  **opt-in** (`LOGGING_PRIVATE_READ=on`, and the deployment's
  `read_private_logs`). Without it, each is counted as skipped
  `private_log`.
- `entries.list` bills nothing, but a project allows 60 calls a minute. A pass
  that meets the quota stops there and resumes at that log on the next run.
  Logs routed to a Cloud Storage bucket or BigQuery dataset are read there.
- **Encryption.** The project's `_Default` log bucket's Cloud KMS key is
  `customer_managed_key` (hashed); otherwise `service_managed`.

### Pub/Sub (coverage only)

- Every topic is a store. Each project's subscriptions say which topics are
  **dead-letter topics** (a subscription's `deadLetterPolicy`), where failed
  messages and their payloads pile up.
- **Nothing is read.** A topic's messages can be read only through a
  subscription. Pulling from a subscription that exists changes what its own
  consumer receives: a message pulled and not acknowledged is redelivered
  with its delivery attempt counted, and one acknowledged is gone. Creating a
  subscription is a write. So a dead-letter topic is `needs_subscription`
  (with `deadLetterQueue: true`), and any other topic is `live_queue`. When a
  project's subscriptions cannot be listed, its topics are
  `needs_subscription`.

#### The opt-in dead-letter reader (design, not built)

For a customer who wants dead-letter topics read:

1. **The deployment creates the subscription**, not the scanner: one
   subscription of the scanner's own (`sds-<topic>`) on each dead-letter
   topic named in `read_dead_letter_topics`. It has no push endpoint, a
   one-day message retention, a 10-second acknowledgement deadline, and
   expires after 31 days without a pull. It sees only messages published
   after it exists (or, with the topic's own retention, it can be sought
   back to a time by the deployment, once).
2. **The scanner gets Pub/Sub Subscriber on those subscriptions only**, never
   on a topic and never project-wide. The strict test would allow
   `pubsub.subscriptions.consume` only on resources the deployment itself
   creates, and never `pubsub.subscriptions.create`.
3. **Per run**, one synchronous `pull` (`maxMessages`, 100) per subscription.
   The messages are read like SQS messages (`field: messages`,
   `readBy: pull`) and then acknowledged, on that subscription only: the
   topic, its publishers and every other subscription are untouched.
4. **Open questions:** whether a subscription made by the deployment is an
   acceptable change to a customer's topic (it adds a delivery target and its
   storage cost), and whether seeking it back into the topic's retention is.

### Persistent disk snapshots (coverage only)

- Cloud Asset Inventory says which projects hold snapshots; each project's
  snapshots come from the Compute Engine API, grouped by the disk they were
  taken of, as the AWS scanner groups EBS snapshots. There is one store per
  disk (or per snapshot whose disk is gone) with the latest snapshot's
  `snapshotTime`, `sizeBytes`, `olderSnapshots` and encryption.
- **It is not read.** Compute Engine has no API that reads a snapshot's
  blocks: the only way is to create a disk from it and attach that disk to a
  VM, both writes. Every snapshot is the gap `needs_disk_restore`.
- **Encryption.** A snapshot under a Cloud KMS key is `customer_managed_key`
  (hashed); under a customer-supplied key, `customer_managed_key` with no
  hash; otherwise `service_managed`.

### Secret Manager (off by default)

- Every project's secrets are one store, with `items`. With
  `SECRET_MANAGER_READ` off (the default), it is `read_not_configured`, and
  the deployment grants no accessor role.
- With it on (and the deployment's `read_secrets`), the latest version of
  each secret is read (`versions/latest:access`) and reported like Secrets
  Manager on AWS: **counts only**, `field: value`, no offsets, and never the
  value. A secret whose latest version is disabled or destroyed is counted
  (`itemTypes: Disabled`), not read. A value that is not text is counted as
  `binary`, not read.
- **Encryption.** A secret replicated under Cloud KMS keys is
  `customer_managed_key` (hashed from its first key); otherwise
  `service_managed`.

### Cloud SQL and AlloyDB

- **Discovery** is on by default. Cloud Asset Inventory lists every Cloud SQL
  instance and AlloyDB cluster. The Cloud SQL Admin API gives each instance's
  engine, state, addresses, server CA, flags and databases; the AlloyDB API
  gives each cluster's key and instances. A Cloud SQL database is a store,
  `instance/database`; an AlloyDB cluster is one store, whose databases are
  listed by SQL once connected (AlloyDB has no API that lists them). System
  databases are not stores. A stopped Cloud SQL instance, or an AlloyDB
  cluster with no instance ready, is `paused`.
- **Reading is opt-in** (`GCP_DB_READ`: `all`, or kinds such as
  `postgresql,alloydb`). Each database needs an IAM database user for the
  service account first, created by you. Until then every run would add a
  failed login to your audit logs.
- **As the service account, with IAM database authentication.** No password
  exists. The service account's access token (scoped to `sqlservice.login`,
  or `alloydb.login`) is the password, over TLS with the server's
  certificate verified against the instance's own CA: Cloud SQL's
  `serverCaCert`, or the AlloyDB cluster's CA from
  `generateClientCertificate` (which mints a short-lived client certificate
  and changes nothing on the cluster). With no CA, nothing is sent. The
  database user is `GCP_DB_PRINCIPAL`, the service account's email, as each
  engine names IAM users: PostgreSQL and AlloyDB without
  `.gserviceaccount.com`, MySQL only the part before `@`. An AlloyDB cluster
  is read through a read pool instance when it has one.
- **The user is checked first**, with the core's allow list of reads, as the
  databases runner does ([DATABASES.md](DATABASES.md)). A user that can write
  is refused as `db_user_can_write` with its privileges by name
  (`writeGrants`); one whose privileges cannot be read is
  `grants_unverifiable`. Nothing is read from either. In an AlloyDB cluster,
  a user that can write in any database refuses the whole cluster.
- **The sample** is the core's: the base tables, then `SELECT * ... LIMIT n`
  with quoted identifiers, in a read-only transaction (and a read-only
  session), always rolled back, resumable by table (and, in AlloyDB, by
  database). A finding is a `store_field` with the kind as `service`, the
  instance or cluster as `store`, then `database`, `schema.table` and the
  column, `readBy: sample`, format `sql`.
- **Unchanged tables** are not sampled again
  ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)):
  from the second pass on, the engine's own change markers are read
  (PostgreSQL's `pg_stat_user_tables`, MySQL's `UPDATE_TIME`, SQL Server's
  index usage stats), and a table whose marker has not moved keeps its
  findings. Every table is still sampled at least weekly, and the rescan
  rules apply ([DATABASES.md](DATABASES.md#tables-unchanged-since-the-last-read)).
- **Gaps:**
  - `network`: the job cannot reach the instance. A Cloud Run job reaches a
    private IP through Direct VPC egress (or a Serverless VPC Access
    connector) into the instance's network; a public IP needs the job's
    egress (Cloud NAT) in the instance's authorized networks. A store with
    only a private address is `networkRestricted`.
  - `access_denied`: no IAM database user yet, `cloudsql.instances.login` (or
    `alloydb.users.login`) missing, or a login the database refused.
  - `no_read_path`: Cloud SQL for SQL Server, which has no IAM database
    authentication, an instance with the IAM authentication flag off, and an
    AlloyDB cluster with no instances.
  - `driver_missing`, `no_grant`, as for the databases runner.
- **Encryption.** The instance's or cluster's Cloud KMS key is
  `customer_managed_key` (hashed); otherwise `service_managed`.

#### Creating the service account's database user

Turn IAM database authentication on (`cloudsql.iam_authentication=on` for
PostgreSQL, `cloudsql_iam_authentication=on` for MySQL,
`alloydb.iam_authentication=on` on an AlloyDB instance), then create the user
and grant reads only. With the service account
`sds-scanner@acme-sds.iam.gserviceaccount.com`:

```sh
# Cloud SQL (either engine): the user's name is the service account's email.
gcloud sql users create sds-scanner@acme-sds.iam.gserviceaccount.com \
  --instance=<instance> --type=cloud_iam_service_account
# AlloyDB:
gcloud alloydb users create sds-scanner@acme-sds.iam \
  --cluster=<cluster> --region=<region> --type=IAM_BASED
```

PostgreSQL and AlloyDB, in each database to read:

```sql
GRANT pg_read_all_data TO "sds-scanner@acme-sds.iam";  -- or SELECT on the schemas to read
-- Before PostgreSQL 15, PUBLIC may create in `public`, which the check refuses:
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

MySQL:

```sql
GRANT SELECT ON `shop`.* TO 'sds-scanner'@'%';
```

Grant nothing else: any privilege but reads is refused, and a role you cannot
narrow is refused rather than read.

## Sensitive Data Protection's profiles (#55)

With `SCAN_MODE` `vendor` or `both` (Terraform: `scan_mode`), the job imports
the data profiles Sensitive Data Protection's discovery keeps, for the
organization (or each project in scope) in each of `SDP_LOCATIONS`:

- a **BigQuery column profile** becomes a finding on the same `store_field`
  (dataset, table, column, `project`, `resourceNameHash`) as this scanner's
  BigQuery findings, so in `both` mode the two are linked;
- a **Cloud Storage file store profile** becomes a finding per info type on
  the bucket (a profile names no object).

Only the location, the info types' names and the hash of the profile's name
are kept; its other matches, samples and quotes are never read, and its
inspection results are never asked for. Info types map to the spec's classes
(`CREDIT_CARD_NUMBER` and `CREDIT_CARD_TRACK_NUMBER` to `card`,
`US_SOCIAL_SECURITY_NUMBER` to `us_ssn`,
`US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER` to `us_itin`, `DATE_OF_BIRTH`
to `dob`, `FINANCIAL_ACCOUNT_NUMBER` and `IBAN_CODE` to `account_number`); any
other is `other`. The Terraform module adds a role that holds only
`dlp.columnDataProfiles.list` and `dlp.fileStoreProfiles.list` when
`scan_mode` is not `scanner`, and enables the DLP API. In `vendor` mode,
BigQuery and Cloud Storage stores are `vendor_mode` and every other kind
`vendor_not_covered`.

## Findings

A Google Cloud document says `"platform": "gcp"` and names its `site`
(`SCANNER_SITE`) instead of an AWS account and region. Every finding and every
store in the run summary names its `project` (masked like a key) and
`resourceNameHash`, the SHA-256 of the store's full resource name exactly as
Cloud Asset Inventory gives it, so you can match it without the name being
written:

```sh
printf %s "//storage.googleapis.com/<bucket>" | shasum -a 256
```

An object's finding is the `gcs_object` resource (`bucket`, `object`,
`generation`, and `column` for a table file). Its `link` opens the bucket in
the Google Cloud console, and is `null` when a name it carries had to be
masked.

## Settings

| Setting | Default | What |
|---|---|---|
| `SCANNER_SITE` | (required) | A name for this deployment, as findings name it (the organization, say): lower case, digits, `.`, `_`, `-` |
| `GCP_ORGANIZATION` | | Discover every project under this organization (its number) |
| `GCP_FOLDERS` | | Or under these folders (numbers, comma-separated) |
| `GCP_PROJECTS` | | Or these projects (ids, comma-separated) |
| `DISCOVER` | every kind (opt-in kinds are listed and reported until their setting is on) | Kinds to discover, comma-separated, or `all` |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | | The core's rules: `gcs:prod-*`, `tag:scan=false` (a store's tags are its labels) |
| `DISCOVER_SAMPLING` | | The core's per-store sampling: `[{"match": "tag:env=prod", "samplePercent": 25}]` |
| `SAMPLE_PERCENT` | 100 | The share of objects read, by a stable hash of the name |
| `GCS_MAX_OBJECTS_PER_PREFIX` | 0 (off) | At most n objects per directory per pass |
| `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES` | 20 MiB, 100 MiB | Bytes read from one object, and inflated from one compressed object |
| `COLUMNAR_MAX_ROWS` | 10000 | Rows read from one table file |
| `BIGQUERY_MAX_ROWS` | 1000 | Rows read from one BigQuery table (`tabledata.list`) |
| `DOCUMENTS_MAX_PER_COLLECTION`, `DOCUMENTS_MAX_COLLECTIONS` | 500, 200 | Firestore documents (Datastore entities) read per collection (kind), and collections (kinds) per database |
| `BIGTABLE_MAX_ROWS` | 1000 | Rows read from one Bigtable table |
| `LOGGING_LOOKBACK_DAYS`, `LOGGING_MAX_ENTRIES_PER_LOG`, `LOGGING_MAX_LOGS` | 1, 500, 200 | Cloud Logging: the window sampled, entries per log, logs per project |
| `LOGGING_PRIVATE_READ` | off | `on` also reads Data Access audit logs (needs Private Logs Viewer) |
| `SECRET_MANAGER_READ` | off | `on` reads Secret Manager secrets' latest versions, reported as counts only |
| `GCP_DB_READ` | off | The database kinds read: `all`, or `cloudsql_postgresql`, `cloudsql_mysql`, `alloydb` (or `postgresql`, `mysql`, `alloy`). `cloudsql_sqlserver` is accepted and stays `no_read_path` |
| `GCP_DB_PRINCIPAL` | | The service account's email; its IAM database users are logged in as. Required to read |
| `DB_SCHEMAS`, `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES` | all but the system's, 1000, 500 | As the databases runner's; Spanner too |
| `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS` | 60, 15 | Per statement, per connection |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | 20000, 2 GiB, 3000 | The run's budget, shared among the stores |
| `OBJECT_INDEX`, `INDEX_MAX_OBJECTS` | on, 10,000,000 | The per-object index in the state bucket (`state/index/`, [#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)): what each object was read with, as keyed hashes; and the most objects one source indexes ([ARCHITECTURE.md](ARCHITECTURE.md#the-object-index-and-component-versions)) |
| `GCS_INVENTORY_MIN_OBJECTS` | 1,000,000 | A bucket whose last complete pass listed at least this many objects is named in the run summary (`recommendation: storage_insights`): a Storage Insights inventory report would spare it a listing each pass. Reading one is designed, not built ([ARCHITECTURE.md](ARCHITECTURE.md#large-buckets-s3-inventory)); 0: never named |
| `RESCAN_PERCENT` | 25 | The share of each source's budget that rescans may use: unchanged objects read again because a component that could change what they give changed, such as a reader or the spec ([ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)); 0 turns rescans off |
| `MAX_OBJECTS_PER_RUN` | 0 (off) | A cap on objects per run |
| `STATE_BUCKET` | | The job's own bucket, `gs://<bucket>`: `findings/latest.json`, `findings/runs/<runId>.json`, the cursors and the lock |
| `FINDINGS_HTTPS_URL`, `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | | The core's signed HTTPS push ([DATABASES.md](DATABASES.md#verifying-a-push)); the key is at least 32 characters |
| `FINDINGS_PUBSUB_TOPIC` | | Also publish each part as a message to this topic (`projects/<project>/topics/<topic>`), as the job's service account: `data` is the part as JSON, the attributes are `source` `sensitive-data-scanner`, `type` `Findings v1`, `runId` and `part`. The topic's owner grants the service account Pub/Sub Publisher on that topic only |
| `FINDINGS_FILE` | | Also write the document to a file |
| `SCAN_MODE` | `scanner` | Who finds the data (#55): `scanner`, `vendor` (Sensitive Data Protection's data profiles are imported; nothing is read) or `both` (linked) ([FINDINGS.md](FINDINGS.md#sources-and-modes-18)) |
| `SDP_LOCATIONS`, `SDP_MAX_PROFILES` | `global`, 20000 | Where Sensitive Data Protection's discovery keeps its profiles, and the most imported a run |

At least one of `STATE_BUCKET`, `FINDINGS_HTTPS_URL`, `FINDINGS_PUBSUB_TOPIC`
and `FINDINGS_FILE` is required.

## Deploying

`deploy/gcp` is a Terraform module (Terraform 1.9 or later, the Google
provider pinned by its lock file); a release attaches it as
`sensitive-data-scanner-gcp-terraform.tar.gz`. It needs, from whoever applies
it, Organization Role Administrator (for the custom roles), the IAM admin role
at the scope it binds at, and owner-level rights in the job's project.

Cloud Run pulls images from Artifact Registry, so mirror the release image
there first (or create a remote repository whose upstream is `ghcr.io`), and
give the mirrored path, pinned by digest:

```sh
terraform -chdir=deploy/gcp init
terraform -chdir=deploy/gcp apply \
  -var organization_id=123456789012 -var project_id=acme-sds \
  -var image=us-docker.pkg.dev/acme-sds/ghcr/txp-labs/sensitive-data-scanner-gcp@sha256:<digest> \
  -var findings_https_url=<url> -var findings_hmac_key=<key>
```

| Variable | Default | What |
|---|---|---|
| `organization_id` | (required) | The organization's number. The custom roles are defined here |
| `scope`, `folder_ids`, `project_ids` | `organization` | What the scanner reads, and where its roles are bound: the organization, the folders, or the projects |
| `project_id`, `region` | (required), `us-central1` | Where the job, its service accounts, its state bucket and its schedule go |
| `image` | (required) | The image, pinned by digest (`GCP_IMAGE_DIGEST` in a release) |
| `job_name` | `sds-scanner` | The job, and the service account's name: `sds-scanner@<project>.iam.gserviceaccount.com`, what the IAM database users are created for |
| `schedule`, `task_timeout_seconds` | daily 06:00 UTC, 3600 | When it runs, and for how long at most |
| `site`, `discover` | `org-<organization_id>`, every kind | `SCANNER_SITE`, `DISCOVER` |
| `read_databases`, `read_private_logs`, `read_secrets` | off, off, off | `GCP_DB_READ=all` (with `GCP_DB_PRINCIPAL` the service account), `LOGGING_PRIVATE_READ`, `SECRET_MANAGER_READ`; each adds its own role |
| `gcs_inventory_min_objects` | 1,000,000 | `GCS_INVENTORY_MIN_OBJECTS`: a bucket whose last complete pass listed at least this many objects is named in the run summary (`recommendation: storage_insights`); 0: never |
| `findings_https_url`, `findings_hmac_key` | | The signed push; both go into Secret Manager secrets of the job's own |
| `findings_pubsub_topic` | | The Pub/Sub push; the topic's owner grants the service account Pub/Sub Publisher on it |
| `network`, `subnetwork` | | Direct VPC egress, so the job reaches private IPs (Cloud SQL, AlloyDB) |
| `state_bucket_name`, `runs_retention_days` | `<project_id>-sds-state`, 90 | The job's own bucket, and how long run documents are kept |
| `enable_apis` | true | Enable, in `project_id`, the APIs the job calls: a service account's calls count against its own project |

**What it creates:**
- the scanner's service account, with no key, and a second one for the
  schedule;
- the custom roles, at the organization, bound at the scope;
- a Cloud Run job (one task, no retries) that runs as the scanner's account,
  and a Cloud Scheduler job that starts it;
- the job's own state bucket, with uniform access and public access
  prevention, and run documents deleted after `runs_retention_days`;
- with a push URL, two Secret Manager secrets for it and its key.

**The roles.** Predefined viewer roles are not used: several carry writes
(BigQuery Data Viewer holds `bigquery.tables.export` and
`bigquery.tables.createSnapshot`; Cloud Asset Viewer can start exports). The
scanner gets custom roles instead, each permission named, and
`scanner/tests/test_gcp_template.py` fails on any that does not read:

| Role | Made when | Permissions |
|---|---|---|
| `sdsScannerReader` | always | `cloudasset.assets.searchAllResources`; `storage.objects.get`, `.list`; `bigquery.datasets.get`, `bigquery.tables.get`, `.list`, `.getData`, `bigquery.rowAccessPolicies.list`; `datastore.databases.getMetadata`, `datastore.entities.get`, `.list`; `spanner.databases.get`, `.select`, `.beginReadOnlyTransaction`, `spanner.sessions.create`, `.delete`; `bigtable.clusters.list`, `bigtable.tables.readRows`; `logging.buckets.list`, `logging.logs.list`, `logging.logEntries.list`; `pubsub.subscriptions.list`; `compute.snapshots.list`; `cloudsql.instances.get`, `cloudsql.databases.list`; `alloydb.clusters.get`, `alloydb.instances.list` |
| `sdsScannerPrivateLogs` | `read_private_logs` | `logging.privateLogEntries.list` |
| `sdsScannerSecrets` | `read_secrets` | `secretmanager.secrets.get`, `secretmanager.versions.access` |
| `sdsScannerDatabases` | `read_databases` | `cloudsql.instances.login`, `alloydb.users.login`, `alloydb.clusters.generateClientCertificate`, `serviceusage.services.use` |

Every permission's verb reads (`get`, `list`, `getData`, `getMetadata`,
`searchAllResources`, `readRows`, `select`, `beginReadOnlyTransaction`), or
is `access` or `login` in an opt-in role, or is one of these, each allowed
for its reason:

- `spanner.sessions.create`, `.delete`: a session holds no data, and every
  statement in it is a single-use read-only transaction; the scanner deletes
  its own session after its pass.
- `alloydb.clusters.generateClientCertificate`: returns the cluster's CA,
  which TLS is verified against, with a short-lived client certificate; it
  changes nothing on the cluster.
- `serviceusage.services.use`: lets the calls count against a project's
  quota, which AlloyDB's IAM login needs.

The only predefined roles bound are on the job's own resources:

| Role | On | Why |
|---|---|---|
| Storage Object User | the job's own state bucket | Its findings, cursors and lock |
| Secret Manager Secret Accessor | the job's two push secrets | The push's URL and key |
| Cloud Run Invoker | the job, for the schedule's own account | Starting the job |

The test also holds these: nothing is bound authoritatively (no
`_iam_binding` or `_iam_policy`), no service account key is made, no basic
role appears, every opt-in role is off by default, and every environment
variable the job sets is one the code reads. CI runs `terraform fmt`,
`validate` and `terraform test` (offline plans and applies against a mock
provider) with a pinned, checksum-verified Terraform.

**What it cannot grant:**
- the databases' IAM users and their read grants (the `gcloud` and SQL
  above), and the IAM authentication flags;
- Pub/Sub Publisher on the consumer's topic;
- a network path to private databases beyond Direct VPC egress into the
  subnetwork you name (firewall rules, authorized networks);
- access inside a VPC Service Controls perimeter: add the scanner's service
  account to the perimeter's access level, or its stores stay `network`.

## Running it

```sh
docker build --target gcp -t sensitive-data-scanner-gcp .

python -m sensitive_data_gcp check   # discovery only: reads nothing, sends nothing
python -m sensitive_data_gcp         # scan (the default)
```

`scan` exits 0 when the findings reached every destination (or another run
holds the lock), 1 when a setting is wrong, the run failed or a destination
failed. `check` exits 0 when every kind could be listed, 2 when any could not.
Both write only the scanner's own JSON log lines; Python's logging (google-auth's
and urllib3's) is switched off, since its messages can quote a URL or a
resource name.
