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
  lines, CSV, conversation transcripts and text. Audio, video, images, office
  documents and archives are counted, not read. Every storage class is read
  in place (Nearline, Coldline and Archive objects are online; their
  retrieval fee falls within the run's bytes budget).
- **Incremental.** A pass reads only the objects updated since the previous
  complete pass started (less `skew`), and a pass cut short by the budget
  resumes at the listing page it stopped in.
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

### Cloud SQL and AlloyDB

- **Discovery** is on by default. Cloud Asset Inventory lists every Cloud SQL
  instance and AlloyDB cluster. The Cloud SQL Admin API gives each instance's
  engine, state, addresses, server CA, flags and databases; the AlloyDB API
  gives each cluster's key and instances. A Cloud SQL database is a store,
  `instance/database`; an AlloyDB cluster is one store, whose databases are
  listed by SQL once connected (AlloyDB has no API that lists them). System
  databases are not stores. A stopped instance is `paused`.
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
- **Gaps:**
  - `network`: the job cannot reach the instance. A Cloud Run job reaches a
    private IP through Direct VPC egress (or a Serverless VPC Access
    connector) into the instance's network; a public IP needs the job's
    egress (Cloud NAT) in the instance's authorized networks. A store with
    only a private address is `networkRestricted`.
  - `access_denied`: no IAM database user yet, `cloudsql.instances.login` (or
    `alloydb.users.login`) missing, or a login the database refused.
  - `no_read_path`: Cloud SQL for SQL Server, which has no IAM database
    authentication, and an instance with the IAM authentication flag off.
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
| `DISCOVER` | every kind read by default | Kinds to discover, comma-separated, or `all` |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | | The core's rules: `gcs:prod-*`, `tag:scan=false` (a store's tags are its labels) |
| `DISCOVER_SAMPLING` | | The core's per-store sampling: `[{"match": "tag:env=prod", "samplePercent": 25}]` |
| `SAMPLE_PERCENT` | 100 | The share of objects read, by a stable hash of the name |
| `GCS_MAX_OBJECTS_PER_PREFIX` | 0 (off) | At most n objects per directory per pass |
| `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES` | 20 MiB, 100 MiB | Bytes read from one object, and inflated from one compressed object |
| `COLUMNAR_MAX_ROWS` | 10000 | Rows read from one table file |
| `BIGQUERY_MAX_ROWS` | 1000 | Rows read from one BigQuery table (`tabledata.list`) |
| `DOCUMENTS_MAX_PER_COLLECTION`, `DOCUMENTS_MAX_COLLECTIONS` | 500, 200 | Firestore documents (Datastore entities) read per collection (kind), and collections (kinds) per database |
| `BIGTABLE_MAX_ROWS` | 1000 | Rows read from one Bigtable table |
| `GCP_DB_READ` | off | The database kinds read: `all`, or `cloudsql_postgresql`, `cloudsql_mysql`, `alloydb` (or `postgresql`, `mysql`, `alloy`) |
| `GCP_DB_PRINCIPAL` | | The service account's email; its IAM database users are logged in as. Required to read |
| `DB_SCHEMAS`, `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES` | all but the system's, 1000, 500 | As the databases runner's; Spanner too |
| `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS` | 60, 15 | Per statement, per connection |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | 20000, 2 GiB, 3000 | The run's budget, shared among the stores |
| `MAX_OBJECTS_PER_RUN` | 0 (off) | A cap on objects per run |
| `STATE_BUCKET` | | The job's own bucket, `gs://<bucket>`: `findings/latest.json`, `findings/runs/<runId>.json`, the cursors and the lock |
| `FINDINGS_HTTPS_URL`, `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | | The core's signed HTTPS push ([DATABASES.md](DATABASES.md#verifying-a-push)); the key is at least 32 characters |
| `FINDINGS_PUBSUB_TOPIC` | | Also publish each part as a message to this topic (`projects/<project>/topics/<topic>`), as the job's service account: `data` is the part as JSON, the attributes are `source` `sensitive-data-scanner`, `type` `Findings v1`, `runId` and `part`. The topic's owner grants the service account Pub/Sub Publisher on that topic only |
| `FINDINGS_FILE` | | Also write the document to a file |

At least one of `STATE_BUCKET`, `FINDINGS_HTTPS_URL`, `FINDINGS_PUBSUB_TOPIC`
and `FINDINGS_FILE` is required.

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
