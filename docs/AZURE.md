# Azure

The Azure scanner runs **in your own Azure tenant**, as a Container Apps job
with a **system-assigned managed identity**. It discovers the data stores of
every subscription under a management group, reads them **read-only**, and
sends **findings only, never values** ([FINDINGS.md](FINDINGS.md), schema
1.6). It is the same detection, findings contract, budgets, sampling, readers
and coverage summary as the AWS scanner (the cloud-neutral core,
`scanner/core`), in its own package (`scanner/azure`, `sensitive_data_azure`)
and its own image (`docker build --target azure`).

- **No secret.** Every request is signed by the job's managed identity
  through `azure-identity`'s `DefaultAzureCredential`. No key, connection
  string or SAS is configured or created.
- **Read-only.** The identity holds Reader and the data-reader roles below,
  and nothing that can write, except to the job's own state container.
- **Discovery across the management group.** One Azure Resource Graph query
  per kind lists every store in every subscription under the management group
  (or the subscriptions you name).
- **Only findings leave.** Store, container, blob and column names are masked
  like S3 keys; resource IDs are hashed (`resourceIdHash`); no value is ever
  written, logged or sent.
- **Every store it cannot read is in the run summary with a reason**:
  `access_denied` (a role is missing), `network` (the store's firewall or
  private endpoint keeps the job out), `self`, `denied` or `not_allowed` (your
  rules), `deferred` (the budget; the next run starts there).
- **Budgets and sampling**: the core's run budget (items, bytes, time, and a
  cap on blobs), a stable per-name sample, and at most n blobs per directory.

## Stores

| Kind (`DISCOVER`) | Store | Read with | Default |
|---|---|---|---|
| `azure_blob` (`blob`, `adls`) | A Blob Storage or ADLS Gen2 container, `account/container` | Reader (the account's containers and encryption scopes) and Storage Blob Data Reader (List Blobs, ranged Get Blob) | read |
| `azure_sql` (`sql`) | An Azure SQL database, `server/database` | Reader (discovery, TDE); a contained user for the identity with `db_datareader` (below) | discovered; read with `AZURE_DB_READ` |
| `azure_sql_mi` (`sqlmi`) | A SQL Managed Instance database, `instance/database` | the same | discovered; read with `AZURE_DB_READ` |
| `azure_postgresql` (`postgresql`) | A PostgreSQL flexible server's database, `server/database` | Reader (discovery, `dataEncryption`); an Entra role for the identity with SELECT (below) | discovered; read with `AZURE_DB_READ` |
| `azure_mysql` (`mysql`) | A MySQL flexible server's database, `server/database` | Reader; an Entra user for the identity with SELECT (below) | discovered; read with `AZURE_DB_READ` |
| `synapse_sql` (`synapse`) | A Synapse dedicated SQL pool, `workspace/pool` | Reader; a user for the identity with `db_datareader` (below) | discovered; read with `AZURE_DB_READ` |
| `cosmosdb` (`cosmos`) | A Cosmos DB for NoSQL container, `account/database/container` | Reader (the account's databases and containers) and the **Cosmos DB Built-in Data Reader** data-plane role on the account | read |
| `cosmosdb` (`account/*`, `api`) | An RU account on the MongoDB, Cassandra, Gremlin or Table API | Reader | gap: `no_read_path` (only the account's keys read it, and they can write) |
| `cosmosdb_mongo` (`mongo`) | A Cosmos DB for MongoDB vCore cluster, `cluster/*` | Reader; a Microsoft Entra ID user for the identity with a read-only role | discovered; read with `AZURE_DB_READ` |
| `azure_table` (`table`) | A Table Storage table, `account/table` | Reader (the account's tables) and Storage Table Data Reader | read |
| `azure_queue` (`queue`) | A Queue Storage queue, `account/queue` | Reader (the account's queues) and Storage Queue Data Reader, **peek only** | read |
| `log_analytics` (`logs`, `monitor`) | A Log Analytics workspace (Azure Monitor logs) | Log Analytics Reader (KQL queries) and Reader (the tables' plans) | read |

### Blob Storage and ADLS Gen2

- **Discovery.** Resource Graph lists the storage accounts with their
  encryption, network rules and whether the hierarchical namespace is on.
  Each account's containers and encryption scopes come from Azure Resource
  Manager with Reader, so a container shows in the run summary even when the
  account's firewall keeps the job away from its data. A FileStorage account
  has no Blob service and is not listed. The job's own container is `self`.
- **Reading** is the Blob service's data plane with Storage Blob Data Reader:
  `List Blobs` in name order, then ranged `Get Blob`. Blobs are read the way
  the AWS scanner reads S3 objects, with the core's readers
  (`sensitive_data_core.scan.objects`): Parquet and ORC by column through
  ranged reads (footer first), Avro, gzip and zstd inflated, JSON and JSON
  lines, CSV, conversation transcripts and text. Audio, video, images, office
  documents and archives are counted, not read. ADLS Gen2 is read through the
  same Blob endpoint; its directories are zero-length blobs and are skipped.
- **Incremental.** A pass reads only the blobs modified since the previous
  complete pass started (less `skew`), and a pass cut short by the budget
  resumes at the listing page it stopped in.
- **Never a write.** Nothing is leased, copied, rehydrated or tiered: an
  Archive-tier blob would need a rehydration, so it is counted as skipped
  `archive_tier`. A blob under a customer-provided key (CPK) cannot be read
  without that key and is counted in `kmsDenied`.
- **Encryption** (`atRestEncryption`). Azure Storage encrypts every blob at
  rest. A finding says under which key: the blob's own encryption scope, else
  its container's default scope, else the account's. A Microsoft-managed key
  is `service_managed`; a key in Key Vault or Managed HSM is
  `customer_managed_key`, named only by `atRestKeyHash`, the SHA-256 of the
  key's versionless identifier in lower case. To match yours:

  ```sh
  printf %s https://<vault>.vault.azure.net/keys/<key-name> | tr A-Z a-z | shasum -a 256
  ```

### Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible servers, Synapse SQL pools

- **Discovery** is on by default. Resource Graph lists every database, and
  Resource Manager (Reader) supplies what it does not have: a flexible
  server's databases, and a SQL server's or Managed Instance's TDE protector.
  System databases are not stores. A paused serverless database or pool, or
  a stopped server, is `paused`: connecting would resume it and bill for it.
- **Reading is opt-in** (`AZURE_DB_READ`: `all`, or kinds such as
  `sql,postgresql`). Each database needs a user for the job's identity first,
  created by you. Until then every run would add a failed Entra login to your
  audit logs, and possibly a Defender alert.
- **As the managed identity, with an Entra token.** No password exists.
  - SQL connections pass the identity to `mssql-python` as its token provider,
    with `Encrypt=yes`, `TrustServerCertificate=no` and
    `ApplicationIntent=ReadOnly`, which routes to a readable secondary where
    the tier has one.
  - PostgreSQL and MySQL take the token (audience
    `https://ossrdbms-aad.database.windows.net`) as the password, over TLS
    with the server's certificate verified, as the user
    `AZURE_DB_PRINCIPAL`: the identity's name.
- **The user is checked first**, with the core's allow list of reads, as the
  databases runner does ([DATABASES.md](DATABASES.md)). A user that can write
  is refused as `db_user_can_write` with its privileges by name
  (`writeGrants`). One whose privileges cannot be read is
  `grants_unverifiable`. Nothing is read from either.
- **The sample** is the core's: the base tables, then `SELECT TOP (n) *`
  (SQL) or `SELECT * ... LIMIT n` with quoted identifiers, in a read-only
  transaction where the engine has one, always rolled back. It resumes by
  table when the budget cuts it short. A finding is a `store_field` with the
  kind as `service`, the server as `store`, then `database`, `schema.table`
  and the column.
- **Gaps:**
  - `network`: public access is off with no private path from the job, or a
    firewall does not admit it. The job's egress must reach the server, for
    example through a private endpoint in the job's virtual network.
  - `access_denied`: no user for the identity yet, or a login the database
    refused.
  - `no_read_path`: a PostgreSQL server with Entra authentication off.
  - `driver_missing`: an image without the driver.
  - `no_grant`: a user that can see no table.
- **Encryption.** A SQL server's or Managed Instance's TDE protector is
  `service_managed` for `ServiceManaged`, and `customer_managed_key` for an
  `AzureKeyVault` key (hashed). A database-level customer key takes
  precedence. TDE off is `unknown`. A flexible server's `dataEncryption` is
  `SystemManaged` or `AzureKeyVault`. A Synapse workspace's customer key is
  `customer_managed_key`; without one, the pool's TDE decides.

#### Creating the identity's user

The identity's name is the Container Apps job's name, for a system-assigned
identity. Run these as the server's Entra administrator.

Azure SQL database and Synapse dedicated SQL pool, in each database or pool:

```sql
CREATE USER [sds-scanner-job] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [sds-scanner-job];  -- Synapse: EXEC sp_addrolemember 'db_datareader', 'sds-scanner-job';
```

SQL Managed Instance, in each database (or `CREATE LOGIN ... FROM EXTERNAL
PROVIDER` once, then `CREATE USER ... FROM LOGIN`):

```sql
CREATE USER [sds-scanner-job] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [sds-scanner-job];
```

PostgreSQL flexible server (Entra authentication on), in the `postgres`
database, then in each database to read:

```sql
SELECT * FROM pgaadauth_create_principal('sds-scanner-job', false, false);
GRANT pg_read_all_data TO "sds-scanner-job";  -- or SELECT on the schemas to read
-- Before PostgreSQL 15, PUBLIC may create in `public`, which the check refuses:
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

MySQL flexible server (with an Entra administrator):

```sql
CREATE AADUSER 'sds-scanner-job';
GRANT SELECT ON `shop`.* TO 'sds-scanner-job'@'%';
```

Grant nothing else: `db_owner`, `db_datawriter`, `db_ddladmin`, any database
permission but `CONNECT`, `SELECT`, `SHOWPLAN`, `REFERENCES` and `VIEW ...`,
and any privilege but reads on PostgreSQL and MySQL are refused. A role you
cannot narrow is refused rather than read.

### Cosmos DB

- **NoSQL** accounts are read by default. Resource Manager (Reader) lists
  their databases and containers. Each container is read with one query as
  the job's identity, `SELECT TOP @n * FROM c` (`COSMOS_MAX_ITEMS`, 1000),
  across partitions. Items are read by top-level property; the system
  properties (`_rid`, `_self`, `_etag`, `_attachments`, `_ts`) are not. A
  finding is a `store_field` with `readBy: query`.
- The identity needs the **Cosmos DB Built-in Data Reader** role on each
  account. It is a Cosmos DB role assignment, not an Azure RBAC one, so it
  cannot be given at the management group. For each account:

  ```sh
  az cosmosdb sql role assignment create --account-name <account> --resource-group <group> \
    --role-definition-id 00000000-0000-0000-0000-000000000001 \
    --principal-id <the job's principal id> --scope /
  ```

  Without it, a container is `access_denied`. A container behind the account's
  firewall is `network`.
- **The other APIs on an RU account** (MongoDB, Cassandra, Gremlin, Table)
  have no Entra data-plane read. Reading them would take the account's keys,
  and `listKeys` returns keys that can write. Each such account is one store
  (`account/*`), reported `no_read_path` with its `api`.
- **MongoDB vCore** clusters support Microsoft Entra ID. With `AZURE_DB_READ`
  naming `cosmosdb_mongo`, a cluster is read as the identity (MONGODB-OIDC),
  as the databases runner reads MongoDB: the user is checked first against
  the core's allow list of MongoDB reads, then `$sample` runs per collection.
  Add the identity as the cluster's Microsoft Entra ID user with a read-only
  role (`readAnyDatabase`). A cluster without Entra authentication is
  `no_read_path`.
- **Encryption.** An account's or cluster's key in Key Vault is
  `customer_managed_key` (hashed). Otherwise Cosmos DB's own keys apply,
  which is `service_managed`.

### Table Storage and Queue Storage

- **Tables** are read with Storage Table Data Reader: the first
  `TABLE_MAX_ENTITIES` (1000) entities of each table, by property. A
  finding names the property as its `field`.
- **Queues** are read with Storage Queue Data Reader by **Peek Messages
  only**: up to 32 messages at the front, which stay visible to their
  consumers with their dequeue count unchanged. The scanner never gets,
  dequeues, updates or deletes a message. A base64-encoded message is decoded
  when that gives text. A finding is `field: messages`, `readBy: peek`.
- **Encryption.** A table or queue is under the account's key when the
  account's encryption covers that service with it (`keyType: Account`), and
  otherwise under a key Microsoft manages.

### Azure Monitor logs (Log Analytics)

- Every Log Analytics workspace in scope is read by default with **Log
  Analytics Reader**, as the job's identity, through the Log Analytics query
  API. Workspace-based Application Insights writes to its workspace, and is
  read there. Diagnostic settings that archive to a storage account are read
  as blobs.
- `Usage` says which tables took data in the window (`LOGS_LOOKBACK_DAYS`,
  1), so an empty table costs nothing. Each of those is sampled with one
  query, `['<table>'] | where TimeGenerated > ago(Nd) | take n`
  (`LOGS_MAX_ROWS_PER_TABLE`, 500). The table name is quoted so that nothing
  in it is KQL. Rows are read by column, format `kql`.
- A table on the **Basic or Auxiliary plan** is billed per query, so it is
  not read. It is counted as skipped `billed_plan`; the plans come from
  Resource Manager with Reader.
- A workspace whose tables the budget does not finish resumes at its next
  table. A workspace with query access from public networks off is
  `networkRestricted`; when the job is not on its private link, it is
  `network`.
- **Encryption.** A workspace linked to a dedicated cluster with a Key Vault
  key is `customer_managed_key` (hashed); otherwise Azure Monitor's own keys
  apply, `service_managed`.

## Findings

An Azure document says `"platform": "azure"` and names its `site`
(`SCANNER_SITE`) instead of an AWS account and region. Every finding and
every store in the run summary names its `subscription`, its `resourceGroup`
(masked like a key) and `resourceIdHash`, the SHA-256 of its resource ID in
lower case, so you can match it without the ID being written:

```sh
printf %s "/subscriptions/<id>/resourceGroups/<group>/providers/Microsoft.Storage/storageAccounts/<name>" \
  | tr A-Z a-z | shasum -a 256
```

A blob's finding is the `blob_object` resource (`account`, `container`,
`blob`, `versionId`, and `column` for a table file). Its `link` opens the
storage account in the Azure portal, and is `null` when a name it carries had
to be masked.

## Settings

| Setting | Default | What |
|---|---|---|
| `SCANNER_SITE` | (required) | A name for this deployment, as findings name it (the management group, say): lower case, digits, `.`, `_`, `-` |
| `AZURE_MANAGEMENT_GROUP` | | Discover every subscription under this management group |
| `AZURE_SUBSCRIPTIONS` | | Or these subscriptions, comma-separated ids |
| `DISCOVER` | every kind read by default | Kinds to discover, comma-separated, or `all` |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | | The core's rules: `azure_blob:prodlake/*`, `tag:scan=false`, `blob:tag:team=data*` (tags are the storage account's) |
| `DISCOVER_SAMPLING` | | The core's per-store sampling: `[{"match": "tag:env=prod", "samplePercent": 25}]` |
| `SAMPLE_PERCENT` | 100 | The share of blobs read, by a stable hash of the name |
| `BLOB_MAX_OBJECTS_PER_PREFIX` | 0 (off) | At most n blobs per directory per pass |
| `MAX_OBJECT_BYTES`, `MAX_INFLATED_BYTES` | 20 MiB, 100 MiB | Bytes read from one blob, and inflated from one compressed blob |
| `COLUMNAR_MAX_ROWS` | 10000 | Rows read from one table file |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | 20000, 2 GiB, 3000 | The run's budget, shared among the stores |
| `MAX_OBJECTS_PER_RUN` | 0 (off) | A cap on blobs per run |
| `STATE_CONTAINER_URL` | | The job's own container, `https://<account>.blob.core.windows.net/<container>`: `findings/latest.json`, `findings/runs/<runId>.json`, the cursors and the lock |
| `FINDINGS_HTTPS_URL`, `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | | The core's signed HTTPS push ([DATABASES.md](DATABASES.md#verifying-a-push)); the key is at least 32 characters |
| `FINDINGS_EVENT_GRID_ENDPOINT` | | Also push each part as a CloudEvent (`source` `sensitive-data-scanner`, `type` `Findings v1`) to an Event Grid topic, as the job's identity; the topic's owner grants it `EventGrid Data Sender` on that topic |
| `FINDINGS_FILE` | | Also write the document to a file |
| `AZURE_DB_READ` | off | The database kinds read: `all`, or `azure_sql`, `azure_sql_mi`, `azure_postgresql`, `azure_mysql`, `synapse_sql`, `cosmosdb_mongo` (or `sql`, `sqlmi`, `postgresql`, `mysql`, `synapse`, `mongo`) |
| `AZURE_DB_PRINCIPAL` | | The identity's name as a PostgreSQL or MySQL user; required to read them |
| `DB_SCHEMAS`, `DB_MAX_ROWS_PER_TABLE`, `DB_MAX_TABLES` | all but the system's, 1000, 500 | As the databases runner's |
| `DB_STATEMENT_TIMEOUT_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS` | 60, 15 | Per statement, per connection |
| `TABLE_MAX_ENTITIES`, `COSMOS_MAX_ITEMS` | 1000, 1000 | Entities sampled per table; items per Cosmos DB container |
| `LOGS_LOOKBACK_DAYS`, `LOGS_MAX_ROWS_PER_TABLE` | 1, 500 | Log Analytics: the window sampled, and rows per table |

At least one of `STATE_CONTAINER_URL`, `FINDINGS_HTTPS_URL`,
`FINDINGS_EVENT_GRID_ENDPOINT` and `FINDINGS_FILE` is required.

## Running it

```sh
docker build --target azure -t sensitive-data-scanner-azure .

python -m sensitive_data_azure check   # discovery only: reads nothing, sends nothing
python -m sensitive_data_azure         # scan (the default)
```

`scan` exits 0 when the findings reached every destination (or another run
holds the lock), 1 when a setting is wrong, the run failed or a destination
failed. `check` exits 0 when every kind could be listed, 2 when any could not.
Both write only the scanner's own JSON log lines; the Azure SDK's logging is
switched off, since its messages can quote a URL or a resource name.
