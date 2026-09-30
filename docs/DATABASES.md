# Databases hosted anywhere

The databases runner is a container you run **inside your own network**:
on-premises, in any cloud, or next to a managed database service. It
connects to each database with a **read-only** user, samples its tables or
collections, and sends **findings only, never values**
([FINDINGS.md](FINDINGS.md), schema 1.4). It is the same detection, findings
contract, budget and coverage summary as the AWS scanner (the cloud-neutral
core, `scanner/core`), in its own package (`scanner/db`,
`sensitive_data_db`) and its own image target.

## Engines

| Engine | Connection string | Driver (extra) | Read-only enforced by | Refused when the user has |
|---|---|---|---|---|
| PostgreSQL (and managed: RDS, Aurora, Azure, Cloud SQL, AlloyDB, ...) | `postgresql://user:password@host:5432/database?sslmode=require` | psycopg 3 (`postgresql`) | `default_transaction_read_only=on` for the session, `SET TRANSACTION READ ONLY`, rollback | superuser, CREATEROLE, CREATEDB, CREATE on the database or any schema, INSERT, UPDATE, DELETE or TRUNCATE on any table or view |
| MySQL and MariaDB | `mysql://user:password@host:3306/database` (`mariadb://` too) | PyMySQL (`mysql`) | `SET SESSION TRANSACTION READ ONLY`, `START TRANSACTION READ ONLY`, rollback | any privilege but SELECT, SHOW VIEW, USAGE, SHOW DATABASES, PROCESS and REPLICATION CLIENT, directly **or through any role granted**, active or not; `WITH GRANT OPTION` |
| SQL Server (Azure SQL, Managed Instance) | `sqlserver://user:password@host:1433/database?encryption=require` | pymssql (`sqlserver`) | rollback (SQL Server has no read-only transaction) | sysadmin, db_owner, db_datawriter, db_ddladmin; any database permission but CONNECT, SELECT, SHOWPLAN, REFERENCES and `VIEW ...`; INSERT, UPDATE, DELETE or ALTER on any table or view |
| Oracle | `oracle://user:password@host:1521/service_name` | python-oracledb, thin mode, no Oracle Client (`oracle`) | `SET TRANSACTION READ ONLY`, rollback | any system privilege but CREATE SESSION, ALTER SESSION, SELECT/READ ANY TABLE, SELECT ANY DICTIONARY, SELECT ANY SEQUENCE, SET CONTAINER; INSERT, UPDATE, DELETE, ALTER, INDEX or UNDER on any object (to the user, its roles or PUBLIC); owning a table |
| MongoDB (Atlas included) | `mongodb://user:password@h1:27017,h2:27017/database?replicaSet=rs0` or `mongodb+srv://...` | PyMongo (`mongodb`) | reads only (`$sample`), from a secondary when there is one | any action but the read actions (`find`, `listCollections`, `listDatabases`, `collStats`, ...); access control off |
| Snowflake | `snowflake://user:password@<account>/<database>?warehouse=WH&role=READER` | snowflake-connector-python (`snowflake`) | rollback, statement timeout | ACCOUNTADMIN, SYSADMIN, SECURITYADMIN, USERADMIN or ORGADMIN; any privilege but USAGE, SELECT, REFERENCES, MONITOR, OPERATE, READ and IMPORTED PRIVILEGES, on any role the user holds or those roles hold |
| Databricks SQL (Unity Catalog) | `databricks://token:<token>@<workspace host>/<http path>?catalog=main` | databricks-sql-connector (`databricks`) | SELECTs only (no transactions) | in the catalog: any privilege but SELECT, USE CATALOG, USE SCHEMA, BROWSE, READ VOLUME, READ FILES, EXECUTE, to the user or a group it is in; owning a table or schema |

- **The check comes first.** Before any table is read, the runner lists the
  user's privileges from the database's own catalog. Each list above is an
  **allow list of reads**: anything else counts as a write, so a privilege the
  scanner does not know is refused rather than waved through. A user that can
  write is reported as `db_user_can_write` with its write privileges by name
  (`writeGrants`), and nothing is read. A user whose privileges cannot be read
  is `grants_unverifiable`, and nothing is read either.
- **The sample** is the core's sampled SQL pass: the base tables from
  `information_schema` (Oracle: `all_tables` of the schemas Oracle does not
  maintain), then `SELECT * FROM "schema"."table" LIMIT n` (SQL Server
  `SELECT TOP (n)`, Oracle `FETCH FIRST n ROWS ONLY`) with quoted
  identifiers. Nothing else is sent. MongoDB: `$sample` of `n` documents per
  collection, views and `system.*` skipped; ids, binary and other non-text
  BSON types are not read. The database named in the URL is the only one
  read; with none, every database but `admin`, `local` and `config` is.
  `DB_SCHEMAS` does not apply to MongoDB.
- **MySQL's read-only question.** MySQL has no read-only role, and the RDS
  Data API cannot check a user's grants. Here the runner reads `SHOW GRANTS`
  for the user and for every role granted to it (MySQL 8's `USING`, or
  MariaDB's `SHOW GRANTS FOR <role>`), and refuses anything but reads, even
  in a role the user has not activated, since it could `SET ROLE`. The
  session and each transaction are read-only as well.

Redis snapshots are read by the AWS scanner when exported to S3 (an `.rdb`
file); a Redis server itself is not read here.

## Quick start

```sh
docker build --target db -t sensitive-data-scanner-db .

docker run --rm \
  -e SCANNER_SITE=dc-1 \
  -e DATABASE_URL_HR='postgresql://scanner_ro:...@10.0.4.12:5432/hr?sslmode=require' \
  -e FINDINGS_FILE=/out/findings.json -v "$PWD/out:/out" \
  sensitive-data-scanner-db            # scan (the default)

docker run --rm ... sensitive-data-scanner-db check   # connect and check the users only
```

`scan` exits 0 when the findings reached every destination, 1 when a setting
is wrong or a destination failed. `check` reads and sends nothing: it exits 0
when every database would be read, 2 when any would not. Both write only the
scanner's own JSON log lines (the drivers' logging is switched off).

## Settings

| Setting | Default | What |
|---|---|---|
| `SCANNER_SITE` | (required) | Where this runs, as findings name it: lower case, digits, `.`, `_`, `-` |
| `DATABASE_URL_<NAME>` | | A connection string. `<NAME>`, lower-cased, names the store in findings |
| `DATABASE_URL_FILE_<NAME>` | | A file holding one (a mounted secret) |
| `DATABASE_URLS_DIR` | | A directory of files, one connection string each, named by the store; dot files are skipped (a Kubernetes secret volume) |
| `DISCOVER_ALLOW`, `DISCOVER_DENY` | | Rules by store name, optionally per engine: `postgresql:hr-*`, `mongodb:*` |
| `DB_SCHEMAS` | all but the system's | Schemas to read, comma-separated (not MongoDB) |
| `DB_MAX_ROWS_PER_TABLE` | 1000 | Rows (MongoDB: documents) sampled per table |
| `DB_MAX_TABLES` | 500 | Tables (collections) per database |
| `DB_STATEMENT_TIMEOUT_SECONDS` | 60 | Per statement |
| `DB_CONNECT_TIMEOUT_SECONDS` | 15 | Per connection |
| `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS` | 20000, 2 GiB, 3600 | The run's budget: tables, bytes, time. A database it does not reach is `deferred` (`budget`) |
| `OBJECT_INDEX`, `INDEX_MAX_OBJECTS`, `RESCAN_PERCENT` | on, 10,000,000, 25 | With `STATE_LOCATION`: the table index beside it, which skips tables unchanged since their last read ([below](#tables-unchanged-since-the-last-read)); the most tables one database indexes; and the share of the budget that rescans may use |
| `FINDINGS_HTTPS_URL` | | Push each part of the document here (HTTPS only) |
| `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | | The key it is signed with, at least 32 characters |
| `FINDINGS_EVENT_BUS_ARN` | | Push to an EventBridge bus, as the AWS scanner does (the container needs AWS credentials) |
| `FINDINGS_FILE` | | Write the whole document to a file |
| `STATE_LOCATION` | none | Where the next run's starting database is kept, so the ones a run's budget did not reach go first next time ([State across runs](#state-across-runs)): an absolute path (or `file:///...`) on a mounted volume, `s3://bucket/key` (the `aws` extra), or an HTTPS URL (GET, and a PUT signed with `FINDINGS_HMAC_KEY`) |

At least one destination is required. **Connection strings and the key are
secrets:** keep them in your secret store and hand them to the container as
an environment variable or a mounted file. The runner never logs, writes or
sends them, and its error messages name a setting by a fixed code
(`{"event":"run.failed","error":"unknown_scheme"}`), never by its value.

## What it reports

A findings document with `platform: "database"` and your `site` in place of
an AWS account and region. Each column (MongoDB: top-level field) with
sensitive data is a `store_field` finding: `service` is the engine, `store`
your name for the database, `table` is `schema.table`. The run summary lists
every database, read or not, and why:

| Status, reason | Meaning |
|---|---|
| `scanned` | Read |
| `skipped`, `db_user_can_write` | The user can write (`writeGrants` names how); nothing was read |
| `skipped`, `grants_unverifiable` | The user's privileges could not be read; nothing was read |
| `skipped`, `driver_missing` | The image has no driver for the engine (a slim build) |
| `skipped`, `read_not_configured` | The connection string names no database (MySQL) |
| `skipped`, `no_grant` | The user can see no table |
| `skipped`, `denied` or `not_allowed` | `DISCOVER_DENY` or `DISCOVER_ALLOW` |
| `deferred`, `budget` | The run's budget ran out first |
| `error`, `error` | The connection or the table listing failed; `error` names the exception class |

Each finding, and each database in the run summary, also says what storage
encryption the database reports about itself (`atRestEncryption`, findings
schema 1.5), read after the user check with catalog queries only:

| Engine | Reported as |
|---|---|
| SQL Server, Azure SQL | TDE on (`sys.databases.is_encrypted`, readable by every login): `customer_managed_key`, except Azure SQL Database and Managed Instance with the service's certificate (`service_managed`). The encryptor comes from `sys.dm_database_encryption_keys` (it needs `VIEW DATABASE STATE`; without it, Azure is `unknown`). TDE off: `unknown` |
| MySQL, MariaDB | Every base table of the database created encrypted (`ENCRYPTION='Y'`, or MariaDB's `ENCRYPTED=YES`, in `information_schema.TABLES`): `customer_managed_key`, the keyring's key. Otherwise `unknown` (a server-wide default is not seen) |
| Snowflake | `service_managed`: Snowflake encrypts all data. Tri-Secret Secure is not detected |
| MongoDB | Atlas (every host under `mongodb.net`): `service_managed`. Self-managed: `unknown` |
| PostgreSQL, Oracle, Databricks | `unknown`: PostgreSQL has no TDE; Oracle's per-tablespace TDE and a lakehouse's cloud storage are not read |

`unknown` is never `none`: a database cannot see the disk or volume under it.
A `card` finding under `service_managed` or `customer_managed_key`, and every
`cvv` finding, carries a `pciNote` for your QSA ([FINDINGS.md](FINDINGS.md#at-rest-encryption-and-pci-dss-notes-15)).

### State across runs

Without `STATE_LOCATION`, each run samples afresh in the configured order, so
a database the run's budget never reaches is `deferred` every time. With it,
the run reads a small JSON document first and writes it last:

```json
{"version": 1, "site": "dc-1", "rotation": "orders"}
```

`rotation` is the first database the budget left `deferred`, and the next
run starts with it, so every database is read over a few runs. The document
holds the name you gave a database and nothing else: no value, no connection
string, no finding.

| `STATE_LOCATION` | Reads and writes with |
|---|---|
| `/state/sds-state.json` or `file:///state/sds-state.json` | The file, replaced atomically (mount a small volume: a Kubernetes `PersistentVolumeClaim`, an EFS access point for ECS) |
| `s3://bucket/key` | `s3:GetObject` and `s3:PutObject` on that key, with the credentials the container has (the `aws` extra) |
| `https://...` | `GET`, and a `PUT` with `X-SDS-Signature` over the body under `FINDINGS_HMAC_KEY`, verified [as a push is](#verifying-a-push) |

A state that is missing, unreadable, not JSON, or another site's counts as
none: the run starts from the top. One that cannot be written is logged by
its error name, and the findings still go out.

### Tables unchanged since the last read

With `STATE_LOCATION`, the runner also keeps a **table index** beside the
state (`<location>.index/`, or `<URL>.index/<file>` over HTTPS with the same
signed PUTs; [#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)).
The document then holds one more thing, `indexSalt`, the random key of the
index's hashes. From the second run on, the runner asks each database what
changed, with one catalog query and no data:

| Engine | What it asks |
|---|---|
| PostgreSQL | `pg_stat_user_tables`: rows inserted, updated, deleted and live, and the last analyze. On a primary only: a replica's counters do not move, so a replica's tables are always sampled |
| MySQL, MariaDB | `information_schema.tables.UPDATE_TIME`. InnoDB keeps it in memory, so after a restart a table is sampled until it changes again |
| SQL Server | The latest `sys.dm_db_index_usage_stats.last_user_update` of the table's indexes (it needs `VIEW DATABASE STATE`, or `VIEW DATABASE PERFORMANCE STATE` on Azure SQL; without it, every table is sampled) |
| Oracle | `ALL_TAB_MODIFICATIONS` (inserts, updates, deletes, truncation, time) and `ALL_TABLES.LAST_ANALYZED` |
| Snowflake, Databricks | `information_schema.tables.last_altered` |
| MongoDB | Nothing cheap: every collection is sampled |

The rules:

- A table whose marker is the one recorded at its last read is not sampled
  again, and its findings are carried from the last run (`findings.json.gz`
  beside the index: findings only, never a value). Coverage counts it as
  listed and not eligible.
- A table whose marker is unknown, or differs, is sampled.
- A table not sampled for 7 days is sampled whatever its marker says, in case
  a marker missed a change (a statistics setting, a restart).
- A table read with a component that has since changed and could change its
  result is sampled again within `RESCAN_PERCENT` of the budget
  ([ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)).
- A database taken out of the configuration loses its carried findings and
  its table index together, so if it is added back its tables are sampled
  again and its findings return. An index the state location would not let
  the runner remove is named in the document (`forget`) and removed on the
  next run.
- A catalog view the user may not read means no markers, and every table is
  sampled, as before. `OBJECT_INDEX=off` turns this off.

## Where findings go

- **HTTPS, signed.** Each part is a `POST` of JSON (the findings document, or
  a slice of it with `part` and `parts`, split like the EventBridge events),
  with `X-SDS-Part: 1/3` and `X-SDS-Signature: t=<unix time>,v1=<hex>`,
  where `v1` is HMAC-SHA256 under the shared key of `<t>.` followed by the
  exact body. A 5xx, a 429 or a network error is retried twice; any other
  4xx is not.
- **EventBridge:** `source` `sensitive-data-scanner`, `detail-type`
  `Findings v1`, as from AWS.
- **A file:** the whole document, replaced atomically.

### Verifying a push

```python
import hashlib, hmac, time

def verify(key: bytes, header: str, body: bytes, tolerance: int = 300) -> bool:
    fields = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    t, v1 = fields.get("t", ""), fields.get("v1", "")
    if not t.isdigit() or abs(time.time() - int(t)) > tolerance:
        return False
    expected = hmac.new(key, t.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
```

Verify against the raw body before parsing it, and reject a replayed
timestamp.

## A read-only user, per engine

**PostgreSQL before 15** gives every role `CREATE` on the `public` schema
through `PUBLIC`, so the user check refuses every user there
(`writeGrants`: `public_schema_create`, `schema_create`), on purpose: a user
that can create a table can write. Run this once, as the database owner or
a superuser, and the check passes:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

PostgreSQL 15 and later revoke it by default. The same check refuses such a
user in the AWS scanner's opt-in RDS Data API mode.

```sql
-- PostgreSQL (before 15, first: REVOKE CREATE ON SCHEMA public FROM PUBLIC;)
CREATE ROLE scanner_ro LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE app TO scanner_ro;
GRANT USAGE ON SCHEMA public TO scanner_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO scanner_ro;   -- or: GRANT pg_read_all_data TO scanner_ro;

-- MySQL, MariaDB
CREATE USER 'scanner_ro'@'%' IDENTIFIED BY '...';
GRANT SELECT, SHOW VIEW ON app.* TO 'scanner_ro'@'%';

-- SQL Server, Azure SQL
CREATE LOGIN scanner_ro WITH PASSWORD = '...';   -- Azure SQL: CREATE USER scanner_ro WITH PASSWORD = '...'
CREATE USER scanner_ro FOR LOGIN scanner_ro;
ALTER ROLE db_datareader ADD MEMBER scanner_ro;
GRANT VIEW DATABASE STATE TO scanner_ro;               -- Azure SQL: GRANT VIEW DATABASE PERFORMANCE STATE TO scanner_ro;

-- Oracle
CREATE USER scanner_ro IDENTIFIED BY "...";
GRANT CREATE SESSION, SELECT ANY TABLE TO scanner_ro;   -- or SELECT on each table

-- Snowflake
CREATE ROLE scanner_reader;
GRANT USAGE ON WAREHOUSE scan_wh TO ROLE scanner_reader;
GRANT USAGE ON DATABASE app TO ROLE scanner_reader;
GRANT USAGE ON ALL SCHEMAS IN DATABASE app TO ROLE scanner_reader;
GRANT SELECT ON ALL TABLES IN DATABASE app TO ROLE scanner_reader;
CREATE USER scanner DEFAULT_ROLE = scanner_reader;
GRANT ROLE scanner_reader TO USER scanner;

-- Databricks (Unity Catalog), for the service principal the token belongs to
GRANT USE CATALOG, USE SCHEMA, SELECT ON CATALOG main TO `scanner`;
```

On SQL Server, `VIEW DATABASE STATE` (on Azure SQL Database, `VIEW DATABASE
PERFORMANCE STATE`) lets the scanner read each table's change marker,
`sys.dm_db_index_usage_stats.last_user_update`, so a table unchanged since its
last read is skipped ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67)). It also names the TDE encryptor.
It reads server state and writes nothing, and the user check counts every
`VIEW ...` permission as a read. Without it, the scanner still reads every
table, sampled on every pass as before.

MongoDB: a user with the built-in `readAnyDatabase` role (Atlas: "Only read
any database"), or `read` on the databases to scan.

## Deploying it

The image is built from this repository (`docker build --target db`). It
runs as a non-root user, needs no inbound port, and needs outbound access
only to the databases and to the findings destination.

### docker run

See [Quick start](#quick-start). With a mounted secrets directory:

```sh
docker run --rm -e SCANNER_SITE=dc-1 \
  -e DATABASE_URLS_DIR=/run/secrets/databases -v /etc/sds/databases:/run/secrets/databases:ro \
  -e FINDINGS_HTTPS_URL=https://collector.example.com/findings \
  -e FINDINGS_HMAC_KEY_FILE=/run/secrets/hmac -v /etc/sds/hmac:/run/secrets/hmac:ro \
  sensitive-data-scanner-db
```

### Kubernetes (a CronJob)

```yaml
apiVersion: v1
kind: Secret
metadata: {name: sds-databases}
stringData:
  hr: postgresql://scanner_ro:...@hr-db.internal:5432/hr?sslmode=require
  orders: mysql://scanner_ro:...@orders-db.internal:3306/orders
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: sensitive-data-scanner-db}
spec:
  schedule: "0 3 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 0
      template:
        spec:
          restartPolicy: Never
          automountServiceAccountToken: false
          securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
          containers:
            - name: scanner
              image: registry.example.com/sensitive-data-scanner-db:0.3.0
              args: ["scan"]
              env:
                - {name: SCANNER_SITE, value: prod-cluster-1}
                - {name: HOME, value: /tmp}
                - {name: DATABASE_URLS_DIR, value: /run/secrets/databases}
                - {name: FINDINGS_HTTPS_URL, value: "https://collector.example.com/findings"}
                - name: FINDINGS_HMAC_KEY
                  valueFrom: {secretKeyRef: {name: sds-hmac, key: key}}
              volumeMounts:
                - {name: databases, mountPath: /run/secrets/databases, readOnly: true}
                - {name: tmp, mountPath: /tmp}
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities: {drop: ["ALL"]}
              resources:
                requests: {cpu: 500m, memory: 1Gi}
                limits: {memory: 2Gi}
          volumes:
            - name: databases
              secret: {secretName: sds-databases}
            - name: tmp
              emptyDir: {}
```

A `Job` with the same pod template runs it once.

### Amazon ECS (a Fargate task)

Connection strings from Secrets Manager; run it on a schedule with
EventBridge Scheduler (`ecs:RunTask`), in the databases' VPC.

```json
{
  "family": "sensitive-data-scanner-db",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::111122223333:role/sds-db-execution",
  "taskRoleArn": "arn:aws:iam::111122223333:role/sds-db-task",
  "containerDefinitions": [
    {
      "name": "scanner",
      "image": "111122223333.dkr.ecr.us-west-2.amazonaws.com/sensitive-data-scanner-db:0.3.0",
      "command": ["scan"],
      "environment": [
        {"name": "SCANNER_SITE", "value": "aws-us-west-2"},
        {"name": "FINDINGS_EVENT_BUS_ARN", "value": "arn:aws:events:us-west-2:444455556666:event-bus/findings"}
      ],
      "secrets": [
        {"name": "DATABASE_URL_ORDERS", "valueFrom": "arn:aws:secretsmanager:us-west-2:111122223333:secret:sds/orders-AbCdEf"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {"awslogs-group": "/sds/db", "awslogs-region": "us-west-2", "awslogs-stream-prefix": "scan"}
      }
    }
  ]
}
```

The execution role reads the secrets (`secretsmanager:GetSecretValue` on
them only); the task role needs only `events:PutEvents` on the bus.

### Azure Container Instances

```sh
az container create \
  --resource-group sds --name sensitive-data-scanner-db \
  --image registry.example.com/sensitive-data-scanner-db:0.3.0 \
  --restart-policy Never --os-type Linux --cpu 1 --memory 2 \
  --vnet sds-vnet --subnet scanner \
  --environment-variables SCANNER_SITE=azure-eastus FINDINGS_HTTPS_URL=https://collector.example.com/findings \
  --secure-environment-variables \
      DATABASE_URL_CRM='sqlserver://scanner_ro:...@crm.database.windows.net:1433/crm?encryption=require' \
      FINDINGS_HMAC_KEY='...'
```

Secure environment variables are not shown in the container's properties.
To keep the connection strings in Key Vault instead, mount them as a secret
volume (`--secrets-mount-path`) and set `DATABASE_URLS_DIR`. Schedule it with
a Logic App or an Azure Container Apps job.

## Image size

The `db` target carries Python 3.12 (Debian slim), Presidio and spaCy (no
model), the core and the runner, and the drivers named in `DB_EXTRAS`.
Measured by CI (`docker image ls`, uncompressed, 30 Sep 2026; the Lambda image is 422 MB):

| Build | `DB_EXTRAS` | Size |
|---|---|---|
| Every engine (the default) | `postgresql mysql sqlserver oracle mongodb snowflake databricks aws` | 445 MB |
| PostgreSQL and MySQL | `postgresql mysql` | 292 MB |

Databricks' connector brings pandas and NumPy, and Snowflake's brings
boto3 and cryptography: leave out the engines you do not read. A database of
an engine the image has no driver for is reported as `driver_missing`.

The same drivers are optional extras of the Python package
(`sensitive-data-scanner-db[postgresql,mysql]`, or `[all]`).

## Tested

- Every engine against stubbed drivers: the connection arguments, the user
  check (read-only users, users that can write, users whose privileges are
  hidden), the statements sent (only catalog SELECTs, SHOW commands, the
  read-only transaction and the sample), rollback, the budget, and the
  document against the schema.
- PostgreSQL 16 and MySQL 8.4 for real, in containers (testcontainers, in
  CI): read-only users are read, a user with INSERT is refused, a superuser
  is refused, a MySQL user whose role (inactive) holds UPDATE is refused,
  and the data is unchanged afterwards.
- The no-leak suite: made-up values in cells, schema, table, column,
  collection and field names, and in a password and a host, appear in no
  finding, log line, file or repr.
- Not yet run against SQL Server, Oracle, MongoDB, Snowflake or Databricks
  themselves.
