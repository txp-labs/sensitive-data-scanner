# sensitive-data-scanner-db

The databases-anywhere runner: a container you run inside your own network
that samples PostgreSQL, MySQL and MariaDB, SQL Server, Oracle, MongoDB
(including Atlas), Snowflake and Databricks SQL with a **read-only** database
user, and sends **findings only, never values**.

It is built on the cloud-neutral core (`../core`). How to configure, deploy
and verify it: [docs/DATABASES.md](../../docs/DATABASES.md).
