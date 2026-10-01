# sensitive-data-scanner

Find **card numbers, US Social Security numbers, ITINs and dates of birth**
in your own cloud accounts, databases and SaaS tenants. The scanner runs
**inside your environment** with read-only access, and **only findings
leave it**: where, what kind, how many and how sure. Never a value.

- **Open source**, Apache License 2.0.
- **Detection:** [Microsoft Presidio](https://github.com/microsoft/presidio)
  with no NLP model, plus our declarative spec ([spec/](spec/README.md)):
  Luhn and issuer checks, SSN and ITIN structure, published test numbers set
  apart, and the question-then-answer rules that catch a number read aloud or
  keyed into a phone menu.
- **One core, five runners:** AWS, Azure, Google Cloud, databases hosted
  anywhere, and SaaS (Microsoft 365, Google Workspace, Slack, Jira and
  Confluence).

> **Status: early.** Released: **v0.4.1** (1 Oct 2026), the first signed
> release (v0.4.0 included the 0.3.0 that was prepared and never published). Proven on real accounts so
> far: whole-account runs in two development AWS accounts (S3, CloudWatch
> Logs, Lambda configuration, SSM, X-Ray, Step Functions and DynamoDB read
> for real, with no values in the output), and one SharePoint site in a test
> Microsoft 365 tenant. PostgreSQL and MySQL run against real engines in
> containers in CI. Everything else, Azure, Google Cloud and most SaaS
> included, is tested against simulated services only.
> [Status and maturity](#status-and-maturity) says exactly what is proven.

## What it reads

**Read** is read by default once the runner is deployed. **Opt-in** is
discovered and reported until you turn it on, because it costs more, needs
a key or role you provide, or reads something more sensitive. **Gap** is
discovered and reported with its reason, never read, because the scanner has
no read-only way in. Nothing it finds is a silent pass: every store it lists
is in the run summary, read or not, with the reason, and the setting that
would read it. **[docs/limitations.md](docs/limitations.md) lists every
deliberate limitation, on every platform, with its setting and default.**

| Platform | Read by default | Opt-in | Reported as a gap |
|---|---|---|---|
| **AWS** ([details](docs/ARCHITECTURE.md#coverage-by-store)) | S3 and S3 directory buckets, CloudWatch Logs, DynamoDB, Glue tables, OpenSearch domains, Kinesis Data Streams, Firehose (its S3 locations), SSM Parameter Store (`SecureString`s opt-in), Timestream for LiveAnalytics, Keyspaces, Step Functions history, Lambda environment variables, X-Ray traces, CodeCommit, ElastiCache and MemoryDB snapshots exported to S3 | RDS and Aurora (snapshot export), small Aurora databases by SQL, Redshift, OpenSearch Serverless, EBS snapshots, SQS dead-letter queues, Secrets Manager, MSK, Amazon MQ for ActiveMQ, ECR images, SageMaker Feature Store, Neptune Analytics (export), EventBridge archives (replay), large DynamoDB tables (export) | ElastiCache and MemoryDB (in memory), DocumentDB, Neptune, EFS, FSx, AWS Backup vaults, Timestream for InfluxDB, Amazon MQ for RabbitMQ, SageMaker notebooks, Glacier vaults |
| **Azure** ([details](docs/AZURE.md#stores)) | Blob Storage and ADLS Gen2, Cosmos DB for NoSQL, Table Storage, Queue Storage (peek only), Azure Monitor logs | Azure Files, Key Vault secrets (counts only), Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible servers, Synapse SQL pools, Cosmos DB for MongoDB vCore | Managed disk snapshots, Cosmos DB accounts on the MongoDB (RU), Cassandra, Gremlin and Table APIs |
| **Google Cloud** ([details](docs/GCP.md#stores)) | Cloud Storage (Archive-class objects opt-in), BigQuery, Firestore and Datastore, Spanner, Bigtable, Cloud Logging | Data Access audit logs, Secret Manager (counts only), Cloud SQL for PostgreSQL and MySQL, AlloyDB, Archive-class objects | Pub/Sub, persistent disk snapshots, Cloud SQL for SQL Server |
| **Databases anywhere** ([details](docs/DATABASES.md#engines)) | PostgreSQL, MySQL and MariaDB, SQL Server, Oracle, MongoDB, Snowflake, Databricks SQL: each one you configure, with a user the runner has checked can only read | | A user that can write, or whose grants cannot be checked, is refused |
| **SaaS** ([details](docs/SAAS.md)) | Microsoft 365 mail (only once the grant is proved scoped), OneDrive and SharePoint; Gmail, Drive and shared drives; Slack channels the app is a member of; Jira issues and Confluence pages | Teams channels and chats (Microsoft's protected API), Slack direct messages (Enterprise Grid's Discovery API) | Slack channels the app was not invited to |

Every platform runs the same scheduled batch pass. Reading an object seconds
after it is written, from a storage event, is designed and not built
([Event-driven mode](docs/ARCHITECTURE.md#event-driven-mode-phase-2-design-only)).

## What it detects

- **Classes:** card numbers (PAN), US SSNs, US ITINs and dates of birth
  anywhere; security codes, PINs, account numbers and an SSN's last four
  when a prompt asked for them
  ([spec/classes.yaml](spec/classes.yaml)).
- **Confidence:** every finding is `high`, `medium` or `low`, with how it was
  found (the shape alone, context words, or a prompt). A date is kept only
  next to a birth-date word; nine bare digits only next to an SSN or ITIN
  word.
- **Context and prompts:** a JSON key, a CSV header or a column name is
  context. In a transcript, a bot or agent turn that asks for a card number
  classes the next customer turn as one, whatever its shape; spoken digits
  ("four two, double four") and numbers split across turns are joined.
  Amazon Connect, Contact Lens and Lex transcripts are read as conversations.
- **Disguised files:** a file's first bytes, not its name, decide how it is
  read. A renamed file is still read, and its findings say `disguised`.
- **Archives:** zip, tar, gzip, bzip2 and xz, entry by entry, in memory
  (7z is counted, not read).
- **PDFs:** the text layer. **Office:** Word, Excel and PowerPoint (Open XML)
  as text. **Columnar:** Parquet, ORC and Avro by column, with the column's
  name as context.
- Audio, video, images and the older binary Office formats are counted, not
  read.

The findings contract is a versioned JSON Schema
([docs/FINDINGS.md](docs/FINDINGS.md)). Each finding names the store and
item, the class, count, confidence and offsets, the storage encryption the
data sat under, and for card data a PCI DSS note for your assessor.

## The scanner, your vendor's tool, or both

If you already run a vendor's DLP, you can import its findings instead of
scanning, or alongside it (`SCAN_MODE`: `scanner`, the default; `vendor`;
`both`). In `both`, a finding of one at the same item and class as the other's
is linked. An importer keeps detector types, counts and ids (hashed), never a
title, subject, file name or matched text.

| Vendor tool | Imported with | What the scanner adds |
|---|---|---|
| **Amazon Macie** | `macie2:ListFindings`, `GetFindings`; the reveal of values is denied ([ARCHITECTURE.md](docs/ARCHITECTURE.md#configuration)) | Every AWS kind but S3: in `vendor` mode they are reported `vendor_not_covered` |
| **Google Cloud Sensitive Data Protection** | its data profiles of BigQuery and Cloud Storage ([GCP.md](docs/GCP.md#sensitive-data-protections-profiles-55)) | Every other Google Cloud kind |
| **Microsoft Purview DLP** | Graph security alerts (`SecurityAlert.Read.All`) ([SAAS.md](docs/SAAS.md#vendor-detection-scanner-vendor-or-both-55)) | Item-level findings: an alert names no item and no kind of data |
| **Google Workspace DLP** | the Alert Center's `DlpRuleViolation` alerts | Findings where no DLP rule matched; Drive findings are linked by document |
| **Slack DLP** | Audit Logs API events (Enterprise Grid) | The kind of data: an event names none |

Jira and Confluence have no detection of their own to import: scanner only.

## How it stays safe

- **Read-only, tested in CI.** Each deployment grants reads only, and a test
  fails the build if a grant that can write appears: the AWS IAM in
  `deploy/scanner.yaml` is checked against every call the code makes, and the
  Azure roles, the Google Cloud roles and the SaaS scopes are held by strict
  tests. The database runners check a user can only read before reading
  anything, and refuse one that can write.
- **No value leaves.** The no-leak suite scans every test case end to end and
  asserts no value appears in findings, events, logs, error messages or
  object reprs; made-up values are planted in cells, documents, messages,
  names and hosts. Store, table and column names that look like a card number
  or SSN are masked; people are named only by a hash.
- **No inbound access.** Findings go to your own results store, your own
  event bus or a signed HTTPS push. The AWS, Azure and Google Cloud runners
  sign in with a role, a managed identity or a service account, not a key;
  a SaaS secret is read from a mounted file, never an environment variable.
- **Reproducible releases.** Dependencies are locked with hashes, base images
  are pinned by digest, and each release carries SBOMs and SHA-256 checksums.
  **Releases are signed** from 0.4.1: the images with cosign (keyless, with
  signed SBOM attestations), the Lambda zip with AWS Signer, so Lambda can
  enforce code signing, and the npm package with provenance
  ([Verifying a release](docs/RELEASING.md#verifying-a-release)).
- A threat model is being written; it will be linked here.

## Efficiency

- **Smart rescans.** Each run reads what changed since the last. An
  unchanged object is read again only when a component that could change its
  result changed (a better PDF reader, a new class in the spec), using at most
  a quarter of the run's budget
  ([How rescans are chosen](docs/ARCHITECTURE.md#how-rescans-are-chosen)).
- **Change markers.** Database tables whose engine says nothing changed are
  not sampled again (re-checked at least every 7 days); DynamoDB reads only
  what changed through incremental exports; BigQuery skips unchanged tables
  ([DATABASES.md](docs/DATABASES.md#tables-unchanged-since-the-last-read)).
- **Inventory.** A bucket of a million objects or more is listed from its
  own S3 Inventory report, when it has one; the scanner never configures one
  ([Large buckets](docs/ARCHITECTURE.md#large-buckets-s3-inventory)).
- **Duplicates.** A copy of an object already read is not fetched again; its
  findings name the original.
- **Budgets and sampling.** A budget per run by items, bytes and time, stable
  sampling per store, and runs that resume where the last stopped.

## Deploy it

| Where | How | Guide |
|---|---|---|
| AWS, one account and region | `deploy/scanner.yaml` (CloudFormation): a Lambda on a schedule | [Batch mode](docs/ARCHITECTURE.md#batch-mode-built), [Permissions](docs/ARCHITECTURE.md#permissions-least-privilege) |
| AWS, a whole organization | `deploy/estate-stackset.yaml`: a service-managed StackSet, findings to one central event bus | [Estate rollout](docs/ARCHITECTURE.md#estate-rollout) |
| Azure | `deploy/azure/` (Bicep at a management group): a Container Apps job with a managed identity | [docs/AZURE.md](docs/AZURE.md#deploying) |
| Google Cloud | `deploy/gcp/` (Terraform at an organization or folders): a Cloud Run job with its own service account | [docs/GCP.md](docs/GCP.md#deploying) |
| Databases anywhere | a container next to your databases: docker, Kubernetes, ECS or Azure Container Instances | [docs/DATABASES.md](docs/DATABASES.md#deploying-it) |
| SaaS | a container in your own environment: examples for ECS, Container Apps, Cloud Run and Kubernetes | [docs/SAAS.md](docs/SAAS.md#deploying) |

To run the AWS scanner by hand, invoke the function asynchronously
(`aws lambda invoke --invocation-type Event ...`). A synchronous invoke runs
long enough for the CLI to retry it
([Invoking a run](docs/ARCHITECTURE.md#invoking-a-run)).

Every release publishes the images (`ghcr.io/txp-labs/sensitive-data-scanner`,
and `-databases`, `-azure`, `-gcp` and `-saas`) and a Lambda zip
([docs/RELEASING.md](docs/RELEASING.md)). The signed zip and the Lambda image
are also in every approved AWS region, where Lambda can take them directly:
`s3://txp-labs-sensitive-data-scanner-<region>/releases/<version>/sensitive-data-scanner-<version>-lambda-python3.12-x86_64.zip`
and `895544787721.dkr.ecr.<region>.amazonaws.com/sensitive-data-scanner:<version>`
([Where the code is](docs/RELEASING.md#where-the-code-is)).
The detection is also a Python library, and the spec a zero-dependency
TypeScript package for redacting a live call in memory
([packages/spec-ts](packages/spec-ts/README.md), on npm as
`@txp-labs/sensitive-data-spec`):

```python
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import Turn

Detector().analyze_conversation([
    Turn("bot", "Please enter or say your nine digit Social Security number."),
    Turn("customer", "123456789#", channel="dtmf"),
]).detections
# [Detection(cls='us_ssn', via='prompt', confidence='high')]
```

All the documentation: [docs/README.md](docs/README.md).

## Status and maturity

| Path | Proven how |
|---|---|
| AWS: whole-account runs | **Proven on real accounts**: whole-account runs (`DISCOVER=all`) in two development AWS accounts. mermera-dev on 30 Sep 2026: 776 stores discovered, 753 read over three runs, the rest reported with a reason. stugum-dev on 1 Oct 2026: 147 sources. No values in either run's output, and no leaks. In mermera-dev, CloudTrail shows no write by the scanner's role but to its own log stream. Neither run completed a first pass of every large store. The problems they found are fixed in v0.4.0 ([#94](https://github.com/txp-labs/sensitive-data-scanner/issues/94), [#101](https://github.com/txp-labs/sensitive-data-scanner/issues/101)), and the fixes are not yet re-run in a real account |
| AWS: S3, CloudWatch Logs, Lambda configuration, SSM Parameter Store, X-Ray, Step Functions, DynamoDB | **Proven by real reads** in those runs. DynamoDB also by the v0.2.0 run of 29 Sep 2026 on one named table (37 findings on the positive control, 0 on the negative) |
| Microsoft 365: SharePoint | **Proven on a real account**, one site only: a run from `main` on 30 Sep 2026, locally, against one SharePoint site in a test tenant, with a certificate app and `Sites.Selected`. 72 files read; both planted findings found (a card in a `.docx` renamed `.png`, an SSN inside a zip); no values in the output. It found a site-naming bug ([#83](https://github.com/txp-labs/sensitive-data-scanner/issues/83)), fixed in v0.4.0 |
| Databases: PostgreSQL 16, MySQL 8.4 | Real engines in containers in CI: read-only users read, users that can write refused, data unchanged |
| AWS: every other store, the opt-in reads (RDS and Aurora by export included), the StackSet rollout across an organization | Tested against simulated services (moto, botocore's Stubber); the template linted and checked against the code's calls. Not yet read in a real account |
| Azure, Google Cloud | Tested against simulated services; the Bicep and Terraform linted and tested offline. Not yet run in a real tenant or organization |
| SaaS other than SharePoint (Microsoft 365 mail, OneDrive and Teams; Google Workspace; Slack; Jira; Confluence) | Tested against simulated vendor APIs. Not yet run against a real tenant |
| SQL Server, Oracle, MongoDB, Snowflake, Databricks | Tested against simulated drivers only |
| Detection | Every vector in `vectors/`, through the spec engine, through Presidio, and through the TypeScript package, which must agree |

Not yet measured: throughput and cold start at scale. Not yet built: the
event-driven mode. Release notes:
[CHANGELOG.md](CHANGELOG.md) and [docs/release-notes/](docs/release-notes).

## Contributing

Issues are welcome: bugs, missed detections, false positives, stores you
need. Please use made-up values only. **Pull requests from outside
contributors open once our Contributor License Agreement completes legal
review**; the [CLA](cla/INDIVIDUAL.md) is a draft until then. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a security problem

Please do not open a public issue. Use GitHub's private vulnerability
reporting (the **Security** tab); [SECURITY.md](SECURITY.md) has the details
and what to expect.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Maintained
by [txp-labs](https://github.com/txp-labs). It powers the sensitive-data
checks in Mermera, and works on its own too.
