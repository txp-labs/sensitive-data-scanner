# Cost model

What the scanner costs to run in a customer's cloud, per platform and estate
size. Two numbers matter:

- **A first full pass**: reading everything once;
- **The steady state**: reading what changes.

The model also shows how budgets, sampling, smart rescans and S3 Inventory
bring both down.

Issue [#78](https://github.com/txp-labs/sensitive-data-scanner/issues/78).
Prices were read on **30 Sep 2026** from the public pricing pages and the AWS
and Azure price-list APIs ([Sources](#sources)).

**How to read these numbers.** They are orders of magnitude, not quotes.

- Every figure is list price in US regions (AWS `us-east-1`, Azure `eastus`,
  Google `us-central1`), with no discounts, savings plans or credits.
- The scanner's read speed on the cloud platforms has not been measured
  ([Assumptions](#assumptions)). It is the largest uncertainty, and the
  compute figures carry it as a factor-of-two range.
- The scanner's charges land in the customer's own bill; this repository
  creates no cloud resources.

## The shape of the cost

The same shape holds on every platform:

1. **Compute is capped by the run budget.**
   - A run stops at `MAX_ITEMS_PER_RUN` (20,000), `MAX_BYTES_PER_RUN` (2
     GiB) or the platform's time limit, whichever comes first.
   - What is left is the next run's backlog.
   - So the schedule and the budget set a **ceiling on the monthly bill**,
     whatever the size of the data. More data means a longer first pass, not
     a bigger bill per run.
2. **Compute is paid per gigabyte read, not per run.**
   - A first pass costs about the same whether it takes a week of hourly
     runs or four months of daily ones.
   - The schedule changes how long the pass takes, not what it costs.
3. **Request charges are small next to compute.**
   - S3 GETs and LISTs cost cents per million objects.
   - The exception is KMS on SSE-KMS buckets without S3 Bucket Keys: one
     `Decrypt` per GET can cost as much as the GETs, several times over.
4. **The stores' own export and query features cost the most per gigabyte.**
   These are RDS snapshot export, DynamoDB export, Redshift Serverless and
   BigQuery.
   - The scanner uses them only where it must, and at the cheapest rate it
     can: `tabledata.list` in BigQuery bills no bytes.
   - Several are opt-in.

## Assumptions

### Read speed

- **Measured:** 2 to 6 MB/s per core for stored text (logs, JSON lines, CSV)
  through `scan_item_text`. This was on an Apple-silicon laptop on 30 Sep
  2026, after the linear-time fix in
  [#91](https://github.com/txp-labs/sensitive-data-scanner/pull/91). Before
  it, large texts were quadratic.
- **Assumed for the clouds:** 1 to 2 MB/s per run.
  - The runner reads one object at a time, and cloud vCPUs are slower than
    the laptop's cores.
  - PDFs, Office files and Parquet were not measured.
  - This range gives the factor of two in the compute figures.
- **At 2 MB/s**, a 900-second Lambda run reads about 1.8 GB, just under the
  2 GiB byte budget. **At 1 MB/s** it reads about 0.9 GB. So on Lambda the
  time limit, not the byte budget, usually ends a run of large text objects.
  A run of small objects ends at the 20,000-item budget instead.

### The account profile

Each AWS account (one region) is assumed to hold:

| Store | Assumed | Why this size |
|---|---|---|
| S3 | 1,000,000 objects, 200 GB the scanner reads (a 200 KB average; objects over `MAX_OBJECT_BYTES`, 20 MiB, are read only up to it); 2% of objects change a day (20,000 objects, 4 GB) | A mid-sized workload account. The totals scale linearly, so use the unit costs for other sizes |
| CloudWatch Logs | 10 GB a day in the scanned groups | |
| DynamoDB | 5 tables under 1 GiB (sampled by `Scan`) and 1 table of 100 GB with PITR (read by export) | |
| RDS | 1 database with a 100 GB snapshot | Needs `RDS_EXPORT_ROLE_ARN` (opt-in) |

**Estates** are 10, 100 and 1,000 such accounts: small, medium and large.
Real estates are lumpier. A few accounts hold most of the data, and most hold
almost none.

### Deployment defaults

- **AWS:** one Lambda function per account and region; 3,008 MB; 900-second
  timeout; `rate(1 day)` (`deploy/scanner.yaml`).
- **Azure:** one Container Apps job for the whole management group; 1 vCPU,
  2 GiB; daily; 3,600-second timeout (`deploy/azure`).
- **Google Cloud:** one Cloud Run job for the organization or folder; 2 vCPU,
  4 GiB; daily; 3,600-second timeout (`deploy/gcp`).

## AWS

### Unit costs

| Item | Price (us-east-1) | Per what the scanner does |
|---|---|---|
| Lambda compute | $0.0000166667 per GB-second (x86) | A run capped at 900 s × 2.9375 GB = 2,644 GB-s = **$0.044 per run**, at most. At 1 to 2 MB/s, that is **$0.025 to $0.05 per GB read** |
| Lambda requests | $0.20 per million | One per run: negligible |
| Lambda free tier | 400,000 GB-s and 1 million requests a month | Enough for about 150 maximum-length runs. Under consolidated billing, AWS Organizations share one free tier, so it is small beside an estate |
| S3 GET | $0.0004 per 1,000 | One GET for an object under 256 KiB; a sniff read plus ranged reads above that. Assume 1.2 GETs an object: **$0.48 per million objects read** |
| S3 LIST | $0.005 per 1,000 (1,000 keys each) | **$0.005 per million objects listed.** Every pass lists the bucket to find changes |
| S3 Inventory | $0.0025 per million objects listed | Replaces the listing of a bucket over `S3_INVENTORY_MIN_OBJECTS` (1 million): **half the LIST cost**. The report must be configured by the customer; the scanner only reads it. It is daily, so changes show a day late |
| S3 transfer to Lambda | free within the region | The scanner runs in each region it reads |
| KMS | $0.03 per 10,000 requests (20,000 free a month) | SSE-KMS objects without an S3 Bucket Key: about one `Decrypt` per GET, so **up to $3.60 per million objects read**. With Bucket Keys, S3 calls KMS far less often: a fraction of that |
| S3 PUT (findings, state, index) | $0.005 per 1,000 | A handful per run: negligible |
| S3 storage of the scanner's own output | $0.023 per GB-month (Standard) | One findings document per run under `findings/runs/`, usually kilobytes and at most a few MB (5,000 findings), kept `FindingsRetentionDays` (90 by default, #119), plus the current `latest.json`, `report.html` and `findings.csv`: **cents a month at most**. `0` keeps run files forever, so the bucket grows by one document a run (the Azure and Google Cloud templates' `findingsRetentionDays` and `findings_retention_days` do the same) |
| Secrets Manager (optional, #109) | $0.40 per secret a month, $0.05 per 10,000 API calls | With `FindingsHmacKey`, one secret per account and region holds the Mermera key: **about $0.40 a month per stack**; it is read once per cold start, so the calls are negligible |
| EventBridge `PutEvents` (optional push) | $1.00 per million events (64 KB chunks) | A findings part is up to about 200 KB (4 chunks). Negligible |
| CloudWatch Logs `FilterLogEvents` | no per-request price on the pricing page | The cost is the Lambda time to read the events: **$0.025 to $0.05 per GB of log read**. The scanner does not use Logs Insights ($0.005 per GB scanned) |
| DynamoDB `Scan` (on-demand) | $0.125 per million read request units; an eventually consistent read is half a unit per 4 KB | A table's pass is capped at 200 pages × 100 items. At 1 KB items that is 20 MB, about 2,500 units: **$0.0003 a table a pass**. On a provisioned table the Scan uses its capacity instead |
| DynamoDB export to S3 | $0.10 per GB (full: table size; incremental: data processed) | A 100 GB table: **$10** for its first full export, then $0.10 per GB changed |
| RDS snapshot export to S3 | $0.013 per GB of snapshot size (RDS for PostgreSQL page's example; check the engine's page) | A 100 GB snapshot: **$1.30** an export. At most `MAX_EXPORTS_PER_RUN` (1) a run, and a store no more often than `EXPORT_MIN_INTERVAL_DAYS` (7) |
| Redshift Serverless (opt-in `REDSHIFT_READ`) | $0.375 per RPU-hour, billed per second, with a 60-second minimum when the workgroup wakes | Sampled `LIMIT` queries, 1,000 rows from up to 500 tables. At the default 128 RPU base, a minute costs about $0.80, so a pass of 5 to 15 minutes is **about $4 to $12**. At an 8 RPU base, a pass is well under $1. A provisioned cluster's queries use its own capacity at no extra charge |

### An account's first full pass (200 GB, 1 million objects)

| Item | Cost |
|---|---:|
| Compute: 200 GB at $0.025 to $0.05 | $5 to $10 |
| S3 GETs | $0.48 |
| S3 LIST | $0.01 |
| KMS (SSE-KMS without Bucket Keys; else about $0) | $0 to $3.60 |
| DynamoDB: first full export of the 100 GB table, plus 5 small Scans | $10 |
| RDS: one export of the 100 GB snapshot | $1.30 |
| **Total** | **about $17 to $25 an account** |

The pass needs about 110 to 220 maximum-length runs.

- At the default `rate(1 day)`, that is **4 to 7 months**.
- At `rate(1 hour)`, it is **5 to 9 days**, for the same cost.

### Steady state per account per month

This profile has 4 GB of S3 changing a day and 10 GB of logs.

| Item | Read everything that changes | At the default daily schedule |
|---|---:|---:|
| Compute | S3 120 GB plus logs 300 GB: **$10 to $21** | Capped at one run a day: **$1.32** |
| S3 GETs and LIST (Inventory: half the LIST) | $0.40 | $0.40 or less |
| KMS without Bucket Keys | up to $2.20 | up to $2.20 |
| DynamoDB: 5 small Scans daily, and incremental exports of 1% change a day | $3 | $3 |
| RDS: weekly re-export | $5.60 | $5.60 |
| **Total** | **about $20 to $32** | **about $10 to $13, with a backlog** |

At the default schedule, the account's changes outgrow one run a day: 14 GB
of new data against at most about 1.8 GB read. The rest waits as backlog and
is reported as backlog in the run summary. To read
all of it:

- run more often, or raise the budget, which costs the left column;
- or read less, with sampling or deny rules ([below](#what-brings-it-down)).

### Estates

| Estate | First full pass | Steady state per month, reading all changes | Steady state per month, default daily run |
|---|---:|---:|---:|
| Small: 10 accounts | $170 to $250 | $200 to $320 | $100 to $130 |
| Medium: 100 accounts | $1,700 to $2,500 | $2,000 to $3,200 | $1,000 to $1,300 |
| Large: 1,000 accounts | $17,000 to $25,000 | $20,000 to $32,000 | $10,000 to $13,000 |

The costs are per region scanned. The StackSet deploys the scanner to every
account and region named, and an account with no data costs roughly nothing:
a short run, one listing, and no reads.

## Azure

One Container Apps job reads the whole management group. It runs daily with
1 vCPU and 2 GiB, for at most 3,600 seconds.

| Item | Price (eastus) | Per what the scanner does |
|---|---|---|
| Container Apps, active | $0.000024 per vCPU-second, $0.000003 per GiB-second | $0.00003 a second, **$0.108 per one-hour run**: at most $3.24 a month daily |
| Free grant | 180,000 vCPU-seconds and 360,000 GiB-seconds a month | A daily one-hour run (108,000 vCPU-s, 216,000 GiB-s) fits within it |
| Blob read | $0.004 per 10,000 (Hot, LRS) | **$0.40 per million blobs read** |
| Blob list | $0.05 per 10,000 | **$5 per million list calls**; a list call returns up to 5,000 blobs |
| Inter-region reads | bandwidth pricing applies | The job reads storage accounts in every region from its own. Deploy one job per region to avoid it |

- **One job for the estate** means compute does not grow with the number of
  subscriptions. What grows is the time to read them. At 1 to 2 MB/s, one
  run reads 3.6 to 7.2 GB.
- The first full pass of 200 GB per subscription is 30 to 60 runs per
  subscription. At 100 subscriptions, raise `replicaTimeoutSeconds`, run more
  often, or split the estate across jobs.
- Compute for the whole pass is about the same in any case: **$0.015 to
  $0.03 per GB read**, a little below Lambda's per-GB rate.
- **Estate figures for the first pass:**
  - small (10 subscriptions, 2 TB): **$30 to $60** compute plus about $4 in
    reads;
  - medium: **$300 to $600** compute plus $40 in reads;
  - large: **$3,000 to $6,000** compute plus $400 in reads.
- Azure SQL, PostgreSQL and MySQL are read with sampled read-only SQL on the
  customer's own compute. Cosmos DB reads use request units on the account's
  own capacity.

## Google Cloud

One Cloud Run job reads the organization or folder. It runs daily with 2
vCPU and 4 GiB, for at most 3,600 seconds.

| Item | Price (us-central1) | Per what the scanner does |
|---|---|---|
| Cloud Run jobs (instance-based) | $0.000018 per vCPU-second, $0.000002 per GiB-second, a 1-minute minimum | $0.000044 a second, **$0.158 per one-hour run**, at most $4.75 a month daily |
| Jobs free tier | 240,000 vCPU-seconds and 450,000 GiB-seconds a month | A daily one-hour run (216,000 vCPU-s, 432,000 GiB-s) fits within it |
| Cloud Storage Class B (reads) | $0.0004 per 1,000 (Standard) | **$0.40 per million objects read** |
| Cloud Storage Class A (lists) | $0.005 per 1,000 (Standard, regional; $0.01 multi-region) | $0.005 per 1,000 list calls |
| BigQuery `tabledata.list` | not billed as a query: Google's cost guide lists table preview as free | 1,000 rows from each table: **$0 in query charges**. A `TABLESAMPLE` query would bill the bytes of the columns it reads, at $6.25 per TiB on demand |
| BigQuery Storage Read API | $1.10 per TiB; 300 TiB a month free | Not used by the scanner today |

- The job runs on 2 vCPU. The runner reads one object at a time, so assume
  the same 1 to 2 MB/s: **$0.02 to $0.04 per GB read**.
- **Estate figures for the first pass**, 200 GB per project:
  - small (10 projects): **$45 to $90**;
  - medium: **$450 to $900**;
  - large: **$4,500 to $9,000**;
  - plus $0.40 per million objects read.
- The free tier covers a daily one-hour run, but not a first pass at scale.

## Databases anywhere and SaaS

- **The databases runner** is a container you run. Its compute is that
  host's. Its reads are sampled `SELECT`s under a read-only user on the
  database's own capacity. It skips tables unchanged since their last read.
- **The SaaS scanner** calls vendor APIs within their rate limits. Microsoft
  Graph, the Google Workspace APIs, Slack and Atlassian do not charge per
  call for these reads. Its compute is the container's: ECS on Fargate at
  $0.000011244 per vCPU-second and $0.000001235 per GB-second (us-east-1), or
  the Container Apps and Cloud Run rates above. A 1 vCPU, 2 GB task running
  one hour a day costs **about $1.50 a month**.

## Reading cold storage classes

Some storage classes charge for every byte read, on top of the request
([#109](https://github.com/txp-labs/sensitive-data-scanner/issues/109)). The
scanner decides what to read from each object's class in the listing it already
does, so an object it leaves out costs nothing, and every run reports what
reading the rest would cost: each object store's `storageClasses` (objects and
bytes per class) and `costEstimate` in the run summary
([FINDINGS.md](FINDINGS.md)). **Every scan cost lands on the customer's own
cloud bill.**

| Platform | Class / tier | Read? | Retrieval | Reads (GET) | Setting |
|---|---|---|---|---|---|
| S3 | Standard, Intelligent-Tiering (frequent, infrequent, archive instant) | yes | none | $0.0004 per 1,000 | |
| S3 | Standard-IA, One Zone-IA | yes, within the byte budget | $0.01 per GB | $0.001 per 1,000 | |
| S3 | Glacier Instant Retrieval | **off by default** | $0.03 per GB | $0.01 per 1,000 | `S3_READ_GLACIER_IR` |
| S3 | Glacier Flexible Retrieval, Deep Archive, Intelligent-Tiering Archive and Deep Archive Access | **no**: needs a restore (a write, hours, the customer's cost): `needs_restore` | | | hook `S3_RESTORE_ARCHIVED` |
| Azure Blob / ADLS Gen2 | Hot | yes | none | $0.0004 per 1,000 ($0.004 per 10,000) | |
| Azure Blob / ADLS Gen2 | Cool | yes, within the byte budget | $0.01 per GB | $0.001 per 1,000 | |
| Azure Blob / ADLS Gen2 | Cold | **off by default** | $0.03 per GB | $0.01 per 1,000 | `AZURE_READ_COLD_TIER` |
| Azure Blob / ADLS Gen2 | Archive | **no**: needs a rehydration (Set Blob Tier or Copy Blob to Hot or Cool; a write, hours, the customer's cost): `needs_rehydration` | | | hook `AZURE_REHYDRATE_ARCHIVE` |
| Cloud Storage | Standard | yes | none | $0.0004 per 1,000 | |
| Cloud Storage | Nearline / Coldline | yes, within the byte budget | $0.01 / $0.02 per GiB | $0.001 / $0.01 per 1,000 | |
| Cloud Storage | Archive | **off by default** (#105) | $0.05 per GiB | $0.05 per 1,000 | `GCS_READ_ARCHIVE` |

Prices are us-east-1, eastus and Cloud Storage's single price; the estimate
uses the store's own region where the table has it.

**How the estimate is worked out.** For each class with a retrieval fee that
the scanner can read (now, or with its setting on): the retrieval fee on the
bytes a read fetches (each object up to `MAX_OBJECT_BYTES`, 20 MiB by default,
not its full size) plus one GET per object. Ranged reads of a large or columnar
object take a few GETs more, so the request part is a floor; the retrieval part
is exact for those bytes. It is the cost of reading every object once (a full
pass); later passes read only what changed, and smart rescans re-read at most
`RESCAN_PERCENT` of a run's budget. `estimatedToScanUsd` covers the classes read
now; `byClass` gives each priced class, read or not, so the cost of turning
Glacier Instant Retrieval or Cold on is shown before anyone does. Classes that
need a restore or a rehydration get counts and bytes only: the scanner cannot
read them, so it has no estimate.

For example, 100 GB in Standard-IA across 100,000 objects under 20 MiB:
$1.00 retrieval and $0.10 in GETs, **$1.10 a full pass**; the same in Glacier
Instant Retrieval: $3.00 and $1.00, **$4.00**; in Azure Cold (eastus): $3.00 and
$1.00, **$4.00**; in Cloud Storage Coldline (93 GiB): $1.86 and $1.00, **about $2.90**.

**The price table** is `scanner/core/src/sensitive_data_core/storage_prices.json`,
dated, with its sources, written by `scripts/storage_prices.py --write` (never
read from a pricing API at run time):

- AWS: the Price List Bulk API's `AmazonS3` offer for each commercial region
  (publication date **2026-09-28**), the figures of
  <https://aws.amazon.com/s3/pricing/> (Requests & data retrievals). Standard-IA,
  One Zone-IA and Glacier Instant Retrieval cost the same in every commercial
  region today; the per-region rows stay so a change shows up in the diff.
- Azure: the Retail Prices API, *General Block Blob v2*, LRS meters, per region
  (read **2026-10-01**), the figures of
  <https://azure.microsoft.com/pricing/details/storage/blobs/>. Cold and Archive
  vary by region (Cold retrieval $0.03 to $0.045 per GB); other redundancies can
  differ from LRS, and hierarchical-namespace (ADLS Gen2) read operations are
  priced as flat.
- Google Cloud: <https://cloud.google.com/storage/pricing>, *Retrieval fees*
  and *Operation charges* (Class B, flat namespace), read **2026-10-01**: the
  same in every location. A bucket with Autoclass pays no retrieval fee; the
  estimate does not know Autoclass and overstates it.
- A region the table lacks is priced as **us-east-1** (AWS) or **eastus**
  (Azure), and the estimate says so (`regionFallback: true`).

## What brings it down

| Lever | Setting | What it saves |
|---|---|---|
| **The run budget** | `MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, `MAX_RUN_SECONDS`, the schedule | A hard ceiling on compute per month: at the defaults, $1.32 an account-region on AWS. It trades cost for time to coverage |
| **Sampling** | `S3_SAMPLE_PERCENT`, per-store `DISCOVER_SAMPLING`, `S3_MAX_OBJECTS_PER_PREFIX`, `DYNAMODB_SAMPLE_PERCENT`, `COLUMNAR_MAX_ROWS`, `REDSHIFT_MAX_ROWS_PER_TABLE` | Compute and GETs fall in proportion. 10% sampling makes a first pass about a tenth of the cost. Sampling by key is stable, so the same objects are sampled each pass |
| **Incremental reads** | always on | Only objects changed since the last pass are read, with log events from a watermark and tables by their engine's change marker. The steady state is the churn, not the estate |
| **Smart rescans** | `OBJECT_INDEX`, `RESCAN_PERCENT` (25%) | An unchanged object is read again only when a component that could change its result changed, within 25% of the budget. A reader or spec upgrade costs at most a quarter of each run until done, never a full re-pass |
| **Duplicates** | the object index | A copy of an object already read (same fingerprint) is not read again |
| **S3 Inventory** | `S3_INVENTORY` for buckets over 1 million objects | Listing at $0.0025 per million objects instead of $0.005, and no listing calls against the bucket |
| **Deny rules and IAM** | `DISCOVER_DENY`, explicit IAM Denies | Stores that are known to be clean, or out of scope, cost nothing |
| **S3 Bucket Keys** | the customer's bucket setting | Removes most of the KMS cost on SSE-KMS buckets |
| **Exports only when needed** | `EXPORT_MIN_INTERVAL_DAYS`, `MAX_EXPORTS_PER_RUN`, `DYNAMODB_INCREMENTAL`, `DYNAMODB_EXPORT_MIN_BYTES` | Full exports once, then incremental, and small tables by a cheap `Scan` |
| **The free queries** | `tabledata.list` (BigQuery), sampled `LIMIT` queries | Samples cost no bytes billed |
| **Cold classes left unread** | `S3_READ_GLACIER_IR`, `AZURE_READ_COLD_TIER`, `GCS_READ_ARCHIVE` (all off) | No retrieval fee for the classes that charge most per byte; the run's `costEstimate` says what reading them would cost |
| **Vendor mode** | `SCAN_MODE=vendor` | Imports Macie's, Google SDP's or Purview's own findings and reads nothing. The scanner's compute and requests go to nearly zero; the vendor's own pricing applies instead |

## Sources

Read on **30 Sep 2026**.

- AWS Lambda pricing, <https://aws.amazon.com/lambda/pricing/>: x86 $0.0000166667 per GB-second, $0.20 per million requests, free tier 400,000 GB-s and 1 million requests.
- Amazon S3 pricing, <https://aws.amazon.com/s3/pricing/>, and the AWS price-list API (`AmazonS3`, us-east-1):
  - GET $0.0004 per 1,000;
  - PUT, COPY, POST and LIST $0.005 per 1,000;
  - S3 Inventory $0.0025 per million objects listed;
  - transfer to other services in the same region free.
- AWS KMS pricing, <https://aws.amazon.com/kms/pricing/>, and the price-list API (`awskms`): $0.03 per 10,000 requests, 20,000 free a month.
- Amazon CloudWatch pricing, <https://aws.amazon.com/cloudwatch/pricing/>, and the price-list API (`AmazonCloudWatch`): Logs Insights $0.005 per GB scanned. The only priced API requests are the metric and dashboard APIs, at $0.01 per 1,000; no price is listed for `FilterLogEvents`.
- Amazon DynamoDB on-demand pricing, <https://aws.amazon.com/dynamodb/pricing/on-demand/>: $0.125 per million read request units, and export to S3 at $0.10 per GB, full and incremental.
- Amazon RDS for PostgreSQL pricing, <https://aws.amazon.com/rds/postgresql/pricing/>: snapshot export $0.013 per GB of snapshot size (the page's example).
- Amazon Redshift pricing, <https://aws.amazon.com/redshift/pricing/>: Serverless $0.375 per RPU-hour (the page's examples).
- AWS Secrets Manager pricing, <https://aws.amazon.com/secrets-manager/pricing/>: $0.40 per secret per month, $0.05 per 10,000 API calls.
- Amazon EventBridge, the price-list API (`AWSEvents`): custom events $1.00 per million (64 KB chunks).
- AWS Fargate pricing, <https://aws.amazon.com/fargate/pricing/>: Linux x86 $0.000011244 per vCPU-second, $0.000001235 per GB-second.
- Azure Container Apps pricing, <https://azure.microsoft.com/en-us/pricing/details/container-apps/>, and the Azure Retail Prices API (`eastus`):
  - Standard active $0.000024 per vCPU-second and $0.000003 per GiB-second;
  - free grant 180,000 vCPU-s and 360,000 GiB-s a month;
  - jobs billed at the active rate while they run.
- Azure Blob Storage, the Azure Retail Prices API (`eastus`, General Block Blob v2, Hot LRS): read $0.004 per 10,000, list $0.05 per 10,000.
- Google Cloud Run pricing, <https://cloud.google.com/run/pricing>: instance-based $0.000018 per vCPU-second and $0.000002 per GiB-second (us-central1); jobs billed at the instance-based rate with a 1-minute minimum; jobs free tier 240,000 vCPU-s and 450,000 GiB-s.
- Google Cloud Storage pricing, <https://cloud.google.com/storage/pricing>: Standard Class A $0.005 per 1,000 (regional), Class B $0.0004 per 1,000.
- BigQuery pricing, <https://cloud.google.com/bigquery/pricing>: on-demand $6.25 per TiB; Storage Read API $1.10 per TiB with 300 TiB a month free.
- BigQuery cost best practices, <https://cloud.google.com/bigquery/docs/best-practices-costs>: table preview, which uses `tabledata.list`, is free.
- Read speed: measured in this repository on 30 Sep 2026 (`scan_item_text` over the benchmark generator's logs, JSON lines and CSV; see [#91](https://github.com/txp-labs/sensitive-data-scanner/pull/91)).
