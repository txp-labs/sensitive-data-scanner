# Findings, schema version 1.11

The scanner reports **findings only**: which locations hold which classes of
sensitive data, how many, how confident, where in the item, and how much it
scanned. **It never reports a value.** A test suite
(`scanner/tests/test_no_leak.py`) scans every test vector and fails if any
value shows up in findings, events, logs, exception messages or object reprs.

- JSON Schema: [`schema/findings.schema.json`](../schema/findings.schema.json)
  (it also ships inside the Python package).
- `schema`: `"sensitive-data-scanner.findings"`, `schemaVersion`: `"1.11"`.
- Version 1.1 (scanner 0.2.0) adds the DynamoDB source: the `dynamodb_item`
  resource and format, and the `dynamodb` coverage kind. Nothing in 1.0 changed,
  so a 1.0 consumer that ignores what it does not know keeps working.
- Version 1.2 adds discovery and data-lake formats: the `discovery` run
  summary (every store, read or not, and why), `kmsDenied` in coverage, `#`
  in a masked bucket or table name, `column` and `catalog` on an S3 object,
  the `parquet`, `orc`, `avro` and `sql` formats, the `rds_column` resource,
  the `glue_table` and `rds` coverage kinds and the `columnar` skip kind. All
  additive.
- Version 1.3 adds the stores found by the adapters: the `store_field`
  resource (one field of a store that is not S3, logs, DynamoDB or RDS, such
  as a Redshift column, an OpenSearch field, an EBS volume's blocks, a
  stream's records, a queue's messages, a parameter's or a secret's value),
  the `redshift`, `opensearch`, `ebs`, `backup`, `documentdb`, `neptune`,
  `efs`, `fsx`, `kinesis`, `firehose`, `sqs`, `ssm`, `secretsmanager`,
  `elasticache`, `memorydb`, `timestream` and `keyspaces` kinds, the `block`,
  `cql` and `rdb` formats, the store reasons
  `read_not_configured`, `paused`, `no_grant`, `vpc_only`,
  `no_snapshot_export`, `needs_task`, `backup_copy`, `archived`,
  `live_queue`, `redrive_would_change`, `no_s3_destination`, `in_memory`
  and `no_read_path`, and the store
  fields `deployment`, `database`, `state`, `resource`, `olderSnapshots`,
  `recoveryPoints`, `fileSystemType`, `destinations`, `deadLetterQueue`,
  `approximateMessages`, `items`, `itemTypes`, `excluded` and `snapshots`. The kinds are one list
  (`$defs/storeKind`) for coverage, the run summary and listing errors. All
  additive.
- Version 1.4 adds the databases-anywhere runner ([DATABASES.md](DATABASES.md)):
  `platform` (`database`; absent means AWS) and `site` (where the runner
  runs, which a databases document names in place of `account` and
  `region`; an AWS document still has both), the `postgresql`, `mysql`
  (MySQL and MariaDB), `sqlserver`, `oracle`, `mongodb`, `snowflake` and
  `databricks` kinds, the store reasons `db_user_can_write`,
  `grants_unverifiable` and `driver_missing`, and the store field
  `writeGrants`. All additive: an AWS document is 1.3's with a new version.
- Version 1.5 adds the storage encryption each finding's data sat under
  (`atRestEncryption`, `atRestKeyHash`) and the PCI DSS notes (`pciNote`) on
  a finding, and `atRestEncryption` and `atRestKeyHash` on a store in the
  run summary ([At-rest encryption and PCI DSS notes](#at-rest-encryption-and-pci-dss-notes-15)),
  and group 7's stores ([#35](https://github.com/txp-labs/sensitive-data-scanner/issues/35)): the
  `stepfunctions`, `lambda`, `xray`, `codecommit`, `s3_directory`, `msk`,
  `mq`, `ecr`, `sagemaker`, `neptune_analytics`, `eventbridge_archive` and
  `glacier` kinds, the store reasons `user_can_write` and
  `archive_retrieval`, the store fields `workflowType`, `eventCount`,
  `retentionDays` and `archives`, and `feature_group` and
  `notebook_instance` as a store's `resource`. All additive.
- Version 1.6 adds the Azure scanner ([AZURE.md](AZURE.md)): `platform:
  azure` (the document names its `site`), the `blob_object` resource (a blob
  of a Blob Storage or ADLS Gen2 container), `subscription`, `resourceGroup`
  and `resourceIdHash` on a `blob_object` or `store_field` resource and on a
  store in the run summary, the `azure_blob`, `azure_sql`, `azure_sql_mi`,
  `azure_postgresql`, `azure_mysql`, `synapse_sql`, `cosmosdb`,
  `cosmosdb_mongo`, `azure_table`, `azure_queue`, `log_analytics`,
  `azure_disk_snapshot` and `key_vault` kinds, the `kql` format, the store
  field `api`, the store reasons `network` and `needs_sas_export`
  (the store's firewall or private endpoint keeps the scanner out), the store
  fields `hierarchicalNamespace` and `networkRestricted`, the skip kind
  `archive_tier`, and Azure portal links. All additive: an AWS document is
  1.5's with a new version.
- Version 1.7 adds Azure Files ([AZURE.md](AZURE.md)): the `azure_files`
  kind and the `azure_file` resource (a file of a share: `account`, `share`,
  `path`, with Azure's `subscription`, `resourceGroup` and
  `resourceIdHash`). It also adds the Google Cloud scanner ([GCP.md](GCP.md)): `platform:
  gcp` (the document names its `site`), the `gcs_object` resource (an object
  of a Cloud Storage bucket), `project` and `resourceNameHash` on a
  `gcs_object` or `store_field` resource and on a store in the run summary,
  the `gcs`, `bigquery`, `firestore`, `datastore`, `spanner`, `bigtable`,
  `cloud_logging`, `pubsub`, `gce_snapshot`, `secret_manager`,
  `cloudsql_postgresql`, `cloudsql_mysql`,
  `cloudsql_sqlserver` and `alloydb` kinds, the store reasons `requester_pays`,
  `row_level_policy`, `authorized_view`, `needs_subscription` and
  `needs_disk_restore`, the skip kind `private_log`, the store fields
  `tableType` and `protectedColumns`, and Google Cloud console links. All additive: an AWS document is 1.6's with a new version.
- Version 1.8 adds the SaaS scanner ([SAAS.md](SAAS.md)): `platform: saas`
  (the document names its `site`), the `saas_item` resource (a message, file
  or part of one in a SaaS tenant: `vendor`, `service`, `tenantHash`,
  `ownerHash`, `container`, `channel`, `itemId`, `itemHash`, `part`, `name`,
  `column`), `vendor`, `tenantHash` and `ownerHash` on a store in the run
  summary, the `m365_mail`, `m365_onedrive`, `m365_sharepoint`,
  `m365_teams_channel`, `m365_teams_chat`, `gws_gmail`, `gws_drive`,
  `gws_shared_drive`, `slack_channel`, `slack_dm`, `jira_project` and
  `confluence_space` kinds, the `docx`, `xlsx` and
  `pptx` formats (the core now reads Office Open XML files), the skip kinds
  `encrypted`, `too_large` and `linked_item`, the store reasons
  `scope_unverified`, `unscoped_grant`, `protected_api`, `not_provisioned`,
  `throttled` and `not_a_member`, and links into Outlook on the web,
  SharePoint, Teams, Google Drive, Slack, Jira and Confluence; and (#55) the finding fields
  `source`, `vendorType`, `vendorFindingId` and `linked`, the `vendor` format
  and `via`, the class `other`, the document fields `scanMode` and
  `vendorCoverage`, and the store reasons `vendor_mode` and
  `vendor_not_covered` ([Sources and modes](#sources-and-modes-18)). All
  additive: an AWS document is 1.7's with a new version.
- Version 1.9 ([#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65))
  reads objects by what their bytes are, not their names, and reads archives
  and PDFs ([Archives, PDFs and disguised files](#archives-pdfs-and-disguised-files-19)):
  the finding fields `disguised`, `declaredType` and `detectedType`,
  `archivePath`, `archivePathMasked` and `archiveEntry` on an `s3_object`,
  `blob_object`, `azure_file`, `gcs_object`, `saas_item` or `store_field`
  resource, the `pdf` format, the skip kinds `archive_unsupported` and
  `pdf_image_only`, `disguised` in coverage and the `disguised` gap on a
  store. All additive.
- Version 1.10 ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67))
  reads an object that did not change again only when a component it was read
  with changed and could change what it finds ([Rescans](#rescans-110)): the
  finding fields `rescanReason` and `rescanClasses`, `indexed`,
  `rescanned` and `rescanBacklog` in coverage, and the store fields
  `exportType` (`incremental`, a DynamoDB export of what changed), `listedBy`
  (`inventory`, an S3 bucket read from its inventory report) and
  `recommendation` (`s3_inventory`), and `duplicateOf` on a finding and
  `duplicates` in coverage. All additive.
- Version 1.11 ([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67))
  narrows an adapter's version to its read path: `relisted` in coverage, when
  a change to how a store is listed made the run list it again from the start
  (reading only what changed). All additive.

## Sources and modes (1.8)

A customer chooses, per platform, who finds its sensitive data
([#55](https://github.com/txp-labs/sensitive-data-scanner/issues/55)):

| Mode | What runs |
|---|---|
| `scanner` (the default) | This scanner reads the stores itself |
| `vendor` | The platform's own detection has found it, and an **importer** turns the vendor's findings into this scanner's; this scanner reads nothing, and each store is `vendor_mode` (the vendor covers its kind) or `vendor_not_covered` |
| `both` | The scanner reads and the importer imports; a finding of one at the same location and class as a finding of the other is **linked** (`linked`), never merged |

Every finding says where it came from: `source` is `scanner`, or
`vendor:<name>` (`vendor:macie`, `vendor:google_sdp`, `vendor:purview`,
`vendor:google_workspace_dlp`, `vendor:slack_dlp`). The document says the mode
each platform ran in (`scanMode`, `{"aws": "both"}`) and, for each importer,
what it read and what its vendor does not cover (`vendorCoverage`).

A vendor's finding **never carries a value**. The importer runs in the
customer's environment, like the scanner, and keeps only:

- the location, masked under the same rules as the scanner's (an S3 key, a
  BigQuery column, a SaaS item named by hashes);
- the vendor's detector type, as a name (`vendorType`: `CREDIT_CARD_NUMBER`),
  masked, and the spec's class it maps to, or `other`;
- the vendor's counts (`count`, `occurrences`) and its finding id
  (`vendorFindingId`, masked);
- the store's encryption, when the vendor reports it.

Everything else a vendor keeps is dropped unread: snippets, samples, matched
text, the positions of each match (a vendor finding has no `offsets`; its
`format` and `via` are `vendor`), titles and descriptions. The no-leak suite
plants values in each of those and fails if any reaches a finding, a log line,
the state or an event.

```json
{
  "id": "5b0e…",
  "resource": { "type": "s3_object", "bucket": "example-lake", "key": "exports/cards.csv", "versionId": "v-1" },
  "format": "vendor",
  "class": "card",
  "count": 2,
  "occurrences": 2,
  "confidence": "medium",
  "via": ["vendor"],
  "offsets": [],
  "source": "vendor:macie",
  "vendorType": "CREDIT_CARD_NUMBER",
  "vendorFindingId": "6f1c…",
  "linked": ["c877…"]
}
```

| Field | Meaning |
|---|---|
| `source` | `scanner`, or `vendor:<name>` |
| `vendorType` | The vendor's detector type, a name only; `other` findings name theirs here (a custom identifier: `custom:<name>`) |
| `vendorFindingId` | The vendor's id for its finding or alert, masked |
| `linked` | In `both` mode: the ids of the other source's findings at the same location and class |
| `scanMode` (document) | The mode each platform ran in |
| `vendorCoverage` (document) | Per importer: `vendor`, `platform`, `mode`, `status` (`read`, `not_enabled`, `access_denied`, `error`, `throttled`), `error`, `findings`, `covers` (the kinds it covers) and `limits` |

`limits` name what a vendor's tool does not cover: `s3_only` (Macie reads S3
alone), `profiled_stores_only`, `sampled_by_vendor`, `profiles_not_items`,
`policy_matches_only`, `alerts_only`, `item_not_linkable` (the vendor names no
item this scanner can link to), `counts_not_distinct` (the vendor's counts are
occurrences), `enterprise_grid_only` and `no_data_class` (the vendor names the
rule that matched, not the kind of data: class `other`, never linked, since a
link needs the same class).

| Platform | Vendor | Importer | Covers | Limits |
|---|---|---|---|---|
| AWS | Amazon Macie | `macie2:ListFindings` and `GetFindings`, category `CLASSIFICATION`, updated since the last run (`MACIE_LOOKBACK_DAYS` first) | `s3` | `s3_only`, `sampled_by_vendor`, `counts_not_distinct` |
| Microsoft 365 | Microsoft Purview DLP | Graph security alerts (`alerts_v2`) from DLP, as class `other` (`DLP_POLICY_MATCH`) on the service its evidence names | the Microsoft 365 kinds | `alerts_only`, `policy_matches_only`, `item_not_linkable`, `no_data_class` |
| Google Workspace | Workspace DLP | the Alert Center's `DlpRuleViolation` alerts, a finding per detector, a Drive document on the same `itemHash` as this scanner's | `gws_gmail`, `gws_drive`, `gws_shared_drive` | `alerts_only`, `policy_matches_only` |
| Slack | Slack DLP | the Audit Logs API's DLP events, as class `other` (the action) on the message or file they name | `slack_channel`, `slack_dm` | `enterprise_grid_only`, `policy_matches_only`, `no_data_class` |
| Google Cloud | Sensitive Data Protection | its discovery's data profiles: `columnDataProfiles` (a BigQuery column's predicted info type, on the same `store_field` as this scanner's BigQuery findings) and `fileStoreDataProfiles` (the info types found in a Cloud Storage bucket, on the bucket), in each of `SDP_LOCATIONS`; never its inspection results, which can quote matched text | `bigquery`, `gcs` | `profiled_stores_only`, `profiles_not_items`, `sampled_by_vendor` |

Macie's managed data identifiers map to the spec's classes:
`CREDIT_CARD_NUMBER`, `CREDIT_CARD_NUMBER_(NO_KEYWORD)` and
`CREDIT_CARD_MAGNETIC_STRIPE` to `card`, `CREDIT_CARD_SECURITY_CODE` to `cvv`,
`USA_SOCIAL_SECURITY_NUMBER` to `us_ssn`,
`USA_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER` to `us_itin`, `DATE_OF_BIRTH` to
`dob`, `BANK_ACCOUNT_NUMBER` and `USA_BANK_ACCOUNT_NUMBER` to
`account_number`; any other type, and each custom data identifier, to `other`.
The scanner never calls `GetSensitiveDataOccurrences`, which reveals samples
of the values, and its template denies it.

## Where findings go

**Batch mode (now).** Each scheduled run writes to the results bucket in the
scanned account:

| Key | What |
|---|---|
| `findings/latest.json` | The findings document for the latest run |
| `findings/runs/<runId>.json` | One document per run |
| `state/…` | The scanner's own cursors and lock. A consumer never needs these; grant it `findings/*` only |

Findings carry over between runs. An S3 object's findings are replaced when a
new version of it is read, and dropped when the object is deleted. A log
event's findings stay (log events do not change) up to a cap of 20,000
stored findings.

**Push: optional in batch mode, and the phase 2 design.** Set
`FINDINGS_EVENT_BUS_ARN` to a consumer-owned EventBridge bus (Mermera's, or
anyone's). After writing the results bucket, the runner calls `PutEvents` from
the scanned account onto that bus:

```json
{
  "Source": "sensitive-data-scanner",
  "DetailType": "Findings v1",
  "EventBusName": "arn:aws:events:us-west-2:<consumer-account>:event-bus/<bus>",
  "Detail": "{ …a findings document, plus \"part\" and \"parts\"… }"
}
```

- The `detail` is a findings document (the same schema) holding a slice of
  the run's findings, coverage and discovered stores. The union of the
  parts is the document.
- Each event stays under EventBridge's 256 KB limit, so a large run is split:
  `part` counts from 1 up to `parts`.
- The consumer's bus policy allows `events:PutEvents` from the scanned
  account. The consumer receives events and never calls in.
- `source` and `detail-type` are versioned with the schema: a breaking change
  to the document becomes `Findings v2`.

## The document

```json
{
  "schema": "sensitive-data-scanner.findings",
  "schemaVersion": "1.3",
  "scannerVersion": "0.2.0",
  "specVersion": "0.4",
  "runId": "20260929T060000Z-1a2b3c4d",
  "account": "123456789012",
  "region": "us-west-2",
  "startedAt": "2026-09-29T06:00:00+00:00",
  "finishedAt": "2026-09-29T06:04:10+00:00",
  "classes": ["us_ssn", "us_itin", "card", "dob", "cvv", "pin", "account_number", "us_ssn_last4"],
  "coverage": [ "… one per source …" ],
  "findings": [ "…" ],
  "findingsTotal": 3,
  "findingsTruncated": false,
  "totals": { "card": 2, "us_ssn": 1 },
  "discovery": { "…": "present when discovery is on (below)" }
}
```

`findings` holds at most 5,000 findings, the most severe and largest first.
`findingsTotal` and `findingsTruncated` say whether any were left out.
`totals` counts distinct values per class across all findings.

### A finding

One class of data at one location.

```json
{
  "id": "c87765820340c54300edbe0ae2bb0bfc",
  "resource": {
    "type": "s3_object",
    "bucket": "example-connect-data",
    "key": "connect/x/Analysis/Voice/2026/09/28/lens.json",
    "versionId": "f8eefbc2-5886-468e-9fc6-d6d738f57381"
  },
  "format": "contact_lens",
  "class": "us_ssn",
  "severity": "high",
  "count": 1,
  "occurrences": 1,
  "confidence": "high",
  "confidenceCounts": { "high": 1 },
  "via": ["prompt"],
  "offsets": [
    { "pointer": "/Transcript/1/Content", "start": 0, "end": 12 },
    { "pointer": "/Transcript/3/Content", "start": 0, "end": 10 },
    { "pointer": "/Transcript/4/Content", "start": 0, "end": 23 }
  ],
  "offsetsTruncated": false,
  "link": "https://us-west-2.console.aws.amazon.com/s3/object/example-connect-data?region=us-west-2&bucketType=general&prefix=…&versionId=…",
  "connect": { "contactId": "11111111-2222-3333-4444-555555555555", "instanceId": "…" },
  "firstSeenAt": "2026-09-29T06:00:00+00:00",
  "lastSeenAt": "2026-09-29T06:00:00+00:00"
}
```

| Field | Meaning |
|---|---|
| `id` | A stable hash of the resource and class. It stays the same across runs for the same location (and object version). Key triage decisions on it. |
| `resource` | `s3_object`: `bucket`, `key` and the `versionId` that was read (`"null"` when versioning is off). `log_event`: `logGroup`, `logStream` and the event `timestamp` (ms). `dynamodb_item`: `table`, `keyHash`, `key` and `attributePath` (below). |
| `connect` | The Amazon Connect contact and instance, when the item names one: a chat or Contact Lens transcript, or a flow log event. |
| `format` | How the item was read: `contact_lens`, `connect_chat`, `lex_v2_log`, `connect_flow_log`, `lambda_log`, `json`, `csv`, `text`, `dynamodb_item`, or (1.2) `parquet`, `orc`, `avro`, `sql`, or (1.3) `block` (raw EBS blocks), `cql` (Keyspaces) and `rdb` (a Redis snapshot file in S3, read as its text runs; no offsets), or (1.6) `kql` (rows of a Log Analytics query), or (1.8) `docx`, `xlsx`, `pptx`, or (1.9) `pdf` (a PDF's text layer and document information). |
| `class`, `severity` | The spec class (`card`, `us_ssn`, `us_itin`, `dob`, `cvv`, `pin`, `account_number`, `us_ssn_last4`) and its severity. |
| `count` | Distinct values of the class in the item. The same card read out by a caller and read back by the agent counts once. |
| `occurrences` | Every place a value appears in the item. |
| `confidence` | The highest confidence among the occurrences; `confidenceCounts` gives them all. |
| `via` | How the values were found: `prompt` (a bot or agent asked for this class), `context` (a context word was nearby) or `shape` (the value alone looks like it). |
| `offsets` | Where each occurrence is, at most 50 (`offsetsTruncated` says if more exist). `start` and `end` are UTF-16 code units. For a JSON item, `pointer` (RFC 6901) names the string they are in. A value split across a caller's turns has one offset per turn. |
| `link` | A deep link into the account's own AWS console: the S3 object version, the log event, or the DynamoDB table's item explorer (it names no key; query by the masked key). A reviewer follows it with their own access. It is `null` when the key had to be masked. |
| `rescanReason`, `rescanClasses` | (1.10) Present when this run read the object again although it had not changed at its source ([Rescans](#rescans-110)). |
| `duplicateOf` | (1.10) This object was not read: its bytes are those of another object of the same store (the same content fingerprint, under a name of the same kind), read with the same components. The finding is that object's finding as this object's own (its resource, id, link and storage encryption), and `duplicateOf` is the other's finding id. |

### A table finding: a column (1.2)

A Parquet, ORC or Avro file, or an object of a Glue table, gives one finding
per class per column:

```json
{
  "resource": {
    "type": "s3_object",
    "bucket": "example-lake",
    "key": "curated/customers/dt=2026-09-28/part-00000.snappy.parquet",
    "versionId": "null",
    "column": "card_number",
    "catalog": { "database": "curated", "table": "customers" }
  },
  "format": "parquet",
  "class": "card",
  "count": 2,
  "offsets": [
    { "pointer": "/0/card_number", "start": 0, "end": 16 },
    { "pointer": "/1/card_number", "start": 0, "end": 16 }
  ]
}
```

| Field | Meaning |
|---|---|
| `column` | The column the values are in, masked like a key. A nested column's offsets point inside it (`/0/payment/pan`) |
| `catalog` | For an object read as part of a Glue table: its `database` and `table`, masked like keys |
| `offsets[].pointer` | `/<row>/<column>`: the row within the file (from 0), and the column |

### An RDS or Aurora finding: a database column (1.2)

```json
{
  "resource": {
    "type": "rds_column",
    "engine": "aurora-postgresql",
    "dbType": "cluster",
    "cluster": "orders",
    "database": "app",
    "table": "public.customers",
    "column": "card_number",
    "readBy": "snapshot_export",
    "snapshotTime": "2026-09-29T06:10:00+00:00"
  },
  "format": "parquet",
  "class": "card",
  "count": 2,
  "offsets": [],
  "link": "https://us-west-2.console.aws.amazon.com/rds/home?region=us-west-2#database:id=orders;is-cluster=true"
}
```

| Field | Meaning |
|---|---|
| `engine`, `dbType`, `cluster` | The engine, and the DB cluster (or, with `dbType: instance`, DB instance) identifier |
| `database`, `table`, `column` | Where the values are: `table` is `schema.table` (for MySQL, `database.table`), so the location reads `schema.table.column` |
| `readBy` | `snapshot_export` (an export of the latest automated snapshot, deleted after reading) or `data_api` (opt-in read-only SQL; format `sql`) |
| `snapshotTime` | When the exported snapshot was taken. The id does not include it, so a finding keeps its id from one snapshot to the next |
| `offsets` | Empty: the rows are not addressable once the export is deleted. `count` adds up across the table's files |

### Any other store: a field (1.3)

Stores other than S3, CloudWatch Logs, DynamoDB and RDS report one class in
one field of one store as `store_field`. A Redshift column:

```json
{
  "resource": {
    "type": "store_field",
    "service": "redshift",
    "store": "warehouse",
    "database": "dev",
    "table": "public.customers",
    "field": "card_number",
    "readBy": "data_api"
  },
  "format": "sql",
  "class": "card",
  "count": 1,
  "offsets": [],
  "link": "https://us-west-2.console.aws.amazon.com/redshiftv2/home?region=us-west-2#cluster-details?cluster=warehouse"
}
```

| Field | Meaning |
|---|---|
| `service` | The product: `redshift` (a provisioned cluster), `redshift_serverless` (a workgroup), `opensearch` (a managed domain), `opensearch_serverless` (a collection) `ebs` (a volume, or a snapshot whose volume is gone), `kinesis` (a stream), `sqs` (a dead-letter queue), `ssm` (a parameter), `secretsmanager` (a secret; the value itself is never reported), `timestream` or `keyspaces` (a table's column), or (1.5) `stepfunctions` (a state machine's execution history), `lambda` (a function's environment variable; counts only, like a secret), `xray` (a traced service's annotations or metadata), `codecommit` (a repository's file), `msk` (a Kafka topic's records), `mq` (an ActiveMQ queue's messages, browsed), `ecr` (a file in an image layer), `neptune_analytics` (a graph's property, by export), `eventbridge` (an archive's events, by replay). Firehose findings are the S3 objects it delivered (`s3_object`), and a directory bucket's are `s3_object` too |
| `store` | The cluster or workgroup (and, for later kinds, the domain, stream, queue, parameter or secret), masked like a key |
| `database`, `table`, `field` | Where the values are, as far as the store has them: for Redshift the database, `schema.table` and the column; for OpenSearch the index (`table`) and the document's top-level field; for EBS `field: blocks` (the raw blocks; no file path); for Kinesis `field: records`, for SQS `field: messages`, for a parameter or a secret `field: value`; for Timestream and Keyspaces the database or keyspace as `store`, the `table` and the column as `field`; (1.5) for Step Functions the state machine as `store` and the event's `input`, `output`, `parameters`, `result`, `error` or `cause` as `field`; for Lambda the function and the variable's name; for X-Ray the segment's service as `store` and `annotations` or `metadata`; for CodeCommit the repository and the file's path; for MSK the cluster, the topic as `table` and `field: records`; for Amazon MQ the broker, the queue as `table` and `field: messages`; for ECR the repository, the layer's digest (19 characters) as `table` and the file's path; for Neptune Analytics the graph, `nodes` or `edges` as `table` and the property; for an EventBridge archive the archive and `field: events`. A SageMaker feature group's offline store is read as S3 objects (`s3_object`) |
| `readBy` | How it was read: `data_api` for Redshift, `search` for OpenSearch, `ebs_direct` for EBS, `shard_sample` for Kinesis, `receive` for SQS, `get_parameters` for SSM, `get_secret_value` for Secrets Manager, `query` for Timestream, `cql` for Keyspaces, (1.5) `execution_history` for Step Functions, `get_function_configuration` for Lambda, `batch_get_traces` for X-Ray, `get_file` for CodeCommit, `consumer_sample` for MSK, `browse` for Amazon MQ, `layer_sample` for ECR, `export` for Neptune Analytics, `replay` for an EventBridge archive |
| `snapshotTime` | For EBS: when the snapshot read was taken. Not part of the id |
| `offsets` | Empty: a sampled row is not addressable later. `count` is distinct values in the sample |

Azure's databases (1.6) report the same way: `service` is the kind
(`azure_sql`, `azure_sql_mi`, `azure_postgresql`, `azure_mysql`,
`synapse_sql`), `store` the server, instance or workspace, `database` the
database or SQL pool, `table` as `schema.table`, `readBy: sample`, format
`sql`, with `subscription`, `resourceGroup` and `resourceIdHash` (of the
database's resource) and a portal `link` to the database. Cosmos DB for
NoSQL (`cosmosdb`) names the account as `store`, the database, the container
as `table` and the item's top-level property as `field`, `readBy: query`,
format `json`; MongoDB vCore (`cosmosdb_mongo`) the cluster, database,
collection and field, `readBy: sample`. Table Storage (`azure_table`): the
account, the table and the entity's property, `readBy: sample`; Queue
Storage (`azure_queue`): the account, the queue and `field: messages`,
`readBy: peek`. Log Analytics (`log_analytics`): the workspace as `store`,
the table as `table` and the column as `field`, `readBy: kql`, format `kql`.
Key Vault (`key_vault`, opt-in): the vault as `store`, the secret's name as
`table`, `field: value`, `readBy: get_secret`, counts only, like Secrets
Manager.

Google Cloud's stores (1.7) report the same way, with `project` and
`resourceNameHash` (of the store's full resource name) and a console `link`.
BigQuery (`bigquery`): the dataset as `store`, the table as `table` and the
column as `field`, `readBy: tabledata_list`, format `json`. Cloud SQL
(`cloudsql_postgresql`, `cloudsql_mysql`) and AlloyDB (`alloydb`): the
instance or cluster as `store`, then `database`, `schema.table` and the
column, `readBy: sample`, format `sql`. Firestore (`firestore`) and
Datastore (`datastore`): the database as `store`, the collection or kind as
`table` and the top-level field as `field`, `readBy: query`, format `json`.
Spanner (`spanner`): the instance as `store`, the database, the table and the
column, `readBy: sample`, format `sql`. Bigtable (`bigtable`): the instance
as `store`, the table as `table` and `family:qualifier` (or `rowKey`) as
`field`, `readBy: read_rows`, format `json`. Cloud Logging
(`cloud_logging`): the project as `store`, the log as `table` and the entry's
column (`textPayload`, `jsonPayload.<field>`, `protoPayload.<field>`,
`labels`) as `field`, `readBy: entries_list`, format `json`. Secret Manager
(`secret_manager`, opt-in): the project as `store`, the secret's name as
`table`, `field: value`, `readBy: access`, counts only, like Secrets Manager.

The shape names no cloud, so a store elsewhere reports the same way. The
databases runner (1.4) reports every engine's columns, and MongoDB's
top-level fields, as `store_field` with `service` the engine
(`postgresql`, `mysql`, `sqlserver`, `oracle`, `mongodb`, `snowflake`,
`databricks`), `store` the name the customer gave the database, `database`
the database (or catalog) connected to, `table` as `schema.table` (for
MongoDB, `database.collection`), `readBy: sample`, format `sql` (MongoDB:
`json`) and no `link`.

### An Azure blob (1.6)

A blob of a Blob Storage or ADLS Gen2 container, read like an S3 object
(text, JSON, CSV, and a table file by column):

```json
{
  "resource": {
    "type": "blob_object",
    "account": "contosolake",
    "container": "raw",
    "blob": "exports/cards.csv",
    "versionId": "null",
    "subscription": "11111111-2222-3333-4444-555555555555",
    "resourceGroup": "rg-data",
    "resourceIdHash": "9a1f…(64 hex)"
  },
  "format": "csv",
  "class": "card",
  "atRestEncryption": "service_managed",
  "link": "https://portal.azure.com/#resource/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/contosolake/containersList"
}
```

| Field | Meaning |
|---|---|
| `account`, `container`, `blob` | The storage account, the container and the blob's name (an ADLS Gen2 path), masked like a key |
| `versionId` | The blob version read, `"null"` when versioning is off |
| `column` | For a Parquet, ORC or Avro file, the column, as for S3 |
| `subscription`, `resourceGroup` | Where the storage account is; the group masked like a key. Every Azure store's finding (a `store_field` too) carries them |
| `resourceIdHash` | The SHA-256 of the store's Azure resource ID in lower case (for a blob, the storage account's). The ID is never written: it names the group and the resource |
| `link` | The storage account's page in the Azure portal; `null` when the subscription, group or account name had to be masked |

### An Azure Files file (1.7)

A file of an Azure Files share, read like a blob (text, JSON, CSV, and a table
file by column), when `AZURE_FILES_READ` is on:

| Field | Meaning |
|---|---|
| `account`, `share`, `path` | The storage account, the share and the file's path in it, masked like a key |
| `column` | For a Parquet, ORC or Avro file, the column |
| `subscription`, `resourceGroup`, `resourceIdHash` | As for a blob: the storage account's |
| `link` | The storage account's file shares in the Azure portal; `null` when the subscription, group or account name had to be masked |

### A Cloud Storage object (1.7)

An object of a Google Cloud Storage bucket, read like an S3 object (text,
JSON, CSV, and a table file by column):

```json
{
  "resource": {
    "type": "gcs_object",
    "bucket": "acme-lake",
    "object": "exports/cards.csv",
    "generation": "1700000000000001",
    "project": "acme-data",
    "resourceNameHash": "4be0…(64 hex)"
  },
  "format": "csv",
  "class": "card",
  "atRestEncryption": "service_managed",
  "link": "https://console.cloud.google.com/storage/browser/acme-lake?project=acme-data"
}
```

| Field | Meaning |
|---|---|
| `bucket`, `object` | The bucket and the object's name, masked like a key |
| `generation` | The object generation read |
| `column` | For a Parquet, ORC or Avro file, the column, as for S3 |
| `project` | The project the bucket is in, masked like a key. Every Google Cloud store's finding (a `store_field` too) carries it |
| `resourceNameHash` | The SHA-256 of the store's full resource name exactly as Cloud Asset Inventory gives it (for an object, its bucket's: `//storage.googleapis.com/<bucket>`). The name is never written |
| `link` | The bucket's page in the Google Cloud console; `null` when the bucket or project name had to be masked |

### A SaaS item (1.8)

A message, a file, or a part of one (an attachment, a reply) in a SaaS
tenant, read by the SaaS scanner ([SAAS.md](SAAS.md)). A person is named only
by the SHA-256 of their address (`ownerHash`); an address is never written,
masked or not.

```json
{
  "resource": {
    "type": "saas_item",
    "vendor": "m365",
    "service": "sharepoint",
    "tenantHash": "9f2c…(64 hex)",
    "container": "Finance",
    "channel": "Documents",
    "itemId": "01ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "itemHash": "c01e…(64 hex)",
    "part": "file",
    "name": "roster.xlsx"
  },
  "format": "xlsx",
  "class": "us_ssn",
  "atRestEncryption": "service_managed",
  "link": "https://contoso.sharepoint.com/_layouts/15/Doc.aspx?sourcedoc=%7B…%7D&action=default"
}
```

| Field | Meaning |
|---|---|
| `vendor`, `service` | `m365`: `exchange`, `onedrive`, `sharepoint`, `teams_channel`, `teams_chat`; `google_workspace`: `gmail`, `drive`, `shared_drive`; `slack`: `channel`, `dm`; `atlassian`: `jira`, `confluence` |
| `tenantHash` | The SHA-256 of the tenant's id, lower-case (Microsoft 365: the Entra tenant id; Google Workspace: the customer id; Slack: the Enterprise Grid organization's id, else the workspace's; Atlassian: the site's cloud id) |
| `ownerHash` | The SHA-256 of the mailbox's, drive's or chat's owner (their principal name, lower-case) |
| `container`, `channel` | The site and document library, or the team and channel, masked like keys |
| `itemId`, `itemHash` | The vendor's id for the item, masked like a key, and its SHA-256 (two ids that mask alike stay two findings) |
| `part` | `message` (a subject and body), `attachment`, `file`, `reply`, `issue` (a Jira issue's summary, description and comments), `page` (a Confluence page's title, body and comments) |
| `name`, `column` | A file's or attachment's name, masked like a key; for a table file, the column |
| `link` | The item in the vendor's own web app, built from ids only (a message in Outlook on the web, a SharePoint or OneDrive file by its unique id, a Teams channel, a Google Drive file by its id, a Slack channel, a Jira issue by its key, a Confluence page by its id; Gmail and Slack direct messages have none); `null` when an id it carries had to be masked |

### A DynamoDB finding

One class of data in one attribute path of one item:

```json
{
  "resource": {
    "type": "dynamodb_item",
    "table": "stugum",
    "keyHash": "3f1c…(64 hex)",
    "key": { "pk": "T#t_0123abcd", "sk": "RUN#2026-09-29T15:00:00Z#r_0123" },
    "attributePath": "stepResults[].observedDtmf"
  },
  "format": "dynamodb_item",
  "class": "us_ssn",
  "via": ["prompt"],
  "offsets": [{ "pointer": "/stepResults/3/observedDtmf", "start": 0, "end": 9 }],
  "link": "https://us-west-2.console.aws.amazon.com/dynamodbv2/home?region=us-west-2#item-explorer?table=stugum"
}
```

(Other fields as above.)

| Field | Meaning |
|---|---|
| `keyHash` | HMAC-SHA256 of the item's key under a random salt in the scanner's state. Stable across runs; never the key. |
| `key` | The key attributes, each value masked like an S3 object key; `keyMasked: true` when anything was masked. |
| `attributePath` | The attribute, with `[]` for every list element, whatever condition (`[kind=sendDtmf]`) the configuration selected it by. Each offset's `pointer` names the exact element. Findings in different paths are different findings. |
| `planted` | `true` when the path is configured as planted test input (a test script's steps), not a leak. |

The DynamoDB resource, format and coverage kind are new in schema 1.1
(additive): they appear only when a DynamoDB source is configured.

### Archives, PDFs and disguised files (1.9)

An object is read by what its first bytes are, not by what its name says
([#65](https://github.com/txp-labs/sensitive-data-scanner/issues/65)). A
Word document renamed `notes.fff` or `photo.jpg` is read as Word; a zip, a
tar, or a gzip, bzip2 or xz stream is read entry by entry (nested up to three
levels; a `.tar.gz` is one); a PDF is read as its text layer. A finding in an
archive entry names the entry, and a finding in a file whose name claims
another kind says so:

```json
{
  "resource": {
    "type": "s3_object",
    "bucket": "example-drop",
    "key": "exports/holiday.jpg",
    "versionId": "null",
    "archivePath": "hr/#########.zip!/people.csv",
    "archivePathMasked": true,
    "archiveEntry": "3/0"
  },
  "format": "csv",
  "class": "us_ssn",
  "disguised": true,
  "declaredType": "image",
  "detectedType": "zip"
}
```

(Other fields as above.)

| Field | Meaning |
|---|---|
| `archivePath` | On the resource of a finding inside an archive: the entry's path in it, with `!/` between nested archives (`backup.zip!/inner.zip!/x.csv` names `x.csv` in `inner.zip` in `backup.zip`'s entry), masked like a key. A single compressed stream (`x.csv.gz`) is the file it holds: no `archivePath`. Two entries are two locations, so two findings |
| `archivePathMasked`, `archiveEntry` | When masking changed the path: `true`, and the entry's position in its archive, one number per level (`3/0`: the first entry of the fourth entry), so two entries whose paths mask alike stay apart. Nothing derived from the path (no hash: a number in a name is quickly guessed from its hash) is written. A masked `archivePath` does not drop the link, which names the object |
| `disguised` | `true` when the object's name (or the entry's, or an archive's holding it) claims one kind and its bytes are another. Absent otherwise |
| `declaredType` | What the name's extension claims: `text`, `zip`, `docx`, `xlsx`, `pptx`, `ole`, `pdf`, `gzip`, `bzip2`, `xz`, `zstd`, `tar`, `7z`, `parquet`, `orc`, `avro`, `rdb`, `image`, `audio`, `video`, `binary`, or `unknown` (an extension the scanner does not know). A kind, never the name. A name with no extension claims nothing |
| `detectedType` | What the bytes are, in the same terms (and `parquet_encrypted`) |

Not a disguise: a zip named as a Word file's kind, or a rights-managed Word
file (an OLE container) named `.docx`; audio in a video container; content
the scanner cannot name (`binary`); text under an unknown extension. A
mismatch is counted in coverage (`disguised`) and in the run summary's
`gaps`, whether or not anything was found in the file.

The caps: all that is inflated from one object stops at
`MAX_INFLATED_BYTES`, an archive's entries at 1,000, and an entry at 200
times its compressed size (past 1 MiB), the zip-bomb guard; a PDF at 500
pages. An object a cap cut is `partial`. An entry whose first bytes say it
is audio, video, an image or binary is counted without inflating the rest.
Nothing is ever written to disk. What is not read is counted in `skipped` by
kind ([Coverage](#coverage)): a 7z archive is `archive_unsupported`, a PDF
with no text layer `pdf_image_only` (OCR is out of scope), a
password-protected zip, zip entry or PDF `encrypted`. A PDF encrypted only
for its permissions (an empty user password) opens for anyone, so it is read.

### Rescans (1.10)

An object that did not change at its source is read again only when a
component it was last read with has changed, and that change could change
what the read finds
([#67](https://github.com/txp-labs/sensitive-data-scanner/issues/67);
[ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)). Its findings say
why:

```json
{
  "resource": { "type": "s3_object", "bucket": "example-drop", "key": "hr/letter.pdf", "versionId": "null" },
  "format": "pdf",
  "class": "us_ssn",
  "rescanReason": "spec_standalone",
  "rescanClasses": ["us_itin"]
}
```

| `rescanReason` | The object was read again because |
|---|---|
| `adapter` | The adapter that reads its store changed (that adapter's objects only) |
| `reader` | A reader it was read with changed (on every platform; an archive is read by its own reader and its entries') |
| `new_reader` | It held a kind no reader read (7z, older Office files, images; Parquet in the Lambda zip), and one does now |
| `sniffer` | The sniffer changed, and what the object is was undetermined (`binary`) or disputed (`disguised`) |
| `spec_standalone` | The unprompted rules changed, and the object was read as text or a table. `rescanClasses` names the classes when only their own rules changed or they are new |
| `spec_conversation` | The prompts, carryover, normalization or answer windows changed, and part of the object was a conversation (a transcript) |
| `unindexed` | It has no row in the object index: it was read before the index knew it, or by a scanner with the index off |

A finding from a read for a change at the source carries neither field. The
next read of the object replaces its findings, and the fields with them.

A source that keeps an object index says in its coverage how many objects the
index holds, what it read again and why, what is still owed, and how many
copies it did not read:

```json
{
  "kind": "s3",
  "target": "example-drop/",
  "listed": 120000,
  "eligible": 310,
  "scanned": 5310,
  "indexed": 120000,
  "rescanned": { "reader": 5000 },
  "rescanBacklog": 7200,
  "duplicates": 42
}
```

(Other coverage fields as below.) Here 310 objects changed at their source and
were read. 5,000 unchanged ones were read again because a reader they were read
with changed (the rescan share of the run), and 7,200 such objects are still
to come, in later runs. 42 copies of objects already read were not read: their
findings carry `duplicateOf`.

### Names are masked

In a bucket name or key, log group or log stream name, DynamoDB table name,
or a discovered store's name, any run of digits that could be a card number
or an SSN is replaced with `#`:

- a Luhn-valid run of 13-19 digits;
- a 3-2-4 or bare nine-digit run;
- any run of 13 or more digits.

The resource then carries `keyMasked: true` (or `nameMasked: true`). Object
keys, log stream names, DynamoDB key values and attribute paths, source
targets and error names all go through the same masking.

A `link` is `null` only when a name it would carry was masked, because it
would carry that name unmasked. Each link names only some of the resource:

| Resource | The link names | So a masked… |
|---|---|---|
| `s3_object` | the bucket and the key | bucket or key drops it; a masked column or catalog name does not |
| `log_event` | the log group and stream | group or stream drops it |
| `dynamodb_item` | the table only (the item explorer); never a key | table drops it; a masked key or attribute path does not |
| `rds_column` | the cluster or instance | identifier drops it; a masked database, table or column does not |
| `store_field` (Redshift, OpenSearch) | the cluster, workgroup, domain or collection | store drops it; a masked database, table, index or field does not |
| `blob_object`, `azure_file` (1.7) and Azure's `store_field` (1.6) | the subscription, resource group and resource (the storage account, server, ...) | any of them drops it; a masked container, share, blob, path, table or column does not |
| `gcs_object` and Google Cloud's `store_field` (1.7) | the project and the store (the bucket, dataset, instance, ...) | any of them drops it; a masked object, table or column does not |
| `saas_item` (1.8) | ids only: a message id, a SharePoint host and file unique id, a Teams channel and team id, a Drive file id, a Slack team and channel id, a Jira issue key, a Confluence page id (and the Atlassian site) | any of them drops it; a masked name, container or channel does not |

So a DynamoDB item keyed by a tenant id with a bare nine-digit run, such as
`T#t_#########`, keeps its link to the table. The reviewer opens the table
and finds the item from the masked key and the finding's other fields. In
0.2.0 and earlier, any masking dropped the link.

### At-rest encryption and PCI DSS notes (1.5)

Every finding says what storage encryption its data sat under, from the
store's own configuration, and a card or CVV finding carries a note for the
customer's PCI DSS assessor:

```json
{
  "class": "card",
  "resource": { "type": "s3_object", "bucket": "example-lake", "key": "exports/cards.csv", "versionId": "null" },
  "atRestEncryption": "customer_managed_key",
  "atRestKeyHash": "5c2a…(64 hex)",
  "pciNote": {
    "requirement": "3.5.1.2",
    "guidance": "PCI DSS 3.5.1.2: storage-level encryption (disk, volume or the service's at-rest encryption) alone does not render PAN unreadable on non-removable media; PAN is also to be rendered unreadable by one of the methods in 3.5.1. For your QSA to assess; the QSA decides."
  }
}
```

| Field | Meaning |
|---|---|
| `atRestEncryption` | `none` (the store says the data is not encrypted at rest), `service_managed` (a key the service holds: SSE-S3, an AWS owned key, an AWS managed key such as `aws/dynamodb` or `aws/ebs`, a database platform's own encryption), `customer_managed_key` (a KMS key, or a database's TDE key, the customer holds) or `unknown` (the store does not say, or its key could not be told apart). Absent on a finding stored before 1.5 until its location is read again |
| `atRestKeyHash` | For `customer_managed_key` (and for `unknown` when a key id is known): the SHA-256 of the key's id, the part after `key/` in its ARN, as lower-case hex. The key's id, ARN and aliases are never written. Hash your key's id to match: `printf %s 1234abcd-12ab-34cd-56ef-1234567890ab \| shasum -a 256` |
| `pciNote` | Guidance for the customer's QSA, never a verdict: `requirement` and `guidance` (below). Present only on the findings it applies to |

Where each store's value comes from:

| Store | From |
|---|---|
| S3 object (and Glue tables, Firehose destinations, exported caches) | The object's own `x-amz-server-side-encryption` header, from the GET that read it: `AES256` is `service_managed`; `aws:kms` and `aws:kms:dsse` go by the key; no header is an object stored without encryption, `none`, whatever the bucket's default is now. The run summary gives the bucket's default (`GetBucketEncryption`) |
| CloudWatch Logs | The group's `kmsKeyId`, else `service_managed` (every group is encrypted) |
| DynamoDB (and its exports) | The table's `SSEDescription`: none is the AWS owned key; `KMS` goes by the key |
| RDS and Aurora (export and Data API) | The cluster's or instance's `StorageEncrypted` and `KmsKeyId`, not the export's |
| Redshift | A cluster's `Encrypted` and `KmsKeyId`; a Serverless namespace's `kmsKeyId` (`AWS_OWNED_KMS_KEY` is `service_managed`) |
| OpenSearch | A domain's `EncryptionAtRestOptions`; a collection's `kmsKeyArn` (`auto` is `service_managed`) |
| EBS | The volume's (or, for a snapshot whose volume is gone, the snapshot's) `Encrypted` and `KmsKeyId` |
| Kinesis | `DescribeStreamSummary`'s `EncryptionType` and `KeyId` |
| SQS | `KmsMasterKeyId`, or `SqsManagedSseEnabled` (`service_managed`); neither is `none` |
| Parameter Store | Per parameter: a `SecureString`'s `KeyId` (`alias/aws/ssm` by default); a `String` or `StringList` is `unknown` (AWS documents no key for them) |
| Secrets Manager | Per secret: its `KmsKeyId`, else `aws/secretsmanager` (`service_managed`) |
| Timestream, Keyspaces | The database's `KmsKeyId`; the table's `encryptionSpecification` |
| Azure Blob Storage and ADLS Gen2 (1.6) | The blob's encryption scope (from the listing), else its container's default scope, else the account's encryption: `Microsoft.Storage` is `service_managed`; `Microsoft.Keyvault` is `customer_managed_key`, hashed from the key's versionless identifier in lower case (`https://<vault>.vault.azure.net/keys/<name>`). Azure Storage always encrypts, so never `none`. The run summary gives the container's default |
| Azure Files (1.7) | The storage account's key: `Microsoft.Storage` is `service_managed`; `Microsoft.Keyvault` is `customer_managed_key`, hashed as for blobs |
| Azure disk snapshots, Key Vault (1.6) | A snapshot's `encryption.type`: a platform key is `service_managed`, a customer key through a disk encryption set `customer_managed_key` (hashed from the set's active key). Key Vault's secrets: `service_managed` |
| Cloud Logging, Pub/Sub, disk snapshots, Secret Manager (1.7) | The `_Default` log bucket's, the topic's, the snapshot's or the secret's Cloud KMS key: `customer_managed_key`, hashed (a snapshot under a customer-supplied key: `customer_managed_key`, no hash); else `service_managed` |
| Firestore, Datastore, Spanner, Bigtable (1.7) | The database's CMEK (`cmekConfig`, `encryptionConfig`) or, for Bigtable, a cluster's: `customer_managed_key`, hashed; else `service_managed` |
| Cloud SQL, AlloyDB (1.7) | The instance's (`diskEncryptionConfiguration`) or the cluster's (`encryptionConfig`) Cloud KMS key: `customer_managed_key`, hashed; else `service_managed` |
| BigQuery (1.7) | The table's own Cloud KMS key, else its dataset's default key: `customer_managed_key`, hashed from the key's resource name; else `service_managed` |
| Google Cloud Storage (1.7) | The object's own `kmsKeyName` (a CMEK): `customer_managed_key`, hashed from the key's resource name without its version (`projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`); else Google's own keys, `service_managed`. Google Cloud always encrypts, so never `none`. An object under a customer-supplied key (CSEK) is never read (`kmsDenied`). The run summary gives the bucket's default key |
| Atlassian (1.8) | Atlassian's own keys, `service_managed`; with Atlassian Cloud BYOK, the key id the customer gives (`ATLASSIAN_BYOK_KEY_ID`): `customer_managed_key`, hashed |
| Slack (1.8) | Slack's own keys, `service_managed`; with Slack Enterprise Key Management, the key id the customer gives (`SLACK_EKM_KEY_ID`): `customer_managed_key`, hashed |
| Google Workspace (1.8) | Google's own keys, `service_managed` (Workspace has no customer-managed key for Gmail or Drive); a client-side encrypted file is never read |
| Microsoft 365 (1.8) | Microsoft's own keys, `service_managed`; with Microsoft Purview Customer Key, the data encryption policy id the customer gives (`M365_CUSTOMER_KEY_ID`): `customer_managed_key`, hashed. A rights-managed Office file is never read (skip kind `encrypted`) |
| Azure Log Analytics (1.6) | The workspace's dedicated cluster's Key Vault key (`customer_managed_key`, hashed), else `service_managed` |
| Azure Cosmos DB, Table and Queue Storage (1.6) | Cosmos DB: the account's or vCore cluster's Key Vault key (`customer_managed_key`, hashed), else `service_managed`. Tables and queues: the account's key when its encryption covers the service (`keyType: Account`), else `service_managed` |
| Azure's databases (1.6) | From Resource Manager: an Azure SQL server's or Managed Instance's TDE protector (`ServiceManaged` is `service_managed`; an `AzureKeyVault` key `customer_managed_key`, hashed as above), a database-level key first, TDE off `unknown`; a flexible server's `dataEncryption` (`SystemManaged` or `AzureKeyVault`); a Synapse workspace's customer key, else the pool's TDE |
| The databases runner | SQL Server: TDE on (`sys.databases.is_encrypted`) is `customer_managed_key` (a certificate in the customer's own master database, or an asymmetric key in Key Vault or an EKM provider), except Azure SQL's service-managed certificate (`service_managed`). MySQL and MariaDB: every base table created encrypted is `customer_managed_key`. Snowflake and MongoDB Atlas: `service_managed`. Everything else, TDE off included, is `unknown`: a database cannot see the disk under it. A database names no key, so no hash |

A KMS key named by its id or ARN is told apart with one `kms:ListAliases`
per run: a key behind an `alias/aws/…` alias is AWS managed; any other key,
including one in another account, is the customer's. Without that listing,
only an `alias/aws/…` name is known, and any other key is `unknown` with its
hash.

**The PCI DSS notes.** They are guidance; the customer's QSA decides:

| `requirement` | On | Says |
|---|---|---|
| `3.3.1` | every `cvv` finding, whatever `atRestEncryption` | Sensitive authentication data is not retained after authorization, even if encrypted (3.3.1.2 names the card verification code): a card verification code in storage is prohibited storage after authorization |
| `3.5.1.2` | a `card` finding whose `atRestEncryption` is `service_managed` or `customer_managed_key` | Storage-level encryption (disk, volume, or the service's at-rest encryption) alone does not render PAN unreadable on non-removable media; PAN is also to be rendered unreadable by one of the methods in 3.5.1 |

A `card` finding under `none` or `unknown` carries no note: its storage
encryption is not what makes it a question for the assessor.

### Coverage

One entry per source says what was, and was not, read:

| Field | Meaning |
|---|---|
| `kind`, `target` | `s3` with `bucket/prefix`, `cloudwatch_logs` with the log group, `dynamodb` with the table (`<table> (query)` for a partition Query, `<table> (export)` for an Export to S3), `glue_table` with `database.table`, `rds` with `cluster:<id>`, `instance:<id>` or `data_api:<cluster>/<database>` (1.2), `redshift` with `cluster:<id>` or `workgroup:<name>`, `opensearch` with `domain:<name>` or `collection:<name>`, `ebs` with the volume or snapshot id, `kinesis` with the stream, `sqs` with the queue, `ssm` with `parameter-store`, `secretsmanager` with `secrets-manager`, `timestream` and `keyspaces` with `database.table`; a Firehose stream's S3 locations are `s3` with `bucket/prefix` (1.3); (1.5) `stepfunctions` and `lambda` with the state machine or function, `xray` with `xray-traces`, `codecommit` with the repository, `s3_directory` with `bucket/`, `msk` with the cluster, `mq` with the broker, `ecr` with the repository, `neptune_analytics` with the graph, `eventbridge_archive` with the archive; a feature group's offline store is `s3` with `bucket/prefix` |
| `listed`, `eligible`, `scanned` | Objects listed, events returned, or DynamoDB items evaluated (`ScannedCount`); the new or changed ones (for DynamoDB, the items returned); the ones read this run |
| `sampledOut`, `samplePercent` | Left out by sampling. Sampling is stated, never silent |
| `partial` | Read only in part: the head of a large object, or a log window cut short by the run's budget |
| `unreadable` | Listed but could not be read (a KMS key the scanner may not use, or an object deleted mid-run) |
| `bytesScanned` | Bytes read |
| `skipped` | Not read, by kind: audio, video, image, document, archive, binary, or (1.2) `columnar`: a Parquet, ORC, zstd or snappy/zstandard Avro file this build cannot read (the Lambda zip; the container image reads them), or one whose byte cap fell before its first rows, or (1.6) `archive_tier`: an Azure blob in the Archive tier, which only a rehydration (a write) could read, and `billed_plan`: a Log Analytics table on the Basic or Auxiliary plan, billed per query, or (1.7) `private_log`: a Cloud Logging Data Access audit log, read only with Private Logs Viewer (opt-in), or (1.8) `encrypted`: a rights-managed (encrypted) Office file, `too_large`: an attachment over `MAX_OBJECT_BYTES`, and `linked_item`: an attached item or a link to a file another store reads, or (1.9) `archive_unsupported`: a 7z archive, or a zip entry in a compression method the standard library lacks, and `pdf_image_only`: a PDF with pages and no text layer (a scan; OCR is out of scope). The kind is what the bytes are, whatever the name says (1.9); `encrypted` is also a password-protected zip (or an entry of one) or PDF, and a Parquet file under modular encryption, `document` an older binary Office file or a PDF that cannot be parsed, `archive` an archive nested past three levels or a damaged stream. An archive's entries that are not read are counted here too |
| `formats` | Items by format |
| `testValues` | Published test card numbers and sample SSNs, set apart and never findings |
| `suppressed` | Numbers next to a word like "order" or "phone", with no card word |
| `redactionMarkers` | Contact Lens and Comprehend markers (`[PII]`, `[SSN]`, …) and `[REDACTED]` / `[REDACTED:<label>]` labels: redaction at work, not a finding |
| `passComplete`, `backlog` | Whether everything eligible has been read, or work carries over to the next run |
| `error` | The AWS error name when the source could not be read (`AccessDenied`, `NoSuchBucket`), else `null` |
| `kmsDenied` | Items not read because the scanner may not use their KMS key (1.2; present when not zero) |
| `disguised` | Objects and archive entries whose name claims another kind than their bytes are, read by content (1.9; present when not zero). Counted whether or not anything was found in them |
| `duplicates` | (1.10) Objects not read because their bytes are an indexed object's ([ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)); their findings carry `duplicateOf` |
| `notAllowed` | (1.10) Objects listed and not read because the store's own rules do not allow them, by reason: `key_filter` (a bucket's `keyInclude` / `keyExclude`, [ARCHITECTURE.md](ARCHITECTURE.md#discovery)). Present when not zero |
| `relisted` | (1.11) How this kind of store is listed changed (its `listing:<kind>` component): the run listed it again from the start. Nothing unchanged was read for it ([ARCHITECTURE.md](ARCHITECTURE.md#how-rescans-are-chosen)) |
| `indexed`, `rescanned`, `rescanBacklog` | (1.10) Present when the source keeps an object index: the objects the index holds after the run, the objects read again this run though unchanged at their source by `rescanReason`, and the rescans still owed (objects whose recorded components are stale, and objects with no row met and not read). Later runs read the backlog within `RESCAN_PERCENT` of each source's budget |

### Discovery: the run summary (1.2)

With discovery on (`DISCOVER`), the document carries `discovery`: every
store in the account and region, discovered or named in the configuration,
and what the run did with it. A store that was not read says why, so a
coverage gap is visible rather than silent.

```json
"discovery": {
  "stores": [
    { "kind": "dynamodb", "name": "events", "origin": "discovery", "status": "skipped",
      "reason": "too_large", "sizeBytes": 53687091200 },
    { "kind": "s3", "name": "example-archive", "origin": "discovery", "status": "error",
      "reason": "kms_access", "error": "AccessDenied", "gaps": { "kmsDenied": 12, "unreadable": 12 } },
    { "kind": "s3", "name": "example-connect-data", "origin": "config", "status": "scanned" }
  ],
  "storesTotal": 3,
  "storesTruncated": false,
  "byStatus": { "error": 1, "scanned": 1, "skipped": 1 },
  "byReason": { "kms_access": 1, "too_large": 1 },
  "listErrors": {}
}
```

| Field | Meaning |
|---|---|
| `kind`, `name` | `s3`, `cloudwatch_logs`, `dynamodb`, `glue_table` (`database.table`, or `database.*` for a database whose tables could not be listed), `rds`, or (1.3) `redshift`, `opensearch`, `ebs`, `backup`, `documentdb`, `neptune`, `efs`, `fsx`, `kinesis`, `firehose`, `sqs`, `ssm`, `secretsmanager`, `elasticache`, `memorydb`, `timestream`, `keyspaces`, or (1.4) `postgresql`, `mysql`, `sqlserver`, `oracle`, `mongodb`, `snowflake`, `databricks` (the databases runner: the name is the one the customer gave the database), or (1.5) `stepfunctions`, `lambda`, `xray` (one store, `xray-traces`), `codecommit`, `s3_directory`, `msk`, `mq`, `ecr`, `sagemaker` (`feature-group/<name>` or `notebook-instance/<name>`), `neptune_analytics`, `eventbridge_archive`, `glacier`, or (1.6) Azure's `azure_blob` (`account/container`; `account/*` when the account's containers could not be listed), `azure_sql`, `azure_sql_mi`, `azure_postgresql`, `azure_mysql` (`server/database`; `server/*` when a flexible server's databases could not be listed), `synapse_sql` (`workspace/pool`), `cosmosdb` (`account/database/container`, or `account/*` for an account on another API), `cosmosdb_mongo` (`cluster/*`), `azure_table` (`account/table`), `azure_queue` (`account/queue`), `log_analytics` (the workspace), `azure_disk_snapshot` (the disk, or the snapshot whose disk is gone; `resource: snapshot`, `snapshotTime`, `olderSnapshots`) and `key_vault` (the vault), or (1.7) `azure_files` (`account/share`; `account/*` when the account's shares could not be listed), or (1.7) Google Cloud's `gcs` (the bucket) and `bigquery` (`project.dataset.table`; `project.dataset.*` when a dataset could not be read), `firestore` and `datastore` (`project/database`), `spanner` (`instance/database`), `bigtable` (`instance/table`), `cloud_logging` and `secret_manager` (the project), `pubsub` (`project/topic`), `gce_snapshot` (the disk, or the snapshot whose disk is gone; `resource: snapshot`, `snapshotTime`, `olderSnapshots`), `cloudsql_postgresql`, `cloudsql_mysql` and `cloudsql_sqlserver` (`instance/database`; `instance/*` when an instance could not be read) and `alloydb` (the cluster), or (1.8) the SaaS scanner's `m365_mail`, `m365_onedrive` and `m365_teams_chat` (a person: `user-<the first 16 hex of ownerHash>`), `m365_sharepoint` (the site) and `m365_teams_channel` (the team), `gws_gmail` and `gws_drive` (a person, as above) and `gws_shared_drive` (the shared drive), `slack_channel` (`#channel`) and `slack_dm` (`direct-messages`), `jira_project` and `confluence_space` (the project's or space's key); an opt-in kind left out of `DISCOVER` is one store named `*`, `read_not_configured`; and the store's name, masked like a key (`nameMasked: true`) |
| `origin` | `discovery`, or `config` for a store named in the configuration |
| `status` | `scanned`, `deferred` (the budget did not reach it; the next run starts with it), `skipped` or `error` |
| `reason` | Why it was not read, or read with nothing readable: `denied`, `not_allowed`, `self`, `too_large`, `unsupported`, `unsupported_format`, `kms_access`, `access_denied`, `lake_formation`, `tags_unreadable`, `budget`, `error`; for exports, `export_not_configured`, `export_pending` (status `deferred`), `export_failed`, `no_snapshot` and `pitr_off` (a large DynamoDB table without point-in-time recovery); (1.3) `read_not_configured` (reading the kind is opt-in and off), `paused` (a paused Redshift cluster), `no_grant` (the database user can see no table), `vpc_only` (an OpenSearch domain inside a VPC), `no_snapshot_export` (DocumentDB, Neptune), `needs_task` (EFS, FSx), `backup_copy` (a Backup vault), `archived` (an archived EBS snapshot), `live_queue` (an SQS queue that is not a dead-letter queue), `redrive_would_change` (a dead-letter queue with its own redrive policy), `no_s3_destination` (a Firehose stream with no S3 location), `in_memory` (ElastiCache, MemoryDB) and `no_read_path` (Timestream for InfluxDB); (1.4) `db_user_can_write` (the databases runner's user can write, so it was refused; see `writeGrants`), `grants_unverifiable` (the user's privileges could not be read, so it was refused) and `driver_missing` (the image carries no driver for the engine); (1.5) `user_can_write` (a broker user given for reading can change a queue or administer the broker, so it was refused; see `writeGrants`), and `vpc_only` and `no_read_path` also for MSK and Amazon MQ (brokers out of reach; no IAM authentication, or RabbitMQ) and SageMaker (an online-only feature group, a notebook instance), and `archive_retrieval` (an S3 Glacier vault: reading an archive needs a retrieval job, which the scanner never starts); (1.6) `network` (the store admits only selected networks or private endpoints, and the scanner is not among them) and `needs_sas_export` (an Azure disk snapshot: its bytes are reachable only through a SAS export, which changes the snapshot, so it is never started); (1.7) `network` also for a Google Cloud store inside a VPC Service Controls perimeter the scanner is outside of, `requester_pays` (a Cloud Storage bucket whose reads would be billed to the scanner's project), `row_level_policy` (a BigQuery table with row-level access policies: a sample would hold only the rows the scanner is granted), `authorized_view` (a BigQuery view a dataset authorizes: it can read what the scanner cannot, so it is never read through), `needs_subscription` (a Pub/Sub dead-letter topic: reading it needs a subscription, a write; `live_queue` for any other topic) and `needs_disk_restore` (a persistent disk snapshot: reading it needs a disk made from it, a write); (1.8) `scope_unverified` (a mailbox not read because the mail grant could not be proved limited to the mailboxes in scope), `unscoped_grant` (the grant was proved to reach a mailbox outside the scope, so no mail is read), `protected_api` (a Teams API Microsoft has not approved the app for), `not_provisioned` (a person with no mailbox or OneDrive, or a group or site that does not exist) and `throttled` (status `deferred`: the vendor kept asking the scanner to wait; the next run goes on there), and `not_a_member` (a Slack channel the app's bot was not invited to: joining would be a write) |
| `error` | The AWS error name, for `error` |
| `sizeBytes` | The table's or log group's size, when AWS reports it |
| `samplePercent`, `maxObjectsPerPrefix` | The store's sampling, when it is sampled |
| `gaps` | Counts listed but not read: `kmsDenied`, `unreadable`, `unsupportedFormat`; and (1.9) `disguised`, the store's objects and entries named as another kind than they are (read, by content); and (1.10) `notAllowed`, objects a bucket's key filter left out (never read) |
| `backlog` | More to read on the next run |
| `logGroupClass`, `tableStatus`, `catalogObject` | Why an `unsupported` store is unsupported (`catalogObject`: `view`, `not_s3`, `resource_link`) |
| `location` | A Glue table's S3 location, `bucket/prefix`, masked |
| `lakeFormation` | The Glue table is registered with Lake Formation |
| `engine`, `dbType`, `snapshotTime`, `exportStatus` | For RDS: the engine, cluster or instance, the snapshot read, and the export's state |
| `readBy`, `pitr` | For DynamoDB: `export` when the table is read from an Export to S3; `pitr: false` when it is too large and has no point-in-time recovery |
| `exportType` | (1.10) For DynamoDB read by export: `incremental` when this run's export holds only the items written since the last one |
| `listedBy`, `recommendation` | (1.10) For S3: `listedBy: inventory` when the bucket's objects came from its own S3 Inventory report instead of a listing; `recommendation: s3_inventory` for a bucket large enough (`S3_INVENTORY_MIN_OBJECTS`) that an inventory would spare it a listing each pass. The scanner never creates one ([ARCHITECTURE.md](ARCHITECTURE.md#large-buckets-s3-inventory)) |
| `deployment`, `database`, `state` | (1.3) `provisioned` or `serverless` (Redshift), `managed` or `serverless` (OpenSearch); the database connected to by default; and the store's state when that is why it was not read |
| `resource`, `olderSnapshots` | (1.3) For EBS: `volume` or `snapshot`, and the earlier snapshots counted, not read; (1.5) for SageMaker, `feature_group` or `notebook_instance` |
| `recoveryPoints` | (1.3) For a Backup vault: its recovery points by resource type |
| `fileSystemType` | (1.3) For FSx: `LUSTRE`, `WINDOWS`, `ONTAP` or `OPENZFS` |
| `destinations` | (1.3) For Firehose: where the stream delivers (`S3`, `Redshift`, `OpenSearch`, `Splunk`, `HttpEndpoint`, `Snowflake`, `Iceberg`) |
| `deadLetterQueue`, `approximateMessages` | (1.3) For SQS: the queue is a dead-letter queue; its approximate message count |
| `snapshots` | (1.3) For ElastiCache and MemoryDB: the cache's snapshots, counted |
| `atRestEncryption`, `atRestKeyHash` | (1.5) The store's storage encryption, as on its findings: for S3, the bucket's default; for a database, what the engine reports |
| `eventCount`, `retentionDays` | (1.5) An EventBridge archive: its events, and how long it keeps them (0: indefinitely); its size is `sizeBytes` |
| `archives` | (1.5) An S3 Glacier vault: its archives, as of its last inventory; its size is `sizeBytes` |
| `workflowType` | (1.5) Step Functions: `standard` (its history is read) or `express` (reported `unsupported`: an Express workflow keeps no history in the service; its runs are in CloudWatch Logs, read there) |
| `subscription`, `resourceGroup`, `resourceIdHash` | (1.6) Azure: where the store is, as on its findings |
| `project`, `resourceNameHash` | (1.7) Google Cloud: where the store is, as on its findings |
| `vendor`, `tenantHash`, `ownerHash` | (1.8) SaaS: the vendor, the hash of the tenant's id, and for a person's store the hash of their principal name, as on its findings |
| `tableType`, `protectedColumns` | (1.7) BigQuery: the table's type (`TABLE`, `VIEW`, `MATERIALIZED_VIEW`, `EXTERNAL`, `SNAPSHOT`; only tables and snapshots are read), and the columns under a policy tag left out of the read |
| `hierarchicalNamespace` | (1.6) An Azure storage account with the hierarchical namespace on (ADLS Gen2) |
| `api` | (1.6) Cosmos DB: the account's API, `sql` (NoSQL), `mongodb`, `cassandra`, `gremlin` or `table`; only NoSQL and a MongoDB vCore cluster are read |
| `networkRestricted` | (1.6) An Azure store that admits only selected networks or private endpoints; when the scanner is not among them it is the `network` gap |
| `writeGrants` | (1.4) The databases runner: the write privileges the database user holds, by name (`superuser`, `table_write`, `INSERT`, `db_datawriter`, `MODIFY`, ...), when the store is refused as `db_user_can_write`; (1.5) for Amazon MQ, `console_access`, `queue_write`, `queue_admin`, `no_authorization_map` or `configuration_unreadable`, when refused as `user_can_write` |
| `items`, `itemTypes`, `excluded` | (1.3) For Parameter Store and Secrets Manager: parameters or secrets listed; by type (or managed by another service); and those not read, by reason (`denied`, `not_allowed`, `tags_unreadable`, `secure_string`, `self`) |

`stores` lists the stores not read first, and holds at most 5,000
(`storesTruncated`). `listErrors` names a listing that failed, by kind
(`{"s3": "AccessDenied"}`).

## Versioning

- `schemaVersion` is `major.minor`.
- Adding an optional field is a minor change (1.0 to 1.1).
- Removing or changing a field is a major change (2.0), and it comes with a
  new event `detail-type` (`Findings v2`).
- Consumers should ignore fields they do not know.
