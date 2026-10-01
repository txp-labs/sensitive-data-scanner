# Settings from Mermera: the runner config contract, version 1

A runner that pushes its findings to Mermera pulls its settings from Mermera
before each run ([#109](https://github.com/txp-labs/sensitive-data-scanner/issues/109)).
The tenant admin sets them in Mermera (`/settings/data-scanner`, Mermera
[#1161](https://github.com/txp-labs/mermera-attestation-app/issues/1161)); the
scanner applies them on its next run, under what the customer's own deployment
sets explicitly, and reports where each setting came from.

This page is the contract between the two: what the scanner sends, what it
expects back, what it does with each answer, and what it reports. The
scanner's side is `scanner/core/src/sensitive_data_core/runner_config.py`;
`scanner/tests/test_runner_config.py` holds it to this page.

## Who pulls

| Runner | Pulls when | Platform key |
|---|---|---|
| AWS (Lambda) | `FINDINGS_HTTPS_URL` and the site's key are set (template parameters `FindingsHttpsUrl`, `FindingsHmacKey`). The template stores the key as a Secrets Manager secret of the stack's own (`/sensitive-data-scanner/<stack>/findings-hmac-key`, the `aws/secretsmanager` key) and passes the function only its ARN, `FINDINGS_HMAC_KEY_SECRET`; the function reads it once per cold start (`secretsmanager:GetSecretValue` on that one ARN, decrypted through Secrets Manager) and holds it in memory only, never in its environment or a log. With `SECRETS_READ` on, the Secrets Manager source leaves that secret out (`excluded.scanner_own_credential`, not a gap). A key it cannot read makes the pull `failed` (`error: key:<error name>`). `FINDINGS_HMAC_KEY` (the key itself) still works for a run outside the template. The findings still go to the event bus: the URL is used for the pull only | `aws` |
| Azure (Container Apps job) | `FINDINGS_HTTPS_URL` with `FINDINGS_HMAC_KEY` or `FINDINGS_HMAC_KEY_FILE` | `azure` |
| Google Cloud (Cloud Run job) | the same | `gcp` |
| SaaS (container) | the same | `saas` |
| Databases (container) | never: it has no setting Mermera can change | |

A runner with no push URL, or a URL that names no site
(`.../sites/<siteId>/findings`), does not pull, and reports
`configPull.status: not_configured`.

## The request

```
GET <push URL with /findings replaced by /config>?schemaVersion=<findings schema>
X-SDS-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.config:<siteId>">
Accept: application/json
User-Agent: sensitive-data-scanner/<version>
```

- **The URL** is the push URL's, with its last segment `findings` replaced by
  `config`. On either host Mermera serves today:
  - `https://<api>/v1/scanner/sites/<siteId>/config` (the original path);
  - `https://ingest.<env>.mermera.com/v1/tenants/<tenantId>/sites/<siteId>/config`
    (the ingest host, [Mermera #1141](https://github.com/txp-labs/mermera-attestation-app/issues/1141)).
- **The signature** is the push's (`X-SDS-Signature`, docs/DATABASES.md), under
  the site's HMAC key, over the bytes `<t>.config:<siteId>`, with `<siteId>`
  exactly as the URL has it (the path parameter Mermera signs over). There is
  no body. Mermera accepts a
  signature within 300 seconds of its clock.
- **`schemaVersion`** is the findings schema the runner writes (`1.13` from
  this release): advisory, unsigned. Mermera may answer 422 for a major it
  does not accept.
- One attempt per run, 10-second timeout, no retry inside the run: the next
  run pulls again.

## The response

`200`, `Content-Type: application/json`, a body of at most **64 KiB** that is
**one flat JSON object**:

- every key matches `^[A-Z][A-Z0-9_]{1,63}$`;
- every value is a **JSON string** (not a boolean, number or null).

```json
{
  "CONFIG_CONTRACT": "1",
  "FINDINGS_SCHEMA_ACCEPTED": "1.x",
  "FINDINGS_SCHEMA_REVIEWED": "1.13",
  "SCAN_MODE": "both",
  "S3_READ_GLACIER_IR": "on",
  "SSM_DECRYPT": "off"
}
```

| Key | Meaning |
|---|---|
| `CONFIG_CONTRACT` | This contract's version: `"1"` (a `"1.x"` is accepted too). Any other major makes the runner ignore the whole response (`configPull.status: invalid`, `error: contract_unsupported`). Absent, the response is read as version 1 (Mermera before #1161 answered without it) |
| `FINDINGS_SCHEMA_ACCEPTED`, `FINDINGS_SCHEMA_REVIEWED` | Mermera's statements about the findings schema it takes (Mermera #1059). Informational: never applied, never reported as ignored |
| a setting in the table below | Applied under the precedence below. **Leave a setting out** to leave it to the deployment or the default; an empty string is a value the setting does not accept |
| anything else | Ignored, and named in `configPull.ignored` (names only, at most 50). A runner never applies a setting this page does not list for its platform, whatever the response says |

**Values.** A switch (`on/off` in the table) takes `on` or `off` (also
`true`, `false`, `1`, `0`, `yes`, `no`, any case); a mode takes one of its
listed words, lower case. A value the setting does not accept is ignored for
that setting (the deployment's value or the default stands) and the setting is
named in `configPull.invalid`. The run reports switches as `"true"` /
`"false"`.

**Errors.** Anything but a 2xx leaves the run on its own settings, and the
document says why: `401`, `403`, `404`, `422` and other 4xx are `refused`
(`error: http_<status>`); `429`, `5xx`, a timeout or no connection are
`failed`. A body that is not the contract is `invalid` (`not_json`,
`not_an_object`, `not_a_setting`, `too_large`, `contract_unsupported`). None of
these fails the run.

## Precedence

For every setting in the table, per run:

1. **`env`**: an explicit, non-empty environment variable: a deploy template
   parameter that was set, a SaaS or databases container's environment, or (AWS)
   a configuration document (`CONFIG_LOCATION`, the invoke payload's `config`);
2. **`mermera`**: the value in the pulled response;
3. **`default`**: the scanner's default (the table's).

The templates leave every setting below **unset by default** so that Mermera's
value applies: an empty CloudFormation parameter (`""`), a null Bicep
parameter (`bool?`), a null Terraform variable. A customer who sets one in the
template pins it there, and Mermera shows it as set by the deployment.

## IAM-gated settings

Some reads need a permission the deploy template grants only when its own
parameter turns them on (the role holds nothing it does not use). Mermera
cannot grant a permission, so when it turns on a setting whose grant the role
lacks, the run keeps the setting at its default (off), never tries the read,
and reports `gate: iam` with the **template parameter** to set.

The template tells the runner which grants it made: `IAM_GRANTS`, a comma list
of grant names (`none` when there are none, so an empty list is still a
statement). A runner without `IAM_GRANTS` (a template from before #109) gates
nothing: a missing permission then shows as the store's `access_denied`.

## The settings

`Grant`: the name in `IAM_GRANTS` the setting needs for the values it lists;
no grant, no gate. `Hook`: the read it turns on is designed and not built;
on, the stores it covers say `not_implemented`
([limitations.md](limitations.md)).

| Setting | Platform | Values | Default | Template parameter | Grant (values) | Hook |
|---|---|---|---|---|---|---|
| `S3_READ_GLACIER_IR` | aws | on/off | off | `S3ReadGlacierIr` | | |
| `S3_RESTORE_ARCHIVED` | aws | on/off | off | `S3RestoreArchived` | | yes |
| `SCAN_MODE` | aws | scanner, vendor, both | scanner | `ScanMode` | `MACIE_IMPORT` (vendor, both) | |
| `SSM_DECRYPT` | aws | on/off | off | `SsmDecrypt` | `SSM_DECRYPT` (on) | |
| `SECRETS_READ` | aws | on/off | off | `SecretsRead` | `SECRETS_READ` (on) | |
| `TIMESTREAM_READ` | aws | on/off | on | `TimestreamRead` | `TIMESTREAM_READ` (on) | |
| `KEYSPACES_READ` | aws | on/off | on | `KeyspacesRead` | `KEYSPACES_READ` (on) | |
| `GLUE_LAKE_FORMATION` | aws | read, skip | read | `GlueLakeFormation` | | |
| `FILESYSTEM_TASK_ENABLED` | aws | on/off | off | `FilesystemTaskEnabled` | | yes |
| `EBS_DIRECT_READ` | aws | on/off | off | `EbsDirectRead` | `EBS_DIRECT_READ` (on) | |
| `SQS_DLQ_READ` | aws | on/off | off | `SqsDlqRead` | `SQS_DLQ_READ` (on) | |
| `MSK_READ` | aws | on/off | off | `MskRead` | `MSK_READ` (on) | |
| `ECR_READ` | aws | on/off | off | `EcrRead` | `ECR_READ` (on) | |
| `SAGEMAKER_READ` | aws | on/off | off | `SageMakerRead` | | |
| `OPENSEARCH_SERVERLESS_READ` | aws | on/off | off | `OpenSearchServerlessRead` | `OPENSEARCH_SERVERLESS_READ` (on) | |
| `AZURE_READ_COLD_TIER` | azure | on/off | off | `readColdTier` | | |
| `AZURE_REHYDRATE_ARCHIVE` | azure | on/off | off | `rehydrateArchive` | | yes |
| `KEYVAULT_SECRETS_READ` | azure | on/off | off | `readKeyVaultSecrets` | `KEYVAULT_SECRETS_READ` (on) | |
| `AZURE_FILES_READ` | azure | on/off | off | `readFileShares` | `AZURE_FILES_READ` (on) | |
| `AZURE_LOG_ANALYTICS` | azure | on/off | on | `readLogAnalytics` | | |
| `AZURE_READ_SNAPSHOTS` | azure | on/off | off | `readDiskSnapshots` | | yes |
| `AZURE_COSMOS_READER_POLICY` | azure | on/off | off | `assignCosmosReaderPolicy` | | yes |
| `GCS_READ_ARCHIVE` | gcp | on/off | off | `read_archive_objects` | | |
| `SCAN_MODE` | gcp | scanner, vendor, both | scanner | `scan_mode` | `SDP_PROFILES` (vendor, both) | |
| `GCP_SPANNER` | gcp | on/off | on | `read_spanner` | `GCP_SPANNER` (on) | |
| `GCP_ALLOYDB` | gcp | on/off | on | `read_alloydb` | `GCP_ALLOYDB` (on; made only with `read_databases`) | |
| `SECRET_MANAGER_READ` | gcp | on/off | off | `read_secrets` | `SECRET_MANAGER_READ` (on) | |
| `LOGGING_PRIVATE_READ` | gcp | on/off | off | `read_private_logs` | `LOGGING_PRIVATE_READ` (on) | |
| `GCP_SQLSERVER` | gcp | on/off | off | `read_sqlserver` | | yes |
| `GCP_READ_PUBSUB_DLQ` | gcp | on/off | off | `read_pubsub_dead_letters` | | yes |
| `SCAN_MODE` | saas | scanner, vendor, both | scanner | `SCAN_MODE` (container environment) | | |
| `SCAN_MODE_M365` | saas | scanner, vendor, both | `SCAN_MODE`'s | `SCAN_MODE_M365` | | |
| `SCAN_MODE_GOOGLE_WORKSPACE` | saas | scanner, vendor, both | `SCAN_MODE`'s | `SCAN_MODE_GOOGLE_WORKSPACE` | | |
| `SCAN_MODE_SLACK` | saas | scanner, vendor, both | `SCAN_MODE`'s | `SCAN_MODE_SLACK` | | |
| `M365_MAIL` | saas | on/off | on | `M365_MAIL` | | |
| `GWS_ALERT_CENTER` | saas | on/off | on | `GWS_ALERT_CENTER` | | |
| `LINK_VENDOR_ALERTS_BY_LOCATION` | saas | on/off | on | `LINK_VENDOR_ALERTS_BY_LOCATION` | | |

**Not settable from Mermera**, by design: anything that names a resource or a
secret (KMS key ARNs, VPC subnets and security groups, brokers, database
users, buckets), anything the template must build something for (the
EventBridge replay queue, the export roles, the Azure database kinds that need
a user), the budgets and export limits (numbers the deployment sizes), and how long
the results store keeps per-run files (`FindingsRetentionDays`,
`findingsRetentionDays`, `findings_retention_days`, #119: a lifecycle rule on
the bucket, which is infrastructure; [limitations.md](limitations.md#how-long-the-scanners-own-output-is-kept-119)).
They stay the deployment's, and a response that names one has it ignored.

## What the run reports (findings schema 1.13)

Every findings document of a runner that reads its settings this way carries
two top-level fields ([FINDINGS.md](FINDINGS.md)):

```json
{
  "settingsSource": {
    "S3_READ_GLACIER_IR": { "value": "true", "source": "mermera" },
    "SSM_DECRYPT": { "value": "false", "source": "env" },
    "SECRETS_READ": {
      "value": "false", "source": "mermera",
      "gate": "iam", "parameter": "SecretsRead", "requested": "true"
    },
    "S3_RESTORE_ARCHIVED": { "value": "true", "source": "mermera", "hook": true },
    "TIMESTREAM_READ": { "value": "true", "source": "default" }
  },
  "configPull": {
    "status": "ok", "contract": "1",
    "applied": ["S3_READ_GLACIER_IR", "S3_RESTORE_ARCHIVED", "SECRETS_READ"],
    "ignored": ["RESULTS_BUCKET"]
  }
}
```

- `settingsSource` has one entry for **every** setting of the runner's
  platform in the table: `value` (what the run used), `source` (`env`,
  `mermera` or `default`), and when gated `gate: "iam"`, `parameter` and
  `requested`. A SaaS vendor's mode left unset takes `SCAN_MODE`'s value and
  source.
- `configPull`: `status` (`ok`, `not_configured`, `failed`, `refused`,
  `invalid`), `contract` (the version the runner speaks), `error` (a code,
  never a message), `applied` (the settings Mermera's values decided, gated
  ones included), `ignored` and `invalid` (names only).

Mermera's *Effective in the last run* is `settingsSource[<name>]`; *Your
deployed template doesn't allow this yet: set parameter X* is an entry with
`gate: "iam"`, X its `parameter`.

## Versioning

- **Contract 1 is additive.** New settings may be added to the table in a
  later scanner release; a runner that does not know one ignores it and lists
  it in `configPull.ignored`, so Mermera can send a setting before every
  runner has been upgraded. New informational keys may be added the same way.
- A change that would make an older runner misread a response (a value that
  is not a string, a nested object, a setting whose meaning changes) is
  contract **2**, sent as `CONFIG_CONTRACT: "2"`; a version-1 runner then
  ignores the whole response and says `contract_unsupported`. The runner says
  which contract it speaks in every document (`configPull.contract`).
- The request (path, signature, `schemaVersion`) is part of the contract: it
  changes only with a new major.
