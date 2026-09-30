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
