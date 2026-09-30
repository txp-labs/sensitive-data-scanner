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
