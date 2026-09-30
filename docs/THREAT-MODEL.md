# Threat model

The scanner reads a customer's most sensitive stores and writes a report about
them. This document covers:

- what an attacker could want from that, and where the attack would cross a
  trust boundary;
- what the code does about each threat, and which test holds it;
- what is left.

Issue [#76](https://github.com/txp-labs/sensitive-data-scanner/issues/76).
Reviewed 30 Sep 2026 against `main`.

Threats are grouped by STRIDE: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service and **E**levation of
privilege. A mitigation is named by the code that does it and by the test that
fails if it stops.

## What is protected

| Asset | Where it lives | Why it matters |
|---|---|---|
| **The customer's data**: card numbers, SSNs, ITINs, dates of birth, and everything around them | The customer's stores (S3, logs, tables, databases, SaaS tenants) | The reason the scanner exists. It must never leave the customer's environment |
| **Findings** | The results bucket (`findings/`), the state container or bucket, pushed events | They name where sensitive data sits. That is a map for an attacker, although it holds no value |
| **Scanner state**: cursors, the lock, the object index, the `index_salt` | `state/` in the results bucket (or the platform's equivalent) | Tampering can hide data from later runs. The salt keys the index's HMACs |
| **The scanner's identity**: its IAM role, managed identity, service account or SaaS grants | The customer's account or tenant | Broad read access to everything that holds data |
| **Push credentials**: the HMAC key for the HTTPS sink, `PutEvents` on the consumer bus | Secrets or environment in the customer's account | Whoever holds them can send findings in the customer's name |
| **The release**: images in GHCR, the Lambda zip, wheels, templates | GitHub Releases and GHCR | This code runs with the scanner's identity in every customer's account |
| **The spec and vectors** | `spec/`, `vectors/`, `packages/spec-ts` | Stugum's live call redaction imports the same contract |

## Trust boundaries

```
 ┌─────────────────────────── customer account / tenant ─────────────────────────┐
 │                                                                               │
 │  stores (S3, logs, DynamoDB, RDS, SaaS …)                                     │
 │        │  read-only grants                                                    │
 │        ▼                                    B2                                │
 │  ┌───────────────┐   findings, state   ┌──────────────────┐                   │
 │  │  the runner   │────────────────────►│ results bucket / │                   │
 │  │ (Lambda, job) │                     │ state location   │                   │
 │  └───────┬───────┘                     └──────────────────┘                   │
 │     B1   │  (every object is untrusted input)                                 │
 └──────────┼────────────────────────────────────────────────────────────────────┘
            │ B3: PutEvents to a consumer bus, or a signed HTTPS POST
            ▼
 ┌──────────────────────┐          ┌──────────────────────────────────────────────┐
 │ Mermera ingest       │          │ B4: GitHub (this repository, Actions,        │
 │ (many tenants)       │          │ Releases) and GHCR: the code the runner runs │
 └──────────────────────┘          └──────────────────────────────────────────────┘
```

- **B1, the object and the runner.** Every byte the runner reads is controlled
  by whoever could write to the store. A support ticket, an upload or a log
  line can be written by anyone the customer serves.
- **B2, the runner and the customer's account.** The runner holds a role with
  read access across the account. It writes only to its own results location.
- **B3, the customer's account and Mermera's ingest.** Findings leave the
  account through a push. Mermera's ingest receives pushes from many
  customers.
- **B4, the release and the customer's account.** The customer runs an image
  or zip built by this repository's release workflow and hosted in GHCR and
  GitHub Releases.

## Attackers

| Attacker | Can | Wants |
|---|---|---|
| **A malicious file** (anyone who can put bytes in a scanned store) | Choose every byte of an object, its name, its archive entries' names, its metadata | To crash or stall the runner and hide data from it; to exhaust memory or budget; to exploit a parser; to get a value copied into findings or logs, where it would travel to people who should not see it |
| **A compromised release** (a stolen maintainer token, a poisoned dependency, a compromised action or base image) | Change the code every customer runs | The customer's data, through the scanner's broad read role |
| **A curious operator** (someone at the customer, or at Mermera, who can read findings, logs, state or the push stream, but not the stores) | Read everything the scanner writes | Values they are not entitled to see |
| **A tenant-crossing attacker** (one Mermera customer, or anyone holding one customer's push credentials) | Send pushes to Mermera's ingest | To read another tenant's findings, or to write findings into another tenant's view |

## STRIDE per boundary

### B1: a malicious object and the runner

| | Threat | Mitigation (code) | Held by (test) |
|---|---|---|---|
| **T, E** | A parser bug in a reader is exploited | Pure-Python readers only, with no native parsing of untrusted input beyond the standard library and pyarrow: `zipfile`, `tarfile`, `gzip`/`bz2`/`lzma`, pypdf, the core's own Avro reader, and an XML reader that refuses DTDs (`scan/office.py`). Archives are read in memory and never extracted, so zip-slip paths go nowhere (`scan/objects.py`) | `test_nothing_is_ever_extracted_zipslip_included`, `test_a_dtd_is_never_expanded_and_encryption_is_counted`; property tests for every reader ([#77](https://github.com/txp-labs/sensitive-data-scanner/issues/77)) |
| **D** | A zip bomb, a deeply nested archive, or a huge PDF or sheet exhausts memory or time | Caps in `scan/objects.py`: `max_inflated_bytes` per object, `MAX_ENTRIES` per archive, `MAX_DEPTH` 3, and `MAX_RATIO` 200 past `RATIO_FLOOR`. Each reader has its own caps: `MAX_PAGES` in `pdf.py`; `MAX_PARTS` and `MAX_CELLS` in `office.py`; `MAX_COLUMNS`, `MAX_CELL_CHARS` and `max_rows` in `columnar.py`; `MAX_BLOCK_BYTES` and `MAX_DEPTH` in `avro.py`; `MAX_LEAVES` and depth 32 for JSON (`item.py`). A capped read is `partial`, never a failure | `test_the_zip_bomb_guard_and_the_caps_make_a_read_partial`, `test_an_archive_nested_past_the_depth_is_counted_and_partial`, `test_the_zip_is_read_through_ranged_fetches_within_the_caps` |
| **D** | One bad object stops the whole run | Each object is read inside its own error boundary. A failure counts it `unreadable` by error name, and a damaged archive entry costs only itself | `test_a_damaged_entry_costs_only_itself`, `test_exceptions_quote_nothing` |
| **D** | Objects crafted to use the whole run budget | The run budget (`MAX_ITEMS_PER_RUN`, `MAX_BYTES_PER_RUN`, per-kind caps, and the platform's time limit) ends a run early and the next resumes from its cursor; rescans take at most a quarter of the budget (`index.py`) | `tests/test_rescans.py`, `tests/test_runner.py` |
| **S, T** | A name claims a harmless type to avoid being read (`cards.jpg` that is a CSV) | Content, not name, decides the reader: the first bytes are sniffed (`scan/sniff.py`). A mismatch is read by content and reported as `disguised` | `test_a_renamed_word_document_is_read_and_marked_disguised`, `test_a_disguise_is_counted_even_when_nothing_is_found` |
| **I** | A value in an object's name, an archive entry's path, a column name or a log group name is copied into findings | Every string written goes through `safety.redact_digits`. Entry paths are masked, and replaced by the entry's position where masking changed them. A console link built from a masked name is dropped. Reprs of results hold no path | `test_a_value_in_an_object_key_is_masked`, `test_entry_findings_name_the_entry_masked_and_carry_the_disguise`, `test_a_link_built_from_a_masked_name_is_dropped`, `test_reprs_hold_no_entry_path` |
| **I** | A parser's exception message quotes the input (a pypdf warning about a malformed object, a `json` error with the text) | `safety.error_name` gives only the exception's class or AWS error code. `ScanError` carries only that. pypdf's logger and warnings are silenced (`scan/pdf.py`) | `test_raised_exceptions_carry_no_message_from_below`, `test_exceptions_quote_nothing` |
| **R** | A file hides from the scanner and nobody can tell | Every store not read, and every object skipped, is in the run summary with its reason (`coverage.py`) | `test_the_run_summary_counts_disguised_objects`, `tests/test_discovery.py` |

### B2: the runner and the customer's account

| | Threat | Mitigation (code) | Held by (test) |
|---|---|---|---|
| **E** | The scanner's role is used to write, delete or reconfigure the customer's stores | The templates grant read actions on data, and writes only to the scanner's own results bucket prefixes (`findings/`, `state/`, `exports/`). Explicit Denies keep writes home, and every opt-in write is aimed at the scanner's own resource | `tests/test_template.py`: `test_every_allow_is_a_read_or_an_aimed_write`, `test_denies_keep_writes_home_and_lake_formation_out`, `test_every_aws_call_the_code_makes_is_allowed`, `test_each_adapter_calls_only_its_own_services` |
| **E** | The same, on Azure, Google Cloud or SaaS | Built-in read roles only; the state writer only on the job's own container or bucket; no keys and no basic roles; SaaS scopes are read scopes only | `tests/test_azure_template.py`, `tests/test_gcp_template.py`, `tests/test_saas_scopes.py` |
| **E** | KMS keys are used directly to decrypt anything | `kms:Decrypt` only through a service (`kms:ViaService`) | `test_kms_is_used_only_through_a_service` |
| **T** | Someone with write access to `state/` edits the cursor or index to make later runs skip data | Tampering is possible for anyone who can write the results bucket; that is the customer's own boundary. The index keys objects by HMAC under a salt that lives in the state document, not the index. A foreign or unreadable index is discarded, and the run starts a fresh one (`index.py`) | `tests/test_index.py` |
| **I** | A curious operator reads findings, logs, the index or pushed events and learns values | **Findings only, never values.** A finding has a class, counts, offsets and masked names. Values exist only in memory while one object is read. Distinct values are counted by an HMAC under a per-process random key (`detect/recognizers.value_key`). The one logger (`safety.log_event`) writes fixed event names and safe fields | The no-leak suite, `tests/test_no_leak.py`: every vector and fixture is read end to end on every platform, and every output (findings, events, logs, errors, reprs, the index's bytes) is searched for every planted value. Also `test_only_safety_writes_output`, `test_every_log_event_uses_a_fixed_name_and_safe_fields`, and the benchmark's own leak check (`tests/bench_score.py`) |
| **I** | The object index reveals names or values by their hashes | Keys, markers and fingerprints are HMAC-SHA256 under the random `index_salt`, truncated. A short number in a name is quickly guessed from a plain hash, but not from a keyed one | `test_no_value_in_the_object_index` |
| **I** | Findings reveal the customer's key ids | A customer-managed key is named only by `atRestKeyHash` | `test_no_value_or_key_name_leaves_the_encryption_facts` |
| **R** | A run's actions cannot be attributed | Every read is made with the scanner's own role, so it shows in the customer's CloudTrail, Azure Activity and Google audit logs under that principal. The run summary records what was read | (platform audit logs; no test) |

### B3: the customer's account and Mermera's ingest

The ingest is Mermera's code, not this repository's. This repository defines
what is sent and how it is signed, and states what a receiver must check.

| | Threat | Mitigation | Held by (test) |
|---|---|---|---|
| **I** | A push is read in transit or at the receiver and holds values | A push is the findings document, split into parts (`push.event_details`), with no value. HTTPS only: a non-HTTPS URL is refused (`findings_url_not_https`) | The no-leak suite (events included); `tests/test_db_sinks.py` |
| **S** | Someone sends findings as a customer they are not | **HTTPS:** each part is signed with HMAC-SHA256 over `<timestamp>.` and the exact body (`X-SDS-Signature: t=…,v1=…`). `push.verify` is the receiver's check: a constant-time compare and a 300-second freshness window. **EventBridge:** the event's `account` is set by AWS, not by the sender | `test_the_signature_is_over_the_timestamp_and_the_exact_body`, `test_https_posts_each_part_signed` |
| **T** | A push is changed in transit | The signature covers the exact body; TLS | as above |
| **S, E** | **Tenant crossing:** a customer, or anyone holding their key, sends findings naming another tenant's account, to pollute that tenant's view, or probes the ingest to read another tenant's findings | Receiver rules, which the ingest must hold. **A receiver must:** (1) keep one HMAC key per tenant and pick it by the endpoint or key id, never by a field inside the body; (2) take the tenant from the key (or, for EventBridge, from the envelope's `account`, mapped to a tenant at onboarding), and **ignore `accountId` and every other identifying field in the body** for tenancy; (3) store findings under that tenant only. The scanner never calls into Mermera and holds no Mermera credential beyond its own tenant's key or bus permission, so it can read nothing back | (Mermera's ingest tests; not in this repository) |
| **R** | A tenant disputes sending a push | Signed pushes under the tenant's own key; the scanner's `events.sent` and `events.failed` log lines | `test_https_posts_each_part_signed` |
| **D** | A replayed or flooded push | The 300-second window bounds replays. There is no nonce, so a replay inside the window is accepted: a receiver should de-duplicate by `runId` and `part` | (residual, below) |

### B4: the release and the customer's account

| | Threat | Mitigation | Held by (test) |
|---|---|---|---|
| **T, E** | A compromised action in CI or the release workflow injects code | Every `uses:` is pinned to a full commit SHA (the txp-labs organization policy). Workflows run with `permissions: contents: read` by default; `packages: write` only in the image jobs. zizmor lints the workflows | the Workflow Lint (zizmor) check; the org policy fails an unpinned workflow at start |
| **T, E** | A poisoned dependency | Dependencies are locked with hashes (`scanner/uv.lock`; `--require-hashes` in the image build), base images are pinned by digest, and Dependabot proposes updates weekly as reviewable PRs. The core has few dependencies (Presidio, pypdf, PyYAML) and no cloud SDK | `test_the_core_depends_on_no_cloud_sdk`; the `Package` check builds from the lock |
| **T** | An artifact is swapped after release | `SHA256SUMS` and SPDX SBOMs are attached to every release, and each image's digest is in the notes | (release workflow; residual, below) |
| **S** | A look-alike image or repository | Digests in the release notes; the templates and deploy examples take an image digest | (residual, below) |
| **T** | A secret is committed | gitleaks on every push and PR | the Secret Scan (gitleaks) check |
| **E** | The released code reads more than it says | The strict IAM tests hold the templates to the actions the code calls, and the code to the actions the templates allow | `test_every_aws_call_the_code_makes_is_allowed`, `test_every_environment_variable_is_one_the_code_reads` |

## Residual risks

1. **Releases are not signed.** Signing is not decided yet: AWS Signer or
   cosign keyless (`docs/RELEASING.md`).
   - A release is verified by SHA-256 and SBOM only. Both come from the same
     GitHub Release as the artifact, so an attacker who can replace one can
     replace the other.
   - A stolen maintainer account, or a compromised release workflow, can
     publish code that customers would run.
   - Until signing exists, customers should pin the image digest from the
     release notes and mirror it into their own registry.
2. **GHCR hosting.**
   - Lambda cannot pull from GHCR: the image has to be mirrored into ECR.
     How Mermera's customer template gets the code is not built yet.
   - The GHCR packages' visibility and repository link are set by hand.
   - A mis-set package, or a compromised organization owner, can repoint a
     tag. A digest cannot be repointed, so pin by digest.
3. **No replay nonce on the HTTPS push.** A captured part can be replayed
   within 300 seconds. It holds no value, and a receiver that de-duplicates
   by `runId` and `part` is unaffected.
4. **The ingest's tenant rules live outside this repository.** B3's
   tenant-crossing mitigations are requirements on Mermera's ingest, and this
   repository cannot test them. The push carries `accountId` as data, so an
   ingest that trusts it is exposed.
5. **Findings are a map.** Findings hold no value, but they say where
   sensitive data is. Anyone who can read the results bucket or the push
   stream learns which stores to attack. Access to `findings/` and to the
   consumer bus should be as narrow as access to the data.
6. **Tampering with state is possible for anyone with write access to the
   results bucket.** A tampered state can make runs skip objects until the
   next full pass. The scanner cannot defend its state against the account
   that owns it.
7. **Parsers are third-party code.** pypdf, pyarrow and the standard
   library's archive modules parse untrusted bytes in the runner's memory.
   - The caps bound their cost, and the property tests
     ([#77](https://github.com/txp-labs/sensitive-data-scanner/issues/77)) exercise them.
   - A memory-safety bug in pyarrow's native code would run with the
     runner's identity.
   - The Lambda zip carries no pyarrow; the container images do.
8. **Detection is not complete.** A value the scanner misses is not reported.
   `docs/BENCHMARK.md` measures precision and recall on a made-up corpus and
   names the known weak spots. It does not measure data the corpus does not
   resemble.
