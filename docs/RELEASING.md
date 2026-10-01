# Releasing

A release is a git tag `vX.Y.Z` on `main`. `.github/workflows/release.yml`
turns it into a GitHub Release. Every release can be rebuilt from its tag:
dependencies come from `scanner/uv.lock` with hashes, and base images are
pinned by digest.

## What a release contains

| Artifact | What it is |
|---|---|
| `ghcr.io/txp-labs/sensitive-data-scanner:X.Y.Z` | The Lambda container image. Python 3.12 slim, the Lambda runtime interface client, and pyarrow for the columnar formats; handler `sensitive_data_scanner.handler.handler`. The release notes and `IMAGE_DIGEST` give its digest. **The recommended package** |
| `sensitive-data-scanner-X.Y.Z-lambda-python3.12-x86_64.zip` | The same scanner as a Lambda zip for the managed `python3.12` runtime (x86_64), with the same handler, **without pyarrow**: with it the zip would pass Lambda's 250 MB unzipped limit. It reads every text format, gzip, and Avro with the standard library's codecs, and counts Parquet, ORC, zstd and snappy or zstandard Avro as skipped `columnar` |
| `ghcr.io/txp-labs/sensitive-data-scanner-databases:X.Y.Z` | The databases runner ([DATABASES.md](DATABASES.md)): the Dockerfile's `db` target with every engine's driver. `DB_IMAGE_DIGEST` and the release notes give its digest. For a slimmer image, build `--target db` with `DB_EXTRAS` yourself |
| `ghcr.io/txp-labs/sensitive-data-scanner-azure:X.Y.Z` | The Azure scanner ([AZURE.md](AZURE.md)): the Dockerfile's `azure` target, a Container Apps job's image with the Azure SDKs, pyarrow and the database drivers. `AZURE_IMAGE_DIGEST` and the release notes give its digest, which the deployment's `image` parameter takes |
| `sensitive-data-scanner-azure.json` | The Azure deployment at a management group: `deploy/azure/main.bicep`, compiled |
| `ghcr.io/txp-labs/sensitive-data-scanner-gcp:X.Y.Z` | The Google Cloud scanner ([GCP.md](GCP.md)): the Dockerfile's `gcp` target, a Cloud Run job's image with google-auth (REST, no gRPC), pyarrow and the Cloud SQL drivers. `GCP_IMAGE_DIGEST` and the release notes give its digest, which the deployment's `image` variable takes (from a mirror in Artifact Registry) |
| `ghcr.io/txp-labs/sensitive-data-scanner-saas:X.Y.Z` | The SaaS scanner ([SAAS.md](SAAS.md)): the Dockerfile's `saas` target, a container the customer runs in its own environment, with `requests`, `cryptography`, boto3 (S3 state, AWS workload identity) and pyarrow; no vendor SDK. `SAAS_IMAGE_DIGEST` and the release notes give its digest, which the deploy examples name |
| `sensitive-data-scanner-saas-deploy.tar.gz` | The SaaS scanner's deploy examples: `deploy/saas` (ECS, Azure Container Apps, Cloud Run, Kubernetes) |
| `sensitive-data-scanner-gcp-terraform.tar.gz` | The Google Cloud deployment: the `deploy/gcp` Terraform module, with its provider lock file |
| `sensitive_data_scanner-X.Y.Z-py3-none-any.whl`, `sensitive_data_scanner_core-X.Y.Z-py3-none-any.whl`, `sensitive_data_scanner_db-X.Y.Z-py3-none-any.whl`, `sensitive_data_scanner_azure-X.Y.Z-py3-none-any.whl`, `sensitive_data_scanner_gcp-X.Y.Z-py3-none-any.whl`, `sensitive_data_scanner_saas-X.Y.Z-py3-none-any.whl` | The Python packages: the AWS scanner, the cloud-neutral core every runner depends on (with the spec, the findings schema and the licenses inside), the databases runner (its drivers are extras), the Azure scanner, the Google Cloud scanner and the SaaS scanner. There is no sdist: the source release is the tag |
| `scanner.yaml`, `estate-stackset.yaml` | The estate rollout templates: the scanner for one account and region, and the service-managed StackSet that deploys it across an organization (`docs/ARCHITECTURE.md`, Estate rollout) |
| `sensitive-data-scanner-X.Y.Z-lambda-python3.12-x86_64-signed.zip` | The Lambda zip signed with AWS Signer: the same bytes as in the regional buckets ([Where the code is](#where-the-code-is)). Present when AWS publishing is configured |
| `*-lambda.spdx.json`, `*-image.spdx.json` | SPDX SBOMs of the zip and the five images (syft); each image's SBOM is also attached to it in GHCR as a signed cosign attestation |
| `IMAGE_DIGEST`, `DB_IMAGE_DIGEST`, `AZURE_IMAGE_DIGEST`, `GCP_IMAGE_DIGEST`, `SAAS_IMAGE_DIGEST` | Each image's digest |
| `owner.repo.<id>.dockerbuild` | buildx's record of each image build (its inputs and timings), attached as it comes |
| `@txp-labs/sensitive-data-spec@X.Y.Z` (npm) | The TypeScript spec package ([packages/spec-ts](../packages/spec-ts/README.md)), published from the release workflow by npm trusted publishing, with provenance |
| `SHA256SUMS` | SHA-256 of every file above, under the names GitHub serves them by. The workflow renames any file whose name GitHub would change (it replaces characters other than letters, digits, `-`, `_` and `.` with `.`), and checks the published names against the list |

## Cutting a release

1. **Open a pull request that closes the round:**
   - set `version` in `scanner/pyproject.toml`,
     `scanner/src/sensitive_data_scanner/__init__.py`, every other
     `scanner/*/pyproject.toml` and its package's `__init__.py` (the core,
     `scanner/core/src/sensitive_data_core/__init__.py`), `scanner/uv.lock`
     (`uv lock`), `packages/spec-ts/package.json` and its
     `package-lock.json`'s own version;
   - rename `## Unreleased` in `CHANGELOG.md` to `## X.Y.Z — YYYY-MM-DD` and
     leave a fresh `## Unreleased` above it;
   - optionally add `docs/release-notes/vX.Y.Z.md`, which the Release puts
     above the changelog section: what the release proves, and what it does
     not.
2. **Merge it once CI is green.** That covers Python, Node, Package, gitleaks
   and zizmor.
3. **Tag the merge commit and push the tag:**

   ```sh
   git checkout main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. **Watch the Release workflow.**
   - `verify` fails unless the tag, both package versions and the changelog
     heading agree.
   - Then `artifacts` (zip, wheels, SBOM), `image`, `db-image`, `azure-image`, `gcp-image` and `saas-image` (each:
     build, push to GHCR, SBOM, cosign signature and SBOM attestation) run in parallel.
   - `aws-publish` signs the zip with AWS Signer, uploads it to every
     region's bucket and copies the Lambda image to ECR
     ([Where the code is](#where-the-code-is)). Without the repository
     variable `ARTIFACTS_ROLE_ARN` it logs a notice ("AWS publishing
     skipped") and does nothing else. Its role trusts only `release.yml` at a
     `v*` tag, so a by-hand run (`workflow_dispatch`, from `main`) cannot
     assume it and fails at that step: a fix to it needs a new patch tag.
   - If the workflow itself needs a fix after the tag is pushed, merge the
     fix and run **Release** by hand (`workflow_dispatch`) with the existing
     tag. It builds the tag's code with the fixed workflow.
   - `release` writes `SHA256SUMS` and creates the GitHub Release.
   - Finally `npm` publishes `@txp-labs/sensitive-data-spec` with
     `npm publish --provenance --access public`. npm trusts this repository's
     `release.yml` (a Trusted Publisher set on npmjs.com), so there is no npm
     token. A version already on npm is skipped.
5. **Check the Release page:** every asset is attached, and the image digest
   in the notes matches the one in GHCR. Then run the checks in
   [Verifying a release](#verifying-a-release).

To verify a download:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## Where the code is

Lambda takes a zip only from S3, and an image only from ECR, in the
function's own region. From 0.4.1, every release is published to the
txp-labs-artifacts account (`895544787721`) in each approved region:
**us-east-1, us-east-2, us-west-2, ca-central-1, eu-west-1, eu-central-1,
ap-southeast-2**.

| What | Where, in region `<region>` |
|---|---|
| The signed Lambda zip | `s3://txp-labs-sensitive-data-scanner-<region>/releases/<version>/sensitive-data-scanner-<version>-lambda-python3.12-x86_64.zip` |
| Its SHA-256 | the same key plus `.sha256` |
| The Lambda image | `895544787721.dkr.ecr.<region>.amazonaws.com/sensitive-data-scanner:<version>`, the same digest as in GHCR |

For example, 0.4.1 in eu-west-1:
`s3://txp-labs-sensitive-data-scanner-eu-west-1/releases/0.4.1/sensitive-data-scanner-0.4.1-lambda-python3.12-x86_64.zip`.

- Anyone can read `releases/*` (`s3:GetObject`, nothing else: no listing).
  The objects are write-once: the bucket refuses any put under `releases/`
  that could overwrite one.
- Any account's Lambda may pull the image (`ecr:BatchGetImage` and
  `ecr:GetDownloadUrlForLayer` only). Tags are immutable; name the image by
  digest anyway.
- In `deploy/scanner.yaml`: `CodeS3BucketPrefix=txp-labs-sensitive-data-scanner`
  and `CodeS3Key=releases/<version>/sensitive-data-scanner-<version>-lambda-python3.12-x86_64.zip`
  for the zip, or `ImageUri=895544787721.dkr.ecr.<region>.amazonaws.com/sensitive-data-scanner@sha256:…`
  for the image.

**Lambda code signing.** The zip is signed by the AWS Signer profile
`TxpLabsSensitiveDataScanner`, version ARN:

```
arn:aws:signer:us-west-2:895544787721:/signing-profiles/TxpLabsSensitiveDataScanner/KFG2ZbbYX5
```

To enforce it, pass that ARN as `scanner.yaml`'s
`CodeSigningProfileVersionArn`; the template attaches a code signing config
with `UntrustedArtifactOnDeployment: Enforce`, so Lambda refuses a zip this
profile did not sign or that changed after signing. Or allow it in your own
code signing config:

```sh
aws lambda create-code-signing-config \
  --allowed-publishers SigningProfileVersionArns=arn:aws:signer:us-west-2:895544787721:/signing-profiles/TxpLabsSensitiveDataScanner/KFG2ZbbYX5 \
  --code-signing-policies UntrustedArtifactOnDeployment=Enforce
```

If the profile is ever rotated, the release notes give the new version ARN.
Lambda code signing covers zips only; the image is covered by cosign.

The hosting itself (buckets, ECR, the release role) is
[deploy/artifacts/](../deploy/artifacts/README.md).

## Verifying a release

**Images (cosign).** Each image is signed keyless by this repository's
release workflow at the version's tag (a Sigstore certificate, logged in
Rekor), and its SPDX SBOM is attached as a signed attestation. With
cosign 2.4 or later, for 0.4.1 (the same for `-databases`, `-azure`, `-gcp`
and `-saas`, with each image's digest from the release notes):

```sh
IMAGE=ghcr.io/txp-labs/sensitive-data-scanner@sha256:<digest>
cosign verify "$IMAGE" \
  --certificate-identity https://github.com/txp-labs/sensitive-data-scanner/.github/workflows/release.yml@refs/tags/v0.4.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity https://github.com/txp-labs/sensitive-data-scanner/.github/workflows/release.yml@refs/tags/v0.4.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To accept any release rather than one, use
`--certificate-identity-regexp '^https://github\.com/txp-labs/sensitive-data-scanner/\.github/workflows/release\.yml@refs/tags/v'`.
The ECR copies have the same digest, so the same check holds for them.

**The Lambda zip.** Compare it with the published checksum, and let Lambda
check the signature (above):

```sh
aws s3 cp --no-sign-request s3://txp-labs-sensitive-data-scanner-us-east-1/releases/0.4.1/sensitive-data-scanner-0.4.1-lambda-python3.12-x86_64.zip .
aws s3 cp --no-sign-request s3://txp-labs-sensitive-data-scanner-us-east-1/releases/0.4.1/sensitive-data-scanner-0.4.1-lambda-python3.12-x86_64.zip.sha256 .
sha256sum -c sensitive-data-scanner-0.4.1-lambda-python3.12-x86_64.zip.sha256
```

**The npm package.** `npm audit signatures` in a project that depends on it
checks its registry signature and provenance attestation; the package page
on npmjs.com links the provenance to the workflow run that built it.

## What is pending (decided later with Chris)

- **Mermera's customer template.** Template 0.2.x should default the signing
  profile version ARN and the per-region code location above. That is a
  Mermera change, made with Chris's approval, because published template
  versions are immutable.
- **Architectures.** The image and zip are x86_64 only. arm64 (Graviton) can
  follow once there is a need.
