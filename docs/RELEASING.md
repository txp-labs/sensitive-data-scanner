# Releasing

A release is a git tag `vX.Y.Z` on `main`. `.github/workflows/release.yml`
turns it into a GitHub Release. Every release can be rebuilt from its tag:
dependencies come from `scanner/uv.lock` with hashes, and base images are
pinned by digest.

## What a release contains

| Artifact | What it is |
|---|---|
| `ghcr.io/txp-labs/sensitive-data-scanner:X.Y.Z` | The Lambda container image. Python 3.12 slim, the Lambda runtime interface client; handler `sensitive_data_scanner.handler.handler`. The release notes and `IMAGE_DIGEST` give its digest |
| `sensitive-data-scanner-X.Y.Z-lambda-python3.12-x86_64.zip` | The same scanner as a Lambda zip for the managed `python3.12` runtime (x86_64). The same handler |
| `sensitive_data_scanner-X.Y.Z-py3-none-any.whl`, `.tar.gz` | The Python package, with the spec, the findings schema and the licenses inside |
| `*-lambda.spdx.json`, `*-image.spdx.json` | SPDX SBOMs of the zip and the image (syft) |
| `SHA256SUMS` | SHA-256 of every file above |

## Cutting a release

1. **Open a pull request that closes the round:**
   - set `version` in `scanner/pyproject.toml`,
     `scanner/src/sensitive_data_scanner/__init__.py` and
     `packages/spec-ts/package.json`;
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
   - Then `artifacts` (zip, wheel, SBOM) and `image` (build, push to GHCR,
     SBOM) run in parallel.
   - Finally `release` writes `SHA256SUMS` and creates the GitHub Release.
5. **Check the Release page:** every asset is attached, and the image digest
   in the notes matches the one in GHCR.

To verify a download:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## What is pending (decided later with Chris)

- **Signing.**
  - Choose between AWS Signer (a signing profile; Lambda can enforce code
    signing for zip deployments) and cosign (keyless with GitHub OIDC,
    Sigstore transparency log; this covers images, which Lambda code
    signing does not).
  - Until signing exists, releases are verified by SHA-256 and SBOM only.
  - The README says "Releases are signed". That becomes true only when this
    is done.
- **Where Mermera's customer template gets the code.** Container images for
  Lambda must come from ECR in the same account or through ECR
  cross-account pull, so GHCR alone is not enough. Zips must come from S3 in
  the function's region. Options:
  - mirror each release into a Mermera-owned ECR repository or S3 bucket per
    region;
  - have the template copy it into the customer's account.

  Neither is built. **This repository creates no AWS resources.**
- **The npm package.** `@txp-labs/sensitive-data-spec` is `private: true`
  and has not been published. Publishing needs:
  - an npm organization;
  - a token held as a repository secret, or npm trusted publishing with
    provenance;
  - removing `private`.
- **GHCR visibility.** The first push creates the package under the
  txp-labs organization. An organization owner may need to make it public,
  and to link it to this repository, in the package settings.
- **Architectures.** The image and zip are x86_64 only. arm64 (Graviton) can
  follow once there is a need.
