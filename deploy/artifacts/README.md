# Release hosting (txp-labs-artifacts)

Where every release's signed Lambda zip and Lambda image live, one copy per
approved region, in the txp-labs-artifacts account (`895544787721`). The
release workflow's `aws-publish` job fills it. Customers read it as described
in [docs/RELEASING.md, Where the code is](../../docs/RELEASING.md#where-the-code-is).
Not deployed by customers.

## What it creates

`artifacts.yaml`, one stack (`sensitive-data-scanner-artifacts`) per region:

| In every region | |
|---|---|
| `txp-labs-sensitive-data-scanner-<region>` | The release bucket. Public `s3:GetObject` on `releases/*` only, through the bucket policy; Block Public Access keeps ACLs blocked and allows only that policy. Versioning, SSE-S3, TLS only, server access logs, ACLs disabled. Puts under `releases/` must be conditional (`If-None-Match: *`), so a published object is never overwritten. `signing/` (home region only in use) is private and expires after 7 days |
| `txp-labs-sensitive-data-scanner-logs-<region>` | Its access logs: private, kept 400 days |
| ECR `sensitive-data-scanner` | The Lambda image. Immutable tags, scan on push. Any account's Lambda may pull (`ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`); `PublicImagePull=false` makes it private |

| In the home region, us-west-2 (the AWS Signer profile's) | |
|---|---|
| The GitHub OIDC provider | `token.actions.githubusercontent.com` (`CreateOidcProvider=false` if the account already has one) |
| Role `sensitive-data-scanner-release` | Trusted only by this repository's `release.yml` at a `v*` tag: the ID-qualified subject `repo:txp-labs@274345004/sensitive-data-scanner@1395634563:ref:refs/tags/v*`, plus `repository_id`, `ref` and `job_workflow_ref` conditions. It may put objects under `releases/` in the seven buckets and under `signing/` in the home bucket, start and read signing jobs on `TxpLabsSensitiveDataScanner`, and push to the home ECR repository. Nothing else, and no delete |
| ECR replication | `sensitive-data-scanner` to the six other regions, into the repositories above |

**Why plain CloudFormation, deployed region by region.** The repository's
other AWS templates are CloudFormation and there is no CDK here. A
self-managed StackSet would need two more admin roles in the account
(`AWSCloudFormationStackSetAdministrationRole` and its execution role) to
deploy the same template to one account; `deploy.sh` runs
`aws cloudformation deploy` per region with the same result and fewer
privileged roles. The template works unchanged as a StackSet if that is
preferred later.

## Deploying

Only after the pull request that changes it is reviewed and merged:

```sh
# Change sets only, nothing executed:
AWS_PROFILE=txp-labs-artifacts deploy/artifacts/deploy.sh --dry-run
# Deploy (home region first), then print the release role's ARN:
AWS_PROFILE=txp-labs-artifacts deploy/artifacts/deploy.sh
```

The script refuses credentials for any other account. Then give the
release workflow the role:

```sh
gh variable set ARTIFACTS_ROLE_ARN -R txp-labs/sensitive-data-scanner \
  --body arn:aws:iam::895544787721:role/sensitive-data-scanner-release
```

Until that variable is set, `aws-publish` logs "AWS publishing skipped" and
the rest of the release goes ahead.

The region list is in four places, held equal by
`scanner/tests/test_artifacts_template.py`: `deploy.sh`, `artifacts.yaml`
(the role's buckets and the replication rule), `release.yml`
(`ARTIFACT_REGIONS`) and `scripts/release-notes.py`.
