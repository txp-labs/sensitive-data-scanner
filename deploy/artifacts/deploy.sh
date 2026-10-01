#!/usr/bin/env bash
# Deploy deploy/artifacts/artifacts.yaml to every approved region of the
# txp-labs-artifacts account (895544787721), home region first (#108).
#
#   AWS_PROFILE=txp-labs-artifacts deploy/artifacts/deploy.sh            # deploy
#   AWS_PROFILE=txp-labs-artifacts deploy/artifacts/deploy.sh --dry-run  # change sets only
#
# One stack per region, named sensitive-data-scanner-artifacts. Outside the home
# region it also creates that region's AWS Signer profile (stack output
# SigningProfileVersionArn: pin it in release.yml and docs/RELEASING.md). The
# home region (us-west-2, whose profile was made by hand) also creates the OIDC
# provider, the release role and the ECR replication rule; its ReleaseRoleArn
# output is the repository variable ARTIFACTS_ROLE_ARN.
set -euo pipefail

ACCOUNT=895544787721
STACK=sensitive-data-scanner-artifacts
HOME_REGION=us-west-2
# Keep in step with release.yml (ARTIFACT_REGIONS) and artifacts.yaml (role, replication).
REGIONS=(us-west-2 us-east-1 us-east-2 ca-central-1 eu-west-1 eu-central-1 ap-southeast-2)
TEMPLATE="$(cd "$(dirname "$0")" && pwd)/artifacts.yaml"

dry_run=()
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=(--no-execute-changeset)
fi

actual=$(aws sts get-caller-identity --query Account --output text)
if [ "${actual}" != "${ACCOUNT}" ]; then
  echo "refusing: credentials are for account ${actual}, not ${ACCOUNT} (txp-labs-artifacts)" >&2
  exit 1
fi
test "${REGIONS[0]}" = "${HOME_REGION}"

for region in "${REGIONS[@]}"; do
  echo "== ${region}"
  aws cloudformation deploy \
    --region "${region}" \
    --stack-name "${STACK}" \
    --template-file "${TEMPLATE}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --tags project=sensitive-data-scanner purpose=release-hosting \
    "${dry_run[@]}"
done

if [ ${#dry_run[@]} -eq 0 ]; then
  for region in "${REGIONS[@]}"; do
    aws cloudformation describe-stacks --region "${region}" --stack-name "${STACK}" \
      --query "Stacks[0].Outputs[?OutputKey=='ReleaseRoleArn' || OutputKey=='SigningProfileVersionArn'].[OutputKey,OutputValue]" \
      --output text | awk -v r="${region}" '{print r "\t" $0}'
  done
fi
