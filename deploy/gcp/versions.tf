# The Google Cloud scanner's deployment (docs/GCP.md, Deploying). Terraform and
# the Google provider are pinned; .terraform.lock.hcl pins the provider's hashes.
terraform {
  required_version = ">= 1.9"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.5"
    }
  }
}
