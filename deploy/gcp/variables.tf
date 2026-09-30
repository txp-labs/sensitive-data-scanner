variable "organization_id" {
  description = "The organization's number. The scanner's read-only custom roles are defined here, and bound here in the organization scope."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{1,24}$", var.organization_id))
    error_message = "organization_id is the organization's number."
  }
}

variable "scope" {
  description = "What the scanner reads: the whole organization, the folders in folder_ids, or the projects in project_ids."
  type        = string
  default     = "organization"
  validation {
    condition     = contains(["organization", "folders", "projects"], var.scope)
    error_message = "scope is organization, folders or projects."
  }
}

variable "folder_ids" {
  description = "With scope = folders: the folders' numbers."
  type        = list(string)
  default     = []
}

variable "project_ids" {
  description = "With scope = projects: the projects' ids."
  type        = list(string)
  default     = []
}

variable "project_id" {
  description = "The project the Cloud Run job, its service accounts, its state bucket and its schedule go in."
  type        = string
}

variable "region" {
  description = "The job's region."
  type        = string
  default     = "us-central1"
}

variable "image" {
  description = "The scanner's image, pinned by digest (GCP_IMAGE_DIGEST in a release): ghcr.io/txp-labs/sensitive-data-scanner-gcp@sha256:... Cloud Run pulls from Artifact Registry, so mirror it there (or use a remote repository) and give that path."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image is pinned by digest (@sha256:...)."
  }
}

variable "job_name" {
  description = "The Cloud Run job, and the service account's name (sds-scanner@<project>.iam.gserviceaccount.com): what the IAM database users are created as."
  type        = string
  default     = "sds-scanner"
}

variable "schedule" {
  description = "When the job runs (cron, UTC)."
  type        = string
  default     = "0 6 * * *"
}

variable "task_timeout_seconds" {
  description = "How long one run may take at most."
  type        = number
  default     = 3600
}

variable "site" {
  description = "SCANNER_SITE: the name findings carry. Default: org-<organization_id>."
  type        = string
  default     = ""
}

variable "discover" {
  description = "DISCOVER: the kinds to discover, comma-separated. Empty: every kind."
  type        = string
  default     = ""
}

variable "read_databases" {
  description = "GCP_DB_READ=all: read Cloud SQL and AlloyDB as the service account (IAM database authentication). Adds the database login role; each database needs an IAM user first (docs/GCP.md)."
  type        = bool
  default     = false
}

variable "read_private_logs" {
  description = "LOGGING_PRIVATE_READ=on: read Data Access audit logs. Adds logging.privateLogEntries.list."
  type        = bool
  default     = false
}

variable "read_secrets" {
  description = "SECRET_MANAGER_READ=on: read Secret Manager secrets' latest versions, reported as counts only. Adds secretmanager.versions.access."
  type        = bool
  default     = false
}

variable "findings_https_url" {
  description = "FINDINGS_HTTPS_URL: the signed push's endpoint. Held in a Secret Manager secret of the job's own."
  type        = string
  default     = ""
  sensitive   = true
}

variable "findings_hmac_key" {
  description = "FINDINGS_HMAC_KEY: the push's signing key, at least 32 characters. Held in a Secret Manager secret of the job's own."
  type        = string
  default     = ""
  sensitive   = true
}

variable "findings_pubsub_topic" {
  description = "FINDINGS_PUBSUB_TOPIC: also publish to this topic (projects/<p>/topics/<t>). The topic's owner grants the service account Pub/Sub Publisher on it."
  type        = string
  default     = ""
}

variable "network" {
  description = "A VPC network for Direct VPC egress, so the job reaches private IPs (Cloud SQL, AlloyDB). Empty: none."
  type        = string
  default     = ""
}

variable "subnetwork" {
  description = "The subnetwork for Direct VPC egress."
  type        = string
  default     = ""
}

variable "state_bucket_name" {
  description = "The job's own state bucket. Default: <project_id>-sds-state."
  type        = string
  default     = ""
}

variable "runs_retention_days" {
  description = "How long findings/runs/<runId>.json documents are kept."
  type        = number
  default     = 90
}

variable "enable_apis" {
  description = "Enable, in project_id, the APIs the job runs on and calls (a service account's calls count against its own project)."
  type        = bool
  default     = true
}
