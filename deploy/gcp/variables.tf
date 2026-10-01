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

variable "read_spanner" {
  description = "GCP_SPANNER: read Spanner databases (on by default). Off leaves out the Spanner role, with its session permissions, and reports each database read_not_configured (docs/limitations.md, C2). Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_alloydb" {
  description = "GCP_ALLOYDB: with read_databases, read AlloyDB too (on by default). Off leaves out the AlloyDB login role, with generateClientCertificate, and reports each cluster read_not_configured (C2). Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_archive_objects" {
  description = "GCS_READ_ARCHIVE: read Archive-class objects, which have a retrieval fee (off by default: counted as notAllowed archive_class, C3). Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_sqlserver" {
  description = "GCP_SQLSERVER: a hook, off by default. Cloud SQL for SQL Server has no IAM database authentication and no reader is built: on, each database is reported not_implemented (C4). Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_pubsub_dead_letters" {
  description = "GCP_READ_PUBSUB_DLQ: a hook, off by default. The dead-letter reader (a subscription of the scanner's own) is not built: on, each dead-letter topic is reported not_implemented (C5). Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_private_logs" {
  description = "LOGGING_PRIVATE_READ=on: read Data Access audit logs. Adds logging.privateLogEntries.list. Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "read_secrets" {
  description = "SECRET_MANAGER_READ=on: read Secret Manager secrets' latest versions, reported as counts only. Adds secretmanager.versions.access. Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = bool
  default     = null
}

variable "scan_mode" {
  description = "SCAN_MODE (#55): scanner (this scanner reads), vendor (Sensitive Data Protection's data profiles are imported; nothing is read) or both. vendor and both add a role that lists the profiles only. Unset (null, the default): Mermera's setting, else the scanner's default (docs/mermera-config.md)."
  type        = string
  default     = null
  validation {
    condition     = var.scan_mode == null || contains(["scanner", "vendor", "both"], coalesce(var.scan_mode, "scanner"))
    error_message = "scan_mode is scanner, vendor or both."
  }
}

variable "sdp_locations" {
  description = "SDP_LOCATIONS: the locations Sensitive Data Protection's discovery keeps its profiles in."
  type        = list(string)
  default     = ["global"]
}

variable "gcs_inventory_min_objects" {
  description = "GCS_INVENTORY_MIN_OBJECTS: a bucket whose last complete pass listed at least this many objects is named in the run summary (recommendation: storage_insights). 0: never named."
  type        = number
  default     = 1000000
  validation {
    condition     = var.gcs_inventory_min_objects >= 0 && var.gcs_inventory_min_objects <= 10000000000 && floor(var.gcs_inventory_min_objects) == var.gcs_inventory_min_objects
    error_message = "gcs_inventory_min_objects is a whole number from 0 to 10000000000."
  }
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

variable "findings_retention_days" {
  description = "Days the state bucket keeps per-run files (findings/runs/), including noncurrent versions; 0 keeps them forever (#119; replaces runs_retention_days). Template-only: not settable from Mermera."
  type        = number
  default     = 90
  validation {
    condition     = var.findings_retention_days >= 0 && floor(var.findings_retention_days) == var.findings_retention_days
    error_message = "findings_retention_days is a whole number of days, 0 or more."
  }
}

variable "enable_apis" {
  description = "Enable, in project_id, the APIs the job runs on and calls (a service account's calls count against its own project)."
  type        = bool
  default     = true
}
