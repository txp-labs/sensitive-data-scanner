# The Google Cloud scanner: a scheduled Cloud Run job, run as its own service
# account with no key, holding read-only custom roles at the organization, the
# folders or the projects it reads, and write access to its own state bucket only.
#
# scanner/tests/test_gcp_template.py holds this file to reads: every permission
# in a custom role reads (or is one of the few named exceptions), no predefined
# role is bound but the three on the job's own resources, and nothing is bound
# authoritatively.

locals {
  site         = var.site != "" ? var.site : "org-${var.organization_id}"
  state_bucket = var.state_bucket_name != "" ? var.state_bucket_name : "${var.project_id}-sds-state"
  # Whether the push is on says nothing of the URL or the key.
  push = nonsensitive(var.findings_https_url != "")

  # What the scanner reads with, by default: listing, metadata and data reads only.
  # The predefined viewer roles are not used: several carry writes (BigQuery Data
  # Viewer's bigquery.tables.export and createSnapshot, Cloud Asset Viewer's exports).
  read_permissions = [
    # Discovery across the scope.
    "cloudasset.assets.searchAllResources",
    # Cloud Storage: list objects, ranged reads.
    "storage.objects.get",
    "storage.objects.list",
    # BigQuery: datasets, tables, row access policies and tabledata.list (no query, no job).
    "bigquery.datasets.get",
    "bigquery.rowAccessPolicies.list",
    "bigquery.tables.get",
    "bigquery.tables.getData",
    "bigquery.tables.list",
    # Firestore and Datastore: a database's mode and key, then queries.
    "datastore.databases.getMetadata",
    "datastore.entities.get",
    "datastore.entities.list",
    # Spanner: a database's dialect and key (discovery; its reads are local.spanner_permissions).
    "spanner.databases.get",
    # Bigtable: the clusters' keys, then readRows.
    "bigtable.clusters.list",
    "bigtable.tables.readRows",
    # Cloud Logging: the _Default bucket's key, the logs, entries.list.
    "logging.buckets.list",
    "logging.logEntries.list",
    "logging.logs.list",
    # Pub/Sub: which topics are dead-letter topics (coverage only).
    "pubsub.subscriptions.list",
    # Compute Engine: disk snapshots (coverage only).
    "compute.snapshots.list",
    # Cloud SQL and AlloyDB: instances, databases, keys (discovery).
    "alloydb.clusters.get",
    "alloydb.instances.list",
    "cloudsql.databases.list",
    "cloudsql.instances.get",
  ]
  # On by default (read_spanner, GCP_SPANNER; #105): SQL in single-use read-only
  # transactions, and the session two of the named exceptions need.
  spanner_permissions = [
    "spanner.databases.beginReadOnlyTransaction",
    "spanner.databases.select",
    "spanner.sessions.create",
    "spanner.sessions.delete",
  ]
  # Opt-in: Data Access audit logs (Private Logs Viewer's one permission).
  private_log_permissions = ["logging.privateLogEntries.list"]
  # Opt-in: Secret Manager's values (counts only) and each secret's key.
  secret_permissions = ["secretmanager.secrets.get", "secretmanager.versions.access"]
  # Opt-in: IAM database authentication to Cloud SQL.
  database_permissions = ["cloudsql.instances.login"]
  # With read_databases, unless read_alloydb is off (GCP_ALLOYDB; #105): AlloyDB's IAM
  # login, with two of the named exceptions (its cluster CA, and the quota project).
  alloydb_permissions = [
    "alloydb.clusters.generateClientCertificate",
    "alloydb.users.login",
    "serviceusage.services.use",
  ]

  # With scan_mode vendor or both (#55): Sensitive Data Protection's data profiles, listed
  # (the profiles only: never its inspection results, which can quote matched text).
  sdp_permissions = [
    "dlp.columnDataProfiles.list",
    "dlp.fileStoreProfiles.list",
  ]

  roles = merge(
    { reader = { id = "sdsScannerReader", title = "Sensitive data scanner: read", permissions = local.read_permissions } },
    var.read_spanner ? { spanner = { id = "sdsScannerSpanner", title = "Sensitive data scanner: Spanner", permissions = local.spanner_permissions } } : {},
    var.read_private_logs ? { private_logs = { id = "sdsScannerPrivateLogs", title = "Sensitive data scanner: private logs", permissions = local.private_log_permissions } } : {},
    var.read_secrets ? { secrets = { id = "sdsScannerSecrets", title = "Sensitive data scanner: secrets", permissions = local.secret_permissions } } : {},
    var.read_databases ? { databases = { id = "sdsScannerDatabases", title = "Sensitive data scanner: database login", permissions = local.database_permissions } } : {},
    var.read_databases && var.read_alloydb ? { alloydb = { id = "sdsScannerAlloyDb", title = "Sensitive data scanner: AlloyDB login", permissions = local.alloydb_permissions } } : {},
    var.scan_mode != "scanner" ? { sdp = { id = "sdsScannerSdpProfiles", title = "Sensitive data scanner: SDP profiles", permissions = local.sdp_permissions } } : {},
  )

  scope_env = (
    var.scope == "organization" ? { GCP_ORGANIZATION = var.organization_id } :
    var.scope == "folders" ? { GCP_FOLDERS = join(",", var.folder_ids) } :
    { GCP_PROJECTS = join(",", var.project_ids) }
  )
  env = { for k, v in merge(local.scope_env, {
    SCANNER_SITE              = local.site
    STATE_BUCKET              = "gs://${local.state_bucket}"
    DISCOVER                  = var.discover
    GCP_DB_READ               = var.read_databases ? "all" : ""
    GCP_DB_PRINCIPAL          = var.read_databases ? google_service_account.scanner.email : ""
    LOGGING_PRIVATE_READ      = var.read_private_logs ? "on" : ""
    SECRET_MANAGER_READ       = var.read_secrets ? "on" : ""
    FINDINGS_PUBSUB_TOPIC     = var.findings_pubsub_topic
    SCAN_MODE                 = var.scan_mode != "scanner" ? var.scan_mode : ""
    SDP_LOCATIONS             = var.scan_mode != "scanner" ? join(",", var.sdp_locations) : ""
    GCS_INVENTORY_MIN_OBJECTS = tostring(var.gcs_inventory_min_objects)
    # The limitations' toggles (docs/limitations.md, #105), always explicit.
    GCP_SPANNER         = var.read_spanner ? "on" : "off"
    GCP_ALLOYDB         = var.read_alloydb ? "on" : "off"
    GCS_READ_ARCHIVE    = var.read_archive_objects ? "on" : "off"
    GCP_SQLSERVER       = var.read_sqlserver ? "on" : "off"
    GCP_READ_PUBSUB_DLQ = var.read_pubsub_dead_letters ? "on" : "off"
  }) : k => v if v != "" }

  apis = concat(var.scan_mode != "scanner" ? ["dlp.googleapis.com"] : [], [
    "alloydb.googleapis.com",
    "bigquery.googleapis.com",
    "bigtableadmin.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudscheduler.googleapis.com",
    "compute.googleapis.com",
    "datastore.googleapis.com",
    "firestore.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "spanner.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
  ])
}

resource "google_project_service" "apis" {
  for_each           = var.enable_apis ? toset(local.apis) : toset([])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ------------------------------------------------------------------ identities

# The scanner's own service account. No key is ever made for it: Cloud Run
# gives the job its tokens through the metadata server.
resource "google_service_account" "scanner" {
  project      = var.project_id
  account_id   = var.job_name
  display_name = "Sensitive data scanner (read-only)"
}

# The scheduler's, which may only start the job.
resource "google_service_account" "scheduler" {
  project      = var.project_id
  account_id   = "${var.job_name}-cron"
  display_name = "Sensitive data scanner schedule"
}

# ------------------------------------------------------------------ read-only roles

resource "google_organization_iam_custom_role" "scanner" {
  for_each    = local.roles
  org_id      = var.organization_id
  role_id     = each.value.id
  title       = each.value.title
  description = "Read-only: docs/GCP.md in txp-labs/sensitive-data-scanner."
  permissions = each.value.permissions
}

resource "google_organization_iam_member" "scanner" {
  for_each = var.scope == "organization" ? local.roles : {}
  org_id   = var.organization_id
  role     = google_organization_iam_custom_role.scanner[each.key].name
  member   = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_folder_iam_member" "scanner" {
  for_each = var.scope == "folders" ? { for p in setproduct(keys(local.roles), var.folder_ids) : "${p[0]}/${p[1]}" => { role = p[0], folder = p[1] } } : {}
  folder   = "folders/${each.value.folder}"
  role     = google_organization_iam_custom_role.scanner[each.value.role].name
  member   = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner" {
  for_each = var.scope == "projects" ? { for p in setproduct(keys(local.roles), var.project_ids) : "${p[0]}/${p[1]}" => { role = p[0], project = p[1] } } : {}
  project  = each.value.project
  role     = google_organization_iam_custom_role.scanner[each.value.role].name
  member   = "serviceAccount:${google_service_account.scanner.email}"
}

# ------------------------------------------------------------------ the job's own state

resource "google_storage_bucket" "state" {
  project                     = var.project_id
  name                        = local.state_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition {
      age            = var.runs_retention_days
      matches_prefix = ["findings/runs/"]
    }
    action {
      type = "Delete"
    }
  }
}

# The one write the scanner holds: objects in its own bucket (findings, cursors, the lock).
resource "google_storage_bucket_iam_member" "state" {
  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.scanner.email}"
}

# The signed push's URL and key, in secrets of the job's own.
resource "google_secret_manager_secret" "push" {
  for_each  = local.push ? toset(["FINDINGS_HTTPS_URL", "FINDINGS_HMAC_KEY"]) : toset([])
  project   = var.project_id
  secret_id = "${var.job_name}-${lower(replace(each.value, "_", "-"))}"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "push" {
  for_each    = google_secret_manager_secret.push
  secret      = each.value.id
  secret_data = each.key == "FINDINGS_HTTPS_URL" ? var.findings_https_url : var.findings_hmac_key
}

resource "google_secret_manager_secret_iam_member" "push" {
  for_each  = google_secret_manager_secret.push
  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scanner.email}"
}

# ------------------------------------------------------------------ the job and its schedule

resource "google_cloud_run_v2_job" "scanner" {
  project             = var.project_id
  name                = var.job_name
  location            = var.region
  deletion_protection = false

  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account = google_service_account.scanner.email
      timeout         = "${var.task_timeout_seconds}s"
      max_retries     = 0

      containers {
        image = var.image
        args  = ["scan"]
        resources {
          limits = {
            cpu    = "2"
            memory = "4Gi"
          }
        }
        dynamic "env" {
          for_each = local.env
          content {
            name  = env.key
            value = env.value
          }
        }
        dynamic "env" {
          for_each = google_secret_manager_secret.push
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value.secret_id
                version = "latest"
              }
            }
          }
        }
      }

      dynamic "vpc_access" {
        for_each = var.network != "" ? [1] : []
        content {
          egress = "PRIVATE_RANGES_ONLY"
          network_interfaces {
            network    = var.network
            subnetwork = var.subnetwork
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_storage_bucket_iam_member.state,
    google_secret_manager_secret_iam_member.push,
    google_secret_manager_secret_version.push,
  ]
}

# The scheduler may start this job, and nothing else.
resource "google_cloud_run_v2_job_iam_member" "scheduler" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.scanner.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "scanner" {
  project          = var.project_id
  region           = var.region
  name             = var.job_name
  schedule         = var.schedule
  time_zone        = "Etc/UTC"
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.scanner.name}:run"
    oauth_token {
      service_account_email = google_service_account.scheduler.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  depends_on = [google_cloud_run_v2_job_iam_member.scheduler]
}
