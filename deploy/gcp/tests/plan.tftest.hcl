# Offline plans and applies with a mock Google provider (`terraform test`, no credentials, no
# calls): which roles are made and bound, and what the job is given, per option.

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email = "sds-scanner@acme-sds.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_organization_iam_custom_role" {
    defaults = {
      name = "organizations/123456789012/roles/sdsScannerReader"
    }
  }
}

variables {
  organization_id = "123456789012"
  project_id      = "acme-sds"
  image           = "ghcr.io/txp-labs/sensitive-data-scanner-gcp@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

run "defaults_read_only" {
  command = plan

  assert {
    condition     = keys(google_organization_iam_custom_role.scanner) == ["reader", "spanner"]
    error_message = "By default only the read role and Spanner's (read_spanner, on by default) are made."
  }
  assert {
    condition     = length(google_organization_iam_member.scanner) == 2 && length(google_folder_iam_member.scanner) == 0
    error_message = "The organization scope binds the read roles at the organization only."
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.name => e.value
      if contains(["GCP_SPANNER", "GCP_ALLOYDB", "GCS_READ_ARCHIVE", "GCP_SQLSERVER", "GCP_READ_PUBSUB_DLQ"], e.name)
    } == {}
    error_message = "Left unset, no toggle reaches the job: it takes Mermera's setting, else its default (#109, docs/mermera-config.md)."
  }
  assert {
    condition     = one([for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.value if e.name == "IAM_GRANTS"]) == "none,GCP_SPANNER"
    error_message = "IAM_GRANTS names the grants this deployment made: Spanner's role only, by default (#109)."
  }
  assert {
    condition     = length(google_secret_manager_secret.push) == 0
    error_message = "No push secret without a push URL."
  }
  assert {
    condition     = !contains([for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.name], "GCP_DB_READ")
    error_message = "Databases are not read by default."
  }
  assert {
    condition     = google_storage_bucket.state.public_access_prevention == "enforced" && google_storage_bucket.state.uniform_bucket_level_access
    error_message = "The state bucket is private."
  }
  assert {
    condition     = one([for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.value if e.name == "GCS_INVENTORY_MIN_OBJECTS"]) == "1000000"
    error_message = "GCS_INVENTORY_MIN_OBJECTS is the scanner's own default unless set."
  }
}

run "inventory_threshold_set" {
  command = plan

  variables {
    gcs_inventory_min_objects = 0
  }

  assert {
    condition     = one([for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.value if e.name == "GCS_INVENTORY_MIN_OBJECTS"]) == "0"
    error_message = "gcs_inventory_min_objects = 0 reaches the job, so no bucket is named."
  }
}

run "inventory_threshold_is_a_whole_count" {
  command = plan

  variables {
    gcs_inventory_min_objects = -1
  }

  expect_failures = [var.gcs_inventory_min_objects]
}

run "opt_ins_and_folders" {
  # Applied against the mock provider (offline), so the service account's email is known.
  command = apply

  variables {
    scope              = "folders"
    folder_ids         = ["111", "222"]
    read_databases     = true
    read_private_logs  = true
    read_secrets       = true
    scan_mode          = "both"
    findings_https_url = "https://collector.example/findings"
    findings_hmac_key  = "made-up-key-made-up-key-made-up-key"
  }

  assert {
    condition     = length(google_organization_iam_custom_role.scanner) == 7
    error_message = "Each opt-in adds its own role (with Spanner's, and AlloyDB's with the databases)."
  }
  assert {
    condition     = length(google_folder_iam_member.scanner) == 14 && length(google_organization_iam_member.scanner) == 0
    error_message = "Each role is bound at each folder, and not at the organization."
  }
  assert {
    condition     = length(google_secret_manager_secret_iam_member.push) == 2
    error_message = "The job reads its own two push secrets."
  }
  assert {
    condition = contains(
      [for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.name],
      "GCP_DB_PRINCIPAL",
    )
    error_message = "Database reads name the service account as the principal."
  }
}

run "limitations_toggled" {
  # #105: Spanner and AlloyDB off drop their roles (and the exception permissions in them);
  # the hooks and Archive-class reads on reach the job as on.
  command = plan

  variables {
    read_databases           = true
    read_spanner             = false
    read_alloydb             = false
    read_archive_objects     = true
    read_sqlserver           = true
    read_pubsub_dead_letters = true
  }

  assert {
    condition     = keys(google_organization_iam_custom_role.scanner) == ["databases", "reader"]
    error_message = "Spanner off and AlloyDB off leave out their roles."
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.name => e.value
      if contains(["GCP_SPANNER", "GCP_ALLOYDB", "GCS_READ_ARCHIVE", "GCP_SQLSERVER", "GCP_READ_PUBSUB_DLQ"], e.name)
      } == {
      GCP_SPANNER         = "off"
      GCP_ALLOYDB         = "off"
      GCS_READ_ARCHIVE    = "on"
      GCP_SQLSERVER       = "on"
      GCP_READ_PUBSUB_DLQ = "on"
    }
    error_message = "Each toggle reaches the job as set."
  }
  assert {
    condition     = one([for e in google_cloud_run_v2_job.scanner.template[0].template[0].containers[0].env : e.value if e.name == "IAM_GRANTS"]) == "none"
    error_message = "With Spanner and AlloyDB off, IAM_GRANTS names no grant (#109)."
  }
}
