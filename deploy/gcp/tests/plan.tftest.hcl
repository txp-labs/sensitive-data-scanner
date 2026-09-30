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
    condition     = keys(google_organization_iam_custom_role.scanner) == ["reader"]
    error_message = "By default only the read role is made."
  }
  assert {
    condition     = length(google_organization_iam_member.scanner) == 1 && length(google_folder_iam_member.scanner) == 0
    error_message = "The organization scope binds the read role at the organization only."
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
    condition     = length(google_organization_iam_custom_role.scanner) == 5
    error_message = "Each opt-in adds its own role."
  }
  assert {
    condition     = length(google_folder_iam_member.scanner) == 10 && length(google_organization_iam_member.scanner) == 0
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
