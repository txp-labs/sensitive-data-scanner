output "service_account_email" {
  description = "The scanner's service account: GCP_DB_PRINCIPAL, and whom a Pub/Sub topic's owner grants Publisher."
  value       = google_service_account.scanner.email
}

output "job_name" {
  value = google_cloud_run_v2_job.scanner.name
}

output "state_bucket" {
  description = "The job's own bucket: findings/latest.json is the latest findings document."
  value       = google_storage_bucket.state.name
}
