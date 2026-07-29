output "artifact_registry_url" {
  description = "Docker repository base URL for log-analyzer images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.log_analyzer.repository_id}"
}

output "log_input_bucket" {
  description = "GCS bucket name for log input files"
  value       = google_storage_bucket.log_input.name
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.security_tools.name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster API server endpoint"
  value       = google_container_cluster.security_tools.endpoint
  sensitive   = true
}
