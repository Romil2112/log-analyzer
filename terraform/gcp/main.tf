terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_artifact_registry_repository" "log_analyzer" {
  location      = var.region
  repository_id = "log-analyzer"
  format        = "DOCKER"
}

resource "google_storage_bucket" "log_input" {
  name          = "${var.project_id}-log-analyzer-input"
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 90
    }
  }
}

resource "google_container_cluster" "security_tools" {
  name     = "security-tools"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}

resource "google_container_node_pool" "primary" {
  name       = "primary"
  location   = var.region
  cluster    = google_container_cluster.security_tools.name
  node_count = var.cluster_node_count

  node_config {
    machine_type = var.cluster_machine_type
    disk_size_gb = 50

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
