variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "PROJECT_ID"
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "us-central1"
}

variable "cluster_node_count" {
  description = "Number of nodes in the GKE node pool"
  type        = number
  default     = 3
}

variable "cluster_machine_type" {
  description = "GCE machine type for GKE nodes"
  type        = string
  default     = "e2-standard-2"
}
