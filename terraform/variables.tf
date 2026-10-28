variable "environment" {
  description = "Target deployment environment (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig file for local execution / plan"
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Kubernetes namespace for VulnTracker deployment"
  type        = string
  default     = "vulntracker"
}

variable "image_repository" {
  description = "Container image repository"
  type        = string
  default     = "vulntracker-api"
}

variable "image_tag" {
  description = "Container image tag (must be pinned, not 'latest')"
  type        = string
  default     = "1.0.0"
}

variable "replica_count" {
  description = "Number of deployment replicas"
  type        = number
  default     = 2
}

variable "keyvault_name" {
  description = "Name of the Azure Key Vault providing secrets via Secrets Store CSI"
  type        = string
  default     = "kv-vulntracker-prod"
}

variable "workload_client_id" {
  description = "Client ID of the Azure Workload Identity Managed Identity"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "tenant_id" {
  description = "Azure Tenant ID for workload identity federation"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

