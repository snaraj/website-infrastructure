variable "approve_admin_tunnel_phase" {
  description = "Explicit admin Tunnel acknowledgement; false fails planning without changing resource identity."
  type        = bool
  default     = false
}

variable "cloudflare_account_id" {
  description = "Exact account ID from current read-only audit evidence."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id)) && can(regex("[1-9a-f]", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a nonzero 32-character lowercase hexadecimal ID."
  }
}

variable "verified_admin_enrollment_contract_sha256" {
  description = "Fresh audit hash for the exact owner-only MFA enrollment application and policy."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_enrollment_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256))
    error_message = "verified_admin_enrollment_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_device_contract_sha256" {
  description = "Fresh audit hash for the exact certificate posture and locked owner device profile."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_device_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_device_contract_sha256))
    error_message = "verified_admin_device_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}
