variable "approve_admin_enrollment_app_phase" {
  description = "Explicit one-policy WARP enrollment application acknowledgement; false fails planning."
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

variable "owner_enrollment_policy_id" {
  description = "Existing exact-owner reusable Access policy from the protected predecessor state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.owner_enrollment_policy_id))
    error_message = "owner_enrollment_policy_id must be one real lowercase UUID."
  }
}

variable "admin_identity_provider_id" {
  description = "The sole audited identity provider permitted by the WARP enrollment application."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.admin_identity_provider_id))
    error_message = "admin_identity_provider_id must be one real lowercase UUID."
  }
}

variable "admin_email" {
  description = "The exact owner identity carried only to bind the predecessor enrollment-policy contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.admin_email))
    error_message = "admin_email must be one exact email identity."
  }
}

variable "verified_admin_enrollment_policy_contract_sha256" {
  description = "Fresh post-audit hash for the exact owner-only policy."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_enrollment_policy_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_enrollment_policy_contract_sha256))
    error_message = "verified_admin_enrollment_policy_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}
