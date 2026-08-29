variable "approve_admin_device_phase" {
  description = "Explicit certificate-posture plus locked-/32-profile acknowledgement; false fails planning."
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

variable "owner_device_ca_certificate_id" {
  description = "Exact uploaded owner-device CA UUID from the protected certificate state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.owner_device_ca_certificate_id))
    error_message = "owner_device_ca_certificate_id must be one real lowercase UUID."
  }
}

variable "owner_device_ca_certificate_sha256" {
  description = "Exact public certificate SHA-256 bound into the predecessor certificate contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.owner_device_ca_certificate_sha256)) && can(regex("[1-9a-f]", var.owner_device_ca_certificate_sha256))
    error_message = "owner_device_ca_certificate_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "owner_enrollment_policy_id" {
  description = "Exact owner-only reusable enrollment policy UUID from protected predecessor state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.owner_enrollment_policy_id))
    error_message = "owner_enrollment_policy_id must be one real lowercase UUID."
  }
}

variable "owner_enrollment_application_id" {
  description = "Exact owner-only WARP enrollment application UUID from protected predecessor state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.owner_enrollment_application_id))
    error_message = "owner_enrollment_application_id must be one real lowercase UUID."
  }
}

variable "admin_identity_provider_id" {
  description = "Exact sole identity-provider UUID bound into the enrollment predecessor contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.admin_identity_provider_id))
    error_message = "admin_identity_provider_id must be one real lowercase UUID."
  }
}

variable "verified_admin_certificate_contract_sha256" {
  description = "Fresh audit hash for the exact public owner-device signing certificate."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_certificate_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_certificate_contract_sha256))
    error_message = "verified_admin_certificate_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_enrollment_contract_sha256" {
  description = "Fresh audit hash for the exact owner-only MFA enrollment app and policy."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_enrollment_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256))
    error_message = "verified_admin_enrollment_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "pi_admin_cidr" {
  description = "Exact private IPv4 address of the Pi expressed as /32."
  type        = string
  sensitive   = true
  validation {
    condition = (
      can(cidrnetmask(var.pi_admin_cidr)) &&
      can(regex("^[0-9.]+/32$", var.pi_admin_cidr)) &&
      anytrue([
        try(cidrcontains("10.0.0.0/8", cidrhost(var.pi_admin_cidr, 0)), false),
        try(cidrcontains("172.16.0.0/12", cidrhost(var.pi_admin_cidr, 0)), false),
        try(cidrcontains("192.168.0.0/16", cidrhost(var.pi_admin_cidr, 0)), false),
      ])
    )
    error_message = "pi_admin_cidr must be one RFC1918 IPv4 /32."
  }
}

variable "admin_email" {
  description = "The one exact owner identity receiving the locked device profile."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.admin_email))
    error_message = "admin_email must be one exact email identity."
  }
}
