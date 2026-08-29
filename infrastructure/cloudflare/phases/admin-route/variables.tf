variable "approve_admin_route_phase" {
  description = "Explicit route acknowledgement; false fails planning without changing desired identity."
  type        = bool
  default     = false
}

variable "cloudflare_account_id" {
  description = "Exact audited account ID."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id)) && can(regex("[1-9a-f]", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a nonzero 32-character lowercase hexadecimal ID."
  }
}

variable "pi_admin_tunnel_id" {
  description = "Existing pi-admin Tunnel UUID emitted by the protected admin-tunnel state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.pi_admin_tunnel_id))
    error_message = "pi_admin_tunnel_id must be a lowercase UUID."
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
  description = "Exact audited Zero Trust administrator identity carried only to bind the policy contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.admin_email))
    error_message = "admin_email must be one exact email identity."
  }
}

variable "admin_device_posture_check_id" {
  description = "Exact audited certificate-v2 posture-rule UUID carried only to bind the policy contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.admin_device_posture_check_id))
    error_message = "admin_device_posture_check_id must be one real lowercase rule UUID."
  }
}

variable "admin_device_profile_id" {
  description = "Exact audited locked owner device-profile UUID carried only to bind the policy contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.admin_device_profile_id))
    error_message = "admin_device_profile_id must be one real lowercase UUID."
  }
}

variable "verified_admin_device_contract_sha256" {
  description = "Exact independently approved certificate posture and locked owner-profile contract used by the audited policies."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_device_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_device_contract_sha256))
    error_message = "verified_admin_device_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_enrollment_contract_sha256" {
  description = "Exact independently approved owner-only MFA enrollment contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_enrollment_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256))
    error_message = "verified_admin_enrollment_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "pi_admin_ssh_allow_precedence" {
  description = "Exact audited SSH allow precedence carried only to bind the policy contract."
  type        = number
  validation {
    condition     = var.pi_admin_ssh_allow_precedence >= 0
    error_message = "SSH allow precedence must be non-negative."
  }
}

variable "pi_admin_block_precedence" {
  description = "Exact audited final-block precedence carried only to bind the policy contract."
  type        = number
  validation {
    condition     = var.pi_admin_block_precedence > var.pi_admin_ssh_allow_precedence
    error_message = "Block precedence must be greater than SSH allow precedence."
  }
}

variable "admin_session_freshness" {
  description = "Exact audited Gateway identity/posture session freshness carried only to bind the policy contract."
  type        = string
  validation {
    condition = (
      can(regex("^[1-9][0-9]*s$", var.admin_session_freshness)) &&
      try(tonumber(trimsuffix(var.admin_session_freshness, "s")), 0) <= 900
    )
    error_message = "admin_session_freshness must be 1-900 seconds."
  }
}

variable "verified_admin_policies_contract_sha256" {
  description = "Hash emitted only after audit verifies the healthy admin Tunnel, WARP/posture, block, and SSH-only allow."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_policies_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_policies_contract_sha256))
    error_message = "verified_admin_policies_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}
