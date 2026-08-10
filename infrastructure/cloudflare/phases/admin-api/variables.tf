variable "enable_kubernetes_api_access" {
  description = "Explicit later-phase acknowledgement. False fails planning and never changes resource count."
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
  description = "Existing pi-admin Tunnel UUID used only to bind this plan to route audit evidence."
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
  description = "Exact Zero Trust administrator identity."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.admin_email))
    error_message = "admin_email must be one exact email identity."
  }
}

variable "admin_device_posture_check_id" {
  description = "Existing required device-posture check ID."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.admin_device_posture_check_id))
    error_message = "admin_device_posture_check_id must be one real lowercase rule UUID."
  }
}

variable "pi_admin_ssh_allow_precedence" {
  description = "Existing verified SSH allow precedence."
  type        = number
}

variable "pi_admin_api_allow_precedence" {
  description = "Selected precedence for the later Kubernetes API allow."
  type        = number
}

variable "pi_admin_block_precedence" {
  description = "Existing verified final-block precedence."
  type        = number
}

variable "admin_session_freshness" {
  description = "Maximum accepted Gateway identity/posture session age in seconds."
  type        = string
  default     = "300s"
  validation {
    condition = (
      can(regex("^[1-9][0-9]*s$", var.admin_session_freshness)) &&
      try(tonumber(trimsuffix(var.admin_session_freshness, "s")), 0) <= 900
    )
    error_message = "admin_session_freshness must be 1-900 seconds."
  }
}

variable "verified_admin_posture_contract_sha256" {
  description = "Exact independently approved certificate-v2 posture contract used by the audited admin policies."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_posture_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_posture_contract_sha256))
    error_message = "verified_admin_posture_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_policies_contract_sha256" {
  description = "Full audit hash binding the exact SSH/block policy identity, posture, session, and precedence contract."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_policies_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_policies_contract_sha256))
    error_message = "verified_admin_policies_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_route_contract_sha256" {
  description = "Hash emitted only after the audit verifies the exact /32 route behind the protected control policies."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_route_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_route_contract_sha256))
    error_message = "verified_admin_route_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}

variable "verified_admin_api_inputs_contract_sha256" {
  description = "Audit hash binding the exact API allow inputs to the verified policy and route contracts."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_admin_api_inputs_contract_sha256)) && can(regex("[1-9a-f]", var.verified_admin_api_inputs_contract_sha256))
    error_message = "verified_admin_api_inputs_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}
