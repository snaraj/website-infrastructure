variable "enable_cloudflare_resources" {
  description = "Fail-closed switch. Set true only for an audited local plan."
  type        = bool
  default     = false
}

variable "cloudflare_account_id" {
  description = "Existing account ID discovered read-only."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "cloudflare_naranjo_online_zone_id" {
  description = "Existing naranjo.online Free-zone ID; the zone itself is not managed."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_naranjo_online_zone_id))
    error_message = "cloudflare_naranjo_online_zone_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "cloudflare_lidersea_com_zone_id" {
  description = "Existing lidersea.com Free-zone ID; the zone itself is not managed."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_lidersea_com_zone_id))
    error_message = "cloudflare_lidersea_com_zone_id must be a 32-character lowercase hexadecimal ID."
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
  description = "Existing required device-posture check ID discovered read-only."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.admin_device_posture_check_id) > 0
    error_message = "admin_device_posture_check_id must not be empty."
  }
}

variable "pi_admin_allow_precedence" {
  description = "Unused Gateway precedence discovered read-only; lower evaluates first."
  type        = number
  validation {
    condition     = var.pi_admin_allow_precedence >= 0
    error_message = "precedence must be non-negative."
  }
}

variable "pi_admin_block_precedence" {
  description = "Unused final-block precedence, numerically after the allow."
  type        = number
  validation {
    condition     = var.pi_admin_block_precedence > 0
    error_message = "block precedence must be positive."
  }
}
