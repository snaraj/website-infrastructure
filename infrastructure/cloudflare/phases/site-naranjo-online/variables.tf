variable "approve_site_naranjo_online_phase" {
  description = "Explicit naranjo.online adoption acknowledgement; false fails planning without changing resource identity."
  type        = bool
  default     = false
}

variable "cloudflare_account_id" {
  description = "Exact audited account ID; supplied only from an ignored protected variable file."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id)) && can(regex("[1-9a-f]", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be one nonzero lowercase 32-hex ID."
  }
}

variable "cloudflare_naranjo_online_zone_id" {
  description = "Existing naranjo.online Free-zone ID; the zone object itself is never managed here."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_naranjo_online_zone_id)) && can(regex("[1-9a-f]", var.cloudflare_naranjo_online_zone_id))
    error_message = "cloudflare_naranjo_online_zone_id must be one nonzero lowercase 32-hex ID."
  }
}

variable "verified_naranjo_online_adoption_audit_sha256" {
  description = "Fresh read-only audit hash proving this site's live Tunnel, ingress, and apex record before any plan."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_naranjo_online_adoption_audit_sha256)) && can(regex("[1-9a-f]", var.verified_naranjo_online_adoption_audit_sha256))
    error_message = "verified_naranjo_online_adoption_audit_sha256 must be one nonzero lowercase SHA-256."
  }
}
