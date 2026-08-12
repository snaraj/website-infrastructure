variable "approve_site_lidersea_com_phase" {
  description = "Explicit lidersea.com adoption acknowledgement; false fails planning without changing resource identity."
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

variable "cloudflare_lidersea_com_zone_id" {
  description = "Existing lidersea.com Free-zone ID; the zone object itself is never managed here."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_lidersea_com_zone_id)) && can(regex("[1-9a-f]", var.cloudflare_lidersea_com_zone_id))
    error_message = "cloudflare_lidersea_com_zone_id must be one nonzero lowercase 32-hex ID."
  }
}

variable "verified_lidersea_com_adoption_audit_sha256" {
  description = "Fresh read-only audit hash proving this site's live Tunnel, ingress, and apex record before any plan."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_lidersea_com_adoption_audit_sha256)) && can(regex("[1-9a-f]", var.verified_lidersea_com_adoption_audit_sha256))
    error_message = "verified_lidersea_com_adoption_audit_sha256 must be one nonzero lowercase SHA-256."
  }
}
