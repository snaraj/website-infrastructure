variable "enable_public_dns_naranjo_activation" {
  description = "Explicit final naranjo.online DNS acknowledgement; false fails planning without changing resource identity."
  type        = bool
  default     = false
}

variable "cloudflare_account_id" {
  description = "Exact audited account ID used only to bind public-edge evidence."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id)) && can(regex("[1-9a-f]", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be one nonzero lowercase 32-hex ID."
  }
}

variable "cloudflare_naranjo_online_zone_id" {
  description = "Existing naranjo.online Free-zone ID; the zone itself is not managed."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_naranjo_online_zone_id)) && can(regex("[1-9a-f]", var.cloudflare_naranjo_online_zone_id))
    error_message = "cloudflare_naranjo_online_zone_id must be one nonzero lowercase 32-hex ID."
  }
}

variable "pi_websites_tunnel_id" {
  description = "Existing pi-websites Tunnel UUID emitted by protected public-edge state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.pi_websites_tunnel_id))
    error_message = "pi_websites_tunnel_id must be a non-synthetic lowercase UUID."
  }
}

variable "verified_public_edge_contract_sha256" {
  description = "Fresh audit hash proving the exact healthy public edge before this DNS activation."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.verified_public_edge_contract_sha256)) && can(regex("[1-9a-f]", var.verified_public_edge_contract_sha256))
    error_message = "verified_public_edge_contract_sha256 must be one nonzero lowercase SHA-256."
  }
}
