variable "approve_public_edge_phase" {
  description = "Explicit public Tunnel/config acknowledgement; false fails planning without changing desired identity."
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
