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
