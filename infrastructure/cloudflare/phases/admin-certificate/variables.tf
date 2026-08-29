variable "approve_admin_certificate_phase" {
  description = "Explicit owner-device CA acknowledgement; false fails planning without changing resource identity."
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

variable "owner_device_ca_certificate_pem" {
  description = "Public signing certificate for the one-device client identity; the CA private key is forbidden."
  type        = string
  sensitive   = true
  validation {
    condition = (
      length(var.owner_device_ca_certificate_pem) >= 512 &&
      length(var.owner_device_ca_certificate_pem) <= 16384 &&
      length(regexall("-----BEGIN CERTIFICATE-----", var.owner_device_ca_certificate_pem)) == 1 &&
      length(regexall("-----END CERTIFICATE-----", var.owner_device_ca_certificate_pem)) == 1 &&
      !strcontains(var.owner_device_ca_certificate_pem, "PRIVATE KEY")
    )
    error_message = "owner_device_ca_certificate_pem must contain exactly one bounded public certificate and no private key."
  }
}

variable "owner_device_ca_certificate_sha256" {
  description = "Independently captured SHA-256 of the exact public CA certificate bytes."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.owner_device_ca_certificate_sha256)) && can(regex("[1-9a-f]", var.owner_device_ca_certificate_sha256))
    error_message = "owner_device_ca_certificate_sha256 must be one nonzero lowercase SHA-256."
  }
}
