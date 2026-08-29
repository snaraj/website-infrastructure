resource "cloudflare_mtls_certificate" "pi_admin_owner_ca" {
  account_id   = var.cloudflare_account_id
  name         = "pi-admin-owner-device-ca"
  ca           = true
  certificates = var.owner_device_ca_certificate_pem

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_certificate_phase
      error_message = "Set approve_admin_certificate_phase=true only for an approved one-certificate plan."
    }
    precondition {
      condition     = sha256(var.owner_device_ca_certificate_pem) == var.owner_device_ca_certificate_sha256
      error_message = "The public CA bytes do not match the independently captured digest."
    }
  }
}
