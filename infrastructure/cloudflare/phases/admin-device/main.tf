resource "cloudflare_zero_trust_device_posture_rule" "pi_admin_owner_certificate" {
  account_id  = var.cloudflare_account_id
  name        = "pi-admin-owner-device-certificate"
  description = "Require the one owner laptop certificate and its matching private key."
  type        = "client_certificate_v2"
  schedule    = "5m"
  expiration  = "10m"
  input = {
    certificate_id    = var.owner_device_ca_certificate_id
    check_private_key = true
    operating_system  = "mac"
    cn                = "$${serial_number}"
    extended_key_usage = [
      "clientAuth",
    ]
    locations = {
      trust_stores = ["system"]
    }
  }
  match = [{
    platform = "mac"
  }]

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_device_phase
      error_message = "Set approve_admin_device_phase=true only for the approved one-device posture/profile plan."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_certificate_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256)) &&
        can(regex("[1-9a-f]", var.owner_device_ca_certificate_sha256)) &&
        var.owner_device_ca_certificate_id != "00000000-0000-0000-0000-000000000000" &&
        var.owner_enrollment_policy_id != "00000000-0000-0000-0000-000000000000" &&
        var.owner_enrollment_application_id != "00000000-0000-0000-0000-000000000000" &&
        var.admin_identity_provider_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic certificate and enrollment predecessor audit contracts are required."
    }
  }
}

resource "cloudflare_zero_trust_device_custom_profile" "pi_admin_owner" {
  account_id                     = var.cloudflare_account_id
  name                           = "pi-admin-owner-device"
  description                    = "Locked owner profile; only the single Pi host route enters Cloudflare."
  enabled                        = true
  precedence                     = 100
  match                          = "identity.email == ${jsonencode(var.admin_email)}"
  allow_mode_switch              = false
  allow_updates                  = true
  allowed_to_leave               = false
  auto_connect                   = 0
  captive_portal                 = 180
  disable_auto_fallback          = true
  register_interface_ip_with_dns = false
  sccm_vpn_boundary_support      = false
  support_url                    = ""
  switch_locked                  = true
  exclude_office_ips             = false
  tunnel_protocol                = "masque"
  service_mode_v2                = { mode = "warp" }
  include = [{
    address     = var.pi_admin_cidr
    description = "Pi admin host only"
  }]

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_device_phase
      error_message = "Set approve_admin_device_phase=true only for the approved one-device posture/profile plan."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_certificate_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256)) &&
        can(regex("[1-9a-f]", var.owner_device_ca_certificate_sha256)) &&
        var.owner_device_ca_certificate_id != "00000000-0000-0000-0000-000000000000" &&
        var.owner_enrollment_policy_id != "00000000-0000-0000-0000-000000000000" &&
        var.owner_enrollment_application_id != "00000000-0000-0000-0000-000000000000" &&
        var.admin_identity_provider_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic certificate and enrollment predecessor audit contracts are required."
    }
  }
}
