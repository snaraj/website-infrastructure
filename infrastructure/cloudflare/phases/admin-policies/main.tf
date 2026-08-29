resource "cloudflare_zero_trust_gateway_policy" "pi_admin_block" {
  account_id  = var.cloudflare_account_id
  name        = "pi-admin-block"
  description = "Block all Gateway network traffic to the Pi except earlier exact allows."
  action      = "block"
  enabled     = true
  filters     = ["l4"]
  precedence  = var.pi_admin_block_precedence
  traffic     = "net.dst.ip in {${var.pi_admin_cidr}}"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_policies_phase
      error_message = "Set approve_admin_policies_phase=true only for an approved admin-policies plan."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_tunnel_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_device_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_policy_inputs_contract_sha256)) &&
        var.admin_device_profile_id != "00000000-0000-0000-0000-000000000000" &&
        var.pi_admin_tunnel_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic Tunnel, enrollment, and locked-device proofs bound to real IDs are required."
    }
  }
}

resource "cloudflare_zero_trust_gateway_policy" "pi_admin_ssh_allow" {
  account_id  = var.cloudflare_account_id
  name        = "pi-admin-ssh-allow"
  description = "Allow one administrator on a required managed device to TCP 22 only."
  action      = "allow"
  enabled     = true
  filters     = ["l4"]
  precedence  = var.pi_admin_ssh_allow_precedence
  traffic     = "net.dst.ip in {${var.pi_admin_cidr}} and net.protocol == \"tcp\" and net.dst.port in {22}"
  identity    = "identity.email == ${jsonencode(var.admin_email)}"
  device_posture = (
    "any(device_posture.checks.passed[*] in {${jsonencode(var.admin_device_posture_check_id)}})"
  )
  rule_settings = {
    check_session = {
      enforce  = true
      duration = var.admin_session_freshness
    }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_policies_phase
      error_message = "Set approve_admin_policies_phase=true only for an approved admin-policies plan."
    }
    precondition {
      condition     = var.pi_admin_ssh_allow_precedence < var.pi_admin_block_precedence
      error_message = "The exact SSH allow must evaluate before the final Pi block."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_tunnel_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_device_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_policy_inputs_contract_sha256)) &&
        var.admin_device_profile_id != "00000000-0000-0000-0000-000000000000" &&
        var.pi_admin_tunnel_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic Tunnel, enrollment, and locked-device proofs bound to real IDs are required."
    }
  }
}
