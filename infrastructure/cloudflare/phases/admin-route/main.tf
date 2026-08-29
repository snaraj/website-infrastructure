resource "cloudflare_zero_trust_tunnel_cloudflared_route" "pi_admin" {
  account_id = var.cloudflare_account_id
  tunnel_id  = var.pi_admin_tunnel_id
  network    = var.pi_admin_cidr
  comment    = "Pi host only; verified block and SSH-only allow required"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_route_phase
      error_message = "Set approve_admin_route_phase=true only after the admin-policies audit contract passes."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_policies_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_device_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_enrollment_contract_sha256)) &&
        var.admin_device_profile_id != "00000000-0000-0000-0000-000000000000" &&
        var.pi_admin_tunnel_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic policies, enrollment, and locked-device proofs bound to real IDs are required."
    }
  }
}
