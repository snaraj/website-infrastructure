resource "cloudflare_zero_trust_gateway_policy" "pi_admin_api_allow" {
  account_id  = var.cloudflare_account_id
  name        = "pi-admin-api-allow"
  description = "Later allow for one administrator on a required managed device to TCP 6443 only."
  action      = "allow"
  enabled     = true
  filters     = ["l4"]
  precedence  = var.pi_admin_api_allow_precedence

  traffic  = "net.dst.ip in {${var.pi_admin_cidr}} and net.protocol == \"tcp\" and net.dst.port in {6443}"
  identity = "identity.email == ${jsonencode(var.admin_email)}"
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
      condition     = var.enable_kubernetes_api_access
      error_message = "Kubernetes API access remains default-off until its separate approved phase."
    }
    precondition {
      condition = (
        var.pi_admin_ssh_allow_precedence < var.pi_admin_api_allow_precedence &&
        var.pi_admin_api_allow_precedence < var.pi_admin_block_precedence
      )
      error_message = "The API allow must evaluate after SSH allow and before the final block."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_route_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_policies_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_posture_contract_sha256)) &&
        can(regex("[1-9a-f]", var.verified_admin_api_inputs_contract_sha256)) &&
        var.pi_admin_tunnel_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "Non-synthetic API-input, route, policy, and posture hashes bound to a real Tunnel are required."
    }
  }
}
