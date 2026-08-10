resource "cloudflare_zero_trust_tunnel_cloudflared" "pi_admin" {
  account_id = var.cloudflare_account_id
  name       = "pi-admin"
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_tunnel_phase
      error_message = "Set approve_admin_tunnel_phase=true only for an approved admin-tunnel plan."
    }
  }
}
