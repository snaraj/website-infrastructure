resource "cloudflare_zero_trust_tunnel_cloudflared" "pi_admin" {
  count = local.enabled

  account_id = var.cloudflare_account_id
  name       = "pi-admin"
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.pi_admin_allow_precedence < var.pi_admin_block_precedence
      error_message = "The exact allow must evaluate before the final Pi block."
    }
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "pi_websites" {
  count = local.enabled

  account_id = var.cloudflare_account_id
  name       = "pi-websites"
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = (
        var.cloudflare_naranjo_online_zone_id != var.cloudflare_lidersea_com_zone_id &&
        var.cloudflare_naranjo_online_zone_id != var.cloudflare_account_id &&
        var.cloudflare_lidersea_com_zone_id != var.cloudflare_account_id
      )
      error_message = "The two public zone IDs must be distinct from each other and from the account ID."
    }
  }
}
