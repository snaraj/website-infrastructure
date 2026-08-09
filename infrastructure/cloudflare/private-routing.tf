resource "cloudflare_zero_trust_tunnel_cloudflared_route" "pi_admin" {
  count = local.enabled

  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0].id
  network    = var.pi_admin_cidr
  comment    = "Pi host only; no LAN subnet"
}
