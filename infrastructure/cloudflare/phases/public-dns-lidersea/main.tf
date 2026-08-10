resource "cloudflare_dns_record" "lidersea_com" {
  zone_id = var.cloudflare_lidersea_com_zone_id
  name    = "lidersea.com"
  type    = "CNAME"
  content = "${var.pi_websites_tunnel_id}.cfargotunnel.com"
  proxied = true
  ttl     = 1

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.enable_public_dns_lidersea_activation
      error_message = "lidersea.com DNS remains default-off until the public-edge audit passes."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_public_edge_contract_sha256)) &&
        var.pi_websites_tunnel_id != "00000000-0000-0000-0000-000000000000"
      )
      error_message = "A non-synthetic public-edge hash bound to a real Tunnel is required."
    }
  }
}
