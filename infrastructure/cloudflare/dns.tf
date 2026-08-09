resource "cloudflare_zero_trust_tunnel_cloudflared_config" "pi_websites" {
  count = local.enabled

  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0].id
  source     = "cloudflare"

  config = {
    # The tunnel crosses namespaces, so fully qualified Service names bind each
    # public hostname to its one intended private ClusterIP origin.
    ingress = [
      {
        hostname = "naranjo.online"
        service  = "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
      },
      {
        hostname = "lidersea.com"
        service  = "http://lidersea-com.lidersea-com.svc.cluster.local:8080"
      },
      {
        service = "http_status:404"
      },
    ]
  }
}

resource "cloudflare_dns_record" "naranjo_online" {
  count = local.enabled

  zone_id = var.cloudflare_naranjo_online_zone_id
  name    = "naranjo.online"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_dns_record" "lidersea_com" {
  count = local.enabled

  zone_id = var.cloudflare_lidersea_com_zone_id
  name    = "lidersea.com"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}
