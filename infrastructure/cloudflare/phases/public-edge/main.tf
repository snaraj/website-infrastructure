resource "cloudflare_zero_trust_tunnel_cloudflared" "pi_websites" {
  account_id = var.cloudflare_account_id
  name       = "pi-websites"
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_public_edge_phase
      error_message = "Set approve_public_edge_phase=true only for an approved public-edge plan."
    }
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "pi_websites" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.pi_websites.id
  source     = "cloudflare"

  config = {
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

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_public_edge_phase
      error_message = "Set approve_public_edge_phase=true only for an approved public-edge plan."
    }
  }
}
