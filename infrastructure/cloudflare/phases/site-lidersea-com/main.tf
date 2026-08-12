# One site, one root, one state, one token. This root adopts the live
# lidersea.com objects; it never creates, replaces, or destroys them, and it
# never references the other site's zone, Tunnel, namespace, or variables.

resource "cloudflare_zero_trust_tunnel_cloudflared" "lidersea_com" {
  account_id = var.cloudflare_account_id
  name       = "lidersea-com"
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "lidersea_com" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.lidersea_com.id
  source     = "cloudflare"

  # Exactly one public hostname rule plus the terminal catch-all. No wildcard
  # hostname, no private/WARP route, no administrative hostname.
  config = {
    ingress = [
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
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

# The apex target is derived from this root's own Tunnel resource, so no Tunnel
# UUID ever appears in Git or in a variable file.
resource "cloudflare_dns_record" "lidersea_com_apex" {
  zone_id = var.cloudflare_lidersea_com_zone_id
  name    = "lidersea.com"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.lidersea_com.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

# Zone security target state. Every setting below is a free-plan zone-level
# control; none of them can bill. Strict origin pull is deliberately excluded:
# the connector-to-origin leg is plain HTTP by accepted decision (ADR 0015), so
# the SSL mode is "full" and must never be raised to a strict variant here.
resource "cloudflare_zone_setting" "lidersea_com_always_use_https" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "always_use_https"
  value      = "on"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

resource "cloudflare_zone_setting" "lidersea_com_min_tls_version" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "min_tls_version"
  value      = "1.2"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

resource "cloudflare_zone_setting" "lidersea_com_tls_1_3" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "tls_1_3"
  value      = "on"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

# 0-RTT stays off: early data is replayable, and the handshake saving is not
# worth that exposure on a site that varies responses per request.
resource "cloudflare_zone_setting" "lidersea_com_zero_rtt" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "0rtt"
  value      = "off"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

# HTTP/3 is advertised on every response from this zone today. Pinning it is
# the same kind of claim as TLS 1.3: an externally attested value that is
# already at target and must not be able to regress unnoticed.
resource "cloudflare_zone_setting" "lidersea_com_http3" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "http3"
  value      = "on"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}

resource "cloudflare_zone_setting" "lidersea_com_ssl" {
  zone_id    = var.cloudflare_lidersea_com_zone_id
  setting_id = "ssl"
  value      = "full"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_site_lidersea_com_phase
      error_message = "Set approve_site_lidersea_com_phase=true only for an approved lidersea.com plan."
    }
  }
}
