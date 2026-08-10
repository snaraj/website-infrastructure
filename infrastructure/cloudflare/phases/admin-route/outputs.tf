output "pi_admin_route_id" {
  value     = cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin.id
  sensitive = true
}
