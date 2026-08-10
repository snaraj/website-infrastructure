output "pi_admin_tunnel_id" {
  description = "Transfer only through the protected operator workflow into the route phase."
  value       = cloudflare_zero_trust_tunnel_cloudflared.pi_admin.id
  sensitive   = true
}
