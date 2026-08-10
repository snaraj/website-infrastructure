output "pi_websites_tunnel_id" {
  description = "Transfer only through the protected operator workflow into the final public-dns phase."
  value       = cloudflare_zero_trust_tunnel_cloudflared.pi_websites.id
  sensitive   = true
}
