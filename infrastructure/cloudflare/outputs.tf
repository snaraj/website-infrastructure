output "managed_resource_mode" {
  description = "False by default; a true plan still requires every external gate."
  value       = var.enable_cloudflare_resources
}

output "pi_admin_tunnel_id" {
  value     = try(cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0].id, null)
  sensitive = true
}

output "pi_websites_tunnel_id" {
  value     = try(cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0].id, null)
  sensitive = true
}
