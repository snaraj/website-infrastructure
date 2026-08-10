output "pi_admin_api_policy_id" {
  value     = cloudflare_zero_trust_gateway_policy.pi_admin_api_allow.id
  sensitive = true
}
