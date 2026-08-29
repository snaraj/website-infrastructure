output "owner_device_posture_rule_id" {
  value     = cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate.id
  sensitive = true
}

output "owner_device_profile_id" {
  value     = cloudflare_zero_trust_device_custom_profile.pi_admin_owner.id
  sensitive = true
}
