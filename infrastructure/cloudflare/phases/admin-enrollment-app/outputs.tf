output "owner_enrollment_application_id" {
  description = "Transfer only through the protected operator workflow into later admin phases."
  value       = cloudflare_zero_trust_access_application.pi_admin_owner_enrollment.id
  sensitive   = true
}
