output "owner_enrollment_policy_id" {
  description = "Transfer only through the protected operator workflow into the enrollment-application phase."
  value       = cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment.id
  sensitive   = true
}
