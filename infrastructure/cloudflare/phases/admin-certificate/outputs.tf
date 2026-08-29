output "owner_device_ca_certificate_id" {
  description = "Transfer only through the protected operator workflow into the admin-device phase."
  value       = cloudflare_mtls_certificate.pi_admin_owner_ca.id
  sensitive   = true
}
