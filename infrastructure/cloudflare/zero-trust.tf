resource "cloudflare_zero_trust_gateway_policy" "pi_admin_allow" {
  count = local.enabled

  account_id  = var.cloudflare_account_id
  name        = "pi-admin-allow"
  description = "Allow one administrator and required managed device to SSH and the Kubernetes API only."
  action      = "allow"
  enabled     = true
  filters     = ["l4"]
  precedence  = var.pi_admin_allow_precedence

  traffic  = "net.dst.ip in {${var.pi_admin_cidr}} and net.protocol == \"tcp\" and net.dst.port in {22 6443}"
  identity = "identity.email == ${jsonencode(var.admin_email)}"
  device_posture = (
    "any(device_posture.checks.passed[*] in {${jsonencode(var.admin_device_posture_check_id)}})"
  )
}

resource "cloudflare_zero_trust_gateway_policy" "pi_admin_block" {
  count = local.enabled

  account_id  = var.cloudflare_account_id
  name        = "pi-admin-block"
  description = "Block all other Gateway network traffic to the Pi."
  action      = "block"
  enabled     = true
  filters     = ["l4"]
  precedence  = var.pi_admin_block_precedence

  traffic = "net.dst.ip in {${var.pi_admin_cidr}}"
}
