resource "cloudflare_zero_trust_access_policy" "pi_admin_owner_enrollment" {
  account_id       = var.cloudflare_account_id
  name             = "pi-admin-owner-device-enrollment"
  decision         = "allow"
  session_duration = "15m"
  include = [{
    email = {
      email = var.admin_email
    }
  }]
  mfa_config = {
    allowed_authenticators = ["biometrics", "security_key"]
    mfa_disabled           = false
    session_duration       = "5m"
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_enrollment_policy_phase
      error_message = "Set approve_admin_enrollment_policy_phase=true only for the approved exact-owner policy plan."
    }
  }
}
