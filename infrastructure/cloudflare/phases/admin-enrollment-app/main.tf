resource "cloudflare_zero_trust_access_application" "pi_admin_owner_enrollment" {
  account_id                = var.cloudflare_account_id
  name                      = "pi-admin-owner-device-enrollment"
  type                      = "warp"
  allowed_idps              = [var.admin_identity_provider_id]
  auto_redirect_to_identity = true
  session_duration          = "15m"
  policies = [{
    id         = var.owner_enrollment_policy_id
    precedence = 1
  }]

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.approve_admin_enrollment_app_phase
      error_message = "Set approve_admin_enrollment_app_phase=true only for the approved one-policy WARP enrollment application."
    }
    precondition {
      condition = (
        can(regex("[1-9a-f]", var.verified_admin_enrollment_policy_contract_sha256)) &&
        can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.admin_email))
      )
      error_message = "A non-synthetic predecessor enrollment-policy audit contract is required."
    }
  }
}
