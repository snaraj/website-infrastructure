# Unexpected Cloudflare billing — Draft / unverified

1. Stop all planned applies and preserve the plan hash, audit output, billing
   page, audit log, actor, time, product, quantity, and price without exposing
   tokens or sensitive IDs publicly.
2. Run the read-only subscription/product inventory. Treat unavailable evidence
   as unknown. Compare the last reviewed plan and committed allowlist.
3. Revoke or disable the responsible write token if compromise or uncontrolled
   mutation is possible. Do not disable Registrar renewal or delete evidence.
4. If safe and understood, disable only the paid/trial/usage feature and apply a
   reviewed inverse change. Prefer downtime; never activate another product as
   fallback.
5. Contact Cloudflare billing/support, document the incident and expected charge,
   rotate affected credentials, repair the policy/test gap, and repeat the audit.

A budget alert is detection only. A zero current invoice does not prove a
usage-based product cannot accrue delayed charges.
