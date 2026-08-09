# GitHub control-plane checklist — Draft / dashboard verification required

For protected `main`, require pull requests, current branches, all repository/
application/container/dependency checks, signed commits after merge-method
testing, and block force pushes/deletion. Apply rules to administrators where
practical. With one trusted operator, do not create an impossible second-reviewer
requirement.

Keep default workflow token permissions read-only and Actions restricted to
GitHub-hosted runners. The publish job alone receives package/OIDC/attestation
permissions on `snaraj/website-infrastructure` `main`. No repository/environment
secret may contain kubeconfig, Cloudflare, SSH, age, Kubernetes PKI/bootstrap,
API-encryption, or tunnel credentials.

Make each exact GHCR package public independently after verifying its source
linkage, digest, attestations, and repository ownership. Package publication is
not deployment promotion; CI never writes either chart digest or pushes to
`main`.
