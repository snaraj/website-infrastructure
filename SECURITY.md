# Security policy

## Reporting

Do not open a public issue containing a credential, home address, account ID,
zone ID, tunnel ID, private hostname, kubeconfig, or infrastructure plan. Revoke
or isolate exposed material first, preserve minimal evidence, and use a private
maintainer channel.

## Production authority

Write access to protected `main` is deployment authority because Flux consumes
it. GitHub-hosted CI has no cluster, SSH, Cloudflare apply, age, Kubernetes PKI,
or bootstrap secrets.
Cloudflare and cluster mutations are manual, local, exit-gated operations.

## Required controls

- MFA/passkeys on Cloudflare and GitHub; minimal administrator membership.
- SSH keys only, no root or password authentication, applied only after a tested
  second session and physical/LAN recovery path exist.
- Restricted Pod Security, non-root containers, read-only root filesystems,
  RuntimeDefault seccomp, all capabilities dropped, and no API token mounts.
- Default-deny ingress and egress per workload namespace.
- Heavy media outside Git/OCI/etcd, originals separated from derivative-only
  read access, no public upload, and a disabled storage profile until dedicated
  mount, checksum, backup/restore, disk-pressure, and admin-saturation evidence
  passes. Current zero-spend Cloudflare terms keep public large-media delivery
  disabled independently from code readiness.
- Private databases and encrypted, off-device, restore-tested backups when any
  database is introduced.
- SOPS/age in Git and Kubernetes API Secret encryption at rest.
- Signed/attested immutable images, SBOM, vulnerability scan, secret scan, SAST,
  manifest validation, and IaC policy gates.
- Authentication, authorization, schema/body/time limits, safe CORS/CSRF,
  abuse controls, and secret-safe logging for every future API.
- Authentication, policy evaluation, and secret loading fail closed.

## Cloudflare spending boundary

Infrastructure spend is forbidden. Domain-registration renewals are separate
and allowed. Budget alerts are delayed secondary detection, never enforcement.
If entitlement, price, trial behavior, or plan state is unknown, the change is
blocked. See `infrastructure/cloudflare/policy/` and the billing incident runbook.
Cacheability, cache BYPASS, Range support, or an origin load test never proves
that a large-media traffic pattern is contractually authorized.

## Secret handling

See [secret classification](docs/security/secret-classification.md). Do not ask
a user to paste secret values into an issue, PR, terminal transcript, CI log, or
chat. A suspected exposure is treated as compromise and rotated from a trusted
workstation.
