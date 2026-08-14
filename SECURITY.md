# Security policy

## Reporting

Do not open a public issue containing a credential, home address, account ID,
zone ID, tunnel ID, private hostname, kubeconfig, infrastructure plan, or
vulnerability detail. Revoke or isolate exposed material first and preserve
minimal evidence. GitHub Private Vulnerability Reporting is currently disabled
for this repository, so the repository does not presently claim a working
private intake. A detail-free public issue may ask the repository owner to
enable the Security-tab reporting form, but withhold all sensitive details
until the authoritative
`repos/snaraj/website-infrastructure/private-vulnerability-reporting` GET and
the closed GitHub-controls readiness receipt both report `enabled: true`.

Once that owner-applied setting is authoritatively enabled, use Security tab →
"Report a vulnerability"; never paste the report into the enabling issue.
Reports are acknowledged on a best-effort basis, normally within 7 days; this
is a single-operator project with no paid program and no bounty. Please allow
up to 90 days for remediation before any public disclosure, and never test
against the live host, tunnels, or domains — every validator in this repository
runs credential-free against fixtures, so findings are demonstrable offline.

## Supported versions

Only the current tip of `main` is supported. After the repository owner's
immutable-release and protected-main readiness receipt passes, every merge has
an immutable plain `vX.Y.Z` platform-source release, but there are no maintained
release branches; a finding fixed on `main` is fixed everywhere. A source
release is not a deployment or promotion. Per-site production graduation state
lives in [`release-policy.env`](release-policy.env) (both sites are
pre-graduation while it reads `GRADUATED=no`).

## Production authority

Write access to protected `main` is deployment authority because Flux consumes
it. GitHub-hosted CI has no cluster, SSH, Cloudflare apply, age, Kubernetes PKI,
or bootstrap secrets.
Cloudflare and cluster mutations are manual, local, exit-gated operations.

## Required controls

- MFA/passkeys on Cloudflare and GitHub; minimal administrator membership.
- SSH keys only, no root or password authentication, applied only after a tested
  second session and physical/LAN recovery path exist.
- SSH-only admin plane (PLAT-DEC-001): the admin VPN reaches host SSH and
  nothing else; 2379/2380/6443/10250 are terminally denied from that path by
  the fail-closed host-ingress guard (`make check-ingress-guard` verifies the
  tracked artifacts).
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
blocked. See `infrastructure/cloudflare/policy/` and
[the billing incident runbook](docs/runbooks/unexpected-cloudflare-billing.md).
Cacheability, cache BYPASS, Range support, or an origin load test never proves
that a large-media traffic pattern is contractually authorized.

## Secret handling

See [secret classification](docs/security/secret-classification.md). Do not ask
a user to paste secret values into an issue, PR, terminal transcript, CI log, or
chat. A suspected exposure is treated as compromise and rotated from a trusted
workstation.
