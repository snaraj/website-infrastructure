# Repository contract discovery

Read the target repository before changing it. The skill supplies methods, not
project identities or permission. Derive and record at least these boundaries:

| Boundary | Values to discover |
|---|---|
| Website identity | Public hostname, source/module paths, image, chart, release, namespace, Service, origin, workflow, signature subject, and promotion key |
| Runtime | Languages, framework, ports, probes, UID/GID, filesystem mode, capabilities, seccomp, resource policy, egress, and supported architectures |
| Traffic | Public and administrative entry points, route order, terminal fallback, DNS behavior, origin visibility, and fail-closed state |
| GitOps | Repository/ref/path, reconciliation identities, dependency order, suspension/readiness gates, and whether automation may write Git |
| Secrets | Encryption mechanism, stable object names/keys, decryptor identity, local-only material, and rotation/recovery procedure |
| Supply chain | Pinned tool/action versions, image digest flow, scan, SBOM, provenance, signature, verification, promotion, and rollback |
| Cost and provider | Authorized products/plans, forbidden billing paths, current entitlements/terms, account boundaries, and unknown-value behavior |
| Persistent data | Data classes, storage discovery, mount boundary, publication, capacity, backup, restore, and loss behavior |
| Privacy | Deliberate public identifiers, prohibited local/operator evidence, synthetic fixture convention, and pre-publication checks |

Apply these rules after discovery:

- Treat each website or service identity as one atomic tuple. Change every
  producer, consumer, policy, test, document, and runbook together.
- Keep origins private unless the repository explicitly authorizes another
  design. Separate public application access from administrative access.
- Preserve namespace isolation, least privilege, default-deny networking,
  non-root execution, immutable deployment references, and bounded resources.
- Let GitOps reconcile declared state; do not silently introduce CI credentials,
  Git writes, image automation, or an imperative deployment path.
- Commit only the encrypted secret format the repository explicitly designs.
  Never read, print, request, or invent a private decryption identity.
- Promote deployable images by immutable digest with repository-required scan,
  SBOM, provenance, signature/attestation, review, and rollback evidence.
- Treat unknown price, entitlement, account identity, target capacity, network
  behavior, or persistent-storage facts as unresolved and fail closed.
- Use local clusters for integration evidence only. They do not prove target
  hardware, networking, storage, reboot, load, or recovery behavior.
- Explain non-obvious invariants in contextual comments while keeping private
  operator details and workstation evidence outside the public index.

No skill, repository file, or script grants permission to authenticate, install,
plan, apply, deploy, commit, push, or modify an external host, provider, DNS zone,
registry, or source-control service.
