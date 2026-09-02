# Declared workload registry

`policies/workload-registry.json` is the sole hand-maintained inventory for
promotable workloads. Release versions and digests are deliberately absent:
they remain evidence produced by the existing acquisition ceremony, while the
registry owns the static identity and deployment tuple reviewers previously
had to reconcile in six places.

## Schema and bounds

The canonical UTF-8 JSON document has one terminal LF, sorted keys and
workloads, duplicate-key rejection, a 64 KiB ceiling, and at most 24 entries.
Each entry declares `slug`, `namespace`, `sourceRepository`, exact
`publisher.workflowRef` at protected `main`, `publisher.oidcIssuer`,
`chartRepository`, `workloadRepository`, `acquisitionProfile`, sorted platform
and target-cluster sets, and a deploy object. Deploy shapes are `site`,
`internal-service`, and `cluster-infrastructure`; only `site` admits a public
domain. Arrays make another architecture or cluster a data change rather than
a registry-schema change, but declaring one does not create or target absent
runtime infrastructure.

All fields are bounded and closed. The registry does not accept caller-chosen
reconciler names or paths: a workload owns its non-reserved slug namespace,
derived `<slug>-reconciler`, and one shape-specific root under
`kubernetes/{websites,services,infrastructure}/<slug>`; paths are unique and
may not overlap. Thus a declaration cannot repoint generated reconciliation or
source-ignore rules at `flux-system`, `cloudflare-public`, or another workload.
Every declared namespace is also pinned to its own slug-named workload service
account; non-site shapes cannot fall through an undefined site-only map.
Today both entries declare only `linux/arm64` and cluster `pie5`. The existing
receipt-v2 `arm64Digest` spelling is preserved byte for byte for that legacy
singleton; the acquisition code can
already produce a keyed `platformDigests` map for a future multi-platform
declaration. No current tag, version, digest, receipt byte, credential, or live
selection changes in this migration.

The platform list is the deployment/acquisition target closure, not a claim
that an upstream signed OCI index contains no other builds or
`unknown/unknown` attestation descriptors. Acquisition requires exactly one
child for every declared platform, and only that exact declared key set enters
the receipt; an undeclared descriptor is never selected or treated as evidence
for a target cluster.

## Derived bindings

- Registry to manifests: `scripts/workload_registry.py` walks every annotated
  `OCIRepository` below `kubernetes/` without following links. The two sets and
  each namespace, path, chart repository, publisher subject, and issuer must be
  exactly equal.
- Registry to receipt and release identity:
  `_site_identities_from_receipt` reads both files from the same immutable Git
  tree, requires record-set equality, and validates every static repository,
  signer, workload image, and declared-platform digest against its entry. The
  registry's immutable first-parent introduction derives one migration
  ceiling: only its parent or an ancestor may use the receipt-derived legacy
  closure. This admits unrelated protected-main commits queued before the
  registry lands without creating a movable exception. A missing registry on
  any descendant is a downgrade and refuses rather than reopening the bridge.
- Registry to Rego and source boundaries: `kubernetes.rego` contains one generated projection.
  `validate_repository.py kubernetes` renders it from the registry plus current
  manifests and compares the marked block byte for byte. Policy sets and maps
  are comprehensions over that projection; every declared shape gets the exact
  OCI/chart-source controls while public network and readiness controls remain
  site-only. The Flux sync fixture and root `.sourceignore` are rendered from
  the same non-overlapping deploy paths. Promotion regenerates the Rego block
  after a selector moves.
- Registry to validator and tests: signature repositories, subjects, chart
  URLs/releases, the image-release site inventory, the Flux sync fixture,
  release-contract tuples, and expected receipt identities are derived. The
  former `ACQUISITION_EXTRAS` and literal site-set assertions are gone.
- Registry to promoter: discovery first proves the complete manifest closure.
  `Selection` then carries the declared profile, repositories, platforms,
  deploy shape, and targets. Unknown profiles and a missing or duplicate child
  for any declared platform refuse before a write; all prior double-resolution,
  digest-bound blob, Cosign, SLSA v1, immutable Release-asset, annotated-tag,
  and protected-main ancestry checks remain unchanged.

Each binding has a one-sided mutation test. The registry itself also refuses
wildcard publishers, duplicate keys, platforms or site domains, foreign
fields, noncanonical bytes, entry 25, receipt-v2 inspection-label collisions,
and any file above its byte limit.

## Capacity and gates

A maximum-shape 24-entry registry is 52,727 bytes and its complete canonical
platform-release identity is 43,680 bytes, below the 65,536-byte asset limit.
Entry 25 is rejected by the registry parser. An oversized registry or identity
is refused; neither path truncates.

The promoter hashes the canonical complete target map into its branch identity
and uses a bounded hashed fragment/title form when the readable form would be
too long. Even 24 maximum-length slugs and versions therefore stay below the
240-byte component bound instead of failing at Git or filesystem name limits.

The trust root is covered by `/policies/ @snaraj` in CODEOWNERS. The required
`repository-and-infrastructure` job runs `validate_repository.py all`, including
the manifest and generated-Rego closure, and scans immutable pull-request
history. `pre-push-security` runs the same repository validation and scans every
outgoing commit before publication.

## Intentional literals and non-goals

The generated Rego projection is a checked derivative, not a second hand
inventory. Receipt records and the independently pinned layer-inspection hash
oracle retain acquisition evidence because those values must come from
verification, not declaration. Remaining literal site sets are separate
authorization or evidence boundaries:

- `policies/release-conftest/`, `validate_release_state.py`,
  `release-gate.sh`, and `render-manifests.sh` describe current live and
  transition topology, not every promotable declaration.
- Cloudflare, edge/exposure, RBAC, capacity, and the naranjo-only PVC controls
  encode concrete network or least-privilege decisions; a registry edit must
  not widen them automatically. In particular, Rego's
  `connector_deployments` remains the explicit ADR 0015 tunnel-token allowlist.
- Bootstrap/selector files remain Codex-owned, while hostile fixtures and
  historical-publication paths keep literal identities as attack cases or
  immutable history rather than inventory.

The deployed Go selector and its bootstrap-owned v1 JSON schema still admit
the two current site identities. That separate runtime boundary is intentionally
not widened by a declaration-only change; `bootstrap/` belongs to Codex and a
future workload activation must update and review that selector boundary before
targeting it. This work adds no workload, cluster, route, secret, hosted
promoter, promotion, or convergence claim.
