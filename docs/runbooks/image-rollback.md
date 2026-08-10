# Website image promotion and rollback — Draft / unverified

Promotion consumes the stable version and multi-architecture digest emitted by
the selected site's protected-main CI. Run `scripts/promote-image.sh
<naranjo-online|lidersea-com> vMAJOR.MINOR.PATCH sha256:<digest>`; the closed
site mapping resolves that version tag to the supplied digest both before and
after exact keyless workflow identity/provenance verification, checks both
platform configs for the requested version and one full Git revision, creates
an ignored candidate and hash-bound review patch for only that site's
authoritative Flux HelmRelease digest/readiness override, requires both its
HelmRelease and parent Kustomization to be suspended, and leaves the worktree
unchanged. Review the printed candidate directory and `evidence.env`, run
`git apply --check` on `promotion.patch`, apply it explicitly, and rerun the
repository and transition gates before opening a PR. The script never stages,
commits, pushes, deploys, or overwrites a concurrent editor. The version is
evidence and navigation; Kubernetes still receives only the digest. The
transaction directory is mode-restricted on POSIX; Git Bash/NTFS inherits the
operator's ACL. No plaintext credential is written, but a configured tunnel
Secret is copied as repository-tracked SOPS ciphertext, so protect retained
artifacts like the checkout. Immediately before applying, verify that
`REVIEWED_HEAD` still
equals `git rev-parse HEAD`, that `ORIGINAL_RELEASE_SHA256` still equals the
selected live release file, and that `PATCH_SHA256` still equals
`promotion.patch`; stop on any mismatch.

For rollback, select a retained version/digest pair that is strictly older than
the site's tracked current `VERSION` and whose mapping, signature,
provenance, SBOM, scan, amd64/arm64 manifests, and prior runtime health remain
accepted. Freeze reconciliation in two reviewed, observed changes. First set
only the site's HelmRelease to `suspend: true` while its parent Kustomization
remains active, merge, and verify that Flux has observed the suspended inner
release. Then set the parent Kustomization to `suspend: true`, merge, and verify
that outer suspension. Setting both gates in one commit is unsafe because Flux
may suspend the parent before it applies the nested HelmRelease change. Do not
weaken or remove the site's enforced signature admission or reviewed capacity
while the parent remains active: CI deliberately retains that production safety
envelope until the outer suspension is both merged and observed. Do not treat a
runtime CLI-only suspension as durable desired state. From a clean
feature branch based on that fully frozen state, run `scripts/promote-image.sh
<naranjo-online|lidersea-com> vMAJOR.MINOR.PATCH sha256:<digest> --rollback`.
Rollback mode requires the already-promoted `deploymentReady: true` state and a
nonzero current digest, rejects the current or any newer tag, verifies the
retained release exactly as promotion does, and its patch changes only the
digest while preserving both suspension gates. Apply and review that patch,
then merge that reviewed digest-only PR, re-run the release and runtime checks,
and resume in two more reviewed, observed changes: activate the parent first and prove the
new digest remains suspended, then activate the HelmRelease. The parent-first
resume commit must restore and retain the same signature/capacity envelope
before Flux can reconcile the site path. Never put the tag in Helm values, move
an old tag,
direct-push main, use `kubectl set image`, or use an unsigned emergency build.
If the prior image is now vulnerable or compromised, roll forward to a repaired
digest under a new version instead.

While one promoted site remains suspended, CI classifies the repository as a
safe `transition` and runs `scripts/render-kubernetes.sh --transition`. That
credential-free path renders the exact authoritative HelmRelease values,
including the staged digest, then applies schema, exposure, and release-policy
checks without contacting a registry, cluster, Flux, or the Pi. It is static
pre-resume proof, not runtime evidence. The single-site Kind runtime rehearsal
retired with the embedded site sources: `scripts/release-gate.sh
--transition-runtime` now fails closed PENDING its post-cutover successor, so
until that successor lands, a rollback's runtime confidence comes from the
rollback digest having already served traffic (choose only previously proven
digests) plus the site repository's own release evidence. Never substitute a production
reconciliation or an ad hoc `kubectl` deployment for this evidence.
