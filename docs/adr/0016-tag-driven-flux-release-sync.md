# ADR 0016: Tag-driven Flux release sync

- Status: Accepted
- Date: 2026-08-12

## Context

Two things about releases were true at once and could not both stay true.

The owner names releases with version tags — `v0.1.9` is what appears in
release notes, in an incident conversation, and in a rollback decision. But the
identity the cluster actually consumed was a raw content address: each site's
`HelmRelease` resolved its chart from a `GitRepository` tracking that site's
`main` branch, and the running image came from an `sha256` digest pinned by hand
into `kubernetes/websites/<site>/release.yaml` by `scripts/promote-image.sh`.

That produced three concrete problems:

1. **The official release identity was not the release name.** The chart the
   cluster ran was whatever `main` happened to point at, which is a moving
   commit, not a release. Nothing in desired state named `v0.1.9`.
2. **Publishing a release did nothing.** A tagged, signed, scanned release could
   sit in GHCR indefinitely; reaching the cluster required a human to run the
   promotion verifier and land a reviewed digest edit. GitOps described the
   desired state but did not follow the releases.
3. **The chart leg was unverified.** Images were verified twice over — cosign
   keyless signature, embedded SLSA provenance, Kyverno admission — but the
   chart arrived over anonymous Git with no signature check at all. The
   strongest link in the chain was guarding the wrong door.

The obvious fix — Flux image automation writing new digests back to Git — is
refused: it requires giving the cluster a Git write credential, which safety
invariant 5 and ADR 0003 forbid outright.

## Decision

**The official release identity is the version tag**, and the cluster follows
published releases automatically, without the cluster ever holding a credential
that can write to a repository.

### 1. The chart version IS the release

Each site's release publisher pushes a Helm chart to
`oci://ghcr.io/snaraj/charts/<site>` at the same `vMAJOR.MINOR.PATCH` version as
the image it built, signed by the same keyless workflow identity. The platform
tracks that chart repository with a bounded SemVer range, so publishing a
release is what deploys it. `kubernetes/websites/<site>/source.yaml` is now an
`OCIRepository` (`source.toolkit.fluxcd.io/v1`), and the site's `HelmRelease`
(`helm.toolkit.fluxcd.io/v2`) consumes it through `chartRef` rather than an
inline `chart` block. No site `GitRepository` remains; the connector chart,
which lives in this repository and has no release identity of its own, keeps
its Git source.

### 2. Digest integrity survives inside the chart

Tag-driven does not mean tag-trusted. The digest-only deploy invariant (safety
invariant 6) is preserved on both legs:

- **Publish time.** Each site's publisher embeds the exact image digest it just
  built, signed, and scanned into the chart it publishes under that version. The
  workload therefore still names `repository@sha256:...`, and the chart version
  and the image digest are produced by one run of one workflow and can never
  drift apart.
- **Reconcile time.** `spec.verify` is mandatory on every site chart source:
  `provider: cosign` with a single `matchOIDCIdentity` entry anchored to that
  site's exact publisher — `https://github.com/snaraj/<site-repo>/.github/
  workflows/release-publisher.yml@refs/tags/v*`, issuer
  `https://token.actions.githubusercontent.com`. source-controller refuses to
  produce an artifact from a chart that is unsigned, signed by the sibling
  site, signed by a different workflow in the same repository, signed under a
  branch ref, or signed under a different issuer. Flux then records the
  resolved artifact as `<tag>@<digest>`, so what ran is content-addressed even
  though a tag selected it.
- **Admission time.** The existing `require-signed-<site>` Kyverno policies are
  unchanged and still verify the image signature and SLSA provenance against
  the identical identity tuple. A chart and the image it names can never be
  accepted from different authorities.

The two site tuples never couple. Chart repository, SemVer range, certificate
subject, image repository, namespace, release name, and reconciler identity are
per site, and the shared validators compare each against its own tuple only
(safety invariant 14).

### 3. The SemVer range is a policy, not a convenience

`>=0.1.9 <1.0.0` for both sites today. Both bounds are load-bearing:

- The **lower bound is a ratchet**: it denies resolution to any release older
  than the last reviewed one. A deleted or administratively re-pointed newer
  tag cannot silently roll a site backwards, and a downgrade is a reviewed PR,
  not an accident. It moves forward only by review; it never moves down.
- The **upper bound is ADR 0014's production-graduation gate expressed as a
  Flux policy.** While a site's `release-policy.env` gate reads `no`, its range
  must exclude major 1 and later. `validate_repository.py` re-derives that
  binding from the tracked gate on every run, so the range and the gate cannot
  disagree silently.

`ref.tag` and `ref.digest` are forbidden on these sources: a fixed tag freezes
the site off the release train, and a mutable name would let the registry
decide what runs.

### 4. No git write-back, ever

Flux image-automation controllers (`image-reflector-controller`,
`image-automation-controller`) are NOT installed and are not part of this
design. The cluster holds no Git credential and no registry credential: chart
pulls are anonymous, `secretRef`, `serviceAccountName`, `certSecretRef`,
`proxySecretRef`, `insecure`, and non-`generic` provider are all denied on site
chart sources by policy. Automation flows one way — the publisher signs, the
cluster verifies and pulls. If a future need appears to make the cluster write
to a repository, it is an owner decision and a new ADR, not an implementation
detail.

### 5. Fail-closed transition plan

Nothing in this ADR activates anything. Every gate that was closed stays
closed, and each step below is separately authorized:

| # | Step | Repository | Authorized by |
| --- | --- | --- | --- |
| 0 | Desired state moves to tag-driven chart sync; `suspend: true` everywhere; the platform's readiness/digest gate retained at its reviewed value | this repository | reviewed PR (this change) |
| 1 | Site publishers embed the built image digest into the published chart | site repositories | reviewed PR per site |
| 2 | Flux controllers installed on the cluster; `flux-system` egress to GHCR/GitHub opened inside the default-deny posture | platform lane | platform-stable signal, then owner |
| 3 | `spec.suspend` flipped to `false` on the parent `Kustomization` and the `HelmRelease` | this repository | reviewed PR, after step 2 |
| 4 | `values.deploymentReady` / `values.image.digest` sentinel removed from the platform once the chart carries the digest | this repository | reviewed PR, after step 1 |
| 5 | `promote-image.sh` demoted to a rollback/emergency-pin tool | this repository | reviewed PR, after step 4 |

The order matters and is not negotiable: the digest must exist inside the chart
(step 1) before the platform's own digest override may be removed (step 4), so
there is never a moment when no artifact carries the digest.

Until step 4, `spec.values.deploymentReady` and `spec.values.image.digest`
remain in each site's `release.yaml` exactly as before, keeping exactly the
meaning they already had. Readiness shut over the all-zeros `sha256:000...0`
digest is the state `validate_release_state.py` classifies as `initial` and
`policies/release-conftest` rejects; a reviewed digest with readiness open is
the `promoted` state `promote-image.sh` advances into under review, which is
where both sites stand for `v0.1.9`. Neither phase reconciles anything while
`spec.suspend` is `true` on both layers, which step 3 alone changes. This ADR
deletes no fail-closed guard: it adds the
chart-source contract beside the existing sentinel and re-points every
validator that described the old chart binding to the new one, with negative
coverage that is equal or stronger at each re-point.

### 6. The promotion path's future role

`scripts/promote-image.sh` and the `release.yaml` digest pin remain fully
operative and are unchanged by this ADR. They stay the mechanism for the
in-flight `v0.1.9` deployment. Afterwards their role narrows, deliberately
rather than by neglect:

- **Rollback and emergency pin.** When a published release must be overridden
  out of band — a bad release, a compromised tag, an incident — an operator
  verifies a specific historical digest and lands a reviewed override. That is
  a slower, louder, reviewed path than the sync loop, which is exactly right
  for the case where the sync loop is what you distrust.
- **Not the routine deployment path.** Routine releases flow through the
  publisher and the SemVer range. A digest edit stops being ordinary traffic
  and becomes a signal that something is wrong.

The registry-side immutability caveats recorded in ADR 0014 still apply and are
what the reconcile-time signature verification and the artifact digest defend
against.

### 7. Release notes

Site release notes lead with the version tag as the release identity and carry
the image digest as supporting metadata, matching what desired state now means.
This is recorded here so the cross-repository change is reviewable as one
decision; it is implemented in the site repositories.

## Relationship to prior decisions

- **ADR 0003 (Flux pull-based reconciliation)** is extended, not superseded.
  Its rules stand — no Git credential, no write capability, least-privilege
  reconcilers, cross-namespace references and remote bases disabled. It
  excluded image automation; this ADR keeps that exclusion and states why
  tag-driven sync does not need it. The controller set it names
  (source/kustomize/helm) is unchanged: `OCIRepository` is a source-controller
  kind already present in the pinned Flux export.
- **ADR 0014 (Immutable container release versioning)** is extended, not
  superseded. Its versioning, tag-immutability, and promotion rules remain
  authoritative. This ADR changes which of its outputs desired state consumes:
  the version tag becomes the deployment identity instead of an operator index,
  while the digest it binds remains the only thing that ever runs. Its
  production-graduation gate gains a second enforcement point in the SemVer
  range. The promotion command shape it documents is unchanged; only its role
  narrows, per section 6.
- **ADR 0010 (Go/Svelte/Helm)** is unaffected: the chart contents and their
  fail-closed defaults remain the site repositories' business.

## Consequences

**Gained.** Publishing a release deploys it. The name the owner uses is the
name desired state carries. The chart leg gains signature verification bound to
the same identity as the image leg. A downgrade, an unsigned chart, a
wrong-identity chart, and an ungraduated major are each denied by a specific,
tested rule rather than by nobody having tried.

**Given up.** A release now reaches the cluster without a per-release human
edit. That is the point, and it moves the review boundary: what is reviewed is
the publisher, the signing identity, and the range — not each deployment. The
compensating controls are the mandatory cosign verification, the ratchet floor,
the graduation ceiling, the unchanged Kyverno image admission, and the fact
that everything stays suspended until an owner-authorized PR says otherwise.

**Costs.** A published chart is a new artifact class the site repositories must
keep signed and correct. A site can no longer be deployed from a branch, by
design. The `flux-system` namespace needs egress to GHCR within the default-deny
posture, which is platform-lane work and a prerequisite for step 2.

**Not proven here.** No Flux controller runs in this repository's CI. The tests
that accompany this decision model the sync contract and pin the manifests'
semantics; they do not observe source-controller resolving a range or verifying
a signature. That distinction is stated in the tests themselves and is why
steps 2 and 3 above are separate, separately authorized events.

References:

- <https://fluxcd.io/flux/components/source/ocirepositories/>
- <https://fluxcd.io/flux/components/helm/helmreleases/>
- <https://fluxcd.io/flux/cheatsheets/oci-artifacts/>
- <https://helm.sh/docs/topics/registries/>

## Amendment (2026-08-22): the publisher's certificate ref

The decision stands unchanged. One factual detail inside it was overtaken by a
change in the site repositories, and this amendment records both the correction
and why the original text was right when it was written.

**What this amendment changes.** Everywhere this ADR binds the site publishers'
keyless certificate identity, the ref is
`…/release-publisher.yml@refs/heads/main`, not `…@refs/tags/v*`. Concretely:

- In §2 "Reconcile time", the `matchOIDCIdentity` subject is
  `https://github.com/snaraj/<site-repo>/.github/workflows/release-publisher.yml@refs/heads/main`,
  and the list of cases source-controller must refuse reads *signed under a tag
  ref or any other branch* where it previously read "signed under a branch ref".
  Every other refusal in that list — unsigned, sibling site, different workflow
  in the same repository, different issuer — is unchanged.
- In §2 "Admission time", the `require-signed-<site>` Kyverno policies bind the
  same amended tuple, so a chart and the image it names still cannot be
  described by this repository as coming from different authorities. See the
  correction below for what those policies do and do not enforce today.
- In §6, `scripts/promote-image.sh` verifies against the same amended identity.
  That leg was not merely stale but broken: every site image published after
  `v0.1.9` is branch-signed, so the previous per-tag identity could not verify
  any image the rollback/emergency-pin path would need today.

**Correction: Kyverno is not a live second line of defence.** §2 "Admission
time" and the "Consequences" section describe the `require-signed-<site>`
policies as an unchanged, operating control. That is not true of runtime state
and must not be read as if it were. Confirmed with the platform lane on
2026-08-22: Kyverno is **not installed** on the cluster — zero CRDs — and is
**not authorized to be installed**; the runbook locks out both the report-only
and the enforcing stage pending issues #100, #101 and #102, and the committed
controller sentinel is not an installable release. The answer recorded was
"NO-GO, not eventually-yes."

So today those two files are **CI assertions and future desired state**, not an
active admission control. They are kept exactly in step with the chart-source
identity anyway, because CI evaluates them and checks their parity against the
Conftest corpus, so an obsolete identity there would be a false assertion this
repository makes about itself. Kyverno becomes a genuine second runtime line
only after a separately reviewed, owner-authorized, evidenced install.

What that means for this amendment: the **live** defences on the chart leg
today are Flux's own `spec.verify` source verification and the publisher-side
controls in the site repositories. There is no compensating admission control
behind them. That is precisely why the ref this identity names has to be the
one an attacker cannot rewrite.

**What this amendment does NOT change.** The version tag is still the official
release identity and still what the SemVer range selects — the chart *version*
and the publisher's *signing ref* are two different things, and only the second
one moved. Digest integrity on both legs, the ratchet floor, the graduation
ceiling, the no-git-write-back rule, and the ordered transition table all stand
exactly as written. Steps 3 and 4 remain separately authorized and are not
performed by the change that carries this amendment.

**What it costs, measured rather than asserted.** The re-point is not free on
the image leg, and the cost lands on exactly one release. Verified against GHCR
on 2026-08-22:

| artifact | verifies under tag ref | verifies under `@refs/heads/main` |
| --- | --- | --- |
| every published site CHART (naranjo 0.1.19–0.1.28, lidersea 0.1.18–0.1.25) | no | **yes** |
| site IMAGES from v0.1.10 onward | no | **yes** |
| site IMAGES at `v0.1.9` — the ones `kubernetes/websites/*/release.yaml` still pins | **yes** | no |

So on the chart leg there is no trade at all: the outgoing identity could verify
*nothing* that exists, and the incoming one verifies everything. On the image
leg the trade is one version against roughly eighteen — `promote-image.sh` gains
the ability to verify every release after `v0.1.9` and loses the ability to
verify `v0.1.9` itself. That is a real operational consequence and is stated
here rather than discovered later: re-running the promotion verifier against the
currently pinned `v0.1.9` digests will now fail, and the correct response is to
promote forward, not to widen the identity to accept both refs. Accepting both
would reintroduce exactly the ungated ref this amendment exists to remove.

**Why the original text was correct.** This ADR is dated 2026-08-12. The site
publishers ran as `push` events on tag refs through `v0.1.9` on 2026-08-11, and
those runs really did mint `…/release-publisher.yml@refs/tags/v0.1.9`. The
images still pinned in `kubernetes/websites/*/release.yaml` are those `v0.1.9`
images and are genuinely tag-signed, which is why the committed manifests
looked internally consistent. The site repositories then redesigned their
publishers to `workflow_dispatch` selected from protected `main`:
naranjo.online's first such run was 2026-08-15, lidersea.com's 2026-08-18, and
neither repository has published from a tag ref since. Both now hard-assert the
new shape in reviewed code — their release contracts refuse any event other
than `workflow_dispatch` and any ref other than `refs/heads/main`. Every chart
and image published since carries the branch ref. The ADR was not wrong; it was
overtaken, and this is the record of that.

**Why the branch ref is the stronger anchor, not a weaker one.** A workflow run
at a ref executes the workflow definition *at that ref*, so the ref inside a
certificate identity names whichever control gates writes to it. Measured on
2026-08-22 in the two SITE repositories — the ones whose publishers mint these
certificates, and whose rulesets are therefore the ones that matter here.
`snaraj/naranjo.online` and `snaraj/lidersea.com` are configured identically:

| ref | protected by | includes `creation`? | bypass actors |
| --- | --- | --- | --- |
| `refs/heads/main` | `Protect-Main` branch ruleset, 10 rules: creation, deletion, non-fast-forward, linear history, pull request, code scanning, code quality, code coverage, required signatures, required status checks | yes | none |
| `refs/tags/v*.*.*` | `immutable-release-tags` tag ruleset, 3 rules: update, deletion, non-fast-forward | **no** | none |

Tags are immutable once created but freely creatable, while `main` is gated on
creation and update by a control with no bypass actors — the owner included.
Under a tag-ref identity, an actor holding only `contents: write` could push a
branch carrying a rewritten publisher, tag it inside the reviewed SemVer window,
run it there, and mint a certificate matching the committed subject. Under a
branch-ref identity the same actor is stopped at the first step, because
changing what the publisher does at `refs/heads/main` means passing the
protected-branch gate. The platform's security model is "agents may push, only
the owner merges"; the branch ref anchors the signing identity to the machine
enforcement of that rule, and a tag ref routes around it. Nothing behind it
compensates, per the Kyverno correction above.

**The accepted subject shape, stated exactly.** Exact issuer, exact
repository and workflow path, terminal `@refs/heads/main`. No `refs/heads/*`,
no `refs/tags/*`, no alternation, no substring match. The anti-widening
property this ADR's §5 promised ("negative coverage that is equal or stronger
at each re-point") is preserved rather than spent: `@refs/heads/main$` is one
fully anchored literal ref, exactly as narrow as the stable-tag pattern it
replaces. The named negative-coverage mutations were re-pointed rather than
removed, and the committed contracts still refuse tag refs, arbitrary branch
refs, `refs/heads/*` and `refs/tags/*` wildcards, foreign workflow paths,
foreign repositories, altered issuers, and every unanchored variant.

**Follow-up, deliberately not carried here.** Nothing in this repository
notices if a site publisher's identity moves again — the failure this
amendment repairs was silent for a week. A recurring check that re-verifies the
newest published chart of each site against the committed identity would close
that gap. It is kept out of this change to keep a signature-policy change
reviewable, and it carries constraints of its own: it must derive issuer and
identity from the committed policy source rather than duplicating a regex in
workflow YAML, resolve each chart to an immutable digest before verifying,
let the two sites fail independently, and land manual-dispatch-only until the
owner confirms its billing and quota effect is zero.

**Not the fix: restricting tag creation.** The obvious-looking counter-move —
add a `creation` rule to the `immutable-release-tags` tag rulesets so a tag-ref
identity becomes defensible again — was considered and is **rejected**, and this
is recorded so it is not proposed a third time. GitHub's "restrict creations"
rule means only *bypass actors* may create a matching ref. Those tag rulesets
have `bypass_actors: []`, and each site's publisher creates its own release tag
using a `contents: write` workflow token, which is not a bypass actor. Adding
the rule would therefore stop the publishers from creating release tags at all
and take releases down. It is not a smaller, safer alternative to this
amendment and must not be described as a simple next step. No ruleset or
repository setting is changed by this amendment; the tag rulesets keep the
immutability they already have.

References:

- <https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- <https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
