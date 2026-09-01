# Site sync branch flip — decoupling ceremony (issue #275)

Owner-attended live ceremony that moves the `flux-system` GitRepository from
the selector-advanced platform tag to protected `main`, retiring the
platform-release-selector's runtime role. Ordered by the owner's 2026-09-01
decoupling ruling: application delivery is never gated behind platform
versioning. Until this ceremony runs, merging the reviewed-model change is
inert — the live cluster keeps the previous tag-driven behavior untouched.

Authority: the repository owner, at the cluster, or the Daybreak validation
lane operating under its cluster-validation grant with the owner watching.
Nothing here is CI-driven and no agent executes it unattended.

## Preconditions

- The pull request that moved `kubernetes/flux-system/gotk-sync.yaml.in` and
  `EXPECTED_FLUX_SYNC` to `ref.branch: main` is merged, and `main` CI is
  green at that merge.
- The trust anchor is receipted: protected `main`'s ruleset currently has NO
  bypass actors, confirmed read-only at ceremony time —
  `gh api repos/snaraj/website-infrastructure/rulesets --jq
  '.[] | select(.target=="branch") | {name, enforcement}'` plus the ruleset's
  `bypass_actors` read returning empty. The branch-tracking model is only as
  strong as that ruleset, so an inexact receipt stops the ceremony exactly
  as an inexact release-control receipt stops a Ready flip.
- Both site Kustomizations report `Ready=True` and both sites answer 200 on
  `/readyz` (do not flip a broken cluster; fix first).

## Ceremony

State capture comes AFTER suspension and drain on purpose: suspending a
CronJob stops future schedules but not Jobs already running, and a live
selector Job could advance the tag after a premature capture — the flip's
own compare-and-swap would still be safe, but a rollback would then restore
a stale tag.

1. Suspend the selector so no new advance can start (its compare-and-swap
   assumes a tag ref and would fail red every tick after the flip anyway):
   `kubectl patch cronjob -n flux-system platform-release-selector
   --type=merge -p '{"spec":{"suspend":true}}'`
2. Drain: wait until the selector owns zero Jobs and zero Pods — the same
   quiescence its own rotation procedure requires:
   `kubectl get jobs,pods -n flux-system
   -l app.kubernetes.io/name=platform-release-selector` returns nothing.
3. Record the exact rollback state, now that nothing can move it:
   `kubectl get gitrepository -n flux-system flux-system -o json |
   tee flip-prestate.json` — keep `spec.ref.tag`, all nine
   `release-selector.platform.snaraj.dev/*` annotations, `metadata.uid`,
   and `metadata.resourceVersion`.
4. Flip the source ref (one operation; the admission policy that bounds the
   selector ServiceAccount does not match an owner/admin principal):
   `kubectl patch gitrepository -n flux-system flux-system --type=json
   -p '[{"op":"remove","path":"/spec/ref/tag"},
        {"op":"add","path":"/spec/ref/branch","value":"main"}]'`
5. Leave the `release-selector.platform.snaraj.dev/*` evidence annotations
   exactly as they stand: the suspended selector's `ValidateCurrent`
   requires all nine to reactivate on rollback, and their removal belongs
   to the selector's platform-lane decommission — not to this ceremony.
6. Force a reconcile rather than waiting an interval:
   `flux reconcile source git flux-system -n flux-system` then
   `flux reconcile kustomization naranjo-online-reconciler -n flux-system`
   and the lidersea twin.

## Verification (all three, not any one)

- `kubectl get gitrepository -n flux-system flux-system -o
  jsonpath='{.status.artifact.revision}'` reports `main@sha1:<current WI main
  head>`.
- Both site Kustomizations reconcile `Ready=True` at that revision and the
  site OCIRepositories still hold their exact reviewed digests (the flip
  changes WHERE desired state is read from, never WHICH chart is selected).
- Outside-in, executable with no cluster access (the probe that proved the
  `0.1.66` deploy on 2026-08-31): for each site, take the live page's
  fingerprinted bundle name (`curl -s https://<site>/ | grep -o
  'assets/index-[A-Za-z0-9_-]*\.css'`), then resolve the committed
  selection's bytes anonymously from ghcr — chart manifest at the
  `source.yaml` digest → sole Helm layer → `values.yaml` image digest →
  arm64 child manifest → largest layer blob — and require the live bundle
  name to appear inside that exact layer (`gzcat layer.tgz | grep -a -c
  '<bundle name>'` ≥ 1). Both sites answer 200 on `/readyz`. Record the
  bundle names and digests beside `flip-prestate.json` as the ceremony
  receipt.

## Rollback

Reverse order, and the ref move MUST be the same JSON-patch style as the
flip — a merge patch would leave `branch` and `tag` set together on the one
ref, which is not the prior state and not a valid selector:

1. `kubectl patch gitrepository -n flux-system flux-system --type=json
   -p '[{"op":"remove","path":"/spec/ref/branch"},
        {"op":"add","path":"/spec/ref/tag","value":"<recorded tag>"}]'`
   with the recorded tag from `flip-prestate.json`, then diff the live
   object's `spec.ref` and annotations against that capture — byte-equal
   or stop.
2. Resume the CronJob: `kubectl patch cronjob -n flux-system
   platform-release-selector --type=merge -p '{"spec":{"suspend":false}}'`
   (its nine evidence annotations were never touched, so its
   compare-and-swap and `ValidateCurrent` resume from exactly the state
   they last recorded).
3. `flux reconcile source git flux-system -n flux-system` and confirm
   `status.artifact.revision` names the recorded tag again.

The reviewed-model change in git stays merged either way; rolling the model
itself back is an ordinary reviewed pull request.

## After the flip

- A merged site promotion (exact-digest `source.yaml` change) now deploys on
  the next reconcile (≤1m source interval + ≤10m Kustomization interval)
  with no platform release involved.
- Platform releases continue to publish on WI merges as the platform's own
  versioned audit artifact; nothing consumes them for site delivery.
- The selector CronJob stays suspended pending its platform-lane
  decommission; its repo-side contracts and bootstrap recovery model are
  re-aimed in a follow-up. The bootstrap recovery path still renders the
  TAG model, and its strict decoders admit only a tag ref — a branch ref
  is refused, not misread — so a full recovery deliberately restores the
  tag-driven state and this ceremony then re-applies on top.
