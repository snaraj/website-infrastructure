# Site sync branch flip — decoupling ceremony (issue #270)

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
- Both site Kustomizations report `Ready=True` and both sites answer 200 on
  `/readyz` (do not flip a broken cluster; fix first).
- The current GitRepository tag and its target platform release are recorded
  for rollback: `kubectl get gitrepository -n flux-system flux-system -o
  jsonpath='{.spec.ref.tag}'`.

## Ceremony

1. Suspend the selector so it cannot race the flip (its compare-and-swap
   assumes a tag ref and would fail red every tick afterward):
   `kubectl patch cronjob -n flux-system platform-release-selector
   --type=merge -p '{"spec":{"suspend":true}}'`
2. Flip the source ref (one operation; the admission policy that bounds the
   selector ServiceAccount does not match an owner/admin principal):
   `kubectl patch gitrepository -n flux-system flux-system --type=json
   -p '[{"op":"remove","path":"/spec/ref/tag"},
        {"op":"add","path":"/spec/ref/branch","value":"main"}]'`
3. Optional hygiene: clear the inert `release-selector.platform.snaraj.dev/*`
   evidence annotations from the GitRepository; they described tag advances
   that no longer happen.
4. Force a reconcile rather than waiting an interval:
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
- Outside-in: both sites answer 200 on `/readyz` and serve the bundle their
  committed selection names.

## Rollback

Reverse order: restore `spec.ref` to `{"tag":"<recorded tag>"}`, resume the
CronJob (`suspend:false`), and `flux reconcile source git flux-system`. The
reviewed-model change in git stays merged either way; rolling the model
itself back is an ordinary reviewed pull request.

## After the flip

- A merged site promotion (exact-digest `source.yaml` change) now deploys on
  the next reconcile (≤1m source interval + ≤10m Kustomization interval)
  with no platform release involved.
- Platform releases continue to publish on WI merges as the platform's own
  versioned audit artifact; nothing consumes them for site delivery.
- The selector CronJob stays suspended pending its platform-lane
  decommission; its repo-side contracts and bootstrap recovery model are
  re-aimed in a follow-up (the recovery path still renders the tag model
  and, if ever exercised, this ceremony re-applies on top).
