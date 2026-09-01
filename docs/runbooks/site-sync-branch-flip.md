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

Every judgment in this ceremony — the trust-anchor receipt, quiescence,
prestate custody, both mutations, both verifications — is made by
`scripts/site_sync_branch_flip.py`, whose battery is
`tests/security/test_site_sync_branch_flip.py`. The operator captures live
state with read-only `kubectl get ... -o json`, feeds the captures to the
tool, and applies only the patches the tool emits. Any `DENY:` exit stops
the ceremony; prose in this runbook never overrides the tool.

## Preconditions

- The pull request that moved `kubernetes/flux-system/gotk-sync.yaml.in` and
  `EXPECTED_FLUX_SYNC` to `ref.branch: main` is merged, and `main` CI is
  green at that merge.
- The trust anchor is receipted against the FULL ruleset document — the
  branch-tracking model is only as strong as protected `main`, so target,
  enforcement, empty bypass actors, the exact include ref, signatures,
  linear history, and the strict required checks are all compared, and one
  weakened field stops the ceremony exactly as an inexact release-control
  receipt stops a Ready flip:

      gh api repos/snaraj/website-infrastructure/rulesets > rulesets.json
      gh api repos/snaraj/website-infrastructure/rulesets/20601016 > ruleset.json
      python3 -I -B scripts/site_sync_branch_flip.py ruleset-receipt \
        rulesets.json ruleset.json

- Both site Kustomizations report `Ready=True` and both sites answer 200 on
  `/readyz` (do not flip a broken cluster; fix first).

## Ceremony

Work from a fresh private scratch directory; the tool refuses any other
custody for the rollback receipt:

    scratch="$(mktemp -d)"

1. Suspend the selector so no new advance can start (its compare-and-swap
   assumes a tag ref and would fail red every tick after the flip anyway):
   `kubectl patch cronjob -n flux-system platform-release-selector
   --type=merge -p '{"spec":{"suspend":true}}'`
2. Prove quiescence. Suspension stops future schedules, not Jobs already
   running, and selector Jobs carry NO labels — only their Pods do — so a
   label-filtered listing can report an empty drain while a live Job races
   the capture. Capture the FULL inventories and let the tool match
   ownership by UID lineage and terminal state:

       kubectl get cronjob -n flux-system platform-release-selector -o json \
         > "$scratch/cronjob.json"
       kubectl get jobs -n flux-system -o json > "$scratch/jobs.json"
       kubectl get pods -n flux-system -o json > "$scratch/pods.json"
       python3 -I -B scripts/site_sync_branch_flip.py quiescence \
         "$scratch/cronjob.json" "$scratch/jobs.json" "$scratch/pods.json"

   Re-capture and re-run until it prints its receipt; a running Job is
   waited out, never raced.
3. Record the rollback state, now that nothing can move it. The tool
   validates kind, name, namespace, UID, a `{tag}`-only ref, and all nine
   `release-selector.platform.snaraj.dev/*` annotations, then writes the
   bounded prestate document atomically (0600, no overwrite) into the
   private directory:

       kubectl get gitrepository -n flux-system flux-system -o json \
         > "$scratch/gitrepository.json"
       python3 -I -B scripts/site_sync_branch_flip.py prestate \
         "$scratch/gitrepository.json" --receipt-dir "$scratch"

4. Flip the source ref with the emitted compare-and-swap patch — its
   leading `test` operations bind the exact captured UID and tag, so a
   moved or replaced object refuses the patch instead of absorbing it (the
   admission policy that bounds the selector ServiceAccount does not match
   an owner/admin principal):

       python3 -I -B scripts/site_sync_branch_flip.py flip-patch \
         "$scratch/flip-prestate.json" > "$scratch/flip.json"
       kubectl patch gitrepository -n flux-system flux-system \
         --type=json --patch-file "$scratch/flip.json"

5. Verify the poststate — same UID, ref exactly `{branch: main}`, all nine
   evidence annotations byte-equal to the capture. The annotations stay
   untouched on purpose: the suspended selector's `ValidateCurrent`
   requires them to reactivate on rollback, and their removal belongs to
   the selector's platform-lane decommission, not to this ceremony:

       kubectl get gitrepository -n flux-system flux-system -o json \
         > "$scratch/post.json"
       python3 -I -B scripts/site_sync_branch_flip.py poststate \
         "$scratch/post.json" "$scratch/flip-prestate.json"

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
- Outside-in, with no cluster access — the executable form of the probe
  that proved the `0.1.66` deploy on 2026-08-31. For each site, the tool
  reads the committed `source.yaml`, requires the live page to name exactly
  one fingerprinted bundle, walks ghcr anonymously (chart manifest at the
  committed digest → sole Helm content layer → `values.yaml` image digest →
  sole arm64 child → hash-verified layer blobs), and requires the live
  bundle inside those exact bytes:

      python3 -I -B scripts/site_sync_branch_flip.py verify-live \
        kubernetes/websites/naranjo-online/source.yaml https://naranjo.online
      python3 -I -B scripts/site_sync_branch_flip.py verify-live \
        kubernetes/websites/lidersea-com/source.yaml https://lidersea.com

  Keep both printed receipts beside `flip-prestate.json` as the ceremony
  record.

## Rollback

Reverse order. The ref move MUST be the emitted JSON patch — a merge patch
would leave `branch` and `tag` set together on the one ref, which is not
the prior state and not a valid selector — and its `test` operations bind
the same captured UID and the flipped ref:

1.     python3 -I -B scripts/site_sync_branch_flip.py rollback-patch \
         "$scratch/flip-prestate.json" > "$scratch/rollback.json"
       kubectl patch gitrepository -n flux-system flux-system \
         --type=json --patch-file "$scratch/rollback.json"
       kubectl get gitrepository -n flux-system flux-system -o json \
         > "$scratch/rolled-back.json"
       python3 -I -B scripts/site_sync_branch_flip.py rollback-verify \
         "$scratch/rolled-back.json" "$scratch/flip-prestate.json"

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
