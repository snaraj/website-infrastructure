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

Every judgment in this ceremony is made by
`scripts/site_sync_branch_flip.py`, whose battery is
`tests/security/test_site_sync_branch_flip.py`. The command blocks below are
the CANONICAL ceremony: the battery compares them byte for byte, in order,
against `CEREMONY_BLOCKS` in the tool, admits no fence of any Markdown
form beyond these reviewed blocks, no indented or HTML code container,
and no other kubectl/python3/flux/gh invocation anywhere in this
document — so a neutralized invocation, a narrowed capture, a retargeted
patch, or a smuggled extra block is a red test, never a silent prose
drift. The operator captures live state
read-only, feeds the captures to the tool, and applies only the patches the
tool emits. Any `DENY:` exit stops the ceremony; prose never overrides the
tool. Every mutation patch leads with JSON-Patch `test` operations binding
the captured object UID and the COMPLETE captured boundary as whole-object
equality — the source's entire spec and entire annotations map, the
selector's entire spec — so a moved, replaced, or concurrently edited
object, and equally one that GAINED a key the capture never saw, refuses
the patch at the API server itself, with no window between a check and the
mutation it guards.

## Preconditions

- The pull request that moved `kubernetes/flux-system/gotk-sync.yaml.in` and
  `EXPECTED_FLUX_SYNC` to `ref.branch: main` is merged, and `main` CI is
  green at that merge.
- Both site Kustomizations report `Ready=True` and both sites answer 200 on
  `/readyz` (do not flip a broken cluster; fix first).
- A fresh private scratch directory holds every capture and receipt; the
  tool refuses any group/world-accessible custody:

```sh
scratch="$(mktemp -d)"
```

- The trust anchor is receipted against the FULL ruleset document — id,
  name, target, source, enforcement, the exact `refs/heads/main` include,
  empty bypass actors, `current_user_can_bypass: never`, and every rule
  with its complete parameters (signatures, linear history,
  creation/deletion/non-fast-forward, the pull-request controls, strict
  required checks with `do_not_enforce_on_create` and both integration
  IDs). The branch-tracking model is only as strong as this ruleset, so one
  weakened field — or a listing long enough to be a truncated page, or any
  second branch-target ruleset — stops the ceremony:

```sh
gh api 'repos/snaraj/website-infrastructure/rulesets?per_page=100' > "$scratch/rulesets.json"
gh api repos/snaraj/website-infrastructure/rulesets/20601016 > "$scratch/ruleset.json"
python3 -I -B scripts/site_sync_branch_flip.py ruleset-receipt "$scratch/rulesets.json" "$scratch/ruleset.json"
```

## Ceremony

1. Capture the selector CronJob and record its pre-ceremony state. The tool
   validates the reviewed selector identity — batch/v1, name, namespace,
   the exact schedule, `concurrencyPolicy: Forbid`, the reviewed service
   account, exactly one container running the digest-pinned selector image —
   and writes a private atomic receipt recording whether it was ALREADY
   suspended, because a rollback must never resume an object this ceremony
   did not suspend:

```sh
kubectl get cronjob -n flux-system platform-release-selector -o json > "$scratch/cronjob.json"
python3 -I -B scripts/site_sync_branch_flip.py selector-prestate "$scratch/cronjob.json" --receipt-dir "$scratch"
```

2. Suspend the selector with the emitted compare-and-swap patch (its `test`
   operations bind the captured UID and the ENTIRE captured spec, so any
   template drift since capture refuses the patch; the tool refuses to
   emit one for an already-suspended selector — investigate that state
   with the owner before continuing):

```sh
python3 -I -B scripts/site_sync_branch_flip.py suspend-patch "$scratch/selector-prestate.json" > "$scratch/suspend.json"
kubectl patch cronjob -n flux-system platform-release-selector --type=json --patch-file "$scratch/suspend.json"
```

3. Prove quiescence. Suspension stops future schedules, not Jobs already
   running, and selector Jobs carry NO labels — only their Pods do — so a
   filtered listing can report an empty drain while a live Job races the
   capture. The tool requires the live selector's COMPLETE spec to equal
   the prestate capture except for the suspension this ceremony applied
   (an execution template the ceremony did not review is refused, never
   receipted), requires every Job the CronJob's own status still names to
   be present in the supplied inventory (an incomplete capture is
   refused, not trusted), and matches ownership by UID lineage and
   terminal state over the FULL namespace inventories:

```sh
kubectl get cronjob -n flux-system platform-release-selector -o json > "$scratch/cronjob-now.json"
kubectl get jobs -n flux-system -o json > "$scratch/jobs.json"
kubectl get pods -n flux-system -o json > "$scratch/pods.json"
python3 -I -B scripts/site_sync_branch_flip.py quiescence "$scratch/cronjob-now.json" "$scratch/jobs.json" "$scratch/pods.json" "$scratch/selector-prestate.json"
```

   Re-capture and re-run until it prints its receipt; a running Job is
   waited out, never raced.

4. Record the rollback state, now that nothing can move it. The tool
   validates the CLOSED GitRepository shape — exactly the reviewed spec
   keys, the reviewed url/interval/timeout/ignore values, exactly the two
   site sparse-checkout directories, and therefore the structural absence
   of secretRef, proxySecretRef, serviceAccountName, recurseSubmodules,
   include, verify, and suspend — plus kind, name, namespace, UID, a
   `{tag}`-only ref, and all nine
   `release-selector.platform.snaraj.dev/*` annotations, then writes the
   prestate document — the full bounded spec and the ENTIRE annotations
   map, so the patches can test both whole — atomically into the private
   directory:

```sh
kubectl get gitrepository -n flux-system flux-system -o json > "$scratch/gitrepository.json"
python3 -I -B scripts/site_sync_branch_flip.py prestate "$scratch/gitrepository.json" --receipt-dir "$scratch"
```

5. Flip the source ref with the emitted compare-and-swap patch. Its `test`
   operations bind the captured UID, the entire annotations map, and the
   entire spec with the old tag — whole-object equality, so a field that
   moved after capture AND a key that appeared after capture both refuse
   the whole patch atomically (the admission policy that bounds the
   selector ServiceAccount does not match an owner/admin principal):

```sh
python3 -I -B scripts/site_sync_branch_flip.py flip-patch "$scratch/flip-prestate.json" > "$scratch/flip.json"
kubectl patch gitrepository -n flux-system flux-system --type=json --patch-file "$scratch/flip.json"
```

6. Verify the poststate — same UID, ref exactly `{branch: main}`, the
   whole spec otherwise equal to the capture with no key gained or lost
   (the flip must never bless concurrent source drift), and the entire
   annotations map equal to the capture, evidence intact. The
   annotations stay untouched on purpose: the suspended selector's
   `ValidateCurrent` requires them to reactivate on rollback, and their
   removal belongs to the selector's platform-lane decommission, not to
   this ceremony:

```sh
kubectl get gitrepository -n flux-system flux-system -o json > "$scratch/post.json"
python3 -I -B scripts/site_sync_branch_flip.py poststate "$scratch/post.json" "$scratch/flip-prestate.json"
```

7. Force a reconcile rather than waiting an interval:

```sh
flux reconcile source git flux-system -n flux-system
flux reconcile kustomization naranjo-online-reconciler -n flux-system
flux reconcile kustomization lidersea-com-reconciler -n flux-system
```

## Verification (all three, not any one)

- The source reports the branch revision:

```sh
kubectl get gitrepository -n flux-system flux-system -o jsonpath='{.status.artifact.revision}'
```

  must print `main@sha1:<current WI main head>`.

- Both site Kustomizations reconcile `Ready=True` at that revision and the
  site OCIRepositories still hold their exact reviewed digests (the flip
  changes WHERE desired state is read from, never WHICH chart is selected).
- Outside-in, with no cluster access — the executable descendant of the
  probe that proved the `0.1.66` deploy on 2026-08-31. For each site, the
  tool reads the committed `source.yaml`, requires the live page to name
  exactly one fingerprinted bundle, fetches that asset's exact BYTES from
  the live site, walks ghcr anonymously with every digest-addressed
  manifest and blob hash-verified (chart manifest → sole Helm content
  layer → `values.yaml` image digest → sole arm64 child), and requires the
  served bytes verbatim inside the committed image layers. Honest boundary:
  this proves the exact content the site serves exists in the committed
  image; no outside probe can name the digest the running workload was
  started from:

```sh
python3 -I -B scripts/site_sync_branch_flip.py verify-live kubernetes/websites/naranjo-online/source.yaml https://naranjo.online
python3 -I -B scripts/site_sync_branch_flip.py verify-live kubernetes/websites/lidersea-com/source.yaml https://lidersea.com
```

  Keep both printed receipts beside `flip-prestate.json` as the ceremony
  record.

## Rollback

Reverse order. Both patches are tool-emitted: the ref move MUST be the
emitted JSON patch — a merge patch would leave `branch` and `tag` set
together on the one ref, which is not the prior state and not a valid
selector — and the rollback verification requires the full captured spec
and annotations byte-equal, not just the ref:

```sh
python3 -I -B scripts/site_sync_branch_flip.py rollback-patch "$scratch/flip-prestate.json" > "$scratch/rollback.json"
kubectl patch gitrepository -n flux-system flux-system --type=json --patch-file "$scratch/rollback.json"
kubectl get gitrepository -n flux-system flux-system -o json > "$scratch/rolled-back.json"
python3 -I -B scripts/site_sync_branch_flip.py rollback-verify "$scratch/rolled-back.json" "$scratch/flip-prestate.json"
```

Then restore the selector to exactly its captured pre-ceremony state. The
resume patch binds the same UID and the ENTIRE captured spec (with the
ceremony's suspension), so it can never activate a template the ceremony
did not review; the tool refuses to emit one if the selector was
suspended BEFORE the ceremony
(resuming it then would activate a state this ceremony never changed — an
owner decision, not a rollback), and the final verification re-proves the
full selector identity against the capture before the source reconciles
back to the recorded tag:

```sh
python3 -I -B scripts/site_sync_branch_flip.py resume-patch "$scratch/selector-prestate.json" > "$scratch/resume.json"
kubectl patch cronjob -n flux-system platform-release-selector --type=json --patch-file "$scratch/resume.json"
kubectl get cronjob -n flux-system platform-release-selector -o json > "$scratch/cronjob-final.json"
python3 -I -B scripts/site_sync_branch_flip.py resume-verify "$scratch/cronjob-final.json" "$scratch/selector-prestate.json"
flux reconcile source git flux-system -n flux-system
```

Confirm `status.artifact.revision` names the recorded tag again (the
revision command in Verification above). The reviewed-model change in git
stays merged either way; rolling the model itself back is an ordinary
reviewed pull request.

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
