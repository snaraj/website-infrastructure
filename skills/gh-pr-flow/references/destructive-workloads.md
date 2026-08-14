# Destructive workload evidence

This contract grants no live action. Use it only after explicit owner
authorization identifies exact targets and a serialized live window.

## Classification is engineering, not prose

Every Kubernetes app/resource claimed ephemeral must be engineered and proven
disposable, not merely described. Admit only a closed positive allowlist of
namespaced workload controllers/resources: `apps/v1` DaemonSet, Deployment, or
ReplicaSet; `batch/v1` CronJob or Job; and `v1` Pod. Reject every cluster-scoped,
state-bearing, secret-bearing, or unknown API/kind, including ClusterRole, CRD,
Namespace, PVC, and Secret. Do not infer safety from the absence of a denylisted
kind. Every admitted resource is classified:

- **ephemeral/disposable:** all durable state is externalized and a clean recreate from zero
  is tested;
- **protected/stateful:** PV/PVC, database, operator, identity, or other state
  with declared durability, backup, restore, ownership, and recovery semantics.

Stateful resources remain supported but never inherit ephemeral deletion
permission. Replica count and disruption shape are adjustable design inputs;
never encode replica=1 as a security invariant.

## Preconditions

Bind a ledger to a closed schema with no missing or foreign fields and:

- 1–32 unique inventory entries, each exact Namespaced/ephemeral-workload
  identity (`apiVersion`, kind, namespace, name, UID) and exactly one explicit
  fault target;
- immutable desired-state and deployable-artifact SHA-256 hashes;
- prestate health/readiness/availability and externalized-state proof;
- explicit protected exclusions: Secrets and token material; SOPS/age keys and ciphertext;
  private keys, etcd and PKI; provider/DNS/domain/Tunnel identities
  and state; protected custody; Git history;
- serialized lane, expected downtime, measurable RTO, readiness and
  availability acceptance, rollback/redeploy procedure and stop conditions.

Provider connector workloads may be stopped/destroyed/redeployed with downtime
only when their API/Tunnel tokens and Kubernetes Secrets remain untouched.
Domains, DNS zones, Tunnel/provider identities/state require exact IaC
reproducibility and a separately explicit target. Public connectors also require
public HTTPS recovery proof.

## Required scenarios

An ephemeral claim is not accepted until deterministic evidence covers clean
recreate from zero plus termination, restart, node loss, and dependency loss.
Record the exact injected fault and expected availability impact. Verify
readiness/liveness, routing, identity binding, observable RTO, and user-visible
acceptance after recovery.

Make signal-triggered rollback re-entry safe. The first caught INT, TERM, or HUP
sets a cleanup guard and defers or ignores further catchable termination signals
until deterministic rollback and residue recording finish; never restore the
default signal action while cleanup is still vulnerable. Hostile tests for
repeated and mixed signals deliver repeated HUP, INT, and TERM plus a mixed
TERM/INT/HUP sequence during cleanup and prove one rollback, one bounded
receipt, and no residue within the declared RTO.
Distinguish uncatchable kill and power loss: atomically persist and fsync a mode
0600 `prepared` recovery journal before mutation so the next run can detect and
safely finish or escalate an interrupted transaction. Close the journal only
after rollback, receipt, and residue verification are durable.

## Ledger

The append-only evidence binds:

```text
prestate hash -> exact fault -> recovery action -> poststate hash
```

Include timestamps, desired-state/artifact hashes, target inventory, the exact
protected-exclusion set, the five exact scenarios, expected/observed downtime
and RTO, acceptance results, rollback status, deterministic cleanup receipt,
recovery-journal state/hash, the four exact signal cases, and residue/orphan
scan. Bind every scenario to the sole fault-target UID and the same journal and
receipt hashes. A missing/foreign field, duplicate, widened cardinality, changed
target/hash, secret overlap, orphan, failed recovery, or unproven externalized
state is a hard stop—not permission to broaden deletion.

Use `scripts/validate_destructive_test_ledger.py` for the portable JSON shape
and `scripts/ci/destructive_transaction_fixture.py` for the disposable local
signal/journal transaction proof. The validator checks evidence structure only
and the fixture mutates only a caller-provided disposable sentinel root; neither
authenticates live state, grants authorization, contacts a cluster, or executes
a live fault.
