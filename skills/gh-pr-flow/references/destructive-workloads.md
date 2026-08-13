# Destructive workload evidence

This contract grants no live action. Use it only after explicit owner
authorization identifies exact targets and a serialized live window.

## Classification is engineering, not prose

Every Kubernetes app/resource claimed ephemeral must be engineered and proven
disposable, not merely described. Every resource is classified:

- **ephemeral/disposable:** all durable state is externalized and a clean recreate from zero
  is tested;
- **protected/stateful:** PV/PVC, database, operator, identity, or other state
  with declared durability, backup, restore, ownership, and recovery semantics.

Stateful resources remain supported but never inherit ephemeral deletion
permission. Replica count and disruption shape are adjustable design inputs;
never encode replica=1 as a security invariant.

## Preconditions

Bind a ledger to:

- exact resource inventory and namespace/UID set;
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
default signal action while cleanup is still vulnerable. Hostile tests deliver
repeated and mixed signals during cleanup and prove one rollback, one bounded
receipt, and no residue. Distinguish uncatchable kill and power loss: persist a
recovery journal before mutation so the next run can detect and safely finish or
escalate an interrupted transaction.

## Ledger

The append-only evidence binds:

```text
prestate hash -> exact fault -> recovery action -> poststate hash
```

Include timestamps, desired-state/artifact hashes, target inventory, protected
exclusions, scenario, expected/observed downtime and RTO, acceptance results,
rollback status, deterministic cleanup receipt, recovery-journal state, and
residue/orphan scan. A missing field, changed target/hash,
secret overlap, orphan, failed recovery, or unproven externalized state is a hard
stop—not permission to broaden deletion.

Use `scripts/validate_destructive_test_ledger.py` for the portable JSON shape.
The validator checks evidence structure only; it does not authenticate live
state, grant authorization, or execute a fault.
