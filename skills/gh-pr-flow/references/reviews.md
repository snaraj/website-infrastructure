# Exact-head adversarial review receipts

## Required normal-comment shape

The durable PR comment contains these standalone lines exactly once:

```text
HEAD: 0123456789abcdef0123456789abcdef01234567
VERDICT: APPROVE
```

or `VERDICT: REQUEST-CHANGES`, plus numbered findings (or explicit no-finding
scope), claim audit, mutation results, full-gate/flake evidence, scratch cleanup,
and a final line:

```text
- Reviewer identity (adversarial reviewer)
```

The identity must differ from the authoring context. Since one GitHub principal
may post both, this is textual process evidence, not cryptographic separation.

## Review procedure

1. Re-query PR base/head, labels, commits, files, checks, discussions, comments,
   milestone, assignee, and linked issue. Fetch exact objects without checking
   out an author's worktree.
2. Read the full issue/PR/commit/comment history and repository architecture.
3. Audit every claim and number against the exact diff and source.
4. Threat-model security, failure, retry, concurrency, recovery, privacy,
   scalability, and future workload assumptions. Do not freeze replica counts,
   storage kinds, StatefulSets, databases, or operators unless the product
   contract actually requires it.
5. Mutate each new/changed guard so its claimed regression survives in the
   source and the gate must turn red. Revert between mutations; scan for
   residue/untracked files.
6. Run focused gates, full repository gates, coverage/quality checks, and the
   repository flake probe. Distinguish capability skips and infrastructure
   failures from passes.
7. Post one receipt at the exact head. Remove `requires-review`; do not flip
   Ready, author fixes, or merge.

## Invalidation and repair

Any new commit invalidates every prior verdict. Edits to a comment do not bind a
new head. The author responds to findings with reproduction and repair evidence,
then requests a fresh review. A later `REQUEST-CHANGES` outranks an earlier
approval. The coordinator considers only the latest valid receipt for the
current head.

If merge precedes review, mark the result POST-MERGE AUDIT. Findings become
linked follow-up issues/PRs; never relabel the audit as pre-merge approval.
