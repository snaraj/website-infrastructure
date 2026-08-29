# Exact-head adversarial review receipts

## Required normal-comment shape

The durable PR comment contains these standalone lines exactly once:

```text
HEAD: <40-lowercase-hex>
VERDICT: APPROVE
```

or `VERDICT: REQUEST-CHANGES`, plus numbered findings (or explicit no-finding
scope), claim audit, mutation results, full-gate/flake evidence, scratch cleanup,
and a final line:

```text
- Reviewer identity (adversarial reviewer)
```

The identity names the reviewing lane — provenance, not authority. Independence
is established by the POSTING ACTOR, and the receipt validator never sees it:
the coordinator reads the comment's author from the forge. Do not compare the
signature against the author's, and never invent a context string to make a
validator return ALLOW; a reviewer satisfies a textual comparison by typing a
different word, which proves nothing. Same-lane review is permitted where the
repository contract permits it.

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

## Main Worker Ready receipt

After one exact-head `APPROVE`, have a coordinator context distinct from both
author and reviewer perform one bounded sanity pass over architecture, merge
order, authority, owner-observed settings, base freshness, and required checks.
Do not repeat code review and do not contact a named worker automatically. Post
one normal comment with these exact standalone lines:

```text
HEAD: <40-lowercase-hex>
ROLE: MAIN-WORKER
VERDICT: PASS
SCOPE: architecture,merge-order,authority,settings,base-freshness,required-checks

- Coordinator context (Main Worker)
```

Use `VERDICT: BLOCK` to record a failed pass; it cannot satisfy Ready. Validate
the Ready receipt with `scripts/validate_review_receipt.py --receipt-kind
main-worker --resource-kind pull-request --required-verdict PASS --head <head>
--author-context <author> --reviewer-context <reviewer> <receipt>`. Any head
change invalidates it. The validator proves closed text shape, not context
independence, settings truth, Ready authority, or merge authority.
