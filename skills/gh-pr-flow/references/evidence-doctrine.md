# Evidence doctrine — the ways a green suite lies

A guard that cannot fail is no guard, and a suite that cannot go red is not
evidence. This is the catalogue behind that principle: distinct, reproducible
mechanisms by which a fully green run proves nothing, each stated as the
MECHANISM, why the suite stayed green, and the general correction. Several
were found only after a reviewer had already approved, and several inside the
fix written to close an earlier finding. Use it while authoring, before
claiming a control works, and while reviewing, as the vacuity probe list.

## 1. How a policy or test suite lies about coverage

**A resource OUTSIDE a rule's match block is reported as a pass.** Policy-test
runners answer "did this rule reject this object", never "does this rule cover
this object". An object that never matched is scored `pass` or `excluded`, so
narrowing a match — back to a superseded name, a stale label, a renamed
identity — silently stops covering the exact thing the rule exists to guard,
with every row still green.
*Correction:* prove coverage structurally. Bind the rule's matched identities
to the RENDERED inventory — the chart, the desired state, the manifest set
actually shipped — in a separate assertion, and mutation-test the narrowing.

**A SKIP counts as a pass.** Narrow a rule until it matches nobody — most
directly through the principal-oriented match fields (roles, cluster roles,
subjects, any caller-identity selector), which make the runner report
"skipped: required variables not provided" — and it scores green.
*Correction:* forbid the principal-oriented match fields outright in a
structural guard, and treat a skip as a result to explain, never as a pass.

**RENAMING a rule out of existence passes every row that references it** —
including rows whose declared expectation was `fail`. A runner cannot fail a
rule it cannot find, so it reports the row as excluded and scores it green.
*Correction:* pin rule NAMES structurally against the rendered inventory.
Never let the policy suite be the only thing that knows a rule exists.

**A short-circuit setting can retire the rule that carries the property.**
Where an engine can be told to apply only the FIRST matching rule, a later
rule never runs, so one token can reopen a closed finding invisibly.
*Correction:* pin the short-circuit setting structurally — that is the robust
half. Declaring the security-critical rule first only changes WHICH rule a
short circuit retires; it is a sane default, not a guard.

**Enforcement can be switched off wholesale, structurally intact.** Two
different fields do it. One stops the rules RUNNING where it matters (an
`admission: false`-shaped toggle leaves only background evaluation); the other
lets them run and suppresses the denial (audit-only and report-only modes).
Rules, fixtures and names all still exist either way.
*Correction:* assert both, per policy — the field that decides whether the
rules run, and the enforcement mode of every rule the round claims to enforce.

**The general correction.** Coverage cannot be inferred from a green run. A
suite proves BEHAVIOUR on matched objects and says nothing about which objects
are matched. Bind matched identities, rule names, match and exclude stanzas,
ordering, and enforcement fields structurally against the rendered inventory.

## 2. How fixtures and gates lie

**A MULTI-DOCUMENT deny fixture asserted at FILE level hides the weakening of
any single rule arm.** With several bypass documents in one file the runner
asserts only that the FILE was rejected; delete one deny arm and the remaining
documents still fail the file. The fixture still "rejects", the suite is
green, and the control it was named for is gone.
*Correction:* one document per file, or assert the expected deny MESSAGE per
document. Any kill matrix whose killers route through a file-level assertion
is CONDITIONAL on the rest of the policy being intact — say so in the matrix.

**A guard "pinned" by grepping its own SOURCE TEXT is not pinned.** Replace
the refusal condition with something that can never match, leave the error
string in place, and the suite stays green — the original mutant only died
because deleting the block also deleted the string the test greps for.
*Correction:* drive the behaviour. Feed the input that SHOULD trip the guard
and assert that the refusal actually fires.

**A gate that reads its THRESHOLD from the artifact it verifies is disabled by
a one-token edit to that artifact.** The comparison turns unequal, and a gate
that SKIPS on mismatch prints OK while its load-bearing assertions never run.
*Correction:* derive thresholds from an independent pin, and FAIL rather than
SKIP when the subject is present but mismatched. A skip on mismatch is a
self-disabling guard.

**A textual assertion over a function body is satisfied by a COMMENT.** Wiring
tests that check membership, a count, or an index over a function's source
pass just as happily when the call is commented out. The realistic regression
is DELETION, which these tests DO catch, so this is a hardening rather than an
emergency — but the gap is real and cheap to close.
*Correction:* strip comment lines from the sliced body before asserting, or
parse the source instead of matching substrings.

**A proven predicate whose CALL SITE no test invokes is an unwired patch.**
The predicate can carry exhaustive coverage while the two lines that WIRE it
into its caller are deletable with the suite still green — fully tested and
completely bypassable.
*Correction:* whenever you add a predicate, helper, or patch, assert the CALL
SITE separately from the thing itself — slice the caller and assert that it
calls what you wrote.

**A HAND-WRITTEN stub of a tool's output makes the guard unfalsifiable.**
Invent the shape a command "would" emit and you encode your belief about it
rather than its behaviour: a guard parsing a fabricated shape can be
constant-red — incapable of passing on any real input — and still survive a
full mutation matrix, because every row feeds it the same fiction.
*Correction:* build every stub from a REAL capture, recorded with the version
that produced it, and regenerate it when the tool moves.

**Two engines called "one-for-one mirrors" need a DIFFERENTIAL harness.**
Comparing enumerations, rule identifiers, and comment markers proves the TEXT
agrees; it never proves the BEHAVIOUR agrees. Accessor semantics diverge on
degenerate values — a null, a string, or a list where an object was expected
makes one engine deny and the other fail open and silently not fire — and two
inputs one token apart are then indistinguishable to the suite.
*Correction:* feed every deny fixture plus a degenerate-shape corpus to BOTH
engines and fail on any allow/deny disagreement; guard each accessor with a
type check that DENIES on failure; then mutate the harness itself, because a
differential test that compares nothing is the next vacuity.

**Scope decided from a FIELD rather than from the KIND is bypassable.** An
entry that claims to be namespaced can name a cluster-scoped object, and
tooling that IGNORES the namespace for root-scoped resources then acts
globally, while the validation reports everything as inside the reviewed bound.
*Correction:* bind scope to KIND, never to the presence or the value of a
namespace field.

**A check keyed on PART of an identity is satisfied by the wrong object.** Key
a declared-gap check, an allowlist, or a suppression on a bare NAME and any
other KIND sharing that name satisfies it: the check passes while the object
it exists to catch is untouched. Found INSIDE a fix, by re-running the matrix.
*Correction:* key on the FULL identity — (kind, name), or whatever tuple makes
two objects distinguishable — anywhere two kinds can collide.

**Patching by INDEX breaks silently when someone adds an item.** A positional
overlay (items 0, 1, 2) merges textually clean against a parallel change that
appends a fourth, and the result is semantically broken — one item silently
unpatched, so the stage that is supposed to fail open enforces, or the stage
that is supposed to enforce does not. Neither change is wrong alone.
*Correction:* patch by NAME, or by a selector that cannot silently
under-match, and assert that the COUNT patched equals the count that exist.

## 3. How the fix itself lies

**Your own NEW assertions are the likeliest survivors.** An assertion written
to close a finding comes from the same mental model that missed it; round
after round, the survivors are the round's own new rows.
*Correction:* re-run the mutation matrix on the FIXED tree, and mutate the
newly written assertions FIRST, before re-running the inherited rows. Never
carry a matrix result forward across a fix. A fix you cannot kill is not a fix.

**The largest NEW control in a round is the one most likely to have NO killer
at all.** Not a weak assertion — no assertion, because the round's attention
went into building the control rather than into failing it.
*Correction:* for every control you ADD, name the single test that fails when
you delete it, and prove it by deleting it. If the answer is "the fixture
suite", check that the fixture is not multi-document and the runner is not
file-level.

**A SURVIVING mutant may be a BAD MUTANT, not a good guard.** A mutant that
swaps accessor style while preserving the structure under test could not have
failed whatever the guard did.
*Correction:* re-derive the mutant and prove it changes the behaviour under
test before concluding that a guard is vacuous — otherwise you will rewrite a
working guard to satisfy a broken probe.

**A NORMALISATION can be a weakening wearing the shape of a fix.** Coercions,
defaults, `or []`, `// {}`, and "just normalise the input" silently expand
what passes, and can skip a shape the stricter code walks today.
*Correction:* mutate a normalisation before shipping it, even when a reviewer
or a coordinator asked for it — a request is not authority; push back with
evidence. The refusal is usually the safer construction.

**Verify the TRUE NEGATIVES too.** A matrix proves the red cases; the cases
you expect to stay green are equally load-bearing, and "obviously fine" is how
a check that never fires gets shipped.
*Correction:* say why each true negative stays green, from the property that
makes it green — not from the observation that it did.

## 4. Keeping the evidence itself honest

**A STAGED command is not a VERIFIED result.** A plan, a preflight, or a brief
carries expectations, and an expectation quoted back as an outcome is how a
wrong premise becomes a green report.
*Correction:* label every unrun command a hypothesis, and never let a staged
expectation into an evidence table.

**Reproducibility evidence needs a PRISTINE checkout.** Build output or
scratch left in a reused workspace masks the failure you are testing for and
pollutes any scan that walks the tree, so a determinism or render claim made
there proves nothing about a fresh clone.
*Correction:* check out the exact commit into a clean workspace for any
determinism or reproducibility evidence.

**A mutation harness must refuse to run against a dirty tree.** Commit the
work first, because reverting a mutation reverts uncommitted real work with
it; assert the target text is present before each edit, so a no-op edit cannot
masquerade as a survivor; and abort if anything is left over afterwards,
tracked or untracked — reverting tracked files does NOT remove a file a
mutation CREATED, and the leftover then falsifies every later row.
