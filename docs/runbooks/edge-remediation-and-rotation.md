# Edge remediation, Tunnel rotation, and account audit — Draft / unverified

Three owner-run ceremonies for the public edge, written to the same evidence
standard as a pull-request body: every step names what is observed, what would
falsify it, and what stops the ceremony.

Scope and authority. Nothing here authorizes a change. The owner performs every
dashboard action, every token rotation, and every API-token issuance; agents
hold no Cloudflare credential. A PASS from any command below is evidence, never
permission, and an unknown answer is a stop, not a pass.

What each ceremony is for:

| Ceremony | Trigger | Credential |
|---|---|---|
| A — two-toggle edge remediation | the pre-toggle probe reports the redirect and TLS-floor gaps | none for the probe; dashboard session for the toggles |
| B — per-site Tunnel token rotation | quarterly drill, or suspected/confirmed compromise | Tunnel token (owner), plus a short-lived API token for force-disconnect |
| C — read-only account audit | after any edge change, and on a routine cadence | one just-in-time READ-ONLY API token, at most 60 minutes |

Related documents, all still in force for their own scope: ADR 0015 records the
two per-site Tunnel decision, the HSTS ownership, and the open `www` decision —
cite it, do not restate it. `docs/runbooks/tunnel-token-rotation.md` governs the
superseded shared public Tunnel and the host-level administrative connector, and
its Cloudflare rotation semantics are the source this runbook builds on.
`docs/runbooks/secret-rotation.md` holds the general secret ceremony.
`docs/runbooks/cloudflare-token-receipt.md` holds the token-receipt schema and
its blockers. `docs/runbooks/unexpected-cloudflare-billing.md` is the zero-spend
incident path.

Two commands appear throughout:

- `scripts/edge-probe.sh` — token-free, read-only, external. Report-only by
  default so it is useful *before* the target state is reached; `--enforce`
  makes an unmet target a nonzero exit.
- `scripts/cloudflare-account-audit.sh` — owner-run, token-taking, read-only,
  redacted by default. It reads the configuration facts the probe cannot see.

---

## Ceremony A — the two-toggle edge remediation

> **Read this before A.0.** Both settings this ceremony toggles now have
> committed state owners in the two site-owned OpenTofu roots —
> `infrastructure/cloudflare/phases/site-naranjo-online/main.tf` and
> `infrastructure/cloudflare/phases/site-lidersea-com/main.tf`. Each root
> orders Minimum TLS Version before Always Use HTTPS and requires the provider
> to read the value back, and
> `infrastructure/cloudflare/policy/cloudflare-plan.rego` admits only the
> measured `off` → `on` and `1.0` → `1.2` transitions on exactly those two
> addresses, with every other resource in the plan a no-op. A dashboard toggle
> is therefore a **break-glass** action under safety invariant 9: it takes
> custody away from that state, so it must be recorded and reconciled back into
> the roots immediately, and the next plan re-read before anything else runs.
>
> The reviewed saved-plan ceremony that would replace this section — together
> with the fixed legacy-capable acceptance client that proves TLS 1.0/1.1
> rejection against the same edge — is **deferred to a tracked follow-up
> issue** and is not in this tree. Until it lands, this section is the only
> written procedure, and it is a break-glass one. Do not read the presence of
> committed OpenTofu owners as authorization to apply them: no live Cloudflare
> transaction is authorized by this repository.

Two zone settings are below their target state on both zones: plaintext HTTP is
served instead of redirected, and the minimum TLS version is 1.0. Everything
else in the target state is already met, so this ceremony changes exactly two
settings per zone and nothing else.

### A.0 Preconditions

1. A maintenance moment the owner chose. Both changes take effect within
   seconds and are reversible in the same place.
2. The current edge-to-origin encryption mode is `full` or `strict`. Confirm it
   with ceremony C first (`zone-setting[<zone>/ssl]`). This matters: the loop
   hazard described in A.4 is real only under the `flexible` mode.
3. The application-side redirect behaviour has two halves, and they are **not
   equally true today**. Read both before relying on either:

   a. **Merged in Git — verifiable now.** Each site's application answers a
      request carrying an `X-Forwarded-Proto: http` header with a 308 to the
      same URL over https, and gates `Strict-Transport-Security` to https
      responses. Confirm by reading each site repository at its current
      default branch.
   b. **Not yet observable at the edge.** The images currently running predate
      those merges. Today both origins answer plaintext with `200` and emit
      HSTS over cleartext; `scripts/edge-probe.sh` records that as
      `hsts-over-cleartext present`. The behaviour ships with the next
      application release. **Do not read (a) as a statement about the live
      origin** until that deploy has landed and the probe's record item flips
      to `absent`.

   This split matters because A.4's loop-safety conclusion must not lean on a
   behaviour that is merged but undeployed. It does not — see A.4.
4. Nobody is mid-rotation on either Tunnel. Ceremonies A and B never overlap.

### A.1 Pre-toggle probe — expect gaps, and record them

```sh
scripts/edge-probe.sh --rounds 2 --round-gap 20 | tee edge-probe-before.txt
```

Expected today, per the 2026-08-12 attestation and reproduced by this script:
`GAP` on `http-redirect-root`, `http-redirect-path-query`, `tls10-refused` and
`tls11-refused` for **both** zones — eight gaps — and `PASS` on everything else,
including `zero-rtt-off`, `hsts-exact`, `tls13-accepted`, `readyz`,
`www-absent`, `site-identity` and `sites-distinct`.

Read four things before continuing:

- the `RESULT` line: `gap=8 skip=0 error=0 divergent=0`. A `skip` means the
  local TLS client could not be proven able to speak a protocol, so that item
  says nothing about the edge; fix the client before trusting the ceremony.
  A `divergent` means two rounds disagreed; re-run before changing anything.
  (`inapplicable` is different and harmless — it counts items outside the
  selected scope, such as cross-zone distinctness in a single-zone run.)
- the capability preflight block: all four protocols must read `capable`.
- the `dnssec` rows: `naranjo.online` signed and validating, `lidersea.com`
  unsigned. `lidersea.com` unsigned is the recorded expectation, not a defect.
- the `hsts-over-cleartext` record rows. `present` means the running
  application build still predates the https-gated HSTS change (precondition
  A.0.3b), which is the expected state until that release deploys. It is a
  deployed-state signal only; browsers ignore HSTS received over cleartext, so
  it is neither a control nor a blocker for this ceremony.

Keep `edge-probe-before.txt` outside the repository. It contains no credential
and no private identifier, but it is a point-in-time observation, not a
committed artifact.

### A.2 The two toggles, one zone at a time

For each zone, in the Cloudflare dashboard, with the zone selected:

1. **SSL/TLS → Edge Certificates → Always Use HTTPS** → **On**.
2. **SSL/TLS → Edge Certificates → Minimum TLS Version** → **TLS 1.2**.

Nothing else on that page changes. In particular do not enable managed HSTS
(the application owns `Strict-Transport-Security`), do not enable Opportunistic
Encryption, TLS 1.3 or 0-RTT settings that are already at their target, and do
not touch Automatic HTTPS Rewrites — it rewrites subresource URLs and is not a
redirect, so it neither substitutes for toggle 1 nor belongs in this change.

Do the first zone completely, verify it with A.3 limited to that zone, and only
then do the second. Two zones changed together share one failure.

```sh
scripts/edge-probe.sh --zone naranjo.online --enforce --rounds 2
```

**This single-zone enforcing run is meaningful and must exit 0.** Cross-zone
distinctness cannot be evaluated with one zone in the run, so it is reported
`INAPPLICABLE` and does not fail the run — an item outside the selected scope
has nothing to prove. Everything that *can* be evaluated for the toggled zone
still has to pass. A nonzero exit here is a real failure of the half-completed
ceremony: stop, do not toggle the second zone, and read the table. Never wave
a nonzero exit through because "it is only one zone".

Safety invariant 9 applies: these are dashboard mutations, therefore break-glass
by definition. Record the exact settings changed, and reconcile them into the
Cloudflare OpenTofu roots immediately afterwards so the next plan does not
propose reverting them.

### A.3 Post-toggle probe — enforce

```sh
scripts/edge-probe.sh --enforce --rounds 2 --round-gap 20 | tee edge-probe-after.txt
```

Required result: exit code 0 and `gap=0 skip=0 error=0 divergent=0`. The four
previously failing items must now read:

| Item | Required observation |
|---|---|
| `http-redirect-root` | `http_code=301` (or `308`), `location=https://<zone>/`, `chain=1:200` |
| `http-redirect-path-query` | `location=https://<zone>/readyz?probe=1&x=2` — path **and** query preserved |
| `tls10-refused` | `refused` |
| `tls11-refused` | `refused` |

Two failure shapes deserve their own reading:

- A redirect that drops the query string, or that produces more than one hop,
  is a **failed** remediation even though HTTP now redirects. The probe asserts
  the whole shape for exactly this reason.
- `tls10-refused` reporting `SKIP` instead of `refused` is a *client* problem,
  never a server pass. The probe proves the local client can speak TLS 1.0
  against a loopback server before it will assert anything about the edge; if
  that proof fails the item is skipped loudly. Never read a skip as success.

Then run ceremony C and confirm the configuration side agrees:
`zone-setting[<zone>/always_use_https] value=on` and
`zone-setting[<zone>/min_tls_version] value=1.2` on both zones. Behaviour and
configuration agreeing is the actual completion criterion; either alone is a
weaker claim.

### A.4 The loop hazard, and why there is no loop here

The classic redirect loop is: the edge terminates TLS and forwards to the origin
over plaintext, the origin sees a plaintext request and redirects to https, the
edge serves that redirect, and the client arrives back at the same place. It
requires the edge-to-origin leg to be plaintext *while the origin insists on
https*.

That combination does not exist here. **The conclusion rests on reason 1
alone**, which is a property of the edge and holds regardless of which
application build is deployed:

1. **Load-bearing.** With Always Use HTTPS on, a plaintext request is answered
   by the edge with a 30x before it ever reaches an origin. No plaintext
   request survives to the origin, so whatever the origin would have done with
   one cannot close a loop.

2. **Defence in depth, and not yet deployed.** On the https path the connector
   presents the request to the application with `X-Forwarded-Proto: https`, so
   the application's fail-closed exact-match redirect does not fire; that
   redirect only ever fires on an explicit `http` forwarded-proto. This is
   precondition A.0.3a — merged in Git, **not** running at the edge yet
   (A.0.3b). It is written here because it will matter after the next
   application release, and because a reader must not mistake it for part of
   today's safety argument. Reason 1 does not depend on it.

The check that keeps reason 1 true is precondition A.0.2: the `flexible` edge-
to-origin mode is the one that would manufacture the loop, and ceremony C fails
the run if the mode is ever `flexible` or `off`.

If a loop is nevertheless observed — a browser reporting too many redirects, or
`chain=` above 1 in the probe — roll back immediately per A.5 and do not
re-toggle until the origin behaviour has been re-read.

### A.5 Rollback

Rollback is the same two controls in the same place, set back:

1. **Minimum TLS Version** → its previous value.
2. **Always Use HTTPS** → **Off**.

Reverse order of application: turn the redirect off first if the symptom is a
loop, since that is the control that changed reachability. Then re-run
`scripts/edge-probe.sh` without `--enforce` and confirm the observations match
`edge-probe-before.txt` item for item. Rolling back restores a known-worse
security posture, so it is an incident, not a resting state: record why, and
schedule the retry.

---

## Ceremony B — per-site Tunnel token rotation

ADR 0015 gives each site its own Tunnel, its own token, and its own connector.
The rotation discipline follows from that: **one Tunnel at a time, never both**.
The peer site's Tunnel, token, connector and Secret are untouched for the whole
ceremony, and proving they were untouched is part of the evidence.

Cloudflare's rotation semantics, unchanged from
`docs/runbooks/tunnel-token-rotation.md`: after rotation the old token cannot
establish a *new* connection, but connectors already connected with it stay
connected until they restart or the connections are force-disconnected.
Therefore **an old token is never a rollback credential**, and a rotation that
skips the force-disconnect leaves an attacker's connector running.

Never place a Tunnel token or the API bearer used for rotation in a command
line, shell history, Git, chat, a log, OpenTofu state, or an unprotected plan.
Use a protected file or a process-local environment variable, keep shell tracing
off, and clear it immediately afterwards.

### B.1 Routine rotation of one site's Tunnel

1. **Fix the blast radius.** Name the site being rotated. Confirm the other
   site's Tunnel is healthy first — `scripts/cloudflare-account-audit.sh` prints
   `tunnel[<name>] status=healthy` and `connectors=N idle=0` for each. Confirm
   host-level and physical/LAN recovery still work; they are the fallback if
   the rotated site loses its connector.
2. **Baseline.** Run `scripts/edge-probe.sh --rounds 1` and keep the output.
   Both sites must be serving before a rotation starts, otherwise a failure
   afterwards cannot be attributed.
3. **Rotate exactly one token.** The owner rotates that Tunnel's token in the
   dashboard and captures the new value directly into a protected mode-0600
   file, without printing it. Existing connectors keep running on the old
   token; the old token can no longer be used to connect anything new.
4. **Force-disconnect that Tunnel's existing connections.** This is the step
   that actually retires the old credential. Use the dashboard control, or a
   short-lived API token holding exactly the connector-write permission, and
   never put either bearer in a URL or a command line. Accept the brief
   interruption for that one site: without this step, any connector already
   holding the old token — including one an attacker controls — keeps serving.
5. **Install the new token through the approved workflow.** The connector reads
   its token from a Kubernetes Secret through `secretKeyRef`, never as a literal
   manifest value; the Secret is SOPS/age ciphertext under the recipient
   selected by `.sops.yaml`, staged in one feature-branch pull request together
   with the non-secret revision field the chart uses to trigger a rollout. The
   per-site Secret paths for the two-Tunnel shape are platform-lane
   reconciliation work and are not yet in Git; until they land, the exact
   staging contract, its ciphertext ceremony, and its blockers are the ones in
   `docs/runbooks/tunnel-token-rotation.md`. Never commit a latent listing, and
   never split the Secret and its listing across two pull requests.
6. **Prove the old token cannot reconnect.** After the rollout completes, the
   audit must show that Tunnel healthy with `idle=0` and no connector that
   predates the rotation. An old-token connector that reappears means the
   force-disconnect did not cover every connection, or the old token was
   reinstalled somewhere.
7. **Prove the peer lane is untouched.** Re-run
   `scripts/cloudflare-account-audit.sh` and diff the redacted output against
   the pre-rotation capture: every line for the other site — Tunnel pseudonym,
   status, ingress, DNS — must be byte-identical. That is exactly what the
   stable pseudonyms are for.
8. **Prove both sites still serve.** `scripts/edge-probe.sh --rounds 2` with
   `site-identity` and `sites-distinct` at PASS, and `readyz` 200 on both.
9. **Destroy the old material.** Delete the protected old-token file. If the
   rollout failed, do **not** restore it: stop the rollout, keep recovery
   access, and issue a *different* new token through another forward rotation.

### B.2 Compromise response for one site

Same shape, reordered so exposure ends first: rotate that site's token
immediately, force-disconnect all of its connections before anything else, then
install the new token through the workflow above and re-verify. Downtime for the
compromised site is expected and accepted; the alternative is leaving a
malicious connector attached. Revoke the short-lived API token afterwards and
record the non-secret revocation evidence. Prove the other site was never
touched. Never restore the compromised token, and never rotate the second site
"while you are in there" — a compromise of one token is not evidence about the
other, and rotating both at once removes the only healthy comparison you have.

### B.3 Drill cadence

- **Quarterly, one site per quarter, alternating.** A rotation nobody has
  rehearsed is not a control. Run B.1 end to end on the site whose turn it is,
  in a maintenance window, and file the evidence. Alternating means each site's
  path is exercised at least annually and the two are never rehearsed together.
- **Emergency drill, twice a year.** Run B.2 against one site with a token that
  is *not* compromised, to measure the real interval between "decide" and "old
  credential provably dead". Record that interval; it is the number that
  matters during an actual incident.
- **After every drill**, capture: which site, the elapsed time per step, the
  redacted audit diff proving the peer lane was untouched, and any step that
  needed improvisation. A step that needed improvisation is a defect in this
  runbook — fix the runbook in the same week.

---

## Ceremony C — read-only account audit

The audit reads configuration facts that no external probe can observe: plan and
subscription state, zone settings, DNSSEC status, the Tunnel and connector
inventory, the absence of a private-network surface, and the DNS record set.

### C.1 Issue a just-in-time read-only token

The owner creates an API token with:

- **read-only permission groups only** — every group's name ends in `Read`;
- the narrowest scope that covers the two zones and the account's Tunnel and
  Zero Trust read surfaces;
- an expiry of **at most 60 minutes**;
- a source-address condition where the network allows one.

The audit refuses to treat an unproven credential as usable: a token that is not
`active` stops the run, and a token that cannot read its own definition is
reported as a limitation — the permissions were *not* machine-verified — rather
than as a pass. That is the expected result for a minimal token, and it means
the scope and expiry must be confirmed by eye in the dashboard.

### C.2 Run it

```sh
read -rs CF_API_TOKEN && export CF_API_TOKEN
scripts/cloudflare-account-audit.sh | tee cloudflare-audit-$(date -u +%Y%m%dT%H%M%SZ).txt
unset CF_API_TOKEN
```

The token is read from the environment only. It is never an argument, never
printed, never written to a file, and never placed in the process table: it
reaches curl through a configuration document on standard input. Every request
the script can issue is a GET; `--self-test` proves that offline, with no token
and no network, and is the right thing to run first on a new host.

### C.3 Review the redacted diff

Default output replaces account, zone, Tunnel and connector identifiers with
stable pseudonyms (`id:` plus twelve hex characters). The same identifier
produces the same pseudonym on every run and every host, so two captures diff
cleanly, while the output carries no identifier worth protecting. Diff the new
capture against the previous one and read every changed line.

Expect, in a healthy steady state: all subscriptions Free and zero-priced; both
zone plans Free; the six zone settings at their target values on both zones;
`naranjo.online` DNSSEC `active` and `lidersea.com` `disabled`; exactly the two
per-site Tunnels, each with one hostname rule plus the terminal 404 and no idle
connector; no private route and no WARP profile; exactly one proxied apex CNAME
per zone targeting that site's own Tunnel, and no other record.

`--raw` prints the real identifiers. Use it only when a pseudonym is genuinely
not enough — for example when the DNS check reports a mismatch and the exact
target must be read. Raw output must never be committed, pasted into an issue,
pull request, comment or ticket, or shared; delete the capture when the review
is finished. The script prints that warning itself, at the top of every raw run.

### C.4 Revoke

Revoke the token as soon as the run is reviewed, and confirm the revocation
using a *different* credential — a token that reports itself revoked is not
evidence. Record the non-secret revocation facts per
`docs/runbooks/cloudflare-token-receipt.md`. A token left alive after the
ceremony is the single most likely way this audit turns into an incident.

---

## Evidence to keep

Every ceremony produces the same three artifacts, kept outside the repository:

1. the before and after `scripts/edge-probe.sh` captures, including the
   `RESULT` line and the capability-preflight block;
2. the before and after redacted `scripts/cloudflare-account-audit.sh`
   captures, and the diff between them;
3. a short written record: what changed, who changed it, when, what was
   observed, and what would have made the ceremony stop.

None of these belong in Git. The repository holds the *procedure* and the
*checks*; the observations stay local, exactly as safety invariant 12 requires.

Revalidate the current provider behaviour immediately before any live change:

- <https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/>
- <https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/>
- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/>
