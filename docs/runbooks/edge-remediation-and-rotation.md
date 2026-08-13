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
| A — two-toggle edge remediation | superseded; use `docs/runbooks/cloudflare-edge-hardening.md` | see the authoritative hardening runbook; no current live authorization exists |
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

## Historical Ceremony A — superseded; do not execute

The former dashboard-toggle procedure was removed because it bypassed the
existing site-owned OpenTofu resources and their state custody. The only
authoritative Draft transaction is
`docs/runbooks/cloudflare-edge-hardening.md`. It remains live-blocked and
requires a hash-bound saved plan, exact provider readback, the frozen legacy-
capable SslStream client, serialized per-zone acceptance, and captured-value
rollback. Do not reconstruct the removed dashboard procedure from repository
history.

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
