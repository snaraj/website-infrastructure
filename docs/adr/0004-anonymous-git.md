# ADR 0004: Anonymous public Git source

- Status: Accepted
- Date: 2026-08-08

## Decision

Keep the desired-state repository public and configure Flux with the repository's
HTTPS URL and no authentication secret. Do not use `flux bootstrap github`.

## Consequences

No Git credential can be stolen from the cluster. Repository confidentiality is
not a control, so no secret or sensitive plan/state may be committed. Signature
verification can be enforced only after the chosen GitHub merge/signing workflow
is tested end-to-end.
