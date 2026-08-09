# ADR 0009: Defer Vault and preserve a migration seam

- Status: Accepted
- Date: 2026-08-08

## Decision

Do not deploy Vault for one operator, one static site, and two tunnel tokens.
Applications consume ordinary Kubernetes Secrets with stable names and keys and
do not know whether SOPS or a future operator produced them.

## Revisit trigger and migration

Revisit at the first database or second Kubernetes environment, or when dynamic
credentials, PKI, multi-operator policy, or central audit becomes necessary.
Deploy hardened multi-node Vault, configure auth/policies, have an operator
produce the same Secret interface, migrate and rotate one workload at a time,
and remove SOPS values only after validation. Retain minimal bootstrap secrets.
