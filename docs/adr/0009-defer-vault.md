# ADR 0009: Keep runtime secret custody explicit

- Status: Accepted
- Date: 2026-08-08

## Decision

Runtime secrets are created on the cluster by an owner ceremony. The repository
carries neither plaintext secrets nor encrypted secret documents. Applications
consume ordinary Kubernetes Secrets with stable names and keys; delivery does
not require a cluster decryption identity or an external secret service.

## Revisit trigger

Revisit when a deployed workload needs dynamic credentials, additional operator
policy, or centralized secret auditing. Any replacement needs its own threat
model, custody and recovery evidence; it is not a prerequisite for the current
release path. Kubernetes API encryption and protected backups remain required.
