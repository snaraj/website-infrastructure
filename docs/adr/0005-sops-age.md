# ADR 0005: SOPS with age

- Status: Accepted
- Date: 2026-08-08

## Decision

Flux-native SOPS decryption produces stable Kubernetes Secret names and keys.
Commit only SOPS ciphertext and one public age recipient. The user creates one
private age identity per cluster/trust boundary, backs it up twice, tests
recovery, and installs it into `flux-system` out of band with `--from-file`.

## Consequences

Anyone with the identity and repository history can decrypt retained ciphertext,
so suspected theft requires credential rotation as well as re-encryption.
Kubernetes API encryption at rest remains necessary after decryption into the
API server.
