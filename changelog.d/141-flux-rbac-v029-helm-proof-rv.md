### Security

- Recut the one-time Flux RBAC transaction for platform release `v0.1.29` after its released `v0.1.28` predecessor safely rolled back: compare every bound HelmRelease field except the controller-written `resourceVersion` at the forward and recovery proof boundaries, retain the current live version as the API write fence, and keep all semantic, release, identity, UID, generation, history, digest, inventory, and readiness checks fail closed.
