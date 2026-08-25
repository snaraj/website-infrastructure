# Flux RBAC resourceVersion baseline repair

- Ignore only controller-written OCIRepository and HelmRelease `resourceVersion` values during stable baseline comparison, retain type-exact binding of every other closed-inventory and semantic field, close a partially established custody binding on failure, and recut the one-time transaction for platform release `v0.1.28` after reproducing the false drift live without mutation.
