### Changed

- Mark both site HelmRelease objects with the stable, version-neutral `app.kubernetes.io/managed-by: fluxcd` label and enforce that exact pair in the closed release-state contract. This provides generic offline ownership metadata and a harmless ordinary tagged-platform change for proving both post-bootstrap site reconcilers advance without manual Kubernetes writes; chart identity, workload specs, RBAC, pruning, and controller configuration remain unchanged.
