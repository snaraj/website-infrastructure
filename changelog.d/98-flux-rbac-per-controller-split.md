### Security

- Split Flux custom-resource authority into three install-root ClusterRoles, each bound to exactly one controller ServiceAccount, while removing every Flux API-group grant from the shared controller role and preserving exact cross-controller denial, rollback, and live-oracle evidence.
