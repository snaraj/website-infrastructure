### Security

- Keep the one-time Flux RBAC convergence transaction credential-free after GitHub stopped supplying `merge_commit_sha` to anonymous pull-request reads: require the unique commit association, authoritative merged endpoint, exact owner/repository/base/head identities, signed source and head commits, matching source-parent/base commits, and matching source/head trees before accepting an omitted or null field.
