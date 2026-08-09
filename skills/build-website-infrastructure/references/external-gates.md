# External mutation gates

All procedures remain **Draft / unverified** until demonstrated on the actual
environment. Stop before the action unless the user explicitly authorizes that
exact target and operation in the current request.

| Operation | Required evidence before authorization | Required rollback |
| --- | --- | --- |
| Host firewall/remote access | read-only inventory, independent recovery access, saved exact config, second tested session | restore saved rules/config from retained session |
| Orchestrator/runtime install | reviewed architecture, storage, cgroups, clean-or-migration state, and exact signed/checksummed artifacts/configuration | preserved prior host/runtime configuration; installation alone does not authorize initialization |
| CNI and service-proxy decision | actual VPN/tunnel interfaces, kill-switch behavior, firewall, packet-filter backend, routes/policy rules, conflict-free CIDRs, and repository-required offline inputs | independent recovery access plus saved exact host/network state; no automatic firewall/VPN cleanup |
| Cluster init/upgrade | all preflight and networking gates, compatible pins/images, PKI/API-encryption handling, and the datastore backup required by the chosen distribution | compatible artifacts/configuration and verified datastore restore point; never treat a destructive reset as rollback |
| GitOps bootstrap | rendered manifests, reviewed source/authentication model, scoped reconciliation identities, and user-held recovery credential | suspend/revert bootstrap resources and desired-state change |
| Decryptor identity install | repository-selected backup ceremony and disposable recovery test | retain the prior identity through verified re-encryption or migration |
| Provider plan | current subscription/entitlement audit, cost-policy allowlist pass, least-privilege tokens, redacted plan, and plan hash | reviewed inverse change; no unauthorized paid fallback |
| Provider apply | explicit approval of the exact plan hash, target fingerprint, and resource counts; protected state | phased disable/revert plus immediate cost/subscription audit |
| Public exposure | all admission/network/authorization/secret/image/origin negative tests and recovery access | disable the public edge/DNS route while keeping the origin closed |
| Media storage enablement | discovered backend identity/capacity/binding, derivative-only least-privilege design, checksum/atomic publication, warning/critical capacity behavior, encrypted independent originals backup, and backend-appropriate rollout/restart/rebuild/restore/administration-saturation tests | suspend the site/edge route and preserve the selected storage read-only/offline; never delete or format data as rollback |
| Public heavy-media delivery | compatible current provider/service terms and cost entitlement, end-to-end Range/response/load evidence without cache dependence, and approved storage gate | return media routes to disabled/404 and preserve ordinary site/admin service; no unauthorized paid fallback |
| Image promotion | final digest scan, SBOM, signature/attestation verification, PR checks | revert deployment digest commit |
| Backup acceptance | encrypted off-device copy plus exact-version timed restore drill | retain prior known-good backup set |

Never display a secret-bearing command with a literal value. Provide placeholders
for environment variable names or protected file inputs, and ask the user to run
secret ceremonies locally without pasting output containing private material.
