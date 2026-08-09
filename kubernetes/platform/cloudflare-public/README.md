# Public Tunnel chart — Draft / suspended

This chart runs exactly two `pi-websites` connectors, without a Service, HPA,
private route, host access, or Kubernetes API token. The runtime token comes from
`pi-websites-tunnel-token`, created only as SOPS ciphertext after the user-run
ceremony. The structural example is excluded from reconciliation and unusable.
Connector egress is limited to cluster DNS, the Cloudflare edge, and the exact
`naranjo-online` and `lidersea-com` workload identities on TCP 8080. Each site
chart owns the reciprocal tunnel-only ingress rule and denies site egress.

Keep the HelmRelease suspended until:

1. every configured site Service is Ready and its independent image admission passes;
2. the SOPS token file exists and is included in the release Kustomization;
3. Cloudflare Free plan/subscriptions and the exact OpenTofu plan hash pass;
4. external recovery/origin tests are ready.

At token rotation, update the encrypted Secret and `tokenRevision` in one
reviewed PR. Roll back only if the old token is not compromised; otherwise
complete rotation forward. The admin tunnel is never changed in the same step.
