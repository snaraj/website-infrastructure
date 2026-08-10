# website-infrastructure

GitOps source for a single Raspberry Pi 5 running upstream Kubernetes,
bootstrapped with kubeadm on containerd, and two independently released
websites built with Svelte frontends, Go services, and Helm charts. The intended
public request path is Cloudflare's edge, one outbound-only `pi-websites`
Tunnel, one private ClusterIP Service per domain, and non-root website pods. No
router port is opened.

This repository is intentionally **not deployable yet**. Credential-free local
artifacts are scaffolded first. Values marked `REPLACE_*` or `UNRESOLVED` are
fail-closed sentinels, not examples. The first external checkpoint is a
read-only Pi and Cloudflare discovery followed by explicit review.

## Non-negotiable policy

- Cloudflare infrastructure cost must remain exactly $0 across exactly two
  active Free-plan zones. Registrar renewals for those domains are the only
  authorized Cloudflare charges; Pro is the next paid boundary and is not
  authorized.
- Unknown entitlement or billing behavior is a `NO-GO`; downtime is preferred.
- No inbound WAN ports, public origin IP, NodePort, LoadBalancer, host port,
  host network, Ingress controller, or public administrative hostname.
- Flux reads this public repository anonymously and has no Git write credential.
- Kubernetes Secret manifests committed to Git are SOPS ciphertext. The age
  private identity never enters Git, CI, documentation, logs, or chat. CI
  validates ciphertext structure only; protected offline decryption must
  authenticate the SOPS MAC and the plaintext credential identity before merge.
- Images are deployed only by immutable digest after review.
- Any pre-existing protected host services, VPN/tunnel interfaces, firewall,
  and policy-routing state are discovered read-only and left unchanged until
  conflicts are reviewed with a tested recovery path.
- A privacy-sensitive legacy workload and its retained data are an inactive,
  operator-only archive under [ADR 0013](docs/adr/0013-protected-legacy-archive.md),
  never a co-hosted Kubernetes workload. Product classification is not host
  inventory; exact units, paths, mounts, identities, and evidence remain local.
- Heavy media never enters Git, frontend output, Go embeds, OCI images, Flux,
  ConfigMaps, Secrets, or etcd. Its proposed read-only data-volume profile is
  disabled pending Pi discovery, restore evidence, and a compatible delivery
  entitlement; current Cloudflare self-serve terms make deliberate large-media
  delivery a zero-spend `NO-GO`.

See [architecture](docs/architecture/overview.md), [kubeadm decision](docs/adr/0011-kubeadm-on-pi.md),
[legacy archive decision](docs/adr/0013-protected-legacy-archive.md),
[security controls](docs/security/security-control-matrix.md), and the
[Cloudflare zero-spend ADR](docs/adr/0006-cloudflare-zero-spend.md). Credential
work on Windows follows the
[protected workstation ceremony](docs/runbooks/windows-credential-ceremony.md),
and every authenticated OpenTofu operation follows the
[Cloudflare state-custody runbook](docs/runbooks/cloudflare-state-custody.md).
Secret-bearing age/SOPS and kubectl work follows the separate
[protected Linux Flux ceremony](bootstrap/flux/README.md); a Windows-local
attestation hash is not portable authorization for it.

## Layout

```text
bootstrap/             user-run Pi, Flux, and recovery procedures
docs/                  architecture, decisions, security, and runbooks
infrastructure/        credential-free OpenTofu configuration and policy
kubernetes/            desired state for the current single Kubernetes environment
policies/              Conftest and Kyverno controls
scripts/               discovery, validation, promotion, and verification
tests/                 allow/deny fixtures and repository-level tests
websites/              website source and container build context
```

Directories named `apps`, `clusters`, or `kubernetes/homelab` are forbidden.
Environment nesting is deferred until a second real Kubernetes environment
exists.

## Tailored here, reusable as a fork

This repository is intentionally opinionated for its operator's public identities:
the two domains, repository owner, release names, and zero-spend choices are
visible and tested as one coherent system. It does not publish local host paths,
service inventory, account/zone IDs, addresses, emails, machine IDs, plans, or
credentials. Someone else can clone it as a reference or fork it, but should
replace each complete identity tuple—domain, source/module/package, image,
chart/namespace/Flux release, workflow/signature, DNS variable, Tunnel rule, and
tests—rather than search-and-replacing one label. All discovery values stay
sentinel/local until that fork's own hardware, account, entitlement, backup, and
recovery evidence passes. This is a reusable fail-closed platform pattern, not a
one-command deployment template.

## Local validation

Run `make check` on a workstation with the pinned tools from `versions.env`.
`make check-fast` performs credential-free static checks and does not contact
the Pi, GitHub, Cloudflare, or a registry. Validation never runs `tofu plan` or
`tofu apply` automatically. Each pull request also builds both frontends,
rejects remote or unhashed generated resources, source maps, and explicit
artifact-size budget overruns, then serves the exact embedded bundles through
the production Go handlers to verify cache identities and browser-security
headers. These deterministic checks are not a claim about Core Web Vitals;
live browser timing remains pending until a real edge URL exists and browser
use is explicitly authorized.

The optional [disposable Kind harness](docs/runbooks/local-kind.md) checks
rendered local artifacts against a short-lived workstation cluster. It is not
the production runtime or a substitute for kubeadm/Pi acceptance.

## Deployment state

| Gate | State |
| --- | --- |
| Repository and policies | Credential-free scaffold and negative-policy tests implemented; live evidence remains absent |
| Pi discovery | Read-only discovery completed; current private evidence remains outside Git |
| Independent recovery + simultaneous two-session gate | Not proven; all host/network/cluster mutation blocked |
| Protected legacy archive | Local root-private archive exists; independent encrypted off-device restore proof remains absent |
| Media storage/profile | Disabled; SSD/filesystem/backup evidence not collected |
| Public heavy-media delivery | NO-GO under current zero-spend Cloudflare boundary |
| Cloudflare subscription audit | Not run |
| kubeadm/containerd installation | Not run |
| CNI and kube-proxy-mode decision | Blocked on Pi network discovery |
| kubeadm cluster initialization | Not run |
| Flux bootstrap | Not run |
| SOPS key ceremony | Not run |
| Cloudflare plan/apply | Not authorized |
| Public exposure | Not authorized |

No script in this repository should be interpreted as authorization to mutate
an external system. Each mutation runbook has an explicit stop point.
