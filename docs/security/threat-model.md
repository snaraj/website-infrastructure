# Threat model

## Assets and assumptions

Protected assets include GitHub/Cloudflare control planes, the Pi and SSD,
irreplaceable media originals and publication metadata, desired state, age
identity, tunnel tokens, Kubernetes PKI/API-encryption keys, user traffic, and
domain renewal continuity. The Internet, public repository
readers, pull requests, container images, the home network, and compromised
workloads are untrusted. The operator
laptop is trusted only while patched, strongly authenticated, and physically
controlled.

## Critical threats and controls

| Threat | Prevent | Detect | Recover |
| --- | --- | --- | --- |
| GitHub takeover or malicious merge | Passkey/MFA, protected main, least privilege, signed review path | audit log, CI, Flux revision | revoke sessions, revert commit, rotate affected values |
| Compromised Action/PR | full-SHA pins, read-only PR token, no infra secrets, GitHub runners | dependency review, action policy, CodeQL/scans | pin/revert, invalidate artifacts |
| Flux privilege escalation | explicit SAs, no cross-namespace refs/remote bases, no Git credential | RBAC/policy tests, audit metadata | suspend/revert, rotate age identity if exposed |
| Stolen cluster age identity | two operator-wrapped restore-tested backups, private key only in `flux-system`, never CI/chat | unexpected decrypt access is hard to prove; monitor workstation/cluster access | new identity, re-encrypt, rotate every credential exposed through repository history |
| Stolen operator-wrapping identity or OpenTofu state | separate identity on BitLocker/ACL workspace, opaque age archives, phase-separated state, never Pi/Git/CI | workspace access evidence, lineage/serial/hash receipts, exact-index/history gates | replace wrapping identity, re-encrypt archives, rotate retained bearer credentials; treat topology/state disclosure as permanent |
| Tunnel token leak or wrong-Tunnel substitution | tunnel-specific token created on the cluster, never in Git, no API token, separate tunnels, independent account/Tunnel-ID digests | protected MAC/plaintext-identity proof, active systemd credential equality/redaction, connector inventory | revoke/rotate one tunnel, force-disconnect on compromise, verify the other unchanged |
| Stolen Pi/SSD | disk/physical controls, Kubernetes API encryption at rest | inventory/availability alert | revoke tokens/keys, rebuild, restore tested backup |
| Accidental legacy workload reactivation | separate must-inactive unit contract, every activation edge disabled, no installer/update/restore path | indexed unit active/enabled checks plus process/listener and reboot evidence | suspend platform mutation, restore hash-bound inactive state without starting the workload |
| Legacy wallet, anonymity identity, or topology disclosure | no content in Git/chat/catalog, operator encryption and separate off-device restore proof, minimized indexed diagnostics | repository privacy tests and owner-reported restore result | isolate host, revoke/rotate affected network credentials or identities where possible, reassess archive trust |
| Legacy archive overwrite or Kubernetes exposure | dedicated canonical private root, mount binding, no PV/hostPath/Flux/CI authority, excluded capacity | local contract validator, rendered-manifest and repository policy checks | stop workloads, preserve evidence, restore only to isolated storage after integrity review |
| Compromised website | restricted pod, digest/signature, no token/egress, default deny | runtime/events/Tunnel logs | roll back digest, isolate namespace, rebuild |
| Media traversal, link, or mount-boundary escape | traversal-resistant rooted opens, regular-file/segment/link checks, read-only derivative-only mount, pending bind-mount acceptance | focused malformed-path/symlink/hard-link tests plus mount-boundary audit | suspend route, preserve volume read-only, roll back digest and inspect publication boundary |
| Malicious or partial media publication | protected operator path, checksum verification, same-filesystem atomic rename, no public upload API | manifest/checksum comparison and unreachable staging tests | remove unpublished derivative, regenerate from verified original |
| Media corruption or data-volume loss | originals separated from derivatives, encrypted off-device originals/metadata backup | scheduled checksum sampling, filesystem health, timed restore drill | restore originals/metadata and regenerate delivery derivatives; etcd is not a media backup |
| Media fills root/control-plane storage | repository-wide size/magic/aggregate gates, narrow Flux artifacts, capped OCI app layer, separate reviewed data filesystem, no container writes | CI negative tests, source-controller/OCI size evidence, filesystem alerts, kubelet DiskPressure, root/data mount verification | block publication, suspend public load, retain SSH/admin path; never delete originals automatically |
| Public load starves administration | measured system/Kubernetes reserves, workload limits, bounded-memory serving, host-level admin Tunnel | CPU/memory/disk/network saturation acceptance | suspend public Tunnel/workloads while host SSH and API recovery remain available |
| Direct-origin bypass | no forwarding/listeners/DNS origin, outbound Tunnel | external port scan and DNS audit | remove exposure/firewall rule, rotate if needed |
| Unsigned image substitution | exact chart digest plus Flux cosign verification bound to protected-main publisher; digest-only workload | CI hostile source/image fixtures and live SourceVerified status | block selection, review an exact prior digest, investigate publisher |
| Accidental Flux prune | scoped paths/SAs, review, health checks | Flux events/diff | Git revert; restore persistent data separately |
| kubeadm/stacked-etcd loss | SSD preflight, compatible pins, snapshots, protected PKI/encryption backup | snapshot, certificate-expiry, and disk-health checks | compatible-version restore drill then reconcile Git |
| Host-network conflict | discovery-gated CNI/kube-proxy, conflict-free CIDRs, no automatic firewall/VPN edits | route, nftables/iptables, VPN/tunnel-interface, policy-routing, and connectivity tests | retain LAN/physical access; restore reviewed host/network state |
| Cloudflare takeover | passkey/MFA, minimal admins, JIT/IP-bounded audit/apply tokens, separate phase state | audit log, token-policy/revocation receipts, read-only inventory | revoke, re-establish tunnels/DNS from reviewed state one phase at a time |
| Paid feature activation | strict resource/product allowlist, no Billing Write, plan gate | pre/post subscription audit and budget alert | stop change, preserve evidence, disable if safe, dispute/escalate |

## Acceptance

Each critical threat has prevention, detection, and recovery. The proposed media
volume remains disabled until ADR 0012's discovery and recovery evidence exists.
A new public route, API, identity system, database, persistent volume, operator,
cluster, or paid exception reopens this model. Residual single-node and ISP
outage risk is accepted.
