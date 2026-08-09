# Discovery record

Discovery is read-only and precedes every host or Cloudflare mutation. Run the
scripts locally; do not commit their output because it contains sensitive
topology even after automatic redaction.

Start with `scripts/discover-pi.sh` (or explicit `--local-only`); local-only is
the fail-closed default and its report must state that external egress probes
were skipped. Do not use explicit `--with-egress` until
the operator has privately proved the existing VPN, DNS, IPv4/IPv6,
kill-switch, firewall, and policy-routing behavior. Even redacted output needs
manual review and remains local.

Before bootstrap preflight, create the ignored, mode-`0600`
`bootstrap/pi/protected-services.env.local` contract. It contains separately
reviewed active services and inactive legacy archives: archive presence and all
generic activation classes are explicit; active service units must stay active;
every declared legacy system-manager service/socket/timer/path unit must be
exactly inactive, without a control group, and persistently disabled/masked;
and every archive root must remain a dedicated canonical non-symlink directory
with private access and the reviewed mount-binding digest. Copy the example,
derive bindings with `scripts/validate_protected_host_contract.py CONTRACT
--emit-bindings`. For either archive-presence decision, complete the fixed
adjacent runtime-review attestation from fresh private evidence, make its
presence value match the contract, and bind its emitted SHA-256. Only then set
the two review flags to `yes` and run `--check-live`; exact names, roots, boot
binding, and both local files stay off Git, while diagnostics report only
indexed checks.
Classification is not inventory, and any unclassified or `UNKNOWN` item blocks
mutation.

## Local preflight

Run the repository preflight from a trusted local workstation before
validation. Treat its results as ephemeral environment evidence: install
nothing automatically, leave unavailable checks pending, and never commit the
tool inventory or preflight output.

## Values that must be resolved outside Git

- Pi hostname/admin user, stable private IP `/32`, LAN CIDR, SSD mount, and
  Kubernetes private hostname;
- Pod/Service CIDRs after checking all VPN/policy routes;
- Cloudflare account/zone/tunnel/route/policy/posture IDs and safe precedences;
- primary/secondary zones and canonical public hostname;
- actual public website image digest;
- age public recipient (private identity never recorded here);
- encrypted off-device backup destination and recovery targets;
- exact protected legacy activation edges, dedicated archive roots,
  content-neutral manifest, secret-backup/restore result, and rollback plan;
- exact upstream Kubernetes, containerd, CRI, etcd-recovery, and control-plane
  image versions/checksums/signatures revalidated at execution time;
- CNI and kube-proxy-mode decision after Pi networking discovery; kube-proxy
  remains installed. Also require reviewed `images.lock.local` and rendered
  `cni-manifest.local.yaml`.

## Exit decision

Record each required gate as `PASS`, `FAIL`, or `UNKNOWN` with date/source.
`UNKNOWN` blocks mutation. Pi must be ARM64, SSD-backed/healthy, cgroup-ready,
time/DNS healthy, and conflict-free. Before kubeadm initialization, inventory
the actual nftables/iptables backend, kernel modules, VPN/tunnel interfaces,
kill-switch behavior, firewall, routes, and policy rules; prove Pod/Service
CIDRs do not overlap; then choose and review CNI and kube-proxy behavior
explicitly. Both zones and Zero Trust must be confirmed Free with no
paid/trial/usage subscription. Any pre-existing active protected services must
remain active; declared legacy activation units must remain inactive and not
enabled, their archive roots must remain stable, and networking state remains
unchanged until separately reviewed. Follow the
[protected legacy archive runbook](../runbooks/protected-legacy-archive.md).
Any stale K3s state is a migration stop, not permission to run an uninstall
script.

Kind may be added later for disposable local manifest/policy integration tests.
Its container nodes cannot prove Raspberry Pi networking, SSD placement,
systemd behavior, reboot, snapshot, or restore gates.
