# Discovery record

Discovery is read-only and precedes every host or Cloudflare mutation. Run the
scripts locally; do not commit their output because it contains sensitive
topology even after automatic redaction.

Before Pi discovery, create the ignored, mode-`0600`
`bootstrap/pi/protected-services.env.local` contract. It must contain exactly
one `PROTECTED_SERVICES_REVIEWED=yes` line and may contain zero or more
`PROTECTED_SYSTEMD_UNIT=<name>.service` lines for units reviewed locally. Unit
names and the file stay off Git; discovery and preflight diagnostics report
only redacted status and indexed checks.

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
paid/trial/usage subscription. Any pre-existing protected host services and
networking state remain unchanged if present. Any stale K3s state is a
migration stop, not permission to run an uninstall script.

Kind may be added later for disposable local manifest/policy integration tests.
Its container nodes cannot prove Raspberry Pi networking, SSD placement,
systemd behavior, reboot, snapshot, or restore gates.
