# Raspberry Pi kubeadm bootstrap — Draft / unverified

No command here has run on the Pi. Production is one upstream Kubernetes node
bootstrapped with kubeadm, using containerd and stacked single-member etcd. Keep
any pre-existing protected host services, VPN/tunnel interfaces, kill-switch
behavior, firewall, and policy routing unchanged.

1. Confirm physical/LAN recovery. Copy `protected-services.env.example` to the
   ignored `protected-services.env.local`, restrict it to mode `0600`, and keep
   exactly one `PROTECTED_SERVICES_REVIEWED=yes` line plus zero or more
   `PROTECTED_SYSTEMD_UNIT=<name>.service` lines for locally reviewed protected
   units. Never commit the file or its unit names. Run `scripts/discover-pi.sh`
   locally on the Pi and manually review its redacted output; diagnostics refer
   to protected entries without printing their names.
2. Copy `decisions.env.example` to ignored `decisions.env.local`,
   `kubeadm-config.yaml.example` to ignored `kubeadm-config.yaml.local`, and
   `encryption-config.yaml.example` to ignored `encryption-config.yaml.local`.
   Copy `images.lock.example` to ignored `images.lock.local` only after exact
   image import. Resolve only verified values and keep encryption key material
   out of Git, logs, terminals, and chat.
3. Do not choose a CNI or kube-proxy mode by assumption. kube-proxy remains
   installed; replacement is outside this contract. Inventory the real
   routes, Pod/Service CIDR conflicts, nftables/iptables backend, VPN/tunnel
   interfaces, kill-switch behavior, firewall, and policy routing. A reviewed
   `images.lock.local` and rendered `cni-manifest.local.yaml` are required local
   artifacts; the latter must match the exact provider/version, Pod CIDR, MTU,
   tunnel/host-port matrix, digest images, and installed kube-proxy contract.
   Both remain `NO-GO` until discovery produces that separate decision.
4. Follow `host-prerequisites/README.md`: generate and review the inert plan,
   run the hash-bound transactional apply, verify immediately, reboot through
   tested recovery, and complete `verify-host-prerequisites.sh --post-reboot`.
   Unknown swap mechanisms or target drift are a hard stop.
5. Run `preflight.sh` until every failure is resolved. It must prove ARM64,
   cgroups, persistent swap/sysctl/module state, reviewed SSD backing/capacity, ports, kernel
   prerequisites, and an unambiguous clean-or-migration state without changing
   the host. Any detected pre-existing protected host services or stale
   K3s/Kubernetes state require human review, never automated removal.
6. On a trusted workstation, obtain every exact pinned ARM64 Kubernetes,
   containerd, CRI, etcd-recovery, and image artifact from official sources.
   Verify independent checksums/signatures and stage them locally; never pipe
   network content to a shell. Stage the recovery archive as
   `.artifacts/bootstrap-arm64/etcd-v${ETCD_VERSION}-linux-arm64.tar.gz` and
   cri-tools as
   `.artifacts/bootstrap-arm64/crictl-v${CRICTL_VERSION}-linux-arm64.tar.gz`.
   Their pinned checksums come from the respective signed GitHub releases and
   must still be independently rechecked immediately before production use.
7. Run `install-kubernetes.sh --check`. Its apply mode installs only the
   reviewed runtime/node tools and containerd configuration; it does not grant
   permission to initialize the cluster or change VPN/firewall rules.
8. Run `install-recovery-tools.sh --check`. Its root-only apply mode requires
   `PHYSICAL_OR_LAN_RECOVERY_TESTED=yes`,
   `CONFIRM_ETCD_TOOLS_INSTALL=install-reviewed-etcd-tools-${ETCD_VERSION}`, and
   `CONFIRM_ETCD_SNAPSHOT_TIMER=enable-reviewed-six-hour-etcd-snapshots`. It
   installs only the verified `etcdctl`/`etcdutl` binaries, the snapshot helper,
   root-owned local decision/version copies, and the six-hour systemd timer.
9. Run `init-control-plane.sh --check`. Only after CNI and kube-proxy-mode decisions,
   local artifacts, preflight evidence, rollback, and exact acknowledgement are
   reviewed may an authorized operator initialize the control plane and install
   the chosen dataplane.
10. Run `verify.sh`; prove containerd, kubelet, API server, scheduler, controller
   manager, stacked etcd, CoreDNS, the chosen CNI/kube-proxy mode, Pod Security,
   audit logging, API encryption, and workload scheduling. Create and verify an
   etcd snapshot, copy it and required PKI/encryption material separately and
   encrypted off-device, reboot, then verify again before Flux.

After the control plane is healthy, run the read-only operational check with
`sudo /usr/local/sbin/website-infrastructure-etcd-snapshot --check`. Create an
immediate snapshot with
`sudo env CONFIRM_ETCD_SNAPSHOT=create-reviewed-stacked-etcd-snapshot /usr/local/sbin/website-infrastructure-etcd-snapshot --apply`.
Inspect scheduling with
`sudo systemctl status website-infrastructure-etcd-snapshot.timer` and inspect
non-secret results with
`sudo journalctl -u website-infrastructure-etcd-snapshot.service`. The helper
stores mode-`0600`, root-owned snapshots under
`/var/backups/kubernetes/etcd`, verifies each with the pinned `etcdutl`, and
retains fourteen. It deliberately does not copy or encrypt anything off-device;
that remains a reviewed manual step.

`configure-host.sh` defaults to inspection. Its apply mode changes only reviewed
SSH and journald drop-ins, backs up exact files, validates sshd, and requires a
tested second session. It never changes firewall/VPN rules or installs updates.

Kind is permitted only for disposable workstation integration tests. It is not
the Pi installation path, production parity, or evidence for networking,
storage, reboot, snapshot, or restore acceptance. All upstream pins remain
fail-closed until independently verified immediately before use.
