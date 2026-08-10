# Raspberry Pi kubeadm bootstrap — Draft / unverified

No command here has run on the Pi. Production is one upstream Kubernetes node
bootstrapped with kubeadm, using containerd and stacked single-member etcd. Keep
any pre-existing protected host services, VPN/tunnel interfaces, kill-switch
behavior, firewall, and policy routing unchanged.

1. Confirm physical/LAN recovery and retain two SSH sessions. Run
   `scripts/discover-pi.sh --local-only` on the Pi before any egress probe and
   manually review its redacted output. Copy `protected-services.env.example`
   to the ignored `protected-services.env.local`, restrict it to mode `0600`,
   explicitly choose `PROTECTED_LEGACY_ARCHIVES_PRESENT=yes|no`, classify every
   committed generic activation class, and classify active protected services
   separately from inactive legacy system-manager service/socket/timer/path
   units and dedicated archive roots. When archives are present, derive one
   bounded metadata-only binding per root with
   `python3 scripts/validate_protected_host_contract.py bootstrap/pi/protected-services.env.local --emit-bindings`,
   and append the hashes in root order. Then copy
   `protected-legacy-runtime-evidence.example` to the fixed adjacent ignored
   `protected-legacy-runtime-evidence.local`, restrict it to mode `0600`, and
   complete every field from a fresh private review on the current boot without
   executing a legacy product. Validate and bind that evidence by running
   `python3 scripts/validate_protected_runtime_evidence.py bootstrap/pi/protected-services.env.local --emit-sha256`
   and append its single emitted assignment to the protected-services contract.
   The emitter securely reads that adjacent contract and refuses to emit when
   the two presence decisions differ; its digest output is binding material,
   never mutation authorization.
   The evidence and its binding are required for both `yes` and `no`, are valid
   for at most 600 seconds, and become invalid after any reboot. Its
   `LEGACY_ARCHIVES_PRESENT` field must match the contract, and
   `ARCHIVE_INVENTORY_STATUS=PASS` is written only after the private storage
   inventory supports that decision. This prevents a `yes` contract from being
   changed to `no` merely by deleting its archive declarations.
   This remains a boot-bound, bounded operator attestation to separately reviewed
   evidence, not a claim that the validator machine-probed every status. Only
   declared system-manager unit and archive root/binding state currently have
   equivalent live machine probes in the gate.
   Then set exactly one
   `PROTECTED_SERVICES_REVIEWED=yes` and one
   `PROTECTED_LEGACY_ARCHIVES_REVIEWED=yes`. From the repository root, run
   `python3 scripts/validate_protected_host_contract.py bootstrap/pi/protected-services.env.local --check-live`.
   Never commit its values; diagnostics use indexes rather than printing
   identities. Follow the
   [legacy archive runbook](../../docs/runbooks/protected-legacy-archive.md)
   before treating that capacity as available.
2. Copy `decisions.env.example` to ignored `decisions.env.local` and
   `kubeadm-config.yaml.example` to ignored `kubeadm-config.yaml.local`.
   Do not hand-edit `encryption-config.yaml.example` and do not invoke
   `generate-encryption-config.sh` yet. Its latent no-display implementation is
   reviewable, but the entrypoint is code-blocked before key generation because
   an already-running mutable Bash file cannot attest its own stage-zero trust.
   Reopening it requires a separately installed reviewed-blob launcher that
   enters through a clean environment, extracts exact reviewed commit blobs
   into protected custody, and holds stable file handles. Until that launcher
   and its adversarial tests exist, do not supply secret-bearing environment
   variables and do not generate the production API-encryption key. You may
   prepare the separate Linux AMD64 LUKS-backed credential volume, disable swap,
   core dumps, cloud sync, and session recording, and prepare two independent
   encrypted backup destinations, but no key ceremony is authorized.
   After the blocker is resolved, the fixed mode-`0600`
   `api-encryption-config.yaml` must remain outside the repository, be supplied
   as `ENCRYPTION_CONFIG_PATH` only for the reviewed preflight/bootstrap
   session, and have two independently restore-tested encrypted backups before
   `ENCRYPTION_KEY_BACKUP_PROVEN=yes` is set.
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
   the host. Active protected services must remain active; declared legacy
   system-manager units must remain exactly inactive, persistently
   disabled/masked, and without a control group; root bindings must remain
   stable. For other runtime-evidence statuses, preflight validates the bounded
   attestation and does not independently observe the underlying fact. Any drift,
   unclassified state, or stale K3s/Kubernetes state requires human review,
   never automated removal.
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
   reviewed runtime/node tools and containerd configuration. Apply re-runs the
   complete protected-host preflight after artifact staging and collision
   checks, immediately before its transaction can create a host target. It does
   not grant permission to initialize the cluster or change VPN/firewall rules.
8. Run `install-recovery-tools.sh --check`. Its root-only apply mode requires
   `PHYSICAL_OR_LAN_RECOVERY_TESTED=yes`,
   `CONFIRM_ETCD_TOOLS_INSTALL=install-reviewed-etcd-tools-${ETCD_VERSION}`, and
   `CONFIRM_ETCD_SNAPSHOT_TIMER=enable-reviewed-six-hour-etcd-snapshots`. It
   installs only the verified `etcdctl`/`etcdutl` binaries, the snapshot helper,
   root-owned local decision/version copies, and the six-hour systemd timer.
9. Run `init-control-plane.sh --check`. Only after CNI and kube-proxy-mode
   decisions, local artifacts, preflight evidence, rollback, and exact
   acknowledgement are reviewed may an authorized operator initialize the
   control plane and install the chosen dataplane. Apply re-runs the complete
   protected-host preflight after image validation and kubeadm dry-run,
   immediately before creating the first `/etc/kubernetes` path.
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
