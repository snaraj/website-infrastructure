# Persistent kubeadm host prerequisites — Draft / Pi-unverified

This subsystem owns exactly two persistent files:

- `/etc/modules-load.d/90-website-infrastructure-kubeadm.conf`
- `/etc/sysctl.d/90-website-infrastructure-kubeadm.conf`

It may also make an exact, backed-up `/etc/fstab` edit, but only when discovery
proves that every configured and active swap source is `fstab-only`. Native
systemd `.swap` units, dphys-swapfile, ZRAM, mixed sources, unresolvable specs,
or any unknown signal are a hard stop. No script uses `swapoff -a`, unloads a
module, sources the review plan, or reloads every host sysctl file.

On the Pi, enter a root shell through tested physical/LAN recovery, set
`umask 077`, and redirect `bash discover-host-prerequisites.sh` to a root-owned
plan outside the repository. Discovery is read-only. Review the resulting hashes,
current sysctls, exact targets, module availability, and swap classification;
then change only `PLAN_STATUS` from `review-required` to
`approved-after-host-discovery`. A reboot, OS/kernel change, target-file edit,
sysctl change, or swap change invalidates the plan and requires fresh discovery.
If `br_netfilter` is not loaded, discovery may record only its two `net.bridge.*`
keys as `unavailable-until-module-load`. Apply captures and hash-binds their
natural post-load values before its first sysctl write so rollback never guesses
a kernel default.

Run `bash apply-host-prerequisites.sh --check --plan /root/<reviewed-plan>` first.
It prints acknowledgements bound to the plan and exact active-swap hashes. Apply
requires all printed values plus `PHYSICAL_OR_LAN_RECOVERY_TESTED=yes`. The
script creates a root-only transaction under
`/var/backups/website-infrastructure/host-prerequisites`, backs up every exact
target before mutation, applies only the committed module/sysctl files, verifies
the live result, and records active state under
`/var/lib/website-infrastructure/host-prerequisites`.

Immediately run `bash verify-host-prerequisites.sh --post-apply`. Reboot through
the normal reviewed host procedure, then run
`bash verify-host-prerequisites.sh --post-reboot`. The latter fails unless the
boot ID changed and the exact files, loaded modules, runtime sysctls, and absent
swap survived the reboot. Do not proceed to kubeadm until it passes.

For rollback, use the transaction ID printed by apply:

```text
bash rollback-host-prerequisites.sh --check --transaction <exact-id>
```

The check prints the hash-bound rollback acknowledgement. Apply mode also
requires tested recovery. Rollback refuses to overwrite target drift, restores
the exact backups and prior runtime sysctl/swap state, and retains transaction
evidence. Modules loaded by apply remain loaded until a reviewed reboot. If an
automatic rollback reports incomplete recovery, stop and use physical/LAN
recovery; do not delete the pending state or backup transaction.
