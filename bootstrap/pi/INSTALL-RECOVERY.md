# Kubernetes installer recovery

`install-kubernetes.sh --apply` builds and collision-checks a complete target
manifest before its first host mutation. Each target is then committed with an
exclusive same-directory hard link, so a file that appears concurrently is
never overwritten.

If a normal command failure or `HUP`, `INT`, or `TERM` occurs after mutation
starts, the exit handler prints the failed `phase=...` and one of these states:

- `rollback=complete`: the installer stopped/disabled the services it introduced,
  removed only targets whose hashes still match this transaction, reloaded
  systemd, and removed newly created directories when empty. Run `--check`
  again before repeating the reviewed `--apply` invocation.
- `rollback=incomplete`: do not rerun the installer and do not run kubeadm.
  Use the already tested physical or LAN recovery path and inspect only the
  exact residual paths printed by the installer. A changed target is left in
  place deliberately; the rollback never deletes a path it can no longer prove
  it installed.

`SIGKILL`, kernel panic, storage failure, or loss of power cannot run a shell
trap. After one of those events, do not assume rollback occurred. Reconnect over
the tested recovery path, preserve the console output, and run `--check`. An
existing target is treated as a stop condition, never as permission to replace
it. The installer never runs `kubeadm init`, so control-plane recovery is not
part of this installation transaction.
