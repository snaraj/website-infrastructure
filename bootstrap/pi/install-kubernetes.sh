#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"

die() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

check_sha() {
  local expected="$1"
  local path="$2"
  [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || die "unresolved SHA-256 for ${path}"
  [[ -f "${path}" && ! -L "${path}" ]] || die "staged artifact is not a regular file: ${path}"
  printf '%s  %s\n' "${expected}" "${path}" | sha256sum --check --status || \
    die "SHA-256 mismatch: ${path}"
}

# Validate both the archive namespace and the tar member type before extraction.
# The pinned archives may contain only regular files and directories. In
# particular, links, devices, sockets and FIFOs are rejected rather than being
# extracted into a privileged staging directory.
safe_archive() {
  local path="$1"
  local pattern="$2"
  local names metadata entry line member_type
  local name_count=0
  local metadata_count=0

  names="$(tar -tzf "${path}")" || die "cannot list archive: ${path}"
  metadata="$(LC_ALL=C tar -tvzf "${path}")" || die "cannot inspect archive member types: ${path}"
  [[ -n "${names}" ]] || die "archive is empty: ${path}"

  while IFS= read -r entry; do
    [[ -n "${entry}" ]] || die "archive contains an empty member name: ${path}"
    [[ "${entry}" != /* \
      && "${entry}" != '.' \
      && "${entry}" != './' \
      && "${entry}" != '..' \
      && "${entry}" != '../' \
      && "${entry}" != ../* \
      && "${entry}" != */../* \
      && "${entry}" != */.. ]] || \
      die "unsafe archive path in ${path}: ${entry}"
    [[ "${entry}" =~ ${pattern} ]] || die "unexpected archive member in ${path}: ${entry}"
    ((name_count += 1))
  done <<< "${names}"

  while IFS= read -r line; do
    [[ -n "${line}" ]] || die "archive has malformed verbose metadata: ${path}"
    member_type="${line:0:1}"
    case "${member_type}" in
      -|d) ;;
      l|h) die "archive links are forbidden in ${path}" ;;
      b|c) die "archive devices are forbidden in ${path}" ;;
      p|s) die "archive special files are forbidden in ${path}" ;;
      *) die "unsupported archive member type '${member_type}' in ${path}" ;;
    esac
    ((metadata_count += 1))
  done <<< "${metadata}"

  [[ "${name_count}" -eq "${metadata_count}" ]] || \
    die "archive name/type listing count mismatch: ${path}"
}

validate_extracted_tree() {
  local root="$1"
  local pattern="$2"
  local path relative
  local -a entries=()

  mapfile -d '' entries < <(find "${root}" -mindepth 1 -print0 | sort -z)
  ((${#entries[@]} > 0)) || die "extracted archive is empty: ${root}"
  for path in "${entries[@]}"; do
    relative="${path#"${root}/"}"
    [[ "${relative}" =~ ${pattern} ]] || die "unexpected extracted path: ${relative}"
    [[ ! -L "${path}" ]] || die "extracted archive contains a link: ${relative}"
    [[ -f "${path}" || -d "${path}" ]] || die "extracted archive contains a special file: ${relative}"
  done
}

validate_directory_chain() {
  local directory="$1"
  local current=''
  local component
  local -a components=()

  [[ "${directory}" == /* ]] || die "target directory is not absolute: ${directory}"
  IFS='/' read -r -a components <<< "${directory#/}"
  for component in "${components[@]}"; do
    [[ -n "${component}" ]] || continue
    current="${current}/${component}"
    if [[ -L "${current}" ]]; then
      die "target directory chain contains a symlink: ${current}"
    fi
    if [[ -e "${current}" && ! -d "${current}" ]]; then
      die "target directory chain contains a non-directory: ${current}"
    fi
  done
}

ensure_directory() {
  local directory="$1"
  local mode="$2"
  local current=''
  local component
  local -a components=()

  IFS='/' read -r -a components <<< "${directory#/}"
  for component in "${components[@]}"; do
    [[ -n "${component}" ]] || continue
    current="${current}/${component}"
    if [[ -L "${current}" ]]; then
      die "target directory chain became a symlink: ${current}"
    elif [[ -e "${current}" ]]; then
      [[ -d "${current}" ]] || die "target directory chain became invalid: ${current}"
    else
      install -d -o 0 -g 0 -m "${mode}" "${current}"
      created_directories+=("${current}")
    fi
  done
}

add_target() {
  local source="$1"
  local destination="$2"
  local mode="$3"

  [[ -f "${source}" && ! -L "${source}" ]] || die "install source is not a regular file: ${source}"
  [[ "${destination}" == /* ]] || die "install destination is not absolute: ${destination}"
  [[ "${mode}" =~ ^0[0-7]{3}$ ]] || die "invalid target mode for ${destination}: ${mode}"
  [[ -z "${seen_targets["${destination}"]+present}" ]] || die "duplicate install target: ${destination}"
  seen_targets["${destination}"]=1
  target_sources+=("${source}")
  target_destinations+=("${destination}")
  target_modes+=("${mode}")
}

assert_target_vacant() {
  local destination="$1"
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    die "refusing to overwrite existing install target: ${destination}"
  fi
}

# Copy to a unique file in the destination directory and use hard-link creation
# as an atomic, no-clobber commit. ln(2) fails with EEXIST if a target appears
# after the pre-mutation collision check.
exclusive_install() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local parent base source_hash staged_hash

  parent="$(dirname "${destination}")"
  base="$(basename "${destination}")"
  pending_destination="$(mktemp -p "${parent}" ".${base}.website-infrastructure.XXXXXX")"
  install -o 0 -g 0 -m "${mode}" "${source}" "${pending_destination}"
  source_hash="$(sha256sum "${source}" | awk '{print $1}')"
  staged_hash="$(sha256sum "${pending_destination}" | awk '{print $1}')"
  [[ "${source_hash}" == "${staged_hash}" ]] || die "staged target hash mismatch: ${destination}"
  if ! ln -- "${pending_destination}" "${destination}"; then
    die "target appeared during installation; refusing overwrite: ${destination}"
  fi
  installed_destinations+=("${destination}")
  installed_hashes+=("${staged_hash}")
  rm -- "${pending_destination}"
  pending_destination=''
}

rollback_installation() {
  local rollback_failed=0
  local index path expected actual

  if [[ "${service_mutation_started}" == 'yes' ]]; then
    systemctl disable --now kubelet.service >/dev/null 2>&1 || true
    systemctl disable --now containerd.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet kubelet.service 2>/dev/null \
      || systemctl is-active --quiet containerd.service 2>/dev/null \
      || systemctl is-enabled --quiet kubelet.service 2>/dev/null \
      || systemctl is-enabled --quiet containerd.service 2>/dev/null; then
      printf 'RECOVERY service state could not be restored to absent/disabled.\n' >&2
      rollback_failed=1
    fi
  fi

  if [[ -n "${pending_destination}" ]]; then
    if [[ -f "${pending_destination}" && ! -L "${pending_destination}" ]]; then
      rm -- "${pending_destination}" || rollback_failed=1
    elif [[ -e "${pending_destination}" || -L "${pending_destination}" ]]; then
      printf 'RECOVERY refusing to remove changed pending path: %s\n' "${pending_destination}" >&2
      rollback_failed=1
    fi
  fi

  for ((index=${#installed_destinations[@]} - 1; index >= 0; index--)); do
    path="${installed_destinations[index]}"
    expected="${installed_hashes[index]}"
    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
      continue
    fi
    if [[ -f "${path}" && ! -L "${path}" ]]; then
      actual="$(sha256sum "${path}" | awk '{print $1}')"
      if [[ "${actual}" == "${expected}" ]]; then
        rm -- "${path}" || rollback_failed=1
        continue
      fi
    fi
    printf 'RECOVERY refusing to remove changed installed target: %s\n' "${path}" >&2
    rollback_failed=1
  done

  systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1

  for ((index=${#created_directories[@]} - 1; index >= 0; index--)); do
    path="${created_directories[index]}"
    if [[ -d "${path}" && ! -L "${path}" ]]; then
      rmdir -- "${path}" 2>/dev/null || rollback_failed=1
    elif [[ -e "${path}" || -L "${path}" ]]; then
      printf 'RECOVERY refusing to remove changed created directory: %s\n' "${path}" >&2
      rollback_failed=1
    fi
  done

  return "${rollback_failed}"
}

cleanup_temporary() {
  if [[ -n "${temporary}" && -d "${temporary}" && ! -L "${temporary}" ]]; then
    rm -rf -- "${temporary}"
  fi
}

on_exit() {
  local status=$?
  local failed_phase="${phase}"
  local rollback_status=0
  trap - EXIT INT TERM HUP
  set +e

  if [[ "${status}" -ne 0 && "${transaction_started}" == 'yes' && "${transaction_complete}" != 'yes' ]]; then
    rollback_installation
    rollback_status=$?
    if [[ "${rollback_status}" -eq 0 ]]; then
      printf 'RECOVERY phase=%s rollback=complete; no cluster initialization was attempted.\n' "${failed_phase}" >&2
      printf 'RECOVERY correct the failure, run --check, then repeat the reviewed --apply invocation.\n' >&2
    else
      printf 'RECOVERY phase=%s rollback=incomplete; do not rerun or initialize the cluster.\n' "${failed_phase}" >&2
      printf 'RECOVERY use physical/LAN access and inspect only the exact residual paths reported above.\n' >&2
    fi
  fi

  cleanup_temporary
  exit "${status}"
}

main() {
  local mode="${1:---check}"
  local artifact_dir="${KUBERNETES_ARTIFACT_DIR:-${repo_root}/.artifacts/bootstrap-arm64}"
  local containerd_archive="${artifact_dir}/containerd-${CONTAINERD_VERSION}-linux-arm64.tar.gz"
  local runc_binary="${artifact_dir}/runc.arm64"
  local cni_archive="${artifact_dir}/cni-plugins-linux-arm64-v${CNI_PLUGINS_VERSION}.tgz"
  local crictl_archive="${artifact_dir}/crictl-v${CRICTL_VERSION}-linux-arm64.tar.gz"
  local kubeadm_binary="${artifact_dir}/kubeadm"
  local kubelet_binary="${artifact_dir}/kubelet"
  local kubectl_binary="${artifact_dir}/kubectl"
  local staged_artifacts staged_containerd_archive staged_cni_archive staged_crictl_archive staged_payload
  local path name index directory
  local -a extracted_containerd_files=()
  local -a extracted_cni_files=()
  local -a required_containerd=(containerd containerd-shim-runc-v2 ctr)
  local -A found_containerd=()

  phase='artifact-validation'
  bash "${repo_root}/bootstrap/pi/preflight.sh" --phase install
  check_sha "${CONTAINERD_ARM64_SHA256}" "${containerd_archive}"
  check_sha "${RUNC_ARM64_SHA256}" "${runc_binary}"
  check_sha "${CNI_PLUGINS_ARM64_SHA256}" "${cni_archive}"
  check_sha "${CRICTL_ARM64_SHA256}" "${crictl_archive}"
  check_sha "${KUBEADM_ARM64_SHA256}" "${kubeadm_binary}"
  check_sha "${KUBELET_ARM64_SHA256}" "${kubelet_binary}"
  check_sha "${KUBECTL_ARM64_SHA256}" "${kubectl_binary}"
  safe_archive "${containerd_archive}" '^bin(/[A-Za-z0-9._-]+)?/?$'
  safe_archive "${cni_archive}" '^[A-Za-z0-9._-]+/?$'
  safe_archive "${crictl_archive}" '^crictl/?$'

  if [[ "${mode}" == '--check' ]]; then
    printf 'PASS all staged upstream ARM64 artifacts match the reviewed hashes. No change made.\n'
    return 0
  fi
  [[ "${mode}" == '--apply' ]] || die "usage: $0 [--check|--apply]"
  [[ "${EUID}" -eq 0 ]] || die 'apply mode requires root'
  [[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == 'yes' ]] || die 'recovery acknowledgement missing'
  [[ "${CONFIRM_KUBERNETES_INSTALL:-}" == "install-reviewed-${KUBERNETES_VERSION}" ]] || \
    die 'exact Kubernetes install acknowledgement missing'

  temporary="$(mktemp -d)"
  [[ -d "${temporary}" && ! -L "${temporary}" ]] || die 'mktemp did not create a private staging directory'
  chmod 0700 "${temporary}"
  transaction_started='no'
  transaction_complete='no'
  service_mutation_started='no'
  pending_destination=''
  created_directories=()
  installed_destinations=()
  installed_hashes=()
  target_sources=()
  target_destinations=()
  target_modes=()
  declare -gA seen_targets=()
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  phase='staging-reviewed-inputs'
  staged_artifacts="${temporary}/artifacts"
  staged_payload="${temporary}/payload"
  install -d -m 0700 "${staged_artifacts}" "${staged_payload}" \
    "${staged_payload}/containerd" "${staged_payload}/cni" "${staged_payload}/files"
  install -m 0600 "${containerd_archive}" "${staged_artifacts}/containerd.tar.gz"
  install -m 0600 "${cni_archive}" "${staged_artifacts}/cni.tgz"
  install -m 0600 "${crictl_archive}" "${staged_artifacts}/crictl.tar.gz"
  install -m 0700 "${runc_binary}" "${staged_payload}/files/runc"
  install -m 0700 "${kubeadm_binary}" "${staged_payload}/files/kubeadm"
  install -m 0700 "${kubelet_binary}" "${staged_payload}/files/kubelet"
  install -m 0700 "${kubectl_binary}" "${staged_payload}/files/kubectl"
  install -m 0600 "${repo_root}/bootstrap/pi/containerd-config.toml" \
    "${staged_payload}/files/containerd-config.toml"
  install -m 0600 "${repo_root}/bootstrap/pi/crictl.yaml" \
    "${staged_payload}/files/crictl.yaml"
  install -m 0600 "${repo_root}/bootstrap/pi/systemd/containerd.service" \
    "${staged_payload}/files/containerd.service"
  install -m 0600 "${repo_root}/bootstrap/pi/systemd/kubelet.service" \
    "${staged_payload}/files/kubelet.service"

  staged_containerd_archive="${staged_artifacts}/containerd.tar.gz"
  staged_cni_archive="${staged_artifacts}/cni.tgz"
  staged_crictl_archive="${staged_artifacts}/crictl.tar.gz"
  check_sha "${CONTAINERD_ARM64_SHA256}" "${staged_containerd_archive}"
  check_sha "${CNI_PLUGINS_ARM64_SHA256}" "${staged_cni_archive}"
  check_sha "${CRICTL_ARM64_SHA256}" "${staged_crictl_archive}"
  check_sha "${RUNC_ARM64_SHA256}" "${staged_payload}/files/runc"
  check_sha "${KUBEADM_ARM64_SHA256}" "${staged_payload}/files/kubeadm"
  check_sha "${KUBELET_ARM64_SHA256}" "${staged_payload}/files/kubelet"
  check_sha "${KUBECTL_ARM64_SHA256}" "${staged_payload}/files/kubectl"
  safe_archive "${staged_containerd_archive}" '^bin(/[A-Za-z0-9._-]+)?/?$'
  safe_archive "${staged_cni_archive}" '^[A-Za-z0-9._-]+/?$'
  safe_archive "${staged_crictl_archive}" '^crictl/?$'

  phase='extracting-reviewed-archives'
  tar --extract --gzip --file "${staged_containerd_archive}" \
    --directory "${staged_payload}/containerd" --no-same-owner --no-same-permissions --no-overwrite-dir
  tar --extract --gzip --file "${staged_cni_archive}" \
    --directory "${staged_payload}/cni" --no-same-owner --no-same-permissions --no-overwrite-dir
  tar --extract --gzip --file "${staged_crictl_archive}" \
    --directory "${staged_payload}/files" --no-same-owner --no-same-permissions --no-overwrite-dir
  validate_extracted_tree "${staged_payload}/containerd" '^bin(/[A-Za-z0-9._-]+)?$'
  validate_extracted_tree "${staged_payload}/cni" '^[A-Za-z0-9._-]+$'
  [[ -f "${staged_payload}/files/crictl" && ! -L "${staged_payload}/files/crictl" ]] || \
    die 'cri-tools archive lacks a regular crictl binary'

  phase='building-complete-target-manifest'
  mapfile -d '' extracted_containerd_files < <(
    find "${staged_payload}/containerd/bin" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z
  )
  for path in "${extracted_containerd_files[@]}"; do
    name="$(basename "${path}")"
    case "${name}" in
      containerd|ctr|containerd-shim-*)
        add_target "${path}" "/usr/local/bin/${name}" 0755
        found_containerd["${name}"]=1
        ;;
    esac
  done
  for name in "${required_containerd[@]}"; do
    [[ -n "${found_containerd["${name}"]+present}" ]] || die "containerd archive lacks ${name}"
  done

  add_target "${staged_payload}/files/runc" /usr/local/sbin/runc 0755
  mapfile -d '' extracted_cni_files < <(
    find "${staged_payload}/cni" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z
  )
  ((${#extracted_cni_files[@]} > 0)) || die 'CNI plugin archive contains no regular binaries'
  for path in "${extracted_cni_files[@]}"; do
    add_target "${path}" "/opt/cni/bin/$(basename "${path}")" 0755
  done
  add_target "${staged_payload}/files/kubeadm" /usr/local/bin/kubeadm 0755
  add_target "${staged_payload}/files/kubelet" /usr/local/bin/kubelet 0755
  add_target "${staged_payload}/files/kubectl" /usr/local/bin/kubectl 0755
  add_target "${staged_payload}/files/crictl" /usr/local/bin/crictl 0755
  add_target "${staged_payload}/files/containerd-config.toml" /etc/containerd/config.toml 0644
  add_target "${staged_payload}/files/crictl.yaml" /etc/crictl.yaml 0644
  add_target "${staged_payload}/files/containerd.service" /etc/systemd/system/containerd.service 0644
  add_target "${staged_payload}/files/kubelet.service" /etc/systemd/system/kubelet.service 0644

  phase='pre-mutation-collision-validation'
  for directory in /usr/local/bin /usr/local/sbin /opt/cni/bin /etc/containerd /etc/systemd/system; do
    validate_directory_chain "${directory}"
  done
  for path in "${target_destinations[@]}"; do
    assert_target_vacant "${path}"
  done
  for name in containerd.service kubelet.service; do
    if systemctl cat "${name}" >/dev/null 2>&1 \
      || systemctl is-active --quiet "${name}" 2>/dev/null \
      || systemctl is-enabled --quiet "${name}" 2>/dev/null; then
      die "refusing to replace or alter existing systemd service state: ${name}"
    fi
  done

  transaction_started='yes'
  phase='creating-target-directories'
  ensure_directory /usr/local/bin 0755
  ensure_directory /usr/local/sbin 0755
  ensure_directory /opt/cni/bin 0755
  ensure_directory /etc/containerd 0755
  ensure_directory /etc/systemd/system 0755

  for ((index=0; index<${#target_destinations[@]}; index++)); do
    phase="installing-target-$((index + 1))-of-${#target_destinations[@]}"
    exclusive_install "${target_sources[index]}" "${target_destinations[index]}" "${target_modes[index]}"
  done

  phase='reloading-systemd-units'
  systemctl daemon-reload
  service_mutation_started='yes'
  phase='enabling-and-starting-containerd'
  systemctl enable --now containerd.service
  phase='enabling-kubelet-without-starting-it'
  systemctl enable kubelet.service

  phase='post-install-verification'
  [[ "$(/usr/local/bin/kubeadm version -o short)" == "${KUBERNETES_VERSION}" ]] || \
    die 'installed kubeadm version mismatch'
  [[ "$(/usr/local/bin/kubelet --version)" == "Kubernetes ${KUBERNETES_VERSION}" ]] || \
    die 'installed kubelet version mismatch'
  /usr/local/bin/kubectl version --client=true >/dev/null
  [[ "$(/usr/local/bin/crictl --version)" == "crictl version v${CRICTL_VERSION}" ]] || \
    die 'installed crictl version mismatch'
  /usr/local/bin/containerd config dump >/dev/null
  /usr/local/bin/ctr plugins ls | \
    grep -Eq '^io[.]containerd[.]grpc[.]v1[[:space:]]+cri[[:space:]].*[[:space:]]ok$' || \
    die 'containerd CRI plugin is not healthy'
  systemctl is-active --quiet containerd.service || die 'containerd service is not active'
  systemctl is-enabled --quiet containerd.service || die 'containerd service is not enabled'
  systemctl is-enabled --quiet kubelet.service || die 'kubelet service is not enabled'

  phase='complete'
  transaction_complete='yes'
  printf 'PASS upstream Kubernetes binaries and containerd installed transactionally. The cluster was not initialized.\n'
  printf 'Next: run init-control-plane.sh --check; do not bypass unresolved CNI/network gates.\n'
}

# Keeping execution behind this guard lets the archive validator be exercised
# directly by the security contract tests without invoking the privileged flow.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  phase='startup'
  temporary=''
  transaction_started='no'
  transaction_complete='no'
  service_mutation_started='no'
  pending_destination=''
  declare -a created_directories=()
  declare -a installed_destinations=()
  declare -a installed_hashes=()
  declare -a target_sources=()
  declare -a target_destinations=()
  declare -a target_modes=()
  declare -A seen_targets=()
  main "$@"
fi
