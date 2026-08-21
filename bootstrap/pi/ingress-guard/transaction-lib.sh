#!/usr/bin/env bash
# Shared, root-only transaction primitives for the SSH-only ingress guard.
# This file is installed from hash-bound custody before it is sourced.

set -Eeuo pipefail
set +x
set +o history
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly IG_STATE_ROOT=/var/lib/website-infrastructure/ingress-guard
readonly IG_INPUT_ROOT="${IG_STATE_ROOT}/input"
readonly IG_CUSTODY_ROOT="${IG_STATE_ROOT}/custody"
readonly IG_TRANSACTION_ROOT="${IG_STATE_ROOT}/transaction"
readonly IG_RECEIPT_ROOT="${IG_STATE_ROOT}/receipts"
readonly IG_LOCK_ROOT="${IG_TRANSACTION_ROOT}"
readonly IG_LOCK_PATH="${IG_LOCK_ROOT}/global.lock"
readonly IG_JOURNAL_PATH="${IG_TRANSACTION_ROOT}/journal.v2"
readonly IG_LOAD_JOURNAL_PATH="${IG_TRANSACTION_ROOT}/load-journal.v2"
readonly IG_LEGACY_JOURNAL_PATH="${IG_TRANSACTION_ROOT}/journal.v1"
readonly IG_LEGACY_LOAD_JOURNAL_PATH="${IG_TRANSACTION_ROOT}/load-journal.v1"
readonly IG_OWNED_TABLE=website_infrastructure_ingress_guard
readonly IG_GUARD_UNIT=website-infrastructure-ingress-guard.service
# Consumed by the transaction entry points after sourcing; intentionally not exported.
# shellcheck disable=SC2034
readonly IG_CONTRACT_INPUT="${IG_INPUT_ROOT}/admin-ingress.env"
# Consumed by the retrofit entry point after sourcing; intentionally not exported.
# shellcheck disable=SC2034
readonly IG_RETROFIT_INPUT="${IG_INPUT_ROOT}/retrofit-attestation.env"

ig_die() {
  printf 'INGRESS-GUARD FAIL %s\n' "$1" >&2
  exit 1
}

ig_require_commands() {
  local command_name
  for command_name in awk chmod cmp flock grep install mktemp mv nft python3 \
    readlink rm rmdir sha256sum stat sync systemctl timeout; do
    command -v "${command_name}" >/dev/null 2>&1 || ig_die TOOL_MISSING
  done
  [[ "$(command -v python3)" == /usr/bin/python3 ]] || ig_die PYTHON_IDENTITY_INVALID
  [[ "$(command -v nft)" == /usr/sbin/nft ]] || ig_die NFT_IDENTITY_INVALID
  [[ "$(command -v systemctl)" == /usr/bin/systemctl ]] || ig_die SYSTEMCTL_IDENTITY_INVALID
  [[ "$(command -v timeout)" == /usr/bin/timeout ]] || ig_die TIMEOUT_IDENTITY_INVALID
}

ig_require_cluster_commands() {
  [[ -f /usr/local/bin/kubectl && ! -L /usr/local/bin/kubectl ]] \
    || ig_die TOOL_MISSING
  [[ "$(stat -c '%u:%g:%a:%h' -- /usr/local/bin/kubectl)" == 0:0:755:1 ]] \
    || ig_die KUBECTL_IDENTITY_INVALID
}

ig_run_bounded() {
  timeout --signal=TERM --kill-after=2s 30s "$@"
}

ig_assert_directory() {
  local path="$1" expected_mode="$2"
  expected_mode="${expected_mode#0}"
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(readlink -f -- "${path}")" == "${path}" ]] || return 1
  [[ "$(stat -c '%u:%g:%a' -- "${path}")" == "0:0:${expected_mode}" ]] || return 1
}

ig_ensure_directory() {
  local path="$1" expected_mode="$2"
  expected_mode="${expected_mode#0}"
  if [[ -e "${path}" || -L "${path}" ]]; then
    ig_assert_directory "${path}" "${expected_mode}" || ig_die DIRECTORY_PRESTATE_INVALID
    return 0
  fi
  install -d -o root -g root -m "0${expected_mode}" -- "${path}" \
    || ig_die DIRECTORY_CREATE_FAILED
  ig_assert_directory "${path}" "${expected_mode}" || ig_die DIRECTORY_CREATE_FAILED
  sync -f -- "$(dirname -- "${path}")" >/dev/null 2>&1 || ig_die DURABILITY_FAILED
}

ig_assert_root_file() {
  local path="$1" expected_mode="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(stat -c '%u:%g:%a:%h' -- "${path}")" == "0:0:${expected_mode}:1" ]] || return 1
}

ig_bootstrap_state_roots() {
  [[ "${EUID}" -eq 0 ]] || ig_die NOT_ROOT
  ig_ensure_directory /var/lib/website-infrastructure 0700
  ig_ensure_directory "${IG_STATE_ROOT}" 0700
  ig_ensure_directory "${IG_INPUT_ROOT}" 0700
  ig_ensure_directory "${IG_CUSTODY_ROOT}" 0700
  ig_ensure_directory "${IG_TRANSACTION_ROOT}" 0700
  local legacy
  for legacy in "${IG_LEGACY_JOURNAL_PATH}" "${IG_LEGACY_LOAD_JOURNAL_PATH}"; do
    [[ ! -e "${legacy}" && ! -L "${legacy}" ]] || ig_die LEGACY_JOURNAL_PRESENT
  done
  ig_ensure_directory "${IG_RECEIPT_ROOT}" 0700
  ig_ensure_directory "${IG_LOCK_ROOT}" 0700
  if [[ ! -e "${IG_LOCK_PATH}" && ! -L "${IG_LOCK_PATH}" ]]; then
    install -o root -g root -m 0600 -- /dev/null "${IG_LOCK_PATH}" \
      || ig_die LOCK_CREATE_FAILED
  fi
  ig_assert_root_file "${IG_LOCK_PATH}" 600 || ig_die LOCK_INVALID
}

ig_acquire_lock() {
  exec 9<>"${IG_LOCK_PATH}"
  flock -n 9 || ig_die LOCK_HELD
}

ig_acquire_lock_wait() {
  exec 9<>"${IG_LOCK_PATH}"
  flock -w 30 9 || ig_die LOCK_HELD
}

ig_release_lock() {
  flock -u 9 || ig_die LOCK_RELEASE_FAILED
  exec 9>&-
}

ig_sha256() {
  sha256sum -- "$1" | awk '{print $1}'
}

ig_secure_root_file_sha256() {
  local path="$1" expected_mode="$2" maximum_bytes="$3"
  /usr/bin/python3 -I -B - "${path}" "${expected_mode}" "${maximum_bytes}" <<'PY'
import hashlib
import os
import stat
import sys

path, mode_text, maximum_text = sys.argv[1:]
maximum = int(maximum_text, 10)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or stat.S_IMODE(before.st_mode) != int(mode_text, 8)
        or before.st_nlink != 1
    ):
        raise ValueError("metadata")
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > maximum:
            raise ValueError("size")
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
         before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns,
         before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns)
        or size != after.st_size
    ):
        raise ValueError("metadata changed")
    print(digest.hexdigest())
finally:
    os.close(descriptor)
PY
}

ig_secure_kernel_value() {
  local kind="$1" path="$2"
  /usr/bin/python3 -I -B - "${kind}" "${path}" <<'PY'
import hashlib
import os
import re
import stat
import sys

kind, path = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise ValueError("kernel metadata")
    payload = os.read(descriptor, 129)
    if len(payload) > 128 or os.read(descriptor, 1):
        raise ValueError("kernel value size")
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
        before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_mode, after.st_uid,
        after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns
    ):
        raise ValueError("kernel metadata changed")
    text = payload.decode("ascii")
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n",
        text,
    ):
        raise ValueError("kernel value")
    if kind == "boot-sha256":
        print(hashlib.sha256(payload).hexdigest())
    elif kind == "uuid":
        print(text.rstrip("\n"))
    else:
        raise ValueError("kind")
finally:
    os.close(descriptor)
PY
}

ig_secure_boot_sha256() {
  ig_secure_kernel_value boot-sha256 /proc/sys/kernel/random/boot_id
}

ig_secure_uuid() {
  ig_secure_kernel_value uuid /proc/sys/kernel/random/uuid
}

ig_immutable_document() {
  local destination="$1"
  shift
  local parent
  parent="$(dirname -- "${destination}")"
  ig_assert_directory "${parent}" 700 || ig_die STATE_DIRECTORY_INVALID
  /usr/bin/python3 -I -B - "${destination}" "$@" <<'PY' || ig_die STATE_WRITE_FAILED
import os
import stat
import sys

destination = sys.argv[1]
fields = sys.argv[2:]
if not fields or any(
    not field or "\n" in field or "\r" in field or field.count("=") != 1
    for field in fields
):
    raise ValueError("document fields")
payload = ("\n".join(fields) + "\n").encode("ascii")
if len(payload) > 16384:
    raise ValueError("document size")
parent, name = os.path.split(destination)
temporary_name = name + ".tmp"
parent_fd = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)


def child_stat(child):
    return os.stat(child, dir_fd=parent_fd, follow_symlinks=False)


def read_child(child, links=(1,)):
    descriptor = os.open(
        child, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink not in links
        ):
            raise ValueError("document metadata")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise ValueError("document size")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


try:
    try:
        destination_metadata = child_stat(name)
    except FileNotFoundError:
        destination_metadata = None
    try:
        temporary_metadata = child_stat(temporary_name)
    except FileNotFoundError:
        temporary_metadata = None

    if temporary_metadata is not None:
        if (
            destination_metadata is not None
            and temporary_metadata.st_dev == destination_metadata.st_dev
            and temporary_metadata.st_ino == destination_metadata.st_ino
            and temporary_metadata.st_nlink == 2
        ):
            read_child(temporary_name, (2,))
            os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        elif destination_metadata is None:
            read_child(temporary_name)
            os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        else:
            raise ValueError("document temporary collision")

    if destination_metadata is not None:
        observed, _metadata = read_child(name)
        if observed != payload:
            raise ValueError("immutable document mismatch")
    else:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.fsync(parent_fd)
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        observed, _metadata = read_child(name)
        if observed != payload:
            raise ValueError("document verification")
finally:
    os.close(parent_fd)
PY
}

ig_discard_unpublished_document_temp() {
  local destination="$1"
  /usr/bin/python3 -I -B - "${destination}" <<'PY' || ig_die STATE_TEMP_INVALID
import os
import stat
import sys

destination = sys.argv[1]
parent, name = os.path.split(destination)
temporary = name + ".tmp"
parent_fd = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
try:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("published destination exists")
    try:
        metadata = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise ValueError("temporary metadata")
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

ig_unpublished_document_temp_state() {
  local destination="$1"
  /usr/bin/python3 -I -B - "${destination}" <<'PY' || ig_die STATE_TEMP_INVALID
import os
import stat
import sys

destination = sys.argv[1]
parent, name = os.path.split(destination)
parent_fd = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
try:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("published destination exists")
    try:
        metadata = os.stat(name + ".tmp", dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        print("absent")
    else:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise ValueError("temporary metadata")
        print("present")
finally:
    os.close(parent_fd)
PY
}

ig_atomic_document() {
  local destination="$1"
  shift
  local parent temporary
  parent="$(dirname -- "${destination}")"
  ig_assert_directory "${parent}" 700 || ig_die STATE_DIRECTORY_INVALID
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    ig_assert_root_file "${destination}" 600 || ig_die STATE_FILE_INVALID
  fi
  temporary="$(mktemp "${parent}/.document.XXXXXXXX")" || ig_die STATE_WRITE_FAILED
  chmod 0600 -- "${temporary}" || ig_die STATE_WRITE_FAILED
  printf '%s\n' "$@" >"${temporary}" || ig_die STATE_WRITE_FAILED
  sync -f -- "${temporary}" >/dev/null 2>&1 || ig_die DURABILITY_FAILED
  mv -fT -- "${temporary}" "${destination}" || ig_die STATE_WRITE_FAILED
  sync -f -- "${parent}" >/dev/null 2>&1 || ig_die DURABILITY_FAILED
}

ig_validate_public_binding() {
  [[ "${IG_SOURCE_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] || ig_die SOURCE_REVISION_INVALID
  [[ "${IG_MANIFEST_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || ig_die MANIFEST_BINDING_INVALID
  [[ "${IG_CUSTODY_RECEIPT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || ig_die CUSTODY_RECEIPT_BINDING_INVALID
  [[ "${IG_CUSTODY_DIR:-}" == "${IG_CUSTODY_ROOT}/${IG_MANIFEST_SHA256}" ]] \
    || ig_die CUSTODY_PATH_INVALID
  ig_assert_directory "${IG_CUSTODY_DIR}" 700 || ig_die CUSTODY_INVALID
}

ig_verify_bundle() {
  local manifest="${IG_CUSTODY_DIR}/source-manifest.v1"
  local observed_hash line_hash line_mode relative source observed_mode expected_mode
  local -a expected_files=(
    bootstrap/pi/ingress-guard/custody-ingress-guard.sh
    bootstrap/pi/ingress-guard/install-ingress-guard.sh
    bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh
    bootstrap/pi/ingress-guard/recover-ingress-guard.sh
    bootstrap/pi/ingress-guard/transaction-lib.sh
    bootstrap/pi/ingress-guard/load-ingress-guard.sh
    bootstrap/pi/ingress-guard/verify-ingress-guard.sh
    bootstrap/pi/ingress-guard/systemd/website-infrastructure-ingress-guard.service
    bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf
    scripts/validate_admin_ingress_contract.py
    scripts/validate_ingress_guard.py
  )
  local count=0
  ig_assert_root_file "${manifest}" 600 || ig_die MANIFEST_INVALID
  observed_hash="$(ig_sha256 "${manifest}")"
  [[ "${observed_hash}" == "${IG_MANIFEST_SHA256}" ]] || ig_die MANIFEST_BINDING_INVALID
  while IFS=$'\t' read -r line_hash line_mode relative; do
    (( count += 1 ))
    [[ "${line_hash}" =~ ^[0-9a-f]{64}$ ]] || ig_die MANIFEST_INVALID
    [[ "${line_mode}" =~ ^0?(600|644|700|755)$ ]] || ig_die MANIFEST_INVALID
    [[ "${relative}" =~ ^[a-zA-Z0-9._/-]+$ ]] || ig_die MANIFEST_INVALID
    [[ "${relative}" != /* && "${relative}" != *'..'* ]] || ig_die MANIFEST_INVALID
    case "${relative}" in
      bootstrap/pi/ingress-guard/custody-ingress-guard.sh|\
        bootstrap/pi/ingress-guard/install-ingress-guard.sh|\
        bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh|\
        bootstrap/pi/ingress-guard/recover-ingress-guard.sh|\
        bootstrap/pi/ingress-guard/load-ingress-guard.sh|\
        bootstrap/pi/ingress-guard/verify-ingress-guard.sh)
        expected_mode=700
        ;;
      bootstrap/pi/ingress-guard/transaction-lib.sh|\
        scripts/validate_admin_ingress_contract.py|scripts/validate_ingress_guard.py)
        expected_mode=600
        ;;
      bootstrap/pi/ingress-guard/systemd/website-infrastructure-ingress-guard.service|\
        bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf)
        expected_mode=644
        ;;
      *)
        ig_die MANIFEST_INVALID
        ;;
    esac
    [[ "${line_mode#0}" == "${expected_mode}" ]] || ig_die MANIFEST_INVALID
    source="${IG_CUSTODY_DIR}/${relative}"
    ig_assert_root_file "${source}" "${line_mode#0}" || ig_die CUSTODY_FILE_INVALID
    [[ "$(ig_sha256 "${source}")" == "${line_hash}" ]] || ig_die CUSTODY_HASH_INVALID
    observed_mode="$(stat -c %a -- "${source}")"
    [[ "${observed_mode}" == "${line_mode#0}" ]] || ig_die CUSTODY_FILE_INVALID
  done <"${manifest}"
  [[ "${count}" -eq 11 ]] || ig_die MANIFEST_INVALID
  for relative in "${expected_files[@]}"; do
    [[ "$(awk -F '\t' -v wanted="${relative}" '$3 == wanted {count += 1} END {print count + 0}' "${manifest}")" == 1 ]] \
      || ig_die MANIFEST_INVALID
  done
}

ig_verify_custody_contract() {
  local validator="${IG_CUSTODY_DIR}/scripts/validate_ingress_guard.py"
  ig_run_bounded python3 -I -B "${validator}" repo-custody >/dev/null 2>&1 \
    || ig_die CUSTODY_REPOSITORY_CONTRACT_INVALID
}

ig_manifest_hash_for() {
  local relative="$1" manifest="${IG_CUSTODY_DIR}/source-manifest.v1"
  local value count
  count="$(awk -F '\t' -v wanted="${relative}" '$3 == wanted {count += 1} END {print count + 0}' "${manifest}")"
  [[ "${count}" == 1 ]] || ig_die MANIFEST_INVALID
  value="$(awk -F '\t' -v wanted="${relative}" '$3 == wanted {print $1}' "${manifest}")"
  [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || ig_die MANIFEST_INVALID
  printf '%s\n' "${value}"
}

ig_verify_custody_receipt() {
  local receipt="${IG_RECEIPT_ROOT}/custody.${IG_MANIFEST_SHA256}.receipt.v2"
  local bootstrap_hash observed_hash
  ig_assert_root_file "${receipt}" 600 || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(awk 'END {print NR + 0}' "${receipt}")" == 8 ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value schema "${receipt}")" == ingress-guard-custody-receipt-v2 ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value result "${receipt}")" == pass ]] || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value source_revision_assertion "${receipt}")" == \
    operator-reviewed-protected-main ]] || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value source_revision "${receipt}")" == "${IG_SOURCE_REVISION}" ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value manifest_sha256 "${receipt}")" == "${IG_MANIFEST_SHA256}" ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  bootstrap_hash="$(ig_manifest_hash_for bootstrap/pi/ingress-guard/custody-ingress-guard.sh)"
  [[ "$(ig_read_value bootstrap_sha256 "${receipt}")" == "${bootstrap_hash}" ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value public_artifacts "${receipt}")" == held-inode-copied ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "$(ig_read_value private_inventory "${receipt}")" == not-read ]] \
    || ig_die CUSTODY_RECEIPT_INVALID
  observed_hash="$(ig_secure_root_file_sha256 "${receipt}" 0600 4096)" \
    || ig_die CUSTODY_RECEIPT_INVALID
  [[ "${observed_hash}" == "${IG_CUSTODY_RECEIPT_SHA256}" ]] \
    || ig_die CUSTODY_RECEIPT_BINDING_INVALID
}

ig_file_prestate() {
  local target="$1" source="$2" mode="$3"
  if [[ ! -e "${target}" && ! -L "${target}" ]]; then
    printf 'absent\n'
    return 0
  fi
  ig_assert_root_file "${target}" "${mode}" || ig_die TARGET_PRESTATE_INVALID
  cmp -s -- "${source}" "${target}" || ig_die TARGET_PRESTATE_INVALID
  printf 'exact\n'
}

ig_directory_prestate() {
  local path="$1" mode="$2"
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    printf 'absent\n'
    return 0
  fi
  ig_assert_directory "${path}" "${mode}" || ig_die DIRECTORY_PRESTATE_INVALID
  printf 'exact\n'
}

ig_remove_directory_if_created() {
  local prestate="$1" path="$2" mode="$3"
  [[ "${prestate}" == absent ]] || return 0
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    return 0
  fi
  ig_assert_directory "${path}" "${mode}" || return 1
  rmdir -- "${path}" || return 1
  [[ ! -e "${path}" && ! -L "${path}" ]] || return 1
  sync -f -- "$(dirname -- "${path}")" >/dev/null 2>&1 || return 1
}

ig_install_exact() {
  local source="$1" target="$2" mode="$3"
  if [[ -e "${target}" || -L "${target}" ]]; then
    ig_assert_root_file "${target}" "${mode}" || ig_die TARGET_CHANGED
    cmp -s -- "${source}" "${target}" || ig_die TARGET_CHANGED
    return 0
  fi
  install -o root -g root -m "0${mode}" -- "${source}" "${target}" \
    || ig_die TARGET_INSTALL_FAILED
  ig_assert_root_file "${target}" "${mode}" || ig_die TARGET_INSTALL_FAILED
  cmp -s -- "${source}" "${target}" || ig_die TARGET_INSTALL_FAILED
  sync -f -- "${target}" >/dev/null 2>&1 || ig_die DURABILITY_FAILED
  sync -f -- "$(dirname -- "${target}")" >/dev/null 2>&1 || ig_die DURABILITY_FAILED
}

ig_remove_if_created() {
  local prestate="$1" source="$2" target="$3" mode="$4"
  [[ "${prestate}" == absent ]] || return 0
  if [[ ! -e "${target}" && ! -L "${target}" ]]; then
    return 0
  fi
  ig_assert_root_file "${target}" "${mode}" || return 1
  cmp -s -- "${source}" "${target}" || return 1
  rm -f -- "${target}" || return 1
  [[ ! -e "${target}" && ! -L "${target}" ]] || return 1
  sync -f -- "$(dirname -- "${target}")" >/dev/null 2>&1 || return 1
}

ig_capture_ruleset() {
  local destination="$1"
  rm -f -- "${destination}"
  ig_run_bounded nft -a -j list ruleset >"${destination}" 2>/dev/null || return 1
  chmod 0600 -- "${destination}" || return 1
}

ig_verify_absent_capture() {
  local capture="$1" validator="$2" contract="$3"
  ig_run_bounded python3 -I -B "${validator}" live --ruleset "${capture}" \
    --contract "${contract}" --expect-absent >/dev/null 2>&1
}

ig_verify_live_capture() {
  local capture="$1" validator="$2" contract="$3"
  ig_run_bounded python3 -I -B "${validator}" live --ruleset "${capture}" \
    --contract "${contract}" >/dev/null 2>&1
}

ig_table_prestate() {
  local capture="$1" validator="$2" contract="$3"
  ig_capture_ruleset "${capture}" || ig_die RULESET_CAPTURE_FAILED
  if ig_verify_absent_capture "${capture}" "${validator}" "${contract}"; then
    printf 'absent\n'
    return 0
  fi
  if ig_verify_live_capture "${capture}" "${validator}" "${contract}"; then
    printf 'healthy\n'
    return 0
  fi
  ig_die TABLE_PRESTATE_INVALID
}

ig_delete_owned_table_and_prove_absent() {
  local capture="$1" validator="$2" contract="$3"
  ig_run_bounded nft delete table inet "${IG_OWNED_TABLE}" 2>/dev/null || return 1
  ig_capture_ruleset "${capture}" || return 1
  ig_verify_absent_capture "${capture}" "${validator}" "${contract}"
}

ig_systemctl_state() {
  local unit="$1" property="$2" value
  value="$(ig_run_bounded systemctl show -p "${property}" --value "${unit}" 2>/dev/null)" || return 1
  case "${property}:${value}" in
    ActiveState:active|ActiveState:inactive|ActiveState:failed|LoadState:loaded|LoadState:not-found)
      printf '%s\n' "${value}"
      ;;
    *)
      return 1
      ;;
  esac
}

ig_unit_enabled_state() {
  if ig_run_bounded systemctl is-enabled --quiet "${IG_GUARD_UNIT}" 2>/dev/null; then
    printf 'enabled\n'
  else
    local status=$?
    [[ "${status}" -eq 1 ]] || return 1
    printf 'disabled\n'
  fi
}

ig_verify_guard_unit_prestate() {
  local target="$1" file_prestate="$2" load_state active_state fragment_path
  load_state="$(ig_systemctl_state "${IG_GUARD_UNIT}" LoadState)" || return 1
  active_state="$(ig_systemctl_state "${IG_GUARD_UNIT}" ActiveState)" || return 1
  [[ "${active_state}" == inactive ]] || return 1
  case "${file_prestate}:${load_state}" in
    absent:not-found)
      ;;
    exact:loaded)
      fragment_path="$(ig_run_bounded systemctl show -p FragmentPath --value "${IG_GUARD_UNIT}" 2>/dev/null)" \
        || return 1
      [[ "${fragment_path}" == "${target}" ]] || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

ig_verify_kubelet_dependency_absent() {
  local effective_after effective_requires
  effective_after="$(ig_run_bounded systemctl show -p After --value kubelet.service 2>/dev/null)" \
    || return 1
  effective_requires="$(ig_run_bounded systemctl show -p Requires --value kubelet.service 2>/dev/null)" \
    || return 1
  ! grep -qw -- "${IG_GUARD_UNIT}" <<<"${effective_after}" || return 1
  ! grep -qw -- "${IG_GUARD_UNIT}" <<<"${effective_requires}" || return 1
}

ig_kubectl_name() {
  local namespace="$1" resource="$2"
  local -a command=(/usr/local/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --request-timeout=20s)
  if [[ "${namespace}" != cluster ]]; then
    command+=(--namespace "${namespace}")
  fi
  ig_run_bounded "${command[@]}" get "${resource}" --ignore-not-found -o name 2>/dev/null
}

ig_cluster_health_scope() {
  local nodes flux_namespace object first second flux=0 tunnel=0 naranjo=0 lidersea=0
  local -a kubectl_command=(/usr/local/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --request-timeout=20s)
  ig_assert_root_file /etc/kubernetes/admin.conf 600 || return 1
  ig_run_bounded "${kubectl_command[@]}" get --raw=/readyz >/dev/null 2>&1 || return 1
  nodes="$(ig_run_bounded "${kubectl_command[@]}" get nodes -o name 2>/dev/null)" \
    || return 1
  [[ -n "${nodes}" ]] || return 1
  ig_run_bounded "${kubectl_command[@]}" wait --for=condition=Ready node --all \
    --timeout=25s >/dev/null 2>&1 || return 1

  object="$(ig_kubectl_name kube-system daemonset/calico-node)" || return 1
  [[ "${object}" == daemonset.apps/calico-node ]] || return 1
  ig_run_bounded "${kubectl_command[@]}" --namespace kube-system rollout status \
    daemonset/calico-node --timeout=25s >/dev/null 2>&1 || return 1

  flux_namespace="$(ig_kubectl_name cluster namespace/flux-system)" || return 1
  if [[ -n "${flux_namespace}" ]]; then
    [[ "${flux_namespace}" == namespace/flux-system ]] || return 1
    for object in source-controller kustomize-controller helm-controller; do
      [[ "$(ig_kubectl_name flux-system "deployment/${object}")" == \
        "deployment.apps/${object}" ]] || return 1
      ig_run_bounded "${kubectl_command[@]}" --namespace flux-system rollout status \
        "deployment/${object}" --timeout=25s >/dev/null 2>&1 || return 1
    done
    flux=1
  fi

  first="$(ig_kubectl_name cloudflare-public deployment/naranjo-online-tunnel)" \
    || return 1
  second="$(ig_kubectl_name cloudflare-public deployment/lidersea-com-tunnel)" \
    || return 1
  case "${first}:${second}" in
    :)
      ;;
    deployment.apps/naranjo-online-tunnel:deployment.apps/lidersea-com-tunnel)
      for object in naranjo-online-tunnel lidersea-com-tunnel; do
        ig_run_bounded "${kubectl_command[@]}" --namespace cloudflare-public \
          rollout status "deployment/${object}" --timeout=25s >/dev/null 2>&1 \
          || return 1
      done
      tunnel=1
      ;;
    *)
      return 1
      ;;
  esac

  object="$(ig_kubectl_name naranjo-online deployment/naranjo-online)" || return 1
  if [[ -n "${object}" ]]; then
    [[ "${object}" == deployment.apps/naranjo-online ]] || return 1
    ig_run_bounded "${kubectl_command[@]}" --namespace naranjo-online rollout status \
      deployment/naranjo-online --timeout=25s >/dev/null 2>&1 || return 1
    naranjo=1
  fi
  object="$(ig_kubectl_name lidersea-com deployment/lidersea-com)" || return 1
  if [[ -n "${object}" ]]; then
    [[ "${object}" == deployment.apps/lidersea-com ]] || return 1
    ig_run_bounded "${kubectl_command[@]}" --namespace lidersea-com rollout status \
      deployment/lidersea-com --timeout=25s >/dev/null 2>&1 || return 1
    lidersea=1
  fi
  printf 'core-f%s-t%s-n%s-l%s\n' "${flux}" "${tunnel}" "${naranjo}" "${lidersea}"
}

ig_verify_cluster_health() {
  local expected="$1" observed
  [[ "${expected}" =~ ^core-f[01]-t[01]-n[01]-l[01]$ ]] || return 1
  observed="$(ig_cluster_health_scope)" || return 1
  [[ "${observed}" == "${expected}" ]]
}

ig_journal_write() {
  [[ "${IG_MODE}" =~ ^(offline|retrofit)$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_PHASE}" =~ ^(prepared|artifacts-installed|guard-start-intent|guard-active|dropin-installed|kubelet-restart-intent|awaiting-reboot-intent|awaiting-reboot|commit-intent|committed|rollback-intent|rolled-back|recovery-required)$ ]] \
    || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_TABLE_PRESTATE}" =~ ^(absent|healthy)$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_ATTEMPT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_KUBELET_PRESTATE}" =~ ^(active|inactive)$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_GUARD_ENABLED_PRESTATE}" =~ ^(enabled|disabled)$ ]] || ig_die JOURNAL_VALUE_INVALID
  local variable
  for variable in IG_PRE_CONTRACT IG_PRE_CONTRACT_VALIDATOR IG_PRE_MODEL_VALIDATOR \
    IG_PRE_TRANSACTION_LIB IG_PRE_LOADER IG_PRE_VERIFY IG_PRE_RECOVER IG_PRE_RETROFIT \
    IG_PRE_UNIT IG_PRE_DROPIN IG_PRE_ETC_DIR IG_PRE_VENDOR_DIR IG_PRE_LIBRARY_DIR \
    IG_PRE_DROPIN_DIR; do
    [[ "${!variable}" =~ ^(absent|exact)$ ]] || ig_die JOURNAL_VALUE_INVALID
  done
  [[ "${IG_BOOT_BINDING}" =~ ^[0-9a-f]{64}$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_CLOSURE_BOOT_BINDING}" =~ ^(none|not-applicable|[0-9a-f]{64})$ ]] \
    || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_CLUSTER_BINDING}" =~ ^(not-applicable|[0-9a-f]{64})$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_CUSTODY_RECEIPT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_ATTESTATION_SHA256}" =~ ^(not-applicable|[0-9a-f]{64})$ ]] \
    || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_CLUSTER_HEALTH_SCOPE}" =~ ^(not-applicable|core-f[01]-t[01]-n[01]-l[01])$ ]] \
    || ig_die JOURNAL_VALUE_INVALID
  [[ "${IG_RECEIPT_SHA256}" =~ ^(none|[0-9a-f]{64})$ ]] || ig_die JOURNAL_VALUE_INVALID
  ig_atomic_document "${IG_JOURNAL_PATH}" \
    'schema=ingress-guard-transaction-v2' \
    "mode=${IG_MODE}" \
    "phase=${IG_PHASE}" \
    "attempt_id=${IG_ATTEMPT_ID}" \
    "source_revision=${IG_SOURCE_REVISION}" \
    "manifest_sha256=${IG_MANIFEST_SHA256}" \
    "custody_receipt_sha256=${IG_CUSTODY_RECEIPT_SHA256}" \
    "boot_binding_sha256=${IG_BOOT_BINDING}" \
    "closure_boot_binding_sha256=${IG_CLOSURE_BOOT_BINDING}" \
    "cluster_binding_sha256=${IG_CLUSTER_BINDING}" \
    "attestation_sha256=${IG_ATTESTATION_SHA256}" \
    "cluster_health_scope=${IG_CLUSTER_HEALTH_SCOPE}" \
    "table_prestate=${IG_TABLE_PRESTATE}" \
    "kubelet_prestate=${IG_KUBELET_PRESTATE}" \
    "guard_enabled_prestate=${IG_GUARD_ENABLED_PRESTATE}" \
    "pre_contract=${IG_PRE_CONTRACT}" \
    "pre_contract_validator=${IG_PRE_CONTRACT_VALIDATOR}" \
    "pre_model_validator=${IG_PRE_MODEL_VALIDATOR}" \
    "pre_transaction_lib=${IG_PRE_TRANSACTION_LIB}" \
    "pre_loader=${IG_PRE_LOADER}" \
    "pre_verify=${IG_PRE_VERIFY}" \
    "pre_recover=${IG_PRE_RECOVER}" \
    "pre_retrofit=${IG_PRE_RETROFIT}" \
    "pre_unit=${IG_PRE_UNIT}" \
    "pre_dropin=${IG_PRE_DROPIN}" \
    "pre_etc_dir=${IG_PRE_ETC_DIR}" \
    "pre_vendor_dir=${IG_PRE_VENDOR_DIR}" \
    "pre_library_dir=${IG_PRE_LIBRARY_DIR}" \
    "pre_dropin_dir=${IG_PRE_DROPIN_DIR}" \
    "receipt_sha256=${IG_RECEIPT_SHA256}"
}

ig_read_value() {
  local key="$1" path="$2" count value
  count="$(awk -F= -v wanted="${key}" '$1 == wanted {count += 1} END {print count + 0}' "${path}")"
  [[ "${count}" == 1 ]] || return 1
  value="$(awk -F= -v wanted="${key}" '$1 == wanted {sub(/^[^=]*=/, ""); print}' "${path}")"
  [[ "${value}" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1
  printf '%s\n' "${value}"
}

ig_load_receipt_path() {
  local attempt="$1" result="$2"
  [[ "${attempt}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || return 1
  [[ "${result}" =~ ^(pass|rollback-verified|recovery-required)$ ]] || return 1
  printf '%s/load.%s.%s.receipt.v2\n' "${IG_RECEIPT_ROOT}" "${attempt}" "${result}"
}

ig_write_load_receipt() {
  local attempt="$1" boot="$2" result="$3" table_state="$4" rollback="$5"
  local destination
  [[ "${attempt}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die LOAD_RECEIPT_VALUE_INVALID
  [[ "${boot}" =~ ^[0-9a-f]{64}$ ]] || ig_die LOAD_RECEIPT_VALUE_INVALID
  [[ "${result}" =~ ^(pass|rollback-verified|recovery-required)$ ]] \
    || ig_die LOAD_RECEIPT_VALUE_INVALID
  [[ "${table_state}" =~ ^(verified|absent|unverified)$ ]] \
    || ig_die LOAD_RECEIPT_VALUE_INVALID
  [[ "${rollback}" =~ ^(not-needed|verified|required)$ ]] \
    || ig_die LOAD_RECEIPT_VALUE_INVALID
  destination="$(ig_load_receipt_path "${attempt}" "${result}")" \
    || ig_die LOAD_RECEIPT_VALUE_INVALID
  ig_immutable_document "${destination}" \
    'schema=ingress-guard-load-receipt-v2' \
    "attempt_id=${attempt}" \
    "boot_binding_sha256=${boot}" \
    "result=${result}" \
    "table_state=${table_state}" \
    "rollback=${rollback}" \
    'private_inventory=not-recorded'
  ig_secure_root_file_sha256 "${destination}" 0600 16384
}

ig_write_load_journal_record() {
  local phase="$1" prestate="$2" attempt="$3" boot="$4" receipt_hash="$5"
  [[ "${phase}" =~ ^(prepared|apply-intent|applied|commit-intent|committed|rollback-intent|rolled-back|recovery-required)$ ]] \
    || ig_die LOAD_JOURNAL_VALUE_INVALID
  [[ "${prestate}" =~ ^(absent|healthy)$ ]] || ig_die LOAD_JOURNAL_VALUE_INVALID
  [[ "${attempt}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die LOAD_JOURNAL_VALUE_INVALID
  [[ "${boot}" =~ ^[0-9a-f]{64}$ ]] || ig_die LOAD_JOURNAL_VALUE_INVALID
  [[ "${receipt_hash}" =~ ^(none|[0-9a-f]{64})$ ]] \
    || ig_die LOAD_JOURNAL_VALUE_INVALID
  ig_atomic_document "${IG_LOAD_JOURNAL_PATH}" \
    'schema=ingress-guard-load-journal-v2' \
    "phase=${phase}" \
    "prestate=${prestate}" \
    "attempt_id=${attempt}" \
    "boot_binding_sha256=${boot}" \
    "receipt_sha256=${receipt_hash}"
}

ig_read_load_journal() {
  ig_assert_root_file "${IG_LOAD_JOURNAL_PATH}" 600 || ig_die LOAD_JOURNAL_INVALID
  [[ "$(awk 'END {print NR + 0}' "${IG_LOAD_JOURNAL_PATH}")" == 6 ]] \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "$(ig_read_value schema "${IG_LOAD_JOURNAL_PATH}")" == \
    ingress-guard-load-journal-v2 ]] || ig_die LOAD_JOURNAL_INVALID
  IG_LOAD_PHASE="$(ig_read_value phase "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  IG_LOAD_PRESTATE="$(ig_read_value prestate "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  IG_LOAD_ATTEMPT_ID="$(ig_read_value attempt_id "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  IG_LOAD_BOOT_BINDING="$(ig_read_value boot_binding_sha256 "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  IG_LOAD_RECEIPT_SHA256="$(ig_read_value receipt_sha256 "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "${IG_LOAD_PHASE}" =~ ^(prepared|apply-intent|applied|commit-intent|committed|rollback-intent|rolled-back|recovery-required)$ ]] \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "${IG_LOAD_PRESTATE}" == absent ]] || ig_die LOAD_JOURNAL_INVALID
  [[ "${IG_LOAD_ATTEMPT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "${IG_LOAD_BOOT_BINDING}" =~ ^[0-9a-f]{64}$ ]] || ig_die LOAD_JOURNAL_INVALID
  [[ "${IG_LOAD_RECEIPT_SHA256}" =~ ^(none|[0-9a-f]{64})$ ]] \
    || ig_die LOAD_JOURNAL_INVALID
}

ig_verify_closed_load_receipt() {
  local result table_state rollback observed destination
  case "${IG_LOAD_PHASE}" in
    committed) result=pass; table_state=verified; rollback=not-needed ;;
    rolled-back) result='rollback-verified'; table_state=absent; rollback=verified ;;
    recovery-required) result=recovery-required; table_state=unverified; rollback=required ;;
    *) return 1 ;;
  esac
  [[ "${IG_LOAD_RECEIPT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || return 1
  destination="$(ig_load_receipt_path "${IG_LOAD_ATTEMPT_ID}" "${result}")" \
    || return 1
  ig_assert_root_file "${destination}" 600 || return 1
  observed="$(ig_write_load_receipt \
    "${IG_LOAD_ATTEMPT_ID}" "${IG_LOAD_BOOT_BINDING}" \
    "${result}" "${table_state}" "${rollback}")" || return 1
  [[ "${observed}" == "${IG_LOAD_RECEIPT_SHA256}" ]]
}

ig_reconcile_published_load_commit() {
  local destination receipt_hash
  [[ -e "${IG_LOAD_JOURNAL_PATH}" || -L "${IG_LOAD_JOURNAL_PATH}" ]] || return 0
  ig_read_load_journal
  case "${IG_LOAD_PHASE}" in
    commit-intent)
      destination="$(ig_load_receipt_path "${IG_LOAD_ATTEMPT_ID}" pass)" \
        || ig_die LOAD_RECEIPT_INVALID
      if [[ -e "${destination}" || -L "${destination}" ]]; then
        receipt_hash="$(ig_write_load_receipt \
          "${IG_LOAD_ATTEMPT_ID}" "${IG_LOAD_BOOT_BINDING}" \
          pass verified not-needed)" || ig_die LOAD_RECEIPT_INVALID
        ig_write_load_journal_record committed absent \
          "${IG_LOAD_ATTEMPT_ID}" "${IG_LOAD_BOOT_BINDING}" "${receipt_hash}"
      fi
      ;;
    committed|rolled-back|recovery-required)
      ig_verify_closed_load_receipt || ig_die LOAD_RECEIPT_INVALID
      ;;
  esac
}

ig_close_load_journal_after_absence() {
  local destination receipt_hash temp_state
  [[ -e "${IG_LOAD_JOURNAL_PATH}" || -L "${IG_LOAD_JOURNAL_PATH}" ]] || return 0
  ig_read_load_journal
  case "${IG_LOAD_PHASE}" in
    prepared|apply-intent|applied|commit-intent|rollback-intent)
      if [[ "${IG_LOAD_PHASE}" == commit-intent ]]; then
        destination="$(ig_load_receipt_path "${IG_LOAD_ATTEMPT_ID}" pass)" \
          || ig_die LOAD_RECEIPT_INVALID
        [[ ! -e "${destination}" && ! -L "${destination}" ]] \
          || ig_die LOAD_RECEIPT_INVALID
        temp_state="$(ig_unpublished_document_temp_state "${destination}")"
        [[ "${temp_state}" == absent ]] || \
          ig_discard_unpublished_document_temp "${destination}"
      fi
      receipt_hash="$(ig_write_load_receipt \
        "${IG_LOAD_ATTEMPT_ID}" "${IG_LOAD_BOOT_BINDING}" \
        rollback-verified absent verified)" || ig_die LOAD_RECEIPT_INVALID
      ig_write_load_journal_record rolled-back absent \
        "${IG_LOAD_ATTEMPT_ID}" "${IG_LOAD_BOOT_BINDING}" "${receipt_hash}"
      ;;
    committed|rolled-back|recovery-required)
      ig_verify_closed_load_receipt || ig_die LOAD_RECEIPT_INVALID
      ;;
  esac
}

ig_load_journal() {
  ig_assert_root_file "${IG_JOURNAL_PATH}" 600 || ig_die JOURNAL_INVALID
  [[ "$(awk 'END {print NR + 0}' "${IG_JOURNAL_PATH}")" == 30 ]] || ig_die JOURNAL_INVALID
  [[ "$(ig_read_value schema "${IG_JOURNAL_PATH}")" == ingress-guard-transaction-v2 ]] \
    || ig_die JOURNAL_INVALID
  IG_MODE="$(ig_read_value mode "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PHASE="$(ig_read_value phase "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_ATTEMPT_ID="$(ig_read_value attempt_id "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_SOURCE_REVISION="$(ig_read_value source_revision "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_MANIFEST_SHA256="$(ig_read_value manifest_sha256 "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_CUSTODY_RECEIPT_SHA256="$(ig_read_value custody_receipt_sha256 "${IG_JOURNAL_PATH}")" \
    || ig_die JOURNAL_INVALID
  IG_BOOT_BINDING="$(ig_read_value boot_binding_sha256 "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_CLOSURE_BOOT_BINDING="$(ig_read_value closure_boot_binding_sha256 "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_CLUSTER_BINDING="$(ig_read_value cluster_binding_sha256 "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_ATTESTATION_SHA256="$(ig_read_value attestation_sha256 "${IG_JOURNAL_PATH}")" \
    || ig_die JOURNAL_INVALID
  IG_CLUSTER_HEALTH_SCOPE="$(ig_read_value cluster_health_scope "${IG_JOURNAL_PATH}")" \
    || ig_die JOURNAL_INVALID
  IG_TABLE_PRESTATE="$(ig_read_value table_prestate "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_KUBELET_PRESTATE="$(ig_read_value kubelet_prestate "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_GUARD_ENABLED_PRESTATE="$(ig_read_value guard_enabled_prestate "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_CONTRACT="$(ig_read_value pre_contract "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_CONTRACT_VALIDATOR="$(ig_read_value pre_contract_validator "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_MODEL_VALIDATOR="$(ig_read_value pre_model_validator "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_TRANSACTION_LIB="$(ig_read_value pre_transaction_lib "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_LOADER="$(ig_read_value pre_loader "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_VERIFY="$(ig_read_value pre_verify "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_RECOVER="$(ig_read_value pre_recover "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_RETROFIT="$(ig_read_value pre_retrofit "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_UNIT="$(ig_read_value pre_unit "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_DROPIN="$(ig_read_value pre_dropin "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_ETC_DIR="$(ig_read_value pre_etc_dir "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_VENDOR_DIR="$(ig_read_value pre_vendor_dir "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_LIBRARY_DIR="$(ig_read_value pre_library_dir "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_PRE_DROPIN_DIR="$(ig_read_value pre_dropin_dir "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  IG_RECEIPT_SHA256="$(ig_read_value receipt_sha256 "${IG_JOURNAL_PATH}")" || ig_die JOURNAL_INVALID
  [[ "${IG_MODE}" =~ ^(offline|retrofit)$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_PHASE}" =~ ^(prepared|artifacts-installed|guard-start-intent|guard-active|dropin-installed|kubelet-restart-intent|awaiting-reboot-intent|awaiting-reboot|commit-intent|committed|rollback-intent|rolled-back|recovery-required)$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_ATTEMPT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_SOURCE_REVISION}" =~ ^[0-9a-f]{40}$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_MANIFEST_SHA256}" =~ ^[0-9a-f]{64}$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_BOOT_BINDING}" =~ ^[0-9a-f]{64}$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_CLOSURE_BOOT_BINDING}" =~ ^(none|not-applicable|[0-9a-f]{64})$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_RECEIPT_SHA256}" =~ ^(none|[0-9a-f]{64})$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_CLUSTER_BINDING}" =~ ^(not-applicable|[0-9a-f]{64})$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_CUSTODY_RECEIPT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_ATTESTATION_SHA256}" =~ ^(not-applicable|[0-9a-f]{64})$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_CLUSTER_HEALTH_SCOPE}" =~ ^(not-applicable|core-f[01]-t[01]-n[01]-l[01])$ ]] \
    || ig_die JOURNAL_INVALID
  [[ "${IG_TABLE_PRESTATE}" =~ ^(absent|healthy)$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_KUBELET_PRESTATE}" =~ ^(active|inactive)$ ]] || ig_die JOURNAL_INVALID
  [[ "${IG_GUARD_ENABLED_PRESTATE}" =~ ^(enabled|disabled)$ ]] || ig_die JOURNAL_INVALID
  local variable
  for variable in IG_PRE_CONTRACT IG_PRE_CONTRACT_VALIDATOR IG_PRE_MODEL_VALIDATOR \
    IG_PRE_TRANSACTION_LIB IG_PRE_LOADER IG_PRE_VERIFY IG_PRE_RECOVER IG_PRE_RETROFIT \
    IG_PRE_UNIT IG_PRE_DROPIN IG_PRE_ETC_DIR IG_PRE_VENDOR_DIR IG_PRE_LIBRARY_DIR \
    IG_PRE_DROPIN_DIR; do
    [[ "${!variable}" =~ ^(absent|exact)$ ]] || ig_die JOURNAL_INVALID
  done
  IG_CUSTODY_DIR="${IG_CUSTODY_ROOT}/${IG_MANIFEST_SHA256}"
}

ig_receipt_path() {
  local result="$1"
  [[ "${result}" =~ ^(pass|rollback-verified|recovery-required|pending-reboot)$ ]] \
    || return 1
  printf '%s/%s.%s.%s.receipt.v2\n' \
    "${IG_RECEIPT_ROOT}" "${IG_MODE}" "${IG_ATTEMPT_ID}" "${result}"
}

ig_journal_receipt_path() {
  case "${IG_PHASE}" in
    committed)
      ig_receipt_path pass
      ;;
    rolled-back)
      ig_receipt_path rollback-verified
      ;;
    awaiting-reboot)
      ig_receipt_path pending-reboot
      ;;
    recovery-required)
      ig_receipt_path recovery-required
      ;;
    *)
      return 1
      ;;
  esac
}

ig_write_receipt() {
  local result="$1" guard_state="$2" persistence="$3" dependency="$4" rollback="$5"
  local destination cluster_health source_binding custody_binding boot_binding
  local cluster_binding private_contract
  [[ "${result}" =~ ^(pass|rollback-verified|recovery-required|pending-reboot)$ ]] \
    || ig_die RECEIPT_VALUE_INVALID
  [[ "${guard_state}" =~ ^(verified|absent|unverified)$ ]] || ig_die RECEIPT_VALUE_INVALID
  [[ "${persistence}" =~ ^(verified|restored|pending|unverified)$ ]] || ig_die RECEIPT_VALUE_INVALID
  [[ "${dependency}" =~ ^(verified|restored|pending|not-applicable|unverified)$ ]] \
    || ig_die RECEIPT_VALUE_INVALID
  [[ "${rollback}" =~ ^(not-needed|verified|required)$ ]] || ig_die RECEIPT_VALUE_INVALID
  case "${IG_CLUSTER_HEALTH_SCOPE}" in
    not-applicable)
      cluster_health=not-applicable
      ;;
    core-f[01]-t[01]-n[01]-l[01])
      if [[ "${result}" == recovery-required ]]; then
        cluster_health=unverified
      else
        cluster_health=verified
      fi
      ;;
    *)
      ig_die RECEIPT_VALUE_INVALID
      ;;
  esac
  if [[ "${result}" == recovery-required ]]; then
    source_binding=verified
    custody_binding=verified
    boot_binding=unverified
    cluster_binding=unverified
    private_contract=unverified
  else
    source_binding=verified
    custody_binding=verified
    boot_binding=verified
    cluster_binding=verified-or-not-applicable
    private_contract=validated-root-custody
  fi
  destination="$(ig_receipt_path "${result}")" || ig_die RECEIPT_VALUE_INVALID
  ig_immutable_document "${destination}" \
    'schema=ingress-guard-receipt-v2' \
    "mode=${IG_MODE}" \
    "attempt_id=${IG_ATTEMPT_ID}" \
    "result=${result}" \
    "source_revision=${IG_SOURCE_REVISION}" \
    "manifest_sha256=${IG_MANIFEST_SHA256}" \
    "custody_receipt_sha256=${IG_CUSTODY_RECEIPT_SHA256}" \
    "source_binding=${source_binding}" \
    "custody_binding=${custody_binding}" \
    "boot_binding=${boot_binding}" \
    "cluster_binding=${cluster_binding}" \
    "private_contract=${private_contract}" \
    "guard_state=${guard_state}" \
    "persistence=${persistence}" \
    "kubelet_dependency=${dependency}" \
    "cluster_health=${cluster_health}" \
    "rollback=${rollback}"
  IG_RECEIPT_SHA256="$(ig_secure_root_file_sha256 "${destination}" 0600 16384)" \
    || ig_die RECEIPT_WRITE_FAILED
}
