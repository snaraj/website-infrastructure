#!/usr/bin/env bash
# Stage and launch the reviewed public ingress-guard artifact set from
# root-owned custody.
#
# Stage zero is deliberately manual: an operator first opens this file on a
# held descriptor, verifies its reviewed SHA-256, and uses /usr/bin/install to
# copy that descriptor to IG_BOOTSTRAP_PATH. Root executes only that installed
# copy. That same fixed bootstrap is the sole public launcher: it verifies the
# immutable custody receipt and opens the selected entrypoint and transaction
# library with O_NOFOLLOW before Bash sees either descriptor. See README.md;
# executing any entrypoint from a checkout is unsupported and refused.

set -Eeuo pipefail
set +x
set +o history
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly IG_STATE_ROOT=/var/lib/website-infrastructure/ingress-guard
readonly IG_BOOTSTRAP_PATH=/usr/local/sbin/website-infrastructure-ingress-guard-custody
readonly IG_CUSTODY_ROOT="${IG_STATE_ROOT}/custody"
readonly IG_RECEIPT_ROOT="${IG_STATE_ROOT}/receipts"
readonly IG_TRANSACTION_ROOT="${IG_STATE_ROOT}/transaction"
readonly IG_LOCK_ROOT="${IG_TRANSACTION_ROOT}"
readonly IG_LOCK_PATH="${IG_LOCK_ROOT}/global.lock"
readonly IG_MANIFEST_REL=bootstrap/pi/ingress-guard/source-manifest.v1

die() {
  printf 'INGRESS-GUARD CUSTODY FAIL %s\n' "$1" >&2
  exit 1
}

assert_directory() {
  local path="$1" mode="$2"
  mode="${mode#0}"
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(readlink -f -- "${path}")" == "${path}" ]] || return 1
  [[ "$(stat -c '%u:%g:%a' -- "${path}")" == "0:0:${mode}" ]]
}

ensure_directory() {
  local path="$1" mode="$2"
  mode="${mode#0}"
  if [[ -e "${path}" || -L "${path}" ]]; then
    assert_directory "${path}" "${mode}" || die DIRECTORY_INVALID
  else
    install -d -o root -g root -m "0${mode}" -- "${path}" || die DIRECTORY_CREATE_FAILED
    sync -f -- "$(dirname -- "${path}")" >/dev/null 2>&1 || die DURABILITY_FAILED
  fi
}

atomic_receipt() {
  local destination="$1"
  /usr/bin/python3 -I -B - "${destination}" \
    'schema=ingress-guard-custody-receipt-v2' \
    'result=pass' \
    'source_revision_assertion=operator-reviewed-protected-main' \
    "source_revision=${INGRESS_GUARD_SOURCE_REVISION}" \
    "manifest_sha256=${INGRESS_GUARD_MANIFEST_SHA256}" \
    "bootstrap_sha256=${INGRESS_GUARD_CUSTODY_SHA256}" \
    'public_artifacts=held-inode-copied' \
    'private_inventory=not-read' <<'PY' || die RECEIPT_WRITE_FAILED
import os
import stat
import sys

destination = sys.argv[1]
fields = sys.argv[2:]
if len(fields) != 8 or any(
    not field or "\n" in field or "\r" in field or field.count("=") != 1
    for field in fields
):
    raise ValueError("receipt fields")
payload = ("\n".join(fields) + "\n").encode("ascii")
parent, name = os.path.split(destination)
temporary_name = name + ".tmp"
parent_fd = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)


def metadata(child):
    return os.stat(child, dir_fd=parent_fd, follow_symlinks=False)


def read_file(child, allowed_links=(1,)):
    descriptor = os.open(
        child, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd
    )
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink not in allowed_links
        ):
            raise ValueError("receipt metadata")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            size += len(chunk)
            if size > 4096:
                raise ValueError("receipt size")
            chunks.append(chunk)
        return b"".join(chunks), observed
    finally:
        os.close(descriptor)


try:
    destination_exists = False
    temporary_exists = False
    try:
        destination_metadata = metadata(name)
        destination_exists = True
    except FileNotFoundError:
        destination_metadata = None
    try:
        temporary_metadata = metadata(temporary_name)
        temporary_exists = True
    except FileNotFoundError:
        temporary_metadata = None

    # A kill after the no-replace hard link but before unlinking the temporary
    # leaves two names for one fully durable inode. Reconcile only that exact
    # state; every foreign link or type fails closed.
    if temporary_exists:
        if (
            destination_exists
            and temporary_metadata.st_ino == destination_metadata.st_ino
            and temporary_metadata.st_dev == destination_metadata.st_dev
            and temporary_metadata.st_nlink == 2
        ):
            read_file(temporary_name, (2,))
            os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            temporary_exists = False
        elif not destination_exists:
            read_file(temporary_name)
            os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            temporary_exists = False
        else:
            raise ValueError("receipt temporary collision")

    if destination_exists:
        observed, _metadata = read_file(name)
        if observed != payload:
            raise ValueError("immutable receipt mismatch")
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
        observed, _metadata = read_file(name)
        if observed != payload:
            raise ValueError("receipt verification")
finally:
    os.close(parent_fd)
PY
}

launch_custodied() {
  local action="$1" destination="$2" receipt="$3"
  exec /usr/bin/python3 -I -B /proc/self/fd/8 "${action}" "${destination}" "${receipt}" \
    "${INGRESS_GUARD_SOURCE_REVISION}" "${INGRESS_GUARD_MANIFEST_SHA256}" 8<<'PY'
import fcntl
import hashlib
import os
import stat
import sys

try:
    os.close(8)
except OSError:
    pass

action, custody, receipt, revision, expected_manifest = sys.argv[1:]
actions = {
    "--install": ("bootstrap/pi/ingress-guard/install-ingress-guard.sh", []),
    "--retrofit-activate": (
        "bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh",
        ["--activate"],
    ),
    "--retrofit-close": (
        "bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh",
        ["--close-after-reboot"],
    ),
    "--recover": ("bootstrap/pi/ingress-guard/recover-ingress-guard.sh", ["--recover"]),
}
if action not in actions:
    raise ValueError("launch action")
entry_relative, entry_arguments = actions[action]
library_relative = "bootstrap/pi/ingress-guard/transaction-lib.sh"
recovery_relative = "bootstrap/pi/ingress-guard/recover-ingress-guard.sh"


def read_descriptor(descriptor, maximum=512 * 1024):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("unsafe file")
    chunks = []
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > maximum:
            raise ValueError("file too large")
        chunks.append(chunk)
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after) or len(payload) != after.st_size:
        raise ValueError("file changed during read")
    return payload, after


def sealed_snapshot(name, payload, mode):
    descriptor = os.memfd_create(
        name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short memfd write")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        os.set_inheritable(descriptor, True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_beneath(root_fd, relative):
    parts = relative.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ValueError("unsafe path")
    directory_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


root_fd = os.open(
    custody, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
descriptors = []
try:
    root_metadata = os.fstat(root_fd)
    if (
        root_metadata.st_uid != 0
        or root_metadata.st_gid != 0
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise ValueError("custody metadata")
    manifest_fd = open_beneath(root_fd, "source-manifest.v1")
    try:
        manifest, manifest_metadata = read_descriptor(manifest_fd)
        if (
            manifest_metadata.st_uid != 0
            or manifest_metadata.st_gid != 0
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
            or hashlib.sha256(manifest).hexdigest() != expected_manifest
        ):
            raise ValueError("manifest binding")
    finally:
        os.close(manifest_fd)
    parsed = {}
    for line in manifest.decode("ascii").splitlines():
        digest, mode, relative = line.split("\t")
        if relative in parsed:
            raise ValueError("manifest duplicate")
        parsed[relative] = (digest, mode)
    for required, mode in (
        (entry_relative, "0700"),
        (library_relative, "0600"),
        (recovery_relative, "0700"),
    ):
        if parsed.get(required, (None, None))[1] != mode:
            raise ValueError("manifest inventory")
    if parsed.get("bootstrap/pi/ingress-guard/custody-ingress-guard.sh", (None,))[0] != \
            os.environ["INGRESS_GUARD_CUSTODY_SHA256"]:
        raise ValueError("fixed launcher manifest binding")

    receipt_fd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        receipt_bytes, receipt_metadata = read_descriptor(receipt_fd, 4096)
        expected_receipt = ("\n".join((
            "schema=ingress-guard-custody-receipt-v2",
            "result=pass",
            "source_revision_assertion=operator-reviewed-protected-main",
            f"source_revision={revision}",
            f"manifest_sha256={expected_manifest}",
            f"bootstrap_sha256={os.environ['INGRESS_GUARD_CUSTODY_SHA256']}",
            "public_artifacts=held-inode-copied",
            "private_inventory=not-read",
        )) + "\n").encode("ascii")
        if (
            receipt_metadata.st_uid != 0
            or receipt_metadata.st_gid != 0
            or stat.S_IMODE(receipt_metadata.st_mode) != 0o600
            or receipt_bytes != expected_receipt
        ):
            raise ValueError("custody receipt")
        receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    finally:
        os.close(receipt_fd)

    for relative in (entry_relative, library_relative, recovery_relative, library_relative):
        descriptor = open_beneath(root_fd, relative)
        try:
            payload, metadata = read_descriptor(descriptor)
            expected_digest, expected_mode = parsed[relative]
            if (
                metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != int(expected_mode, 8)
                or hashlib.sha256(payload).hexdigest() != expected_digest
            ):
                raise ValueError("entrypoint binding")
        finally:
            os.close(descriptor)
        descriptors.append(
            sealed_snapshot(relative.rsplit("/", 1)[-1], payload, int(expected_mode, 8))
        )

    entry_fd, library_fd, recovery_fd, recovery_library_fd = descriptors
    allowed_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
        "INGRESS_GUARD_SOURCE_REVISION": revision,
        "INGRESS_GUARD_MANIFEST_SHA256": expected_manifest,
        "INGRESS_GUARD_LAUNCH_VERIFIED": revision + ":" + expected_manifest,
        "INGRESS_GUARD_LAUNCH_CUSTODY_DIR": custody,
        "INGRESS_GUARD_TRANSACTION_LIBRARY": f"/proc/self/fd/{library_fd}",
        "INGRESS_GUARD_RECOVERY_ENTRY": f"/proc/self/fd/{recovery_fd}",
        "INGRESS_GUARD_RECOVERY_LIBRARY": f"/proc/self/fd/{recovery_library_fd}",
        "INGRESS_GUARD_CUSTODY_RECEIPT_SHA256": receipt_sha256,
    }
    for name in (
        "CONFIRM_INGRESS_GUARD_INSTALL",
        "CONFIRM_INGRESS_GUARD_RETROFIT",
        "CONFIRM_INGRESS_GUARD_RETROFIT_CLOSE",
        "CONFIRM_INGRESS_GUARD_RECOVERY",
        "SSH_CONNECTION",
        "SUDO_USER",
        "TERM",
    ):
        if name in os.environ:
            allowed_environment[name] = os.environ[name]
    fcntl.flock(9, fcntl.LOCK_UN)
    os.close(9)
    os.execve(
        "/bin/bash",
        ["bash", f"/proc/self/fd/{entry_fd}", *entry_arguments],
        allowed_environment,
    )
finally:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass
    os.close(root_fd)
PY
}

[[ "${EUID}" -eq 0 ]] || die NOT_ROOT
[[ -t 0 && -t 1 && -t 2 ]] || die DIRECT_TTY_REQUIRED
if [[ -n "${SSH_CONNECTION:-}" && \
  ( -z "${SUDO_USER:-}" || "${SUDO_USER}" == root ) ]]; then
  die ROOT_SSH_FORBIDDEN
fi

for command_name in flock install mktemp mv readlink sha256sum stat sync timeout; do
  command -v "${command_name}" >/dev/null 2>&1 || die TOOL_MISSING
done
[[ "$(command -v python3)" == /usr/bin/python3 ]] || die PYTHON_IDENTITY_INVALID
[[ "$(command -v timeout)" == /usr/bin/timeout ]] || die TIMEOUT_IDENTITY_INVALID
assert_directory /usr/local/sbin 755 || die BOOTSTRAP_PARENT_INVALID
[[ "$(readlink -f -- "${BASH_SOURCE[0]}")" == "${IG_BOOTSTRAP_PATH}" ]] \
  || die MUTABLE_ENTRYPOINT_REFUSED
[[ -f "${IG_BOOTSTRAP_PATH}" && ! -L "${IG_BOOTSTRAP_PATH}" ]] \
  || die BOOTSTRAP_INVALID
[[ "$(stat -c '%u:%g:%a:%h' -- "${IG_BOOTSTRAP_PATH}")" == 0:0:700:1 ]] \
  || die BOOTSTRAP_INVALID

action="${1:---stage}"
case "${action}" in
  --stage|--install|--retrofit-activate|--retrofit-close|--recover)
    ;;
  *)
    die ACTION_INVALID
    ;;
esac

[[ "${INGRESS_GUARD_SOURCE_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] \
  || die SOURCE_REVISION_INVALID
[[ "${INGRESS_GUARD_MANIFEST_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
  || die MANIFEST_BINDING_INVALID
[[ "${INGRESS_GUARD_CUSTODY_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
  || die BOOTSTRAP_BINDING_INVALID
if [[ "${action}" == --stage ]]; then
  [[ "${CONFIRM_INGRESS_GUARD_CUSTODY:-}" == \
    "custody-reviewed-ingress-guard-${INGRESS_GUARD_SOURCE_REVISION}-${INGRESS_GUARD_MANIFEST_SHA256}" ]] \
    || die EXACT_CONFIRMATION_MISSING
fi
[[ "$(sha256sum -- "${IG_BOOTSTRAP_PATH}" | awk '{print $1}')" == \
  "${INGRESS_GUARD_CUSTODY_SHA256}" ]] || die BOOTSTRAP_BINDING_INVALID

source_root=''
if [[ "${action}" == --stage ]]; then
  source_root="${INGRESS_GUARD_SOURCE_ROOT:-}"
  [[ "${source_root}" == /* && "${source_root}" != / && "${source_root}" != *$'\n'* ]] \
    || die SOURCE_ROOT_INVALID
fi

ensure_directory /var/lib/website-infrastructure 0700
ensure_directory "${IG_STATE_ROOT}" 0700
ensure_directory "${IG_CUSTODY_ROOT}" 0700
ensure_directory "${IG_RECEIPT_ROOT}" 0700
ensure_directory "${IG_TRANSACTION_ROOT}" 0700
if [[ ! -e "${IG_LOCK_PATH}" && ! -L "${IG_LOCK_PATH}" ]]; then
  install -o root -g root -m 0600 -- /dev/null "${IG_LOCK_PATH}" || die LOCK_CREATE_FAILED
fi
[[ -f "${IG_LOCK_PATH}" && ! -L "${IG_LOCK_PATH}" ]] || die LOCK_INVALID
[[ "$(stat -c '%u:%g:%a:%h' -- "${IG_LOCK_PATH}")" == 0:0:600:1 ]] || die LOCK_INVALID
exec 9<>"${IG_LOCK_PATH}"
flock -n 9 || die LOCK_HELD

destination="${IG_CUSTODY_ROOT}/${INGRESS_GUARD_MANIFEST_SHA256}"
stage=''
operation=verify
copy_target="${destination}"
if [[ ! -e "${destination}" && ! -L "${destination}" ]]; then
  [[ "${action}" == --stage ]] || die CUSTODY_MISSING
  operation=copy
  stage="$(mktemp -d "${IG_CUSTODY_ROOT}/.stage.XXXXXXXX")" || die STAGE_CREATE_FAILED
  chmod 0700 -- "${stage}" || die STAGE_CREATE_FAILED
  chown root:root -- "${stage}" || die STAGE_CREATE_FAILED
  copy_target="${stage}"
fi

cleanup_stage() {
  local status=$?
  trap - EXIT HUP INT TERM
  if (( status != 0 )) && [[ -n "${stage:-}" && "${stage}" == "${IG_CUSTODY_ROOT}/.stage."* ]]; then
    /usr/bin/timeout --signal=TERM --kill-after=2s 5s /usr/bin/python3 -I -B -c \
      'import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' "${stage}" \
      >/dev/null 2>&1 || true
  fi
  exit "${status}"
}
trap cleanup_stage EXIT
trap 'trap "" HUP INT TERM; exit 129' HUP
trap 'trap "" HUP INT TERM; exit 130' INT
trap 'trap "" HUP INT TERM; exit 143' TERM

# The copier opens the source root and every path component with O_NOFOLLOW,
# hashes the bytes read from that descriptor, and writes exactly those bytes
# to a new root-owned file. Source path replacement or in-place mutation can
# therefore only produce a hash failure; no checkout byte is executed.
/usr/bin/timeout --signal=TERM --kill-after=2s 30s /usr/bin/python3 -I -B - "${source_root}" "${copy_target}" \
  "${INGRESS_GUARD_MANIFEST_SHA256}" "${IG_MANIFEST_REL}" "${operation}" \
  "${INGRESS_GUARD_CUSTODY_SHA256}" <<'PY' \
  || die SOURCE_CUSTODY_FAILED
import hashlib
import os
import stat
import sys

(
    source_root,
    destination,
    expected_manifest,
    manifest_relative,
    operation,
    fixed_launcher_hash,
) = sys.argv[1:]
allowed = {
    "bootstrap/pi/ingress-guard/custody-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/install-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/recover-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/transaction-lib.sh": 0o600,
    "bootstrap/pi/ingress-guard/load-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/verify-ingress-guard.sh": 0o700,
    "bootstrap/pi/ingress-guard/systemd/website-infrastructure-ingress-guard.service": 0o644,
    "bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf": 0o644,
    "scripts/validate_admin_ingress_contract.py": 0o600,
    "scripts/validate_ingress_guard.py": 0o600,
}
max_bytes = 512 * 1024


def open_beneath(root_fd, relative):
    parts = relative.split("/")
    if not parts or any(not p or p in {".", ".."} for p in parts):
        raise ValueError("unsafe relative path")
    directory_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def read_exact(root_fd, relative):
    descriptor = open_beneath(root_fd, relative)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe source type")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("source too large")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def parse_manifest(manifest_bytes):
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest:
        raise ValueError("manifest binding mismatch")
    text = manifest_bytes.decode("ascii")
    parsed = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("manifest shape")
        digest, mode_text, relative = fields
        if relative in parsed or relative not in allowed:
            raise ValueError("manifest inventory")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("manifest digest")
        if mode_text != format(allowed[relative], "04o"):
            raise ValueError("manifest mode")
        parsed[relative] = digest
    if set(parsed) != set(allowed):
        raise ValueError("manifest inventory")
    if parsed["bootstrap/pi/ingress-guard/custody-ingress-guard.sh"] != fixed_launcher_hash:
        raise ValueError("fixed launcher manifest binding")
    return parsed


def verify_destination():
    root_fd = os.open(
        destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        root_metadata = os.fstat(root_fd)
        if (
            root_metadata.st_uid != 0
            or root_metadata.st_gid != 0
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ValueError("custody root metadata")
        manifest_bytes = read_exact(root_fd, "source-manifest.v1")
        manifest_descriptor = open_beneath(root_fd, "source-manifest.v1")
        try:
            manifest_metadata = os.fstat(manifest_descriptor)
            if (
                manifest_metadata.st_uid != 0
                or manifest_metadata.st_gid != 0
                or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
                or manifest_metadata.st_nlink != 1
            ):
                raise ValueError("manifest metadata")
        finally:
            os.close(manifest_descriptor)
        parsed = parse_manifest(manifest_bytes)
        expected_files = set(allowed) | {"source-manifest.v1"}
        expected_directories = {""}
        for relative in allowed:
            parts = relative.split("/")[:-1]
            for index in range(1, len(parts) + 1):
                expected_directories.add("/".join(parts[:index]))
            payload = read_exact(root_fd, relative)
            descriptor = open_beneath(root_fd, relative)
            try:
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_uid != 0
                    or metadata.st_gid != 0
                    or stat.S_IMODE(metadata.st_mode) != allowed[relative]
                    or metadata.st_nlink != 1
                    or hashlib.sha256(payload).hexdigest() != parsed[relative]
                ):
                    raise ValueError("custody artifact mismatch")
            finally:
                os.close(descriptor)
        observed_files = set()
        observed_directories = set()
        for current, directories, files in os.walk(
            destination, topdown=True, followlinks=False
        ):
            current_relative = os.path.relpath(current, destination)
            if current_relative == ".":
                current_relative = ""
            current_metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or current_metadata.st_uid != 0
                or current_metadata.st_gid != 0
                or stat.S_IMODE(current_metadata.st_mode) != 0o700
            ):
                raise ValueError("custody directory metadata")
            observed_directories.add(current_relative.replace(os.sep, "/"))
            for name in directories:
                if stat.S_ISLNK(os.lstat(os.path.join(current, name)).st_mode):
                    raise ValueError("custody symlink")
            for name in files:
                child = os.path.join(current, name)
                if not stat.S_ISREG(os.lstat(child).st_mode):
                    raise ValueError("custody file type")
                observed_files.add(
                    os.path.relpath(child, destination).replace(os.sep, "/")
                )
        if observed_files != expected_files or observed_directories != expected_directories:
            raise ValueError("custody inventory")
    finally:
        os.close(root_fd)


if operation == "copy":
    root_fd = os.open(
        source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        manifest_bytes = read_exact(root_fd, manifest_relative)
        parsed = parse_manifest(manifest_bytes)

        for relative in sorted(allowed):
            payload = read_exact(root_fd, relative)
            if hashlib.sha256(payload).hexdigest() != parsed[relative]:
                raise ValueError("source hash")
            target = os.path.join(destination, *relative.split("/"))
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                allowed[relative],
            )
            try:
                os.fchmod(descriptor, allowed[relative])
                os.fchown(descriptor, 0, 0)
                write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        manifest_target = os.path.join(destination, "source-manifest.v1")
        descriptor = os.open(
            manifest_target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            write_all(descriptor, manifest_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for current, directories, _files in os.walk(destination, topdown=False):
            for name in directories:
                os.chmod(os.path.join(current, name), 0o700)
                os.chown(os.path.join(current, name), 0, 0)
            directory_fd = os.open(
                current, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        os.close(root_fd)
    verify_destination()
elif operation == "verify":
    verify_destination()
else:
    raise ValueError("operation")
PY

if [[ "${operation}" == copy ]]; then
  mv -T -- "${stage}" "${destination}" || die CUSTODY_COMMIT_FAILED
  stage=''
  sync -f -- "${IG_CUSTODY_ROOT}" >/dev/null 2>&1 || die DURABILITY_FAILED
fi
custody_receipt="${IG_RECEIPT_ROOT}/custody.${INGRESS_GUARD_MANIFEST_SHA256}.receipt.v2"
atomic_receipt "${custody_receipt}"

if [[ "${action}" != --stage ]]; then
  launch_custodied "${action}" "${destination}" "${custody_receipt}"
fi

trap - EXIT HUP INT TERM
printf 'INGRESS-GUARD CUSTODY PASS public-artifacts-root-custodied\n'
