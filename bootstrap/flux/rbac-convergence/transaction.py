#!/usr/bin/python3 -IB
"""Protected, in-place Flux RBAC convergence transaction.

This program is deliberately not a generic Kubernetes apply wrapper.  Its
closed inventory is the existing-install migration described by issue #141:
six additive per-controller RBAC objects, twelve active-site namespaced RBAC
objects, two controller argument rollouts, replacement of the shared RBAC
pair, and deletion of the legacy cluster-admin binding.  It never reads a
Secret and never applies ``access.yaml``.

The file is executed only from the fixed root-owned custody launcher described
in this directory's README.  Importing it is supported for hermetic tests;
direct execution from a checkout is refused before a kubeconfig is opened.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Mapping, MutableMapping, Sequence


SCHEMA = "flux-rbac-convergence-transaction-v1"
PLAN_SCHEMA = "flux-rbac-convergence-plan-v1"
JOURNAL_SCHEMA = "flux-rbac-convergence-journal-v1"
RECEIPT_SCHEMA = "flux-rbac-convergence-receipt-v1"
ORACLE_EVIDENCE_SCHEMA = "flux-rbac-convergence-oracle-evidence-v1"
VERIFICATION_SCHEMA = "flux-rbac-convergence-verification-v1"
TARGET_SCHEMA = "flux-rbac-convergence-target-v1"
CUSTODY_SCHEMA = "flux-rbac-convergence-custody-receipt-v1"
DESIRED_SCHEMA = "flux-rbac-convergence-desired-v1"

REPOSITORY = "snaraj/website-infrastructure"
OWNER_LOGIN = "snaraj"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
SOURCE_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
# This is a closed, one-time migration executable, not a generic release
# selector.  Its protected-base candidate follows v0.1.23 and can therefore
# enter custody only through the one platform release that this change creates.
# If the protected base advances before merge, the candidate and this binding
# must be regenerated and reviewed together.
AUTHORIZED_RELEASE_TAG = "v0.1.24"
DNS_RE = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")
UID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)

STATE_ROOT = Path("/var/lib/website-infrastructure/flux-rbac-convergence")
STATE_PARENT = STATE_ROOT.parent
CUSTODY_ROOT = STATE_ROOT / "custody"
CUSTODY_RECEIPT = STATE_ROOT / "custody.receipt.json"
INPUT_ROOT = STATE_ROOT / "input"
TARGET_PATH = INPUT_ROOT / "target.json"
PLAN_PATH = STATE_ROOT / "plan.json"
JOURNAL_PATH = STATE_ROOT / "journal.json"
RECEIPT_ROOT = STATE_ROOT / "receipts"
EVIDENCE_ROOT = STATE_ROOT / "evidence"
LOCK_PATH = STATE_ROOT / "transaction.lock"
INSTALLED_LAUNCHER = Path(
    "/usr/local/sbin/website-infrastructure-flux-rbac-convergence"
)
PYTHON_PATH = Path("/usr/bin/python3")
SOURCE_MANIFEST_REL = "bootstrap/flux/rbac-convergence/source-manifest.v1"
DESIRED_REL = "bootstrap/flux/rbac-convergence/desired-active.json"
ORACLE_REL = "scripts/flux_rbac_denial_oracle.py"
KUBECONFIG_VALIDATOR_REL = "scripts/validate_kubeconfig_snapshot.py"
PLATFORM_CONTRACT_REL = "scripts/ci/platform_release_contract.py"
VERSIONS_REL = "versions.env"
RELEASE_FRAGMENT_REL = "changelog.d/141-flux-rbac-v024-dynamic-site-baseline.md"

TRANSACTION_ANNOTATION = "platform.snaraj.dev/flux-rbac-transaction"
PROOF_ANNOTATION = "platform.snaraj.dev/flux-rbac-convergence-proof"
PLAN_TTL = dt.timedelta(hours=24)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_HTTP_BYTES = 8 * 1024 * 1024
ROLLOUT_TIMEOUT_SECONDS = 300
HELM_TIMEOUT_SECONDS = 300
DELETE_TIMEOUT_SECONDS = 60
TRANSACTION_TARGET_COUNT = 23

CONTROLLERS = (
    "source-controller",
    "kustomize-controller",
    "helm-controller",
)
CONTROLLER_RUNTIME_FIELDS = (
    "uid",
    "generation",
    "image",
    "args",
    "podUid",
    "podRestarts",
    "podServiceAccountName",
    "podContainerName",
    "podImage",
    "podImageID",
    "podArgs",
    "podCommand",
    "podReplicaSetName",
    "podReplicaSetUid",
    "semanticSha256",
)
CONTROLLER_SUBJECTS = frozenset(
    ("flux-system", controller) for controller in CONTROLLERS
)
TRACKED_RBAC_SUBJECTS = CONTROLLER_SUBJECTS | frozenset(
    {
        ("naranjo-online", "helm-reconciler"),
        ("lidersea-com", "helm-reconciler"),
    }
)
SPLIT_NAMES = (
    "crd-controller-source-flux-system",
    "crd-controller-kustomize-flux-system",
    "crd-controller-helm-flux-system",
)
SHARED_NAME = "crd-controller-flux-system"
BROAD_NAME = "cluster-reconciler-flux-system"
KUBERNETES_DEFAULT_GROUP_BINDINGS = {
    "system:basic-user": frozenset({"system:authenticated"}),
    "system:discovery": frozenset({"system:authenticated"}),
    "system:public-info-viewer": frozenset(
        {"system:authenticated", "system:unauthenticated"}
    ),
    "system:service-account-issuer-discovery": frozenset(
        {"system:serviceaccounts"}
    ),
}
SITE_RELEASES = frozenset(
    {
        ("naranjo-online", "naranjo-online"),
        ("lidersea-com", "lidersea-com"),
    }
)
SITE_CHART_SEMVER_RANGE = ">=0.1.9 <1.0.0"
SITE_CHART_MIN_VERSION = (0, 1, 9)
SITE_CHART_MAX_VERSION = (1, 0, 0)
SITE_CHART_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
SITE_SIGNING_REPOSITORIES = {
    ("naranjo-online", "naranjo-online"): "naranjo.online",
    ("lidersea-com", "lidersea-com"): "lidersea.com",
}
HELM_READY_REASONS = frozenset(
    {"InstallSucceeded", "UpgradeSucceeded", "TestSucceeded"}
)
FORBIDDEN_HELM_SPEC_FIELDS = frozenset(
    {
        "chart",
        "dependsOn",
        "kubeConfig",
        "postRenderers",
        "storageNamespace",
        "targetNamespace",
        "valuesFrom",
    }
)
SITE_INVENTORY_KINDS = {
    "Deployment": ("apps", "v1"),
    "Service": ("", "v1"),
    "ServiceAccount": ("", "v1"),
    "NetworkPolicy": ("networking.k8s.io", "v1"),
}

FLUX_CRD_COLLECTIONS = {
    "Bucket": "/apis/source.toolkit.fluxcd.io/v1/buckets",
    "ExternalArtifact": "/apis/source.toolkit.fluxcd.io/v1/externalartifacts",
    "GitRepository": "/apis/source.toolkit.fluxcd.io/v1/gitrepositories",
    "HelmChart": "/apis/source.toolkit.fluxcd.io/v1/helmcharts",
    "HelmRepository": "/apis/source.toolkit.fluxcd.io/v1/helmrepositories",
    "OCIRepository": "/apis/source.toolkit.fluxcd.io/v1/ocirepositories",
    "Kustomization": "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
    "HelmRelease": "/apis/helm.toolkit.fluxcd.io/v2/helmreleases",
}
FLUX_EMPTY_KINDS = frozenset(
    {
        "Bucket",
        "ExternalArtifact",
        "GitRepository",
        "HelmChart",
        "HelmRepository",
        "Kustomization",
    }
)

VOLATILE_ANNOTATIONS = frozenset(
    {
        "deployment.kubernetes.io/revision",
        "kubectl.kubernetes.io/last-applied-configuration",
        TRANSACTION_ANNOTATION,
    }
)
SERVER_METADATA = frozenset(
    {
        "creationTimestamp",
        "deletionGracePeriodSeconds",
        "deletionTimestamp",
        "generateName",
        "generation",
        "managedFields",
        "resourceVersion",
        "selfLink",
        "uid",
    }
)


class TransactionError(RuntimeError):
    """A fail-closed transaction result safe to report as a fixed token."""


class RecoveryRequired(TransactionError):
    """The live state cannot be classified safely without owner recovery."""


class Interrupted(TransactionError):
    """A catchable signal arrived after the durable journal existed."""


TRANSACTION_SIGNALS = frozenset({signal.SIGINT, signal.SIGTERM, signal.SIGHUP})

MODE_ENVIRONMENT = {
    "--stage": frozenset(
        {
            "LC_ALL",
            "FLUX_RBAC_SOURCE_ROOT",
            "FLUX_RBAC_SOURCE_REVISION",
            "FLUX_RBAC_MANIFEST_SHA256",
            "FLUX_RBAC_LAUNCHER_SHA256",
            "FLUX_RBAC_PYTHON_SHA256",
            "CONFIRM_FLUX_RBAC_CUSTODY",
        }
    ),
    "--plan": frozenset({"LC_ALL"}),
    "--apply": frozenset(
        {
            "LC_ALL",
            "FLUX_RBAC_EXPECTED_PLAN_SHA256",
            "CONFIRM_FLUX_RBAC_APPLY",
        }
    ),
    "--rollback": frozenset(
        {
            "LC_ALL",
            "FLUX_RBAC_EXPECTED_PLAN_SHA256",
            "CONFIRM_FLUX_RBAC_ROLLBACK",
        }
    ),
    "--verify": frozenset({"LC_ALL", "FLUX_RBAC_EXPECTED_PLAN_SHA256"}),
}


def block_transaction_signals() -> object | None:
    """Defer handled signals across one response-to-journal critical section."""

    if not hasattr(signal, "pthread_sigmask"):
        return None
    return signal.pthread_sigmask(signal.SIG_BLOCK, TRANSACTION_SIGNALS)


def restore_transaction_signals(previous: object | None) -> None:
    if previous is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)  # type: ignore[arg-type]


def validate_process_boundary(mode: str) -> None:
    """Reject ambient startup influence before any privileged mode acts."""

    expected_environment = MODE_ENVIRONMENT.get(mode)
    if expected_environment is None:
        raise TransactionError("MODE_INVALID")
    flags = sys.flags
    if (
        os.geteuid() != 0
        or sys.version_info[:2] < (3, 9)
        or sys.argv[0] != str(INSTALLED_LAUNCHER)
        or sys.executable != str(PYTHON_PATH)
        or flags.isolated != 1
        or flags.ignore_environment != 1
        or flags.no_user_site != 1
        or flags.dont_write_bytecode != 1
    ):
        raise TransactionError("PROCESS_BOUNDARY_INVALID")
    if set(os.environ) != set(expected_environment) or os.environ.get("LC_ALL") != "C":
        raise TransactionError("PROCESS_ENVIRONMENT_INVALID")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise TransactionError("JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def parse_json_bytes(payload: bytes, *, maximum: int = MAX_JSON_BYTES) -> object:
    if not payload or len(payload) > maximum or b"\x00" in payload:
        raise TransactionError("JSON_SIZE_INVALID")
    try:
        return json.loads(
            payload,
            object_pairs_hook=_json_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                TransactionError("JSON_NUMBER_INVALID")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransactionError("JSON_INVALID") from exc


def read_regular(
    path: Path,
    *,
    owner: int | None = None,
    mode: int | None = None,
    maximum: int = MAX_JSON_BYTES,
    durable: bool = False,
) -> bytes:
    if not path.is_absolute():
        raise TransactionError("PATH_NOT_ABSOLUTE")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TransactionError("FILE_OPEN_FAILED") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TransactionError("FILE_METADATA_INVALID")
        if owner is not None and before.st_uid != owner:
            raise TransactionError("FILE_OWNER_INVALID")
        if mode is not None and stat.S_IMODE(before.st_mode) != mode:
            raise TransactionError("FILE_MODE_INVALID")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise TransactionError("FILE_SIZE_INVALID")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if stable(before) != stable(after) or size != after.st_size:
            raise TransactionError("FILE_CHANGED_DURING_READ")
        if durable:
            os.fsync(descriptor)
            fsync_directory(path.parent)
            durable_after = os.fstat(descriptor)
            if stable(before) != stable(durable_after):
                raise TransactionError("FILE_CHANGED_DURING_DURABILITY_BARRIER")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_regular_descriptor(descriptor: int, *, maximum: int) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise TransactionError("SOURCE_FILE_METADATA_INVALID")
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > maximum:
            raise TransactionError("SOURCE_FILE_SIZE_INVALID")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    stable = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if stable(before) != stable(after) or size != after.st_size:
        raise TransactionError("SOURCE_FILE_CHANGED_DURING_READ")
    return b"".join(chunks)


def open_directory_no_symlinks(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise TransactionError("CUSTODY_SOURCE_ROOT_INVALID")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise TransactionError("CUSTODY_SOURCE_ROOT_INVALID")
            child = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise TransactionError("CUSTODY_SOURCE_ROOT_INVALID")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise TransactionError("CUSTODY_SOURCE_ROOT_INVALID") from exc
    except BaseException:
        os.close(descriptor)
        raise


def read_relative_regular(
    root_descriptor: int, relative: str, *, maximum: int
) -> bytes:
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise TransactionError("CUSTODY_SOURCE_ENTRY_INVALID")
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    directory = os.dup(root_descriptor)
    try:
        for component in path.parts[:-1]:
            if component in {"", ".", ".."}:
                raise TransactionError("CUSTODY_SOURCE_ENTRY_INVALID")
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.parts[-1], file_flags, dir_fd=directory)
        try:
            return read_regular_descriptor(descriptor, maximum=maximum)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise TransactionError("CUSTODY_SOURCE_ENTRY_INVALID") from exc
    finally:
        os.close(directory)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_atomic_temporary(path: Path, expected: os.stat_result) -> bytes:
    """Read one already-classified atomic-write temporary without following it."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            before.st_dev != expected.st_dev
            or before.st_ino != expected.st_ino
            or before.st_mode != expected.st_mode
            or before.st_uid != expected.st_uid
            or before.st_gid != expected.st_gid
            or before.st_nlink != expected.st_nlink
        ):
            raise TransactionError("OUTPUT_TEMP_CHANGED")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_JSON_BYTES:
                raise TransactionError("OUTPUT_TEMP_TOO_LARGE")
            chunks.append(chunk)
        # A complete-looking leftover is not safe to publish until this
        # recovery attempt has made the file contents durable itself.
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or size != after.st_size:
            raise TransactionError("OUTPUT_TEMP_CHANGED")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def recover_atomic_temporary(path: Path, payload: bytes, *, replace: bool) -> bool:
    """Recover only a strictly attributable fixed ``.new`` file.

    Every caller holds the transaction lock, and no caller proceeds past an
    unpublished journal intent to an API mutation.  Therefore a complete temp
    matching this retry can be published, while a partial/different nlink-one
    temp can be discarded and rewritten.  The nlink-two case is the narrow
    crash window after a no-replace link published the destination.
    """

    temporary = path.with_name(path.name + ".new")
    try:
        metadata = temporary.lstat()
    except FileNotFoundError:
        return False
    parent_metadata = path.parent.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != parent_metadata.st_uid
        or metadata.st_gid != parent_metadata.st_gid
        or metadata.st_dev != parent_metadata.st_dev
        or metadata.st_nlink not in {1, 2}
    ):
        raise TransactionError("OUTPUT_STALE_TEMP_INVALID")
    existing: os.stat_result | None = None
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    if metadata.st_nlink == 2:
        if (
            existing is None
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_dev != metadata.st_dev
            or existing.st_ino != metadata.st_ino
            or existing.st_nlink != 2
        ):
            raise TransactionError("OUTPUT_STALE_LINK_INVALID")
        published_payload = read_atomic_temporary(temporary, metadata)
        temporary.unlink()
        fsync_directory(path.parent)
        if published_payload == payload:
            return True
        if not replace:
            raise TransactionError("OUTPUT_STALE_LINK_COLLISION")
        return False
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or stat.S_IMODE(existing.st_mode) != 0o600
        or existing.st_uid != parent_metadata.st_uid
        or existing.st_gid != parent_metadata.st_gid
        or existing.st_dev != parent_metadata.st_dev
        or existing.st_nlink != 1
    ):
        raise TransactionError("OUTPUT_DESTINATION_INVALID")
    stale_payload = read_atomic_temporary(temporary, metadata)
    if stale_payload == payload:
        if replace:
            os.replace(temporary, path)
        else:
            if existing is not None:
                raise TransactionError("OUTPUT_STALE_TEMP_DESTINATION_COLLISION")
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        fsync_directory(path.parent)
        return True
    temporary.unlink()
    fsync_directory(path.parent)
    return False


def atomic_write(
    path: Path,
    payload: bytes,
    *,
    replace: bool,
    preserve_complete_temporary: bool = False,
) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise TransactionError("OUTPUT_PARENT_INVALID")
    temporary = path.with_name(path.name + ".new")
    if recover_atomic_temporary(path, payload, replace=replace):
        return
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    payload_complete = False
    try:
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except FileExistsError as exc:
            raise TransactionError("OUTPUT_TEMP_COLLISION") from exc
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise TransactionError("OUTPUT_SHORT_WRITE")
            view = view[written:]
        os.fsync(descriptor)
        payload_complete = True
        os.close(descriptor)
        descriptor = -1
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        fsync_directory(parent)
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        preserve = preserve_complete_temporary and payload_complete
        try:
            if not preserve and (temporary.exists() or temporary.is_symlink()):
                temporary.unlink()
            fsync_directory(parent)
        except OSError:
            pass
        raise


def publish_once(path: Path, payload: bytes) -> None:
    """Publish immutable bytes, including recovery of the nlink-two window."""

    if recover_atomic_temporary(path, payload, replace=False):
        return
    if path.exists() or path.is_symlink():
        owner = path.parent.lstat().st_uid
        if read_regular(
            path, owner=owner, mode=0o600, durable=True
        ) != payload:
            raise TransactionError("OUTPUT_PUBLISH_COLLISION")
        return
    atomic_write(path, payload, replace=False)


def ensure_root_directory(path: Path, mode: int) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != mode
            or path.is_symlink()
        ):
            raise TransactionError("STATE_DIRECTORY_INVALID")
        return
    path.mkdir(mode=mode)
    os.chown(path, 0, 0)
    os.chmod(path, mode)
    fsync_directory(path.parent)


def ensure_state_root() -> None:
    """Create only the two fixed, root-owned private state directories."""

    ensure_root_directory(STATE_PARENT, 0o700)
    ensure_root_directory(STATE_ROOT, 0o700)


def exact_fields(value: Mapping[str, object], fields: Iterable[str], label: str) -> None:
    expected = frozenset(fields)
    if frozenset(value) != expected:
        raise TransactionError(f"{label}_FIELDS_INVALID")


def require_string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TransactionError(f"{label}_INVALID")
    return value


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso8601(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise TransactionError(f"{label}_TIME_INVALID")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransactionError(f"{label}_TIME_INVALID") from exc
    if result.tzinfo is None:
        raise TransactionError(f"{label}_TIME_INVALID")
    return result


def semantic_object(value: Mapping[str, object]) -> dict[str, object]:
    """Return the writable, status-free semantic object used by plan review."""

    metadata_value = value.get("metadata")
    if not isinstance(metadata_value, Mapping):
        raise TransactionError("OBJECT_METADATA_INVALID")
    metadata: dict[str, object] = {}
    for key, item in metadata_value.items():
        if key in SERVER_METADATA:
            continue
        if key == "annotations":
            if not isinstance(item, Mapping):
                raise TransactionError("OBJECT_ANNOTATIONS_INVALID")
            annotations = {
                str(name): annotation
                for name, annotation in item.items()
                if name not in VOLATILE_ANNOTATIONS
            }
            if annotations:
                metadata[key] = annotations
            continue
        metadata[key] = copy.deepcopy(item)
    result: dict[str, object] = {
        "apiVersion": value.get("apiVersion"),
        "kind": value.get("kind"),
        "metadata": metadata,
    }
    for key, item in value.items():
        if key not in {"apiVersion", "kind", "metadata", "status"}:
            result[key] = copy.deepcopy(item)
    if not isinstance(result["apiVersion"], str) or not isinstance(result["kind"], str):
        raise TransactionError("OBJECT_TYPE_INVALID")
    return result


def semantic_hash(value: Mapping[str, object]) -> str:
    return sha256_bytes(canonical_json(semantic_object(value)))


def semantic_without_proof_annotation(
    value: Mapping[str, object],
) -> tuple[str | None, str]:
    """Return the proof annotation and the exact semantic hash without it."""

    normalized = semantic_object(value)
    metadata = normalized.get("metadata")
    if not isinstance(metadata, MutableMapping):
        raise TransactionError("OBJECT_METADATA_INVALID")
    annotations = metadata.get("annotations")
    proof_value: object | None = None
    if isinstance(annotations, MutableMapping):
        proof_value = annotations.pop(PROOF_ANNOTATION, None)
        if not annotations:
            metadata.pop("annotations", None)
    if proof_value is not None and not isinstance(proof_value, str):
        raise TransactionError("PROOF_ANNOTATION_VALUE_INVALID")
    return proof_value, sha256_bytes(canonical_json(normalized))


def metadata_identity(value: Mapping[str, object]) -> tuple[str, str | None, str]:
    metadata = value.get("metadata")
    if not isinstance(metadata, Mapping):
        raise TransactionError("OBJECT_METADATA_INVALID")
    kind = value.get("kind")
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if (
        not isinstance(kind, str)
        or not isinstance(name, str)
        or (namespace is not None and not isinstance(namespace, str))
    ):
        raise TransactionError("OBJECT_IDENTITY_INVALID")
    return kind, namespace, name


def live_identity(value: Mapping[str, object]) -> tuple[str, str]:
    metadata = value.get("metadata")
    if not isinstance(metadata, Mapping):
        raise TransactionError("LIVE_METADATA_INVALID")
    uid = require_string(metadata.get("uid"), UID_RE, "LIVE_UID")
    resource_version = metadata.get("resourceVersion")
    if (
        not isinstance(resource_version, str)
        or not resource_version.isascii()
        or not resource_version.isdecimal()
        or int(resource_version) <= 0
    ):
        raise TransactionError("LIVE_RESOURCE_VERSION_INVALID")
    return uid, resource_version


def object_is_terminating(value: Mapping[str, object]) -> bool:
    metadata = value.get("metadata")
    if not isinstance(metadata, Mapping):
        raise TransactionError("LIVE_METADATA_INVALID")
    return metadata.get("deletionTimestamp") is not None


def with_transaction_annotation(
    value: Mapping[str, object], attempt_id: str
) -> dict[str, object]:
    result = copy.deepcopy(dict(value))
    metadata = result.setdefault("metadata", {})
    if not isinstance(metadata, MutableMapping):
        raise TransactionError("DESIRED_METADATA_INVALID")
    annotations = metadata.setdefault("annotations", {})
    if not isinstance(annotations, MutableMapping):
        raise TransactionError("DESIRED_ANNOTATIONS_INVALID")
    existing = annotations.get(TRANSACTION_ANNOTATION)
    if existing not in (None, attempt_id):
        raise TransactionError("TRANSACTION_ANNOTATION_COLLISION")
    annotations[TRANSACTION_ANNOTATION] = attempt_id
    return result


def remove_transaction_annotation(value: Mapping[str, object]) -> dict[str, object]:
    result = copy.deepcopy(dict(value))
    metadata = result.get("metadata")
    if isinstance(metadata, MutableMapping):
        annotations = metadata.get("annotations")
        if isinstance(annotations, MutableMapping):
            annotations.pop(TRANSACTION_ANNOTATION, None)
            if not annotations:
                metadata.pop("annotations", None)
    return result


def writable_from_live(value: Mapping[str, object]) -> dict[str, object]:
    result = semantic_object(value)
    metadata = result["metadata"]
    assert isinstance(metadata, MutableMapping)
    uid, resource_version = live_identity(value)
    metadata["uid"] = uid
    metadata["resourceVersion"] = resource_version
    return result


def load_module(path: Path, name: str) -> ModuleType:
    payload = read_regular(path, owner=0, mode=0o600, maximum=2 * 1024 * 1024)
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(payload, str(path), "exec"), module.__dict__)
    except BaseException as exc:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise TransactionError("CUSTODY_MODULE_LOAD_FAILED") from exc
    return module


def parse_versions(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransactionError("VERSIONS_ENCODING_INVALID") from exc
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw != line or line.count("=") != 1:
            raise TransactionError("VERSIONS_LINE_INVALID")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
            raise TransactionError("VERSIONS_LINE_INVALID")
        if key in result:
            raise TransactionError("VERSIONS_DUPLICATE_KEY")
        result[key] = value
    return result


@dataclass(frozen=True)
class Target:
    release_tag: str
    kubectl: Path
    kubeconfig: Path
    context: str
    server: str
    ca_sha256: str
    kube_system_uid_sha256: str
    node_identity_sha256: str


def load_target(path: Path = TARGET_PATH) -> Target:
    document = parse_json_bytes(read_regular(path, owner=0, mode=0o600))
    if not isinstance(document, Mapping):
        raise TransactionError("TARGET_INVALID")
    exact_fields(
        document,
        {
            "schema",
            "releaseTag",
            "kubectl",
            "kubeconfig",
            "context",
            "server",
            "kubernetesCaSha256",
            "kubeSystemNamespaceUidSha256",
            "nodeIdentitySha256",
        },
        "TARGET",
    )
    if document.get("schema") != TARGET_SCHEMA:
        raise TransactionError("TARGET_SCHEMA_INVALID")
    tag = require_string(document.get("releaseTag"), TAG_RE, "TARGET_TAG")
    kubectl = Path(str(document.get("kubectl", "")))
    kubeconfig = Path(str(document.get("kubeconfig", "")))
    context = document.get("context")
    server = document.get("server")
    if (
        not kubectl.is_absolute()
        or not kubeconfig.is_absolute()
        or not isinstance(context, str)
        or not context
        or len(context) > 253
        or not isinstance(server, str)
        or not server.startswith("https://")
        or urllib.parse.urlsplit(server).username is not None
        or urllib.parse.urlsplit(server).password is not None
        or urllib.parse.urlsplit(server).query
        or urllib.parse.urlsplit(server).fragment
    ):
        raise TransactionError("TARGET_TUPLE_INVALID")
    return Target(
        tag,
        kubectl,
        kubeconfig,
        context,
        server,
        require_string(document.get("kubernetesCaSha256"), SHA256_RE, "TARGET_CA"),
        require_string(
            document.get("kubeSystemNamespaceUidSha256"),
            SHA256_RE,
            "TARGET_NAMESPACE_UID",
        ),
        require_string(
            document.get("nodeIdentitySha256"), SHA256_RE, "TARGET_NODE"
        ),
    )


def load_custody_receipt() -> dict[str, object]:
    document = parse_json_bytes(read_regular(CUSTODY_RECEIPT, owner=0, mode=0o600))
    if not isinstance(document, dict):
        raise TransactionError("CUSTODY_RECEIPT_INVALID")
    exact_fields(
        document,
        {
            "schema",
            "sourceRevision",
            "manifestSha256",
            "launcherSha256",
            "pythonPath",
            "pythonSha256",
            "custodySha256",
        },
        "CUSTODY_RECEIPT",
    )
    if document.get("schema") != CUSTODY_SCHEMA:
        raise TransactionError("CUSTODY_RECEIPT_SCHEMA_INVALID")
    for key, pattern in (
        ("sourceRevision", SOURCE_REVISION_RE),
        ("manifestSha256", SHA256_RE),
        ("launcherSha256", SHA256_RE),
        ("pythonSha256", SHA256_RE),
        ("custodySha256", SHA256_RE),
    ):
        require_string(document.get(key), pattern, "CUSTODY_RECEIPT")
    if document.get("pythonPath") != str(PYTHON_PATH):
        raise TransactionError("CUSTODY_PYTHON_PATH_INVALID")
    return document


def custody_path(relative: str) -> Path:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise TransactionError("CUSTODY_RELATIVE_PATH_INVALID")
    return CUSTODY_ROOT / relative


def validate_custody(receipt: Mapping[str, object]) -> dict[str, str]:
    manifest_payload = read_regular(
        custody_path(SOURCE_MANIFEST_REL), owner=0, mode=0o600, maximum=256 * 1024
    )
    if sha256_bytes(manifest_payload) != receipt.get("manifestSha256"):
        raise TransactionError("CUSTODY_MANIFEST_DIGEST_MISMATCH")
    try:
        text = manifest_payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransactionError("CUSTODY_MANIFEST_ENCODING_INVALID") from exc
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(" ")
        if len(fields) != 3:
            raise TransactionError("CUSTODY_MANIFEST_LINE_INVALID")
        digest, mode_text, relative = fields
        if (
            SHA256_RE.fullmatch(digest) is None
            or mode_text not in {"0600", "0700"}
            or relative in entries
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            raise TransactionError("CUSTODY_MANIFEST_LINE_INVALID")
        path = custody_path(relative)
        payload = read_regular(path, owner=0, mode=int(mode_text, 8), maximum=4 * 1024 * 1024)
        if sha256_bytes(payload) != digest:
            raise TransactionError("CUSTODY_ENTRY_DIGEST_MISMATCH")
        entries[relative] = digest
    required = {
        DESIRED_REL,
        ORACLE_REL,
        KUBECONFIG_VALIDATOR_REL,
        PLATFORM_CONTRACT_REL,
        VERSIONS_REL,
        RELEASE_FRAGMENT_REL,
        "bootstrap/flux/rbac-convergence/transaction.py",
    }
    if set(entries) != required:
        raise TransactionError("CUSTODY_ENTRY_SET_INVALID")
    observed_files: set[str] = set()
    for root, directories, files in os.walk(CUSTODY_ROOT, followlinks=False):
        root_path = Path(root)
        if any((root_path / name).is_symlink() for name in directories + files):
            raise TransactionError("CUSTODY_SYMLINK_FORBIDDEN")
        for name in files:
            observed_files.add(str((root_path / name).relative_to(CUSTODY_ROOT)))
    if observed_files != set(entries) | {SOURCE_MANIFEST_REL}:
        raise TransactionError("CUSTODY_INVENTORY_INVALID")
    derived = sha256_bytes(
        canonical_json({key: entries[key] for key in sorted(entries)})
    )
    if derived != receipt.get("custodySha256"):
        raise TransactionError("CUSTODY_TREE_DIGEST_MISMATCH")
    return entries


class KubeClient:
    """Pinned kubectl plus pinned, flattened kubeconfig held by descriptors."""

    def __init__(self, target: Target, versions: Mapping[str, str], oracle: ModuleType):
        machine = os.uname().machine.lower()
        pin_key = (
            "KUBECTL_ARM64_SHA256"
            if machine in {"aarch64", "arm64"}
            else "KUBECTL_LINUX_AMD64_SHA256"
            if machine in {"x86_64", "amd64"}
            else ""
        )
        if not pin_key or SHA256_RE.fullmatch(versions.get(pin_key, "")) is None:
            raise TransactionError("KUBECTL_ARCHITECTURE_UNSUPPORTED")
        try:
            self.kubectl = oracle.BoundFile(
                target.kubectl,
                executable=True,
                expected_digest=versions[pin_key],
            )
            self.kubeconfig = oracle.BoundFile(target.kubeconfig, executable=False)
        except Exception as exc:
            raise TransactionError("KUBECTL_CUSTODY_FAILED") from exc
        if (
            self.kubeconfig.kubeconfig_context != target.context
            or self.kubeconfig.kubeconfig_server != target.server
        ):
            self.close()
            raise TransactionError("KUBECONFIG_TARGET_MISMATCH")
        self.target = target
        self.digest = self.kubectl.digest
        self.kubeconfig_digest = self.kubeconfig.digest

    def close(self) -> None:
        for item in (getattr(self, "kubectl", None), getattr(self, "kubeconfig", None)):
            if item is not None:
                item.close()

    def kubeconfig_payload(self) -> bytes:
        """Read the already-bound kubeconfig descriptor, never its mutable path."""

        try:
            self.kubeconfig.validate()
            os.lseek(self.kubeconfig.descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(self.kubeconfig.descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 256 * 1024:
                    raise TransactionError("KUBECONFIG_SIZE_INVALID")
                chunks.append(chunk)
            os.lseek(self.kubeconfig.descriptor, 0, os.SEEK_SET)
        except (OSError, AttributeError) as exc:
            raise TransactionError("KUBECONFIG_DESCRIPTOR_READ_FAILED") from exc
        payload = b"".join(chunks)
        if not payload or sha256_bytes(payload) != self.kubeconfig_digest:
            raise TransactionError("KUBECONFIG_DESCRIPTOR_CHANGED")
        return payload

    def __enter__(self) -> "KubeClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def run(
        self,
        arguments: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        executable = self.kubectl.invocation_path()
        config = self.kubeconfig.invocation_path()
        command = [
            executable,
            "--kubeconfig",
            config,
            "--context",
            self.target.context,
            "--server",
            self.target.server,
            "--cache-dir",
            str(self.kubeconfig.work / "cache"),
            "--request-timeout=20s",
            *arguments,
        ]
        try:
            completed = subprocess.run(
                command,
                executable=executable,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                pass_fds=(self.kubectl.descriptor, self.kubeconfig.descriptor),
                input=stdin,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TransactionError("KUBECTL_TRANSPORT_FAILED") from exc
        if len(completed.stdout) > MAX_JSON_BYTES or len(completed.stderr) > MAX_JSON_BYTES:
            raise TransactionError("KUBECTL_RESPONSE_TOO_LARGE")
        return completed

    @staticmethod
    def _document(completed: subprocess.CompletedProcess[bytes], label: str) -> dict[str, object]:
        if completed.returncode != 0 or completed.stderr:
            raise TransactionError(f"{label}_FAILED")
        value = parse_json_bytes(completed.stdout)
        if not isinstance(value, dict):
            raise TransactionError(f"{label}_NON_OBJECT")
        return value

    def get(self, path: str) -> dict[str, object]:
        return self._document(self.run(("get", f"--raw={path}")), "KUBECTL_GET")

    def get_optional(self, path: str) -> dict[str, object] | None:
        completed = self.run(("get", f"--raw={path}"))
        if completed.returncode == 0 and not completed.stderr:
            value = parse_json_bytes(completed.stdout)
            if not isinstance(value, dict):
                raise TransactionError("KUBECTL_GET_NON_OBJECT")
            return value
        text = completed.stderr.decode("utf-8", "replace")
        if completed.returncode != 0 and "(NotFound)" in text and not completed.stdout:
            return None
        raise TransactionError("KUBECTL_GET_FAILED")

    def post(self, path: str, body: Mapping[str, object]) -> dict[str, object]:
        return self._document(
            self.run(("create", f"--raw={path}", "-f", "-"), stdin=canonical_json(body)),
            "KUBECTL_POST",
        )

    def post_fence(
        self, path: str, body: Mapping[str, object]
    ) -> dict[str, object] | None:
        """Return a response or a definitive server-side AlreadyExists fence."""

        completed = self.run(
            ("create", f"--raw={path}", "-f", "-"), stdin=canonical_json(body)
        )
        if completed.returncode == 0 and not completed.stderr:
            return self._document(completed, "KUBECTL_POST_FENCE")
        text = completed.stderr.decode("utf-8", "replace")
        if completed.returncode != 0 and not completed.stdout and "(AlreadyExists)" in text:
            return None
        raise TransactionError("KUBECTL_POST_FENCE_FAILED")

    def put(self, path: str, body: Mapping[str, object]) -> dict[str, object]:
        return self._document(
            self.run(("replace", f"--raw={path}", "-f", "-"), stdin=canonical_json(body)),
            "KUBECTL_PUT",
        )

    def put_fence(
        self, path: str, body: Mapping[str, object]
    ) -> dict[str, object] | None:
        """Return a response or a definitive server-side resourceVersion fence."""

        completed = self.run(
            ("replace", f"--raw={path}", "-f", "-"), stdin=canonical_json(body)
        )
        if completed.returncode == 0 and not completed.stderr:
            return self._document(completed, "KUBECTL_PUT_FENCE")
        text = completed.stderr.decode("utf-8", "replace")
        if completed.returncode != 0 and not completed.stdout and "(Conflict)" in text:
            return None
        raise TransactionError("KUBECTL_PUT_FENCE_FAILED")

    def delete(self, path: str, uid: str, resource_version: str) -> dict[str, object]:
        body = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid, "resourceVersion": resource_version},
            "propagationPolicy": "Background",
        }
        return self._document(
            self.run(("delete", f"--raw={path}", "-f", "-"), stdin=canonical_json(body)),
            "KUBECTL_DELETE",
        )


RESOURCE_PATHS: dict[str, tuple[str, str]] = {
    "ClusterRole": ("/apis/rbac.authorization.k8s.io/v1/clusterroles", "cluster"),
    "ClusterRoleBinding": (
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "cluster",
    ),
    "Role": ("/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles", "namespaced"),
    "RoleBinding": (
        "/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings",
        "namespaced",
    ),
    "ServiceAccount": ("/api/v1/namespaces/{namespace}/serviceaccounts", "namespaced"),
    "Deployment": ("/apis/apps/v1/namespaces/{namespace}/deployments", "namespaced"),
    "HelmRelease": (
        "/apis/helm.toolkit.fluxcd.io/v2/namespaces/{namespace}/helmreleases",
        "namespaced",
    ),
}


def resource_urls(kind: str, namespace: str | None, name: str) -> tuple[str, str]:
    if kind not in RESOURCE_PATHS or DNS_RE.fullmatch(name) is None:
        raise TransactionError("RESOURCE_IDENTITY_OUTSIDE_ALLOWLIST")
    template, scope = RESOURCE_PATHS[kind]
    if scope == "cluster":
        if namespace is not None:
            raise TransactionError("CLUSTER_RESOURCE_HAS_NAMESPACE")
        collection = template
    else:
        if namespace is None or DNS_RE.fullmatch(namespace) is None:
            raise TransactionError("NAMESPACED_RESOURCE_NAMESPACE_INVALID")
        collection = template.format(namespace=namespace)
    return collection, collection + "/" + name


class GitHubRejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every GitHub redirect before urllib can follow it."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        del request, file_pointer, code, message, headers, new_url
        raise TransactionError("GITHUB_REDIRECT_INVALID")


def github_urlopen(request: urllib.request.Request) -> object:
    opener = urllib.request.build_opener(GitHubRejectRedirectHandler())
    return opener.open(request, timeout=20)


def github_request(path: str) -> object:
    url = GITHUB_API + path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "website-infrastructure-flux-rbac-convergence/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
        method="GET",
    )
    try:
        with github_urlopen(request) as response:
            if response.status != 200:
                raise TransactionError("GITHUB_HTTP_STATUS_INVALID")
            if response.geturl() != url:
                raise TransactionError("GITHUB_REDIRECT_INVALID")
            payload = response.read(MAX_HTTP_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransactionError("GITHUB_REQUEST_FAILED") from exc
    if len(payload) > MAX_HTTP_BYTES:
        raise TransactionError("GITHUB_RESPONSE_TOO_LARGE")
    value = parse_json_bytes(payload, maximum=MAX_HTTP_BYTES)
    return value


def github_get(path: str) -> dict[str, object]:
    value = github_request(path)
    if not isinstance(value, dict):
        raise TransactionError("GITHUB_RESPONSE_NON_OBJECT")
    return value


def github_get_list(path: str) -> list[object]:
    value = github_request(path)
    if not isinstance(value, list):
        raise TransactionError("GITHUB_RESPONSE_NON_ARRAY")
    return value


def github_require_pull_merged(path: str) -> None:
    """Require GitHub's authoritative merged-PR endpoint to return 204."""

    url = GITHUB_API + path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "website-infrastructure-flux-rbac-convergence/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
        method="GET",
    )
    try:
        with github_urlopen(request) as response:
            if response.status != 204:
                raise TransactionError("GITHUB_PULL_MERGED_STATUS_INVALID")
            if response.geturl() != url:
                raise TransactionError("GITHUB_REDIRECT_INVALID")
            payload = response.read(1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise TransactionError("GITHUB_PULL_NOT_MERGED") from exc
        raise TransactionError("GITHUB_PULL_MERGED_STATUS_INVALID") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransactionError("GITHUB_REQUEST_FAILED") from exc
    if payload:
        raise TransactionError("GITHUB_PULL_MERGED_RESPONSE_INVALID")


def git_blob_sha1(payload: bytes) -> str:
    framed = b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest()


def verify_custody_source_tree(
    source_revision: str,
    tree_sha: str,
    entries: Mapping[str, str],
) -> str:
    """Bind every custodied public byte to the protected commit's Git tree."""

    if SOURCE_REVISION_RE.fullmatch(source_revision) is None or SOURCE_REVISION_RE.fullmatch(tree_sha) is None:
        raise TransactionError("SOURCE_TREE_INPUT_INVALID")
    document = github_get(
        f"/repos/{REPOSITORY}/git/trees/{tree_sha}?recursive=1"
    )
    rows = document.get("tree")
    if document.get("sha") != tree_sha or document.get("truncated") is not False or not isinstance(rows, list):
        raise TransactionError("SOURCE_TREE_RESPONSE_INVALID")
    by_path: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise TransactionError("SOURCE_TREE_ENTRY_INVALID")
        path = row.get("path")
        if isinstance(path, str) and path in by_path:
            raise TransactionError("SOURCE_TREE_DUPLICATE_PATH")
        if isinstance(path, str):
            by_path[path] = row
    expected_paths = set(entries) | {SOURCE_MANIFEST_REL}
    receipt: list[dict[str, object]] = []
    for relative in sorted(expected_paths):
        row = by_path.get(relative)
        if (
            not isinstance(row, Mapping)
            or row.get("type") != "blob"
            or row.get("mode") not in {"100644", "100755"}
        ):
            raise TransactionError("SOURCE_TREE_BLOB_INVALID")
        payload = read_regular(
            custody_path(relative), owner=0, maximum=4 * 1024 * 1024
        )
        digest = sha256_bytes(payload)
        if relative == SOURCE_MANIFEST_REL:
            manifest = load_custody_receipt().get("manifestSha256")
            if digest != manifest:
                raise TransactionError("SOURCE_TREE_MANIFEST_MISMATCH")
        elif entries.get(relative) != digest:
            raise TransactionError("SOURCE_TREE_CUSTODY_MISMATCH")
        blob_sha = git_blob_sha1(payload)
        if row.get("sha") != blob_sha or row.get("size") != len(payload):
            raise TransactionError("SOURCE_TREE_BLOB_MISMATCH")
        receipt.append(
            {
                "path": relative,
                "mode": row.get("mode"),
                "gitBlobSha1": blob_sha,
                "sha256": digest,
            }
        )
    return sha256_bytes(canonical_json(receipt))


def expected_release_body(source_sha: str, tag: str, fragment_payload: bytes) -> str:
    try:
        fragment = fragment_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransactionError("RELEASE_FRAGMENT_ENCODING_INVALID") from exc
    if (
        not fragment.endswith("\n")
        or fragment.endswith("\n\n")
        or "\r" in fragment
        or "\x00" in fragment
    ):
        raise TransactionError("RELEASE_FRAGMENT_INVALID")
    return (
        f"## Platform {tag}\n\n"
        f"Immutable repository source: `{source_sha}`\n\n"
        "This release names platform source only. It does not deploy, promote, "
        "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
        f"Fragment: `{RELEASE_FRAGMENT_REL}` "
        f"(`sha256:{sha256_bytes(fragment_payload)}`)\n\n"
        f"{fragment}"
    )


def select_workflow_run(
    document: Mapping[str, object], *, source_sha: str, workflow_path: str, event: str
) -> Mapping[str, object]:
    runs = document.get("workflow_runs")
    if not isinstance(runs, list) or not isinstance(document.get("total_count"), int):
        raise TransactionError("WORKFLOW_RUNS_INVALID")
    candidates = []
    for item in runs:
        if not isinstance(item, Mapping):
            continue
        if (
            item.get("head_sha") == source_sha
            and item.get("head_branch") == "main"
            and item.get("path") == workflow_path
            and item.get("event") == event
            and item.get("status") == "completed"
            and item.get("conclusion") == "success"
            and isinstance(item.get("id"), int)
            and isinstance(item.get("run_attempt"), int)
        ):
            candidates.append(item)
    if len(candidates) != 1:
        raise TransactionError("WORKFLOW_RUN_IDENTITY_INVALID")
    return candidates[0]


def verify_release_identity(
    source_revision: str,
    tag: str,
    contract: ModuleType,
    fragment_payload: bytes,
    *,
    require_main_tip: bool = True,
) -> dict[str, object]:
    """Rebuild protected-main CI -> annotated tag -> immutable Release."""

    if (
        SOURCE_REVISION_RE.fullmatch(source_revision) is None
        or TAG_RE.fullmatch(tag) is None
        or tag != AUTHORIZED_RELEASE_TAG
    ):
        raise TransactionError("RELEASE_INPUT_INVALID")
    commit = github_get(f"/repos/{REPOSITORY}/commits/{source_revision}")
    if commit.get("sha") != source_revision:
        raise TransactionError("GITHUB_COMMIT_IDENTITY_INVALID")
    commit_body = commit.get("commit")
    verification = commit_body.get("verification") if isinstance(commit_body, Mapping) else None
    tree = commit_body.get("tree") if isinstance(commit_body, Mapping) else None
    parents = commit.get("parents")
    if (
        not isinstance(verification, Mapping)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or not isinstance(tree, Mapping)
        or SOURCE_REVISION_RE.fullmatch(str(tree.get("sha", ""))) is None
        or not isinstance(parents, list)
        or len(parents) != 1
        or not isinstance(parents[0], Mapping)
        or SOURCE_REVISION_RE.fullmatch(str(parents[0].get("sha", ""))) is None
    ):
        raise TransactionError("PROTECTED_MAIN_SIGNATURE_INVALID")
    tree_sha = str(tree["sha"])
    source_parent_sha = str(parents[0]["sha"])
    main_ref = github_get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    main_object = main_ref.get("object")
    if (
        main_ref.get("ref") != "refs/heads/main"
        or not isinstance(main_object, Mapping)
        or main_object.get("type") != "commit"
    ):
        raise TransactionError("PROTECTED_MAIN_REF_INVALID")
    main_sha = main_object.get("sha")
    if require_main_tip:
        if main_sha != source_revision:
            raise TransactionError("PROTECTED_MAIN_HEAD_MOVED")
    else:
        if not isinstance(main_sha, str) or SOURCE_REVISION_RE.fullmatch(main_sha) is None:
            raise TransactionError("PROTECTED_MAIN_HEAD_INVALID")
        comparison = github_get(
            f"/repos/{REPOSITORY}/compare/{source_revision}...{main_sha}"
        )
        merge_base = comparison.get("merge_base_commit")
        base_commit = comparison.get("base_commit")
        if (
            comparison.get("status") not in {"ahead", "identical"}
            or not isinstance(merge_base, Mapping)
            or merge_base.get("sha") != source_revision
            or not isinstance(base_commit, Mapping)
            or base_commit.get("sha") != source_revision
        ):
            raise TransactionError("PROTECTED_MAIN_ANCESTRY_INVALID")

    associations = github_get_list(
        f"/repos/{REPOSITORY}/commits/{source_revision}/pulls"
    )
    if len(associations) != 1 or not isinstance(associations[0], Mapping):
        raise TransactionError("PROTECTED_MAIN_PR_ASSOCIATION_INVALID")
    pull_number = associations[0].get("number")
    if not isinstance(pull_number, int) or pull_number <= 0:
        raise TransactionError("PROTECTED_MAIN_PR_NUMBER_INVALID")
    pull = github_get(f"/repos/{REPOSITORY}/pulls/{pull_number}")
    pull_base = pull.get("base")
    pull_head = pull.get("head")
    merged_by = pull.get("merged_by")
    base_repo = pull_base.get("repo") if isinstance(pull_base, Mapping) else None
    head_repo = pull_head.get("repo") if isinstance(pull_head, Mapping) else None
    pull_author = pull.get("user")
    base_user = pull_base.get("user") if isinstance(pull_base, Mapping) else None
    head_user = pull_head.get("user") if isinstance(pull_head, Mapping) else None
    head_sha = pull_head.get("sha") if isinstance(pull_head, Mapping) else None
    head_ref = pull_head.get("ref") if isinstance(pull_head, Mapping) else None
    merge_commit_sha = pull.get("merge_commit_sha")
    merged_at = pull.get("merged_at")
    if (
        pull.get("number") != pull_number
        or pull.get("state") != "closed"
        or pull.get("draft") is not False
        or pull.get("merged") is not True
        or not isinstance(merged_at, str)
        or merge_commit_sha not in (None, source_revision)
        or not isinstance(pull_base, Mapping)
        or pull_base.get("ref") != "main"
        or pull_base.get("label") != f"{OWNER_LOGIN}:main"
        or pull_base.get("sha") != source_parent_sha
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != REPOSITORY
        or not isinstance(base_user, Mapping)
        or base_user.get("login") != OWNER_LOGIN
        or not isinstance(head_repo, Mapping)
        or head_repo.get("full_name") != REPOSITORY
        or not isinstance(head_user, Mapping)
        or head_user.get("login") != OWNER_LOGIN
        or not isinstance(head_ref, str)
        or not head_ref
        or pull_head.get("label") != f"{OWNER_LOGIN}:{head_ref}"
        or not isinstance(pull_author, Mapping)
        or pull_author.get("login") != OWNER_LOGIN
        or not isinstance(merged_by, Mapping)
        or merged_by.get("login") != OWNER_LOGIN
        or not isinstance(head_sha, str)
        or SOURCE_REVISION_RE.fullmatch(head_sha) is None
    ):
        raise TransactionError("PROTECTED_MAIN_PR_IDENTITY_INVALID")
    try:
        pull_merged_at = parse_time(merged_at, "PR_MERGED_AT")
    except TransactionError as exc:
        raise TransactionError("PROTECTED_MAIN_PR_IDENTITY_INVALID") from exc
    github_require_pull_merged(
        f"/repos/{REPOSITORY}/pulls/{pull_number}/merge"
    )
    head_commit = github_get(f"/repos/{REPOSITORY}/commits/{head_sha}")
    head_body = head_commit.get("commit")
    head_verification = head_body.get("verification") if isinstance(head_body, Mapping) else None
    head_tree = head_body.get("tree") if isinstance(head_body, Mapping) else None
    if (
        head_commit.get("sha") != head_sha
        or not isinstance(head_verification, Mapping)
        or head_verification.get("verified") is not True
        or head_verification.get("reason") != "valid"
    ):
        raise TransactionError("PROTECTED_PR_HEAD_SIGNATURE_INVALID")
    if not isinstance(head_tree, Mapping) or head_tree.get("sha") != tree_sha:
        raise TransactionError("PROTECTED_PR_HEAD_TREE_INVALID")

    pull_runs = github_get(
        f"/repos/{REPOSITORY}/actions/workflows/pull-request.yml/runs?"
        + urllib.parse.urlencode(
            {"branch": "main", "event": "push", "head_sha": source_revision, "per_page": 100}
        )
    )
    pull_run = select_workflow_run(
        pull_runs,
        source_sha=source_revision,
        workflow_path=".github/workflows/pull-request.yml",
        event="push",
    )
    run_id = pull_run["id"]
    run_attempt = pull_run["run_attempt"]
    jobs = github_get(
        f"/repos/{REPOSITORY}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"
    )
    codeql_runs = github_get(
        f"/repos/{REPOSITORY}/actions/workflows/codeql.yml/runs?"
        + urllib.parse.urlencode(
            {"branch": "main", "event": "push", "head_sha": source_revision, "per_page": 100}
        )
    )
    try:
        codeql_identity = contract.classify_codeql_run(codeql_runs, source_revision)
    except Exception as exc:
        raise TransactionError("CODEQL_RUN_INVALID") from exc
    if codeql_identity is None:
        raise TransactionError("CODEQL_RUN_INCOMPLETE")
    codeql_id, codeql_attempt = codeql_identity
    codeql_jobs = github_get(
        f"/repos/{REPOSITORY}/actions/runs/{codeql_id}/jobs?filter=latest&per_page=100"
    )
    try:
        ci_receipt = contract.build_main_ci_jobs_receipt(
            jobs,
            codeql_runs,
            codeql_jobs,
            REPOSITORY,
            str(run_id),
            str(run_attempt),
            source_revision,
        )
    except Exception as exc:
        raise TransactionError("PROTECTED_MAIN_CI_INVALID") from exc

    platform_runs = github_get(
        f"/repos/{REPOSITORY}/actions/workflows/platform-release.yml/runs?"
        + urllib.parse.urlencode({"head_sha": source_revision, "per_page": 100})
    )
    platform_run = select_workflow_run(
        platform_runs,
        source_sha=source_revision,
        workflow_path=".github/workflows/platform-release.yml",
        event="workflow_run",
    )

    ref_record = github_get(f"/repos/{REPOSITORY}/git/ref/tags/{tag}")
    ref_object = ref_record.get("object")
    if not isinstance(ref_object, Mapping) or ref_object.get("type") != "tag":
        raise TransactionError("ANNOTATED_TAG_REF_INVALID")
    tag_object_sha = require_string(ref_object.get("sha"), SOURCE_REVISION_RE, "TAG_OBJECT")
    tag_record = github_get(f"/repos/{REPOSITORY}/git/tags/{tag_object_sha}")
    commit_record = github_get(f"/repos/{REPOSITORY}/git/commits/{source_revision}")
    commit_committer = commit_record.get("committer")
    tagger = tag_record.get("tagger")
    if not isinstance(commit_committer, Mapping) or not isinstance(tagger, Mapping):
        raise TransactionError("TAG_TIME_IDENTITY_INVALID")
    tagger_date = commit_committer.get("date")
    message = f"Platform release {tag} from {source_revision}"
    try:
        contract.validate_tag_record(
            ref_record,
            tag_record,
            tag=tag,
            source_sha=source_revision,
            message=message,
            tagger_name="github-actions[bot]",
            tagger_email="41898282+github-actions[bot]@users.noreply.github.com",
            tagger_date=tagger_date,
        )
    except Exception as exc:
        raise TransactionError("ANNOTATED_TAG_INVALID") from exc

    release = github_get(f"/repos/{REPOSITORY}/releases/tags/{tag}")
    body = expected_release_body(source_revision, tag, fragment_payload)
    try:
        contract.validate_release_record(
            release,
            tag=tag,
            title=f"Platform {tag}",
            body=body,
            source_sha=source_revision,
        )
    except Exception as exc:
        raise TransactionError("GITHUB_RELEASE_INVALID") from exc
    release_published = parse_time(release.get("published_at"), "RELEASE_PUBLISHED")
    ci_updated = parse_time(pull_run.get("updated_at"), "CI_UPDATED")
    platform_started = parse_time(
        platform_run.get("run_started_at"), "PLATFORM_STARTED"
    )
    platform_updated = parse_time(platform_run.get("updated_at"), "PLATFORM_UPDATED")
    if (
        platform_started < ci_updated
        or
        release_published < ci_updated
        or release_published < platform_started
        or release_published > platform_updated
    ):
        raise TransactionError("RELEASE_ORDER_INVALID")
    return {
        "repository": REPOSITORY,
        "sourceRevision": source_revision,
        "sourceTreeSha": tree_sha,
        "pullRequestNumber": pull_number,
        "pullHeadSha": head_sha,
        "pullMergedAt": iso8601(pull_merged_at),
        "mergedBy": OWNER_LOGIN,
        "mainCiRunId": run_id,
        "mainCiRunAttempt": run_attempt,
        "mainCiReceiptSha256": sha256_bytes(canonical_json(ci_receipt)),
        "codeqlRunId": codeql_id,
        "codeqlRunAttempt": codeql_attempt,
        "platformRunId": platform_run["id"],
        "platformRunAttempt": platform_run["run_attempt"],
        "tag": tag,
        "tagObject": tag_object_sha,
        "peeledCommit": source_revision,
        "releaseId": release.get("id"),
        "releaseTarget": release.get("target_commitish"),
        "releasePublishedAt": iso8601(release_published),
        "commitVerified": True,
    }


def pem_der_sha256(encoded: str) -> str:
    try:
        pem = base64.b64decode(encoded, validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise TransactionError("KUBECONFIG_CA_INVALID") from exc
    match = re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n(?P<body>[A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----\n?",
        pem,
    )
    if match is None:
        raise TransactionError("KUBECONFIG_CA_INVALID")
    try:
        der = base64.b64decode(match.group("body").replace("\n", ""), validate=True)
    except ValueError as exc:
        raise TransactionError("KUBECONFIG_CA_INVALID") from exc
    return sha256_bytes(der)


def bind_target(client: KubeClient, target: Target) -> dict[str, object]:
    kubeconfig_payload = client.kubeconfig_payload()
    document = parse_json_bytes(kubeconfig_payload, maximum=256 * 1024)
    if not isinstance(document, Mapping):
        raise TransactionError("KUBECONFIG_DOCUMENT_INVALID")
    clusters = document.get("clusters")
    if not isinstance(clusters, list) or len(clusters) != 1:
        raise TransactionError("KUBECONFIG_CLUSTER_INVALID")
    cluster = clusters[0]
    cluster = cluster.get("cluster") if isinstance(cluster, Mapping) else None
    if not isinstance(cluster, Mapping) or not isinstance(
        cluster.get("certificate-authority-data"), str
    ):
        raise TransactionError("KUBECONFIG_CA_INVALID")
    if pem_der_sha256(cluster["certificate-authority-data"]) != target.ca_sha256:
        raise TransactionError("KUBERNETES_CA_MISMATCH")
    namespace = client.get("/api/v1/namespaces/kube-system")
    namespace_uid, _ = live_identity(namespace)
    if sha256_bytes((namespace_uid + "\n").encode("ascii")) != target.kube_system_uid_sha256:
        raise TransactionError("KUBE_SYSTEM_NAMESPACE_IDENTITY_MISMATCH")
    nodes = client.get("/api/v1/nodes")
    items = nodes.get("items")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
        raise TransactionError("NODE_INVENTORY_INVALID")
    node_metadata = items[0].get("metadata")
    if not isinstance(node_metadata, Mapping):
        raise TransactionError("NODE_IDENTITY_INVALID")
    node_name = node_metadata.get("name")
    node_uid = node_metadata.get("uid")
    if not isinstance(node_name, str) or not isinstance(node_uid, str):
        raise TransactionError("NODE_IDENTITY_INVALID")
    node_hash = sha256_bytes((node_name + "\n" + node_uid + "\n").encode("utf-8"))
    if node_hash != target.node_identity_sha256:
        raise TransactionError("NODE_IDENTITY_MISMATCH")
    return {
        "contextSha256": sha256_bytes((target.context + "\n").encode("utf-8")),
        "serverSha256": sha256_bytes((target.server + "\n").encode("utf-8")),
        "caSha256": target.ca_sha256,
        "kubeSystemNamespaceUidSha256": target.kube_system_uid_sha256,
        "nodeIdentitySha256": target.node_identity_sha256,
        "kubeconfigSha256": client.kubeconfig_digest,
    }


def ready_condition(value: Mapping[str, object]) -> Mapping[str, object]:
    status = value.get("status")
    conditions = status.get("conditions") if isinstance(status, Mapping) else None
    if not isinstance(conditions, list):
        raise TransactionError("READY_CONDITIONS_INVALID")
    matches = [
        item
        for item in conditions
        if isinstance(item, Mapping) and item.get("type") == "Ready"
    ]
    if len(matches) != 1 or matches[0].get("status") != "True":
        raise TransactionError("READY_CONDITION_FALSE")
    return matches[0]


def collection_items(client: KubeClient, path: str) -> list[Mapping[str, object]]:
    document = client.get(path)
    items = document.get("items")
    if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
        raise TransactionError("COLLECTION_ITEMS_INVALID")
    return list(items)  # type: ignore[return-value]


def expected_site_oci_spec(namespace: str, name: str) -> dict[str, object]:
    repository = SITE_SIGNING_REPOSITORIES.get((namespace, name))
    if repository is None:
        raise TransactionError("OCI_SITE_IDENTITY_INVALID")
    return {
        "interval": "10m0s",
        "layerSelector": {
            "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
            "operation": "copy",
        },
        "provider": "generic",
        "ref": {"semver": SITE_CHART_SEMVER_RANGE},
        "timeout": "60s",
        "url": f"oci://ghcr.io/snaraj/charts/{name}",
        "verify": {
            "matchOIDCIdentity": [
                {
                    "issuer": r"^https://token\.actions\.githubusercontent\.com$",
                    "subject": (
                        r"^https://github\.com/snaraj/"
                        + re.escape(repository)
                        + r"/\.github/workflows/release-publisher\.yml@refs/heads/main$"
                    ),
                }
            ],
            "provider": "cosign",
        },
    }


def require_sha256_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise TransactionError(code)
    digest = value.removeprefix("sha256:")
    if SHA256_RE.fullmatch(digest) is None or set(digest) == {"0"}:
        raise TransactionError(code)
    return value


def require_site_chart_version(value: object, code: str) -> str:
    """Require one canonical release SemVer inside the reviewed source range."""

    if not isinstance(value, str):
        raise TransactionError(code)
    match = SITE_CHART_VERSION_RE.fullmatch(value)
    if match is None:
        raise TransactionError(code)
    try:
        components = tuple(int(component) for component in match.groups())
    except ValueError as exc:
        raise TransactionError(code) from exc
    if not SITE_CHART_MIN_VERSION <= components < SITE_CHART_MAX_VERSION:
        raise TransactionError(code)
    return value


def parse_site_oci_revision(revision: object) -> tuple[str, str]:
    if not isinstance(revision, str):
        raise TransactionError("OCI_REVISION_INVALID")
    match = re.fullmatch(
        r"v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)@sha256:"
        r"(?P<digest>[0-9a-f]{64})",
        revision,
    )
    if match is None or set(match.group("digest")) == {"0"}:
        raise TransactionError("OCI_REVISION_INVALID")
    version = require_site_chart_version(
        match.group("version"), "OCI_REVISION_INVALID"
    )
    return version, "sha256:" + match.group("digest")


def validate_site_chart_snapshot_binding(
    snapshot: Mapping[str, object],
    version: object,
    upstream_digest: object,
    code: str,
) -> tuple[str, str]:
    """Bind a normalized Helm snapshot to one exact source version and digest."""

    normalized_version = require_site_chart_version(version, code)
    normalized_digest = require_sha256_digest(upstream_digest, code)
    expected_revision = (
        normalized_version
        + "+"
        + normalized_digest.removeprefix("sha256:")[:12]
    )
    if (
        snapshot.get("attemptedRevision") != expected_revision
        or snapshot.get("attemptedRevisionDigest") != normalized_digest
        or snapshot.get("historyChartVersion") != expected_revision
        or snapshot.get("historyOciDigest") not in (None, normalized_digest)
    ):
        raise TransactionError(code)
    return normalized_version, normalized_digest


def validate_site_helm_release(
    release: Mapping[str, object],
    namespace: str,
    name: str,
    version: str,
    upstream_digest: str,
) -> dict[str, object]:
    """Validate one closed, credentialless same-site OCI Helm chain."""

    if release.get("apiVersion") != "helm.toolkit.fluxcd.io/v2" or release.get(
        "kind"
    ) != "HelmRelease":
        raise TransactionError("HELM_TYPE_INVALID")
    metadata = release.get("metadata")
    spec = release.get("spec")
    status = release.get("status")
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(
        status, Mapping
    ):
        raise TransactionError("HELM_OBJECT_INVALID")
    if metadata.get("namespace") != namespace or metadata.get("name") != name:
        raise TransactionError("HELM_IDENTITY_INVALID")
    if object_is_terminating(release):
        raise TransactionError("HELM_TERMINATING")
    uid, resource_version = live_identity(release)
    generation = metadata.get("generation")
    if not isinstance(generation, int) or generation <= 0:
        raise TransactionError("HELM_GENERATION_INVALID")
    if any(field in spec for field in FORBIDDEN_HELM_SPEC_FIELDS):
        raise TransactionError("HELM_FORBIDDEN_SPEC_PATH")
    upgrade = spec.get("upgrade")
    install = spec.get("install")
    if (
        isinstance(upgrade, Mapping)
        and upgrade.get("force") is True
        or isinstance(install, Mapping)
        and install.get("replace") is True
    ):
        raise TransactionError("HELM_REPLACEMENT_BEHAVIOR_FORBIDDEN")
    if spec.get("chartRef") != {
        "kind": "OCIRepository",
        "name": name + "-chart",
    }:
        raise TransactionError("HELM_CHART_REFERENCE_INVALID")
    if (
        spec.get("suspend") not in (None, False)
        or spec.get("releaseName") != name
        or spec.get("serviceAccountName") != "helm-reconciler"
        or spec.get("values") != {"deploymentReady": True}
    ):
        raise TransactionError("HELM_SAFE_LIVE_SPEC_INVALID")
    if "helmChart" in status or status.get("storageNamespace") != namespace:
        raise TransactionError("HELM_STATUS_TARGET_INVALID")
    if (
        status.get("observedGeneration") != generation
        or status.get("lastAttemptedGeneration") != generation
    ):
        raise TransactionError("HELM_STATUS_GENERATION_INVALID")

    version = require_site_chart_version(version, "HELM_CHART_VERSION_INVALID")
    upstream_digest = require_sha256_digest(
        upstream_digest, "HELM_UPSTREAM_DIGEST_INVALID"
    )
    attempted_digest = require_sha256_digest(
        status.get("lastAttemptedRevisionDigest"),
        "HELM_ATTEMPTED_DIGEST_INVALID",
    )
    expected_revision = version + "+" + upstream_digest.removeprefix("sha256:")[:12]
    attempted_revision = status.get("lastAttemptedRevision")
    if attempted_digest != upstream_digest or attempted_revision != expected_revision:
        raise TransactionError("HELM_REVISION_INVALID")
    attempted_action = status.get("lastAttemptedReleaseAction")
    if attempted_action is not None and attempted_action not in {"install", "upgrade"}:
        raise TransactionError("HELM_ATTEMPTED_ACTION_INVALID")

    release_ready = ready_condition(release)
    if (
        release_ready.get("reason") not in HELM_READY_REASONS
        or release_ready.get("observedGeneration") != generation
    ):
        raise TransactionError("HELM_READY_REASON_INVALID")
    conditions = status.get("conditions")
    if not isinstance(conditions, list) or any(
        isinstance(condition, Mapping)
        and condition.get("type") == "Remediated"
        and condition.get("status") == "True"
        for condition in conditions
    ):
        raise TransactionError("HELM_REMEDIATION_STATE_INVALID")

    history = status.get("history")
    if not isinstance(history, list) or not history or not isinstance(history[0], Mapping):
        raise TransactionError("HELM_HISTORY_INVALID")
    latest = history[0]
    history_revision = latest.get("version")
    if (
        type(history_revision) is not int
        or history_revision <= 0
        or latest.get("status") != "deployed"
        or latest.get("name") != name
        or latest.get("namespace") != namespace
        or latest.get("chartName") != name
        or latest.get("chartVersion") != attempted_revision
    ):
        raise TransactionError("HELM_HISTORY_INVALID")
    history_action = latest.get("action")
    if history_action is not None and history_action not in {"install", "upgrade"}:
        raise TransactionError("HELM_HISTORY_ACTION_INVALID")
    history_oci_digest = latest.get("ociDigest")
    if history_oci_digest is not None and history_oci_digest != upstream_digest:
        raise TransactionError("HELM_HISTORY_OCI_DIGEST_INVALID")
    history_digest = require_sha256_digest(
        latest.get("digest"), "HELM_HISTORY_DIGEST_INVALID"
    )
    history_config_digest = require_sha256_digest(
        latest.get("configDigest"), "HELM_HISTORY_CONFIG_DIGEST_INVALID"
    )
    inventory = status.get("inventory")
    inventory_entries = (
        inventory.get("entries") if isinstance(inventory, Mapping) else None
    )
    if not isinstance(inventory_entries, list) or len(inventory_entries) != len(
        SITE_INVENTORY_KINDS
    ):
        raise TransactionError("HELM_INVENTORY_INVALID")
    normalized_inventory: list[dict[str, str]] = []
    observed_kinds: set[str] = set()
    for entry in inventory_entries:
        if not isinstance(entry, Mapping) or set(entry) != {"id", "v"}:
            raise TransactionError("HELM_INVENTORY_INVALID")
        inventory_id = entry.get("id")
        api_version = entry.get("v")
        if not isinstance(inventory_id, str) or not isinstance(api_version, str):
            raise TransactionError("HELM_INVENTORY_INVALID")
        parts = inventory_id.split("_", 3)
        if len(parts) != 4:
            raise TransactionError("HELM_INVENTORY_INVALID")
        item_namespace, item_name, group, kind = parts
        expected_group_version = SITE_INVENTORY_KINDS.get(kind)
        if (
            item_namespace != namespace
            or not item_name
            or expected_group_version != (group, api_version)
            or kind in observed_kinds
        ):
            raise TransactionError("HELM_INVENTORY_INVALID")
        observed_kinds.add(kind)
        normalized_inventory.append({"id": inventory_id, "v": api_version})
    if observed_kinds != set(SITE_INVENTORY_KINDS):
        raise TransactionError("HELM_INVENTORY_INVALID")
    normalized_inventory.sort(key=lambda entry: (entry["id"], entry["v"]))
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "observedGeneration": status.get("observedGeneration"),
        "lastAttemptedGeneration": status.get("lastAttemptedGeneration"),
        "attemptedRevision": attempted_revision,
        "attemptedRevisionDigest": attempted_digest,
        "attemptedReleaseAction": attempted_action,
        "historyRevision": history_revision,
        "historyChartVersion": latest.get("chartVersion"),
        "historyStatus": latest.get("status"),
        "historyAction": history_action,
        "historyOciDigest": history_oci_digest,
        "historyDigest": history_digest,
        "historyConfigDigest": history_config_digest,
        "inventory": normalized_inventory,
        "readyReason": release_ready.get("reason"),
        "specSha256": sha256_bytes(canonical_json(spec)),
        "semanticSha256": semantic_hash(release),
    }


def flux_snapshot(client: KubeClient) -> dict[str, object]:
    collections = {
        kind: collection_items(client, path)
        for kind, path in FLUX_CRD_COLLECTIONS.items()
    }
    unexpected = {
        kind: len(collections[kind])
        for kind in sorted(FLUX_EMPTY_KINDS)
        if collections[kind]
    }
    if unexpected:
        raise TransactionError("FLUX_UNOWNED_RESOURCE_PRESENT")
    oci = collections["OCIRepository"]
    helm = collections["HelmRelease"]
    expected = set(SITE_RELEASES)
    oci_by_id: dict[tuple[str, str], Mapping[str, object]] = {}
    for item in oci:
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping):
            raise TransactionError("OCI_METADATA_INVALID")
        identity = (metadata.get("namespace"), metadata.get("name"))
        if not all(isinstance(part, str) for part in identity):
            raise TransactionError("OCI_IDENTITY_INVALID")
        oci_by_id[identity] = item  # type: ignore[index]
    expected_oci = {(namespace, name + "-chart") for namespace, name in expected}
    if set(oci_by_id) != expected_oci:
        raise TransactionError("OCI_INVENTORY_INVALID")
    helm_by_id: dict[tuple[str, str], Mapping[str, object]] = {}
    for item in helm:
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping):
            raise TransactionError("HELM_METADATA_INVALID")
        identity = (metadata.get("namespace"), metadata.get("name"))
        if not all(isinstance(part, str) for part in identity):
            raise TransactionError("HELM_IDENTITY_INVALID")
        helm_by_id[identity] = item  # type: ignore[index]
    if set(helm_by_id) != expected:
        raise TransactionError("HELM_INVENTORY_INVALID")
    result_oci: dict[str, object] = {}
    result_helm: dict[str, object] = {}
    for namespace, name in sorted(expected):
        source = oci_by_id[(namespace, name + "-chart")]
        if object_is_terminating(source):
            raise TransactionError("OCI_TERMINATING")
        source_ready = ready_condition(source)
        source_status = source.get("status")
        source_spec = source.get("spec")
        artifact = source_status.get("artifact") if isinstance(source_status, Mapping) else None
        revision = artifact.get("revision") if isinstance(artifact, Mapping) else None
        digest = artifact.get("digest") if isinstance(artifact, Mapping) else None
        conditions = source_status.get("conditions") if isinstance(source_status, Mapping) else None
        verified = [
            condition
            for condition in conditions or []
            if isinstance(condition, Mapping) and condition.get("type") == "SourceVerified"
        ]
        expected_spec = expected_site_oci_spec(namespace, name)
        source_chart_version, upstream_digest = parse_site_oci_revision(revision)
        if (
            not isinstance(source_status, Mapping)
            or not isinstance(source_spec, Mapping)
            or dict(source_spec) != expected_spec
            or require_sha256_digest(digest, "OCI_STORED_ARTIFACT_DIGEST_INVALID")
            != digest
            or source_status.get("observedGeneration")
            != source.get("metadata", {}).get("generation")
            or source_ready.get("reason") != "Succeeded"
            or source_ready.get("observedGeneration")
            != source.get("metadata", {}).get("generation")
            or len(verified) != 1
            or verified[0].get("status") != "True"
            or verified[0].get("reason") != "Succeeded"
            or verified[0].get("observedGeneration")
            != source.get("metadata", {}).get("generation")
        ):
            raise TransactionError("OCI_REVISION_INVALID")
        source_uid, source_rv = live_identity(source)
        result_oci[f"{namespace}/{name}-chart"] = {
            "uid": source_uid,
            "resourceVersion": source_rv,
            "generation": source.get("metadata", {}).get("generation"),
            "observedGeneration": source_status.get("observedGeneration")
            if isinstance(source_status, Mapping)
            else None,
            "revision": revision,
            "chartVersion": source_chart_version,
            "upstreamDigest": upstream_digest,
            "storedArtifactDigest": digest,
            "readyReason": source_ready.get("reason"),
            "sourceVerifiedReason": verified[0].get("reason"),
            "specSha256": sha256_bytes(canonical_json(source_spec)),
            "semanticSha256": semantic_hash(source),
        }
        release = helm_by_id[(namespace, name)]
        result_helm[f"{namespace}/{name}"] = validate_site_helm_release(
            release, namespace, name, source_chart_version, upstream_digest
        )
    return {
        "closedEmptyInventories": {
            kind: 0 for kind in sorted(FLUX_EMPTY_KINDS)
        },
        "gitRepositories": 0,
        "kustomizations": 0,
        "oci": result_oci,
        "helm": result_helm,
    }


def workload_snapshot(client: KubeClient) -> dict[str, object]:
    result: dict[str, object] = {}
    for namespace, name in sorted(SITE_RELEASES):
        deployments = collection_items(
            client, f"/apis/apps/v1/namespaces/{namespace}/deployments"
        )
        matches = [
            item
            for item in deployments
            if isinstance(item.get("metadata"), Mapping)
            and item["metadata"].get("name") == name
        ]
        if len(matches) != 1:
            raise TransactionError("SITE_DEPLOYMENT_INVENTORY_INVALID")
        deployment = matches[0]
        uid, _rv = live_identity(deployment)
        metadata = deployment.get("metadata")
        spec = deployment.get("spec")
        status = deployment.get("status")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(status, Mapping):
            raise TransactionError("SITE_DEPLOYMENT_INVALID")
        owned_collections: list[tuple[str, list[Mapping[str, object]]]] = [
            ("Deployment", [deployment]),
            (
                "Service",
                collection_items(client, f"/api/v1/namespaces/{namespace}/services"),
            ),
            (
                "ServiceAccount",
                collection_items(
                    client, f"/api/v1/namespaces/{namespace}/serviceaccounts"
                ),
            ),
            (
                "NetworkPolicy",
                collection_items(
                    client,
                    f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
                ),
            ),
        ]
        owned_rows: list[dict[str, object]] = []
        for kind, candidates in owned_collections:
            for candidate in candidates:
                candidate_metadata = candidate.get("metadata")
                annotations = (
                    candidate_metadata.get("annotations")
                    if isinstance(candidate_metadata, Mapping)
                    else None
                )
                if (
                    not isinstance(annotations, Mapping)
                    or annotations.get("meta.helm.sh/release-name") != name
                    or annotations.get("meta.helm.sh/release-namespace") != namespace
                ):
                    continue
                candidate_name = candidate_metadata.get("name")
                candidate_api_version = candidate.get("apiVersion")
                if not isinstance(candidate_name, str) or not isinstance(
                    candidate_api_version, str
                ):
                    raise TransactionError("SITE_OWNED_OBJECT_IDENTITY_INVALID")
                candidate_uid, _ = live_identity(candidate)
                proof_annotation, without_proof_sha256 = (
                    semantic_without_proof_annotation(candidate)
                )
                owned_rows.append(
                    {
                        "kind": kind,
                        "name": candidate_name,
                        "apiVersion": candidate_api_version,
                        "uid": candidate_uid,
                        "semanticSha256": semantic_hash(candidate),
                        "proofAnnotation": proof_annotation,
                        "semanticWithoutProofSha256": without_proof_sha256,
                    }
                )
        owned_rows.sort(key=lambda item: (str(item["kind"]), str(item["name"])))
        if len(owned_rows) != len(SITE_INVENTORY_KINDS) or {
            str(item["kind"]) for item in owned_rows
        } != set(SITE_INVENTORY_KINDS):
            raise TransactionError("SITE_OWNED_OBJECT_INVENTORY_INVALID")
        replicas = spec.get("replicas")
        if (
            not isinstance(replicas, int)
            or replicas < 1
            or status.get("observedGeneration") != metadata.get("generation")
            or status.get("availableReplicas") != replicas
            or status.get("updatedReplicas") != replicas
            or status.get("unavailableReplicas") not in (None, 0)
        ):
            raise TransactionError("SITE_DEPLOYMENT_NOT_READY")
        selector = spec.get("selector")
        match_labels = selector.get("matchLabels") if isinstance(selector, Mapping) else None
        if (
            not isinstance(match_labels, Mapping)
            or not match_labels
            or any(not isinstance(key, str) or not isinstance(value, str) for key, value in match_labels.items())
        ):
            raise TransactionError("SITE_DEPLOYMENT_SELECTOR_INVALID")
        pod_rows: list[dict[str, object]] = []
        for pod in collection_items(client, f"/api/v1/namespaces/{namespace}/pods"):
            pod_metadata = pod.get("metadata")
            labels = pod_metadata.get("labels") if isinstance(pod_metadata, Mapping) else None
            if not isinstance(labels, Mapping) or not all(
                labels.get(key) == value for key, value in match_labels.items()
            ):
                continue
            pod_status = pod.get("status")
            statuses = pod_status.get("containerStatuses") if isinstance(pod_status, Mapping) else None
            conditions = pod_status.get("conditions") if isinstance(pod_status, Mapping) else None
            ready = [
                item
                for item in conditions or []
                if isinstance(item, Mapping) and item.get("type") == "Ready"
            ]
            if (
                pod_metadata.get("deletionTimestamp") is not None
                or not isinstance(statuses, list)
                or not statuses
                or any(
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("restartCount"), int)
                    or item.get("restartCount") < 0
                    for item in statuses
                )
                or len(ready) != 1
                or ready[0].get("status") != "True"
                or pod_status.get("phase") != "Running"
            ):
                raise TransactionError("SITE_POD_NOT_READY")
            pod_uid, _ = live_identity(pod)
            pod_rows.append(
                {
                    "uid": pod_uid,
                    "restartCounts": [item["restartCount"] for item in statuses],
                    "images": [item.get("image") for item in statuses],
                }
            )
        pod_rows.sort(key=lambda item: str(item["uid"]))
        if len(pod_rows) != replicas:
            raise TransactionError("SITE_POD_INVENTORY_INVALID")
        result[f"{namespace}/{name}"] = {
            "uid": uid,
            "generation": metadata.get("generation"),
            "replicas": replicas,
            "templateSha256": sha256_bytes(canonical_json(spec.get("template"))),
            "semanticSha256": semantic_hash(deployment),
            "proofAnnotation": semantic_without_proof_annotation(deployment)[0],
            "semanticWithoutProofSha256": semantic_without_proof_annotation(
                deployment
            )[1],
            "pods": pod_rows,
            "ownedObjects": owned_rows,
        }
    return result


def validate_helm_workload_inventory(
    flux: Mapping[str, object], workloads: Mapping[str, object]
) -> None:
    helm = flux.get("helm")
    if not isinstance(helm, Mapping) or set(helm) != {
        f"{namespace}/{name}" for namespace, name in SITE_RELEASES
    } or set(workloads) != set(helm):
        raise TransactionError("SITE_INVENTORY_BINDING_INVALID")
    for identity, release in helm.items():
        workload = workloads.get(identity)
        if not isinstance(release, Mapping) or not isinstance(workload, Mapping):
            raise TransactionError("SITE_INVENTORY_BINDING_INVALID")
        namespace = str(identity).split("/", 1)[0]
        owned = workload.get("ownedObjects")
        if not isinstance(owned, list):
            raise TransactionError("SITE_INVENTORY_BINDING_INVALID")
        expected: list[dict[str, str]] = []
        for row in owned:
            if not isinstance(row, Mapping):
                raise TransactionError("SITE_INVENTORY_BINDING_INVALID")
            kind = row.get("kind")
            name = row.get("name")
            api_version = row.get("apiVersion")
            group_version = SITE_INVENTORY_KINDS.get(str(kind))
            if (
                group_version is None
                or not isinstance(name, str)
                or api_version
                != (group_version[1] if not group_version[0] else "/".join(group_version))
            ):
                raise TransactionError("SITE_INVENTORY_BINDING_INVALID")
            expected.append(
                {
                    "id": f"{namespace}_{name}_{group_version[0]}_{kind}",
                    "v": group_version[1],
                }
            )
        expected.sort(key=lambda entry: (entry["id"], entry["v"]))
        if release.get("inventory") != expected:
            raise TransactionError("SITE_INVENTORY_BINDING_INVALID")


def validate_clean_workload_baseline(workloads: Mapping[str, object]) -> None:
    for workload in workloads.values():
        if not isinstance(workload, Mapping):
            raise TransactionError("WORKLOAD_BASELINE_INVALID")
        if (
            workload.get("proofAnnotation") is not None
            or workload.get("semanticWithoutProofSha256")
            != workload.get("semanticSha256")
        ):
            raise TransactionError("WORKLOAD_PROOF_ANNOTATION_COLLISION")
        rows = workload.get("ownedObjects")
        if not isinstance(rows, list):
            raise TransactionError("WORKLOAD_BASELINE_INVALID")
        for row in rows:
            if (
                not isinstance(row, Mapping)
                or row.get("proofAnnotation") is not None
                or row.get("semanticWithoutProofSha256")
                != row.get("semanticSha256")
            ):
                raise TransactionError("WORKLOAD_PROOF_ANNOTATION_COLLISION")


def compare_flux_without_resource_versions(
    current: Mapping[str, object], planned: Mapping[str, object]
) -> None:
    if current.get("gitRepositories") != 0 or current.get("kustomizations") != 0:
        raise TransactionError("FLUX_SYNC_PREMATURELY_PRESENT")
    for section in ("oci", "helm"):
        current_rows = current.get(section)
        planned_rows = planned.get(section)
        if (
            not isinstance(current_rows, Mapping)
            or not isinstance(planned_rows, Mapping)
            or set(current_rows) != set(planned_rows)
        ):
            raise TransactionError("HELM_PROOF_FLUX_INVENTORY_DRIFT")
        for identity, planned_row in planned_rows.items():
            current_row = current_rows.get(identity)
            if not isinstance(current_row, Mapping) or not isinstance(
                planned_row, Mapping
            ):
                raise TransactionError("HELM_PROOF_FLUX_INVENTORY_DRIFT")
            if {
                key: value
                for key, value in current_row.items()
                if key != "resourceVersion"
            } != {
                key: value
                for key, value in planned_row.items()
                if key != "resourceVersion"
            }:
                raise TransactionError("HELM_PROOF_FLUX_DRIFT")


def validate_active_helm_proof_inventory(
    client: KubeClient,
    plan: Mapping[str, object],
    plan_sha256: str,
    upgraded_release: Mapping[str, object],
) -> dict[str, object]:
    baselines = plan.get("baselines")
    planned_flux = baselines.get("flux") if isinstance(baselines, Mapping) else None
    planned_workloads = (
        baselines.get("workloads") if isinstance(baselines, Mapping) else None
    )
    if not isinstance(planned_flux, Mapping) or not isinstance(
        planned_workloads, Mapping
    ):
        raise TransactionError("HELM_PROOF_BASELINE_INVALID")
    validate_clean_workload_baseline(planned_workloads)
    current_flux = flux_snapshot(client)
    current_workloads = workload_snapshot(client)
    validate_helm_workload_inventory(current_flux, current_workloads)

    planned_oci = planned_flux.get("oci")
    current_oci = current_flux.get("oci")
    if not isinstance(planned_oci, Mapping) or not isinstance(current_oci, Mapping):
        raise TransactionError("HELM_PROOF_OCI_BASELINE_INVALID")
    compare_flux_without_resource_versions(
        {"gitRepositories": 0, "kustomizations": 0, "oci": current_oci, "helm": {}},
        {"gitRepositories": 0, "kustomizations": 0, "oci": planned_oci, "helm": {}},
    )

    planned_helm = planned_flux.get("helm")
    current_helm = current_flux.get("helm")
    if not isinstance(planned_helm, Mapping) or not isinstance(current_helm, Mapping):
        raise TransactionError("HELM_PROOF_RELEASE_BASELINE_INVALID")
    lidersea = "lidersea-com/lidersea-com"
    compare_flux_without_resource_versions(
        {
            "gitRepositories": 0,
            "kustomizations": 0,
            "oci": {},
            "helm": {lidersea: current_helm.get(lidersea)},
        },
        {
            "gitRepositories": 0,
            "kustomizations": 0,
            "oci": {},
            "helm": {lidersea: planned_helm.get(lidersea)},
        },
    )
    naranjo = "naranjo-online/naranjo-online"
    current_naranjo = current_helm.get(naranjo)
    if not isinstance(current_naranjo, Mapping):
        raise TransactionError("HELM_PROOF_RELEASE_INVENTORY_INVALID")
    if {
        key: value
        for key, value in current_naranjo.items()
        if key != "resourceVersion"
    } != {
        key: value
        for key, value in upgraded_release.items()
        if key != "resourceVersion"
    }:
        raise TransactionError("HELM_PROOF_RELEASE_DRIFT")

    if set(current_workloads) != set(planned_workloads):
        raise TransactionError("HELM_PROOF_WORKLOAD_INVENTORY_DRIFT")
    if current_workloads.get(lidersea) != planned_workloads.get(lidersea):
        raise TransactionError("HELM_PROOF_UNRELATED_SITE_DRIFT")
    planned_naranjo = planned_workloads.get(naranjo)
    active_naranjo = current_workloads.get(naranjo)
    if not isinstance(planned_naranjo, Mapping) or not isinstance(
        active_naranjo, Mapping
    ):
        raise TransactionError("HELM_PROOF_WORKLOAD_BASELINE_INVALID")
    for key in ("uid", "generation", "replicas", "templateSha256", "pods"):
        if active_naranjo.get(key) != planned_naranjo.get(key):
            raise TransactionError("HELM_PROOF_WORKLOAD_IDENTITY_DRIFT")
    if (
        active_naranjo.get("proofAnnotation") != plan_sha256
        or active_naranjo.get("semanticWithoutProofSha256")
        != planned_naranjo.get("semanticSha256")
        or active_naranjo.get("semanticSha256")
        == planned_naranjo.get("semanticSha256")
    ):
        raise TransactionError("HELM_PROOF_DEPLOYMENT_MUTATION_INVALID")
    planned_rows = planned_naranjo.get("ownedObjects")
    active_rows = active_naranjo.get("ownedObjects")
    if not isinstance(planned_rows, list) or not isinstance(active_rows, list):
        raise TransactionError("HELM_PROOF_OWNED_INVENTORY_INVALID")
    planned_by_identity = {
        (row.get("kind"), row.get("name"), row.get("apiVersion")): row
        for row in planned_rows
        if isinstance(row, Mapping)
    }
    active_by_identity = {
        (row.get("kind"), row.get("name"), row.get("apiVersion")): row
        for row in active_rows
        if isinstance(row, Mapping)
    }
    if (
        len(planned_by_identity) != len(SITE_INVENTORY_KINDS)
        or set(active_by_identity) != set(planned_by_identity)
    ):
        raise TransactionError("HELM_PROOF_OWNED_INVENTORY_INVALID")
    for identity, planned_row in planned_by_identity.items():
        active_row = active_by_identity[identity]
        if (
            active_row.get("uid") != planned_row.get("uid")
            or active_row.get("proofAnnotation") != plan_sha256
            or active_row.get("semanticWithoutProofSha256")
            != planned_row.get("semanticSha256")
            or active_row.get("semanticSha256")
            == planned_row.get("semanticSha256")
        ):
            raise TransactionError("HELM_PROOF_OWNED_MUTATION_INVALID")
    evidence = {"flux": current_flux, "workloads": current_workloads}
    evidence["sha256"] = sha256_bytes(canonical_json(evidence))
    return evidence


def validate_restored_helm_proof_inventory(
    client: KubeClient,
    plan: Mapping[str, object],
    restored_release: Mapping[str, object],
) -> dict[str, object]:
    baselines = plan.get("baselines")
    planned_flux = baselines.get("flux") if isinstance(baselines, Mapping) else None
    planned_workloads = (
        baselines.get("workloads") if isinstance(baselines, Mapping) else None
    )
    if not isinstance(planned_flux, Mapping) or not isinstance(
        planned_workloads, Mapping
    ):
        raise TransactionError("HELM_PROOF_BASELINE_INVALID")
    current_flux = flux_snapshot(client)
    current_workloads = workload_snapshot(client)
    validate_helm_workload_inventory(current_flux, current_workloads)
    validate_clean_workload_baseline(current_workloads)
    if current_workloads != planned_workloads:
        raise TransactionError("HELM_PROOF_WORKLOAD_NOT_RESTORED")

    planned_oci = planned_flux.get("oci")
    current_oci = current_flux.get("oci")
    planned_helm = planned_flux.get("helm")
    current_helm = current_flux.get("helm")
    if (
        not isinstance(planned_oci, Mapping)
        or not isinstance(current_oci, Mapping)
        or not isinstance(planned_helm, Mapping)
        or not isinstance(current_helm, Mapping)
    ):
        raise TransactionError("HELM_PROOF_FLUX_BASELINE_INVALID")
    compare_flux_without_resource_versions(
        {"gitRepositories": 0, "kustomizations": 0, "oci": current_oci, "helm": {}},
        {"gitRepositories": 0, "kustomizations": 0, "oci": planned_oci, "helm": {}},
    )
    lidersea = "lidersea-com/lidersea-com"
    compare_flux_without_resource_versions(
        {
            "gitRepositories": 0,
            "kustomizations": 0,
            "oci": {},
            "helm": {lidersea: current_helm.get(lidersea)},
        },
        {
            "gitRepositories": 0,
            "kustomizations": 0,
            "oci": {},
            "helm": {lidersea: planned_helm.get(lidersea)},
        },
    )
    naranjo = "naranjo-online/naranjo-online"
    current_naranjo = current_helm.get(naranjo)
    planned_naranjo = planned_helm.get(naranjo)
    if not isinstance(current_naranjo, Mapping) or not isinstance(
        planned_naranjo, Mapping
    ):
        raise TransactionError("HELM_PROOF_RELEASE_INVENTORY_INVALID")
    if {
        key: value
        for key, value in current_naranjo.items()
        if key != "resourceVersion"
    } != {
        key: value
        for key, value in restored_release.items()
        if key != "resourceVersion"
    }:
        raise TransactionError("HELM_PROOF_RESTORED_RELEASE_DRIFT")
    for key in (
        "uid",
        "attemptedRevision",
        "attemptedRevisionDigest",
        "historyChartVersion",
        "historyConfigDigest",
        "inventory",
        "specSha256",
        "semanticSha256",
    ):
        if current_naranjo.get(key) != planned_naranjo.get(key):
            raise TransactionError("HELM_PROOF_RESTORED_RELEASE_INVALID")
    if (
        not isinstance(current_naranjo.get("generation"), int)
        or not isinstance(planned_naranjo.get("generation"), int)
        or current_naranjo["generation"] <= planned_naranjo["generation"]
        or not isinstance(current_naranjo.get("historyRevision"), int)
        or not isinstance(planned_naranjo.get("historyRevision"), int)
        or current_naranjo["historyRevision"] <= planned_naranjo["historyRevision"]
    ):
        raise TransactionError("HELM_PROOF_RESTORED_REVISION_INVALID")
    evidence = {"flux": current_flux, "workloads": current_workloads}
    evidence["sha256"] = sha256_bytes(canonical_json(evidence))
    return evidence


def controller_owner_reference(
    value: Mapping[str, object], expected_kind: str
) -> Mapping[str, object]:
    metadata = value.get("metadata")
    references = metadata.get("ownerReferences") if isinstance(metadata, Mapping) else None
    controllers = [
        reference
        for reference in references or []
        if isinstance(reference, Mapping) and reference.get("controller") is True
    ]
    if len(controllers) != 1:
        raise TransactionError("CONTROLLER_OWNER_REFERENCE_INVALID")
    reference = controllers[0]
    if (
        reference.get("apiVersion") != "apps/v1"
        or reference.get("kind") != expected_kind
        or not isinstance(reference.get("name"), str)
        or UID_RE.fullmatch(str(reference.get("uid"))) is None
    ):
        raise TransactionError("CONTROLLER_OWNER_REFERENCE_INVALID")
    return reference


def validate_controller_image_id(image_id: object, expected_image: str) -> str:
    if not isinstance(image_id, str) or not image_id:
        raise TransactionError("CONTROLLER_POD_IMAGE_ID_INVALID")
    normalized = image_id
    for prefix in ("docker-pullable://", "containerd://"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    match = re.fullmatch(r"(?P<repository>[^@]+)@sha256:(?P<digest>[0-9a-f]{64})", normalized)
    expected_match = re.fullmatch(
        r"(?P<tagged>[^@]+)@sha256:(?P<digest>[0-9a-f]{64})", expected_image
    )
    if match is None or expected_match is None:
        raise TransactionError("CONTROLLER_POD_IMAGE_ID_INVALID")
    tagged = expected_match.group("tagged")
    slash = tagged.rfind("/")
    colon = tagged.rfind(":")
    repository = tagged[:colon] if colon > slash else tagged
    image_id_repository = match.group("repository")
    image_id_colon = image_id_repository.rfind(":")
    image_id_slash = image_id_repository.rfind("/")
    if image_id_colon > image_id_slash:
        image_id_repository = image_id_repository[:image_id_colon]
    if (
        image_id_repository != repository
        or match.group("digest") != expected_match.group("digest")
    ):
        raise TransactionError("CONTROLLER_POD_IMAGE_ID_INVALID")
    return image_id


def controller_snapshot(client: KubeClient) -> dict[str, object]:
    versions = parse_versions(read_regular(custody_path(VERSIONS_REL), owner=0, mode=0o600))
    expected_images = {
        "source-controller": versions["FLUX_SOURCE_CONTROLLER_IMAGE"],
        "kustomize-controller": versions["FLUX_KUSTOMIZE_CONTROLLER_IMAGE"],
        "helm-controller": versions["FLUX_HELM_CONTROLLER_IMAGE"],
    }
    pods = collection_items(client, "/api/v1/namespaces/flux-system/pods")
    replica_sets = collection_items(
        client, "/apis/apps/v1/namespaces/flux-system/replicasets"
    )
    result: dict[str, object] = {}
    for name in CONTROLLERS:
        _collection, url = resource_urls("Deployment", "flux-system", name)
        deployment = client.get(url)
        uid, rv = live_identity(deployment)
        metadata = deployment.get("metadata")
        spec = deployment.get("spec")
        status = deployment.get("status")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(status, Mapping):
            raise TransactionError("CONTROLLER_DEPLOYMENT_INVALID")
        template = spec.get("template")
        template_spec = template.get("spec") if isinstance(template, Mapping) else None
        containers = (
            template_spec.get("containers")
            if isinstance(template_spec, Mapping)
            else None
        )
        if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], Mapping):
            raise TransactionError("CONTROLLER_CONTAINER_INVALID")
        container = containers[0]
        if (
            container.get("name") != "manager"
            or container.get("image") != expected_images[name]
            or not isinstance(template_spec, Mapping)
            or template_spec.get("serviceAccountName") != name
        ):
            raise TransactionError("CONTROLLER_IMAGE_INVALID")
        args = container.get("args")
        command = container.get("command")
        if (
            not isinstance(args, list)
            or any(not isinstance(item, str) for item in args)
            or (
                command is not None
                and (
                    not isinstance(command, list)
                    or any(not isinstance(item, str) for item in command)
                )
            )
        ):
            raise TransactionError("CONTROLLER_ARGS_INVALID")
        replicas = spec.get("replicas")
        if (
            replicas != 1
            or status.get("observedGeneration") != metadata.get("generation")
            or status.get("availableReplicas") != 1
            or status.get("updatedReplicas") != 1
            or status.get("unavailableReplicas") not in (None, 0)
        ):
            raise TransactionError("CONTROLLER_DEPLOYMENT_NOT_READY")
        matching_pods = []
        for pod in pods:
            pod_metadata = pod.get("metadata")
            labels = pod_metadata.get("labels") if isinstance(pod_metadata, Mapping) else None
            if (
                isinstance(labels, Mapping)
                and labels.get("app") == name
                and pod_metadata.get("deletionTimestamp") is None
            ):
                matching_pods.append(pod)
        if len(matching_pods) != 1:
            raise TransactionError("CONTROLLER_POD_INVENTORY_INVALID")
        pod = matching_pods[0]
        pod_uid, _pod_rv = live_identity(pod)
        pod_spec = pod.get("spec")
        pod_status = pod.get("status")
        statuses = pod_status.get("containerStatuses") if isinstance(pod_status, Mapping) else None
        conditions = pod_status.get("conditions") if isinstance(pod_status, Mapping) else None
        ready = [
            item
            for item in conditions or []
            if isinstance(item, Mapping) and item.get("type") == "Ready"
        ]
        pod_containers = (
            pod_spec.get("containers") if isinstance(pod_spec, Mapping) else None
        )
        if (
            not isinstance(pod_spec, Mapping)
            or pod_spec.get("serviceAccountName") != name
            or not isinstance(pod_containers, list)
            or len(pod_containers) != 1
            or not isinstance(pod_containers[0], Mapping)
            or pod_containers[0].get("name") != "manager"
            or pod_containers[0].get("image") != container.get("image")
            or pod_containers[0].get("args") != args
            or pod_containers[0].get("command") != command
            or not isinstance(statuses, list)
            or len(statuses) != 1
            or not isinstance(statuses[0], Mapping)
            or statuses[0].get("name") != "manager"
            or statuses[0].get("ready") is not True
            or not isinstance(statuses[0].get("state"), Mapping)
            or not isinstance(statuses[0]["state"].get("running"), Mapping)
            or type(statuses[0].get("restartCount")) is not int
            or statuses[0].get("restartCount") < 0
            or statuses[0].get("image") != pod_containers[0].get("image")
            or len(ready) != 1
            or ready[0].get("status") != "True"
            or pod_status.get("phase") != "Running"
        ):
            raise TransactionError("CONTROLLER_POD_NOT_READY")
        image_id = validate_controller_image_id(
            statuses[0].get("imageID"), expected_images[name]
        )
        pod_owner = controller_owner_reference(pod, "ReplicaSet")
        matching_replica_sets = [
            replica_set
            for replica_set in replica_sets
            if isinstance(replica_set.get("metadata"), Mapping)
            and replica_set["metadata"].get("name") == pod_owner.get("name")
            and replica_set["metadata"].get("uid") == pod_owner.get("uid")
        ]
        if len(matching_replica_sets) != 1 or object_is_terminating(
            matching_replica_sets[0]
        ):
            raise TransactionError("CONTROLLER_REPLICASET_INVALID")
        replica_set_owner = controller_owner_reference(
            matching_replica_sets[0], "Deployment"
        )
        if replica_set_owner.get("name") != name or replica_set_owner.get("uid") != uid:
            raise TransactionError("CONTROLLER_REPLICASET_OWNER_INVALID")
        result[name] = {
            "uid": uid,
            "resourceVersion": rv,
            "generation": metadata.get("generation"),
            "image": containers[0].get("image"),
            "args": args,
            "podUid": pod_uid,
            "podRestarts": statuses[0].get("restartCount"),
            "podServiceAccountName": pod_spec.get("serviceAccountName"),
            "podContainerName": pod_containers[0].get("name"),
            "podImage": pod_containers[0].get("image"),
            "podImageID": image_id,
            "podArgs": copy.deepcopy(pod_containers[0].get("args")),
            "podCommand": copy.deepcopy(pod_containers[0].get("command")),
            "podReplicaSetName": pod_owner.get("name"),
            "podReplicaSetUid": pod_owner.get("uid"),
            "semanticSha256": semantic_hash(deployment),
            "rollbackObject": writable_from_live(deployment),
        }
    return result


def tracked_binding_subjects(subjects: object) -> list[str]:
    """Return every binding principal that authorizes a tracked ServiceAccount."""

    if not isinstance(subjects, list):
        return []
    selected: set[str] = set()
    tracked_users = {
        f"system:serviceaccount:{namespace}:{name}"
        for namespace, name in TRACKED_RBAC_SUBJECTS
    }
    tracked_groups = {"system:serviceaccounts", "system:authenticated"} | {
        f"system:serviceaccounts:{namespace}"
        for namespace, _name in TRACKED_RBAC_SUBJECTS
    }
    for subject in subjects:
        if not isinstance(subject, Mapping):
            continue
        kind = subject.get("kind")
        name = subject.get("name")
        namespace = subject.get("namespace")
        if kind == "ServiceAccount" and (namespace, name) in TRACKED_RBAC_SUBJECTS:
            selected.add(f"ServiceAccount:{namespace}/{name}")
        elif kind == "User" and name in tracked_users:
            selected.add(f"User:{name}")
        elif kind == "Group" and name in tracked_groups:
            selected.add(f"Group:{name}")
    return sorted(selected)


def binding_graph_row(item: Mapping[str, object]) -> dict[str, object] | None:
    tracked_subjects = tracked_binding_subjects(item.get("subjects"))
    if not tracked_subjects:
        return None
    metadata = item.get("metadata")
    role_ref = item.get("roleRef")
    if not isinstance(metadata, Mapping) or not isinstance(role_ref, Mapping):
        raise TransactionError("BINDING_GRAPH_INVALID")
    kind, namespace, name = metadata_identity(item)
    classification = "closed-transaction-scope"
    expected_subjects = KUBERNETES_DEFAULT_GROUP_BINDINGS.get(name)
    if expected_subjects is not None:
        if (
            kind != "ClusterRoleBinding"
            or namespace is not None
            or item.get("apiVersion") != "rbac.authorization.k8s.io/v1"
            or frozenset(item)
            != frozenset({"apiVersion", "kind", "metadata", "roleRef", "subjects"})
            or dict(role_ref)
            != {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": name,
            }
        ):
            raise TransactionError("KUBERNETES_DEFAULT_BINDING_POSTURE_INVALID")
        subjects = item.get("subjects")
        if not isinstance(subjects, list):
            raise TransactionError("KUBERNETES_DEFAULT_BINDING_SUBJECTS_INVALID")
        observed_subjects: set[str] = set()
        for subject in subjects:
            if (
                not isinstance(subject, Mapping)
                or frozenset(subject) != frozenset({"apiGroup", "kind", "name"})
                or subject.get("apiGroup") != "rbac.authorization.k8s.io"
                or subject.get("kind") != "Group"
                or not isinstance(subject.get("name"), str)
            ):
                raise TransactionError("KUBERNETES_DEFAULT_BINDING_SUBJECTS_INVALID")
            observed_subjects.add(str(subject["name"]))
        if len(observed_subjects) != len(subjects) or observed_subjects != set(
            expected_subjects
        ):
            raise TransactionError("KUBERNETES_DEFAULT_BINDING_SUBJECTS_INVALID")
        classification = "kubernetes-default-group"
    return {
        "kind": kind,
        "namespace": namespace,
        "name": name,
        "uid": metadata.get("uid"),
        "roleRef": dict(role_ref),
        "trackedSubjects": tracked_subjects,
        "classification": classification,
        "semanticSha256": semantic_hash(item),
    }


def binding_graph(client: KubeClient) -> dict[str, object]:
    cluster = collection_items(
        client, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
    )
    namespaced = collection_items(
        client, "/apis/rbac.authorization.k8s.io/v1/rolebindings"
    )
    rows: list[dict[str, object]] = []
    for item in cluster + namespaced:
        row = binding_graph_row(item)
        if row is not None:
            rows.append(row)
    rows.sort(key=lambda row: (str(row["kind"]), str(row["namespace"]), str(row["name"])))
    broad = [row for row in rows if row["kind"] == "ClusterRoleBinding" and row["roleRef"].get("name") == "cluster-admin"]  # type: ignore[union-attr]
    if len(broad) != 1 or broad[0]["name"] != BROAD_NAME:
        raise TransactionError("CONTROLLER_CLUSTER_ADMIN_GRAPH_INVALID")
    return {"rows": rows, "sha256": sha256_bytes(canonical_json(rows))}


def public_health() -> dict[str, int]:
    result: dict[str, int] = {}
    for hostname in ("naranjo.online", "lidersea.com"):
        request = urllib.request.Request(
            "https://" + hostname + "/",
            headers={"User-Agent": "website-infrastructure-live-proof/1"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status_code = response.status
                final = urllib.parse.urlsplit(response.geturl())
                response.read(1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransactionError("PUBLIC_SITE_PROBE_FAILED") from exc
        if (
            status_code != 200
            or final.scheme != "https"
            or final.hostname != hostname
            or final.username is not None
            or final.password is not None
        ):
            raise TransactionError("PUBLIC_SITE_NOT_HEALTHY")
        result[hostname] = status_code
    return result


def tls_tool_binding() -> dict[str, str]:
    cafile = ssl.get_default_verify_paths().cafile
    if not cafile:
        raise TransactionError("TLS_CA_BUNDLE_UNAVAILABLE")
    try:
        ca_path = Path(cafile).resolve(strict=True)
    except OSError as exc:
        raise TransactionError("TLS_CA_BUNDLE_UNAVAILABLE") from exc
    if not ca_path.is_absolute():
        raise TransactionError("TLS_CA_BUNDLE_UNAVAILABLE")
    ca_payload = read_regular(ca_path, maximum=2 * 1024 * 1024)
    return {
        "openssl": ssl.OPENSSL_VERSION,
        "caBundleSha256": sha256_bytes(ca_payload),
    }


def load_desired() -> dict[str, object]:
    document = parse_json_bytes(read_regular(custody_path(DESIRED_REL), owner=0, mode=0o600))
    if not isinstance(document, dict) or document.get("schema") != DESIRED_SCHEMA:
        raise TransactionError("DESIRED_DOCUMENT_INVALID")
    exact_fields(
        document,
        {
            "schema",
            "clusterRbacObjects",
            "deletionIdentities",
            "namespacedObjects",
            "controllerArgs",
            "temporaryProof",
        },
        "DESIRED_DOCUMENT",
    )
    return document


def desired_operations(document: Mapping[str, object]) -> list[dict[str, object]]:
    """Normalize the reviewed data bundle into the literal operation order."""

    cluster = document.get("clusterRbacObjects")
    namespaced = document.get("namespacedObjects")
    deletion = document.get("deletionIdentities")
    controller_args = document.get("controllerArgs")
    if (
        not isinstance(cluster, list)
        or not isinstance(namespaced, list)
        or not isinstance(deletion, list)
        or not isinstance(controller_args, Mapping)
    ):
        raise TransactionError("DESIRED_SECTIONS_INVALID")
    objects = []
    for item in cluster + namespaced:
        if not isinstance(item, Mapping):
            raise TransactionError("DESIRED_OBJECT_INVALID")
        objects.append(dict(item))
    cluster_ids = [metadata_identity(item) for item in objects[: len(cluster)]]
    namespaced_ids = [metadata_identity(item) for item in objects[len(cluster) :]]
    expected_split = {
        (kind, None, name)
        for name in SPLIT_NAMES
        for kind in ("ClusterRole", "ClusterRoleBinding")
    }
    shared = {
        ("ClusterRole", None, SHARED_NAME),
        ("ClusterRoleBinding", None, SHARED_NAME),
    }
    if len(cluster_ids) != 8 or set(cluster_ids) != expected_split | shared:
        raise TransactionError("DESIRED_CLUSTER_INVENTORY_INVALID")
    expected_namespaced = {
        ("Role", "flux-system", "flux-controller-runtime"),
        ("RoleBinding", "flux-system", "flux-controller-runtime"),
    }
    for namespace in ("naranjo-online", "lidersea-com"):
        expected_namespaced.update(
            {
                ("Role", namespace, "flux-controller-impersonation"),
                ("RoleBinding", namespace, "flux-controller-impersonation"),
                ("ServiceAccount", namespace, "helm-reconciler"),
                ("Role", namespace, "helm-reconciler"),
                ("RoleBinding", namespace, "helm-reconciler"),
            }
        )
    if len(namespaced_ids) != 12 or set(namespaced_ids) != expected_namespaced:
        raise TransactionError("DESIRED_NAMESPACED_INVENTORY_INVALID")
    if deletion != [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "name": BROAD_NAME,
        }
    ]:
        raise TransactionError("DESIRED_DELETION_INVALID")
    if set(controller_args) != {"kustomize-controller", "helm-controller"}:
        raise TransactionError("DESIRED_CONTROLLER_ARGS_INVENTORY_INVALID")
    operations: list[dict[str, object]] = []
    by_id = {metadata_identity(item): item for item in objects}
    for name in SPLIT_NAMES:
        for kind in ("ClusterRole", "ClusterRoleBinding"):
            desired = by_id[(kind, None, name)]
            operations.append(
                {
                    "id": f"create:{kind}:{name}",
                    "phase": "split",
                    "action": "create",
                    "kind": kind,
                    "namespace": None,
                    "name": name,
                    "desired": desired,
                }
            )
    for kind, namespace, name in sorted(expected_namespaced, key=lambda row: (row[1] or "", row[2], row[0])):
        desired = by_id[(kind, namespace, name)]
        operations.append(
            {
                "id": f"converge:{kind}:{namespace}:{name}",
                "phase": "namespaced",
                "action": "converge",
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "desired": desired,
            }
        )
    for name in ("kustomize-controller", "helm-controller"):
        args = controller_args[name]
        if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
            raise TransactionError("DESIRED_CONTROLLER_ARGS_INVALID")
        if args.count("--feature-gates=DisableConfigWatchers=true") != 1:
            raise TransactionError("DESIRED_WATCHER_GATE_INVALID")
        operations.append(
            {
                "id": f"rollout:Deployment:flux-system:{name}",
                "phase": "watchers",
                "action": "args",
                "kind": "Deployment",
                "namespace": "flux-system",
                "name": name,
                "desiredArgs": args,
            }
        )
    for kind in ("ClusterRole", "ClusterRoleBinding"):
        desired = by_id[(kind, None, SHARED_NAME)]
        operations.append(
            {
                "id": f"replace:{kind}:{SHARED_NAME}",
                "phase": "shared",
                "action": "replace",
                "kind": kind,
                "namespace": None,
                "name": SHARED_NAME,
                "desired": desired,
            }
        )
    operations.append(
        {
            "id": f"delete:ClusterRoleBinding:{BROAD_NAME}",
            "phase": "broad-delete",
            "action": "delete",
            "kind": "ClusterRoleBinding",
            "namespace": None,
            "name": BROAD_NAME,
        }
    )
    if len(operations) != 23:
        raise TransactionError("DESIRED_OPERATION_COUNT_INVALID")
    return operations


def plan_target(client: KubeClient, operation: Mapping[str, object]) -> dict[str, object]:
    kind = str(operation["kind"])
    namespace = operation.get("namespace")
    name = str(operation["name"])
    _collection, url = resource_urls(kind, namespace if isinstance(namespace, str) else None, name)
    live = client.get_optional(url)
    if live is not None and object_is_terminating(live):
        raise TransactionError("TARGET_PRESTATE_TERMINATING")
    if live is not None:
        annotations = live.get("metadata", {}).get("annotations")
        if isinstance(annotations, Mapping) and TRANSACTION_ANNOTATION in annotations:
            raise TransactionError("FOREIGN_TRANSACTION_MARKER_PRESENT")
    action = operation["action"]
    if action == "create" and live is not None:
        raise TransactionError("SPLIT_PRESTATE_NOT_ABSENT")
    if action in {"replace", "delete", "args"} and live is None:
        raise TransactionError("REQUIRED_PRESTATE_ABSENT")
    if action == "delete" and live is not None:
        metadata = live.get("metadata")
        finalizers = metadata.get("finalizers") if isinstance(metadata, Mapping) else None
        if finalizers not in (None, []):
            raise TransactionError("DELETE_PRESTATE_HAS_FINALIZERS")
    desired: dict[str, object] | None = None
    if action in {"create", "converge", "replace"}:
        raw = operation.get("desired")
        if not isinstance(raw, Mapping):
            raise TransactionError("OPERATION_DESIRED_INVALID")
        desired = semantic_object(raw)
    elif action == "args":
        assert live is not None
        desired = writable_from_live(live)
        spec = desired.get("spec")
        template = spec.get("template") if isinstance(spec, MutableMapping) else None
        pod_spec = template.get("spec") if isinstance(template, MutableMapping) else None
        containers = pod_spec.get("containers") if isinstance(pod_spec, MutableMapping) else None
        if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], MutableMapping):
            raise TransactionError("DEPLOYMENT_CONTAINER_INVALID")
        containers[0]["args"] = copy.deepcopy(operation["desiredArgs"])
        desired = semantic_object(desired)
    prestate: dict[str, object]
    if live is None:
        prestate = {"present": False}
    else:
        uid, resource_version = live_identity(live)
        metadata = live.get("metadata")
        prestate = {
            "present": True,
            "uid": uid,
            "resourceVersion": resource_version,
            "generation": metadata.get("generation") if isinstance(metadata, Mapping) else None,
            "semanticSha256": semantic_hash(live),
            "rollbackObject": writable_from_live(live),
        }
    effective_action = action
    if (
        action in {"converge", "replace", "args"}
        and live is not None
        and desired is not None
        and semantic_hash(live) == semantic_hash(desired)
    ):
        effective_action = "noop"
    return {
        "id": operation["id"],
        "phase": operation["phase"],
        "action": effective_action,
        "declaredAction": action,
        "kind": kind,
        "namespace": namespace,
        "name": name,
        "url": url,
        "prestate": prestate,
        "desired": desired,
        "desiredSha256": semantic_hash(desired) if desired is not None else None,
    }


def build_plan(client: KubeClient, target: Target, custody: Mapping[str, object]) -> dict[str, object]:
    desired = load_desired()
    operations = desired_operations(desired)
    targets = [plan_target(client, operation) for operation in operations]
    split_presence = [item["prestate"]["present"] for item in targets if item["phase"] == "split"]  # type: ignore[index]
    if any(split_presence):
        raise TransactionError("SPLIT_PRESTATE_PARTIAL_OR_PRESENT")
    source_revision = str(custody["sourceRevision"])
    contract = load_module(custody_path(PLATFORM_CONTRACT_REL), "platform_release_contract")
    source = verify_release_identity(
        source_revision,
        target.release_tag,
        contract,
        read_regular(custody_path(RELEASE_FRAGMENT_REL), owner=0, mode=0o600),
    )
    entries = validate_custody(custody)
    source["sourceBundleSha256"] = verify_custody_source_tree(
        source_revision, str(source["sourceTreeSha"]), entries
    )
    target_binding = bind_target(client, target)
    controllers = controller_snapshot(client)
    flux = flux_snapshot(client)
    workloads = workload_snapshot(client)
    validate_helm_workload_inventory(flux, workloads)
    validate_clean_workload_baseline(workloads)
    graph = binding_graph(client)
    allowed_binding_identities = {
        ("ClusterRoleBinding", None, BROAD_NAME),
        ("ClusterRoleBinding", None, SHARED_NAME),
        *(
            ("ClusterRoleBinding", None, name)
            for name in KUBERNETES_DEFAULT_GROUP_BINDINGS
        ),
    } | {
        (item["kind"], item.get("namespace"), item["name"])
        for item in targets
        if item["kind"] in {"RoleBinding", "ClusterRoleBinding"}
    }
    graph_rows = graph.get("rows")
    if not isinstance(graph_rows, list) or any(
        not isinstance(row, Mapping)
        or (row.get("kind"), row.get("namespace"), row.get("name"))
        not in allowed_binding_identities
        for row in graph_rows
    ):
        raise TransactionError("TRACKED_BINDING_OUTSIDE_CLOSED_INVENTORY")
    public = public_health()
    now = utc_now()
    tls = tls_tool_binding()
    return {
        "schema": PLAN_SCHEMA,
        "createdAt": iso8601(now),
        "expiresAt": iso8601(now + PLAN_TTL),
        "source": {
            **source,
            "sourceManifestSha256": custody["manifestSha256"],
            "custodySha256": custody["custodySha256"],
        },
        "target": target_binding,
        "tools": {
            "pythonPath": custody["pythonPath"],
            "pythonSha256": custody["pythonSha256"],
            "kubectlSha256": client.digest,
            "kubeconfigSha256": client.kubeconfig_digest,
            **tls,
        },
        "targets": targets,
        "operationOrder": [item["id"] for item in targets],
        "baselines": {
            "controllers": controllers,
            "flux": flux,
            "workloads": workloads,
            "bindingGraph": graph,
            "publicSites": public,
        },
        "temporaryProof": desired.get("temporaryProof"),
    }


def write_plan(plan: Mapping[str, object]) -> str:
    payload = canonical_json(plan)
    digest = sha256_bytes(payload)
    publish_once(PLAN_PATH, payload)
    return digest


def read_plan(
    expected_sha256: str | None = None, *, require_fresh: bool = True
) -> tuple[dict[str, object], str]:
    payload = read_regular(PLAN_PATH, owner=0, mode=0o600)
    digest = sha256_bytes(payload)
    if expected_sha256 is not None and digest != expected_sha256:
        raise TransactionError("PLAN_DIGEST_MISMATCH")
    document = parse_json_bytes(payload)
    if not isinstance(document, dict) or document.get("schema") != PLAN_SCHEMA:
        raise TransactionError("PLAN_SCHEMA_INVALID")
    expires_at = parse_time(document.get("expiresAt"), "PLAN_EXPIRES")
    if require_fresh and expires_at < utc_now():
        raise TransactionError("PLAN_EXPIRED")
    return document, digest


def parse_journal_payload(payload: bytes) -> dict[str, object]:
    value = parse_json_bytes(payload)
    if (
        not isinstance(value, dict)
        or value.get("schema") != JOURNAL_SCHEMA
        or canonical_json(value) != payload
        or SHA256_RE.fullmatch(str(value.get("planSha256"))) is None
        or SOURCE_REVISION_RE.fullmatch(str(value.get("sourceRevision"))) is None
        or SHA256_RE.fullmatch(str(value.get("targetSha256"))) is None
        or SHA256_RE.fullmatch(str(value.get("attemptId"))) is None
        or type(value.get("sequence")) is not int
        or int(value["sequence"]) < 1
        or value.get("state")
        not in {"prepared", "recovery-required", "committed", "rolled-back"}
        or not isinstance(value.get("phase"), str)
        or (
            value.get("pendingOperation") is not None
            and not isinstance(value.get("pendingOperation"), str)
        )
        or not isinstance(value.get("operations"), dict)
        or not isinstance(value.get("helmProof"), dict)
        or not isinstance(value.get("recoveryRequired"), bool)
    ):
        raise TransactionError("JOURNAL_INVALID")
    validate_journal_embedded_evidence(value)
    return value


def validate_journal_successor(
    previous: Mapping[str, object], successor: Mapping[str, object]
) -> None:
    for field in (
        "schema",
        "planSha256",
        "sourceRevision",
        "targetSha256",
        "attemptId",
    ):
        if successor.get(field) != previous.get(field):
            raise TransactionError("JOURNAL_TEMP_IDENTITY_MISMATCH")
    if successor.get("sequence") != int(previous["sequence"]) + 1:
        raise TransactionError("JOURNAL_TEMP_SEQUENCE_INVALID")
    transitions = {
        "prepared": {"prepared", "recovery-required", "committed", "rolled-back"},
        "recovery-required": {"recovery-required", "rolled-back"},
        "committed": {"committed"},
        "rolled-back": {"rolled-back"},
    }
    if successor.get("state") not in transitions[str(previous.get("state"))]:
        raise TransactionError("JOURNAL_TEMP_STATE_REGRESSION")
    if not set(previous).issubset(successor):
        raise TransactionError("JOURNAL_TEMP_FIELDS_REMOVED")
    old_operations = previous.get("operations")
    new_operations = successor.get("operations")
    if not isinstance(old_operations, Mapping) or not isinstance(new_operations, Mapping):
        raise TransactionError("JOURNAL_TEMP_OPERATIONS_INVALID")
    if not set(old_operations).issubset(new_operations):
        raise TransactionError("JOURNAL_TEMP_OPERATIONS_REMOVED")
    old_receipts = previous.get("receiptRecords", {})
    new_receipts = successor.get("receiptRecords", {})
    if (
        not isinstance(old_receipts, Mapping)
        or not isinstance(new_receipts, Mapping)
        or not set(old_receipts).issubset(new_receipts)
        or any(new_receipts[key] != value for key, value in old_receipts.items())
    ):
        raise TransactionError("JOURNAL_TEMP_RECEIPTS_REMOVED")
    for field in ("oracleEvidenceRecords",):
        old_records = previous.get(field, {})
        new_records = successor.get(field, {})
        if (
            not isinstance(old_records, Mapping)
            or not isinstance(new_records, Mapping)
            or not set(old_records).issubset(new_records)
            or any(new_records[key] != value for key, value in old_records.items())
        ):
            raise TransactionError("JOURNAL_TEMP_EVIDENCE_REGRESSION")
    for field in ("terminalEvidence", "terminalEvidenceSha256"):
        if field in previous and successor.get(field) != previous.get(field):
            raise TransactionError("JOURNAL_TEMP_TERMINAL_EVIDENCE_REGRESSION")
    if (
        "terminalEvidence" not in previous
        and "terminalEvidence" in successor
        and successor.get("state") not in {"committed", "rolled-back"}
    ):
        raise TransactionError("JOURNAL_TEMP_TERMINAL_EVIDENCE_EARLY")
    old_counter = previous.get("verificationCounter")
    new_counter = successor.get("verificationCounter")
    old_chain = previous.get("verificationChainSha256")
    new_chain = successor.get("verificationChainSha256")
    old_pending = previous.get("pendingVerification")
    new_pending = successor.get("pendingVerification")
    if (
        type(old_counter) is not int
        or type(new_counter) is not int
        or SHA256_RE.fullmatch(str(old_chain)) is None
        or SHA256_RE.fullmatch(str(new_chain)) is None
    ):
        raise TransactionError("JOURNAL_TEMP_VERIFICATION_REGRESSION")
    if old_pending is None and new_pending is None:
        valid_verification_transition = (
            new_counter == old_counter and new_chain == old_chain
        )
    elif old_pending is None and isinstance(new_pending, Mapping):
        valid_verification_transition = (
            new_counter == old_counter + 1
            and new_pending.get("verificationIndex") == new_counter
            and new_chain == old_chain
        )
    elif isinstance(old_pending, Mapping) and new_pending == old_pending:
        valid_verification_transition = (
            new_counter == old_counter and new_chain == old_chain
        )
    elif isinstance(old_pending, Mapping) and new_pending is None:
        valid_verification_transition = (
            new_counter == old_counter
            and new_chain == sha256_bytes(canonical_json(old_pending))
        )
    else:
        valid_verification_transition = False
    if not valid_verification_transition:
        raise TransactionError("JOURNAL_TEMP_VERIFICATION_REGRESSION")


def recover_journal_temporary() -> None:
    """Publish one complete, canonical next journal record after a hard stop."""

    temporary = JOURNAL_PATH.with_name(JOURNAL_PATH.name + ".new")
    try:
        metadata = temporary.lstat()
    except FileNotFoundError:
        return
    parent = JOURNAL_PATH.parent.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != parent.st_uid
        or metadata.st_gid != parent.st_gid
        or metadata.st_dev != parent.st_dev
        or metadata.st_nlink not in {1, 2}
    ):
        raise TransactionError("JOURNAL_TEMP_METADATA_INVALID")
    try:
        destination = JOURNAL_PATH.lstat()
    except FileNotFoundError:
        destination = None
    if metadata.st_nlink == 2:
        if (
            destination is None
            or not stat.S_ISREG(destination.st_mode)
            or destination.st_dev != metadata.st_dev
            or destination.st_ino != metadata.st_ino
            or destination.st_nlink != 2
        ):
            raise TransactionError("JOURNAL_TEMP_LINK_INVALID")
        temporary.unlink()
        fsync_directory(JOURNAL_PATH.parent)
        return
    payload = read_atomic_temporary(temporary, metadata)
    candidate = parse_journal_payload(payload)
    if destination is None:
        if (
            candidate.get("sequence") != 1
            or candidate.get("state") != "prepared"
            or candidate.get("phase") != "prepared"
            or candidate.get("pendingOperation") is not None
            or candidate.get("operations") != {}
        ):
            raise TransactionError("JOURNAL_TEMP_INITIAL_INVALID")
    else:
        if (
            not stat.S_ISREG(destination.st_mode)
            or stat.S_IMODE(destination.st_mode) != 0o600
            or destination.st_uid != parent.st_uid
            or destination.st_gid != parent.st_gid
            or destination.st_dev != parent.st_dev
            or destination.st_nlink != 1
        ):
            raise TransactionError("JOURNAL_DESTINATION_INVALID")
        current = parse_journal_payload(
            read_regular(
                JOURNAL_PATH,
                owner=parent.st_uid,
                mode=0o600,
            )
        )
        validate_journal_successor(current, candidate)
    os.replace(temporary, JOURNAL_PATH)
    fsync_directory(JOURNAL_PATH.parent)


class Journal:
    def __init__(self, plan_sha256: str, source_revision: str, target_sha256: str):
        self.document: dict[str, object] = {
            "schema": JOURNAL_SCHEMA,
            "planSha256": plan_sha256,
            "sourceRevision": source_revision,
            "targetSha256": target_sha256,
            "attemptId": hashlib.sha256(os.urandom(32)).hexdigest(),
            "state": "prepared",
            "phase": "prepared",
            "sequence": 0,
            "pendingOperation": None,
            "operations": {},
            "helmProof": {"state": "not-started"},
            "oracleEvidenceRecords": {},
            "verificationCounter": 0,
            "verificationChainSha256": "0" * 64,
            "pendingVerification": None,
            "recoveryRequired": False,
        }

    @classmethod
    def load(cls) -> "Journal":
        recover_journal_temporary()
        value = parse_journal_payload(
            read_regular(JOURNAL_PATH, owner=0, mode=0o600, durable=True)
        )
        instance = object.__new__(cls)
        instance.document = value
        return instance

    def write(self) -> None:
        sequence = self.document.get("sequence")
        if not isinstance(sequence, int) or sequence < 0:
            raise TransactionError("JOURNAL_SEQUENCE_INVALID")
        self.document["sequence"] = sequence + 1
        payload = canonical_json(self.document)
        previous_signals = block_transaction_signals()
        try:
            try:
                atomic_write(
                    JOURNAL_PATH,
                    payload,
                    replace=JOURNAL_PATH.exists(),
                    preserve_complete_temporary=True,
                )
            except BaseException:
                try:
                    published = read_regular(JOURNAL_PATH, owner=0, mode=0o600) == payload
                except TransactionError:
                    published = False
                if not published:
                    self.document["sequence"] = sequence
                # Visible bytes are not a durability receipt. In particular,
                # os.replace()/link() may have succeeded before the parent
                # directory fsync failed. Never authorize a following API
                # mutation from that merely-visible journal state.
                raise
        finally:
            restore_transaction_signals(previous_signals)

    def intent(self, operation_id: str, phase: str) -> None:
        self.document["phase"] = phase
        self.document["pendingOperation"] = operation_id
        operations = self.document.get("operations")
        if not isinstance(operations, MutableMapping):
            raise TransactionError("JOURNAL_OPERATIONS_INVALID")
        if operation_id in operations:
            raise TransactionError("JOURNAL_OPERATION_REPLAY")
        operations[operation_id] = {"state": "intent"}
        self.write()

    def committed(self, operation_id: str, live: Mapping[str, object] | None) -> None:
        operations = self.document["operations"]
        assert isinstance(operations, MutableMapping)
        record = operations.get(operation_id)
        if not isinstance(record, MutableMapping) or record.get("state") != "intent":
            raise TransactionError("JOURNAL_OPERATION_STATE_INVALID")
        record["state"] = "committed"
        if live is not None:
            uid, resource_version = live_identity(live)
            record.update(
                {
                    "uid": uid,
                    "resourceVersion": resource_version,
                    "semanticSha256": semantic_hash(live),
                }
            )
        self.document["pendingOperation"] = None
        self.write()

    def delete_transition(
        self,
        operation_id: str,
        delete_state: str,
        live: Mapping[str, object] | None = None,
    ) -> None:
        operations = self.document.get("operations")
        record = operations.get(operation_id) if isinstance(operations, MutableMapping) else None
        if not isinstance(record, MutableMapping) or record.get("state") != "intent":
            raise TransactionError("DELETE_JOURNAL_STATE_INVALID")
        prior = record.get("deleteState")
        expected_prior = {
            "mark-intent": None,
            "marked": "mark-intent",
            "delete-intent": "marked",
            "delete-accepted": "delete-intent",
        }
        if delete_state not in expected_prior or prior != expected_prior[delete_state]:
            raise TransactionError("DELETE_JOURNAL_TRANSITION_INVALID")
        record["deleteState"] = delete_state
        if delete_state == "marked":
            if live is None:
                raise TransactionError("DELETE_MARK_RESPONSE_MISSING")
            uid, resource_version = live_identity(live)
            record.update(
                {
                    "markedUid": uid,
                    "markedResourceVersion": resource_version,
                    "markedSemanticSha256": semantic_hash(live),
                }
            )
        elif live is not None:
            raise TransactionError("DELETE_TRANSITION_LIVE_UNEXPECTED")
        self.write()

    def controller_rollout(
        self, operation_id: str, snapshot: Mapping[str, object]
    ) -> None:
        operations = self.document.get("operations")
        record = operations.get(operation_id) if isinstance(operations, MutableMapping) else None
        if not isinstance(record, MutableMapping) or record.get("state") != "committed":
            raise TransactionError("CONTROLLER_ROLLOUT_JOURNAL_INVALID")
        fields = CONTROLLER_RUNTIME_FIELDS
        evidence = {field: copy.deepcopy(snapshot.get(field)) for field in fields}
        if (
            not isinstance(evidence["generation"], int)
            or evidence["podRestarts"] != 0
            or not isinstance(evidence["podUid"], str)
            or not isinstance(evidence["args"], list)
            or evidence["podArgs"] != evidence["args"]
            or evidence["podImage"] != evidence["image"]
            or not isinstance(evidence["podImageID"], str)
            or not isinstance(evidence["podServiceAccountName"], str)
            or evidence["podContainerName"] != "manager"
            or not isinstance(evidence["podReplicaSetName"], str)
            or UID_RE.fullmatch(str(evidence["podReplicaSetUid"])) is None
        ):
            raise TransactionError("CONTROLLER_ROLLOUT_EVIDENCE_INVALID")
        if "rolloutSnapshot" in record and record["rolloutSnapshot"] != evidence:
            raise TransactionError("CONTROLLER_ROLLOUT_EVIDENCE_COLLISION")
        record["rolloutSnapshot"] = evidence
        self.write()

    def mark_recovery_required(self) -> None:
        if terminal_result(self.document.get("state")) is not None:
            raise TransactionError("TERMINAL_JOURNAL_RECOVERY_REGRESSION")
        self.document["state"] = "recovery-required"
        self.document["recoveryRequired"] = True
        self.write()


def compare_prestate(client: KubeClient, target: Mapping[str, object]) -> None:
    live = client.get_optional(str(target["url"]))
    prestate = target.get("prestate")
    if not isinstance(prestate, Mapping):
        raise TransactionError("PLAN_PRESTATE_INVALID")
    if prestate.get("present") is False:
        if live is not None:
            raise TransactionError("PLAN_ABSENCE_DRIFT")
        return
    if live is None:
        raise TransactionError("PLAN_OBJECT_DISAPPEARED")
    if object_is_terminating(live):
        raise TransactionError("PLAN_OBJECT_TERMINATING")
    uid, rv = live_identity(live)
    if (
        uid != prestate.get("uid")
        or rv != prestate.get("resourceVersion")
        or semantic_hash(live) != prestate.get("semanticSha256")
    ):
        raise TransactionError("PLAN_OBJECT_DRIFT")
    metadata = live.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("generation") != prestate.get("generation"):
        raise TransactionError("PLAN_GENERATION_DRIFT")


def replace_body(
    current: Mapping[str, object], desired: Mapping[str, object], attempt_id: str
) -> dict[str, object]:
    current_uid, current_rv = live_identity(current)
    body = with_transaction_annotation(semantic_object(desired), attempt_id)
    metadata = body.get("metadata")
    if not isinstance(metadata, MutableMapping):
        raise TransactionError("REPLACE_METADATA_INVALID")
    metadata["uid"] = current_uid
    metadata["resourceVersion"] = current_rv
    return body


def has_transaction_marker(value: Mapping[str, object], attempt_id: str) -> bool:
    metadata = value.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, Mapping) else None
    return (
        isinstance(annotations, Mapping)
        and annotations.get(TRANSACTION_ANNOTATION) == attempt_id
    )


def wait_object_absent(
    client: KubeClient,
    url: str,
    *,
    expected_uid: str,
    expected_semantic_sha256: str,
    attempt_id: str,
) -> None:
    """Wait only for disappearance of the exact transaction-marked object."""

    deadline = time.monotonic() + DELETE_TIMEOUT_SECONDS
    while True:
        live = client.get_optional(url)
        if live is None:
            return
        uid, _resource_version = live_identity(live)
        if (
            uid != expected_uid
            or semantic_hash(live) != expected_semantic_sha256
            or not has_transaction_marker(live, attempt_id)
        ):
            raise RecoveryRequired("DELETE_WAIT_ATTRIBUTION_FAILED")
        if time.monotonic() >= deadline:
            raise RecoveryRequired("DELETE_WAIT_TIMEOUT")
        time.sleep(1)


def apply_operation(client: KubeClient, target: Mapping[str, object], journal: Journal) -> None:
    operation_id = str(target["id"])
    action = target["action"]
    url = str(target["url"])
    attempt_id = str(journal.document["attemptId"])
    journal.intent(operation_id, str(target["phase"]))
    if action == "noop":
        current = client.get_optional(url)
        prestate = target.get("prestate")
        if current is None or not isinstance(prestate, Mapping):
            raise RecoveryRequired("NOOP_PRESTATE_ABSENT")
        if object_is_terminating(current):
            raise RecoveryRequired("NOOP_PRESTATE_TERMINATING")
        uid, rv = live_identity(current)
        if (
            uid != prestate.get("uid")
            or rv != prestate.get("resourceVersion")
            or semantic_hash(current) != prestate.get("semanticSha256")
            or semantic_hash(current) != target.get("desiredSha256")
        ):
            raise RecoveryRequired("NOOP_PRESTATE_DRIFT")
        journal.committed(operation_id, current)
        return
    mutation_signals: object | None = None
    try:
        if action == "create":
            if client.get_optional(url) is not None:
                raise RecoveryRequired("CREATE_PRESTATE_DRIFT")
            desired = target.get("desired")
            if not isinstance(desired, Mapping):
                raise TransactionError("CREATE_DESIRED_INVALID")
            kind, namespace, name = metadata_identity(desired)
            collection, _ = resource_urls(kind, namespace, name)
            mutation_signals = block_transaction_signals()
            result = client.post(
                collection, with_transaction_annotation(desired, attempt_id)
            )
        elif action in {"converge", "replace", "args"}:
            current = client.get_optional(url)
            if current is None:
                if action != "converge":
                    raise RecoveryRequired("REPLACE_OBJECT_ABSENT")
                desired = target.get("desired")
                if not isinstance(desired, Mapping):
                    raise TransactionError("CONVERGE_DESIRED_INVALID")
                kind, namespace, name = metadata_identity(desired)
                collection, _ = resource_urls(kind, namespace, name)
                mutation_signals = block_transaction_signals()
                result = client.post(
                    collection, with_transaction_annotation(desired, attempt_id)
                )
            else:
                prestate = target.get("prestate")
                if not isinstance(prestate, Mapping):
                    raise TransactionError("REPLACE_PRESTATE_INVALID")
                if object_is_terminating(current):
                    raise RecoveryRequired("REPLACE_OBJECT_TERMINATING")
                uid, rv = live_identity(current)
                if (
                    prestate.get("present") is not True
                    or uid != prestate.get("uid")
                    or rv != prestate.get("resourceVersion")
                    or semantic_hash(current) != prestate.get("semanticSha256")
                ):
                    raise RecoveryRequired("REPLACE_PRESTATE_DRIFT")
                desired = target.get("desired")
                if not isinstance(desired, Mapping):
                    raise TransactionError("REPLACE_DESIRED_INVALID")
                mutation_signals = block_transaction_signals()
                result = client.put(
                    url, replace_body(current, desired, attempt_id)
                )
        elif action == "delete":
            current = client.get_optional(url)
            prestate = target.get("prestate")
            if current is None or not isinstance(prestate, Mapping):
                raise RecoveryRequired("DELETE_PRESTATE_ABSENT")
            if object_is_terminating(current):
                raise RecoveryRequired("DELETE_PRESTATE_TERMINATING")
            uid, rv = live_identity(current)
            if (
                uid != prestate.get("uid")
                or rv != prestate.get("resourceVersion")
                or semantic_hash(current) != prestate.get("semanticSha256")
            ):
                raise RecoveryRequired("DELETE_PRESTATE_DRIFT")
            metadata = current.get("metadata")
            finalizers = (
                metadata.get("finalizers") if isinstance(metadata, Mapping) else None
            )
            if finalizers not in (None, []):
                raise RecoveryRequired("DELETE_PRESTATE_FINALIZERS")
            journal.delete_transition(operation_id, "mark-intent")
            mark_signals = block_transaction_signals()
            try:
                marked = client.put(
                    url,
                    with_transaction_annotation(
                        writable_from_live(current), attempt_id
                    ),
                )
                marked_uid, marked_rv = live_identity(marked)
                if (
                    metadata_identity(marked)
                    != (target["kind"], target.get("namespace"), target["name"])
                    or marked_uid != uid
                    or marked_rv == rv
                    or object_is_terminating(marked)
                    or semantic_hash(marked) != prestate.get("semanticSha256")
                    or not has_transaction_marker(marked, attempt_id)
                ):
                    raise RecoveryRequired("DELETE_MARK_RESPONSE_INVALID")
                journal.delete_transition(operation_id, "marked", marked)
            finally:
                restore_transaction_signals(mark_signals)
            journal.delete_transition(operation_id, "delete-intent")
            delete_signals = block_transaction_signals()
            try:
                client.delete(url, marked_uid, marked_rv)
                journal.delete_transition(operation_id, "delete-accepted")
            finally:
                restore_transaction_signals(delete_signals)
            wait_object_absent(
                client,
                url,
                expected_uid=marked_uid,
                expected_semantic_sha256=str(prestate["semanticSha256"]),
                attempt_id=attempt_id,
            )
            journal.committed(operation_id, None)
            return
        else:
            raise TransactionError("OPERATION_ACTION_INVALID")
        if metadata_identity(result) != (
            target["kind"],
            target.get("namespace"),
            target["name"],
        ):
            raise RecoveryRequired("MUTATION_RESPONSE_IDENTITY_INVALID")
        if semantic_hash(result) != target.get("desiredSha256"):
            raise RecoveryRequired("MUTATION_RESPONSE_SEMANTICS_INVALID")
        journal.committed(operation_id, result)
    finally:
        restore_transaction_signals(mutation_signals)


def wait_controller_rollout(
    client: KubeClient, name: str, prior_pod_uid: str | None = None
) -> dict[str, object]:
    deadline = time.monotonic() + ROLLOUT_TIMEOUT_SECONDS
    last_error: TransactionError | None = None
    while time.monotonic() < deadline:
        try:
            snapshot = controller_snapshot(client)[name]
            if prior_pod_uid is not None and snapshot["podUid"] == prior_pod_uid:
                raise TransactionError("CONTROLLER_POD_NOT_REPLACED")
            if snapshot["podRestarts"] != 0:
                raise TransactionError("CONTROLLER_NEW_POD_RESTARTED")
            return snapshot  # type: ignore[return-value]
        except TransactionError as exc:
            last_error = exc
            time.sleep(2)
    raise TransactionError("CONTROLLER_ROLLOUT_TIMEOUT") from last_error


OWNED_ROWS = (
    ("source-controller", "patch", "source.toolkit.fluxcd.io", "buckets"),
    ("source-controller", "update", "source.toolkit.fluxcd.io", "buckets/status"),
    ("kustomize-controller", "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    ("kustomize-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/status"),
    ("kustomize-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/finalizers"),
    ("helm-controller", "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    ("helm-controller", "update", "helm.toolkit.fluxcd.io", "helmreleases/status"),
    ("helm-controller", "create", "source.toolkit.fluxcd.io", "helmcharts"),
    ("helm-controller", "delete", "source.toolkit.fluxcd.io", "helmcharts"),
)
CROSSING_ROWS = (
    ("source-controller", "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    ("source-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/status"),
    ("source-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/finalizers"),
    ("source-controller", "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    ("source-controller", "update", "helm.toolkit.fluxcd.io", "helmreleases/status"),
    ("source-controller", "create", "source.toolkit.fluxcd.io", "helmcharts"),
    ("source-controller", "delete", "source.toolkit.fluxcd.io", "helmcharts"),
    ("kustomize-controller", "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    ("kustomize-controller", "update", "helm.toolkit.fluxcd.io", "helmreleases/status"),
    ("kustomize-controller", "patch", "source.toolkit.fluxcd.io", "ocirepositories"),
    ("kustomize-controller", "patch", "source.toolkit.fluxcd.io", "gitrepositories"),
    ("kustomize-controller", "create", "source.toolkit.fluxcd.io", "helmcharts"),
    ("helm-controller", "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    ("helm-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/status"),
    ("helm-controller", "update", "kustomize.toolkit.fluxcd.io", "kustomizations/finalizers"),
    ("helm-controller", "patch", "source.toolkit.fluxcd.io", "gitrepositories"),
    ("helm-controller", "patch", "source.toolkit.fluxcd.io", "ocirepositories"),
    ("helm-controller", "update", "source.toolkit.fluxcd.io", "buckets/status"),
)
INFORMER_RESOURCES = {
    "source-controller": (
        ("source.toolkit.fluxcd.io", "buckets"),
        ("source.toolkit.fluxcd.io", "gitrepositories"),
        ("source.toolkit.fluxcd.io", "helmcharts"),
        ("source.toolkit.fluxcd.io", "helmrepositories"),
        ("source.toolkit.fluxcd.io", "ocirepositories"),
    ),
    "kustomize-controller": (
        ("kustomize.toolkit.fluxcd.io", "kustomizations"),
        ("source.toolkit.fluxcd.io", "buckets"),
        ("source.toolkit.fluxcd.io", "gitrepositories"),
        ("source.toolkit.fluxcd.io", "ocirepositories"),
    ),
    "helm-controller": (
        ("helm.toolkit.fluxcd.io", "helmreleases"),
        ("source.toolkit.fluxcd.io", "helmcharts"),
        ("source.toolkit.fluxcd.io", "ocirepositories"),
    ),
}

ORACLE_PHASE_COUNTS = {
    "pre-shared": 101,
    "mixed": 69,
    "final": 125,
    "rollback": 27,
}
ORACLE_RECEIPT_MAX_BYTES = 4096
ORACLE_PHASE_MAX_BYTES = 256 * 1024


def normalized_discovery(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise TransactionError("AUTHORIZATION_DISCOVERY_INVALID")
    exact_fields(
        value,
        {
            "state",
            "groupVersion",
            "resource",
            "kind",
            "namespaced",
            "crdName",
            "verb",
            "verbEvidence",
        },
        "AUTHORIZATION_DISCOVERY",
    )
    group_version = value.get("groupVersion")
    resource = value.get("resource")
    kind = value.get("kind")
    crd_name = value.get("crdName")
    verb = value.get("verb")
    if (
        value.get("state") != "RESOLVED"
        or not isinstance(group_version, str)
        or len(group_version) > 253
        or re.fullmatch(r"[a-z0-9.]+/v[0-9]+|v[0-9]+", group_version) is None
        or not isinstance(resource, str)
        or len(resource) > 128
        or re.fullmatch(r"[a-z0-9]+(?:/[a-z0-9]+)?", resource) is None
        or not isinstance(kind, str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", kind) is None
        or type(value.get("namespaced")) is not bool
        or (
            crd_name is not None
            and (
                not isinstance(crd_name, str)
                or len(crd_name) > 253
                or DNS_RE.fullmatch(crd_name) is None
            )
        )
        or not isinstance(verb, str)
        or re.fullmatch(r"[a-z]+", verb) is None
        or value.get("verbEvidence") not in {"DISCOVERY", "AUTHORIZATION_ONLY"}
    ):
        raise TransactionError("AUTHORIZATION_DISCOVERY_INVALID")
    return copy.deepcopy(dict(value))


def normalized_oracle_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise TransactionError("AUTHORIZATION_RECEIPT_INVALID")
    exact_fields(
        value,
        {
            "request",
            "discovery",
            "authorization",
            "expected",
            "controls",
            "result",
        },
        "AUTHORIZATION_RECEIPT",
    )
    request = value.get("request")
    if not isinstance(request, Mapping):
        raise TransactionError("AUTHORIZATION_REQUEST_INVALID")
    exact_fields(
        request,
        {
            "subject",
            "verb",
            "apiGroup",
            "resource",
            "subresource",
            "namespace",
            "name",
            "allNamespaces",
        },
        "AUTHORIZATION_REQUEST",
    )
    subject = request.get("subject")
    verb = request.get("verb")
    group = request.get("apiGroup")
    resource = request.get("resource")
    subresource = request.get("subresource")
    namespace = request.get("namespace")
    name = request.get("name")
    subject_parts = subject.split(":") if isinstance(subject, str) else []
    if (
        not isinstance(subject, str)
        or re.fullmatch(
            r"system:serviceaccount:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?:"
            r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?",
            subject,
        )
        is None
        or len(subject_parts) != 4
        or len(subject_parts[2]) > 63
        or len(subject_parts[3]) > 253
        or not isinstance(verb, str)
        or re.fullmatch(r"[a-z]+", verb) is None
        or not isinstance(group, str)
        or len(group) > 253
        or (group and DNS_RE.fullmatch(group) is None)
        or not isinstance(resource, str)
        or len(resource) > 128
        or re.fullmatch(r"[a-z0-9]+(?:/[a-z0-9]+)?", resource) is None
        or (
            subresource is not None
            and (
                not isinstance(subresource, str)
                or re.fullmatch(r"[a-z0-9]+", subresource) is None
            )
        )
        or (
            namespace is not None
            and (
                not isinstance(namespace, str)
                or len(namespace) > 63
                or DNS_RE.fullmatch(namespace) is None
            )
        )
        or (
            name is not None
            and (
                not isinstance(name, str)
                or len(name) > 253
                or DNS_RE.fullmatch(name) is None
            )
        )
        or type(request.get("allNamespaces")) is not bool
    ):
        raise TransactionError("AUTHORIZATION_REQUEST_INVALID")
    controls = value.get("controls")
    if not isinstance(controls, list) or len(controls) != 3:
        raise TransactionError("AUTHORIZATION_CONTROLS_INVALID")
    normalized_controls: list[dict[str, object]] = []
    expected_controls = (
        ("builtin-authorizer", "ALLOWED"),
        ("flux-authorizer", "ALLOWED"),
        ("inert-denial", "DENIED"),
    )
    for control, (control_name, authorization) in zip(
        controls, expected_controls
    ):
        if not isinstance(control, Mapping):
            raise TransactionError("AUTHORIZATION_CONTROL_INVALID")
        exact_fields(
            control,
            {"name", "discovery", "authorization"},
            "AUTHORIZATION_CONTROL",
        )
        if (
            control.get("name") != control_name
            or control.get("authorization") != authorization
        ):
            raise TransactionError("AUTHORIZATION_CONTROL_INVALID")
        normalized_controls.append(
            {
                "name": control_name,
                "discovery": normalized_discovery(control.get("discovery")),
                "authorization": authorization,
            }
        )
    if (
        value.get("result") != "PASS"
        or value.get("authorization") not in {"ALLOWED", "DENIED"}
        or value.get("expected") != value.get("authorization")
    ):
        raise TransactionError("AUTHORIZATION_RECEIPT_INVALID")
    normalized = {
        "request": copy.deepcopy(dict(request)),
        "discovery": normalized_discovery(value.get("discovery")),
        "authorization": value.get("authorization"),
        "expected": value.get("expected"),
        "controls": normalized_controls,
        "result": "PASS",
    }
    if len(canonical_json(normalized)) > ORACLE_RECEIPT_MAX_BYTES:
        raise TransactionError("AUTHORIZATION_RECEIPT_TOO_LARGE")
    return normalized


def run_oracle_request(
    oracle: ModuleType,
    client: KubeClient,
    *,
    subject: str,
    verb: str,
    group: str,
    resource: str,
    expected: str,
    namespace: str | None = None,
    name: str | None = None,
    all_namespaces: bool = False,
) -> dict[str, object]:
    try:
        code, receipt = oracle.run_oracle(
            client,
            subject=subject,
            verb=verb,
            group=group,
            resource=resource,
            namespace=namespace,
            name=name,
            all_namespaces=all_namespaces,
            expected=expected,
        )
    except Exception as exc:
        raise TransactionError("AUTHORIZATION_ORACLE_UNRESOLVED") from exc
    if code != 0 or receipt.get("result") != "PASS" or receipt.get("authorization") != expected:
        raise TransactionError("AUTHORIZATION_ORACLE_MISMATCH")
    normalized = normalized_oracle_receipt(receipt)
    expected_subresource = resource.split("/", 1)[1] if "/" in resource else None
    if normalized["request"] != {
        "subject": subject,
        "verb": verb,
        "apiGroup": group,
        "resource": resource,
        "subresource": expected_subresource,
        "namespace": namespace,
        "name": name,
        "allNamespaces": all_namespaces,
    }:
        raise TransactionError("AUTHORIZATION_ORACLE_REQUEST_MISMATCH")
    return normalized


def run_oracle_row(
    oracle: ModuleType,
    client: KubeClient,
    row: tuple[str, str, str, str],
    expected: str,
) -> dict[str, object]:
    controller, verb, group, resource = row
    return run_oracle_request(
        oracle,
        client,
        subject=f"system:serviceaccount:flux-system:{controller}",
        verb=verb,
        group=group,
        resource=resource,
        all_namespaces=True,
        expected=expected,
    )


def tenant_authorization_phase(
    oracle: ModuleType, client: KubeClient, *, include_impersonation: bool
) -> list[dict[str, object]]:
    """Prove tenant-local Helm authority and its cross-tenant/write walls."""

    receipts: list[dict[str, object]] = []
    sites = ("naranjo-online", "lidersea-com")
    for namespace in sites:
        foreign = sites[1] if namespace == sites[0] else sites[0]
        tenant = f"system:serviceaccount:{namespace}:helm-reconciler"
        if include_impersonation:
            receipts.append(
                run_oracle_request(
                    oracle,
                    client,
                    subject="system:serviceaccount:flux-system:helm-controller",
                    verb="impersonate",
                    group="",
                    resource="serviceaccounts",
                    namespace=namespace,
                    name="helm-reconciler",
                    expected="ALLOWED",
                )
            )
        for group, resource in (("", "pods"), ("apps", "replicasets")):
            for verb in ("get", "list", "watch"):
                receipts.append(
                    run_oracle_request(
                        oracle,
                        client,
                        subject=tenant,
                        verb=verb,
                        group=group,
                        resource=resource,
                        namespace=namespace,
                        expected="ALLOWED",
                    )
                )
                receipts.append(
                    run_oracle_request(
                        oracle,
                        client,
                        subject=tenant,
                        verb=verb,
                        group=group,
                        resource=resource,
                        namespace=foreign,
                        expected="DENIED",
                    )
                )
        receipts.append(
            run_oracle_request(
                oracle,
                client,
                subject=tenant,
                verb="update",
                group="",
                resource="pods",
                namespace=namespace,
                expected="DENIED",
            )
        )
        receipts.append(
            run_oracle_request(
                oracle,
                client,
                subject=tenant,
                verb="delete",
                group="apps",
                resource="replicasets",
                namespace=namespace,
                expected="DENIED",
            )
        )
        receipts.append(
            run_oracle_request(
                oracle,
                client,
                subject=tenant,
                verb="get",
                group="",
                resource="pods",
                namespace=foreign,
                expected="DENIED",
            )
        )
        receipts.append(
            run_oracle_request(
                oracle,
                client,
                subject=tenant,
                verb="list",
                group="apps",
                resource="replicasets",
                namespace=foreign,
                expected="DENIED",
            )
        )
        if include_impersonation:
            default_tenant = f"system:serviceaccount:{namespace}:default"
            for verb, group, resource in (
                ("get", "", "secrets"),
                ("create", "", "secrets"),
                ("patch", "apps", "deployments"),
            ):
                receipts.append(
                    run_oracle_request(
                        oracle,
                        client,
                        subject=default_tenant,
                        verb=verb,
                        group=group,
                        resource=resource,
                        namespace=namespace,
                        expected="DENIED",
                    )
                )
    return receipts


def startup_authorization_phase(
    oracle: ModuleType, client: KubeClient
) -> list[dict[str, object]]:
    """Prove all 24 informers plus representative startup/runtime authority."""

    receipts: list[dict[str, object]] = []
    for controller, resources in INFORMER_RESOURCES.items():
        for group, resource in resources:
            for verb in ("list", "watch"):
                receipts.append(
                    run_oracle_request(
                        oracle,
                        client,
                        subject=f"system:serviceaccount:flux-system:{controller}",
                        verb=verb,
                        group=group,
                        resource=resource,
                        all_namespaces=True,
                        expected="ALLOWED",
                    )
                )
    if len(receipts) != 24:
        raise TransactionError("INFORMER_MATRIX_SIZE_INVALID")
    for controller in CONTROLLERS:
        subject = f"system:serviceaccount:flux-system:{controller}"
        for group, resource in (
            ("coordination.k8s.io", "leases"),
            ("", "configmaps"),
            ("", "events"),
        ):
            receipts.append(
                run_oracle_request(
                    oracle,
                    client,
                    subject=subject,
                    verb="create",
                    group=group,
                    resource=resource,
                    namespace="flux-system",
                    expected="ALLOWED",
                )
            )
        receipts.append(
            run_oracle_request(
                oracle,
                client,
                subject=subject,
                verb="list",
                group="",
                resource="namespaces",
                expected="ALLOWED",
            )
        )
        for resource in ("serviceaccounts", "configmaps"):
            receipts.append(
                run_oracle_request(
                    oracle,
                    client,
                    subject=subject,
                    verb="list",
                    group="",
                    resource=resource,
                    all_namespaces=True,
                    expected="ALLOWED",
                )
            )
    return receipts


def build_oracle_evidence(
    matrix_phase: str, receipts: list[dict[str, object]]
) -> dict[str, object]:
    expected_count = ORACLE_PHASE_COUNTS.get(matrix_phase)
    if expected_count is None:
        raise TransactionError("AUTHORIZATION_PHASE_INVALID")
    if len(receipts) != expected_count:
        raise TransactionError("AUTHORIZATION_RECEIPT_COUNT_INVALID")
    normalized = [normalized_oracle_receipt(receipt) for receipt in receipts]
    receipts_payload = canonical_json(normalized)
    if len(receipts_payload) > ORACLE_PHASE_MAX_BYTES:
        raise TransactionError("AUTHORIZATION_PHASE_TOO_LARGE")
    receipts_sha256 = sha256_bytes(receipts_payload)
    return {
        "matrixPhase": matrix_phase,
        "receiptCount": len(normalized),
        "receiptsSha256": receipts_sha256,
        "receipts": normalized,
    }


def authorization_phase(
    oracle: ModuleType, client: KubeClient, phase: str
) -> dict[str, object]:
    receipts: list[dict[str, object]] = []
    receipts.extend(startup_authorization_phase(oracle, client))
    for row in OWNED_ROWS:
        receipts.append(run_oracle_row(oracle, client, row, "ALLOWED"))
    for index, row in enumerate(CROSSING_ROWS):
        if phase == "pre-shared":
            expected = "ALLOWED"
        elif phase == "mixed":
            expected = "DENIED" if index < 7 else "ALLOWED"
        elif phase == "final":
            expected = "DENIED"
        else:
            raise TransactionError("AUTHORIZATION_PHASE_INVALID")
        receipts.append(run_oracle_row(oracle, client, row, expected))
    if phase in {"pre-shared", "final"}:
        receipts.extend(
            tenant_authorization_phase(
                oracle,
                client,
                include_impersonation=phase == "final",
            )
        )
    if phase == "final":
        for controller in CONTROLLERS:
            for verb in ("get", "list", "watch"):
                receipts.append(
                    run_oracle_row(
                        oracle,
                        client,
                        (controller, verb, "", "secrets"),
                        "DENIED",
                    )
                )
        kustomize_subject = (
            "system:serviceaccount:flux-system:kustomize-controller"
        )
        for verb, group, resource, namespace in (
            ("create", "apps", "deployments", "kube-system"),
            ("get", "", "secrets", "kube-system"),
            ("create", "rbac.authorization.k8s.io", "clusterrolebindings", None),
            ("create", "", "namespaces", None),
        ):
            receipts.append(
                run_oracle_request(
                    oracle,
                    client,
                    subject=kustomize_subject,
                    verb=verb,
                    group=group,
                    resource=resource,
                    namespace=namespace,
                    expected="DENIED",
                )
            )
        helm_subject = "system:serviceaccount:flux-system:helm-controller"
        for verb, group, resource, namespace, name in (
            ("create", "", "serviceaccounts/token", "kube-system", "default"),
            ("update", "", "secrets", "flux-system", None),
            ("impersonate", "", "serviceaccounts", "flux-system", "root-reconciler"),
        ):
            receipts.append(
                run_oracle_request(
                    oracle,
                    client,
                    subject=helm_subject,
                    verb=verb,
                    group=group,
                    resource=resource,
                    namespace=namespace,
                    name=name,
                    expected="DENIED",
                )
            )
    return build_oracle_evidence(phase, receipts)


def stable_baselines(plan: Mapping[str, object], client: KubeClient, *, allow_proof: bool = False) -> None:
    baselines = plan.get("baselines")
    if not isinstance(baselines, Mapping):
        raise TransactionError("PLAN_BASELINES_INVALID")
    current_flux = flux_snapshot(client)
    planned_flux = baselines.get("flux")
    if not allow_proof:
        if current_flux != planned_flux:
            raise TransactionError("FLUX_BASELINE_DRIFT")
    else:
        if not isinstance(planned_flux, Mapping):
            raise TransactionError("FLUX_BASELINE_INVALID")
        if current_flux.get("oci") != planned_flux.get("oci"):
            raise TransactionError("OCI_BASELINE_DRIFT")
        planned_helm = planned_flux.get("helm")
        current_helm = current_flux.get("helm")
        if not isinstance(planned_helm, Mapping) or not isinstance(current_helm, Mapping):
            raise TransactionError("HELM_BASELINE_INVALID")
        for identity, planned in planned_helm.items():
            current = current_helm.get(identity)
            if not isinstance(planned, Mapping) or not isinstance(current, Mapping):
                raise TransactionError("HELM_BASELINE_INVALID")
            for key in (
                "uid",
                "attemptedRevision",
                "attemptedRevisionDigest",
                "historyChartVersion",
                "historyConfigDigest",
                "specSha256",
                "semanticSha256",
            ):
                if current.get(key) != planned.get(key):
                    raise TransactionError("HELM_FINAL_DRIFT")
            if not isinstance(current.get("generation"), int) or current["generation"] < planned.get("generation", 0):
                raise TransactionError("HELM_GENERATION_REGRESSED")
    planned_workloads = baselines.get("workloads")
    current_workloads = workload_snapshot(client)
    validate_helm_workload_inventory(current_flux, current_workloads)
    if not allow_proof and current_workloads != planned_workloads:
        raise TransactionError("WORKLOAD_BASELINE_DRIFT")
    if allow_proof:
        if not isinstance(planned_workloads, Mapping):
            raise TransactionError("WORKLOAD_BASELINE_INVALID")
        for identity, planned in planned_workloads.items():
            current = current_workloads.get(identity)
            if not isinstance(planned, Mapping) or not isinstance(current, Mapping):
                raise TransactionError("WORKLOAD_BASELINE_INVALID")
            if (
                current.get("uid") != planned.get("uid")
                or current.get("replicas") != planned.get("replicas")
                or current.get("templateSha256") != planned.get("templateSha256")
                or current.get("semanticSha256") != planned.get("semanticSha256")
                or current.get("pods") != planned.get("pods")
                or current.get("ownedObjects") != planned.get("ownedObjects")
            ):
                raise TransactionError("WORKLOAD_IDENTITY_DRIFT")
    if public_health() != baselines.get("publicSites"):
        raise TransactionError("PUBLIC_SITE_BASELINE_DRIFT")


def verify_controller_phase(
    plan: Mapping[str, object],
    client: KubeClient,
    changed: frozenset[str],
    journal: Journal | None = None,
) -> dict[str, object]:
    if not changed.issubset({"kustomize-controller", "helm-controller"}):
        raise TransactionError("CONTROLLER_PHASE_SET_INVALID")
    baselines = plan.get("baselines")
    planned = baselines.get("controllers") if isinstance(baselines, Mapping) else None
    targets = plan.get("targets")
    if not isinstance(planned, Mapping) or not isinstance(targets, list):
        raise TransactionError("CONTROLLER_PHASE_PLAN_INVALID")
    desired_by_name = {
        str(item.get("name")): item
        for item in targets
        if isinstance(item, Mapping) and item.get("phase") == "watchers"
    }
    current = controller_snapshot(client)
    stable_keys = CONTROLLER_RUNTIME_FIELDS
    for name in CONTROLLERS:
        baseline = planned.get(name)
        observed = current.get(name)
        if not isinstance(baseline, Mapping) or not isinstance(observed, Mapping):
            raise TransactionError("CONTROLLER_PHASE_SNAPSHOT_INVALID")
        if name not in changed:
            if any(observed.get(key) != baseline.get(key) for key in stable_keys):
                raise TransactionError("CONTROLLER_UNEXPECTED_DRIFT")
            continue
        target = desired_by_name.get(name)
        operations = journal.document.get("operations") if journal is not None else None
        record = (
            operations.get(target.get("id"))
            if isinstance(target, Mapping) and isinstance(operations, Mapping)
            else None
        )
        rollout = record.get("rolloutSnapshot") if isinstance(record, Mapping) else None
        observed_rollout = {
            key: copy.deepcopy(observed.get(key))
            for key in CONTROLLER_RUNTIME_FIELDS
        }
        if (
            not isinstance(target, Mapping)
            or not isinstance(rollout, Mapping)
            or observed_rollout != dict(rollout)
            or observed.get("uid") != baseline.get("uid")
            or observed.get("image") != baseline.get("image")
            or observed.get("semanticSha256") != target.get("desiredSha256")
            or observed.get("podUid") == baseline.get("podUid")
            or observed.get("podRestarts") != 0
            or not isinstance(observed.get("generation"), int)
            or not isinstance(baseline.get("generation"), int)
            or observed["generation"] <= baseline["generation"]
        ):
            raise TransactionError("CONTROLLER_EXPECTED_ROLLOUT_INVALID")
    return current


def planned_site_chart_identity(
    plan: Mapping[str, object], namespace: str, name: str
) -> tuple[str, str, Mapping[str, object]]:
    """Recover one exact OCI-to-Helm identity from the immutable plan baseline."""

    if (namespace, name) not in SITE_RELEASES:
        raise TransactionError("PLAN_SITE_CHART_BINDING_INVALID")
    baselines = plan.get("baselines")
    planned_flux = baselines.get("flux") if isinstance(baselines, Mapping) else None
    planned_helm = planned_flux.get("helm") if isinstance(planned_flux, Mapping) else None
    planned_oci = planned_flux.get("oci") if isinstance(planned_flux, Mapping) else None
    planned_release = (
        planned_helm.get(f"{namespace}/{name}")
        if isinstance(planned_helm, Mapping)
        else None
    )
    planned_source = (
        planned_oci.get(f"{namespace}/{name}-chart")
        if isinstance(planned_oci, Mapping)
        else None
    )
    if not isinstance(planned_release, Mapping) or not isinstance(
        planned_source, Mapping
    ):
        raise TransactionError("PLAN_SITE_CHART_BINDING_INVALID")
    try:
        version, upstream_digest = parse_site_oci_revision(
            planned_source.get("revision")
        )
        if (
            planned_source.get("chartVersion") != version
            or planned_source.get("upstreamDigest") != upstream_digest
        ):
            raise TransactionError("PLAN_SITE_CHART_BINDING_INVALID")
        version, upstream_digest = validate_site_chart_snapshot_binding(
            planned_release,
            version,
            upstream_digest,
            "PLAN_SITE_CHART_BINDING_INVALID",
        )
    except TransactionError as exc:
        raise TransactionError("PLAN_SITE_CHART_BINDING_INVALID") from exc
    return version, upstream_digest, planned_release


def build_helm_proof_spec(
    pre_spec: object, plan_sha256: object
) -> dict[str, object]:
    """Construct the sole temporary Helm proof spec from immutable inputs."""

    if not isinstance(pre_spec, Mapping):
        raise TransactionError("HELM_PROOF_SPEC_INVALID")
    if (
        not isinstance(plan_sha256, str)
        or SHA256_RE.fullmatch(plan_sha256) is None
    ):
        raise TransactionError("HELM_PROOF_PLAN_SHA256_INVALID")
    changed_spec = copy.deepcopy(dict(pre_spec))
    if "commonMetadata" in changed_spec:
        common = changed_spec["commonMetadata"]
        if not isinstance(common, Mapping):
            raise TransactionError("HELM_PROOF_COMMON_METADATA_INVALID")
        changed_common = copy.deepcopy(dict(common))
    else:
        changed_common = {}
    if "annotations" in changed_common:
        annotations = changed_common["annotations"]
        if not isinstance(annotations, Mapping):
            raise TransactionError("HELM_PROOF_ANNOTATIONS_INVALID")
        changed_annotations = copy.deepcopy(dict(annotations))
    else:
        changed_annotations = {}
    if PROOF_ANNOTATION in changed_annotations:
        raise TransactionError("HELM_PROOF_ANNOTATION_COLLISION")
    changed_annotations[PROOF_ANNOTATION] = plan_sha256
    changed_common["annotations"] = changed_annotations
    changed_spec["commonMetadata"] = changed_common
    return changed_spec


def helm_proof(
    client: KubeClient,
    plan: Mapping[str, object],
    plan_sha256: str,
    journal: Journal,
) -> None:
    proof = plan.get("temporaryProof")
    if not isinstance(proof, Mapping):
        raise TransactionError("HELM_PROOF_PLAN_INVALID")
    if proof != {
        "identity": {
            "apiVersion": "helm.toolkit.fluxcd.io/v2",
            "kind": "HelmRelease",
            "namespace": "naranjo-online",
            "name": "naranjo-online",
        },
        "annotationKey": PROOF_ANNOTATION,
    }:
        raise TransactionError("HELM_PROOF_IDENTITY_INVALID")
    try:
        version, upstream_digest, planned_release = planned_site_chart_identity(
            plan, "naranjo-online", "naranjo-online"
        )
    except TransactionError as exc:
        raise TransactionError("HELM_PROOF_BASELINE_INVALID") from exc
    _collection, url = resource_urls("HelmRelease", "naranjo-online", "naranjo-online")
    current = client.get(url)
    pre_snapshot = validate_site_helm_release(
        current,
        "naranjo-online",
        "naranjo-online",
        version,
        upstream_digest,
    )
    if pre_snapshot != dict(planned_release):
        raise TransactionError("HELM_PROOF_PLAN_PRESTATE_DRIFT")
    uid = str(pre_snapshot["uid"])
    pre_resource_version = str(pre_snapshot["resourceVersion"])
    spec = current.get("spec")
    if not isinstance(spec, Mapping):
        raise TransactionError("HELM_PROOF_SPEC_INVALID")
    pre_spec = copy.deepcopy(dict(spec))
    mutated_spec = build_helm_proof_spec(pre_spec, plan_sha256)
    pre_generation = pre_snapshot["generation"]
    pre_history_revision = pre_snapshot["historyRevision"]
    if not isinstance(pre_generation, int) or not isinstance(
        pre_history_revision, int
    ):
        raise TransactionError("HELM_PROOF_PRESTATE_INVALID")
    changed = writable_from_live(current)
    changed["spec"] = copy.deepcopy(mutated_spec)
    journal.document["helmProof"] = {
        "state": "add-intent",
        "uid": uid,
        "preResourceVersion": pre_resource_version,
        "preGeneration": pre_generation,
        "preHistoryRevision": pre_history_revision,
        "preSnapshot": copy.deepcopy(pre_snapshot),
        "namespace": "naranjo-online",
        "name": "naranjo-online",
        "version": version,
        "upstreamDigest": upstream_digest,
        "preSpec": pre_spec,
        "mutatedSpec": mutated_spec,
        "mutatedSpecSha256": sha256_bytes(canonical_json(mutated_spec)),
    }
    journal.write()
    add_signals = block_transaction_signals()
    try:
        response = client.put(url, changed)
        if object_is_terminating(response):
            raise RecoveryRequired("HELM_PROOF_RESPONSE_TERMINATING")
        response_uid, response_rv = live_identity(response)
        response_generation = response.get("metadata", {}).get("generation")
        if (
            response_uid != uid
            or int(response_rv) <= int(pre_resource_version)
            or not isinstance(response_generation, int)
            or response_generation <= pre_generation
            or response.get("spec") != mutated_spec
            or semantic_hash(response) != semantic_hash(changed)
        ):
            raise RecoveryRequired("HELM_PROOF_RESPONSE_INVALID")
        journal.document["helmProof"]["state"] = "added"  # type: ignore[index]
        journal.document["helmProof"]["addedResourceVersion"] = response_rv  # type: ignore[index]
        journal.document["helmProof"]["addedGeneration"] = response_generation  # type: ignore[index]
        journal.write()
    finally:
        restore_transaction_signals(add_signals)
    upgraded = wait_helm(
        client,
        url,
        uid,
        "naranjo-online",
        "naranjo-online",
        version,
        upstream_digest,
        pre_generation,
        pre_history_revision,
        plan_sha256,
    )
    journal.document["helmProof"]["upgradedGeneration"] = upgraded["generation"]  # type: ignore[index]
    journal.document["helmProof"]["upgradedSnapshot"] = upgraded  # type: ignore[index]
    active_inventory = validate_active_helm_proof_inventory(
        client, plan, plan_sha256, upgraded
    )
    journal.document["helmProof"]["activeInventory"] = active_inventory  # type: ignore[index]
    journal.write()
    restore_live = client.get(url)
    if object_is_terminating(restore_live):
        raise RecoveryRequired("HELM_PROOF_RESTORE_OBJECT_TERMINATING")
    restore_uid, restore_rv = live_identity(restore_live)
    restore_generation = restore_live.get("metadata", {}).get("generation")
    if restore_uid != uid or restore_live.get("spec") != mutated_spec:
        raise RecoveryRequired("HELM_PROOF_CONCURRENT_SPEC_DRIFT")
    if not isinstance(restore_generation, int):
        raise RecoveryRequired("HELM_PROOF_RESTORE_GENERATION_INVALID")
    journal.document["helmProof"]["state"] = "restore-intent"  # type: ignore[index]
    journal.document["helmProof"]["restoreResourceVersion"] = restore_rv  # type: ignore[index]
    journal.write()
    restore = writable_from_live(restore_live)
    restore["spec"] = pre_spec
    restore_signals = block_transaction_signals()
    try:
        restored_response = client.put(url, restore)
        if object_is_terminating(restored_response):
            raise RecoveryRequired("HELM_PROOF_RESTORE_RESPONSE_TERMINATING")
        restored_uid, restored_rv = live_identity(restored_response)
        restored_response_generation = restored_response.get("metadata", {}).get(
            "generation"
        )
        if (
            restored_uid != uid
            or int(restored_rv) <= int(restore_rv)
            or not isinstance(restored_response_generation, int)
            or restored_response_generation <= restore_generation
            or restored_response.get("spec") != pre_spec
            or semantic_hash(restored_response) != semantic_hash(restore)
        ):
            raise RecoveryRequired("HELM_PROOF_RESTORE_RESPONSE_INVALID")
        journal.document["helmProof"].update(  # type: ignore[union-attr]
            {
                "state": "restore-accepted",
                "restoredResourceVersion": restored_rv,
                "restoredResponseGeneration": restored_response_generation,
            }
        )
        journal.write()
    finally:
        restore_transaction_signals(restore_signals)
    restored = wait_helm(
        client,
        url,
        uid,
        "naranjo-online",
        "naranjo-online",
        version,
        upstream_digest,
        int(upgraded["generation"]),
        int(upgraded["historyRevision"]),
        None,
    )
    final_live = client.get(url)
    final_spec = final_live.get("spec")
    if object_is_terminating(final_live) or final_spec != pre_spec:
        raise RecoveryRequired("HELM_PROOF_SPEC_NOT_RESTORED")
    restored_inventory = validate_restored_helm_proof_inventory(
        client, plan, restored
    )
    journal.document["helmProof"].update(  # type: ignore[union-attr]
        {
            "state": "restored",
            "restoredGeneration": restored["generation"],
            "restoredHistoryRevision": restored["historyRevision"],
            "restoredSnapshot": restored,
            "restoredInventory": restored_inventory,
        }
    )
    journal.write()


def wait_helm(
    client: KubeClient,
    url: str,
    uid: str,
    namespace: str,
    name: str,
    version: str,
    upstream_digest: str,
    prior_generation: int,
    prior_history_revision: int,
    expected_annotation: str | None,
) -> dict[str, object]:
    deadline = time.monotonic() + HELM_TIMEOUT_SECONDS
    last_error: TransactionError | None = None
    while time.monotonic() < deadline:
        try:
            current = client.get(url)
            snapshot = validate_site_helm_release(
                current, namespace, name, version, upstream_digest
            )
            spec = current.get("spec")
            if not isinstance(spec, Mapping):
                raise TransactionError("HELM_PROOF_LIVE_INVALID")
            if (
                snapshot.get("uid") != uid
                or not isinstance(snapshot.get("generation"), int)
                or snapshot["generation"] <= prior_generation
                or not isinstance(snapshot.get("historyRevision"), int)
                or snapshot["historyRevision"] <= prior_history_revision
                or snapshot.get("readyReason") != "UpgradeSucceeded"
                or snapshot.get("attemptedReleaseAction") != "upgrade"
                or snapshot.get("historyAction") not in (None, "upgrade")
            ):
                raise TransactionError("HELM_PROOF_NOT_CONVERGED")
            annotations = spec.get("commonMetadata")
            annotations = annotations.get("annotations") if isinstance(annotations, Mapping) else None
            if expected_annotation is not None:
                if not isinstance(annotations, Mapping) or annotations.get(PROOF_ANNOTATION) != expected_annotation:
                    raise TransactionError("HELM_PROOF_ANNOTATION_NOT_APPLIED")
            elif isinstance(annotations, Mapping) and PROOF_ANNOTATION in annotations:
                raise TransactionError("HELM_PROOF_ANNOTATION_NOT_RESTORED")
            return snapshot
        except TransactionError as exc:
            last_error = exc
            time.sleep(2)
    raise TransactionError("HELM_PROOF_TIMEOUT") from last_error


def wait_helm_restored(
    client: KubeClient,
    url: str,
    uid: str,
    expected_spec: Mapping[str, object],
    namespace: str,
    name: str,
    version: str,
    upstream_digest: str,
    prior_generation: int,
    prior_history_revision: int,
    *,
    require_history_advance: bool,
) -> None:
    deadline = time.monotonic() + HELM_TIMEOUT_SECONDS
    last_error: TransactionError | None = None
    while time.monotonic() < deadline:
        try:
            current = client.get(url)
            snapshot = validate_site_helm_release(
                current, namespace, name, version, upstream_digest
            )
            history_revision = snapshot.get("historyRevision")
            if (
                snapshot.get("uid") != uid
                or current.get("spec") != expected_spec
                or not isinstance(snapshot.get("generation"), int)
                or snapshot["generation"] <= prior_generation
                or not isinstance(history_revision, int)
                or (
                    require_history_advance
                    and history_revision <= prior_history_revision
                )
                or (
                    not require_history_advance
                    and history_revision < prior_history_revision
                )
                or (
                    require_history_advance
                    and snapshot.get("readyReason") != "UpgradeSucceeded"
                )
                or (
                    require_history_advance
                    and snapshot.get("attemptedReleaseAction") != "upgrade"
                )
                or (
                    require_history_advance
                    and snapshot.get("historyAction") not in (None, "upgrade")
                )
            ):
                raise TransactionError("HELM_RESTORE_NOT_CONVERGED")
            return
        except TransactionError as exc:
            last_error = exc
            time.sleep(2)
    raise TransactionError("HELM_RESTORE_TIMEOUT") from last_error


def cleanup_transaction_annotations(client: KubeClient, plan: Mapping[str, object], journal: Journal) -> None:
    operations = journal.document.get("operations")
    targets = plan.get("targets")
    if not isinstance(operations, Mapping) or not isinstance(targets, list):
        raise TransactionError("CLEANUP_STATE_INVALID")
    target_by_id = {item["id"]: item for item in targets if isinstance(item, Mapping)}
    for operation_id, record in operations.items():
        if not isinstance(record, Mapping) or record.get("state") != "committed":
            continue
        target = target_by_id.get(operation_id)
        if not isinstance(target, Mapping) or target.get("action") in {"delete", "noop"}:
            continue
        url = str(target["url"])
        live = client.get(url)
        if object_is_terminating(live):
            raise RecoveryRequired("ANNOTATION_CLEANUP_OBJECT_TERMINATING")
        uid, _ = live_identity(live)
        if uid != record.get("uid") or semantic_hash(live) != target.get("desiredSha256"):
            raise RecoveryRequired("ANNOTATION_CLEANUP_DRIFT")
        annotations = live.get("metadata", {}).get("annotations")
        if not isinstance(annotations, Mapping) or annotations.get(TRANSACTION_ANNOTATION) != journal.document["attemptId"]:
            raise RecoveryRequired("TRANSACTION_ANNOTATION_MISSING")
        body = writable_from_live(live)
        body = remove_transaction_annotation(body)
        result = client.put(url, body)
        if object_is_terminating(result) or semantic_hash(result) != target.get("desiredSha256"):
            raise RecoveryRequired("ANNOTATION_CLEANUP_FAILED")
        mutable = dict(record)
        mutable["state"] = "verified"
        mutable["resourceVersion"] = live_identity(result)[1]
        operations[operation_id] = mutable  # type: ignore[index]
        journal.write()


def verify_converged(
    client: KubeClient,
    plan: Mapping[str, object],
    journal: Journal,
    oracle: ModuleType,
    *,
    after_proof: bool,
) -> dict[str, object]:
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise TransactionError("PLAN_TARGETS_INVALID")
    operations = journal.document.get("operations")
    if not isinstance(operations, Mapping):
        raise TransactionError("JOURNAL_OPERATIONS_INVALID")
    for target in targets:
        if not isinstance(target, Mapping):
            raise TransactionError("PLAN_TARGET_INVALID")
        live = client.get_optional(str(target["url"]))
        if target.get("action") == "delete":
            if live is not None:
                raise TransactionError("BROAD_BINDING_STILL_PRESENT")
        else:
            if (
                live is None
                or object_is_terminating(live)
                or semantic_hash(live) != target.get("desiredSha256")
            ):
                raise TransactionError("TARGET_NOT_CONVERGED")
            prestate = target.get("prestate")
            record = operations.get(target.get("id"))
            if not isinstance(prestate, Mapping) or not isinstance(record, Mapping):
                raise TransactionError("TARGET_IDENTITY_EVIDENCE_INVALID")
            uid, _ = live_identity(live)
            expected_uid = (
                prestate.get("uid")
                if prestate.get("present") is True
                else record.get("uid")
            )
            if uid != expected_uid or record.get("state") not in {
                "committed",
                "verified",
            }:
                raise TransactionError("TARGET_UID_NOT_CONVERGED")
    graph = binding_graph_final(client)
    verify_expected_binding_graph(plan, graph)
    oracle_evidence = authorization_phase(oracle, client, "final")
    stable_baselines(plan, client, allow_proof=after_proof)
    changed_watchers = frozenset(
        str(target.get("name"))
        for target in targets
        if isinstance(target, Mapping)
        and target.get("phase") == "watchers"
        and target.get("action") != "noop"
    )
    controllers = verify_controller_phase(
        plan,
        client,
        changed_watchers,
        journal,
    )
    for name in ("kustomize-controller", "helm-controller"):
        args = controllers[name]["args"]  # type: ignore[index]
        if args.count("--feature-gates=DisableConfigWatchers=true") != 1:
            raise TransactionError("WATCHER_GATE_NOT_CONVERGED")
        if controllers[name]["podRestarts"] != 0:  # type: ignore[index]
            raise TransactionError("CONVERGED_CONTROLLER_RESTARTED")
    return {"bindingGraph": graph, "authorizationEvidence": oracle_evidence}


def capture_terminal_target_inventory(
    client: KubeClient,
    plan: Mapping[str, object],
    journal: Journal,
    terminal_state: str,
) -> list[dict[str, object]]:
    if terminal_state not in {"committed", "rolled-back"}:
        raise TransactionError("TERMINAL_INVENTORY_STATE_INVALID")
    targets = plan.get("targets")
    operations = journal.document.get("operations")
    if not isinstance(targets, list) or not isinstance(operations, Mapping):
        raise TransactionError("TERMINAL_INVENTORY_INPUT_INVALID")
    rows: list[dict[str, object]] = []
    for target in targets:
        if not isinstance(target, Mapping):
            raise TransactionError("TERMINAL_INVENTORY_TARGET_INVALID")
        operation_id = target.get("id")
        record = operations.get(operation_id)
        prestate = target.get("prestate")
        if not isinstance(prestate, Mapping):
            raise TransactionError("TERMINAL_INVENTORY_PRESTATE_INVALID")
        live = client.get_optional(str(target.get("url")))
        if terminal_state == "committed" and target.get("action") == "delete":
            if live is not None:
                raise TransactionError("TERMINAL_DELETION_NOT_ABSENT")
            rows.append({"id": operation_id, "present": False})
            continue
        if terminal_state == "rolled-back" and prestate.get("present") is False:
            if live is not None:
                raise TransactionError("TERMINAL_ROLLBACK_RESIDUE")
            rows.append({"id": operation_id, "present": False})
            continue
        if live is None or object_is_terminating(live):
            raise TransactionError("TERMINAL_TARGET_ABSENT_OR_TERMINATING")
        uid, resource_version = live_identity(live)
        semantic_sha256 = semantic_hash(live)
        if terminal_state == "committed":
            if (
                not isinstance(record, Mapping)
                or record.get("state") not in {"committed", "verified"}
                or semantic_sha256 != target.get("desiredSha256")
            ):
                raise TransactionError("TERMINAL_COMMITTED_TARGET_DRIFT")
            expected_uid = (
                prestate.get("uid")
                if prestate.get("present") is True
                else record.get("uid")
            )
            if uid != expected_uid:
                raise TransactionError("TERMINAL_COMMITTED_UID_DRIFT")
        else:
            if semantic_sha256 != prestate.get("semanticSha256"):
                raise TransactionError("TERMINAL_ROLLBACK_SEMANTIC_DRIFT")
            if target.get("action") != "delete" and uid != prestate.get("uid"):
                raise TransactionError("TERMINAL_ROLLBACK_UID_DRIFT")
            if target.get("action") == "delete" and isinstance(record, Mapping):
                allowed_uids = {
                    value
                    for value in (prestate.get("uid"), record.get("restoredUid"))
                    if isinstance(value, str)
                }
                if uid not in allowed_uids:
                    raise TransactionError("TERMINAL_ROLLBACK_UID_DRIFT")
        rows.append(
            {
                "id": operation_id,
                "present": True,
                "uid": uid,
                "resourceVersion": resource_version,
                "semanticSha256": semantic_sha256,
            }
        )
    return rows


def verify_expected_binding_graph(
    plan: Mapping[str, object], graph: Mapping[str, object]
) -> None:
    """Prove the binding graph changed only at reviewed target identities."""

    baselines = plan.get("baselines")
    baseline_graph = baselines.get("bindingGraph") if isinstance(baselines, Mapping) else None
    baseline_rows = baseline_graph.get("rows") if isinstance(baseline_graph, Mapping) else None
    actual_rows = graph.get("rows")
    targets = plan.get("targets")
    if not isinstance(baseline_rows, list) or not isinstance(actual_rows, list) or not isinstance(targets, list):
        raise TransactionError("BINDING_GRAPH_PLAN_INVALID")

    def key(row: Mapping[str, object]) -> tuple[object, object, object]:
        return row.get("kind"), row.get("namespace"), row.get("name")

    expected: dict[tuple[object, object, object], tuple[str, object | None]] = {}
    for row in baseline_rows:
        if not isinstance(row, Mapping):
            raise TransactionError("BINDING_GRAPH_BASELINE_INVALID")
        identity = key(row)
        if identity == ("ClusterRoleBinding", None, BROAD_NAME):
            continue
        expected[identity] = (str(row.get("semanticSha256")), row.get("uid"))
    for target in targets:
        if not isinstance(target, Mapping) or target.get("kind") not in {
            "RoleBinding",
            "ClusterRoleBinding",
        }:
            continue
        identity = (target.get("kind"), target.get("namespace"), target.get("name"))
        if target.get("action") == "delete":
            expected.pop(identity, None)
        else:
            expected[identity] = (str(target.get("desiredSha256")), None)
    actual_by_id = {
        key(row): row for row in actual_rows if isinstance(row, Mapping)
    }
    if set(actual_by_id) != set(expected):
        raise TransactionError("BINDING_GRAPH_INVENTORY_DRIFT")
    for identity, (digest, stable_uid) in expected.items():
        row = actual_by_id[identity]
        if row.get("semanticSha256") != digest:
            raise TransactionError("BINDING_GRAPH_SEMANTIC_DRIFT")
        if stable_uid is not None and row.get("uid") != stable_uid:
            raise TransactionError("BINDING_GRAPH_UID_DRIFT")


def binding_graph_final(client: KubeClient) -> dict[str, object]:
    graph = binding_graph_without_broad_requirement(client)
    rows = graph["rows"]
    broad = [
        row
        for row in rows
        if row["kind"] == "ClusterRoleBinding"
        and isinstance(row.get("roleRef"), Mapping)
        and row["roleRef"].get("name") == "cluster-admin"
    ]
    if broad:
        raise TransactionError("CONTROLLER_CLUSTER_ADMIN_REMAINS")
    return graph


def binding_graph_without_broad_requirement(client: KubeClient) -> dict[str, object]:
    cluster = collection_items(
        client, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
    )
    namespaced = collection_items(
        client, "/apis/rbac.authorization.k8s.io/v1/rolebindings"
    )
    rows: list[dict[str, object]] = []
    for item in cluster + namespaced:
        row = binding_graph_row(item)
        if row is not None:
            rows.append(row)
    rows.sort(key=lambda row: (str(row["kind"]), str(row["namespace"]), str(row["name"])))
    return {"rows": rows, "sha256": sha256_bytes(canonical_json(rows))}


def restore_object(client: KubeClient, target: Mapping[str, object], journal: Journal) -> None:
    prestate = target.get("prestate")
    if not isinstance(prestate, Mapping):
        raise RecoveryRequired("ROLLBACK_PRESTATE_INVALID")
    url = str(target["url"])
    live = client.get_optional(url)
    action = target.get("action")
    operations = journal.document.get("operations")
    record = operations.get(target["id"]) if isinstance(operations, MutableMapping) else None
    if not isinstance(record, Mapping):
        raise RecoveryRequired("ROLLBACK_OPERATION_RECORD_MISSING")
    if action == "delete":
        attempt_id = str(journal.document.get("attemptId"))
        accepted_delete = (
            record.get("deleteState") == "delete-accepted"
            and record.get("state") in {"intent", "committed", "verified"}
        )
        if live is not None:
            uid, resource_version = live_identity(live)
            if semantic_hash(live) != prestate.get("semanticSha256"):
                raise RecoveryRequired("ROLLBACK_DELETED_OBJECT_DRIFT")
            marker_matches = has_transaction_marker(live, attempt_id)
            annotations = live.get("metadata", {}).get("annotations")
            marker_present = (
                isinstance(annotations, Mapping)
                and TRANSACTION_ANNOTATION in annotations
            )
            if (
                uid == prestate.get("uid")
                and not marker_present
                and record.get("deleteState") == "mark-intent"
            ):
                if resource_version != prestate.get("resourceVersion"):
                    raise RecoveryRequired("ROLLBACK_DELETE_MARK_FENCE_DRIFT")
                request = with_transaction_annotation(
                    writable_from_live(live), attempt_id
                )
                fence_signals = block_transaction_signals()
                try:
                    try:
                        fenced = client.put_fence(url, request)
                    except TransactionError as exc:
                        raise RecoveryRequired(
                            "ROLLBACK_DELETE_MARK_FENCE_TRANSPORT_UNRESOLVED"
                        ) from exc
                    if fenced is not None and (
                        live_identity(fenced)[0] != uid
                        or semantic_hash(fenced) != prestate.get("semanticSha256")
                        or not has_transaction_marker(fenced, attempt_id)
                    ):
                        raise RecoveryRequired(
                            "ROLLBACK_DELETE_MARK_FENCE_RESPONSE_INVALID"
                        )
                    live = client.get_optional(url)
                finally:
                    restore_transaction_signals(fence_signals)
                if (
                    live is None
                    or object_is_terminating(live)
                    or live_identity(live)[0] != uid
                    or semantic_hash(live) != prestate.get("semanticSha256")
                    or not has_transaction_marker(live, attempt_id)
                ):
                    raise RecoveryRequired("ROLLBACK_DELETE_MARK_FENCE_UNRESOLVED")
                uid, resource_version = live_identity(live)
                marker_matches = True
                marker_present = True
            if object_is_terminating(live):
                if (
                    uid != prestate.get("uid")
                    or not marker_matches
                    or not accepted_delete
                ):
                    raise RecoveryRequired("ROLLBACK_TERMINATING_DELETE_UNATTRIBUTED")
                wait_object_absent(
                    client,
                    url,
                    expected_uid=uid,
                    expected_semantic_sha256=str(prestate["semanticSha256"]),
                    attempt_id=attempt_id,
                )
                live = None
            elif uid == prestate.get("uid"):
                rollback_state = record.get("rollbackState")
                if marker_matches:
                    if rollback_state not in {None, "marker-cleanup-intent"}:
                        raise RecoveryRequired("ROLLBACK_MARKER_STATE_INVALID")
                    if rollback_state is None:
                        mutable = dict(record)
                        mutable["rollbackState"] = "marker-cleanup-intent"
                        operations[target["id"]] = mutable
                        journal.write()
                        record = mutable
                    body = remove_transaction_annotation(writable_from_live(live))
                    cleanup_signals = block_transaction_signals()
                    try:
                        response = client.put(url, body)
                        response_uid, response_rv = live_identity(response)
                        if (
                            response_uid != uid
                            or response_rv == resource_version
                            or object_is_terminating(response)
                            or semantic_hash(response)
                            != prestate.get("semanticSha256")
                            or has_transaction_marker(response, attempt_id)
                        ):
                            raise RecoveryRequired(
                                "ROLLBACK_MARKER_CLEANUP_INVALID"
                            )
                        mutable = dict(record)
                        mutable.update(
                            {
                                "rollbackState": "marker-cleaned",
                                "restoredUid": response_uid,
                                "restoredResourceVersion": response_rv,
                            }
                        )
                        operations[target["id"]] = mutable
                        journal.write()
                    finally:
                        restore_transaction_signals(cleanup_signals)
                    return
                if marker_present:
                    raise RecoveryRequired("ROLLBACK_MARKER_COLLISION")
                if rollback_state == "marker-cleanup-intent":
                    mutable = dict(record)
                    mutable.update(
                        {
                            "rollbackState": "marker-cleaned",
                            "restoredUid": uid,
                            "restoredResourceVersion": resource_version,
                        }
                    )
                    operations[target["id"]] = mutable
                    journal.write()
                    return
                if rollback_state == "marker-cleaned":
                    return
                if record.get("deleteState") not in {None, "mark-intent"}:
                    raise RecoveryRequired("ROLLBACK_DELETE_MARKER_DISAPPEARED")
                return
            else:
                rollback_state = record.get("rollbackState")
                if rollback_state == "restore-intent" and marker_matches:
                    mutable = dict(record)
                    mutable.update(
                        {
                            "rollbackState": "restored",
                            "restoredUid": uid,
                            "restoredResourceVersion": resource_version,
                        }
                    )
                    operations[target["id"]] = mutable
                    journal.write()
                    return
                if rollback_state in {"restored", "verified"} and uid == record.get(
                    "restoredUid"
                ):
                    return
                raise RecoveryRequired("ROLLBACK_DELETED_OBJECT_ATTRIBUTION_FAILED")
        if live is None:
            if not accepted_delete:
                raise RecoveryRequired("ROLLBACK_DELETE_ABSENCE_UNATTRIBUTED")
            rollback = prestate.get("rollbackObject")
            if not isinstance(rollback, Mapping):
                raise RecoveryRequired("ROLLBACK_DELETED_PRESTATE_INVALID")
            body = semantic_object(rollback)
            metadata = body.get("metadata")
            if isinstance(metadata, MutableMapping):
                metadata.pop("uid", None)
                metadata.pop("resourceVersion", None)
            body = with_transaction_annotation(body, attempt_id)
            mutable = dict(record)
            mutable["rollbackState"] = "restore-intent"
            operations[target["id"]] = mutable
            journal.write()
            kind, namespace, name = metadata_identity(body)
            collection, _ = resource_urls(kind, namespace, name)
            restore_signals = block_transaction_signals()
            try:
                restored = client.post_fence(collection, body)
                if restored is None:
                    restored = client.get_optional(url)
                if (
                    restored is None
                    or object_is_terminating(restored)
                    or semantic_hash(restored) != prestate.get("semanticSha256")
                    or not has_transaction_marker(restored, attempt_id)
                ):
                    raise RecoveryRequired("ROLLBACK_DELETED_RESTORE_INVALID")
                restored_uid, restored_rv = live_identity(restored)
                mutable.update(
                    {
                        "rollbackState": "restored",
                        "restoredUid": restored_uid,
                        "restoredResourceVersion": restored_rv,
                    }
                )
                operations[target["id"]] = mutable
                journal.write()
            finally:
                restore_transaction_signals(restore_signals)
            return
    if prestate.get("present") is False:
        if live is None:
            if record.get("state") != "intent":
                return
            desired = target.get("desired")
            if not isinstance(desired, Mapping):
                raise RecoveryRequired("ROLLBACK_CREATE_FENCE_DESIRED_INVALID")
            kind, namespace, name = metadata_identity(desired)
            collection, _ = resource_urls(kind, namespace, name)
            request = with_transaction_annotation(
                desired, str(journal.document.get("attemptId"))
            )
            fence_signals = block_transaction_signals()
            try:
                try:
                    fenced = client.post_fence(collection, request)
                except TransactionError as exc:
                    raise RecoveryRequired(
                        "ROLLBACK_CREATE_FENCE_TRANSPORT_UNRESOLVED"
                    ) from exc
                if fenced is not None and (
                    metadata_identity(fenced) != (kind, namespace, name)
                    or semantic_hash(fenced) != target.get("desiredSha256")
                    or not has_transaction_marker(
                        fenced, str(journal.document.get("attemptId"))
                    )
                ):
                    raise RecoveryRequired("ROLLBACK_CREATE_FENCE_RESPONSE_INVALID")
                live = client.get_optional(url)
            finally:
                restore_transaction_signals(fence_signals)
            if live is None:
                raise RecoveryRequired("ROLLBACK_CREATE_FENCE_UNRESOLVED")
        uid, rv = live_identity(live)
        annotations = live.get("metadata", {}).get("annotations")
        marker_matches = isinstance(annotations, Mapping) and annotations.get(TRANSACTION_ANNOTATION) == journal.document.get("attemptId")
        response_bound = record.get("state") in {"committed", "verified"}
        if (
            semantic_hash(live) != target.get("desiredSha256")
            or (response_bound and uid != record.get("uid"))
            or (not response_bound and not marker_matches)
        ):
            raise RecoveryRequired("ROLLBACK_CREATED_OBJECT_DRIFT")
        delete_signals = block_transaction_signals()
        try:
            client.delete(url, uid, rv)
            if client.get_optional(url) is not None:
                raise RecoveryRequired("ROLLBACK_CREATED_OBJECT_REMAINS")
        finally:
            restore_transaction_signals(delete_signals)
        return
    if live is None:
        raise RecoveryRequired("ROLLBACK_UPDATED_OBJECT_ABSENT")
    if object_is_terminating(live):
        raise RecoveryRequired("ROLLBACK_UPDATED_OBJECT_TERMINATING")
    uid, _rv = live_identity(live)
    if uid == prestate.get("uid") and semantic_hash(live) == prestate.get(
        "semanticSha256"
    ):
        rollback_state = record.get("rollbackState")
        if rollback_state == "restore-intent":
            source_rv = record.get("rollbackSourceResourceVersion")
            current_rv = live_identity(live)[1]
            if (
                not isinstance(source_rv, str)
                or not source_rv.isdecimal()
                or int(current_rv) <= int(source_rv)
            ):
                raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_FENCE_INVALID")
            mutable = dict(record)
            mutable.update(
                {
                    "rollbackState": "restored",
                    "rollbackRestoredResourceVersion": current_rv,
                }
            )
            operations[target["id"]] = mutable
            journal.write()
            return
        if rollback_state == "restored":
            if record.get("rollbackRestoredResourceVersion") is None:
                raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_RECORD_INVALID")
            return
        if rollback_state is not None:
            raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_STATE_INVALID")
        if action == "noop" or record.get("state") != "intent":
            return
        if live_identity(live)[1] != prestate.get("resourceVersion"):
            raise RecoveryRequired("ROLLBACK_UPDATE_FENCE_PRESTATE_DRIFT")
        desired = target.get("desired")
        if not isinstance(desired, Mapping):
            raise RecoveryRequired("ROLLBACK_UPDATE_FENCE_DESIRED_INVALID")
        request = replace_body(
            live, desired, str(journal.document.get("attemptId"))
        )
        fence_signals = block_transaction_signals()
        try:
            try:
                fenced = client.put_fence(url, request)
            except TransactionError as exc:
                raise RecoveryRequired(
                    "ROLLBACK_UPDATE_FENCE_TRANSPORT_UNRESOLVED"
                ) from exc
            if fenced is not None and (
                metadata_identity(fenced)
                != (target["kind"], target.get("namespace"), target["name"])
                or semantic_hash(fenced) != target.get("desiredSha256")
                or not has_transaction_marker(
                    fenced, str(journal.document.get("attemptId"))
                )
            ):
                raise RecoveryRequired("ROLLBACK_UPDATE_FENCE_RESPONSE_INVALID")
            live = client.get_optional(url)
        finally:
            restore_transaction_signals(fence_signals)
        if live is None or object_is_terminating(live):
            raise RecoveryRequired("ROLLBACK_UPDATE_FENCE_UNRESOLVED")
        uid, _rv = live_identity(live)
    annotations = live.get("metadata", {}).get("annotations")
    marker_matches = (
        isinstance(annotations, Mapping)
        and annotations.get(TRANSACTION_ANNOTATION) == journal.document.get("attemptId")
    )
    if record.get("state") not in {"intent", "committed", "verified"}:
        raise RecoveryRequired("ROLLBACK_UPDATE_RECORD_STATE_INVALID")
    response_bound = record.get("state") in {"committed", "verified"}
    if (
        uid != prestate.get("uid")
        or semantic_hash(live) != target.get("desiredSha256")
        or (response_bound and uid != record.get("uid"))
        or (not response_bound and not marker_matches)
    ):
        raise RecoveryRequired("ROLLBACK_UPDATED_OBJECT_DRIFT")
    rollback = prestate.get("rollbackObject")
    if not isinstance(rollback, Mapping):
        raise RecoveryRequired("ROLLBACK_OBJECT_INVALID")
    body = semantic_object(rollback)
    metadata = body.get("metadata")
    if not isinstance(metadata, MutableMapping):
        raise RecoveryRequired("ROLLBACK_METADATA_INVALID")
    live_uid, source_rv = live_identity(live)
    metadata["uid"], metadata["resourceVersion"] = live_uid, source_rv
    mutable = dict(record)
    mutable.update(
        {
            "rollbackState": "restore-intent",
            "rollbackSourceResourceVersion": source_rv,
        }
    )
    operations[target["id"]] = mutable
    journal.write()
    restore_signals = block_transaction_signals()
    try:
        try:
            restored = client.put_fence(url, body)
        except TransactionError as exc:
            raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_TRANSPORT_UNRESOLVED") from exc
        if restored is not None and (
            live_identity(restored)[0] != prestate.get("uid")
            or int(live_identity(restored)[1]) <= int(source_rv)
            or semantic_hash(restored) != prestate.get("semanticSha256")
        ):
            raise RecoveryRequired("ROLLBACK_SEMANTICS_INVALID")
        observed = client.get_optional(url)
        if observed is None or object_is_terminating(observed):
            raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_UNRESOLVED")
        restored_uid, restored_rv = live_identity(observed)
        if (
            restored_uid != prestate.get("uid")
            or int(restored_rv) <= int(source_rv)
            or semantic_hash(observed) != prestate.get("semanticSha256")
        ):
            raise RecoveryRequired("ROLLBACK_UPDATE_RESTORE_UNRESOLVED")
        mutable.update(
            {
                "rollbackState": "restored",
                "rollbackRestoredResourceVersion": restored_rv,
            }
        )
        operations[target["id"]] = mutable
        journal.write()
    finally:
        restore_transaction_signals(restore_signals)


def cleanup_rollback_annotations(
    client: KubeClient, plan: Mapping[str, object], journal: Journal
) -> None:
    targets = plan.get("targets")
    operations = journal.document.get("operations")
    if not isinstance(targets, list) or not isinstance(operations, MutableMapping):
        raise RecoveryRequired("ROLLBACK_CLEANUP_STATE_INVALID")
    for target in targets:
        if not isinstance(target, Mapping) or target.get("action") != "delete":
            continue
        record = operations.get(target["id"])
        if not isinstance(record, Mapping) or record.get("rollbackState") not in {
            "restored",
            "verified",
        }:
            continue
        live = client.get(str(target["url"]))
        if object_is_terminating(live):
            raise RecoveryRequired("ROLLBACK_CLEANUP_OBJECT_TERMINATING")
        uid, _ = live_identity(live)
        prestate = target.get("prestate")
        if (
            not isinstance(prestate, Mapping)
            or uid != record.get("restoredUid")
            or semantic_hash(live) != prestate.get("semanticSha256")
        ):
            raise RecoveryRequired("ROLLBACK_CLEANUP_DRIFT")
        annotations = live.get("metadata", {}).get("annotations")
        if isinstance(annotations, Mapping) and annotations.get(
            TRANSACTION_ANNOTATION
        ) == journal.document.get("attemptId"):
            body = remove_transaction_annotation(writable_from_live(live))
            response = client.put(str(target["url"]), body)
            if object_is_terminating(response) or semantic_hash(response) != prestate.get("semanticSha256"):
                raise RecoveryRequired("ROLLBACK_CLEANUP_FAILED")
            uid, rv = live_identity(response)
        elif not isinstance(annotations, Mapping) or TRANSACTION_ANNOTATION not in annotations:
            _uid, rv = live_identity(live)
        else:
            raise RecoveryRequired("ROLLBACK_CLEANUP_MARKER_COLLISION")
        mutable = dict(record)
        mutable.update(
            {
                "rollbackState": "verified",
                "restoredUid": uid,
                "restoredResourceVersion": rv,
            }
        )
        operations[target["id"]] = mutable
        journal.write()


def restore_helm_proof(
    client: KubeClient, plan: Mapping[str, object], journal: Journal
) -> None:
    proof = journal.document.get("helmProof")
    if not isinstance(proof, Mapping) or proof.get("state") == "not-started":
        return
    _collection, url = resource_urls("HelmRelease", "naranjo-online", "naranjo-online")
    live = client.get(url)
    if object_is_terminating(live):
        raise RecoveryRequired("ROLLBACK_HELM_OBJECT_TERMINATING")
    uid, _ = live_identity(live)
    if uid != proof.get("uid"):
        raise RecoveryRequired("ROLLBACK_HELM_UID_DRIFT")
    pre_spec = proof.get("preSpec")
    mutated_spec = proof.get("mutatedSpec")
    mutated_spec_sha256 = proof.get("mutatedSpecSha256")
    plan_sha256 = journal.document.get("planSha256")
    pre_snapshot = proof.get("preSnapshot")
    namespace = proof.get("namespace")
    name = proof.get("name")
    version = proof.get("version")
    upstream_digest = proof.get("upstreamDigest")
    pre_generation = proof.get("preGeneration")
    pre_history_revision = proof.get("preHistoryRevision")
    if (
        not isinstance(pre_spec, Mapping)
        or not isinstance(mutated_spec, Mapping)
        or not isinstance(pre_snapshot, Mapping)
        or namespace != "naranjo-online"
        or name != "naranjo-online"
        or not isinstance(pre_generation, int)
        or not isinstance(pre_history_revision, int)
    ):
        raise RecoveryRequired("ROLLBACK_HELM_SPEC_INVALID")
    try:
        planned_version, planned_digest, planned_snapshot = (
            planned_site_chart_identity(
                plan, "naranjo-online", "naranjo-online"
            )
        )
    except TransactionError as exc:
        raise RecoveryRequired("ROLLBACK_HELM_PLAN_BINDING_INVALID") from exc
    if (
        version != planned_version
        or upstream_digest != planned_digest
        or dict(pre_snapshot) != dict(planned_snapshot)
        or uid != planned_snapshot.get("uid")
        or pre_generation != planned_snapshot.get("generation")
        or pre_history_revision != planned_snapshot.get("historyRevision")
        or sha256_bytes(canonical_json(pre_spec))
        != planned_snapshot.get("specSha256")
    ):
        raise RecoveryRequired("ROLLBACK_HELM_PLAN_BINDING_INVALID")
    try:
        version, upstream_digest = validate_site_chart_snapshot_binding(
            pre_snapshot,
            version,
            upstream_digest,
            "ROLLBACK_HELM_SPEC_INVALID",
        )
    except TransactionError as exc:
        raise RecoveryRequired("ROLLBACK_HELM_SPEC_INVALID") from exc
    try:
        expected_mutated_spec = build_helm_proof_spec(pre_spec, plan_sha256)
    except TransactionError as exc:
        raise RecoveryRequired("ROLLBACK_HELM_PROOF_BINDING_INVALID") from exc
    expected_mutated_spec_sha256 = sha256_bytes(
        canonical_json(expected_mutated_spec)
    )
    if (
        dict(mutated_spec) != expected_mutated_spec
        or not isinstance(mutated_spec_sha256, str)
        or SHA256_RE.fullmatch(mutated_spec_sha256) is None
        or mutated_spec_sha256 != expected_mutated_spec_sha256
    ):
        raise RecoveryRequired("ROLLBACK_HELM_PROOF_BINDING_INVALID")
    mutated_spec = expected_mutated_spec
    live_spec = live.get("spec")
    if live_spec == pre_spec and proof.get("state") == "add-intent":
        try:
            unchanged = validate_site_helm_release(
                live, namespace, name, version, upstream_digest
            )
        except TransactionError as exc:
            raise RecoveryRequired(
                "ROLLBACK_HELM_UNCHANGED_PRESTATE_DRIFT"
            ) from exc
        if unchanged != dict(pre_snapshot):
            raise RecoveryRequired("ROLLBACK_HELM_UNCHANGED_PRESTATE_DRIFT")
        request = writable_from_live(live)
        request["spec"] = copy.deepcopy(dict(mutated_spec))
        fence_signals = block_transaction_signals()
        try:
            try:
                fenced = client.put_fence(url, request)
            except TransactionError as exc:
                raise RecoveryRequired(
                    "ROLLBACK_HELM_FENCE_TRANSPORT_UNRESOLVED"
                ) from exc
            if fenced is not None and (
                live_identity(fenced)[0] != uid
                or fenced.get("spec") != mutated_spec
                or semantic_hash(fenced) != semantic_hash(request)
            ):
                raise RecoveryRequired("ROLLBACK_HELM_FENCE_RESPONSE_INVALID")
            live = client.get(url)
        finally:
            restore_transaction_signals(fence_signals)
        if (
            object_is_terminating(live)
            or live_identity(live)[0] != uid
            or live.get("spec") != mutated_spec
        ):
            raise RecoveryRequired("ROLLBACK_HELM_FENCE_UNRESOLVED")
        live_spec = live.get("spec")
    if live_spec == mutated_spec:
        _uid, live_rv = live_identity(live)
        mutable_proof = dict(proof)
        mutable_proof["state"] = "rollback-restore-intent"
        mutable_proof["rollbackRestoreResourceVersion"] = live_rv
        journal.document["helmProof"] = mutable_proof
        journal.write()
        body = writable_from_live(live)
        body["spec"] = copy.deepcopy(dict(pre_spec))
        restore_signals = block_transaction_signals()
        try:
            response = client.put(url, body)
            if object_is_terminating(response):
                raise RecoveryRequired("ROLLBACK_HELM_RESPONSE_TERMINATING")
            response_uid, response_rv = live_identity(response)
            live_generation = live.get("metadata", {}).get("generation")
            response_generation = response.get("metadata", {}).get("generation")
            if (
                response_uid != uid
                or int(response_rv) <= int(live_rv)
                or not isinstance(live_generation, int)
                or not isinstance(response_generation, int)
                or response_generation <= live_generation
                or response.get("spec") != pre_spec
                or semantic_hash(response) != semantic_hash(body)
            ):
                raise RecoveryRequired("ROLLBACK_HELM_RESPONSE_INVALID")
            mutable_proof["rollbackRestoredResourceVersion"] = response_rv
            journal.document["helmProof"] = mutable_proof
            journal.write()
        finally:
            restore_transaction_signals(restore_signals)
    elif live_spec != pre_spec:
        raise RecoveryRequired("ROLLBACK_HELM_CONCURRENT_SPEC_DRIFT")
    wait_helm_restored(
        client,
        url,
        uid,
        pre_spec,
        namespace,
        name,
        version,
        upstream_digest,
        pre_generation,
        pre_history_revision,
        require_history_advance=False,
    )
    final = client.get(url)
    if object_is_terminating(final) or final.get("spec") != pre_spec:
        raise RecoveryRequired("ROLLBACK_HELM_RESTORE_FAILED")
    mutable_proof = dict(journal.document["helmProof"])  # type: ignore[arg-type]
    mutable_proof["state"] = "restored"
    journal.document["helmProof"] = mutable_proof
    journal.write()


def verify_rolled_back_state(
    client: KubeClient,
    plan: Mapping[str, object],
    oracle: ModuleType,
    *,
    proof_started: bool,
) -> dict[str, object]:
    targets = plan.get("targets")
    baselines = plan.get("baselines")
    if not isinstance(targets, list) or not isinstance(baselines, Mapping):
        raise RecoveryRequired("ROLLBACK_VERIFY_PLAN_INVALID")
    for target in targets:
        if not isinstance(target, Mapping):
            raise RecoveryRequired("ROLLBACK_VERIFY_TARGET_INVALID")
        prestate = target.get("prestate")
        live = client.get_optional(str(target["url"]))
        if not isinstance(prestate, Mapping):
            raise RecoveryRequired("ROLLBACK_VERIFY_PRESTATE_INVALID")
        if prestate.get("present") is False:
            if live is not None:
                raise RecoveryRequired("ROLLBACK_VERIFY_RESIDUE")
            continue
        if (
            live is None
            or object_is_terminating(live)
            or semantic_hash(live) != prestate.get("semanticSha256")
        ):
            raise RecoveryRequired("ROLLBACK_VERIFY_SEMANTIC_DRIFT")
        if target.get("action") != "delete" and live_identity(live)[0] != prestate.get("uid"):
            raise RecoveryRequired("ROLLBACK_VERIFY_UID_DRIFT")

    baseline_graph = baselines.get("bindingGraph")
    baseline_rows = baseline_graph.get("rows") if isinstance(baseline_graph, Mapping) else None
    current_graph = binding_graph(client)
    current_rows = current_graph.get("rows")
    if not isinstance(baseline_rows, list) or not isinstance(current_rows, list):
        raise RecoveryRequired("ROLLBACK_VERIFY_GRAPH_INVALID")

    def graph_key(row: Mapping[str, object]) -> tuple[object, object, object]:
        return row.get("kind"), row.get("namespace"), row.get("name")

    expected_graph = {
        graph_key(row): row for row in baseline_rows if isinstance(row, Mapping)
    }
    actual_graph = {
        graph_key(row): row for row in current_rows if isinstance(row, Mapping)
    }
    if set(expected_graph) != set(actual_graph):
        raise RecoveryRequired("ROLLBACK_VERIFY_GRAPH_INVENTORY")
    for identity, expected in expected_graph.items():
        actual = actual_graph[identity]
        if actual.get("semanticSha256") != expected.get("semanticSha256"):
            raise RecoveryRequired("ROLLBACK_VERIFY_GRAPH_SEMANTICS")
        if identity != ("ClusterRoleBinding", None, BROAD_NAME) and actual.get("uid") != expected.get("uid"):
            raise RecoveryRequired("ROLLBACK_VERIFY_GRAPH_UID")

    receipts = [run_oracle_row(oracle, client, row, "ALLOWED") for row in OWNED_ROWS]
    receipts.extend(
        run_oracle_row(oracle, client, row, "ALLOWED") for row in CROSSING_ROWS
    )
    stable_baselines(plan, client, allow_proof=proof_started)
    controllers = controller_snapshot(client)
    source_baseline = baselines.get("controllers")
    source_baseline = (
        source_baseline.get("source-controller")
        if isinstance(source_baseline, Mapping)
        else None
    )
    if controllers.get("source-controller") != source_baseline:
        raise RecoveryRequired("ROLLBACK_VERIFY_SOURCE_CONTROLLER_DRIFT")
    for name in ("kustomize-controller", "helm-controller"):
        if controllers[name]["podRestarts"] != 0:  # type: ignore[index]
            raise RecoveryRequired("ROLLBACK_VERIFY_CONTROLLER_RESTART")
    return {
        "bindingGraph": current_graph,
        "authorizationEvidence": build_oracle_evidence("rollback", receipts),
    }


def rollback_internal(client: KubeClient, plan: Mapping[str, object], journal: Journal) -> None:
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise RecoveryRequired("ROLLBACK_PLAN_INVALID")
    target_by_id = {item["id"]: item for item in targets if isinstance(item, Mapping)}
    operations = journal.document.get("operations")
    if not isinstance(operations, Mapping):
        raise RecoveryRequired("ROLLBACK_JOURNAL_INVALID")
    proof = journal.document.get("helmProof")
    proof_started = isinstance(proof, Mapping) and proof.get("state") != "not-started"
    # The deleted broad authority is restored first, before any narrower object.
    broad_id = f"delete:ClusterRoleBinding:{BROAD_NAME}"
    if broad_id in operations:
        restore_object(client, target_by_id[broad_id], journal)
    order = [str(item) for item in plan.get("operationOrder", [])]
    categories = (
        "replace:ClusterRoleBinding",
        "replace:ClusterRole",
        "rollout:Deployment:flux-system:helm-controller",
        "rollout:Deployment:flux-system:kustomize-controller",
    )
    handled = {broad_id}
    for prefix in categories:
        for operation_id in reversed(order):
            if operation_id in operations and operation_id.startswith(prefix):
                restore_object(client, target_by_id[operation_id], journal)
                handled.add(operation_id)
                if (
                    operation_id.startswith("rollout:")
                    and target_by_id[operation_id].get("action") != "noop"
                ):
                    wait_controller_rollout(client, str(target_by_id[operation_id]["name"]))
    restore_helm_proof(client, plan, journal)
    for operation_id in reversed(order):
        if operation_id in operations and operation_id not in handled:
            restore_object(client, target_by_id[operation_id], journal)
    cleanup_rollback_annotations(client, plan, journal)
    oracle = load_module(custody_path(ORACLE_REL), "flux_rbac_denial_oracle_rollback")
    evidence = verify_rolled_back_state(
        client, plan, oracle, proof_started=proof_started
    )
    authorization_evidence = evidence.get("authorizationEvidence")
    plan_sha256 = str(journal.document.get("planSha256"))
    source_revision = str(journal.document.get("sourceRevision"))
    if not isinstance(authorization_evidence, Mapping):
        raise RecoveryRequired("ROLLBACK_ORACLE_EVIDENCE_INVALID")
    evidence["authorizationEvidence"] = persist_oracle_evidence(
        "rollback-terminal",
        authorization_evidence,
        plan_sha256,
        source_revision,
        journal,
    )
    publish_oracle_evidence_records(journal)
    evidence["terminalTargetInventory"] = capture_terminal_target_inventory(
        client, plan, journal, "rolled-back"
    )
    targets = plan.get("targets")
    operations = journal.document.get("operations")
    if not isinstance(targets, list) or not isinstance(operations, Mapping):
        raise RecoveryRequired("ROLLBACK_TERMINAL_OPERATIONS_INVALID")
    target_ids = {
        str(target.get("id")) for target in targets if isinstance(target, Mapping)
    }
    if (
        len(target_ids) != TRANSACTION_TARGET_COUNT
        or not set(operations).issubset(target_ids)
    ):
        raise RecoveryRequired("ROLLBACK_TERMINAL_OPERATIONS_INVALID")
    terminal_operations = copy.deepcopy(dict(operations))
    for target_id in target_ids - set(terminal_operations):
        terminal_operations[target_id] = {
            "state": "not-started",
            "rollbackState": "prestate-verified",
        }
    terminal_evidence = copy.deepcopy(evidence)
    terminal_signals = block_transaction_signals()
    try:
        journal.document.update(
            {
                "state": "rolled-back",
                "phase": "rolled-back",
                "pendingOperation": None,
                "recoveryRequired": False,
                "operations": terminal_operations,
                "terminalEvidence": terminal_evidence,
                "terminalEvidenceSha256": sha256_bytes(
                    canonical_json(terminal_evidence)
                ),
            }
        )
        validate_terminal_evidence_document(journal.document)
        journal.write()
    finally:
        restore_transaction_signals(terminal_signals)


def terminal_result(state: object) -> str | None:
    return {"committed": "pass", "rolled-back": "rolled-back"}.get(str(state))


def terminal_evidence_digest(
    journal: Journal, result: str
) -> tuple[Mapping[str, object], str]:
    if terminal_result(journal.document.get("state")) != result:
        raise TransactionError("TERMINAL_EVIDENCE_STATE_INVALID")
    validate_terminal_evidence_document(journal.document)
    evidence = journal.document.get("terminalEvidence")
    digest = journal.document.get("terminalEvidenceSha256")
    if (
        not isinstance(evidence, Mapping)
        or SHA256_RE.fullmatch(str(digest)) is None
        or sha256_bytes(canonical_json(evidence)) != digest
    ):
        raise TransactionError("TERMINAL_EVIDENCE_INVALID")
    return evidence, str(digest)


def validate_terminal_inventory_evidence(
    inventory: object, operations: object
) -> None:
    if not isinstance(inventory, list) or len(inventory) != TRANSACTION_TARGET_COUNT:
        raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
    identifiers: set[str] = set()
    for row in inventory:
        if not isinstance(row, Mapping) or type(row.get("present")) is not bool:
            raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
        identifiers.add(identifier)
        if row["present"] is False:
            if set(row) != {"id", "present"}:
                raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
            continue
        if (
            set(row)
            != {"id", "present", "uid", "resourceVersion", "semanticSha256"}
            or UID_RE.fullmatch(str(row.get("uid"))) is None
            or not isinstance(row.get("resourceVersion"), str)
            or not str(row["resourceVersion"]).isdecimal()
            or SHA256_RE.fullmatch(str(row.get("semanticSha256"))) is None
        ):
            raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
    if (
        not isinstance(operations, Mapping)
        or len(operations) != TRANSACTION_TARGET_COUNT
        or set(operations) != identifiers
    ):
        raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")


def validate_terminal_evidence_document(document: Mapping[str, object]) -> None:
    result = terminal_result(document.get("state"))
    has_terminal = (
        "terminalEvidence" in document or "terminalEvidenceSha256" in document
    )
    if result is None:
        if has_terminal:
            raise TransactionError("JOURNAL_TERMINAL_EVIDENCE_EARLY")
        return
    evidence = document.get("terminalEvidence")
    digest = document.get("terminalEvidenceSha256")
    if (
        not isinstance(evidence, Mapping)
        or set(evidence)
        != {"bindingGraph", "authorizationEvidence", "terminalTargetInventory"}
        or SHA256_RE.fullmatch(str(digest)) is None
        or sha256_bytes(canonical_json(evidence)) != digest
    ):
        raise TransactionError("JOURNAL_TERMINAL_EVIDENCE_INVALID")
    graph = evidence.get("bindingGraph")
    rows = graph.get("rows") if isinstance(graph, Mapping) else None
    if (
        not isinstance(graph, Mapping)
        or set(graph) != {"rows", "sha256"}
        or not isinstance(rows, list)
        or graph.get("sha256") != sha256_bytes(canonical_json(rows))
    ):
        raise TransactionError("JOURNAL_TERMINAL_GRAPH_INVALID")
    identities: set[tuple[object, object, object]] = set()
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "kind",
                "namespace",
                "name",
                "uid",
                "roleRef",
                "trackedSubjects",
                "classification",
                "semanticSha256",
            }
            or row.get("kind") not in {"RoleBinding", "ClusterRoleBinding"}
            or not isinstance(row.get("name"), str)
            or UID_RE.fullmatch(str(row.get("uid"))) is None
            or not isinstance(row.get("roleRef"), Mapping)
            or not isinstance(row.get("trackedSubjects"), list)
            or any(not isinstance(item, str) for item in row["trackedSubjects"])
            or row.get("classification")
            not in {"closed-transaction-scope", "kubernetes-default-group"}
            or SHA256_RE.fullmatch(str(row.get("semanticSha256"))) is None
        ):
            raise TransactionError("JOURNAL_TERMINAL_GRAPH_INVALID")
        identity = (row.get("kind"), row.get("namespace"), row.get("name"))
        if identity in identities:
            raise TransactionError("JOURNAL_TERMINAL_GRAPH_INVALID")
        identities.add(identity)

    label, phase = (
        ("post-proof-final", "final")
        if result == "pass"
        else ("rollback-terminal", "rollback")
    )
    authorization = evidence.get("authorizationEvidence")
    records = document.get("oracleEvidenceRecords")
    record = records.get(label) if isinstance(records, Mapping) else None
    public_fields = {
        "label",
        "matrixPhase",
        "receiptCount",
        "receiptsSha256",
        "file",
        "fileSha256",
    }
    if (
        not isinstance(authorization, Mapping)
        or set(authorization) != public_fields
        or authorization.get("label") != label
        or authorization.get("matrixPhase") != phase
        or not isinstance(record, Mapping)
        or dict(authorization)
        != {field: record.get(field) for field in public_fields}
    ):
        raise TransactionError("JOURNAL_TERMINAL_ORACLE_INVALID")
    validate_terminal_inventory_evidence(
        evidence.get("terminalTargetInventory"), document.get("operations")
    )


def terminal_inventory_semantic_projection(inventory: object) -> object:
    if not isinstance(inventory, list):
        raise TransactionError("TERMINAL_EVIDENCE_INVENTORY_INVALID")
    return [
        {key: value for key, value in row.items() if key != "resourceVersion"}
        if isinstance(row, Mapping)
        else row
        for row in inventory
    ]


def validate_fresh_terminal_evidence(
    journal: Journal, result: str, evidence: Mapping[str, object]
) -> None:
    terminal, _digest = terminal_evidence_digest(journal, result)
    authorization = evidence.get("authorizationEvidence")
    terminal_authorization = terminal.get("authorizationEvidence")
    if (
        set(evidence)
        != {"bindingGraph", "authorizationEvidence", "terminalTargetInventory"}
        or evidence.get("bindingGraph") != terminal.get("bindingGraph")
        or not isinstance(authorization, Mapping)
        or not isinstance(terminal_authorization, Mapping)
        or authorization.get("receiptsSha256")
        != terminal_authorization.get("receiptsSha256")
        or terminal_inventory_semantic_projection(
            evidence.get("terminalTargetInventory")
        )
        != terminal_inventory_semantic_projection(
            terminal.get("terminalTargetInventory")
        )
    ):
        raise TransactionError("FRESH_TERMINAL_EVIDENCE_DRIFT")


def validate_journal_embedded_evidence(document: Mapping[str, object]) -> None:
    records = document.get("oracleEvidenceRecords", {})
    if not isinstance(records, Mapping) or len(records) > 5:
        raise TransactionError("JOURNAL_ORACLE_EVIDENCE_INVALID")
    allowed_labels = {
        "pre-shared",
        "mixed",
        "final",
        "post-proof-final",
        "rollback-terminal",
    }
    for label, record in records.items():
        if (
            label not in allowed_labels
            or not isinstance(record, Mapping)
            or set(record)
            != {
                "label",
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
                "file",
                "fileSha256",
                "document",
            }
        ):
            raise TransactionError("JOURNAL_ORACLE_EVIDENCE_INVALID")
        evidence_document = record.get("document")
        if (
            not isinstance(evidence_document, Mapping)
            or set(evidence_document)
            != {
                "schema",
                "label",
                "planSha256",
                "sourceRevision",
                "attemptId",
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
                "receipts",
            }
            or evidence_document.get("schema") != ORACLE_EVIDENCE_SCHEMA
            or evidence_document.get("label") != label
            or evidence_document.get("planSha256") != document.get("planSha256")
            or evidence_document.get("sourceRevision")
            != document.get("sourceRevision")
            or evidence_document.get("attemptId") != document.get("attemptId")
        ):
            raise TransactionError("JOURNAL_ORACLE_EVIDENCE_INVALID")
        receipts = evidence_document.get("receipts")
        if not isinstance(receipts, list):
            raise TransactionError("JOURNAL_ORACLE_EVIDENCE_INVALID")
        normalized = build_oracle_evidence(
            str(evidence_document.get("matrixPhase")), receipts
        )
        payload = canonical_json(evidence_document)
        payload_sha256 = sha256_bytes(payload)
        if (
            {key: record.get(key) for key in (
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
            )}
            != {key: normalized[key] for key in (
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
            )}
            or record.get("label") != label
            or record.get("file") != f"oracle.{label}.{payload_sha256}.json"
            or record.get("fileSha256") != payload_sha256
        ):
            raise TransactionError("JOURNAL_ORACLE_EVIDENCE_INVALID")
    counter = document.get("verificationCounter")
    chain = document.get("verificationChainSha256")
    pending = document.get("pendingVerification")
    if (
        type(counter) is not int
        or counter < 0
        or SHA256_RE.fullmatch(str(chain)) is None
        or (pending is not None and not isinstance(pending, Mapping))
        or (counter == 0 and (chain != "0" * 64 or pending is not None))
        or (counter > 0 and chain == "0" * 64 and not (counter == 1 and pending))
    ):
        raise TransactionError("JOURNAL_VERIFICATION_STATE_INVALID")
    if pending is not None:
        instance = object.__new__(Journal)
        instance.document = dict(document)
        if pending.get("verificationIndex") != counter:
            raise TransactionError("JOURNAL_VERIFICATION_STATE_INVALID")
        validate_verification_document(
            instance,
            pending,
            expected_previous_sha256=str(chain),
        )
    validate_terminal_evidence_document(document)


def persist_oracle_evidence(
    label: str,
    evidence: Mapping[str, object],
    plan_sha256: str,
    source_revision: str,
    journal: Journal,
) -> dict[str, object]:
    if label not in {
        "pre-shared",
        "mixed",
        "final",
        "post-proof-final",
        "rollback-terminal",
    }:
        raise TransactionError("ORACLE_EVIDENCE_LABEL_INVALID")
    if (
        SHA256_RE.fullmatch(plan_sha256) is None
        or SOURCE_REVISION_RE.fullmatch(source_revision) is None
        or journal.document.get("planSha256") != plan_sha256
        or journal.document.get("sourceRevision") != source_revision
    ):
        raise TransactionError("ORACLE_EVIDENCE_BINDING_INVALID")
    if set(evidence) != {
        "matrixPhase",
        "receiptCount",
        "receiptsSha256",
        "receipts",
    }:
        raise TransactionError("ORACLE_EVIDENCE_INVALID")
    receipts = evidence.get("receipts")
    if not isinstance(receipts, list):
        raise TransactionError("ORACLE_EVIDENCE_INVALID")
    normalized = build_oracle_evidence(str(evidence.get("matrixPhase")), receipts)
    if normalized != dict(evidence):
        raise TransactionError("ORACLE_EVIDENCE_INVALID")
    document = {
        "schema": ORACLE_EVIDENCE_SCHEMA,
        "label": label,
        "planSha256": plan_sha256,
        "sourceRevision": source_revision,
        "attemptId": journal.document.get("attemptId"),
        **normalized,
    }
    payload = canonical_json(document)
    if len(payload) > ORACLE_PHASE_MAX_BYTES + 4096:
        raise TransactionError("ORACLE_EVIDENCE_TOO_LARGE")
    payload_sha256 = sha256_bytes(payload)
    path = EVIDENCE_ROOT / f"oracle.{label}.{payload_sha256}.json"
    public_record = {
        "label": label,
        "matrixPhase": normalized["matrixPhase"],
        "receiptCount": normalized["receiptCount"],
        "receiptsSha256": normalized["receiptsSha256"],
        "file": path.name,
        "fileSha256": payload_sha256,
    }
    record = {**public_record, "document": document}
    records = journal.document.setdefault("oracleEvidenceRecords", {})
    if not isinstance(records, MutableMapping) or len(records) > 5:
        raise TransactionError("ORACLE_EVIDENCE_RECORDS_INVALID")
    existing = records.get(label)
    if existing is None:
        records[label] = record
        journal.write()
    elif existing != record:
        raise TransactionError("ORACLE_EVIDENCE_RECORD_COLLISION")
    publish_oracle_evidence_records(journal)
    return public_record


def publish_oracle_evidence_records(journal: Journal) -> None:
    records = journal.document.get("oracleEvidenceRecords", {})
    if not isinstance(records, Mapping) or len(records) > 5:
        raise TransactionError("ORACLE_EVIDENCE_RECORDS_INVALID")
    ensure_root_directory(EVIDENCE_ROOT, 0o700)
    expected_files: set[str] = set()
    for label, record in records.items():
        if not isinstance(label, str) or not isinstance(record, Mapping):
            raise TransactionError("ORACLE_EVIDENCE_RECORD_INVALID")
        exact_fields(
            record,
            {
                "label",
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
                "file",
                "fileSha256",
                "document",
            },
            "ORACLE_EVIDENCE_RECORD",
        )
        document = record.get("document")
        if not isinstance(document, Mapping):
            raise TransactionError("ORACLE_EVIDENCE_DOCUMENT_INVALID")
        exact_fields(
            document,
            {
                "schema",
                "label",
                "planSha256",
                "sourceRevision",
                "attemptId",
                "matrixPhase",
                "receiptCount",
                "receiptsSha256",
                "receipts",
            },
            "ORACLE_EVIDENCE_DOCUMENT",
        )
        receipts = document.get("receipts")
        if not isinstance(receipts, list):
            raise TransactionError("ORACLE_EVIDENCE_DOCUMENT_INVALID")
        normalized = build_oracle_evidence(
            str(document.get("matrixPhase")), receipts
        )
        payload = canonical_json(document)
        payload_sha256 = sha256_bytes(payload)
        expected_name = f"oracle.{label}.{payload_sha256}.json"
        if (
            document.get("schema") != ORACLE_EVIDENCE_SCHEMA
            or document.get("label") != label
            or document.get("planSha256") != journal.document.get("planSha256")
            or document.get("sourceRevision")
            != journal.document.get("sourceRevision")
            or document.get("attemptId") != journal.document.get("attemptId")
            or {
                "matrixPhase": record.get("matrixPhase"),
                "receiptCount": record.get("receiptCount"),
                "receiptsSha256": record.get("receiptsSha256"),
            }
            != {
                key: normalized[key]
                for key in ("matrixPhase", "receiptCount", "receiptsSha256")
            }
            or record.get("label") != label
            or record.get("file") != expected_name
            or record.get("fileSha256") != payload_sha256
            or len(payload) > ORACLE_PHASE_MAX_BYTES + 4096
        ):
            raise TransactionError("ORACLE_EVIDENCE_RECORD_INVALID")
        expected_files.add(expected_name)
        path = EVIDENCE_ROOT / expected_name
        publish_once(path, payload)
    actual_files = {path.name for path in EVIDENCE_ROOT.iterdir()}
    if actual_files != expected_files:
        raise TransactionError("ORACLE_EVIDENCE_ORPHAN_FILE")


def terminal_receipt_payload(
    journal: Journal, result: str
) -> tuple[dict[str, object], bytes]:
    if result not in {"pass", "rolled-back"}:
        raise TransactionError("TERMINAL_RECEIPT_RESULT_INVALID")
    _terminal_evidence, terminal_digest = terminal_evidence_digest(journal, result)
    records = journal.document.get("receiptRecords")
    record = records.get(result) if isinstance(records, Mapping) else None
    if (
        not isinstance(record, Mapping)
        or set(record)
        != {
            "result",
            "evidenceSha256",
            "recordedAt",
            "journalSequence",
            "journalState",
        }
        or record.get("result") != result
        or record.get("evidenceSha256") != terminal_digest
        or record.get("journalState")
        != ("committed" if result == "pass" else "rolled-back")
        or not isinstance(record.get("journalSequence"), int)
        or int(record["journalSequence"])
        > int(journal.document.get("sequence", -1))
        or not isinstance(record.get("recordedAt"), str)
        or iso8601(parse_time(record.get("recordedAt"), "RECEIPT_RECORDED_AT"))
        != record.get("recordedAt")
    ):
        raise TransactionError("TERMINAL_RECEIPT_RECORD_MISSING")
    document = {
        "schema": RECEIPT_SCHEMA,
        "result": result,
        "planSha256": journal.document.get("planSha256"),
        "sourceRevision": journal.document.get("sourceRevision"),
        "journalSequence": record["journalSequence"],
        "journalState": record["journalState"],
        "evidenceSha256": record["evidenceSha256"],
        "recordedAt": record["recordedAt"],
    }
    return document, canonical_json(document)


def validate_terminal_receipt_file(journal: Journal) -> Path:
    result = terminal_result(journal.document.get("state"))
    if result not in {"pass", "rolled-back"}:
        raise TransactionError("TERMINAL_RECEIPT_STATE_INVALID")
    _document, payload = terminal_receipt_payload(journal, result)
    ensure_root_directory(RECEIPT_ROOT, 0o700)
    path = RECEIPT_ROOT / f"{result}.{journal.document['planSha256']}.json"
    publish_once(path, payload)
    return path


def terminal_receipt_sha256(journal: Journal, result: str) -> str:
    _document, payload = terminal_receipt_payload(journal, result)
    return sha256_bytes(payload)


def pending_verification(journal: Journal) -> tuple[int, Mapping[str, object] | None]:
    counter = journal.document.get("verificationCounter", 0)
    chain = journal.document.get("verificationChainSha256", "0" * 64)
    pending = journal.document.get("pendingVerification")
    if type(counter) is not int or counter < 0 or (
        pending is not None and not isinstance(pending, Mapping)
    ) or SHA256_RE.fullmatch(str(chain)) is None:
        raise TransactionError("VERIFICATION_STATE_INVALID")
    return counter, pending


def validate_verification_document(
    journal: Journal,
    document: Mapping[str, object],
    *,
    allow_next_sequence: bool = False,
    expected_previous_sha256: str | None = None,
) -> bytes:
    exact_fields(
        document,
        {
            "schema",
            "verificationIndex",
            "result",
            "planSha256",
            "sourceRevision",
            "journalState",
            "journalSequence",
            "recordedAt",
            "previousVerificationSha256",
            "terminalReceiptSha256",
            "evidenceSha256",
            "evidence",
        },
        "VERIFICATION_DOCUMENT",
    )
    result = document.get("result")
    expected_state = "committed" if result == "pass" else "rolled-back"
    recorded_at = document.get("recordedAt")
    evidence = document.get("evidence")
    if expected_previous_sha256 is None:
        expected_previous_sha256 = str(
            journal.document.get("verificationChainSha256", "0" * 64)
        )
    authorization_evidence = (
        evidence.get("authorizationEvidence")
        if isinstance(evidence, Mapping)
        else None
    )
    if (
        result not in {"pass", "rolled-back"}
        or document.get("schema") != VERIFICATION_SCHEMA
        or document.get("journalState") != expected_state
        or document.get("planSha256") != journal.document.get("planSha256")
        or document.get("sourceRevision") != journal.document.get("sourceRevision")
        or type(document.get("verificationIndex")) is not int
        or int(document["verificationIndex"]) <= 0
        or type(document.get("journalSequence")) is not int
        or int(document["journalSequence"]) <= 0
        or int(document["journalSequence"])
        > int(journal.document.get("sequence", -1))
        + (1 if allow_next_sequence else 0)
        or not isinstance(recorded_at, str)
        or iso8601(parse_time(recorded_at, "VERIFICATION_RECORDED_AT"))
        != recorded_at
        or document.get("previousVerificationSha256")
        != expected_previous_sha256
        or not isinstance(evidence, Mapping)
        or set(evidence)
        != {
            "bindingGraph",
            "authorizationEvidence",
            "terminalTargetInventory",
        }
        or not isinstance(evidence.get("bindingGraph"), Mapping)
        or not isinstance(evidence.get("terminalTargetInventory"), list)
        or not isinstance(authorization_evidence, Mapping)
        or set(authorization_evidence)
        != {
            "matrixPhase",
            "receiptCount",
            "receiptsSha256",
            "receipts",
        }
        or authorization_evidence.get("matrixPhase")
        != ("final" if result == "pass" else "rollback")
        or not isinstance(authorization_evidence.get("receipts"), list)
        or build_oracle_evidence(
            str(authorization_evidence.get("matrixPhase")),
            authorization_evidence.get("receipts"),  # type: ignore[arg-type]
        )
        != dict(authorization_evidence)
        or document.get("evidenceSha256")
        != sha256_bytes(canonical_json(evidence))
        or document.get("terminalReceiptSha256")
        != terminal_receipt_sha256(journal, str(result))
    ):
        raise TransactionError("VERIFICATION_RECORD_INVALID")
    validate_fresh_terminal_evidence(journal, str(result), evidence)
    payload = canonical_json(document)
    if len(payload) > 512 * 1024:
        raise TransactionError("VERIFICATION_RECORD_TOO_LARGE")
    return payload


def validate_verification_history(journal: Journal) -> None:
    """Re-read every completed immutable verification and its hash chain."""

    counter, pending = pending_verification(journal)
    completed = counter - (1 if pending is not None else 0)
    if completed < 0:
        raise TransactionError("VERIFICATION_HISTORY_INVALID")
    ensure_root_directory(RECEIPT_ROOT, 0o700)
    validate_terminal_receipt_file(journal)
    owner = RECEIPT_ROOT.lstat().st_uid
    plan_sha256 = str(journal.document.get("planSha256"))
    expected_names: set[str] = set()
    previous_sha256 = "0" * 64
    for index in range(1, completed + 1):
        name = f"verify.{index:08d}.{plan_sha256}.json"
        expected_names.add(name)
        payload = read_regular(
            RECEIPT_ROOT / name,
            owner=owner,
            mode=0o600,
            maximum=512 * 1024,
        )
        value = parse_json_bytes(payload, maximum=512 * 1024)
        if (
            not isinstance(value, Mapping)
            or canonical_json(value) != payload
            or value.get("verificationIndex") != index
        ):
            raise TransactionError("VERIFICATION_HISTORY_INVALID")
        validate_verification_document(
            journal,
            value,
            expected_previous_sha256=previous_sha256,
        )
        previous_sha256 = sha256_bytes(payload)
    if previous_sha256 != journal.document.get("verificationChainSha256"):
        raise TransactionError("VERIFICATION_HISTORY_CHAIN_MISMATCH")

    # A pending destination and its fixed .new file are the only permissible
    # extra verification names; publish_once validates and recovers either.
    if pending is not None:
        pending_name = f"verify.{counter:08d}.{plan_sha256}.json"
        expected_names.update({pending_name, pending_name + ".new"})
    actual_names = {
        path.name
        for path in RECEIPT_ROOT.iterdir()
        if path.name.startswith("verify.")
    }
    if not actual_names.issubset(expected_names):
        raise TransactionError("VERIFICATION_HISTORY_ORPHAN_FILE")


def publish_pending_verification(journal: Journal) -> None:
    counter, pending = pending_verification(journal)
    validate_verification_history(journal)
    if pending is None:
        return
    if pending.get("verificationIndex") != counter:
        raise TransactionError("VERIFICATION_PENDING_INDEX_INVALID")
    previous_sha256 = str(journal.document["verificationChainSha256"])
    payload = validate_verification_document(
        journal,
        pending,
        expected_previous_sha256=previous_sha256,
    )
    path = RECEIPT_ROOT / (
        f"verify.{counter:08d}.{journal.document['planSha256']}.json"
    )
    publish_once(path, payload)
    journal.document["verificationChainSha256"] = sha256_bytes(payload)
    journal.document["pendingVerification"] = None
    journal.write()


def write_verification_record(
    result: str,
    plan_sha256: str,
    source_revision: str,
    journal: Journal,
    evidence: Mapping[str, object],
) -> Path:
    if (
        result not in {"pass", "rolled-back"}
        or journal.document.get("state") not in {"committed", "rolled-back"}
        or journal.document.get("planSha256") != plan_sha256
        or journal.document.get("sourceRevision") != source_revision
    ):
        raise TransactionError("VERIFICATION_BINDING_INVALID")
    publish_pending_verification(journal)
    counter, pending = pending_verification(journal)
    if pending is not None:
        raise TransactionError("VERIFICATION_PENDING_NOT_CLEARED")
    index = counter + 1
    sequence = journal.document.get("sequence")
    if not isinstance(sequence, int):
        raise TransactionError("VERIFICATION_SEQUENCE_INVALID")
    evidence_copy = copy.deepcopy(dict(evidence))
    document = {
        "schema": VERIFICATION_SCHEMA,
        "verificationIndex": index,
        "result": result,
        "planSha256": plan_sha256,
        "sourceRevision": source_revision,
        "journalState": journal.document.get("state"),
        "journalSequence": sequence + 1,
        "recordedAt": iso8601(utc_now()),
        "previousVerificationSha256": journal.document[
            "verificationChainSha256"
        ],
        "terminalReceiptSha256": terminal_receipt_sha256(journal, result),
        "evidenceSha256": sha256_bytes(canonical_json(evidence_copy)),
        "evidence": evidence_copy,
    }
    validate_verification_document(
        journal, document, allow_next_sequence=True
    )
    journal.document["verificationCounter"] = index
    journal.document["pendingVerification"] = document
    journal.write()
    publish_pending_verification(journal)
    return RECEIPT_ROOT / f"verify.{index:08d}.{plan_sha256}.json"


def write_receipt(
    result: str,
    plan_sha256: str,
    source_revision: str,
    journal: Journal,
    evidence: Mapping[str, object] | None = None,
) -> Path:
    if result not in {"pass", "rolled-back", "recovery-required"}:
        raise TransactionError("RECEIPT_RESULT_INVALID")
    expected_state = {
        "pass": "committed",
        "rolled-back": "rolled-back",
        "recovery-required": "recovery-required",
    }[result]
    if (
        journal.document.get("state") != expected_state
        or journal.document.get("planSha256") != plan_sha256
        or journal.document.get("sourceRevision") != source_revision
    ):
        raise TransactionError("RECEIPT_STATE_INVALID")
    ensure_root_directory(RECEIPT_ROOT, 0o700)
    path = RECEIPT_ROOT / f"{result}.{plan_sha256}.json"
    if result in {"pass", "rolled-back"}:
        terminal_evidence, evidence_digest = terminal_evidence_digest(
            journal, result
        )
        if evidence is not None and dict(evidence) != dict(terminal_evidence):
            raise TransactionError("RECEIPT_TERMINAL_EVIDENCE_MISMATCH")
        require_evidence_match = True
    else:
        evidence_digest = sha256_bytes(canonical_json(evidence or {}))
        require_evidence_match = evidence is not None
    receipt_records = journal.document.setdefault("receiptRecords", {})
    if not isinstance(receipt_records, MutableMapping):
        raise TransactionError("RECEIPT_RECORDS_INVALID")
    record = receipt_records.get(result)
    if record is None:
        sequence = journal.document.get("sequence")
        if not isinstance(sequence, int):
            raise TransactionError("RECEIPT_SEQUENCE_INVALID")
        record = {
            "result": result,
            "evidenceSha256": evidence_digest,
            "recordedAt": iso8601(utc_now()),
            "journalSequence": sequence + 1,
            "journalState": journal.document.get("state"),
        }
        receipt_records[result] = record
        journal.write()
    elif (
        not isinstance(record, Mapping)
        or set(record)
        != {
            "result",
            "evidenceSha256",
            "recordedAt",
            "journalSequence",
            "journalState",
        }
        or record.get("result") != result
        or (require_evidence_match and record.get("evidenceSha256") != evidence_digest)
        or not isinstance(record.get("recordedAt"), str)
        or iso8601(parse_time(record.get("recordedAt"), "RECEIPT_RECORDED_AT"))
        != record.get("recordedAt")
        or not isinstance(record.get("journalSequence"), int)
        or int(record["journalSequence"])
        > int(journal.document.get("sequence", -1))
        or not isinstance(record.get("journalState"), str)
        or (
            result == "pass"
            and record.get("journalState") != "committed"
        )
        or (
            result == "rolled-back"
            and record.get("journalState") != "rolled-back"
        )
        or (
            result == "recovery-required"
            and record.get("journalState") != "recovery-required"
        )
    ):
        raise TransactionError("RECEIPT_RECORD_COLLISION")
    if result in {"pass", "rolled-back"}:
        _document, payload = terminal_receipt_payload(journal, result)
    else:
        document = {
            "schema": RECEIPT_SCHEMA,
            "result": result,
            "planSha256": plan_sha256,
            "sourceRevision": source_revision,
            "journalSequence": record["journalSequence"],
            "journalState": record["journalState"],
            "evidenceSha256": record["evidenceSha256"],
            "recordedAt": record["recordedAt"],
        }
        payload = canonical_json(document)
    publish_once(path, payload)
    return path


def validate_local_plan_bindings(
    plan: Mapping[str, object],
    client: KubeClient,
    target: Target,
    custody: Mapping[str, object],
    journal: Journal | None = None,
) -> None:
    source = plan.get("source")
    tools = plan.get("tools")
    target_plan = plan.get("target")
    if not isinstance(source, Mapping) or not isinstance(tools, Mapping) or not isinstance(target_plan, Mapping):
        raise TransactionError("PLAN_BINDINGS_INVALID")
    if source.get("sourceRevision") != custody.get("sourceRevision"):
        raise TransactionError("PLAN_SOURCE_MISMATCH")
    if source.get("sourceManifestSha256") != custody.get("manifestSha256"):
        raise TransactionError("PLAN_MANIFEST_MISMATCH")
    if source.get("custodySha256") != custody.get("custodySha256"):
        raise TransactionError("PLAN_CUSTODY_MISMATCH")
    if source.get("tag") != target.release_tag:
        raise TransactionError("PLAN_RELEASE_TAG_MISMATCH")
    if (
        tools.get("pythonPath") != custody.get("pythonPath")
        or tools.get("pythonSha256") != custody.get("pythonSha256")
        or tools.get("kubectlSha256") != client.digest
    ):
        raise TransactionError("PLAN_TOOL_MISMATCH")
    if tools.get("kubeconfigSha256") != client.kubeconfig_digest:
        raise TransactionError("PLAN_KUBECONFIG_MISMATCH")
    if {
        "openssl": tools.get("openssl"),
        "caBundleSha256": tools.get("caBundleSha256"),
    } != tls_tool_binding():
        raise TransactionError("PLAN_TLS_TOOL_MISMATCH")
    current_target = bind_target(client, target)
    if current_target != target_plan:
        raise TransactionError("PLAN_TARGET_MISMATCH")
    if journal is not None:
        if (
            journal.document.get("sourceRevision") != custody.get("sourceRevision")
            or journal.document.get("targetSha256")
            != sha256_bytes(canonical_json(target_plan))
        ):
            raise TransactionError("JOURNAL_LOCAL_BINDING_MISMATCH")


def validate_plan_bindings(
    plan: Mapping[str, object],
    plan_sha256: str,
    client: KubeClient,
    target: Target,
    custody: Mapping[str, object],
    *,
    require_apply_ack: bool = True,
    require_main_tip: bool = True,
) -> ModuleType:
    validate_local_plan_bindings(plan, client, target, custody)
    source = plan.get("source")
    assert isinstance(source, Mapping)
    contract = load_module(custody_path(PLATFORM_CONTRACT_REL), "platform_release_contract_recheck")
    current_source = verify_release_identity(
        str(custody["sourceRevision"]),
        target.release_tag,
        contract,
        read_regular(custody_path(RELEASE_FRAGMENT_REL), owner=0, mode=0o600),
        require_main_tip=require_main_tip,
    )
    entries = validate_custody(custody)
    current_source["sourceBundleSha256"] = verify_custody_source_tree(
        str(custody["sourceRevision"]),
        str(current_source["sourceTreeSha"]),
        entries,
    )
    for key in (
        "repository",
        "sourceRevision",
        "sourceTreeSha",
        "sourceBundleSha256",
        "pullRequestNumber",
        "pullHeadSha",
        "pullMergedAt",
        "mergedBy",
        "mainCiRunId",
        "mainCiRunAttempt",
        "mainCiReceiptSha256",
        "codeqlRunId",
        "codeqlRunAttempt",
        "platformRunId",
        "platformRunAttempt",
        "tag",
        "tagObject",
        "releaseId",
        "releaseTarget",
        "releasePublishedAt",
        "commitVerified",
    ):
        if current_source.get(key) != source.get(key):
            raise TransactionError("PLAN_RELEASE_IDENTITY_MOVED")
    if require_apply_ack:
        expected_ack = f"apply-reviewed-flux-rbac-{plan_sha256}"
        if os.environ.get("CONFIRM_FLUX_RBAC_APPLY") != expected_ack:
            raise TransactionError("APPLY_ACK_INVALID")
    return load_module(custody_path(ORACLE_REL), "flux_rbac_denial_oracle_custodied")


def apply(plan: dict[str, object], plan_sha256: str, client: KubeClient, target: Target, custody: Mapping[str, object]) -> None:
    if JOURNAL_PATH.exists() or JOURNAL_PATH.is_symlink():
        raise TransactionError("JOURNAL_ALREADY_EXISTS")
    oracle = validate_plan_bindings(plan, plan_sha256, client, target, custody)
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise TransactionError("PLAN_TARGETS_INVALID")
    for item in targets:
        if not isinstance(item, Mapping):
            raise TransactionError("PLAN_TARGET_INVALID")
        compare_prestate(client, item)
    stable_baselines(plan, client)
    target_digest = sha256_bytes(canonical_json(plan["target"]))
    journal = Journal(plan_sha256, str(custody["sourceRevision"]), target_digest)
    journal.write()
    old_handlers: dict[int, object] = {}

    def handle_signal(signum: int, _frame: object) -> None:
        raise Interrupted(f"SIGNAL_{signum}")

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[signum] = signal.signal(signum, handle_signal)
    try:
        target_by_phase: dict[str, list[Mapping[str, object]]] = {}
        for item in targets:
            assert isinstance(item, Mapping)
            target_by_phase.setdefault(str(item["phase"]), []).append(item)
        for item in target_by_phase.get("split", []):
            apply_operation(client, item, journal)
        for item in target_by_phase.get("namespaced", []):
            apply_operation(client, item, journal)
        changed_controllers: set[str] = set()
        verify_controller_phase(
            plan, client, frozenset(changed_controllers), journal
        )
        pre_oracle = authorization_phase(oracle, client, "pre-shared")
        pre_oracle_record = persist_oracle_evidence(
            "pre-shared",
            pre_oracle,
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
        )
        journal.document["preSharedOracleSha256"] = pre_oracle_record[
            "receiptsSha256"
        ]
        journal.write()
        stable_baselines(plan, client)
        for item in target_by_phase.get("watchers", []):
            baseline = plan["baselines"]["controllers"][item["name"]]  # type: ignore[index]
            apply_operation(client, item, journal)
            if item.get("action") != "noop":
                rollout = wait_controller_rollout(
                    client, str(item["name"]), str(baseline["podUid"])
                )
                journal.controller_rollout(str(item["id"]), rollout)
                changed_controllers.add(str(item["name"]))
            verify_controller_phase(
                plan, client, frozenset(changed_controllers), journal
            )
            stable_baselines(plan, client)
        for item in target_by_phase.get("shared", []):
            apply_operation(client, item, journal)
        mixed = authorization_phase(oracle, client, "mixed")
        mixed_record = persist_oracle_evidence(
            "mixed",
            mixed,
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
        )
        journal.document["mixedOracleSha256"] = mixed_record["receiptsSha256"]
        journal.write()
        stable_baselines(plan, client)
        verify_controller_phase(
            plan, client, frozenset(changed_controllers), journal
        )
        for item in target_by_phase.get("broad-delete", []):
            apply_operation(client, item, journal)
        final_oracle = authorization_phase(oracle, client, "final")
        final_oracle_record = persist_oracle_evidence(
            "final",
            final_oracle,
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
        )
        journal.document["finalOracleSha256"] = final_oracle_record[
            "receiptsSha256"
        ]
        journal.write()
        stable_baselines(plan, client)
        verify_controller_phase(
            plan, client, frozenset(changed_controllers), journal
        )
        helm_proof(client, plan, plan_sha256, journal)
        cleanup_transaction_annotations(client, plan, journal)
        evidence = verify_converged(
            client, plan, journal, oracle, after_proof=True
        )
        post_proof_oracle = evidence.get("authorizationEvidence")
        if not isinstance(post_proof_oracle, Mapping):
            raise TransactionError("POST_PROOF_ORACLE_EVIDENCE_INVALID")
        evidence["authorizationEvidence"] = persist_oracle_evidence(
            "post-proof-final",
            post_proof_oracle,
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
        )
        publish_oracle_evidence_records(journal)
        evidence["terminalTargetInventory"] = capture_terminal_target_inventory(
            client, plan, journal, "committed"
        )
        terminal_evidence = copy.deepcopy(evidence)
        terminal_signals = block_transaction_signals()
        try:
            journal.document.update(
                {
                    "state": "committed",
                    "phase": "committed",
                    "pendingOperation": None,
                    "terminalEvidence": terminal_evidence,
                    "terminalEvidenceSha256": sha256_bytes(
                        canonical_json(terminal_evidence)
                    ),
                }
            )
            validate_terminal_evidence_document(journal.document)
            journal.write()
        finally:
            restore_transaction_signals(terminal_signals)
        write_receipt(
            "pass", plan_sha256, str(custody["sourceRevision"]), journal
        )
    except BaseException as exc:
        if journal.document.get("state") == "committed":
            raise RecoveryRequired("COMMITTED_RECEIPT_INCOMPLETE") from exc
        try:
            journal.mark_recovery_required()
            rollback_internal(client, plan, journal)
            write_receipt(
                "rolled-back",
                plan_sha256,
                str(custody["sourceRevision"]),
                journal,
                None,
            )
        except BaseException as rollback_exc:
            if journal.document.get("state") == "rolled-back":
                raise RecoveryRequired(
                    "ROLLED_BACK_RECEIPT_INCOMPLETE"
                ) from rollback_exc
            try:
                journal.mark_recovery_required()
                write_receipt(
                    "recovery-required",
                    plan_sha256,
                    str(custody["sourceRevision"]),
                    journal,
                )
            except BaseException:
                pass
            raise RecoveryRequired("AUTOMATIC_ROLLBACK_FAILED") from exc
        raise TransactionError("APPLY_ROLLED_BACK") from exc
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)  # type: ignore[arg-type]


def rollback(
    plan: dict[str, object],
    plan_sha256: str,
    client: KubeClient,
    target: Target,
    custody: Mapping[str, object],
) -> None:
    expected = f"rollback-reviewed-flux-rbac-{plan_sha256}"
    if os.environ.get("CONFIRM_FLUX_RBAC_ROLLBACK") != expected:
        raise TransactionError("ROLLBACK_ACK_INVALID")
    journal = Journal.load()
    if journal.document.get("planSha256") != plan_sha256 or journal.document.get("sourceRevision") != custody.get("sourceRevision"):
        raise TransactionError("ROLLBACK_BINDING_MISMATCH")
    validate_local_plan_bindings(plan, client, target, custody, journal)
    state = journal.document.get("state")
    publish_oracle_evidence_records(journal)
    if state == "committed":
        raise TransactionError("COMMITTED_USE_VERIFY")
    if state == "rolled-back":
        write_receipt(
            "rolled-back",
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
        )
        publish_pending_verification(journal)
        return
    rollback_internal(client, plan, journal)
    write_receipt("rolled-back", plan_sha256, str(custody["sourceRevision"]), journal)


def verify(
    plan: dict[str, object],
    plan_sha256: str,
    client: KubeClient,
    target: Target,
    custody: Mapping[str, object],
) -> None:
    journal = Journal.load()
    if journal.document.get("planSha256") != plan_sha256:
        raise TransactionError("VERIFY_PLAN_MISMATCH")
    validate_local_plan_bindings(plan, client, target, custody, journal)
    state = journal.document.get("state")
    publish_oracle_evidence_records(journal)
    if state not in {"committed", "rolled-back"}:
        raise RecoveryRequired("VERIFY_JOURNAL_NOT_TERMINAL")
    result = "pass" if state == "committed" else "rolled-back"
    write_receipt(
        result, plan_sha256, str(custody["sourceRevision"]), journal
    )
    publish_pending_verification(journal)
    if state == "committed":
        oracle = validate_plan_bindings(
            plan,
            plan_sha256,
            client,
            target,
            custody,
            require_apply_ack=False,
            require_main_tip=False,
        )
        evidence = verify_converged(
            client, plan, journal, oracle, after_proof=True
        )
        authorization_evidence = evidence.get("authorizationEvidence")
        if not isinstance(authorization_evidence, Mapping):
            raise TransactionError("VERIFY_ORACLE_EVIDENCE_INVALID")
        oracle_records = journal.document.get("oracleEvidenceRecords")
        terminal_oracle = (
            oracle_records.get("post-proof-final")
            if isinstance(oracle_records, Mapping)
            else None
        )
        if (
            not isinstance(terminal_oracle, Mapping)
            or authorization_evidence.get("receiptsSha256")
            != terminal_oracle.get("receiptsSha256")
        ):
            raise TransactionError("VERIFY_ORACLE_EVIDENCE_DRIFT")
        evidence["terminalTargetInventory"] = capture_terminal_target_inventory(
            client, plan, journal, "committed"
        )
        validate_fresh_terminal_evidence(journal, "pass", evidence)
        write_receipt(
            "pass", plan_sha256, str(custody["sourceRevision"]), journal
        )
        write_verification_record(
            "pass",
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
            evidence,
        )
        return
    if state == "rolled-back":
        oracle = load_module(
            custody_path(ORACLE_REL), "flux_rbac_denial_oracle_verify_rollback"
        )
        proof = journal.document.get("helmProof")
        proof_started = isinstance(proof, Mapping) and proof.get("state") != "not-started"
        evidence = verify_rolled_back_state(
            client, plan, oracle, proof_started=proof_started
        )
        authorization_evidence = evidence.get("authorizationEvidence")
        if not isinstance(authorization_evidence, Mapping):
            raise TransactionError("VERIFY_ROLLBACK_ORACLE_EVIDENCE_INVALID")
        oracle_records = journal.document.get("oracleEvidenceRecords")
        terminal_oracle = (
            oracle_records.get("rollback-terminal")
            if isinstance(oracle_records, Mapping)
            else None
        )
        if (
            not isinstance(terminal_oracle, Mapping)
            or authorization_evidence.get("receiptsSha256")
            != terminal_oracle.get("receiptsSha256")
        ):
            raise TransactionError("VERIFY_ROLLBACK_ORACLE_EVIDENCE_DRIFT")
        evidence["terminalTargetInventory"] = capture_terminal_target_inventory(
            client, plan, journal, "rolled-back"
        )
        validate_fresh_terminal_evidence(journal, "rolled-back", evidence)
        write_receipt(
            "rolled-back", plan_sha256, str(custody["sourceRevision"]), journal
        )
        write_verification_record(
            "rolled-back",
            plan_sha256,
            str(custody["sourceRevision"]),
            journal,
            evidence,
        )
        return
    raise AssertionError("unreachable terminal state")


def acquire_lock() -> int:
    descriptor = os.open(
        LOCK_PATH,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(descriptor)
        raise TransactionError("TRANSACTION_LOCK_BUSY") from exc
    return descriptor


def parse_source_manifest(payload: bytes) -> dict[str, tuple[str, int]]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransactionError("SOURCE_MANIFEST_ENCODING_INVALID") from exc
    entries: dict[str, tuple[str, int]] = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(" ")
        if len(fields) != 3:
            raise TransactionError("SOURCE_MANIFEST_LINE_INVALID")
        digest, mode_text, relative = fields
        if (
            SHA256_RE.fullmatch(digest) is None
            or mode_text not in {"0600", "0700"}
            or relative in entries
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            raise TransactionError("SOURCE_MANIFEST_LINE_INVALID")
        entries[relative] = (digest, int(mode_text, 8))
    return entries


def validate_source_manifest_bundle(
    entries: Mapping[str, tuple[str, int]], expected_launcher: str
) -> None:
    required = {
        DESIRED_REL,
        ORACLE_REL,
        KUBECONFIG_VALIDATOR_REL,
        PLATFORM_CONTRACT_REL,
        VERSIONS_REL,
        RELEASE_FRAGMENT_REL,
        "bootstrap/flux/rbac-convergence/transaction.py",
    }
    if set(entries) != required:
        raise TransactionError("CUSTODY_ENTRY_SET_INVALID")
    transaction_digest, transaction_mode = entries[
        "bootstrap/flux/rbac-convergence/transaction.py"
    ]
    if transaction_digest != expected_launcher or transaction_mode != 0o700:
        raise TransactionError("CUSTODY_LAUNCHER_ENTRY_MISMATCH")


def expected_custody_receipt(
    source_revision: str,
    manifest_sha256: str,
    launcher_sha256: str,
    python_sha256: str,
    entries: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    return {
        "schema": CUSTODY_SCHEMA,
        "sourceRevision": source_revision,
        "manifestSha256": manifest_sha256,
        "launcherSha256": launcher_sha256,
        "pythonPath": str(PYTHON_PATH),
        "pythonSha256": python_sha256,
        "custodySha256": sha256_bytes(
            canonical_json({key: entries[key][0] for key in sorted(entries)})
        ),
    }


def remove_stale_custody_stages() -> None:
    """Remove only root-owned partial trees created by an interrupted stage."""

    state_metadata = STATE_ROOT.lstat()
    pattern = re.compile(r"custody\.new\.[0-9a-f]{64}\Z")
    for staging in STATE_ROOT.iterdir():
        if pattern.fullmatch(staging.name) is None:
            continue
        metadata = staging.lstat()
        if (
            staging.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_dev != state_metadata.st_dev
        ):
            raise TransactionError("CUSTODY_STALE_STAGE_INVALID")
        for root, directories, files in os.walk(staging, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                path = root_path / name
                item = path.lstat()
                if (
                    path.is_symlink()
                    or not stat.S_ISREG(item.st_mode)
                    or item.st_uid != 0
                    or item.st_gid != 0
                    or item.st_nlink != 1
                    or stat.S_IMODE(item.st_mode) not in {0o600, 0o700}
                    or item.st_dev != state_metadata.st_dev
                ):
                    raise TransactionError("CUSTODY_STALE_FILE_INVALID")
                path.unlink()
            for name in directories:
                path = root_path / name
                item = path.lstat()
                if (
                    path.is_symlink()
                    or not stat.S_ISDIR(item.st_mode)
                    or item.st_uid != 0
                    or item.st_gid != 0
                    or stat.S_IMODE(item.st_mode) != 0o700
                    or item.st_dev != state_metadata.st_dev
                ):
                    raise TransactionError("CUSTODY_STALE_DIRECTORY_INVALID")
                path.rmdir()
        staging.rmdir()
    fsync_directory(STATE_ROOT)


def stage_custody() -> None:
    """Copy one exact reviewed release bundle into root-only custody."""

    if not sys.stdin.isatty():
        raise TransactionError("DIRECT_TTY_REQUIRED")
    source_root_raw = os.environ.get("FLUX_RBAC_SOURCE_ROOT", "")
    source_revision = os.environ.get("FLUX_RBAC_SOURCE_REVISION", "")
    expected_manifest = os.environ.get("FLUX_RBAC_MANIFEST_SHA256", "")
    expected_launcher = os.environ.get("FLUX_RBAC_LAUNCHER_SHA256", "")
    expected_python = os.environ.get("FLUX_RBAC_PYTHON_SHA256", "")
    if (
        SOURCE_REVISION_RE.fullmatch(source_revision) is None
        or SHA256_RE.fullmatch(expected_manifest) is None
        or SHA256_RE.fullmatch(expected_launcher) is None
        or SHA256_RE.fullmatch(expected_python) is None
    ):
        raise TransactionError("CUSTODY_BINDING_INPUT_INVALID")
    expected_ack = (
        f"stage-reviewed-flux-rbac-{source_revision}-{expected_manifest}"
    )
    if os.environ.get("CONFIRM_FLUX_RBAC_CUSTODY") != expected_ack:
        raise TransactionError("CUSTODY_ACK_INVALID")
    launcher_payload = read_regular(
        INSTALLED_LAUNCHER, owner=0, mode=0o700, maximum=2 * 1024 * 1024
    )
    if sha256_bytes(launcher_payload) != expected_launcher:
        raise TransactionError("CUSTODY_LAUNCHER_DIGEST_MISMATCH")
    python_payload = read_regular(
        PYTHON_PATH.resolve(), owner=0, maximum=64 * 1024 * 1024
    )
    if sha256_bytes(python_payload) != expected_python:
        raise TransactionError("CUSTODY_PYTHON_DIGEST_MISMATCH")

    ensure_state_root()
    ensure_root_directory(INPUT_ROOT, 0o700)
    stage_lock_fd = acquire_lock()
    try:
        if CUSTODY_ROOT.is_symlink() or CUSTODY_RECEIPT.is_symlink():
            raise TransactionError("CUSTODY_EXISTING_PATH_INVALID")
        if CUSTODY_ROOT.exists():
            # Interrupted post-rename recovery is intentionally source-free:
            # rebuild only from the already root-owned custody tree.
            manifest_payload = read_regular(
                custody_path(SOURCE_MANIFEST_REL),
                owner=0,
                mode=0o600,
                maximum=256 * 1024,
            )
            if sha256_bytes(manifest_payload) != expected_manifest:
                raise TransactionError("CUSTODY_MANIFEST_DIGEST_MISMATCH")
            entries = parse_source_manifest(manifest_payload)
            validate_source_manifest_bundle(entries, expected_launcher)
            receipt = expected_custody_receipt(
                source_revision,
                expected_manifest,
                expected_launcher,
                expected_python,
                entries,
            )
            validate_custody(receipt)
            publish_once(CUSTODY_RECEIPT, canonical_json(receipt))
            if load_custody_receipt() != receipt:
                raise TransactionError("CUSTODY_EXISTING_RECEIPT_MISMATCH")
            print("STAGED")
            return
        if CUSTODY_RECEIPT.exists():
            raise TransactionError("CUSTODY_RECEIPT_WITHOUT_TREE")

        source_root = Path(source_root_raw)
        source_root_fd = open_directory_no_symlinks(source_root)
        try:
            manifest_payload = read_relative_regular(
                source_root_fd, SOURCE_MANIFEST_REL, maximum=256 * 1024
            )
            if sha256_bytes(manifest_payload) != expected_manifest:
                raise TransactionError("CUSTODY_MANIFEST_DIGEST_MISMATCH")
            entries = parse_source_manifest(manifest_payload)
            validate_source_manifest_bundle(entries, expected_launcher)
            receipt = expected_custody_receipt(
                source_revision,
                expected_manifest,
                expected_launcher,
                expected_python,
                entries,
            )
            remove_stale_custody_stages()
            staging = STATE_ROOT / (
                "custody.new." + hashlib.sha256(os.urandom(32)).hexdigest()
            )
            staging.mkdir(mode=0o700)
            os.chown(staging, 0, 0)
            os.chmod(staging, 0o700)
            try:
                for relative, (expected_digest, mode) in entries.items():
                    payload = read_relative_regular(
                        source_root_fd, relative, maximum=4 * 1024 * 1024
                    )
                    if sha256_bytes(payload) != expected_digest:
                        raise TransactionError(
                            "CUSTODY_SOURCE_ENTRY_DIGEST_MISMATCH"
                        )
                    destination = staging / relative
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    for parent in destination.parents:
                        if parent == STATE_ROOT:
                            break
                        os.chown(parent, 0, 0)
                        os.chmod(parent, 0o700)
                    descriptor = os.open(
                        destination,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        mode,
                    )
                    try:
                        os.fchmod(descriptor, mode)
                        os.fchown(descriptor, 0, 0)
                        view = memoryview(payload)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise TransactionError("CUSTODY_SHORT_WRITE")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    fsync_directory(destination.parent)
                manifest_destination = staging / SOURCE_MANIFEST_REL
                manifest_destination.parent.mkdir(
                    parents=True, exist_ok=True, mode=0o700
                )
                os.chown(manifest_destination.parent, 0, 0)
                os.chmod(manifest_destination.parent, 0o700)
                descriptor = os.open(
                    manifest_destination,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    os.fchown(descriptor, 0, 0)
                    view = memoryview(manifest_payload)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise TransactionError("CUSTODY_MANIFEST_SHORT_WRITE")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                fsync_directory(manifest_destination.parent)
                fsync_directory(staging)
                os.rename(staging, CUSTODY_ROOT)
                fsync_directory(STATE_ROOT)
            except BaseException:
                if staging.exists() and not CUSTODY_ROOT.exists():
                    for root, directories, files in os.walk(staging, topdown=False):
                        for name in files:
                            (Path(root) / name).unlink()
                        for name in directories:
                            (Path(root) / name).rmdir()
                    staging.rmdir()
                raise
        finally:
            os.close(source_root_fd)
        publish_once(CUSTODY_RECEIPT, canonical_json(receipt))
        validate_custody(receipt)
        print("STAGED")
    finally:
        os.close(stage_lock_fd)


def validate_runtime_custody() -> tuple[dict[str, object], dict[str, str]]:
    if os.geteuid() != 0:
        raise TransactionError("ROOT_REQUIRED")
    if sys.argv[0] != str(INSTALLED_LAUNCHER):
        raise TransactionError("DIRECT_CHECKOUT_EXECUTION_BLOCKED")
    receipt = load_custody_receipt()
    launcher_payload = read_regular(INSTALLED_LAUNCHER, owner=0, mode=0o700, maximum=2 * 1024 * 1024)
    if sha256_bytes(launcher_payload) != receipt.get("launcherSha256"):
        raise TransactionError("INSTALLED_LAUNCHER_MISMATCH")
    if receipt.get("pythonPath") != str(PYTHON_PATH) or sys.executable != str(
        PYTHON_PATH
    ):
        raise TransactionError("PYTHON_PATH_MISMATCH")
    python_path = PYTHON_PATH.resolve()
    python_payload = read_regular(python_path, owner=0, maximum=64 * 1024 * 1024)
    if sha256_bytes(python_payload) != receipt.get("pythonSha256"):
        raise TransactionError("PYTHON_IDENTITY_MISMATCH")
    return receipt, validate_custody(receipt)


def run_mode(mode: str) -> None:
    custody, _entries = validate_runtime_custody()
    ensure_state_root()
    ensure_root_directory(INPUT_ROOT, 0o700)
    lock_fd = acquire_lock()
    try:
        target = load_target()
        versions = parse_versions(read_regular(custody_path(VERSIONS_REL), owner=0, mode=0o600))
        # Loading the validator before the oracle satisfies the oracle's direct
        # import without ever adding the custody directory to sys.path.
        validator = load_module(custody_path(KUBECONFIG_VALIDATOR_REL), "validate_kubeconfig_snapshot")
        sys.modules["validate_kubeconfig_snapshot"] = validator
        oracle = load_module(custody_path(ORACLE_REL), "flux_rbac_denial_oracle_runtime")
        with KubeClient(target, versions, oracle) as client:
            if mode == "--plan":
                if JOURNAL_PATH.exists() or JOURNAL_PATH.is_symlink():
                    raise TransactionError("JOURNAL_EXISTS_BEFORE_PLAN")
                plan = build_plan(client, target, custody)
                digest = write_plan(plan)
                print(f"PLAN_SHA256={digest}")
            else:
                expected = os.environ.get("FLUX_RBAC_EXPECTED_PLAN_SHA256")
                if SHA256_RE.fullmatch(expected or "") is None:
                    raise TransactionError("EXPECTED_PLAN_SHA256_INVALID")
                plan, digest = read_plan(
                    expected, require_fresh=mode == "--apply"
                )
                if mode == "--apply":
                    apply(plan, digest, client, target, custody)
                    print("PASS")
                elif mode == "--rollback":
                    rollback(plan, digest, client, target, custody)
                    print("ROLLED_BACK")
                elif mode == "--verify":
                    verify(plan, digest, client, target, custody)
                    print("PASS")
                else:
                    raise TransactionError("MODE_INVALID")
    finally:
        os.close(lock_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "mode",
        choices=("--stage", "--plan", "--apply", "--rollback", "--verify"),
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        parser().print_help()
        return 0
    if len(arguments) != 1 or arguments[0] not in {
        "--stage",
        "--plan",
        "--apply",
        "--rollback",
        "--verify",
    }:
        parser().print_usage(sys.stderr)
        return 2
    try:
        validate_process_boundary(arguments[0])
        if arguments[0] == "--stage":
            stage_custody()
        else:
            run_mode(arguments[0])
    except RecoveryRequired:
        print("RECOVERY_REQUIRED", file=sys.stderr)
        return 3
    except TransactionError:
        print("FAIL", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
