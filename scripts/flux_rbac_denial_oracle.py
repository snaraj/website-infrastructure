#!/usr/bin/env python3
"""Fail-closed, read-only Flux RBAC authorization oracle.

Discovery and authorization are independent evidence dimensions.  This tool
uses fresh API discovery and the live CRD object before it asks the production
kubectl adapter to issue a raw SelfSubjectAccessReview.  It never
applies, patches, deletes, creates, or otherwise mutates a cluster object.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

if __package__:
    from scripts.validate_kubeconfig_snapshot import SnapshotError, parse_snapshot
else:
    from validate_kubeconfig_snapshot import SnapshotError, parse_snapshot


EXIT_MISMATCH = 1
EXIT_UNRESOLVED = 2
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DIRECT_LIVE_BLOCK = (
    "direct checkout invocation is blocked pending an owner-approved trusted "
    "reviewed-blob launcher; no protected kubeconfig was opened"
)
DENIAL_CONTROL_SUBJECT = (
    "system:serviceaccount:flux-system:rbac-oracle-denial-control"
)
SERVICE_ACCOUNT_RE = re.compile(
    r"system:serviceaccount:(?P<namespace>[a-z0-9](?:[-a-z0-9]*[a-z0-9])?):"
    r"(?P<name>[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\Z"
)
DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
DNS_SUBDOMAIN_RE = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
API_VERB_RE = re.compile(r"[a-z]+\Z")
VERBS = frozenset({"create", "delete", "get", "impersonate", "list", "patch", "update"})
AUTHORIZATION_ONLY_VERBS = frozenset({("impersonate", "", "serviceaccounts", None)})
# The oracle is intentionally generic over canonical ServiceAccounts: the
# subject is part of the exact SSAR and receipt, while this exception closes
# only the one unadvertised RBAC identity issue #98 asks it to classify. It is
# not a wildcard over verb, group, resource, or subresource.
AUTHORIZATION_ONLY_RESOURCES = frozenset(
    {
        (
            "update",
            "kustomize.toolkit.fluxcd.io",
            "kustomizations",
            "finalizers",
        ),
    }
)


class OracleError(Exception):
    """A closed oracle state that cannot be treated as authorization evidence."""


@dataclass(frozen=True)
class ResourceIdentity:
    group: str
    version: str
    resource: str
    kind: str
    namespaced: bool
    crd_name: str | None = None
    subresource: str | None = None

    @property
    def group_version(self) -> str:
        return self.version if not self.group else f"{self.group}/{self.version}"

    @property
    def discovery_path(self) -> str:
        if not self.group:
            return f"/api/{self.version}"
        return f"/apis/{self.group}/{self.version}"

    @property
    def discovery_resource(self) -> str:
        if self.subresource is None:
            return self.resource
        return f"{self.resource}/{self.subresource}"


RESOURCE_IDENTITIES = {
    ("", "configmaps"): ResourceIdentity("", "v1", "configmaps", "ConfigMap", True),
    ("", "namespaces"): ResourceIdentity("", "v1", "namespaces", "Namespace", False),
    ("", "pods"): ResourceIdentity("", "v1", "pods", "Pod", True),
    ("", "secrets"): ResourceIdentity("", "v1", "secrets", "Secret", True),
    ("", "serviceaccounts"): ResourceIdentity("", "v1", "serviceaccounts", "ServiceAccount", True),
    ("", "serviceaccounts/token"): ResourceIdentity(
        "", "v1", "serviceaccounts", "TokenRequest", True, subresource="token"
    ),
    ("apps", "deployments"): ResourceIdentity("apps", "v1", "deployments", "Deployment", True),
    ("apps", "replicasets"): ResourceIdentity("apps", "v1", "replicasets", "ReplicaSet", True),
    ("coordination.k8s.io", "leases"): ResourceIdentity("coordination.k8s.io", "v1", "leases", "Lease", True),
    ("rbac.authorization.k8s.io", "clusterrolebindings"): ResourceIdentity(
        "rbac.authorization.k8s.io", "v1", "clusterrolebindings", "ClusterRoleBinding", False
    ),
}

for _group, _resource, _kind in (
    ("source.toolkit.fluxcd.io", "buckets", "Bucket"),
    ("source.toolkit.fluxcd.io", "externalartifacts", "ExternalArtifact"),
    ("source.toolkit.fluxcd.io", "gitrepositories", "GitRepository"),
    ("source.toolkit.fluxcd.io", "helmcharts", "HelmChart"),
    ("source.toolkit.fluxcd.io", "helmrepositories", "HelmRepository"),
    ("source.toolkit.fluxcd.io", "ocirepositories", "OCIRepository"),
    ("kustomize.toolkit.fluxcd.io", "kustomizations", "Kustomization"),
    ("helm.toolkit.fluxcd.io", "helmreleases", "HelmRelease"),
):
    RESOURCE_IDENTITIES[(_group, _resource)] = ResourceIdentity(
        _group,
        "v1" if _resource != "helmreleases" else "v2",
        _resource,
        _kind,
        True,
        f"{_resource}.{_group}",
    )

# Issue #98 names these exact status/finalizer identities in its live
# cross-controller matrix. Keep the registry literal: adding an identity is an
# expansion of what the closed oracle is willing to classify as evidence.
for _group, _resource, _kind, _subresource in (
    ("source.toolkit.fluxcd.io", "buckets", "Bucket", "status"),
    ("kustomize.toolkit.fluxcd.io", "kustomizations", "Kustomization", "status"),
    ("kustomize.toolkit.fluxcd.io", "kustomizations", "Kustomization", "finalizers"),
    ("helm.toolkit.fluxcd.io", "helmreleases", "HelmRelease", "status"),
):
    _base = RESOURCE_IDENTITIES[(_group, _resource)]
    RESOURCE_IDENTITIES[(_group, f"{_resource}/{_subresource}")] = ResourceIdentity(
        _group,
        _base.version,
        _resource,
        _kind,
        True,
        _base.crd_name,
        _subresource,
    )


def canonical_service_account(value: str) -> tuple[str, str]:
    """Return namespace/name only for the exact Kubernetes subject grammar."""

    match = SERVICE_ACCOUNT_RE.fullmatch(value)
    if match is None:
        raise OracleError("subject is not an exact canonical Kubernetes ServiceAccount identity")
    namespace, name = match.group("namespace"), match.group("name")
    if not _valid_namespace(namespace) or not _valid_object_name(name):
        raise OracleError("subject is not an exact canonical Kubernetes ServiceAccount identity")
    return namespace, name


def _valid_namespace(value: str) -> bool:
    return len(value) <= 63 and DNS_LABEL_RE.fullmatch(value) is not None


def _valid_object_name(value: str) -> bool:
    return (
        len(value) <= 253
        and DNS_SUBDOMAIN_RE.fullmatch(value) is not None
        and all(len(label) <= 63 for label in value.split("."))
    )


def service_account_groups(subject: str) -> tuple[str, str, str]:
    namespace, _ = canonical_service_account(subject)
    return (
        "system:serviceaccounts",
        f"system:serviceaccounts:{namespace}",
        "system:authenticated",
    )


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _bytes_fd(descriptor: int, limit: int = 256 * 1024) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    os.lseek(descriptor, 0, os.SEEK_SET)
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = b"".join(chunks)
    if not value or len(value) > limit:
        raise OracleError("held kubeconfig bytes are empty or oversized")
    return value


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _stable_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
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


def _validate_regular_source(metadata: os.stat_result, *, executable: bool) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise OracleError("custody source is not a regular file")
    if metadata.st_nlink != 1:
        raise OracleError("custody source must have exactly one hard link")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise OracleError("custody source owner is outside the root/operator contract")
    if metadata.st_mode & 0o7000:
        raise OracleError("custody source has special permission bits")
    if metadata.st_mode & 0o022:
        raise OracleError("custody source is writable by group or other")
    if executable and not metadata.st_mode & 0o111:
        raise OracleError("custody executable is not executable")
    if not executable and metadata.st_mode & 0o077:
        raise OracleError("kubeconfig custody source must be mode 0600 or stricter")


def _open_absolute_no_follow(path: Path, flags: int) -> tuple[int, int, str]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or not path.is_absolute() or not path.name:
        raise OracleError("host cannot provide no-follow descriptor traversal")
    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    parent = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise OracleError("custody source path is non-canonical")
            next_parent = os.open(component, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        descriptor = os.open(path.name, flags | nofollow, dir_fd=parent)
    except BaseException:
        os.close(parent)
        raise
    return descriptor, parent, path.name


def _private_work() -> Path:
    root = Path("/tmp").resolve(strict=True)
    metadata = root.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or (mode & 0o022 and not mode & stat.S_ISVTX)
    ):
        raise OracleError("fixed private custody root has unsafe provenance")
    work = Path(tempfile.mkdtemp(prefix="flux-rbac-custody.", dir=root))
    os.chmod(work, 0o700)
    created = work.stat()
    if (
        not stat.S_ISDIR(created.st_mode)
        or created.st_uid != os.geteuid()
        or stat.S_IMODE(created.st_mode) != 0o700
    ):
        raise OracleError("private custody directory has unsafe provenance")
    return work


class BoundFile:
    """A source copied once from a held FD and revalidated before every use."""

    def __init__(
        self,
        source: Path,
        *,
        executable: bool,
        expected_digest: str | None = None,
    ) -> None:
        self.source = source
        self.executable = executable
        self.expected_digest = expected_digest
        if executable and (
            not isinstance(expected_digest, str)
            or SHA256_RE.fullmatch(expected_digest) is None
        ):
            raise OracleError("executable custody requires one reviewed SHA-256 pin")
        if os.name != "posix":
            raise OracleError("POSIX descriptor custody requires WSL/Linux or macOS")
        self.work = _private_work()
        self.path = self.work / ("kubectl" if executable else "kubeconfig")
        self.descriptor = -1
        self.digest = ""
        self.kubeconfig_context: str | None = None
        self.kubeconfig_server: str | None = None
        self._retained_path = platform.system() == "Darwin"
        try:
            self._bind()
        except BaseException:
            self.close()
            raise

    def _bind(self) -> None:
        if not self.source.is_absolute():
            raise OracleError("custody source path must be absolute")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = -1
        try:
            source_fd, parent_fd, final_name = _open_absolute_no_follow(self.source, flags)
        except OSError as exc:
            raise OracleError(f"custody source could not be opened without following links: {exc}") from exc
        try:
            opened = os.fstat(source_fd)
            parent_before = os.fstat(parent_fd)
            _validate_regular_source(opened, executable=self.executable)
            try:
                entry = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise OracleError(f"custody source path disappeared after open: {exc}") from exc
            if not _same_inode(opened, entry):
                raise OracleError("custody source path changed while it was opened")
            source_digest = _sha256_fd(source_fd)
            if self.expected_digest is not None and source_digest != self.expected_digest:
                raise OracleError("kubectl executable does not match its reviewed SHA-256 pin")

            # The protected source may be 0600, but the staged image passed to
            # kubectl is 0400 so a same-UID peer cannot reopen it writable via
            # /proc/<pid>/fd between validation and the child's read.
            output_mode = 0o500 if self.executable else 0o400
            output_fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, output_mode)
            try:
                os.lseek(source_fd, 0, os.SEEK_SET)
                while True:
                    chunk = os.read(source_fd, 64 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output_fd, view)
                        view = view[written:]
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            os.chmod(self.path, output_mode)
            self.descriptor = os.open(self.path, flags)
            staged = os.fstat(self.descriptor)
            if not stat.S_ISREG(staged.st_mode) or staged.st_uid != os.geteuid():
                raise OracleError("bound custody image has invalid provenance")
            if stat.S_IMODE(staged.st_mode) != output_mode or staged.st_nlink != 1:
                raise OracleError("bound custody image has invalid mode or link count")
            self.digest = _sha256_fd(self.descriptor)
            if self.digest != source_digest:
                raise OracleError("bound custody image differs from the held source bytes")
            if self.executable:
                prefix = os.read(self.descriptor, 128)
                os.lseek(self.descriptor, 0, os.SEEK_SET)
                if prefix.startswith(b"#!") and not prefix.startswith(b"#!/bin/bash -p\n"):
                    raise OracleError("script executable does not use the fixed /bin/bash -p interpreter")
            else:
                try:
                    snapshot = _bytes_fd(self.descriptor)
                    parse_snapshot(snapshot)
                except SnapshotError as exc:
                    raise OracleError(
                        "held kubeconfig violates the closed flattened embedded-credential schema"
                    ) from exc
                document = json.loads(snapshot)
                self.kubeconfig_context = document["current-context"]
                self.kubeconfig_server = document["clusters"][0]["cluster"]["server"]
            current = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not _same_inode(opened, current)
                or _stable_metadata(opened) != _stable_metadata(os.fstat(source_fd))
                or _stable_metadata(parent_before) != _stable_metadata(os.fstat(parent_fd))
            ):
                raise OracleError("custody source changed during binding")
            if not self._retained_path:
                self.path.unlink()
        finally:
            os.close(source_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def validate(self) -> None:
        if self.descriptor < 0:
            raise OracleError("bound custody descriptor is closed")
        metadata = os.fstat(self.descriptor)
        expected_mode = 0o500 if self.executable else 0o400
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise OracleError("bound custody descriptor provenance changed")
        expected_links = 1 if self._retained_path else 0
        if stat.S_IMODE(metadata.st_mode) != expected_mode or metadata.st_nlink != expected_links:
            raise OracleError("bound custody descriptor mode or link provenance changed")
        if _sha256_fd(self.descriptor) != self.digest:
            raise OracleError("bound custody bytes changed after validation")
        if self._retained_path:
            work = os.stat(self.work, follow_symlinks=False)
            path = os.stat(self.path, follow_symlinks=False)
            if not stat.S_ISDIR(work.st_mode) or stat.S_IMODE(work.st_mode) != 0o700:
                raise OracleError("private custody directory provenance changed")
            if not _same_inode(metadata, path):
                raise OracleError("private custody path no longer names the held descriptor")
        work = os.stat(self.work, follow_symlinks=False)
        if (
            not stat.S_ISDIR(work.st_mode)
            or work.st_uid != os.geteuid()
            or stat.S_IMODE(work.st_mode) != 0o700
        ):
            raise OracleError("private custody directory provenance changed")

    def invocation_path(self) -> str:
        self.validate()
        if self._retained_path:
            return str(self.path)
        return f"/proc/self/fd/{self.descriptor}"

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        shutil.rmtree(self.work, ignore_errors=True)

    def __enter__(self) -> "BoundFile":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class KubectlAdapter:
    """The production kubectl path, executed only from bound custody."""

    def __init__(
        self,
        kubectl: BoundFile,
        kubeconfig: BoundFile,
        context: str,
        server: str,
    ) -> None:
        if kubeconfig.kubeconfig_context != context or kubeconfig.kubeconfig_server != server:
            raise OracleError("held kubeconfig context or API server differs from the reviewed target")
        self.kubectl = kubectl
        self.kubeconfig = kubeconfig
        self.context = context

    def run(
        self,
        arguments: Sequence[str],
        *,
        stdin: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        executable = self.kubectl.invocation_path()
        config = self.kubeconfig.invocation_path()
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        command = [
            executable,
            "--kubeconfig",
            config,
            "--context",
            self.context,
            "--cache-dir",
            str(self.kubeconfig.work / "cache"),
            "--request-timeout=10s",
            *arguments,
        ]
        try:
            completed = subprocess.run(
                command,
                executable=executable,
                env=environment,
                pass_fds=(self.kubectl.descriptor, self.kubeconfig.descriptor),
                input=stdin,
                capture_output=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OracleError(
                "kubectl invocation failed before a bounded response"
            ) from exc
        if len(completed.stdout) > MAX_RESPONSE_BYTES or len(completed.stderr) > MAX_RESPONSE_BYTES:
            raise OracleError("kubectl response exceeded the closed evidence bound")
        return completed


def _clean_output(completed: subprocess.CompletedProcess[bytes], operation: str) -> bytes:
    if completed.returncode != 0:
        raise OracleError(f"{operation} transport/exit failure")
    if completed.stderr:
        raise OracleError(f"{operation} emitted warning or error output")
    return completed.stdout


def _json_output(completed: subprocess.CompletedProcess[bytes], operation: str) -> dict[str, object]:
    payload = _clean_output(completed, operation)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OracleError(f"{operation} returned unparseable JSON") from exc
    if not isinstance(value, dict):
        raise OracleError(f"{operation} returned a non-object JSON document")
    return value


def discover(
    adapter: KubectlAdapter,
    identity: ResourceIdentity,
    required_verb: str,
) -> dict[str, object]:
    """Prove one exact resource identity through uncached raw discovery."""

    if required_verb not in VERBS:
        raise OracleError("discovery verb is outside the reviewed oracle verb set")

    document = _json_output(
        adapter.run(("get", f"--raw={identity.discovery_path}")),
        f"discovery {identity.group_version}",
    )
    type_metadata_is_exact = (
        identity.group == "" and "apiVersion" not in document
    ) or (
        identity.group != "" and document.get("apiVersion") == "v1"
    )
    if not type_metadata_is_exact or document.get("kind") != "APIResourceList":
        raise OracleError("discovery returned the wrong Kubernetes response kind")
    if document.get("groupVersion") != identity.group_version:
        raise OracleError("discovery returned a stale or foreign group/version")
    resources = document.get("resources")
    if not isinstance(resources, list):
        raise OracleError("discovery resources are malformed")
    authorization_only_verb = (
        required_verb,
        identity.group,
        identity.resource,
        identity.subresource,
    ) in AUTHORIZATION_ONLY_VERBS
    authorization_only_resource = (
        required_verb,
        identity.group,
        identity.resource,
        identity.subresource,
    ) in AUTHORIZATION_ONLY_RESOURCES
    # `*/finalizers` is an RBAC identity consulted by Kubernetes admission,
    # not an API subresource advertised in APIResourceList. Resolve its exact
    # base APIResource and CRD before the exact finalizer SSAR; only the
    # separately enumerated ServiceAccount impersonate verb may be absent from
    # the base APIResource verb inventory.
    discovery_resource = (
        identity.resource if authorization_only_resource else identity.discovery_resource
    )
    matches = [
        item
        for item in resources
        if isinstance(item, dict) and item.get("name") == discovery_resource
    ]
    if len(matches) != 1:
        raise OracleError("discovery did not contain exactly one reviewed resource identity")
    match = matches[0]
    if match.get("kind") != identity.kind or match.get("namespaced") is not identity.namespaced:
        raise OracleError("discovery resource kind or scope is foreign")
    verbs = match.get("verbs")
    if (
        not isinstance(verbs, list)
        or any(
            not isinstance(item, str) or API_VERB_RE.fullmatch(item) is None
            for item in verbs
        )
        or len(set(verbs)) != len(verbs)
        or (required_verb not in verbs and not authorization_only_verb)
    ):
        raise OracleError("discovery does not support the exact reviewed request verb")

    if identity.crd_name is not None:
        crd = _json_output(
            adapter.run(
                (
                    "get",
                    "--raw=/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"
                    + identity.crd_name,
                )
            ),
            f"CRD identity {identity.crd_name}",
        )
        spec = crd.get("spec")
        status = crd.get("status")
        metadata = crd.get("metadata")
        if (
            crd.get("apiVersion") != "apiextensions.k8s.io/v1"
            or crd.get("kind") != "CustomResourceDefinition"
            or not isinstance(metadata, dict)
            or metadata.get("name") != identity.crd_name
            or not isinstance(spec, dict)
            or spec.get("group") != identity.group
            or spec.get("scope") != ("Namespaced" if identity.namespaced else "Cluster")
        ):
            raise OracleError("live CRD identity is malformed or foreign")
        names = spec.get("names")
        versions = spec.get("versions")
        if (
            not isinstance(names, dict)
            or names.get("plural") != identity.resource
            or names.get("kind") != identity.kind
            or not isinstance(versions, list)
            or [
                item.get("name")
                for item in versions
                if isinstance(item, dict) and item.get("served") is True
            ]
            != [identity.version]
            or [
                item.get("name")
                for item in versions
                if isinstance(item, dict) and item.get("storage") is True
            ]
            != [identity.version]
        ):
            raise OracleError("live CRD names or served/storage version are foreign")
        conditions = status.get("conditions") if isinstance(status, dict) else None
        if not isinstance(conditions, list):
            raise OracleError("live CRD conditions are malformed")
        for condition_type in ("Established", "NamesAccepted"):
            matches = [
                item
                for item in conditions
                if isinstance(item, dict) and item.get("type") == condition_type
            ]
            if len(matches) != 1 or matches[0].get("status") != "True":
                raise OracleError(
                    "live CRD is not freshly Established with accepted names"
                )
    return {
        "state": "RESOLVED",
        "groupVersion": identity.group_version,
        "resource": identity.discovery_resource,
        "kind": identity.kind,
        "namespaced": identity.namespaced,
        "crdName": identity.crd_name,
        "verb": required_verb,
        "verbEvidence": (
            "AUTHORIZATION_ONLY"
            if authorization_only_verb or authorization_only_resource
            else "DISCOVERY"
        ),
    }


def authorize(
    adapter: KubectlAdapter,
    *,
    subject: str,
    verb: str,
    identity: ResourceIdentity,
    namespace: str | None,
    name: str | None,
) -> str:
    """Issue and validate one exact raw SelfSubjectAccessReview."""

    impersonation_groups = service_account_groups(subject)
    attributes = {
        "verb": verb,
        "version": identity.version,
        "resource": identity.resource,
    }
    if identity.subresource is not None:
        attributes["subresource"] = identity.subresource
    if identity.group:
        attributes["group"] = identity.group
    if namespace is not None:
        attributes["namespace"] = namespace
    if name is not None:
        attributes["name"] = name
    request = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": {"resourceAttributes": attributes},
    }
    payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    response = _json_output(
        adapter.run(
            (
                "create",
                "--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                "-f",
                "-",
                f"--as={subject}",
                *(f"--as-group={group}" for group in impersonation_groups),
            ),
            stdin=payload,
        ),
        "authorization SelfSubjectAccessReview",
    )
    spec = response.get("spec")
    status = response.get("status")
    evaluation_error = status.get("evaluationError") if isinstance(status, dict) else None
    if (
        response.get("apiVersion") != "authorization.k8s.io/v1"
        or response.get("kind") != "SelfSubjectAccessReview"
        or not isinstance(spec, dict)
        or spec != request["spec"]
        or not isinstance(status, dict)
        or type(status.get("allowed")) is not bool
        or ("denied" in status and type(status["denied"]) is not bool)
        or evaluation_error not in (None, "")
        or (status["allowed"] is True and status.get("denied") is True)
    ):
        raise OracleError("authorization response did not exactly echo the reviewed request")
    return "ALLOWED" if status["allowed"] else "DENIED"


def run_oracle(
    adapter: KubectlAdapter,
    *,
    subject: str,
    verb: str,
    group: str,
    resource: str,
    namespace: str | None,
    name: str | None,
    all_namespaces: bool = False,
    expected: str,
) -> tuple[int, dict[str, object]]:
    """Run positive controls and one exact reviewed request."""

    canonical_service_account(subject)
    if type(all_namespaces) is not bool or expected not in {"ALLOWED", "DENIED"}:
        raise OracleError("request scope or expected state is outside the closed contract")
    if verb not in VERBS:
        raise OracleError("request verb is outside the reviewed oracle verb set")
    if namespace is not None and not _valid_namespace(namespace):
        raise OracleError("request namespace is malformed")
    if name is not None and not _valid_object_name(name):
        raise OracleError("request name is malformed")
    try:
        requested = RESOURCE_IDENTITIES[(group, resource)]
    except KeyError as exc:
        raise OracleError("request resource is outside the reviewed oracle identity set") from exc
    if requested.namespaced and ((namespace is None) == (not all_namespaces)):
        raise OracleError("namespaced request requires exactly one of namespace or all-namespaces")
    if not requested.namespaced and (namespace is not None or all_namespaces):
        raise OracleError("cluster-scoped request must not carry a namespace scope")
    controls = (
        (
            "builtin-authorizer",
            "system:serviceaccount:flux-system:source-controller",
            "create",
            RESOURCE_IDENTITIES[("coordination.k8s.io", "leases")],
            "flux-system",
            None,
            "ALLOWED",
        ),
        (
            "flux-authorizer",
            "system:serviceaccount:flux-system:kustomize-controller",
            "list",
            RESOURCE_IDENTITIES[("kustomize.toolkit.fluxcd.io", "kustomizations")],
            "flux-system",
            None,
            "ALLOWED",
        ),
        (
            "inert-denial",
            DENIAL_CONTROL_SUBJECT,
            "get",
            RESOURCE_IDENTITIES[("", "secrets")],
            "kube-system",
            None,
            "DENIED",
        ),
    )
    discovery: dict[tuple[str, str, str], dict[str, object]] = {}
    for identity, discovery_verb in tuple((item[3], item[2]) for item in controls) + (
        (requested, verb),
    ):
        key = (identity.group, identity.discovery_resource, discovery_verb)
        if key not in discovery:
            discovery[key] = discover(adapter, identity, discovery_verb)

    control_receipts = []
    for label, control_subject, control_verb, identity, control_namespace, control_name, control_expected in controls:
        observed = authorize(
            adapter,
            subject=control_subject,
            verb=control_verb,
            identity=identity,
            namespace=control_namespace,
            name=control_name,
        )
        control_receipts.append(
            {
                "name": label,
                "discovery": discovery[
                    (identity.group, identity.discovery_resource, control_verb)
                ],
                "authorization": observed,
            }
        )
        if observed != control_expected:
            return EXIT_MISMATCH, {
                "discovery": discovery[
                    (requested.group, requested.discovery_resource, verb)
                ],
                "authorization": "UNRESOLVED",
                "controls": control_receipts,
                "result": "FAIL",
            }

    observed = authorize(
        adapter,
        subject=subject,
        verb=verb,
        identity=requested,
        namespace=namespace,
        name=name,
    )
    receipt = {
        "request": {
            "subject": subject,
            "verb": verb,
            "apiGroup": group,
            "resource": resource,
            "subresource": requested.subresource,
            "namespace": namespace,
            "name": name,
            "allNamespaces": all_namespaces,
        },
        "discovery": discovery[(requested.group, requested.discovery_resource, verb)],
        "authorization": observed,
        "expected": expected,
        "controls": control_receipts,
        "result": "PASS" if observed == expected else "FAIL",
    }
    return (0 if observed == expected else EXIT_MISMATCH), receipt


def _pin_key() -> str:
    if platform.system() != "Linux":
        raise OracleError("live custody is Linux/WSL-only; native Windows/macOS runs portable tests only")
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "KUBECTL_LINUX_AMD64_SHA256"
    if machine in {"aarch64", "arm64"}:
        return "KUBECTL_ARM64_SHA256"
    raise OracleError("host architecture has no reviewed kubectl executable pin")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--verb", required=True)
    parser.add_argument("--api-group", default="")
    parser.add_argument("--resource", required=True)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--namespace")
    scope.add_argument("--all-namespaces", action="store_true")
    parser.add_argument("--name")
    parser.add_argument("--expect", choices=("ALLOWED", "DENIED"), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _parser().parse_args(argv)
    # A mutable checkout script cannot establish its own stage-zero trust.  The
    # protocol implementation is executable only by the hermetic tests until a
    # separately reviewed launcher supplies this exact blob from held custody.
    print(
        json.dumps(
            {
                "authorization": "UNRESOLVED",
                "discovery": "UNRESOLVED",
                "reason": DIRECT_LIVE_BLOCK,
                "result": "UNRESOLVED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return EXIT_UNRESOLVED


if __name__ == "__main__":
    sys.exit(main())
