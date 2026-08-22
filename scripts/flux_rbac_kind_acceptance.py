#!/usr/bin/env python3
"""Isolated acceptance for the issue-98/186 Flux RBAC recut.

The wholly self-created kind cluster is the test substrate.  The program
installs the real pinned controllers, exercises the stock and final
authorizers, performs real Helm actions, and removes only its owned cluster,
registry, Docker network, image, and kubeconfig before writing a bounded
receipt.  It never accepts an existing kubeconfig or cluster name and grants
no authority to mutate a protected cluster.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


ROOT_ENVIRONMENT = "FLUX_RBAC_ACCEPTANCE_REPOSITORY_ROOT"
LAUNCH_ROOT_ENVIRONMENT = "FLUX_RBAC_ACCEPTANCE_LAUNCH_ROOT"
HANDOFF_ENVIRONMENT = "FLUX_RBAC_ACCEPTANCE_HANDOFF"
_configured_root = os.environ.pop(ROOT_ENVIRONMENT, None)
_configured_launch_root = os.environ.pop(LAUNCH_ROOT_ENVIRONMENT, None)
_configured_handoff = os.environ.pop(HANDOFF_ENVIRONMENT, None)
ROOT = (
    Path(_configured_root).resolve()
    if _configured_root is not None
    else Path(__file__).resolve().parents[1]
)
FIXTURE_ROOT = ROOT / "tests" / "kubernetes" / "flux-rbac-kind"
VERSIONS_FILE = ROOT / "versions.env"
CONTROLLERS_ROOT = ROOT / "kubernetes" / "flux-system" / "controllers"
STOCK_COMPONENTS = CONTROLLERS_ROOT / "gotk-components.yaml"
ACCESS_MANIFEST = ROOT / "kubernetes" / "flux-system" / "access.yaml"
VERSIONS_RELATIVE = "versions.env"
CONTROLLERS_RELATIVE = "kubernetes/flux-system/controllers"
STOCK_COMPONENTS_RELATIVE = f"{CONTROLLERS_RELATIVE}/gotk-components.yaml"
ACCESS_MANIFEST_RELATIVE = "kubernetes/flux-system/access.yaml"
FIXTURE_RELATIVE = "tests/kubernetes/flux-rbac-kind"
SNAPSHOT_INPUTS = (
    "scripts/flux_rbac_kind_acceptance.py",
    VERSIONS_RELATIVE,
    ACCESS_MANIFEST_RELATIVE,
    STOCK_COMPONENTS_RELATIVE,
    f"{CONTROLLERS_RELATIVE}/kustomization.yaml",
    f"{CONTROLLERS_RELATIVE}/per-controller-rbac.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/allow-egress.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/cluster-reconciler.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/crd-controller-binding.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/crd-controller-role.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/helm-controller.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/kustomize-controller.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/namespace.yaml",
    f"{CONTROLLERS_RELATIVE}/patches/source-controller.yaml",
    f"{FIXTURE_RELATIVE}/chart/Chart.yaml",
    f"{FIXTURE_RELATIVE}/chart/values.yaml",
    f"{FIXTURE_RELATIVE}/chart/templates/deployment.yaml",
    f"{FIXTURE_RELATIVE}/workload/Dockerfile",
    f"{FIXTURE_RELATIVE}/workload/main.go",
)

# Official Docker Distribution image.  The manifest-list digest, rather than a
# tag, makes the one extra acceptance dependency immutable on both supported
# host architectures.
REGISTRY_IMAGE = (
    "registry:2.8.3@sha256:"
    "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)
OWNER_LABEL = "dev.snaraj.flux-rbac-acceptance-owner"
LOOPBACK = "127.0.0.1"
RFC1918_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
FINAL_NETWORK_POLICY_NAMES = frozenset(
    {
        "allow-egress",
        "allow-scraping",
        "allow-webhooks",
        "flux-rbac-acceptance-egress",
    }
)
CANONICAL_ORIGIN_URLS = (
    "https://github.com/snaraj/website-infrastructure.git",
)
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
REQUIRED_PINS = (
    "KUBERNETES_VERSION",
    "KIND_VERSION",
    "KIND_NODE_IMAGE",
    "HELM_VERSION",
    "GO_VERSION",
    "FLUX_VERSION",
    "FLUX_SOURCE_CONTROLLER_IMAGE",
    "FLUX_KUSTOMIZE_CONTROLLER_IMAGE",
    "FLUX_HELM_CONTROLLER_IMAGE",
)
TENANTS = ("cloudflare-public", "naranjo-online", "lidersea-com")
TENANT_CROSS_TARGET = {
    "cloudflare-public": "naranjo-online",
    "naranjo-online": "lidersea-com",
    "lidersea-com": "cloudflare-public",
}
TOOL_NAMES = ("python", "git", "docker", "kind", "kubectl", "helm", "go")
TOOL_IDENTITY_KEYS = {
    "path",
    "sha256",
    "device",
    "inode",
    "size",
    "mtimeNs",
    "uid",
}
TOOL_RECEIPT_KEYS = {
    key
    for name in TOOL_NAMES
    for key in (name, f"{name}Sha256", f"{name}Device", f"{name}Inode")
} | {"dockerContextSha256", "dockerEndpointSha256", "dockerDaemonIdSha256"}
DOCKER_CUSTODY_KEYS = {"context", "endpoint", "daemonId"}
JOURNAL_SCHEMA = 4
JOURNAL_KEYS = {
    "schemaVersion",
    "owner",
    "expectedCommit",
    "tempRoot",
    "tempParent",
    "cluster",
    "network",
    "registry",
    "kubeconfig",
    "kubeconfigSha256",
    "kubeconfigServer",
    "workloadImage",
    "networkCreated",
    "registryCreated",
    "clusterCreated",
    "imageCreated",
    "toolIdentities",
    "dockerCustody",
    "state",
    "receiptPath",
    "receiptSha256",
    "receiptCleanup",
}
PASS_CLEANUP_KEYS = {
    "clusterAbsent",
    "registryAbsent",
    "networkAbsent",
    "imageAbsent",
    "kubeconfigAbsent",
    "temporaryRootAbsent",
    "journalRetainedUntilReceipt",
}
PASS_EVIDENCE_KEYS = {
    "priorOwnedResidueRecovered",
    "inputInventorySha256",
    "stockCrossingsAllowed",
    "finalOwnedAllowed",
    "finalCrossingsDenied",
    "generalDenials",
    "tenantReadsAllowed",
    "tenantBoundariesDenied",
    "controllerInitialCreation",
    "kustomizeFinalRbacColdStart",
    "helmSecretColdStart",
    "readinessNegatives",
    "releaseLifecycle",
}
INITIAL_ZERO_CONTROLLERS = ("kustomize-controller", "helm-controller")
CONTROLLER_ZERO_CHANGED_FIELDS = tuple(
    f"apps/v1 Deployment flux-system/{name} spec.replicas"
    for name in INITIAL_ZERO_CONTROLLERS
)
SCOPE_RECEIPT = {
    "evidenceClass": "owner-controlled-local-disposable-acceptance",
    "stageZeroProvenanceClaimed": False,
    "promotionAuthorized": False,
    "cluster": "disposable-kind-only",
    "acceptanceWorkloadLifecycle": "install-upgrade-fail-rollback",
    "controllerColdStarts": "initial-creation-only",
    "protectedClusterMutationAuthorized": False,
    "protectedKubeconfigInputAccepted": False,
    "protectedOrForeignWorkloadMutationAuthorized": False,
    "hostCleanup": "harness-owned-resources-only",
}


def cluster_name(run_id: str) -> str:
    return f"fra-{run_id}"


def network_name(run_id: str) -> str:
    return f"fra-network-{run_id}"


def registry_name(run_id: str) -> str:
    return f"fra-registry-{run_id}"


def registry_publish_spec() -> str:
    """Request a Docker-assigned loopback port without the empty-port form."""

    # Docker 24 can report a random HostPort for the empty host-port form
    # without actually opening the host listener. An explicit zero preserves
    # daemon allocation and makes the resulting inspected port reachable.
    return f"{LOOPBACK}:0:5000"


def private_ipv4_host_cidr(value: object) -> str:
    """Return one RFC 1918 IPv4 host route or fail closed."""

    if not isinstance(value, str):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID") from None
    if (
        address.version != 4
        or not any(address in network for network in RFC1918_IPV4_NETWORKS)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    return f"{address.compressed}/32"


def service_private_ipv4(
    document: Mapping[str, object],
    *,
    namespace: str,
    name: str,
    required_ports: Sequence[tuple[str, int, str, int | str]],
) -> str:
    """Bind a synthetic Service identity, private address, and required ports."""

    metadata = document.get("metadata")
    spec = document.get("spec")
    if (
        not isinstance(metadata, dict)
        or metadata.get("namespace") != namespace
        or metadata.get("name") != name
        or not isinstance(spec, dict)
        or spec.get("type") != "ClusterIP"
        or spec.get("ipFamilies") != ["IPv4"]
        or spec.get("ipFamilyPolicy") != "SingleStack"
    ):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    cluster_ip = spec.get("clusterIP")
    if spec.get("clusterIPs") != [cluster_ip]:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    ports = spec.get("ports")
    if not isinstance(ports, list) or not ports:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    if any(not isinstance(item, dict) for item in ports):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    observed = [
        (
            item.get("name"),
            item.get("port"),
            item.get("protocol", "TCP"),
            item.get("targetPort", item.get("port")),
        )
        for item in ports
    ]
    required = set(required_ports)
    if (
        len(observed) != len(set(observed))
        or set(observed) != required
    ):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    return private_ipv4_host_cidr(cluster_ip).removesuffix("/32")


def api_backend_private_ipv4s(document: Mapping[str, object]) -> tuple[str, ...]:
    """Extract the bounded ready IPv4 backend set for the synthetic API Service."""

    items = document.get("items")
    if not isinstance(items, list) or not items or len(items) > 16:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    addresses: set[str] = set()
    address_count = 0
    for item in items:
        if not isinstance(item, dict) or item.get("addressType") != "IPv4":
            raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
        metadata = item.get("metadata")
        ports = item.get("ports")
        endpoints = item.get("endpoints")
        if (
            not isinstance(metadata, dict)
            or metadata.get("namespace") != "default"
            or not isinstance(metadata.get("labels"), dict)
            or metadata["labels"].get("kubernetes.io/service-name") != "kubernetes"
            or not isinstance(ports, list)
            or len(ports) != 1
            or not isinstance(ports[0], dict)
            or ports[0].get("name") != "https"
            or ports[0].get("port") != 6443
            or ports[0].get("protocol", "TCP") != "TCP"
            or not isinstance(endpoints, list)
            or not endpoints
        ):
            raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
            conditions = endpoint.get("conditions", {})
            endpoint_addresses = endpoint.get("addresses")
            if (
                not isinstance(conditions, dict)
                or conditions.get("ready") is not True
                or conditions.get("terminating") is True
            ):
                raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
            if not isinstance(endpoint_addresses, list) or not endpoint_addresses:
                raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
            for address in endpoint_addresses:
                canonical = private_ipv4_host_cidr(address).removesuffix("/32")
                if canonical != address:
                    raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
                addresses.add(canonical)
                address_count += 1
    if (
        not addresses
        or len(addresses) > 16
        or len(addresses) != address_count
    ):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    return tuple(sorted(addresses))


def acceptance_egress_policy(
    *,
    owner: str,
    api_service_ip: str,
    api_backend_ips: Sequence[str],
    dns_service_ip: str,
    source_service_ip: str,
    registry_service_ip: str,
    registry_backend_ip: str,
) -> dict[str, object]:
    """Build only the flows needed by the disposable real-controller test."""

    if re.fullmatch(r"[0-9a-f]{32}", owner) is None:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    if not api_backend_ips or len(api_backend_ips) > 16:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    api_backends = sorted(
        {private_ipv4_host_cidr(address) for address in api_backend_ips}
    )
    if len(api_backends) != len(api_backend_ips):
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    registry_peers = sorted(
        {
            private_ipv4_host_cidr(registry_service_ip),
            private_ipv4_host_cidr(registry_backend_ip),
        }
    )
    if len(registry_peers) != 2:
        raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "flux-rbac-acceptance-egress",
            "namespace": "flux-system",
            "labels": {OWNER_LABEL: owner},
        },
        "spec": {
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/part-of": "flux"}
            },
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [
                        {
                            "ipBlock": {
                                "cidr": private_ipv4_host_cidr(api_service_ip)
                            }
                        }
                    ],
                    "ports": [{"port": 443, "protocol": "TCP"}],
                },
                {
                    "to": [
                        {"ipBlock": {"cidr": cidr}} for cidr in api_backends
                    ],
                    "ports": [{"port": 6443, "protocol": "TCP"}],
                },
                {
                    "to": [
                        {
                            "ipBlock": {
                                "cidr": private_ipv4_host_cidr(dns_service_ip)
                            }
                        },
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": "kube-system"
                                }
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        },
                    ],
                    "ports": [
                        {"port": 53, "protocol": "UDP"},
                        {"port": 53, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [
                        {
                            "ipBlock": {
                                "cidr": private_ipv4_host_cidr(source_service_ip)
                            }
                        }
                    ],
                    "ports": [{"port": 80, "protocol": "TCP"}],
                },
                {
                    "to": [
                        {"podSelector": {"matchLabels": {"app": "source-controller"}}}
                    ],
                    "ports": [{"port": 9090, "protocol": "TCP"}],
                },
                {
                    "to": [
                        {"ipBlock": {"cidr": cidr}} for cidr in registry_peers
                    ],
                    "ports": [{"port": 5000, "protocol": "TCP"}],
                },
            ],
        },
    }


def validate_final_network_policy_inventory(
    document: Mapping[str, object],
    *,
    owner: str,
    acceptance_spec: object,
) -> None:
    """Prove the complete final Flux NetworkPolicy set and exact rule shapes."""

    if (
        re.fullmatch(r"[0-9a-f]{32}", owner) is None
        or not isinstance(acceptance_spec, dict)
        or document.get("apiVersion") != "v1"
        or document.get("kind") != "List"
    ):
        raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
    items = document.get("items")
    if not isinstance(items, list) or len(items) != len(FINAL_NETWORK_POLICY_NAMES):
        raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
    observed_specs: dict[str, object] = {}
    for item in items:
        if (
            not isinstance(item, dict)
            or item.get("apiVersion") != "networking.k8s.io/v1"
            or item.get("kind") != "NetworkPolicy"
        ):
            raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("namespace") != "flux-system":
            raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
        name = metadata.get("name")
        if not isinstance(name, str) or name in observed_specs:
            raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
        if name == "flux-rbac-acceptance-egress":
            if metadata.get("labels") != {OWNER_LABEL: owner}:
                raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
        observed_specs[name] = item.get("spec")
    expected_specs: dict[str, object] = {
        "allow-egress": {
            "ingress": [{"from": [{"podSelector": {}}]}],
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
        "allow-scraping": {
            "ingress": [
                {
                    "from": [{"namespaceSelector": {}}],
                    "ports": [{"port": 8080, "protocol": "TCP"}],
                }
            ],
            "podSelector": {},
            "policyTypes": ["Ingress"],
        },
        "allow-webhooks": {
            "ingress": [{"from": [{"namespaceSelector": {}}]}],
            "podSelector": {
                "matchLabels": {"app": "notification-controller"}
            },
            "policyTypes": ["Ingress"],
        },
        "flux-rbac-acceptance-egress": acceptance_spec,
    }
    if set(observed_specs) != FINAL_NETWORK_POLICY_NAMES or observed_specs != expected_specs:
        raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")


class AcceptanceError(RuntimeError):
    """A fail-closed state whose code is safe to expose in the receipt."""

    def __init__(self, code: str) -> None:
        if SAFE_CODE_RE.fullmatch(code) is None:
            raise ValueError("acceptance error code is not receipt-safe")
        super().__init__(code)
        self.code = code


class State(str, Enum):
    NEW = "new"
    PREFLIGHT = "preflight"
    ALLOCATED = "allocated"
    INFRASTRUCTURE = "infrastructure"
    ARTIFACTS = "artifacts"
    STOCK = "stock"
    FINAL_RBAC = "final-rbac"
    COLD_START = "cold-start"
    READINESS_NEGATIVES = "readiness-negatives"
    RELEASE = "release"
    COMPLETE = "complete"


STATE_ORDER = tuple(State)


@dataclass
class StateMachine:
    current: State = State.NEW

    def advance(self, expected: State, target: State) -> None:
        if self.current is not expected:
            raise AcceptanceError("STATE_ORDER_INVALID")
        if STATE_ORDER.index(target) != STATE_ORDER.index(expected) + 1:
            raise AcceptanceError("STATE_TRANSITION_INVALID")
        self.current = target


@dataclass(frozen=True)
class AccessRow:
    label: str
    subject: str
    verb: str
    group: str
    resource: str
    subresource: str | None = None
    namespace: str | None = None


def controller_subject(name: str) -> str:
    return f"system:serviceaccount:flux-system:{name}"


def tenant_subject(namespace: str) -> str:
    return f"system:serviceaccount:{namespace}:helm-reconciler"


SOURCE = controller_subject("source-controller")
KUSTOMIZE = controller_subject("kustomize-controller")
HELM = controller_subject("helm-controller")


# This is the literal issue-98 crossing matrix from the narrowing runbook.
CROSSING_ROWS = (
    AccessRow("source-kustomization", SOURCE, "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    AccessRow("source-kustomization-status", SOURCE, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "status"),
    AccessRow("source-kustomization-finalizers", SOURCE, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "finalizers"),
    AccessRow("source-helmrelease", SOURCE, "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    AccessRow("source-helmrelease-status", SOURCE, "update", "helm.toolkit.fluxcd.io", "helmreleases", "status"),
    AccessRow("source-create-helmchart", SOURCE, "create", "source.toolkit.fluxcd.io", "helmcharts"),
    AccessRow("source-delete-helmchart", SOURCE, "delete", "source.toolkit.fluxcd.io", "helmcharts"),
    AccessRow("kustomize-helmrelease", KUSTOMIZE, "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    AccessRow("kustomize-helmrelease-status", KUSTOMIZE, "update", "helm.toolkit.fluxcd.io", "helmreleases", "status"),
    AccessRow("kustomize-ocirepository", KUSTOMIZE, "patch", "source.toolkit.fluxcd.io", "ocirepositories"),
    AccessRow("kustomize-gitrepository", KUSTOMIZE, "patch", "source.toolkit.fluxcd.io", "gitrepositories"),
    AccessRow("kustomize-create-helmchart", KUSTOMIZE, "create", "source.toolkit.fluxcd.io", "helmcharts"),
    AccessRow("helm-kustomization", HELM, "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    AccessRow("helm-kustomization-status", HELM, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "status"),
    AccessRow("helm-kustomization-finalizers", HELM, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "finalizers"),
    AccessRow("helm-gitrepository", HELM, "patch", "source.toolkit.fluxcd.io", "gitrepositories"),
    AccessRow("helm-ocirepository", HELM, "patch", "source.toolkit.fluxcd.io", "ocirepositories"),
    AccessRow("helm-bucket-status", HELM, "update", "source.toolkit.fluxcd.io", "buckets", "status"),
)

OWNED_ROWS = (
    AccessRow("source-owned-main", SOURCE, "patch", "source.toolkit.fluxcd.io", "gitrepositories"),
    AccessRow("source-owned-status", SOURCE, "update", "source.toolkit.fluxcd.io", "gitrepositories", "status"),
    AccessRow("kustomize-owned-main", KUSTOMIZE, "patch", "kustomize.toolkit.fluxcd.io", "kustomizations"),
    AccessRow("kustomize-owned-status", KUSTOMIZE, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "status"),
    AccessRow("kustomize-owned-finalizers", KUSTOMIZE, "update", "kustomize.toolkit.fluxcd.io", "kustomizations", "finalizers"),
    AccessRow("helm-owned-main", HELM, "patch", "helm.toolkit.fluxcd.io", "helmreleases"),
    AccessRow("helm-owned-status", HELM, "update", "helm.toolkit.fluxcd.io", "helmreleases", "status"),
    AccessRow("helm-owned-create-chart", HELM, "create", "source.toolkit.fluxcd.io", "helmcharts"),
    AccessRow("helm-owned-delete-chart", HELM, "delete", "source.toolkit.fluxcd.io", "helmcharts"),
)

GENERAL_DENIED_ROWS = (
    AccessRow("kustomize-kube-system-deployment", KUSTOMIZE, "create", "apps", "deployments", namespace="kube-system"),
    AccessRow("kustomize-kube-system-secret", KUSTOMIZE, "get", "", "secrets", namespace="kube-system"),
    AccessRow("kustomize-clusterrolebinding", KUSTOMIZE, "create", "rbac.authorization.k8s.io", "clusterrolebindings"),
    AccessRow("kustomize-namespace", KUSTOMIZE, "create", "", "namespaces"),
    AccessRow("helm-token", HELM, "create", "", "serviceaccounts", "token", "kube-system"),
    AccessRow("helm-secret-write", HELM, "update", "", "secrets", namespace="flux-system"),
)

HELM_SECRET_ROWS = tuple(
    AccessRow(f"helm-secret-{verb}", HELM, verb, "", "secrets")
    for verb in ("get", "list", "watch")
)


def tenant_rows() -> tuple[tuple[AccessRow, ...], tuple[AccessRow, ...]]:
    allowed: list[AccessRow] = []
    denied: list[AccessRow] = []
    for namespace in TENANTS:
        subject = tenant_subject(namespace)
        for resource, group in (("pods", ""), ("replicasets", "apps")):
            for verb in ("get", "list", "watch"):
                allowed.append(
                    AccessRow(
                        f"{namespace}-{resource}-{verb}",
                        subject,
                        verb,
                        group,
                        resource,
                        namespace=namespace,
                    )
                )
        target = TENANT_CROSS_TARGET[namespace]
        denied.extend(
            (
                AccessRow(f"{namespace}-pod-write", subject, "update", "", "pods", namespace=namespace),
                AccessRow(f"{namespace}-replicaset-write", subject, "delete", "apps", "replicasets", namespace=namespace),
                AccessRow(f"{namespace}-cross-pod", subject, "get", "", "pods", namespace=target),
                AccessRow(f"{namespace}-cross-replicaset", subject, "list", "apps", "replicasets", namespace=target),
            )
        )
    return tuple(allowed), tuple(denied)


TENANT_ALLOWED_ROWS, TENANT_DENIED_ROWS = tenant_rows()


def parse_versions_payload(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise AcceptanceError("VERSION_FILE_INVALID") from None
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise AcceptanceError("VERSION_FILE_INVALID")
        key, value = line.split("=", 1)
        if key in values or not key or not value:
            raise AcceptanceError("VERSION_FILE_INVALID")
        values[key] = value
    if any(key not in values for key in REQUIRED_PINS):
        raise AcceptanceError("VERSION_PIN_MISSING")
    for key in ("KIND_NODE_IMAGE", "FLUX_SOURCE_CONTROLLER_IMAGE", "FLUX_KUSTOMIZE_CONTROLLER_IMAGE", "FLUX_HELM_CONTROLLER_IMAGE"):
        if "@sha256:" not in values[key]:
            raise AcceptanceError("IMAGE_PIN_MUTABLE")
    return values


def parse_versions(path: Path = VERSIONS_FILE) -> dict[str, str]:
    try:
        payload = path.read_bytes()
    except OSError:
        raise AcceptanceError("VERSION_FILE_INVALID") from None
    return parse_versions_payload(payload)


def clean_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the minimum host environment, dropping credential-shaped keys."""

    keep = {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in keep}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "KUBECONFIG": "",
        }
    )
    if extra:
        if {
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_NO_LAZY_FETCH",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_OPTIONAL_LOCKS",
            "GIT_TERMINAL_PROMPT",
            "SSH_AUTH_SOCK",
            "KUBECONFIG",
        } & set(extra):
            raise AcceptanceError("ENVIRONMENT_ROUTE_OVERRIDE")
        environment.update(extra)
    return environment


def python_version() -> str:
    return "Python {}.{}.{}".format(
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )


def require_isolated_interpreter() -> None:
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or not sys.dont_write_bytecode
    ):
        raise AcceptanceError("INTERPRETER_MODE_INVALID")


def default_journal_path() -> Path:
    configured = os.environ.get("XDG_STATE_HOME")
    base = Path(configured) if configured else Path.home() / ".local" / "state"
    if not base.is_absolute():
        raise AcceptanceError("STATE_HOME_NOT_ABSOLUTE")
    current = Path(base.anchor)
    for component in base.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError:
            raise AcceptanceError("STATE_HOME_UNSAFE") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise AcceptanceError("STATE_HOME_UNSAFE")
    try:
        resolved = base.resolve(strict=False)
    except OSError:
        raise AcceptanceError("STATE_HOME_UNSAFE") from None
    if (
        resolved == Path(resolved.anchor)
        or resolved == ROOT
        or ROOT in resolved.parents
    ):
        raise AcceptanceError("STATE_HOME_UNSAFE")
    return resolved / "website-infrastructure" / "flux-rbac-kind-acceptance.json"


def allowed_temp_parent() -> Path:
    return Path(os.environ.get("TMPDIR", tempfile.gettempdir())).resolve()


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def kubeconfig_binding(path: Path, cluster: str) -> tuple[str, str]:
    """Bind a mode-0600 kubeconfig to this run's loopback kind endpoint."""

    if path.is_symlink():
        raise AcceptanceError("OWNED_KUBECONFIG_INVALID")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            payload = bytearray()
            while len(payload) <= 1024 * 1024:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                payload.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise AcceptanceError("OWNED_KUBECONFIG_INVALID") from None
    if (
        len(payload) > 1024 * 1024
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise AcceptanceError("OWNED_KUBECONFIG_INVALID")
    try:
        text = bytes(payload).decode("utf-8")
    except UnicodeDecodeError:
        raise AcceptanceError("OWNED_KUBECONFIG_INVALID") from None
    servers = re.findall(r"(?m)^[ \t]*server:[ \t]*(\S+)[ \t]*$", text)
    contexts = re.findall(r"(?m)^current-context:[ \t]*(\S+)[ \t]*$", text)
    if len(servers) != 1 or len(contexts) != 1 or contexts[0] != f"kind-{cluster}":
        raise AcceptanceError("OWNED_KUBECONFIG_INVALID")
    match = re.fullmatch(r"https://127\.0\.0\.1:([1-9][0-9]{0,4})", servers[0])
    if match is None or int(match.group(1)) > 65535:
        raise AcceptanceError("OWNED_KUBECONFIG_ENDPOINT_INVALID")
    return (
        f"sha256:{hashlib.sha256(payload).hexdigest()}",
        servers[0],
    )


@dataclass(frozen=True)
class ToolIdentity:
    path: str
    sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    uid: int

    @classmethod
    def capture(cls, path: Path) -> "ToolIdentity":
        if not path.is_absolute() or path.is_symlink():
            raise AcceptanceError("TOOL_PATH_INVALID")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid not in {0, os.geteuid()}
                    or stat.S_IMODE(before.st_mode) & 0o022
                    or not stat.S_IMODE(before.st_mode) & 0o100
                ):
                    raise AcceptanceError("TOOL_PATH_UNTRUSTED")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except AcceptanceError:
            raise
        except OSError:
            raise AcceptanceError("TOOL_PATH_INVALID") from None
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise AcceptanceError("TOOL_IDENTITY_CHANGED")
        return cls(
            path=str(path),
            sha256=f"sha256:{digest.hexdigest()}",
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            mtime_ns=before.st_mtime_ns,
            uid=before.st_uid,
        )

    @classmethod
    def from_document(cls, value: object) -> "ToolIdentity":
        if not isinstance(value, dict) or set(value) != TOOL_IDENTITY_KEYS:
            raise AcceptanceError("JOURNAL_TOOL_IDENTITY_INVALID")
        path = value.get("path")
        sha256 = value.get("sha256")
        integers = {
            "device": value.get("device"),
            "inode": value.get("inode"),
            "size": value.get("size"),
            "mtime_ns": value.get("mtimeNs"),
            "uid": value.get("uid"),
        }
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or not isinstance(sha256, str)
            or DIGEST_RE.fullmatch(sha256) is None
            or any(type(item) is not int or item < 0 for item in integers.values())
            or integers["inode"] == 0
            or integers["size"] == 0
        ):
            raise AcceptanceError("JOURNAL_TOOL_IDENTITY_INVALID")
        return cls(path=path, sha256=sha256, **integers)

    def document(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "mtimeNs": self.mtime_ns,
            "uid": self.uid,
        }


def local_docker_socket(endpoint: str) -> Path:
    """Return the resolved local Unix socket or reject remote Docker routing."""

    prefix = "unix://"
    if (
        not endpoint.startswith(prefix)
        or len(endpoint) > 4096
        or any(character in endpoint for character in ("\x00", "\n", "\r", "%", "?", "#"))
    ):
        raise AcceptanceError("DOCKER_ENDPOINT_NOT_LOCAL")
    socket_path = Path(endpoint[len(prefix) :])
    if not socket_path.is_absolute():
        raise AcceptanceError("DOCKER_ENDPOINT_NOT_LOCAL")
    try:
        resolved = socket_path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        raise AcceptanceError("DOCKER_ENDPOINT_NOT_LOCAL") from None
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        raise AcceptanceError("DOCKER_ENDPOINT_NOT_LOCAL")
    return resolved


def canonical_local_docker_endpoint(endpoint: str) -> str:
    return f"unix://{local_docker_socket(endpoint)}"


@dataclass(frozen=True)
class DockerCustody:
    context: str
    endpoint: str
    daemon_id: str

    @classmethod
    def from_document(cls, value: object) -> "DockerCustody":
        if not isinstance(value, dict) or set(value) != DOCKER_CUSTODY_KEYS:
            raise AcceptanceError("JOURNAL_DOCKER_CUSTODY_INVALID")
        context = value.get("context")
        endpoint = value.get("endpoint")
        daemon_id = value.get("daemonId")
        if (
            not isinstance(context, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context) is None
            or not isinstance(endpoint, str)
            or not endpoint.startswith("unix:///")
            or len(endpoint) > 4096
            or any(character in endpoint for character in ("\x00", "\n", "\r"))
            or not isinstance(daemon_id, str)
            or re.fullmatch(r"[A-Za-z0-9:_.-]{8,256}", daemon_id) is None
        ):
            raise AcceptanceError("JOURNAL_DOCKER_CUSTODY_INVALID")
        return cls(context=context, endpoint=endpoint, daemon_id=daemon_id)

    def document(self) -> dict[str, str]:
        return {
            "context": self.context,
            "endpoint": self.endpoint,
            "daemonId": self.daemon_id,
        }

    def receipt(self) -> dict[str, str]:
        return {
            "dockerContextSha256": (
                "sha256:" + hashlib.sha256(self.context.encode("utf-8")).hexdigest()
            ),
            "dockerEndpointSha256": (
                "sha256:" + hashlib.sha256(self.endpoint.encode("utf-8")).hexdigest()
            ),
            "dockerDaemonIdSha256": (
                "sha256:" + hashlib.sha256(self.daemon_id.encode("utf-8")).hexdigest()
            ),
        }


class Runner:
    """A no-shell subprocess adapter that never streams command output."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolIdentity] = {}
        self._docker_custody: DockerCustody | None = None
        self._docker_bootstrap = False

    def resolve_tools(self) -> None:
        resolved: dict[str, ToolIdentity] = {}
        for name in TOOL_NAMES:
            selected = sys.executable if name == "python" else shutil.which(name)
            if selected is None:
                raise AcceptanceError("TOOL_PATH_INVALID")
            try:
                path = Path(selected).resolve(strict=True)
            except OSError:
                raise AcceptanceError("TOOL_PATH_INVALID") from None
            resolved[name] = ToolIdentity.capture(path)
        self._tools = resolved

    def tools_bound(self) -> bool:
        return set(self._tools) == set(TOOL_NAMES)

    def docker_bound(self) -> bool:
        return self._docker_custody is not None

    def _docker_context_endpoint(self, context: str) -> str:
        observed = json_output(
            self.run(
                (
                    "docker",
                    "context",
                    "inspect",
                    context,
                    "--format",
                    "{{json .Endpoints.docker.Host}}",
                )
            )
        )
        if not isinstance(observed, str):
            raise AcceptanceError("DOCKER_CONTEXT_INVALID")
        return observed

    def _docker_daemon_id(self) -> str:
        observed = json_output(
            self.run(("docker", "info", "--format", "{{json .ID}}"))
        )
        if (
            not isinstance(observed, str)
            or re.fullmatch(r"[A-Za-z0-9:_.-]{8,256}", observed) is None
        ):
            raise AcceptanceError("DOCKER_DAEMON_ID_INVALID")
        return observed

    def bind_local_docker(self) -> None:
        if self._docker_custody is not None:
            raise AcceptanceError("DOCKER_CUSTODY_ALREADY_BOUND")
        self._docker_bootstrap = True
        try:
            context = text_output(self.run(("docker", "context", "show")))
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context) is None:
                raise AcceptanceError("DOCKER_CONTEXT_INVALID")
            endpoint = canonical_local_docker_endpoint(
                self._docker_context_endpoint(context)
            )
            self._docker_custody = DockerCustody(
                context=context, endpoint=endpoint, daemon_id="pending-id"
            )
            daemon_id = self._docker_daemon_id()
            self._docker_custody = DockerCustody(
                context=context, endpoint=endpoint, daemon_id=daemon_id
            )
        except Exception:
            self._docker_custody = None
            raise
        finally:
            self._docker_bootstrap = False

    def adopt_journal_docker(self, value: object) -> None:
        expected = DockerCustody.from_document(value)
        if self._docker_custody is not None:
            raise AcceptanceError("DOCKER_CUSTODY_ALREADY_BOUND")
        self._docker_bootstrap = True
        try:
            if (
                canonical_local_docker_endpoint(
                    self._docker_context_endpoint(expected.context)
                )
                != expected.endpoint
            ):
                raise AcceptanceError("DOCKER_CONTEXT_CHANGED")
            local_docker_socket(expected.endpoint)
            self._docker_custody = expected
            if self._docker_daemon_id() != expected.daemon_id:
                raise AcceptanceError("DOCKER_DAEMON_CHANGED")
        except Exception:
            self._docker_custody = None
            raise
        finally:
            self._docker_bootstrap = False

    def journal_docker_custody(self) -> dict[str, str]:
        custody = self._docker_custody
        if custody is None:
            raise AcceptanceError("DOCKER_CUSTODY_NOT_BOUND")
        local_docker_socket(custody.endpoint)
        if self._docker_daemon_id() != custody.daemon_id:
            raise AcceptanceError("DOCKER_DAEMON_CHANGED")
        return custody.document()

    def docker_receipt(self) -> dict[str, str]:
        custody = DockerCustody.from_document(self.journal_docker_custody())
        return custody.receipt()

    def adopt_journal_tools(self, value: object) -> None:
        if not isinstance(value, dict) or set(value) != set(TOOL_NAMES):
            raise AcceptanceError("JOURNAL_TOOL_IDENTITY_INVALID")
        expected = {
            name: ToolIdentity.from_document(value[name]) for name in TOOL_NAMES
        }
        try:
            current_python = ToolIdentity.capture(
                Path(sys.executable).resolve(strict=True)
            )
        except OSError:
            raise AcceptanceError("INTERPRETER_IDENTITY_CHANGED") from None
        if expected["python"] != current_python:
            raise AcceptanceError("INTERPRETER_IDENTITY_CHANGED")
        for name, identity in expected.items():
            if ToolIdentity.capture(Path(identity.path)) != identity:
                raise AcceptanceError("TOOL_IDENTITY_CHANGED")
        self._tools = expected

    def journal_tool_identities(self) -> dict[str, dict[str, object]]:
        if set(self._tools) != set(TOOL_NAMES):
            raise AcceptanceError("TOOLS_NOT_BOUND")
        return {name: self.tool_identity(name).document() for name in TOOL_NAMES}

    def tool_identity(self, name: str) -> ToolIdentity:
        identity = self._tools.get(name)
        if identity is None:
            raise AcceptanceError("TOOL_NOT_BOUND")
        if ToolIdentity.capture(Path(identity.path)) != identity:
            raise AcceptanceError("TOOL_IDENTITY_CHANGED")
        return identity

    def bound_path(self) -> str:
        if not self._tools:
            raise AcceptanceError("TOOLS_NOT_BOUND")
        directories: list[str] = []
        for name in TOOL_NAMES:
            identity = self._tools.get(name)
            if identity is None:
                continue
            parent = str(Path(identity.path).parent)
            if parent not in directories:
                directories.append(parent)
        return os.pathsep.join(directories)

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path = ROOT,
        input_bytes: bytes | None = None,
        extra_environment: Mapping[str, str] | None = None,
        timeout: int = 180,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        if not arguments or any(not isinstance(value, str) or not value for value in arguments):
            raise AcceptanceError("COMMAND_INVALID")
        if arguments[0] not in TOOL_NAMES:
            raise AcceptanceError("TOOL_NOT_BOUND")
        identity = self.tool_identity(arguments[0])
        if arguments[0] == "git":
            bound_arguments = (
                identity.path,
                "--no-replace-objects",
                "-c",
                "credential.helper=",
                "-c",
                "core.askPass=",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "http.extraHeader=",
                "-c",
                "http.proxy=",
                "-c",
                "http.sslVerify=true",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                *arguments[1:],
            )
        else:
            bound_arguments = (identity.path, *arguments[1:])
        environment = clean_environment(extra_environment)
        environment["PATH"] = self.bound_path()
        if arguments[0] in {"docker", "kind"}:
            if self._docker_custody is None:
                if not (
                    self._docker_bootstrap
                    and arguments[0] == "docker"
                    and len(arguments) >= 3
                    and arguments[1] == "context"
                    and arguments[2] in {"show", "inspect"}
                ):
                    raise AcceptanceError("DOCKER_CUSTODY_NOT_BOUND")
            else:
                local_docker_socket(self._docker_custody.endpoint)
                environment["DOCKER_HOST"] = self._docker_custody.endpoint
        try:
            result = subprocess.run(
                list(bound_arguments),
                cwd=cwd,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise AcceptanceError("COMMAND_UNAVAILABLE") from None
        if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
            raise AcceptanceError("COMMAND_OUTPUT_OVERSIZED")
        if check and result.returncode != 0:
            raise AcceptanceError("COMMAND_FAILED")
        return result


def text_output(result: subprocess.CompletedProcess[bytes]) -> str:
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise AcceptanceError("COMMAND_OUTPUT_INVALID") from None


def json_output(result: subprocess.CompletedProcess[bytes]) -> object:
    try:
        return json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AcceptanceError("COMMAND_JSON_INVALID") from None


def docker_object_absent(result: subprocess.CompletedProcess[bytes]) -> bool:
    """Distinguish a proved missing object from daemon/transport failure."""

    if result.returncode == 0:
        return False
    message = result.stderr.decode("utf-8", errors="replace").lower()
    return any(
        marker in message
        for marker in (
            "no such object",
            "no such container",
            "no such image",
            "no such network",
            "network ",
        )
    ) and ("not found" in message or "no such" in message)


def require_docker_image_name_available(runner: Runner, image: str) -> None:
    inspected = runner.run(
        ("docker", "image", "inspect", image), check=False, timeout=30
    )
    if inspected.returncode == 0:
        raise AcceptanceError("IMAGE_NAME_COLLISION")
    if not docker_object_absent(inspected):
        raise AcceptanceError("DOCKER_INSPECTION_FAILED")


def git_path(raw: bytes, code: str) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AcceptanceError(code) from None
    parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or "\x00" in value
    ):
        raise AcceptanceError(code)
    return value


def commit_tree_inventory(payload: bytes) -> dict[str, tuple[str, str]]:
    if not payload or not payload.endswith(b"\x00"):
        raise AcceptanceError("COMMIT_TREE_INVALID")
    inventory: dict[str, tuple[str, str]] = {}
    for record in payload[:-1].split(b"\x00"):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid = metadata.split(b" ", 2)
            oid = raw_oid.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            raise AcceptanceError("COMMIT_TREE_INVALID") from None
        path = git_path(raw_path, "COMMIT_TREE_INVALID")
        decoded_mode = mode.decode("ascii", errors="ignore")
        if (
            object_type != b"blob"
            or decoded_mode not in {"100644", "100755", "120000"}
            or SHA_RE.fullmatch(oid) is None
            or path in inventory
        ):
            raise AcceptanceError("COMMIT_TREE_INVALID")
        inventory[path] = (decoded_mode, oid)
    if not inventory:
        raise AcceptanceError("COMMIT_TREE_INVALID")
    return inventory


def index_inventory(payload: bytes) -> dict[str, tuple[str, str]]:
    if not payload or not payload.endswith(b"\x00"):
        raise AcceptanceError("INDEX_FLAGS_INVALID")
    inventory: dict[str, tuple[str, str]] = {}
    for record in payload[:-1].split(b"\x00"):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            tag, mode, raw_oid, stage = metadata.split(b" ", 3)
            oid = raw_oid.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            raise AcceptanceError("INDEX_FLAGS_INVALID") from None
        path = git_path(raw_path, "INDEX_FLAGS_INVALID")
        decoded_mode = mode.decode("ascii", errors="ignore")
        if (
            tag != b"H"
            or decoded_mode not in {"100644", "100755", "120000"}
            or SHA_RE.fullmatch(oid) is None
            or stage != b"0"
            or path in inventory
        ):
            raise AcceptanceError("INDEX_FLAGS_INVALID")
        inventory[path] = (decoded_mode, oid)
    if not inventory:
        raise AcceptanceError("INDEX_FLAGS_INVALID")
    return inventory


def git_blob_oid(size: int, chunks: Iterable[bytes]) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {size}\x00".encode("ascii"))
    observed = 0
    for chunk in chunks:
        observed += len(chunk)
        digest.update(chunk)
    if observed != size:
        raise AcceptanceError("WORKTREE_RAW_MISMATCH")
    return digest.hexdigest()


def stable_regular_blob_oid(path: Path, executable: bool) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or bool(stat.S_IMODE(before.st_mode) & 0o111) != executable
            ):
                raise AcceptanceError("WORKTREE_RAW_MISMATCH")

            def chunks() -> Iterable[bytes]:
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        return
                    yield chunk

            oid = git_blob_oid(before.st_size, chunks())
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except AcceptanceError:
        raise
    except OSError:
        raise AcceptanceError("WORKTREE_RAW_MISMATCH") from None
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise AcceptanceError("WORKTREE_RAW_MISMATCH")
    return oid


def stable_symlink_blob_oid(path: Path) -> str:
    try:
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode):
            raise AcceptanceError("WORKTREE_RAW_MISMATCH")
        payload = os.fsencode(os.readlink(path))
        after = path.lstat()
    except AcceptanceError:
        raise
    except OSError:
        raise AcceptanceError("WORKTREE_RAW_MISMATCH") from None
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise AcceptanceError("WORKTREE_RAW_MISMATCH")
    return git_blob_oid(len(payload), (payload,))


def read_private_handoff(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            payload = os.read(descriptor, 1024)
            overflow = os.read(descriptor, 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID") from None
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        overflow
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
    ):
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID")
    return payload


def validate_launch_context(runner: Runner, expected_commit: str) -> None:
    if (
        _configured_root is None
        or _configured_launch_root is None
        or _configured_handoff is None
        or SHA_RE.fullmatch(expected_commit) is None
    ):
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID")
    configured_root = Path(_configured_root)
    launch_root = Path(_configured_launch_root)
    handoff = Path(_configured_handoff)
    script = Path(__file__)
    try:
        if (
            not configured_root.is_absolute()
            or configured_root != ROOT
            or not launch_root.is_absolute()
            or launch_root.resolve(strict=True) != launch_root
            or launch_root == ROOT
            or ROOT in launch_root.parents
            or handoff != launch_root / "handoff"
            or script != launch_root / "flux_rbac_kind_acceptance.py"
            or script.resolve(strict=True) != script
        ):
            raise AcceptanceError("LAUNCH_CONTEXT_INVALID")
        launch_metadata = launch_root.lstat()
        if (
            not stat.S_ISDIR(launch_metadata.st_mode)
            or stat.S_ISLNK(launch_metadata.st_mode)
            or launch_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(launch_metadata.st_mode) != 0o700
        ):
            raise AcceptanceError("LAUNCH_CONTEXT_INVALID")
    except AcceptanceError:
        raise
    except OSError:
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID") from None

    observed_script_oid = stable_regular_blob_oid(script, False)
    expected_script_oid = text_output(
        runner.run(
            (
                "git",
                "rev-parse",
                f"{expected_commit}:scripts/flux_rbac_kind_acceptance.py",
            )
        )
    )
    expected_handoff = (
        f"1\n{expected_commit}\n{expected_script_oid}\n".encode("ascii")
    )
    if (
        SHA_RE.fullmatch(expected_script_oid) is None
        or observed_script_oid != expected_script_oid
        or read_private_handoff(handoff) != expected_handoff
    ):
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID")
    try:
        handoff.unlink()
        fsync_directory(launch_root)
    except OSError:
        raise AcceptanceError("LAUNCH_CONTEXT_INVALID") from None


def verify_raw_worktree(inventory: Mapping[str, tuple[str, str]]) -> None:
    for relative, (mode, expected_oid) in inventory.items():
        current = ROOT
        parts = relative.split("/")
        try:
            for component in parts[:-1]:
                current /= component
                metadata = current.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise AcceptanceError("WORKTREE_RAW_MISMATCH")
            path = current / parts[-1]
            observed_oid = (
                stable_symlink_blob_oid(path)
                if mode == "120000"
                else stable_regular_blob_oid(path, mode == "100755")
            )
        except AcceptanceError:
            raise
        except OSError:
            raise AcceptanceError("WORKTREE_RAW_MISMATCH") from None
        if observed_oid != expected_oid:
            raise AcceptanceError("WORKTREE_RAW_MISMATCH")


def git_preflight(runner: Runner, expected_commit: str) -> str:
    if SHA_RE.fullmatch(expected_commit) is None:
        raise AcceptanceError("EXPECTED_COMMIT_INVALID")

    def git(*arguments: str) -> str:
        return text_output(runner.run(("git", *arguments)))

    if Path(git("rev-parse", "--show-toplevel")).resolve() != ROOT:
        raise AcceptanceError("WORKTREE_ROOT_MISMATCH")
    grafts = git("rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
    if not grafts or os.path.lexists(grafts):
        raise AcceptanceError("GRAFTS_PRESENT")
    for alternate_name in ("alternates", "http-alternates"):
        alternate = git(
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            f"objects/info/{alternate_name}",
        )
        if not alternate or os.path.lexists(alternate):
            raise AcceptanceError("ALTERNATE_OBJECT_STORE_PRESENT")
    if git("for-each-ref", "--format=%(refname)", "refs/replace"):
        raise AcceptanceError("REPLACE_REFS_PRESENT")
    if git("rev-parse", "--is-shallow-repository") != "false":
        raise AcceptanceError("SHALLOW_REPOSITORY_INVALID")
    fsck = runner.run(
        ("git", "fsck", "--strict", "--full", "--no-reflogs"),
        check=False,
        timeout=300,
    )
    if fsck.returncode != 0:
        raise AcceptanceError("GIT_OBJECT_STORE_INVALID")
    if git("rev-parse", "HEAD") != expected_commit:
        raise AcceptanceError("HEAD_MISMATCH")
    expected_inventory = commit_tree_inventory(
        runner.run(("git", "ls-tree", "-r", "-z", expected_commit)).stdout
    )
    observed_index = index_inventory(
        runner.run(("git", "ls-files", "--stage", "-v", "-z")).stdout
    )
    if observed_index != expected_inventory:
        raise AcceptanceError("INDEX_TREE_MISMATCH")
    verify_raw_worktree(expected_inventory)
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    if not branch or branch in {"main", "master"}:
        raise AcceptanceError("BRANCH_INVALID")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise AcceptanceError("WORKTREE_DIRTY")
    if git("rev-parse", "@{upstream}") != expected_commit:
        raise AcceptanceError("UPSTREAM_MISMATCH")
    if git("config", "--get", f"branch.{branch}.remote") != "origin":
        raise AcceptanceError("UPSTREAM_REMOTE_INVALID")
    origin_urls = git("remote", "get-url", "--all", "origin").splitlines()
    if len(origin_urls) != 1 or origin_urls[0] not in CANONICAL_ORIGIN_URLS:
        raise AcceptanceError("ORIGIN_URL_INVALID")
    expected_ref = f"refs/heads/{branch}"
    if git("config", "--get", f"branch.{branch}.merge") != expected_ref:
        raise AcceptanceError("UPSTREAM_REF_INVALID")
    remote_parent = allowed_temp_parent()
    if remote_parent == ROOT or ROOT in remote_parent.parents:
        raise AcceptanceError("REMOTE_QUERY_DIRECTORY_INVALID")
    try:
        with tempfile.TemporaryDirectory(
            prefix="flux-rbac-remote-query-", dir=remote_parent
        ) as remote_directory:
            os.chmod(remote_directory, 0o700)
            remote = text_output(
                runner.run(
                    (
                        "git",
                        "ls-remote",
                        "--exit-code",
                        origin_urls[0],
                        expected_ref,
                    ),
                    cwd=Path(remote_directory),
                    extra_environment={
                        "GIT_CEILING_DIRECTORIES": remote_directory
                    },
                )
            ).splitlines()
    except OSError:
        raise AcceptanceError("REMOTE_QUERY_DIRECTORY_INVALID") from None
    if remote != [f"{expected_commit}\t{expected_ref}"]:
        raise AcceptanceError("REMOTE_HEAD_MISMATCH")
    return branch


def verify_tools(runner: Runner, pins: Mapping[str, str]) -> dict[str, object]:
    require_isolated_interpreter()
    python = python_version()
    git = text_output(runner.run(("git", "--version")))
    docker = text_output(runner.run(("docker", "version", "--format", "{{.Server.Version}}")))
    kind = text_output(runner.run(("kind", "version")))
    kubectl = json_output(runner.run(("kubectl", "version", "--client", "-o", "json")))
    helm = text_output(runner.run(("helm", "version", "--template", "{{.Version}}")))
    go = text_output(runner.run(("go", "version")))
    if not git:
        raise AcceptanceError("GIT_VERSION_INVALID")
    if not docker:
        raise AcceptanceError("DOCKER_VERSION_INVALID")
    if pins["KIND_VERSION"] not in kind.split():
        raise AcceptanceError("KIND_VERSION_MISMATCH")
    if not isinstance(kubectl, dict) or kubectl.get("clientVersion", {}).get("gitVersion") != pins["KUBERNETES_VERSION"]:
        raise AcceptanceError("KUBECTL_VERSION_MISMATCH")
    if helm != pins["HELM_VERSION"]:
        raise AcceptanceError("HELM_VERSION_MISMATCH")
    if f"go{pins['GO_VERSION'].lstrip('v')}" not in go.split():
        raise AcceptanceError("GO_VERSION_MISMATCH")
    observed: dict[str, object] = {
        "python": python,
        "git": git,
        "docker": docker,
        "kind": pins["KIND_VERSION"],
        "kubectl": pins["KUBERNETES_VERSION"],
        "helm": pins["HELM_VERSION"],
        "go": pins["GO_VERSION"],
    }
    for name in TOOL_NAMES:
        identity = runner.tool_identity(name)
        observed[f"{name}Sha256"] = identity.sha256
        observed[f"{name}Device"] = identity.device
        observed[f"{name}Inode"] = identity.inode
    observed.update(runner.docker_receipt())
    return observed


def service_account_groups(subject: str) -> tuple[str, str, str]:
    parts = subject.split(":")
    if len(parts) != 4 or parts[:2] != ["system", "serviceaccount"] or not parts[2] or not parts[3]:
        raise AcceptanceError("SUBJECT_INVALID")
    return (
        "system:serviceaccounts",
        f"system:serviceaccounts:{parts[2]}",
        "system:authenticated",
    )


def review_document(row: AccessRow) -> dict[str, object]:
    attributes: dict[str, object] = {
        "verb": row.verb,
        "group": row.group,
        "resource": row.resource,
    }
    if row.subresource is not None:
        attributes["subresource"] = row.subresource
    if row.namespace is not None:
        attributes["namespace"] = row.namespace
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": {"resourceAttributes": attributes},
    }


def exact_rule_index(
    role: Mapping[str, object],
    *,
    group: str,
    resource: str,
    verbs: Iterable[str],
) -> int:
    expected_verbs = set(verbs)
    matches: list[int] = []
    rules = role.get("rules")
    if not isinstance(rules, list):
        raise AcceptanceError("RBAC_RULES_INVALID")
    for index, candidate in enumerate(rules):
        if not isinstance(candidate, dict):
            continue
        groups = candidate.get("apiGroups")
        resources = candidate.get("resources")
        actual_verbs = candidate.get("verbs")
        if groups == [group] and resources == [resource] and isinstance(actual_verbs, list) and set(actual_verbs) == expected_verbs and len(actual_verbs) == len(expected_verbs):
            matches.append(index)
    if len(matches) != 1:
        raise AcceptanceError("RBAC_RULE_NOT_EXACT")
    return matches[0]


def condition(document: Mapping[str, object], condition_type: str) -> dict[str, object] | None:
    status = document.get("status")
    if not isinstance(status, dict):
        return None
    conditions = status.get("conditions")
    if not isinstance(conditions, list):
        return None
    matches = [item for item in conditions if isinstance(item, dict) and item.get("type") == condition_type]
    return matches[0] if len(matches) == 1 else None


def current_generation(document: Mapping[str, object]) -> bool:
    metadata = document.get("metadata")
    status = document.get("status")
    return (
        isinstance(metadata, dict)
        and isinstance(status, dict)
        and type(metadata.get("generation")) is int
        and status.get("observedGeneration") == metadata["generation"]
    )


def deployed_history(document: Mapping[str, object]) -> dict[str, object] | None:
    status = document.get("status")
    history = status.get("history") if isinstance(status, dict) else None
    if not isinstance(history, list) or not history or not isinstance(history[0], dict):
        return None
    return history[0] if history[0].get("status") == "deployed" else None


def deployment_healthy(document: Mapping[str, object]) -> bool:
    metadata = document.get("metadata")
    status = document.get("status")
    return (
        isinstance(metadata, dict)
        and isinstance(status, dict)
        and status.get("observedGeneration") == metadata.get("generation")
        and status.get("availableReplicas") == 1
        and status.get("readyReplicas") == 1
    )


def upgrade_effect_bound(
    release: Mapping[str, object],
    deployment: Mapping[str, object],
    *,
    previous_version: int,
    annotation: str,
    value: str,
) -> bool:
    ready = condition(release, "Ready")
    latest = deployed_history(release)
    metadata = deployment.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    return (
        current_generation(release)
        and ready is not None
        and ready.get("status") == "True"
        and ready.get("reason") == "UpgradeSucceeded"
        and latest is not None
        and type(latest.get("version")) is int
        and latest["version"] > previous_version
        and isinstance(latest.get("configDigest"), str)
        and isinstance(annotations, dict)
        and annotations.get(annotation) == value
        and deployment_healthy(deployment)
    )


def controller_deployments_zero_replica(payload: bytes) -> bytes:
    separator = b"\n---\n"
    documents = payload.split(separator)
    before = b"\n  replicas: 1\n"
    after = b"\n  replicas: 0\n"
    changed: dict[int, bytes] = {}
    for controller in INITIAL_ZERO_CONTROLLERS:
        identity = f"\n  name: {controller}\n".encode("utf-8")
        candidates = [
            index
            for index, document in enumerate(documents)
            if b"\nkind: Deployment\n" in b"\n" + document
            and identity in b"\n" + document
            and b"\n  namespace: flux-system\n" in b"\n" + document
        ]
        if len(candidates) != 1:
            raise AcceptanceError("CONTROLLER_ZERO_TRANSFORM_INVALID")
        index = candidates[0]
        if index in changed or documents[index].count(before) != 1:
            raise AcceptanceError("CONTROLLER_ZERO_TRANSFORM_INVALID")
        changed[index] = documents[index].replace(before, after, 1)
    transformed = separator.join(changed.get(index, document) for index, document in enumerate(documents))
    if (
        len(transformed) != len(payload)
        or transformed.count(after) != payload.count(after) + len(INITIAL_ZERO_CONTROLLERS)
        or any(
            changed[index].replace(after, before, 1) != documents[index]
            for index in changed
        )
    ):
        raise AcceptanceError("CONTROLLER_ZERO_TRANSFORM_INVALID")
    return transformed


def current_upgrade_failure_bound(
    release: Mapping[str, object],
    *,
    generation: int,
    namespace: str,
    resource: str,
    group: str,
) -> bool:
    metadata = release.get("metadata")
    status = release.get("status")
    spec = release.get("spec")
    common = spec.get("commonMetadata") if isinstance(spec, dict) else None
    annotations = common.get("annotations") if isinstance(common, dict) else None
    ready = condition(release, "Ready")
    message = ready.get("message") if isinstance(ready, dict) else None
    return (
        isinstance(metadata, dict)
        and metadata.get("generation") == generation
        and isinstance(status, dict)
        and status.get("observedGeneration") == generation
        and isinstance(annotations, dict)
        and annotations.get("acceptance.snaraj.dev/readiness-negative") == resource
        and isinstance(ready, dict)
        and ready.get("status") == "False"
        and ready.get("reason") == "UpgradeFailed"
        and isinstance(message, str)
        and authorization_failure_bound(
            [message], namespace=namespace, resource=resource, group=group
        )
    )


def rollback_after_failure_bound(
    release: Mapping[str, object],
    *,
    generation: int,
    failure_resource_version: str,
) -> bool:
    """Require rollback on an API object newer than the observed failure."""

    metadata = release.get("metadata")
    status = release.get("status")
    rollback = condition(release, "Remediated")
    return (
        isinstance(metadata, dict)
        and metadata.get("generation") == generation
        and isinstance(metadata.get("resourceVersion"), str)
        and metadata["resourceVersion"] != failure_resource_version
        and isinstance(status, dict)
        and status.get("observedGeneration") == generation
        and rollback is not None
        and rollback.get("status") == "True"
        and rollback.get("reason") == "RollbackSucceeded"
    )


def same_pod_kubelet_retry_bound(
    failed: Mapping[str, object], recovered: Mapping[str, object]
) -> bool:
    """Prove kubelet retried the same failed container and it became Ready."""

    failed_metadata = failed.get("metadata")
    recovered_metadata = recovered.get("metadata")
    failed_status = failed.get("status")
    recovered_status = recovered.get("status")
    failed_containers = (
        failed_status.get("containerStatuses")
        if isinstance(failed_status, dict)
        else None
    )
    recovered_containers = (
        recovered_status.get("containerStatuses")
        if isinstance(recovered_status, dict)
        else None
    )
    ready_conditions = (
        [
            item
            for item in recovered_status.get("conditions", [])
            if isinstance(item, dict) and item.get("type") == "Ready"
        ]
        if isinstance(recovered_status, dict)
        and isinstance(recovered_status.get("conditions", []), list)
        else []
    )
    if (
        not isinstance(failed_metadata, dict)
        or not isinstance(recovered_metadata, dict)
        or not isinstance(failed_containers, list)
        or len(failed_containers) != 1
        or not isinstance(failed_containers[0], dict)
        or not isinstance(recovered_containers, list)
        or len(recovered_containers) != 1
        or not isinstance(recovered_containers[0], dict)
    ):
        return False
    failed_restarts = failed_containers[0].get("restartCount")
    recovered_restarts = recovered_containers[0].get("restartCount")
    return (
        isinstance(failed_metadata.get("uid"), str)
        and failed_metadata["uid"] == recovered_metadata.get("uid")
        and type(failed_restarts) is int
        and failed_restarts >= 0
        and type(recovered_restarts) is int
        and recovered_restarts > failed_restarts
        and recovered_containers[0].get("ready") is True
        and isinstance(recovered_status, dict)
        and recovered_status.get("phase") == "Running"
        and len(ready_conditions) == 1
        and ready_conditions[0].get("status") == "True"
    )


def zero_replica_without_pods(
    deployment: Mapping[str, object], pods: object
) -> bool:
    """Bind an initial-creation proof to replicas zero and no existing Pod."""

    spec = deployment.get("spec")
    return isinstance(spec, dict) and spec.get("replicas") == 0 and pods == []


def controller_cold_start_ready_bound(
    deployment: Mapping[str, object],
    pods: object,
    controller: str,
    *,
    expected_pod_uid: str | None = None,
) -> bool:
    """Require one current-generation, zero-restart manager Pod for a controller."""

    metadata = deployment.get("metadata")
    spec = deployment.get("spec")
    status = deployment.get("status")
    if (
        not isinstance(metadata, dict)
        or metadata.get("name") != controller
        or metadata.get("namespace") != "flux-system"
        or type(metadata.get("generation")) is not int
        or not isinstance(spec, dict)
        or spec.get("replicas") != 1
        or not isinstance(status, dict)
        or status.get("observedGeneration") != metadata["generation"]
        or any(
            status.get(field) != 1
            for field in (
                "replicas", "updatedReplicas", "availableReplicas", "readyReplicas"
            )
        )
        or not isinstance(pods, list)
        or len(pods) != 1
        or not isinstance(pods[0], dict)
    ):
        return False
    pod_metadata = pods[0].get("metadata")
    pod_status = pods[0].get("status")
    labels = pod_metadata.get("labels") if isinstance(pod_metadata, dict) else None
    conditions = pod_status.get("conditions") if isinstance(pod_status, dict) else None
    containers = (
        pod_status.get("containerStatuses") if isinstance(pod_status, dict) else None
    )
    ready = [
        item
        for item in conditions
        if isinstance(item, dict) and item.get("type") == "Ready"
    ] if isinstance(conditions, list) else []
    return (
        isinstance(pod_metadata, dict)
        and isinstance(pod_metadata.get("uid"), str)
        and bool(pod_metadata["uid"])
        and (expected_pod_uid is None or pod_metadata["uid"] == expected_pod_uid)
        and isinstance(labels, dict)
        and labels.get("app") == controller
        and isinstance(pod_status, dict)
        and pod_status.get("phase") == "Running"
        and isinstance(containers, list)
        and len(containers) == 1
        and isinstance(containers[0], dict)
        and containers[0].get("name") == "manager"
        and containers[0].get("ready") is True
        and containers[0].get("restartCount") == 0
        and len(ready) == 1
        and ready[0].get("status") == "True"
    )


def authorization_failure_bound(
    messages: Iterable[str], *, namespace: str, resource: str, group: str
) -> bool:
    subject = f"system:serviceaccount:{namespace}:helm-reconciler"
    required = (
        "forbidden",
        f'user "{subject}"',
        f'resource "{resource}"',
        f'api group "{group}"',
        f'namespace "{namespace}"',
    )
    return any(
        all(fragment in message.lower() for fragment in required)
        and re.search(r"\bcannot (?:get|list|watch) resource\b", message.lower())
        is not None
        for message in messages
    )


def load_journal_document(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise AcceptanceError("JOURNAL_PATH_UNSAFE")
    try:
        metadata = path.stat()
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise AcceptanceError("JOURNAL_INVALID") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
        or set(document) != JOURNAL_KEYS
        or document.get("schemaVersion") != JOURNAL_SCHEMA
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    owner = document.get("owner")
    expected_commit = document.get("expectedCommit")
    if (
        not isinstance(owner, str)
        or re.fullmatch(r"[0-9a-f]{32}", owner) is None
        or document.get("cluster") != cluster_name(owner)
        or document.get("network") != network_name(owner)
        or document.get("registry") != registry_name(owner)
        or not isinstance(expected_commit, str)
        or SHA_RE.fullmatch(expected_commit) is None
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    for key in ("networkCreated", "registryCreated", "clusterCreated", "imageCreated"):
        if type(document.get(key)) is not bool:
            raise AcceptanceError("JOURNAL_INVALID")
    temp_root = Path(str(document.get("tempRoot", "")))
    temp_parent = Path(str(document.get("tempParent", "")))
    kubeconfig = Path(str(document.get("kubeconfig", "")))
    if (
        not temp_root.is_absolute()
        or not temp_parent.is_absolute()
        or temp_parent != allowed_temp_parent()
        or temp_root.parent != temp_parent
        or not temp_root.name.startswith("flux-rbac-kind-")
        or kubeconfig != temp_root / "kubeconfig"
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    kubeconfig_sha256 = document.get("kubeconfigSha256")
    kubeconfig_server = document.get("kubeconfigServer")
    if (kubeconfig_sha256 is None) != (kubeconfig_server is None):
        raise AcceptanceError("JOURNAL_INVALID")
    if kubeconfig_sha256 is not None and (
        not document.get("clusterCreated")
        or not isinstance(kubeconfig_sha256, str)
        or DIGEST_RE.fullmatch(kubeconfig_sha256) is None
        or not isinstance(kubeconfig_server, str)
        or re.fullmatch(r"https://127\.0\.0\.1:[1-9][0-9]{0,4}", kubeconfig_server)
        is None
        or int(kubeconfig_server.rsplit(":", 1)[1]) > 65535
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    tool_identities = document.get("toolIdentities")
    if not isinstance(tool_identities, dict) or set(tool_identities) != set(TOOL_NAMES):
        raise AcceptanceError("JOURNAL_TOOL_IDENTITY_INVALID")
    for value in tool_identities.values():
        ToolIdentity.from_document(value)
    DockerCustody.from_document(document.get("dockerCustody"))
    receipt_path = Path(str(document.get("receiptPath", "")))
    try:
        receipt_parent = receipt_path.parent.resolve(strict=True)
    except OSError:
        raise AcceptanceError("JOURNAL_INVALID") from None
    if (
        not receipt_path.is_absolute()
        or receipt_parent == ROOT
        or ROOT in receipt_parent.parents
        or receipt_journal_paths_collide(receipt_path, path)
        or document.get("state") not in {"active", "prepared", "closed"}
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    receipt_sha = document.get("receiptSha256")
    receipt_cleanup = document.get("receiptCleanup")
    if (receipt_sha is None) != (receipt_cleanup is None):
        raise AcceptanceError("JOURNAL_INVALID")
    if receipt_sha is not None and (
        not isinstance(receipt_sha, str)
        or DIGEST_RE.fullmatch(receipt_sha) is None
        or not isinstance(receipt_cleanup, dict)
        or set(receipt_cleanup) != PASS_CLEANUP_KEYS
        or any(type(value) is not bool for value in receipt_cleanup.values())
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    if (
        document.get("state") == "closed" and receipt_sha is None
    ) or (
        document.get("state") == "active" and receipt_sha is not None
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    image = document.get("workloadImage")
    if image is not None and (
        not isinstance(image, str)
        or not image.startswith(LOOPBACK + ":")
        or f"/acceptance/flux-rbac-workload-{owner}:" not in image
    ):
        raise AcceptanceError("JOURNAL_INVALID")
    return document


def owned_from_journal(runner: Runner, path: Path) -> "OwnedResources":
    document = load_journal_document(path)
    return OwnedResources(
        runner=runner,
        run_id=str(document["owner"]),
        expected_commit=str(document["expectedCommit"]),
        temp_root=Path(str(document["tempRoot"])),
        temp_parent=Path(str(document["tempParent"])),
        cluster=str(document["cluster"]),
        network=str(document["network"]),
        registry=str(document["registry"]),
        kubeconfig=Path(str(document["kubeconfig"])),
        kubeconfig_sha256=(
            str(document["kubeconfigSha256"])
            if document["kubeconfigSha256"] is not None
            else None
        ),
        kubeconfig_server=(
            str(document["kubeconfigServer"])
            if document["kubeconfigServer"] is not None
            else None
        ),
        journal_path=path,
        receipt_path=Path(str(document["receiptPath"])),
        workload_image=document["workloadImage"] if isinstance(document["workloadImage"], str) else None,
        network_created=document["networkCreated"] is True,
        registry_created=document["registryCreated"] is True,
        cluster_created=document["clusterCreated"] is True,
        image_created=document["imageCreated"] is True,
        journal_state=str(document["state"]),
        receipt_sha256=document["receiptSha256"] if isinstance(document["receiptSha256"], str) else None,
        receipt_cleanup=document["receiptCleanup"] if isinstance(document["receiptCleanup"], dict) else None,
    )


def recover_previous(runner: Runner, journal_path: Path) -> bool:
    staging = journal_path.with_name(journal_path.name + ".new")
    if staging.exists() and not journal_path.exists():
        try:
            load_journal_document(staging)
        except AcceptanceError:
            raise AcceptanceError("RECOVERY_JOURNAL_INCOMPLETE") from None
        os.replace(staging, journal_path)
        fsync_directory(journal_path.parent)
    elif staging.exists() and journal_path.exists():
        try:
            staged = load_journal_document(staging)
        except AcceptanceError:
            staged = None
        try:
            current = load_journal_document(journal_path)
        except AcceptanceError:
            current = None
        if staged is not None and (
            current is None or staged.get("owner") == current.get("owner")
        ):
            os.replace(staging, journal_path)
        elif current is not None:
            staging.unlink()
        else:
            raise AcceptanceError("RECOVERY_JOURNAL_INCOMPLETE")
        fsync_directory(journal_path.parent)
    if journal_path.exists():
        try:
            document = load_journal_document(journal_path)
        except AcceptanceError:
            raise AcceptanceError("RECOVERY_JOURNAL_INCOMPLETE") from None
        runner.adopt_journal_tools(document["toolIdentities"])
        runner.adopt_journal_docker(document["dockerCustody"])
        owned = owned_from_journal(runner, journal_path)
        if owned.journal_state == "closed":
            owned.remove_closed_journal()
            return True
        if owned.journal_state == "active":
            owned.prepare_for_cleanup()
        owned.cleanup()
        if (
            owned.journal_state == "prepared"
            and owned.receipt_sha256 is not None
            and owned.receipt_cleanup is not None
            and owned.finish_staged_receipt()
        ):
            owned.close_journal()
            owned.remove_closed_journal()
            return True
        if owned.receipt_path.exists() or owned.receipt_staging_path.exists():
            raise AcceptanceError("RECOVERY_RECEIPT_INCOMPLETE")
        recovered_receipt = build_receipt(
            expected_commit=owned.expected_commit,
            result="FAIL",
            phase=State.NEW,
            primary_error_code="RECOVERED_INCOMPLETE_RUN",
            cleanup_error_code=None,
            tools={},
            pins={},
            evidence={"interruptedRunRecovered": True},
            cleanup=owned.cleanup(),
        )
        digest = receipt_digest(recovered_receipt)
        owned.bind_receipt(digest, recovered_receipt["cleanup"])
        if write_receipt(owned.receipt_path, recovered_receipt) != digest:
            raise AcceptanceError("RECEIPT_DIGEST_MISMATCH")
        owned.close_journal()
        owned.remove_closed_journal()
        return True
    return False


@dataclass
class OwnedResources:
    """Names and paths created by one run, with ownership-checked cleanup."""

    runner: Runner
    run_id: str
    expected_commit: str
    temp_root: Path
    temp_parent: Path
    cluster: str
    network: str
    registry: str
    kubeconfig: Path
    journal_path: Path
    receipt_path: Path
    kubeconfig_sha256: str | None = None
    kubeconfig_server: str | None = None
    workload_image: str | None = None
    network_created: bool = False
    registry_created: bool = False
    cluster_created: bool = False
    image_created: bool = False
    journal_state: str = "active"
    receipt_sha256: str | None = None
    receipt_cleanup: dict[str, bool] | None = None
    cleaned: bool = False

    @property
    def owner_marker(self) -> Path:
        return self.temp_root / "owner.json"

    @property
    def journal_staging_path(self) -> Path:
        return self.journal_path.with_name(self.journal_path.name + ".new")

    @property
    def receipt_staging_path(self) -> Path:
        return self.receipt_path.with_name(
            f".{self.receipt_path.name}.flux-rbac-new"
        )

    def journal_payload(self) -> dict[str, object]:
        return {
            "schemaVersion": JOURNAL_SCHEMA,
            "owner": self.run_id,
            "expectedCommit": self.expected_commit,
            "tempRoot": str(self.temp_root),
            "tempParent": str(self.temp_parent),
            "cluster": self.cluster,
            "network": self.network,
            "registry": self.registry,
            "kubeconfig": str(self.kubeconfig),
            "kubeconfigSha256": self.kubeconfig_sha256,
            "kubeconfigServer": self.kubeconfig_server,
            "workloadImage": self.workload_image,
            "networkCreated": self.network_created,
            "registryCreated": self.registry_created,
            "clusterCreated": self.cluster_created,
            "imageCreated": self.image_created,
            "toolIdentities": self.runner.journal_tool_identities(),
            "dockerCustody": self.runner.journal_docker_custody(),
            "state": self.journal_state,
            "receiptPath": str(self.receipt_path),
            "receiptSha256": self.receipt_sha256,
            "receiptCleanup": self.receipt_cleanup,
        }

    def _journal_parent(self) -> Path:
        parent = self.journal_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = parent.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise AcceptanceError("JOURNAL_DIRECTORY_UNSAFE")
        return parent

    def claim_journal(self) -> None:
        parent = self._journal_parent()
        if self.journal_path.is_symlink() or self.journal_staging_path.exists():
            raise AcceptanceError("JOURNAL_PATH_UNSAFE")
        payload = json.dumps(
            self.journal_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.journal_path, flags, 0o600)
        except OSError:
            raise AcceptanceError("JOURNAL_CLAIM_FAILED") from None
        try:
            write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(parent)

    def record(self) -> None:
        parent = self._journal_parent()
        if self.journal_path.is_symlink() or self.journal_staging_path.is_symlink():
            raise AcceptanceError("JOURNAL_PATH_UNSAFE")
        if self.journal_path.exists():
            existing = load_journal_document(self.journal_path)
            if existing.get("owner") != self.run_id:
                raise AcceptanceError("JOURNAL_OWNER_MISMATCH")
        payload = json.dumps(
            self.journal_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.journal_staging_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(self.journal_staging_path, self.journal_path)
        fsync_directory(parent)

    def prepare_for_cleanup(self) -> None:
        if self.journal_state not in {"active", "prepared"}:
            raise AcceptanceError("JOURNAL_STATE_INVALID")
        self.journal_state = "prepared"
        self.record()

    def bind_receipt(self, digest: str, cleanup: Mapping[str, bool]) -> None:
        if (
            self.journal_state != "prepared"
            or DIGEST_RE.fullmatch(digest) is None
            or set(cleanup) != PASS_CLEANUP_KEYS
            or any(type(value) is not bool for value in cleanup.values())
        ):
            raise AcceptanceError("JOURNAL_RECEIPT_BINDING_INVALID")
        self.receipt_sha256 = digest
        self.receipt_cleanup = dict(cleanup)
        self.record()

    def receipt_matches_binding(self) -> bool:
        if self.receipt_sha256 is None or self.receipt_cleanup is None:
            return False
        staging = self.receipt_path.with_name(
            f".{self.receipt_path.name}.flux-rbac-new"
        )
        try:
            if staging.exists() and self.receipt_path.exists():
                staged_metadata = staging.lstat()
                receipt_metadata = self.receipt_path.lstat()
                if (
                    staging.is_symlink()
                    or self.receipt_path.is_symlink()
                    or staged_metadata.st_dev != receipt_metadata.st_dev
                    or staged_metadata.st_ino != receipt_metadata.st_ino
                    or staged_metadata.st_uid != os.geteuid()
                ):
                    return False
                staging.unlink()
                fsync_directory(self.receipt_path.parent)
            metadata = self.receipt_path.lstat()
            payload = self.receipt_path.read_bytes()
            receipt = json.loads(payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return (
            not self.receipt_path.is_symlink()
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and len(payload) <= MAX_RECEIPT_BYTES
            and f"sha256:{hashlib.sha256(payload).hexdigest()}" == self.receipt_sha256
            and isinstance(receipt, dict)
            and receipt.get("commit") == self.expected_commit
            and receipt.get("cleanup") == self.receipt_cleanup
        )

    def finish_staged_receipt(self) -> bool:
        if self.receipt_matches_binding():
            return True
        if (
            self.receipt_sha256 is None
            or self.receipt_path.exists()
            or not self.receipt_staging_path.exists()
            or self.receipt_staging_path.is_symlink()
        ):
            return False
        try:
            metadata = self.receipt_staging_path.lstat()
            payload = self.receipt_staging_path.read_bytes()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or f"sha256:{hashlib.sha256(payload).hexdigest()}"
                != self.receipt_sha256
            ):
                return False
            os.link(
                self.receipt_staging_path,
                self.receipt_path,
                follow_symlinks=False,
            )
            fsync_directory(self.receipt_path.parent)
            self.receipt_staging_path.unlink()
            fsync_directory(self.receipt_path.parent)
        except OSError:
            return False
        return self.receipt_matches_binding()

    def close_journal(self) -> None:
        if (
            self.journal_state != "prepared"
            or self.receipt_cleanup is None
            or not self.receipt_matches_binding()
        ):
            raise AcceptanceError("JOURNAL_RECEIPT_BINDING_INVALID")
        current_cleanup = self.cleanup()
        if (
            set(current_cleanup) != PASS_CLEANUP_KEYS
            or any(value is not True for value in current_cleanup.values())
        ):
            raise AcceptanceError("JOURNAL_RECEIPT_BINDING_INVALID")
        self.journal_state = "closed"
        self.record()

    def remove_closed_journal(self) -> None:
        document = load_journal_document(self.journal_path)
        if (
            self.journal_state != "closed"
            or document.get("state") != "closed"
            or document.get("owner") != self.run_id
            or not self.receipt_matches_binding()
        ):
            raise AcceptanceError("JOURNAL_NOT_DURABLY_CLOSED")
        if self.journal_staging_path.exists():
            staged = load_journal_document(self.journal_staging_path)
            if staged.get("owner") != self.run_id or staged.get("state") != "closed":
                raise AcceptanceError("JOURNAL_OWNER_MISMATCH")
            self.journal_staging_path.unlink()
        self.journal_path.unlink()
        fsync_directory(self.journal_path.parent)

    def _inspect_label(self, kind: str, name: str) -> bool:
        result = self.runner.run(
            ("docker", kind, "inspect", name), check=False, timeout=30
        )
        if result.returncode != 0:
            if docker_object_absent(result):
                return False
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        payload = json_output(result)
        if not isinstance(payload, list) or len(payload) != 1:
            raise AcceptanceError("OWNERSHIP_INSPECTION_INVALID")
        labels = payload[0].get("Labels") if kind == "network" else payload[0].get("Config", {}).get("Labels")
        if not isinstance(labels, dict) or labels.get(OWNER_LABEL) != self.run_id:
            raise AcceptanceError("OWNERSHIP_MISMATCH")
        return True

    def _assert_temp_root_owned(self) -> None:
        try:
            root_metadata = self.temp_root.lstat()
            marker_metadata = self.owner_marker.lstat()
        except OSError:
            raise AcceptanceError("OWNERSHIP_MISMATCH") from None
        if (
            self.temp_parent != allowed_temp_parent()
            or self.temp_root.parent.resolve() != self.temp_parent
            or not self.temp_root.name.startswith("flux-rbac-kind-")
            or self.temp_root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
            or self.owner_marker.is_symlink()
            or not stat.S_ISREG(marker_metadata.st_mode)
            or marker_metadata.st_uid != os.geteuid()
            or marker_metadata.st_nlink != 1
            or stat.S_IMODE(marker_metadata.st_mode) != 0o600
        ):
            raise AcceptanceError("OWNERSHIP_MISMATCH")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.owner_marker, flags)
            try:
                opened_metadata = os.fstat(descriptor)
                content = os.read(descriptor, 257)
            finally:
                os.close(descriptor)
            marker = json.loads(content)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise AcceptanceError("OWNERSHIP_MISMATCH") from None
        if (
            len(content) > 256
            or opened_metadata.st_dev != marker_metadata.st_dev
            or opened_metadata.st_ino != marker_metadata.st_ino
            or opened_metadata.st_nlink != 1
            or marker != {"owner": self.run_id}
        ):
            raise AcceptanceError("OWNERSHIP_MISMATCH")

    def _owned_kind_cluster_present(self) -> bool:
        clusters_result = self.runner.run(
            ("kind", "get", "clusters"), check=False, timeout=30
        )
        if clusters_result.returncode != 0:
            raise AcceptanceError("KIND_INSPECTION_FAILED")
        if self.cluster not in text_output(clusters_result).splitlines():
            return False
        self._assert_temp_root_owned()
        if not self.network_created or not self._inspect_label("network", self.network):
            raise AcceptanceError("OWNERSHIP_MISMATCH")
        expected_node = f"{self.cluster}-control-plane"
        node_list = self.runner.run(
            (
                "docker",
                "container",
                "ls",
                "--all",
                "--filter",
                f"label=io.x-k8s.kind.cluster={self.cluster}",
                "--format",
                "{{.Names}}",
            ),
            check=False,
            timeout=30,
        )
        if node_list.returncode != 0:
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        if text_output(node_list).splitlines() != [expected_node]:
            raise AcceptanceError("OWNERSHIP_MISMATCH")
        inspected = self.runner.run(
            ("docker", "container", "inspect", expected_node),
            check=False,
            timeout=30,
        )
        if inspected.returncode != 0:
            if docker_object_absent(inspected):
                raise AcceptanceError("OWNERSHIP_MISMATCH")
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        payload = json_output(inspected)
        if not isinstance(payload, list) or len(payload) != 1:
            raise AcceptanceError("OWNERSHIP_INSPECTION_INVALID")
        item = payload[0]
        labels = item.get("Config", {}).get("Labels")
        networks = item.get("NetworkSettings", {}).get("Networks")
        if (
            not isinstance(labels, dict)
            or labels.get("io.x-k8s.kind.cluster") != self.cluster
            or labels.get("io.x-k8s.kind.role") != "control-plane"
            or not isinstance(networks, dict)
            or self.network not in networks
        ):
            raise AcceptanceError("OWNERSHIP_MISMATCH")
        return True

    def cleanup(self) -> dict[str, bool]:
        if self.cleaned:
            final = self.verify_absent(include_journal=False)
            final["journalRetainedUntilReceipt"] = self.journal_path.exists()
            return final
        failures = False
        if self.image_created and self.workload_image:
            inspected = self.runner.run(
                ("docker", "image", "inspect", self.workload_image),
                check=False,
                timeout=30,
            )
            if inspected.returncode == 0:
                payload = json_output(inspected)
                labels = payload[0].get("Config", {}).get("Labels") if isinstance(payload, list) and len(payload) == 1 else None
                if not isinstance(labels, dict) or labels.get(OWNER_LABEL) != self.run_id:
                    failures = True
                elif self.runner.run(("docker", "image", "rm", "--force", self.workload_image), check=False, timeout=60).returncode != 0:
                    failures = True
            elif not docker_object_absent(inspected):
                failures = True
        if self.registry_created:
            try:
                if self._inspect_label("container", self.registry):
                    if self.runner.run(("docker", "container", "rm", "--force", self.registry), check=False, timeout=60).returncode != 0:
                        failures = True
            except AcceptanceError:
                failures = True
        if self.cluster_created:
            try:
                if self._owned_kind_cluster_present():
                    if self.runner.run(("kind", "delete", "cluster", "--name", self.cluster), check=False, timeout=180).returncode != 0:
                        failures = True
            except AcceptanceError:
                failures = True
        if self.network_created:
            try:
                if self._inspect_label("network", self.network):
                    if self.runner.run(("docker", "network", "rm", self.network), check=False, timeout=60).returncode != 0:
                        failures = True
            except AcceptanceError:
                failures = True
        if failures:
            raise AcceptanceError("CLEANUP_FAILED")
        remote_absent = self.verify_absent(include_journal=False)
        if not all(
            remote_absent[key]
            for key in (
                "clusterAbsent",
                "registryAbsent",
                "networkAbsent",
                "imageAbsent",
            )
        ):
            raise AcceptanceError("CLEANUP_FAILED")
        if self.temp_root.exists():
            try:
                self._assert_temp_root_owned()
                shutil.rmtree(self.temp_root)
            except (AcceptanceError, OSError):
                raise AcceptanceError("CLEANUP_FAILED") from None
        absent = self.verify_absent(include_journal=False)
        if not all(absent.values()):
            raise AcceptanceError("CLEANUP_FAILED")
        self.cleaned = True
        final = self.verify_absent(include_journal=False)
        try:
            journal = load_journal_document(self.journal_path)
            retained = (
                journal.get("owner") == self.run_id
                and journal.get("state") == "prepared"
            )
        except AcceptanceError:
            retained = False
        final["journalRetainedUntilReceipt"] = retained
        if set(final) != PASS_CLEANUP_KEYS or not all(final.values()):
            raise AcceptanceError("CLEANUP_FAILED")
        return final

    def verify_absent(self, *, include_journal: bool = True) -> dict[str, bool]:
        clusters_result = self.runner.run(
            ("kind", "get", "clusters"), check=False, timeout=30
        )
        clusters = text_output(clusters_result).splitlines() if clusters_result.returncode == 0 else [self.cluster]
        container = self.runner.run(
            ("docker", "container", "inspect", self.registry), check=False, timeout=30
        )
        network = self.runner.run(
            ("docker", "network", "inspect", self.network), check=False, timeout=30
        )
        image_result: subprocess.CompletedProcess[bytes] | None = None
        if self.workload_image:
            image_result = self.runner.run(
                ("docker", "image", "inspect", self.workload_image),
                check=False,
                timeout=30,
            )
        if container.returncode != 0 and not docker_object_absent(container):
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        if network.returncode != 0 and not docker_object_absent(network):
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        if image_result is not None and image_result.returncode != 0 and not docker_object_absent(image_result):
            raise AcceptanceError("DOCKER_INSPECTION_FAILED")
        result = {
            "clusterAbsent": self.cluster not in clusters,
            "registryAbsent": container.returncode != 0,
            "networkAbsent": network.returncode != 0,
            "imageAbsent": image_result is None or image_result.returncode != 0,
            "kubeconfigAbsent": not self.kubeconfig.exists(),
            "temporaryRootAbsent": not self.temp_root.exists(),
        }
        if include_journal:
            result["journalAbsent"] = (
                not self.journal_path.exists()
                and not self.journal_staging_path.exists()
            )
        return result


def allocate_owned(
    runner: Runner, expected_commit: str, journal_path: Path, receipt_path: Path
) -> OwnedResources:
    tmp_parent = allowed_temp_parent()
    tmp_parent.mkdir(parents=True, exist_ok=True)
    run_id = secrets.token_hex(16)
    temp_root = Path(tempfile.mkdtemp(prefix="flux-rbac-kind-", dir=tmp_parent))
    os.chmod(temp_root, 0o700)
    marker = temp_root / "owner.json"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        write_all(descriptor, json.dumps({"owner": run_id}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    owned = OwnedResources(
        runner=runner,
        run_id=run_id,
        expected_commit=expected_commit,
        temp_root=temp_root,
        temp_parent=tmp_parent,
        cluster=cluster_name(run_id),
        network=network_name(run_id),
        registry=registry_name(run_id),
        kubeconfig=temp_root / "kubeconfig",
        journal_path=journal_path,
        receipt_path=receipt_path,
    )
    try:
        owned.claim_journal()
    except AcceptanceError:
        try:
            marker_value = json.loads(marker.read_text(encoding="utf-8"))
            root_metadata = temp_root.lstat()
            if (
                marker_value == {"owner": run_id}
                and not temp_root.is_symlink()
                and stat.S_ISDIR(root_metadata.st_mode)
                and root_metadata.st_uid == os.geteuid()
                and stat.S_IMODE(root_metadata.st_mode) == 0o700
                and temp_root.parent == tmp_parent
            ):
                shutil.rmtree(temp_root)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        raise
    return owned


@dataclass
class AcceptanceHarness:
    runner: Runner
    expected_commit: str
    pins: Mapping[str, str]
    journal_path: Path = field(default_factory=default_journal_path)
    receipt_path: Path | None = None
    prior_recovery: bool | None = None
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    machine: StateMachine = field(default_factory=StateMachine)
    owned: OwnedResources | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    tools: dict[str, object] = field(default_factory=dict)
    registry_ip: str | None = None
    registry_port: str | None = None
    workload_reference: str | None = None
    final_render: bytes | None = None
    acceptance_egress_document: dict[str, object] | None = None
    kustomize_pod_uid: str | None = None
    snapshot_root: Path | None = None
    input_digests: dict[str, str] = field(default_factory=dict)

    def held_path(self, relative: str) -> Path:
        if self.snapshot_root is None or relative not in SNAPSHOT_INPUTS:
            raise AcceptanceError("HELD_INPUT_INVALID")
        candidate = self.snapshot_root / relative
        try:
            metadata = candidate.stat()
            payload = candidate.read_bytes()
        except OSError:
            raise AcceptanceError("HELD_INPUT_INVALID") from None
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or self.input_digests.get(relative)
            != f"sha256:{hashlib.sha256(payload).hexdigest()}"
        ):
            raise AcceptanceError("HELD_INPUT_INVALID")
        return candidate

    def held_directory(self, relative: str) -> Path:
        if self.snapshot_root is None:
            raise AcceptanceError("HELD_INPUT_INVALID")
        candidate = self.snapshot_root / relative
        try:
            metadata = candidate.stat()
        except OSError:
            raise AcceptanceError("HELD_INPUT_INVALID") from None
        prefix = relative.rstrip("/") + "/"
        members = [item for item in SNAPSHOT_INPUTS if item.startswith(prefix)]
        if (
            candidate.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or not members
        ):
            raise AcceptanceError("HELD_INPUT_INVALID")
        for member in members:
            self.held_path(member)
        return candidate

    def materialize_commit_inputs(self) -> None:
        if self.owned is None:
            raise AcceptanceError("RESOURCES_NOT_ALLOCATED")
        snapshot = self.owned.temp_root / "commit-inputs"
        try:
            snapshot.mkdir(mode=0o700)
        except OSError:
            raise AcceptanceError("INPUT_SNAPSHOT_FAILED") from None
        digests: dict[str, str] = {}
        for relative in SNAPSHOT_INPUTS:
            result = self.runner.run(
                (
                    "git",
                    "cat-file",
                    "blob",
                    f"{self.expected_commit}:{relative}",
                ),
                timeout=60,
            )
            payload = result.stdout
            destination = snapshot / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(destination.parent, 0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(destination, flags, 0o600)
                try:
                    write_all(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                raise AcceptanceError("INPUT_SNAPSHOT_FAILED") from None
            digests[relative] = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        self.snapshot_root = snapshot
        self.input_digests = digests
        held_pins = parse_versions(self.held_path(VERSIONS_RELATIVE))
        if dict(self.pins) != held_pins:
            raise AcceptanceError("VERSION_INPUT_DRIFT")
        self.pins = held_pins
        self.evidence["inputInventorySha256"] = dict(sorted(digests.items()))

    def kube(
        self,
        *arguments: str,
        input_bytes: bytes | None = None,
        check: bool = True,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[bytes]:
        if self.owned is None:
            raise AcceptanceError("RESOURCES_NOT_ALLOCATED")
        journal = load_journal_document(self.owned.journal_path)
        try:
            self.owned._assert_temp_root_owned()
            observed_sha256, observed_server = kubeconfig_binding(
                self.owned.kubeconfig, self.owned.cluster
            )
        except (AcceptanceError, OSError):
            raise AcceptanceError("OWNED_KUBECONFIG_INVALID") from None
        if (
            journal.get("owner") != self.owned.run_id
            or journal.get("kubeconfig") != str(self.owned.kubeconfig)
            or journal.get("cluster") != self.owned.cluster
            or journal.get("clusterCreated") is not True
            or journal.get("kubeconfigSha256") != self.owned.kubeconfig_sha256
            or journal.get("kubeconfigServer") != self.owned.kubeconfig_server
            or observed_sha256 != self.owned.kubeconfig_sha256
            or observed_server != self.owned.kubeconfig_server
            or self.owned.kubeconfig != self.owned.temp_root / "kubeconfig"
        ):
            raise AcceptanceError("OWNED_KUBECONFIG_INVALID")
        return self.runner.run(
            ("kubectl", "--kubeconfig", str(self.owned.kubeconfig), *arguments),
            input_bytes=input_bytes,
            check=check,
            timeout=timeout,
        )

    def kube_json(self, *arguments: str) -> dict[str, object]:
        value = json_output(self.kube(*arguments))
        if not isinstance(value, dict):
            raise AcceptanceError("KUBERNETES_OBJECT_INVALID")
        return value

    def apply_document(self, document: Mapping[str, object]) -> None:
        self.kube(
            "apply",
            "-f",
            "-",
            input_bytes=json.dumps(document, separators=(",", ":")).encode("utf-8"),
        )

    def run(self) -> dict[str, object]:
        recovered = (
            recover_previous(self.runner, self.journal_path)
            if self.prior_recovery is None
            else self.prior_recovery
        )
        self.evidence["priorOwnedResidueRecovered"] = recovered
        git_preflight(self.runner, self.expected_commit)
        self.machine.advance(State.NEW, State.PREFLIGHT)

        if self.receipt_path is None:
            raise AcceptanceError("RECEIPT_PATH_INVALID")
        self.owned = allocate_owned(
            self.runner, self.expected_commit, self.journal_path, self.receipt_path
        )
        self.materialize_commit_inputs()
        self.tools = verify_tools(self.runner, self.pins)
        self.machine.advance(State.PREFLIGHT, State.ALLOCATED)
        self.create_infrastructure()
        self.machine.advance(State.ALLOCATED, State.INFRASTRUCTURE)
        self.build_artifacts()
        self.machine.advance(State.INFRASTRUCTURE, State.ARTIFACTS)
        self.install_stock()
        self.assert_matrix(CROSSING_ROWS, True)
        self.evidence["stockCrossingsAllowed"] = len(CROSSING_ROWS)
        self.machine.advance(State.ARTIFACTS, State.STOCK)
        self.apply_final_rbac()
        self.assert_matrix(OWNED_ROWS, True)
        self.assert_matrix(CROSSING_ROWS, False)
        self.assert_matrix(GENERAL_DENIED_ROWS, False)
        self.assert_matrix(TENANT_ALLOWED_ROWS, True)
        self.assert_matrix(TENANT_DENIED_ROWS, False)
        self.assert_matrix(HELM_SECRET_ROWS, True)
        self.assert_review(
            AccessRow("helm-secret-update", HELM, "update", "", "secrets"), False
        )
        self.evidence.update(
            {
                "finalOwnedAllowed": len(OWNED_ROWS),
                "finalCrossingsDenied": len(CROSSING_ROWS),
                "generalDenials": len(GENERAL_DENIED_ROWS),
                "tenantReadsAllowed": len(TENANT_ALLOWED_ROWS),
                "tenantBoundariesDenied": len(TENANT_DENIED_ROWS),
            }
        )
        self.machine.advance(State.STOCK, State.FINAL_RBAC)
        self.kustomize_final_rbac_cold_start()
        self.helm_secret_cold_start()
        self.machine.advance(State.FINAL_RBAC, State.COLD_START)
        self.readiness_negatives()
        self.machine.advance(State.COLD_START, State.READINESS_NEGATIVES)
        self.release_lifecycle()
        self.assert_final_network_boundary()
        self.machine.advance(State.READINESS_NEGATIVES, State.RELEASE)
        self.machine.advance(State.RELEASE, State.COMPLETE)
        return dict(self.evidence)

    def create_infrastructure(self) -> None:
        assert self.owned is not None
        owner = f"{OWNER_LABEL}={self.owned.run_id}"
        self.owned.network_created = True
        self.owned.record()
        self.runner.run(
            ("docker", "network", "create", "--driver", "bridge", "--label", owner, self.owned.network)
        )
        self.owned.registry_created = True
        self.owned.record()
        self.runner.run(
            (
                "docker",
                "run",
                "--detach",
                "--restart=no",
                "--network",
                self.owned.network,
                "--publish",
                registry_publish_spec(),
                "--label",
                owner,
                "--name",
                self.owned.registry,
                REGISTRY_IMAGE,
            ),
            timeout=180,
        )
        inspect = json_output(
            self.runner.run(("docker", "container", "inspect", self.owned.registry))
        )
        if not isinstance(inspect, list) or len(inspect) != 1:
            raise AcceptanceError("REGISTRY_INSPECTION_INVALID")
        item = inspect[0]
        ports = item.get("NetworkSettings", {}).get("Ports", {}).get("5000/tcp")
        networks = item.get("NetworkSettings", {}).get("Networks", {})
        network = networks.get(self.owned.network) if isinstance(networks, dict) else None
        if not isinstance(ports, list) or len(ports) != 1 or ports[0].get("HostIp") != LOOPBACK:
            raise AcceptanceError("REGISTRY_PORT_INVALID")
        port = ports[0].get("HostPort")
        address = network.get("IPAddress") if isinstance(network, dict) else None
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            raise AcceptanceError("REGISTRY_ADDRESS_INVALID") from None
        if not isinstance(port, str) or not port.isdigit() or not parsed_address.is_private or parsed_address.version != 4:
            raise AcceptanceError("REGISTRY_ADDRESS_INVALID")
        self.registry_port = port
        self.registry_ip = address

        config = self.owned.temp_root / "kind.yaml"
        config.write_text(
            "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
            "networking:\n  ipFamily: ipv4\n"
            "nodes:\n  - role: control-plane\n",
            encoding="utf-8",
        )
        os.chmod(config, 0o600)
        self.owned.cluster_created = True
        self.owned.record()
        self.runner.run(
            (
                "kind",
                "create",
                "cluster",
                "--name",
                self.owned.cluster,
                "--image",
                self.pins["KIND_NODE_IMAGE"],
                "--kubeconfig",
                str(self.owned.kubeconfig),
                "--config",
                str(config),
                "--wait",
                "180s",
            ),
            extra_environment={"KIND_EXPERIMENTAL_DOCKER_NETWORK": self.owned.network},
            timeout=300,
        )
        os.chmod(self.owned.kubeconfig, 0o600)
        metadata = self.owned.kubeconfig.stat()
        if (
            self.owned.kubeconfig.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AcceptanceError("KUBECONFIG_MODE_INVALID")
        (
            self.owned.kubeconfig_sha256,
            self.owned.kubeconfig_server,
        ) = kubeconfig_binding(self.owned.kubeconfig, self.owned.cluster)
        self.owned.record()
        version = self.kube_json("version", "-o", "json")
        node_tag = self.pins["KIND_NODE_IMAGE"].split(":v", 1)[1].split("@", 1)[0]
        if version.get("serverVersion", {}).get("gitVersion") != f"v{node_tag}":
            raise AcceptanceError("KIND_NODE_VERSION_MISMATCH")

    def build_artifacts(self) -> None:
        assert self.owned is not None
        assert self.registry_port is not None
        context = self.owned.temp_root / "workload"
        context.mkdir(mode=0o700)
        architecture = text_output(
            self.runner.run(("docker", "info", "--format", "{{.Architecture}}"))
        )
        go_arch = {
            "amd64": "amd64",
            "x86_64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }.get(architecture)
        if go_arch is None:
            raise AcceptanceError("HOST_ARCHITECTURE_UNSUPPORTED")
        binary = context / "acceptance-workload"
        self.runner.run(
            (
                "go",
                "build",
                "-trimpath",
                "-ldflags=-s -w",
                "-o",
                str(binary),
                str(self.held_path(f"{FIXTURE_RELATIVE}/workload/main.go")),
            ),
            extra_environment={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": go_arch},
            timeout=180,
        )
        shutil.copyfile(
            self.held_path(f"{FIXTURE_RELATIVE}/workload/Dockerfile"),
            context / "Dockerfile",
        )
        tag = (
            f"{LOOPBACK}:{self.registry_port}/acceptance/"
            f"flux-rbac-workload-{self.owned.run_id}:"
            f"{self.expected_commit[:12]}"
        )
        require_docker_image_name_available(self.runner, tag)
        self.owned.workload_image = tag
        self.owned.image_created = True
        self.owned.record()
        self.runner.run(
            (
                "docker",
                "build",
                "--network=none",
                "--pull=false",
                "--label",
                f"{OWNER_LABEL}={self.owned.run_id}",
                "--tag",
                tag,
                str(context),
            ),
            timeout=300,
        )
        built = json_output(
            self.runner.run(("docker", "image", "inspect", tag), timeout=30)
        )
        built_labels = (
            built[0].get("Config", {}).get("Labels")
            if isinstance(built, list) and len(built) == 1
            else None
        )
        if (
            not isinstance(built_labels, dict)
            or built_labels.get(OWNER_LABEL) != self.owned.run_id
        ):
            raise AcceptanceError("IMAGE_OWNERSHIP_MISMATCH")
        self.runner.run(("docker", "push", tag), timeout=300)
        digests = json_output(
            self.runner.run(
                ("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", tag)
            )
        )
        if not isinstance(digests, list):
            raise AcceptanceError("WORKLOAD_DIGEST_INVALID")
        prefix = tag.rsplit(":", 1)[0] + "@"
        matches = [value for value in digests if isinstance(value, str) and value.startswith(prefix)]
        if len(matches) != 1 or DIGEST_RE.fullmatch(matches[0].split("@", 1)[1]) is None:
            raise AcceptanceError("WORKLOAD_DIGEST_INVALID")
        digest = matches[0].split("@", 1)[1]
        self.workload_reference = f"{tag}@{digest}"
        self.runner.run(
            ("kind", "load", "docker-image", "--name", self.owned.cluster, tag),
            timeout=300,
        )

        chart_output = self.owned.temp_root / "chart"
        chart_output.mkdir(mode=0o700)
        self.runner.run(
            (
                "helm",
                "package",
                str(self.held_directory(f"{FIXTURE_RELATIVE}/chart")),
                "--version",
                "0.1.0",
                "--app-version",
                "0.1.0",
                "--destination",
                str(chart_output),
            )
        )
        archives = list(chart_output.glob("flux-rbac-acceptance-0.1.0.tgz"))
        if len(archives) != 1 or not archives[0].is_file():
            raise AcceptanceError("CHART_PACKAGE_INVALID")
        self.runner.run(
            (
                "helm",
                "push",
                str(archives[0]),
                f"oci://{LOOPBACK}:{self.registry_port}/acceptance",
                "--plain-http",
            ),
            timeout=180,
        )

    def install_stock(self) -> None:
        assert self.registry_ip is not None
        for namespace in (*TENANTS, "kyverno", "flux-rbac-acceptance"):
            self.apply_document(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": namespace},
                }
            )
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "registry", "namespace": "flux-rbac-acceptance"},
            "spec": {"ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}]},
        }
        endpoint = {
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "registry",
                "namespace": "flux-rbac-acceptance",
                "labels": {"kubernetes.io/service-name": "registry"},
            },
            "addressType": "IPv4",
            "ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}],
            "endpoints": [{"addresses": [self.registry_ip], "conditions": {"ready": True}}],
        }
        self.apply_document(service)
        self.apply_document(endpoint)
        stock = self.held_path(STOCK_COMPONENTS_RELATIVE).read_bytes()
        stock_zero = controller_deployments_zero_replica(stock)
        self.evidence["controllerInitialCreation"] = {
            "stockInputSha256": f"sha256:{hashlib.sha256(stock).hexdigest()}",
            "stockZeroSha256": f"sha256:{hashlib.sha256(stock_zero).hexdigest()}",
            "changedFields": list(CONTROLLER_ZERO_CHANGED_FIELDS),
            "bothZeroPodsBeforeStart": False,
            "destructiveWorkloadAction": False,
            "initialCreationOnly": True,
        }
        self.kube("apply", "-f", "-", input_bytes=stock_zero, timeout=300)
        self.kube(
            "apply", "-f", str(self.held_path(ACCESS_MANIFEST_RELATIVE)), timeout=180
        )
        self.wait_crds()
        self.wait_controllers(("source-controller",))

    def wait_crds(self) -> None:
        for name in (
            "buckets.source.toolkit.fluxcd.io",
            "externalartifacts.source.toolkit.fluxcd.io",
            "gitrepositories.source.toolkit.fluxcd.io",
            "helmcharts.source.toolkit.fluxcd.io",
            "helmrepositories.source.toolkit.fluxcd.io",
            "ocirepositories.source.toolkit.fluxcd.io",
            "kustomizations.kustomize.toolkit.fluxcd.io",
            "helmreleases.helm.toolkit.fluxcd.io",
        ):
            self.kube(
                "wait",
                "--for=condition=Established",
                f"customresourcedefinition/{name}",
                "--timeout=120s",
            )

    def wait_controllers(
        self,
        names: Sequence[str] = (
            "source-controller",
            "kustomize-controller",
            "helm-controller",
        ),
    ) -> None:
        for name in names:
            self.kube(
                "-n",
                "flux-system",
                "rollout",
                "status",
                f"deployment/{name}",
                "--timeout=180s",
                timeout=210,
            )

    def assert_review(self, row: AccessRow, expected: bool) -> None:
        arguments: list[str] = ["--as", row.subject]
        for group in service_account_groups(row.subject):
            arguments.extend(("--as-group", group))
        arguments.extend(
            (
                "create",
                "--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                "-f",
                "-",
            )
        )
        response = json_output(
            self.kube(
                *arguments,
                input_bytes=json.dumps(review_document(row), separators=(",", ":")).encode("utf-8"),
            )
        )
        status = response.get("status") if isinstance(response, dict) else None
        if (
            not isinstance(status, dict)
            or type(status.get("allowed")) is not bool
            or status.get("evaluationError") not in (None, "")
            or status["allowed"] is not expected
        ):
            raise AcceptanceError("AUTHORIZATION_MATRIX_MISMATCH")

    def assert_matrix(self, rows: Sequence[AccessRow], expected: bool) -> None:
        labels = [row.label for row in rows]
        if len(labels) != len(set(labels)):
            raise AcceptanceError("AUTHORIZATION_MATRIX_INVALID")
        for row in rows:
            self.assert_review(row, expected)

    def assert_acceptance_egress(self) -> None:
        if self.owned is None or self.acceptance_egress_document is None:
            raise AcceptanceError("ACCEPTANCE_EGRESS_INVALID")
        observed = self.kube_json(
            "-n",
            "flux-system",
            "get",
            "networkpolicy",
            "flux-rbac-acceptance-egress",
            "-o",
            "json",
        )
        metadata = observed.get("metadata")
        labels = metadata.get("labels") if isinstance(metadata, dict) else None
        expected_spec = self.acceptance_egress_document.get("spec")
        if (
            not isinstance(labels, dict)
            or labels.get(OWNER_LABEL) != self.owned.run_id
            or observed.get("spec") != expected_spec
        ):
            raise AcceptanceError("ACCEPTANCE_EGRESS_INVALID")

    def install_acceptance_egress(self) -> None:
        if self.owned is None or self.registry_ip is None:
            raise AcceptanceError("ACCEPTANCE_EGRESS_INPUT_INVALID")
        api_service = self.kube_json(
            "-n", "default", "get", "service", "kubernetes", "-o", "json"
        )
        api_slices = self.kube_json(
            "-n",
            "default",
            "get",
            "endpointslices",
            "-l",
            "kubernetes.io/service-name=kubernetes",
            "-o",
            "json",
        )
        dns_service = self.kube_json(
            "-n", "kube-system", "get", "service", "kube-dns", "-o", "json"
        )
        source_service = self.kube_json(
            "-n",
            "flux-system",
            "get",
            "service",
            "source-controller",
            "-o",
            "json",
        )
        registry_service = self.kube_json(
            "-n",
            "flux-rbac-acceptance",
            "get",
            "service",
            "registry",
            "-o",
            "json",
        )
        document = acceptance_egress_policy(
            owner=self.owned.run_id,
            api_service_ip=service_private_ipv4(
                api_service,
                namespace="default",
                name="kubernetes",
                required_ports=(("https", 443, "TCP", 6443),),
            ),
            api_backend_ips=api_backend_private_ipv4s(api_slices),
            dns_service_ip=service_private_ipv4(
                dns_service,
                namespace="kube-system",
                name="kube-dns",
                required_ports=(
                    ("dns", 53, "UDP", 53),
                    ("dns-tcp", 53, "TCP", 53),
                    ("metrics", 9153, "TCP", 9153),
                ),
            ),
            source_service_ip=service_private_ipv4(
                source_service,
                namespace="flux-system",
                name="source-controller",
                required_ports=(("http", 80, "TCP", "http"),),
            ),
            registry_service_ip=service_private_ipv4(
                registry_service,
                namespace="flux-rbac-acceptance",
                name="registry",
                required_ports=(("registry", 5000, "TCP", 5000),),
            ),
            registry_backend_ip=self.registry_ip,
        )
        self.apply_document(document)
        self.acceptance_egress_document = document
        self.assert_acceptance_egress()

    def assert_final_network_boundary(self) -> None:
        if self.owned is None or self.acceptance_egress_document is None:
            raise AcceptanceError("FINAL_NETWORK_BOUNDARY_INVALID")
        policies = self.kube_json(
            "-n",
            "flux-system",
            "get",
            "networkpolicies",
            "-o",
            "json",
        )
        validate_final_network_policy_inventory(
            policies,
            owner=self.owned.run_id,
            acceptance_spec=self.acceptance_egress_document.get("spec"),
        )

    def apply_final_rbac(self) -> None:
        rendered = self.kube(
            "kustomize",
            str(self.held_directory(CONTROLLERS_RELATIVE)),
            timeout=180,
        ).stdout
        try:
            text = rendered.decode("utf-8")
        except UnicodeDecodeError:
            raise AcceptanceError("FINAL_RENDER_INVALID") from None
        required_names = (
            "crd-controller-source-flux-system",
            "crd-controller-kustomize-flux-system",
            "crd-controller-helm-flux-system",
        )
        images = (
            self.pins["FLUX_SOURCE_CONTROLLER_IMAGE"],
            self.pins["FLUX_KUSTOMIZE_CONTROLLER_IMAGE"],
            self.pins["FLUX_HELM_CONTROLLER_IMAGE"],
        )
        if (
            any(text.count(f"name: {name}") != 3 for name in required_names)
            or "name: cluster-reconciler-flux-system" in text
            or "kind: Secret" in text
            or any(text.count(image) != 1 for image in images)
        ):
            raise AcceptanceError("FINAL_RENDER_INVALID")
        self.final_render = rendered
        # The final controller root deliberately turns upstream's allow-all
        # egress policy into a deny. Install the disposable test's exact API,
        # DNS, artifact, and local-registry flows first so a NetworkPolicy-
        # enforcing kind CNI tests RBAC instead of deadlocking every manager.
        self.install_acceptance_egress()
        zero_render = controller_deployments_zero_replica(rendered)
        initial = self.evidence.get("controllerInitialCreation")
        if not isinstance(initial, dict):
            raise AcceptanceError("CONTROLLER_ZERO_TRANSFORM_INVALID")
        initial["finalRenderSha256"] = f"sha256:{hashlib.sha256(rendered).hexdigest()}"
        initial["finalZeroSha256"] = f"sha256:{hashlib.sha256(zero_render).hexdigest()}"
        self.kube("apply", "-f", "-", input_bytes=zero_render, timeout=300)
        self.kube(
            "delete",
            "clusterrolebinding",
            "cluster-reconciler-flux-system",
            "--wait=true",
            "--timeout=60s",
        )
        self.assert_final_network_boundary()
        self.wait_controllers(("source-controller",))
        shared = self.kube_json("get", "clusterrole", "crd-controller-flux-system", "-o", "json")
        rules = shared.get("rules")
        if not isinstance(rules, list) or any(
            group.endswith("toolkit.fluxcd.io")
            for rule in rules
            if isinstance(rule, dict)
            for group in rule.get("apiGroups", [])
            if isinstance(group, str)
        ):
            raise AcceptanceError("SHARED_ROLE_NOT_FINAL")
        binding = self.kube_json("get", "clusterrolebinding", "crd-controller-flux-system", "-o", "json")
        subjects = binding.get("subjects")
        names = {
            (item.get("namespace"), item.get("name"))
            for item in subjects
            if isinstance(item, dict)
        } if isinstance(subjects, list) else set()
        if names != {
            ("flux-system", "source-controller"),
            ("flux-system", "kustomize-controller"),
            ("flux-system", "helm-controller"),
        }:
            raise AcceptanceError("SHARED_BINDING_NOT_FINAL")

    def remove_exact_rule(
        self,
        kind: str,
        name: str,
        *,
        group: str,
        resource: str,
        verbs: Sequence[str],
        namespace: str | None = None,
    ) -> None:
        arguments = ["get", kind, name]
        if namespace:
            arguments.extend(("-n", namespace))
        arguments.extend(("-o", "json"))
        role = self.kube_json(*arguments)
        index = exact_rule_index(role, group=group, resource=resource, verbs=verbs)
        patch_arguments = ["patch", kind, name]
        if namespace:
            patch_arguments.extend(("-n", namespace))
        patch_arguments.extend(
            (
                "--type=json",
                "-p",
                json.dumps([{"op": "remove", "path": f"/rules/{index}"}], separators=(",", ":")),
            )
        )
        self.kube(*patch_arguments)

    def wait_until(
        self,
        predicate: Callable[[], object | None],
        *,
        timeout: float,
        code: str,
    ) -> object:
        deadline = self.monotonic() + timeout
        while self.monotonic() < deadline:
            value = predicate()
            if value is not None:
                return value
            self.sleep(1.0)
        raise AcceptanceError(code)

    def controller_deployment_and_pods(
        self, controller: str
    ) -> tuple[dict[str, object], object]:
        deployment = self.kube_json(
            "-n", "flux-system", "get", "deployment", controller, "-o", "json"
        )
        pods = self.kube_json(
            "-n", "flux-system", "get", "pods", "-l", f"app={controller}",
            "-o", "json",
        ).get("items")
        return deployment, pods

    def kustomize_final_rbac_cold_start(self) -> None:
        states = {
            controller: self.controller_deployment_and_pods(controller)
            for controller in INITIAL_ZERO_CONTROLLERS
        }
        if any(
            not zero_replica_without_pods(deployment, pods)
            for deployment, pods in states.values()
        ):
            raise AcceptanceError("CONTROLLER_INITIAL_ZERO_INVALID")
        initial = self.evidence.get("controllerInitialCreation")
        if not isinstance(initial, dict):
            raise AcceptanceError("CONTROLLER_INITIAL_ZERO_INVALID")
        initial["bothZeroPodsBeforeStart"] = True

        broad = self.kube(
            "get", "clusterrolebinding", "cluster-reconciler-flux-system",
            "-o", "name", check=False,
        )
        broad_output = (broad.stdout + broad.stderr).decode(
            "utf-8", errors="replace"
        ).lower()
        if broad.returncode == 0 or (
            "notfound" not in broad_output and "not found" not in broad_output
        ):
            raise AcceptanceError("BROAD_BINDING_ABSENCE_UNPROVEN")

        self.kube(
            "-n", "flux-system", "patch", "deployment", "kustomize-controller",
            "--type=merge", "-p", '{"spec":{"replicas":1}}',
        )

        def ready() -> dict[str, object] | None:
            deployment, pods = self.controller_deployment_and_pods(
                "kustomize-controller"
            )
            if controller_cold_start_ready_bound(
                deployment, pods, "kustomize-controller"
            ):
                assert isinstance(pods, list) and isinstance(pods[0], dict)
                return pods[0]
            return None

        pod = self.wait_until(
            ready, timeout=180, code="KUSTOMIZE_FINAL_RBAC_COLD_START_INVALID"
        )
        metadata = pod.get("metadata") if isinstance(pod, dict) else None
        uid = metadata.get("uid") if isinstance(metadata, dict) else None
        if not isinstance(uid, str) or not uid:
            raise AcceptanceError("KUSTOMIZE_FINAL_RBAC_COLD_START_INVALID")
        self.kustomize_pod_uid = uid

        helm_deployment, helm_pods = self.controller_deployment_and_pods(
            "helm-controller"
        )
        if not zero_replica_without_pods(helm_deployment, helm_pods):
            raise AcceptanceError("HELM_STARTED_BEFORE_COLD_START")
        self.evidence["kustomizeFinalRbacColdStart"] = {
            "zeroPodsBeforeStart": True,
            "finalRbacOnly": True,
            "currentGenerationReady": True,
            "singleReadyPod": True,
            "managerRestartCount": 0,
            "helmRemainedZero": True,
            "podUidPreservedAfterHelmRestore": False,
            "destructiveWorkloadAction": False,
            "initialCreationOnly": True,
        }

    def helm_secret_cold_start(self) -> None:
        if self.kustomize_pod_uid is None:
            raise AcceptanceError("KUSTOMIZE_COLD_START_NOT_PROVEN")
        kustomize_deployment, kustomize_pods = self.controller_deployment_and_pods(
            "kustomize-controller"
        )
        if not controller_cold_start_ready_bound(
            kustomize_deployment,
            kustomize_pods,
            "kustomize-controller",
            expected_pod_uid=self.kustomize_pod_uid,
        ):
            raise AcceptanceError("KUSTOMIZE_COLD_START_NOT_PRESERVED")
        deployment, pods = self.controller_deployment_and_pods("helm-controller")
        if not zero_replica_without_pods(deployment, pods):
            raise AcceptanceError("HELM_INITIAL_ZERO_INVALID")
        initial = self.evidence.get("controllerInitialCreation")
        if not isinstance(initial, dict):
            raise AcceptanceError("HELM_INITIAL_ZERO_INVALID")
        self.remove_exact_rule(
            "clusterrole",
            "crd-controller-helm-flux-system",
            group="",
            resource="secrets",
            verbs=("get", "list", "watch"),
        )
        for row in HELM_SECRET_ROWS:
            self.assert_review(row, False)
        self.kube(
            "-n",
            "flux-system",
            "patch",
            "deployment",
            "helm-controller",
            "--type=merge",
            "-p",
            '{"spec":{"replicas":1}}',
        )

        def cache_failure() -> dict[str, object] | None:
            deployment = self.kube_json(
                "-n", "flux-system", "get", "deployment", "helm-controller", "-o", "json"
            )
            current_pods = self.kube_json(
                "-n", "flux-system", "get", "pods", "-l", "app=helm-controller", "-o", "json"
            ).get("items")
            logs = self.kube(
                "-n",
                "flux-system",
                "logs",
                "-l",
                "app=helm-controller",
                "--all-containers=true",
                "--tail=200",
                check=False,
                timeout=30,
            )
            combined = (logs.stdout + logs.stderr).decode("utf-8", errors="replace").lower()
            status = deployment.get("status")
            unavailable = not isinstance(status, dict) or status.get("availableReplicas", 0) == 0
            forbidden = "secrets is forbidden" in combined and (
                "cannot list resource" in combined or "failed to list" in combined
            )
            if (
                unavailable
                and forbidden
                and isinstance(current_pods, list)
                and len(current_pods) == 1
                and isinstance(current_pods[0], dict)
            ):
                failed_status = current_pods[0].get("status")
                failed_containers = (
                    failed_status.get("containerStatuses")
                    if isinstance(failed_status, dict)
                    else None
                )
                if (
                    isinstance(current_pods[0].get("metadata", {}).get("uid"), str)
                    and isinstance(failed_containers, list)
                    and len(failed_containers) == 1
                    and isinstance(failed_containers[0], dict)
                    and type(failed_containers[0].get("restartCount")) is int
                ):
                    return current_pods[0]
            return None

        failed_pod = self.wait_until(
            cache_failure, timeout=75, code="HELM_SECRET_NEGATIVE_NOT_OBSERVED"
        )
        if not isinstance(failed_pod, dict):
            raise AcceptanceError("HELM_SECRET_NEGATIVE_NOT_OBSERVED")
        if self.final_render is None:
            raise AcceptanceError("FINAL_RENDER_MISSING")
        self.kube("apply", "-f", "-", input_bytes=self.final_render, timeout=300)
        self.wait_controllers(("helm-controller",))
        new_pods = self.kube_json(
            "-n", "flux-system", "get", "pods", "-l", "app=helm-controller", "-o", "json"
        ).get("items")
        if (
            not isinstance(new_pods, list)
            or len(new_pods) != 1
            or not isinstance(new_pods[0], dict)
            or not same_pod_kubelet_retry_bound(failed_pod, new_pods[0])
        ):
            raise AcceptanceError("HELM_POSITIVE_COLD_START_INVALID")
        kustomize_deployment, kustomize_pods = self.controller_deployment_and_pods(
            "kustomize-controller"
        )
        if not controller_cold_start_ready_bound(
            kustomize_deployment,
            kustomize_pods,
            "kustomize-controller",
            expected_pod_uid=self.kustomize_pod_uid,
        ):
            raise AcceptanceError("KUSTOMIZE_POD_CHANGED_DURING_HELM_RESTORE")
        kustomize_evidence = self.evidence.get("kustomizeFinalRbacColdStart")
        if not isinstance(kustomize_evidence, dict):
            raise AcceptanceError("KUSTOMIZE_COLD_START_NOT_PROVEN")
        kustomize_evidence["podUidPreservedAfterHelmRestore"] = True
        self.assert_matrix(HELM_SECRET_ROWS, True)
        self.assert_review(
            AccessRow("helm-secret-update", HELM, "update", "", "secrets"), False
        )
        self.evidence["helmSecretColdStart"] = {
            "negativeCacheSyncDenied": True,
            "positiveKubeletRetryReady": True,
            "readVerbsAllowed": len(HELM_SECRET_ROWS),
            "writeDenied": True,
            "samePodRecovered": True,
            "destructiveWorkloadAction": False,
            "initialCreationOnly": True,
        }

    @property
    def chart_url(self) -> str:
        return (
            "oci://registry.flux-rbac-acceptance.svc.cluster.local:5000/"
            "acceptance/flux-rbac-acceptance"
        )

    def source_document(self, namespace: str) -> dict[str, object]:
        return {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "OCIRepository",
            "metadata": {"name": "acceptance-chart", "namespace": namespace},
            "spec": {
                "interval": "1m",
                "url": self.chart_url,
                "insecure": True,
                "ref": {"tag": "0.1.0"},
            },
        }

    def release_document(self, namespace: str) -> dict[str, object]:
        if self.workload_reference is None:
            raise AcceptanceError("WORKLOAD_REFERENCE_MISSING")
        return {
            "apiVersion": "helm.toolkit.fluxcd.io/v2",
            "kind": "HelmRelease",
            "metadata": {"name": "acceptance", "namespace": namespace},
            "spec": {
                "interval": "1m",
                "timeout": "40s",
                "chartRef": {"kind": "OCIRepository", "name": "acceptance-chart"},
                "serviceAccountName": "helm-reconciler",
                "install": {
                    "remediation": {"retries": 0, "remediateLastFailure": False}
                },
                # This is acceptance-only: the platform manifests retain their
                # reviewed production policy.  It proves a failed upgrade
                # returns to the immediately preceding deployed revision.
                "upgrade": {
                    "remediation": {
                        "retries": 0,
                        "remediateLastFailure": True,
                        "strategy": "rollback",
                    }
                },
                "values": {
                    "image": self.workload_reference,
                    "failureMode": False,
                },
            },
        }

    def wait_source_ready(self, namespace: str) -> None:
        def ready() -> bool | None:
            source = self.kube_json(
                "-n", namespace, "get", "ocirepository", "acceptance-chart", "-o", "json"
            )
            item = condition(source, "Ready")
            status = source.get("status")
            artifact = status.get("artifact") if isinstance(status, dict) else None
            digest = artifact.get("digest") if isinstance(artifact, dict) else None
            return True if current_generation(source) and item and item.get("status") == "True" and isinstance(digest, str) and DIGEST_RE.fullmatch(digest) else None

        self.wait_until(ready, timeout=180, code="OCI_SOURCE_NOT_READY")

    def workload_healthy(self, namespace: str) -> bool:
        deployment = self.kube_json(
            "-n", namespace, "get", "deployment", "flux-rbac-acceptance", "-o", "json"
        )
        return deployment_healthy(deployment)

    def release_diagnostics(
        self, namespace: str, release: Mapping[str, object]
    ) -> tuple[list[str], set[str]]:
        status = release.get("status")
        conditions = status.get("conditions") if isinstance(status, dict) else None
        messages = [
            item["message"]
            for item in conditions
            if isinstance(item, dict) and isinstance(item.get("message"), str)
        ] if isinstance(conditions, list) else []
        reasons = {
            item["reason"]
            for item in conditions
            if isinstance(item, dict) and isinstance(item.get("reason"), str)
        } if isinstance(conditions, list) else set()
        events = self.kube_json(
            "-n",
            namespace,
            "get",
            "events",
            "--field-selector",
            "involvedObject.kind=HelmRelease,involvedObject.name=acceptance",
            "-o",
            "json",
        ).get("items")
        if isinstance(events, list):
            messages.extend(
                item["message"]
                for item in events
                if isinstance(item, dict) and isinstance(item.get("message"), str)
            )
            reasons.update(
                item["reason"]
                for item in events
                if isinstance(item, dict) and isinstance(item.get("reason"), str)
            )
        return messages, reasons

    def wait_failed_install_with_healthy_workload(
        self, namespace: str, resource: str, group: str
    ) -> None:
        def failed() -> bool | None:
            release = self.kube_json(
                "-n", namespace, "get", "helmrelease", "acceptance", "-o", "json"
            )
            ready = condition(release, "Ready")
            messages, _ = self.release_diagnostics(namespace, release)
            if (
                current_generation(release)
                and ready
                and ready.get("status") == "False"
                and ready.get("reason") == "InstallFailed"
                and authorization_failure_bound(
                    messages,
                    namespace=namespace,
                    resource=resource,
                    group=group,
                )
                and self.workload_healthy(namespace)
            ):
                return True
            return None

        self.wait_until(failed, timeout=150, code="READINESS_NEGATIVE_NOT_OBSERVED")

    def run_install_readiness_negative(
        self, namespace: str, resource: str, group: str
    ) -> None:
        self.remove_exact_rule(
            "role",
            "helm-reconciler",
            namespace=namespace,
            group=group,
            resource=resource,
            verbs=("get", "list", "watch"),
        )
        for verb in ("get", "list", "watch"):
            self.assert_review(
                AccessRow(
                    f"negative-{namespace}-{resource}-{verb}",
                    tenant_subject(namespace),
                    verb,
                    group,
                    resource,
                    namespace=namespace,
                ),
                False,
            )
        self.apply_document(self.source_document(namespace))
        self.wait_source_ready(namespace)
        self.apply_document(self.release_document(namespace))
        self.wait_failed_install_with_healthy_workload(namespace, resource, group)
        self.kube(
            "-n",
            namespace,
            "patch",
            "helmrelease",
            "acceptance",
            "--type=merge",
            "-p",
            '{"spec":{"suspend":true}}',
        )
        self.kube(
            "apply", "-f", str(self.held_path(ACCESS_MANIFEST_RELATIVE)), timeout=180
        )

    def run_upgrade_readiness_negative(
        self, namespace: str, resource: str, group: str
    ) -> None:
        self.apply_document(self.source_document(namespace))
        self.wait_source_ready(namespace)
        self.apply_document(self.release_document(namespace))
        installed = self.wait_release_reason(namespace, "InstallSucceeded")
        baseline = deployed_history(installed)
        if (
            baseline is None
            or type(baseline.get("version")) is not int
            or not isinstance(baseline.get("configDigest"), str)
        ):
            raise AcceptanceError("UPGRADE_NEGATIVE_BASELINE_INVALID")
        baseline_version = baseline["version"]
        baseline_config = baseline["configDigest"]
        self.remove_exact_rule(
            "role",
            "helm-reconciler",
            namespace=namespace,
            group=group,
            resource=resource,
            verbs=("get", "list", "watch"),
        )
        for verb in ("get", "list", "watch"):
            self.assert_review(
                AccessRow(
                    f"upgrade-negative-{namespace}-{resource}-{verb}",
                    tenant_subject(namespace),
                    verb,
                    group,
                    resource,
                    namespace=namespace,
                ),
                False,
            )
        patched = json_output(
            self.kube(
                "-n",
                namespace,
                "patch",
                "helmrelease",
                "acceptance",
                "--type=merge",
                "-p",
                json.dumps(
                    {
                        "spec": {
                            "commonMetadata": {
                                "annotations": {
                                    "acceptance.snaraj.dev/readiness-negative": resource
                                }
                            }
                        }
                    },
                    separators=(",", ":"),
                ),
                "-o",
                "json",
            )
        )
        target_generation = (
            patched.get("metadata", {}).get("generation")
            if isinstance(patched, dict)
            else None
        )
        if type(target_generation) is not int:
            raise AcceptanceError("UPGRADE_NEGATIVE_GENERATION_INVALID")
        failure_resource_version: str | None = None

        def remediated() -> bool | None:
            nonlocal failure_resource_version
            release = self.kube_json(
                "-n", namespace, "get", "helmrelease", "acceptance", "-o", "json"
            )
            if failure_resource_version is None:
                rollback = condition(release, "Remediated")
                rollback_already_succeeded = (
                    rollback is not None
                    and rollback.get("status") == "True"
                    and rollback.get("reason") == "RollbackSucceeded"
                )
                resource_version = release.get("metadata", {}).get(
                    "resourceVersion"
                )
                if (
                    not rollback_already_succeeded
                    and isinstance(resource_version, str)
                    and resource_version
                    and current_upgrade_failure_bound(
                        release,
                        generation=target_generation,
                        namespace=namespace,
                        resource=resource,
                        group=group,
                    )
                ):
                    failure_resource_version = resource_version
                return None
            if not rollback_after_failure_bound(
                release,
                generation=target_generation,
                failure_resource_version=failure_resource_version,
            ):
                return None
            latest = deployed_history(release)
            deployment = self.kube_json(
                "-n", namespace, "get", "deployment", "flux-rbac-acceptance", "-o", "json"
            )
            annotations = deployment.get("metadata", {}).get("annotations")
            if not isinstance(annotations, dict):
                annotations = {}
            if (
                latest
                and type(latest.get("version")) is int
                and latest["version"] > baseline_version
                and latest.get("configDigest") == baseline_config
                and "acceptance.snaraj.dev/readiness-negative" not in annotations
                and self.workload_healthy(namespace)
            ):
                return True
            return None

        self.wait_until(
            remediated, timeout=210, code="READINESS_UPGRADE_ROLLBACK_NOT_OBSERVED"
        )
        self.kube(
            "-n",
            namespace,
            "patch",
            "helmrelease",
            "acceptance",
            "--type=merge",
            "-p",
            '{"spec":{"suspend":true}}',
        )
        self.kube(
            "apply", "-f", str(self.held_path(ACCESS_MANIFEST_RELATIVE)), timeout=180
        )

    def readiness_negatives(self) -> None:
        self.run_install_readiness_negative("cloudflare-public", "pods", "")
        self.run_upgrade_readiness_negative(
            "naranjo-online", "replicasets", "apps"
        )
        self.assert_matrix(TENANT_ALLOWED_ROWS, True)
        self.evidence["readinessNegatives"] = {
            "pods": {
                "phase": "install",
                "reason": "InstallFailed",
                "authorizationMessageBound": True,
                "workloadHealthy": True,
            },
            "replicasets": {
                "phase": "upgrade",
                "reason": "UpgradeFailed",
                "authorizationMessageBound": True,
                "currentGenerationFailureObserved": True,
                "injectedFailureBound": True,
                "rollbackReason": "RollbackSucceeded",
                "helmRemediationRollback": "acceptance-only",
                "priorConfigRestored": True,
                "workloadHealthy": True,
            },
        }

    def wait_release_reason(self, namespace: str, reason: str, *, timeout: float = 180) -> dict[str, object]:
        def ready() -> dict[str, object] | None:
            release = self.kube_json(
                "-n", namespace, "get", "helmrelease", "acceptance", "-o", "json"
            )
            ready_condition = condition(release, "Ready")
            history = deployed_history(release)
            if (
                current_generation(release)
                and ready_condition
                and ready_condition.get("status") == "True"
                and ready_condition.get("reason") == reason
                and history is not None
                and self.workload_healthy(namespace)
            ):
                return release
            return None

        result = self.wait_until(ready, timeout=timeout, code="RELEASE_TRANSITION_NOT_READY")
        if not isinstance(result, dict):
            raise AcceptanceError("RELEASE_TRANSITION_INVALID")
        return result

    def release_lifecycle(self) -> None:
        namespace = "lidersea-com"
        self.apply_document(self.source_document(namespace))
        self.wait_source_ready(namespace)
        self.apply_document(self.release_document(namespace))
        installed = self.wait_release_reason(namespace, "InstallSucceeded")
        installed_history = deployed_history(installed)
        if installed_history is None or type(installed_history.get("version")) is not int:
            raise AcceptanceError("INSTALL_HISTORY_INVALID")
        install_version = installed_history["version"]

        self.kube(
            "-n",
            namespace,
            "patch",
            "helmrelease",
            "acceptance",
            "--type=merge",
            "-p",
            json.dumps(
                {
                    "spec": {
                        "commonMetadata": {
                            "annotations": {
                                "acceptance.snaraj.dev/revision": "two"
                            }
                        }
                    }
                },
                separators=(",", ":"),
            ),
        )
        upgraded = self.wait_release_reason(namespace, "UpgradeSucceeded")
        deployment = self.kube_json(
            "-n",
            namespace,
            "get",
            "deployment",
            "flux-rbac-acceptance",
            "-o",
            "json",
        )
        if not upgrade_effect_bound(
            upgraded,
            deployment,
            previous_version=install_version,
            annotation="acceptance.snaraj.dev/revision",
            value="two",
        ):
            raise AcceptanceError("UPGRADE_WORKLOAD_EFFECT_MISSING")
        upgrade_history = deployed_history(upgraded)
        if (
            upgrade_history is None
            or type(upgrade_history.get("version")) is not int
            or upgrade_history["version"] <= install_version
            or not isinstance(upgrade_history.get("configDigest"), str)
        ):
            raise AcceptanceError("UPGRADE_HISTORY_INVALID")
        upgrade_version = upgrade_history["version"]
        upgrade_config = upgrade_history["configDigest"]

        self.kube(
            "-n",
            namespace,
            "patch",
            "helmrelease",
            "acceptance",
            "--type=merge",
            "-p",
            json.dumps(
                {
                    "spec": {
                        "commonMetadata": {
                            "annotations": {
                                "acceptance.snaraj.dev/revision": "three"
                            }
                        },
                        "values": {"failureMode": True},
                    }
                },
                separators=(",", ":"),
            ),
        )

        def rolled_back() -> dict[str, object] | None:
            release = self.kube_json(
                "-n", namespace, "get", "helmrelease", "acceptance", "-o", "json"
            )
            remediated = condition(release, "Remediated")
            ready = condition(release, "Ready")
            rollback_condition = (
                remediated
                if remediated and remediated.get("status") == "True" and remediated.get("reason") == "RollbackSucceeded"
                else ready
            )
            latest = deployed_history(release)
            deployment = self.kube_json(
                "-n", namespace, "get", "deployment", "flux-rbac-acceptance", "-o", "json"
            )
            annotations = deployment.get("metadata", {}).get("annotations")
            if not isinstance(annotations, dict):
                annotations = {}
            containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            environment = containers[0].get("env", []) if isinstance(containers, list) and len(containers) == 1 else []
            failure_values = {
                item.get("value")
                for item in environment
                if isinstance(item, dict) and item.get("name") == "FAIL_STARTUP"
            }
            if (
                current_generation(release)
                and rollback_condition
                and rollback_condition.get("reason") == "RollbackSucceeded"
                and latest
                and type(latest.get("version")) is int
                and latest["version"] > upgrade_version
                and latest.get("configDigest") == upgrade_config
                and annotations.get("acceptance.snaraj.dev/revision") == "two"
                and failure_values == {"false"}
                and self.workload_healthy(namespace)
            ):
                return release
            return None

        rollback = self.wait_until(
            rolled_back, timeout=210, code="ROLLBACK_NOT_OBSERVED"
        )
        rollback_condition = condition(rollback, "Remediated") or condition(rollback, "Ready")
        self.evidence["releaseLifecycle"] = {
            "installReason": "InstallSucceeded",
            "upgradeReason": "UpgradeSucceeded",
            "upgradeUsedCommonMetadata": True,
            "rollbackReason": rollback_condition.get("reason") if rollback_condition else None,
            "remediateLastFailure": True,
            "rollbackRestoredPriorConfig": True,
            "helmRemediationRollback": "acceptance-only",
            "protectedConvergenceRollbackTested": False,
        }


def receipt_staging_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.flux-rbac-new")


def receipt_journal_paths_collide(receipt_path: Path, journal_path: Path) -> bool:
    receipt = receipt_path.parent.resolve(strict=False) / receipt_path.name
    journal = journal_path.parent.resolve(strict=False) / journal_path.name
    return bool(
        {receipt, receipt_staging_path(receipt)}
        & {journal, journal.with_name(journal.name + ".new")}
    )


def validate_receipt_path(path: Path, *, journal_path: Path | None = None) -> Path:
    if not path.is_absolute():
        raise AcceptanceError("RECEIPT_PATH_NOT_ABSOLUTE")
    resolved_parent = path.parent.resolve()
    try:
        inside_repository = resolved_parent == ROOT or ROOT in resolved_parent.parents
    except RuntimeError:
        raise AcceptanceError("RECEIPT_PATH_INVALID") from None
    candidate = resolved_parent / path.name
    if (
        inside_repository
        or not resolved_parent.is_dir()
        or path.exists()
        or path.is_symlink()
        or (
            journal_path is not None
            and receipt_journal_paths_collide(candidate, journal_path)
        )
    ):
        raise AcceptanceError("RECEIPT_PATH_INVALID")
    return candidate


def validate_pass_components(
    *,
    phase: State,
    primary_error_code: str | None,
    cleanup_error_code: str | None,
    tools: Mapping[str, object],
    pins: Mapping[str, str],
    evidence: Mapping[str, object],
    cleanup: Mapping[str, bool],
) -> None:
    if (
        phase is not State.COMPLETE
        or primary_error_code is not None
        or cleanup_error_code is not None
        or set(cleanup) != PASS_CLEANUP_KEYS
        or any(value is not True for value in cleanup.values())
        or set(tools) != TOOL_RECEIPT_KEYS
        or set(evidence) != PASS_EVIDENCE_KEYS
    ):
        raise AcceptanceError("RECEIPT_PASS_SCHEMA_INVALID")
    for name in TOOL_NAMES:
        if (
            not isinstance(tools.get(name), str)
            or not tools[name]
            or not isinstance(tools.get(f"{name}Sha256"), str)
            or DIGEST_RE.fullmatch(tools[f"{name}Sha256"]) is None
            or type(tools.get(f"{name}Device")) is not int
            or tools[f"{name}Device"] < 0
            or type(tools.get(f"{name}Inode")) is not int
            or tools[f"{name}Inode"] <= 0
        ):
            raise AcceptanceError("RECEIPT_TOOL_SCHEMA_INVALID")
    if (
        not isinstance(tools.get("dockerContextSha256"), str)
        or DIGEST_RE.fullmatch(tools["dockerContextSha256"]) is None
        or not isinstance(tools.get("dockerEndpointSha256"), str)
        or DIGEST_RE.fullmatch(tools["dockerEndpointSha256"]) is None
        or not isinstance(tools.get("dockerDaemonIdSha256"), str)
        or DIGEST_RE.fullmatch(tools["dockerDaemonIdSha256"]) is None
    ):
        raise AcceptanceError("RECEIPT_TOOL_SCHEMA_INVALID")
    if (
        tools["kind"] != pins.get("KIND_VERSION")
        or tools["kubectl"] != pins.get("KUBERNETES_VERSION")
        or tools["helm"] != pins.get("HELM_VERSION")
        or tools["go"] != pins.get("GO_VERSION")
    ):
        raise AcceptanceError("RECEIPT_TOOL_SCHEMA_INVALID")
    if any(
        not isinstance(pins.get(key), str) or not pins[key]
        for key in REQUIRED_PINS
    ) or any(
        "@" not in pins[key]
        or DIGEST_RE.fullmatch(pins[key].rsplit("@", 1)[1]) is None
        for key in (
            "KIND_NODE_IMAGE",
            "FLUX_SOURCE_CONTROLLER_IMAGE",
            "FLUX_KUSTOMIZE_CONTROLLER_IMAGE",
            "FLUX_HELM_CONTROLLER_IMAGE",
        )
    ):
        raise AcceptanceError("RECEIPT_PIN_SCHEMA_INVALID")
    inventory = evidence.get("inputInventorySha256")
    if (
        not isinstance(evidence.get("priorOwnedResidueRecovered"), bool)
        or not isinstance(inventory, dict)
        or set(inventory) != set(SNAPSHOT_INPUTS)
        or any(
            not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None
            for value in inventory.values()
        )
        or evidence.get("stockCrossingsAllowed") != len(CROSSING_ROWS)
        or evidence.get("finalOwnedAllowed") != len(OWNED_ROWS)
        or evidence.get("finalCrossingsDenied") != len(CROSSING_ROWS)
        or evidence.get("generalDenials") != len(GENERAL_DENIED_ROWS)
        or evidence.get("tenantReadsAllowed") != len(TENANT_ALLOWED_ROWS)
        or evidence.get("tenantBoundariesDenied") != len(TENANT_DENIED_ROWS)
    ):
        raise AcceptanceError("RECEIPT_EVIDENCE_SCHEMA_INVALID")
    initial = evidence.get("controllerInitialCreation")
    initial_keys = {
        "stockInputSha256",
        "stockZeroSha256",
        "finalRenderSha256",
        "finalZeroSha256",
        "changedFields",
        "bothZeroPodsBeforeStart",
        "destructiveWorkloadAction",
        "initialCreationOnly",
    }
    if (
        not isinstance(initial, dict)
        or set(initial) != initial_keys
        or any(
            not isinstance(initial.get(key), str)
            or DIGEST_RE.fullmatch(initial[key]) is None
            for key in (
                "stockInputSha256",
                "stockZeroSha256",
                "finalRenderSha256",
                "finalZeroSha256",
            )
        )
        or initial["stockInputSha256"] != inventory[STOCK_COMPONENTS_RELATIVE]
        or initial["stockInputSha256"] == initial["stockZeroSha256"]
        or initial["finalRenderSha256"] == initial["finalZeroSha256"]
        or initial["changedFields"] != list(CONTROLLER_ZERO_CHANGED_FIELDS)
        or initial["bothZeroPodsBeforeStart"] is not True
        or initial["destructiveWorkloadAction"] is not False
        or initial["initialCreationOnly"] is not True
    ):
        raise AcceptanceError("RECEIPT_LIFECYCLE_SCHEMA_INVALID")
    if evidence.get("kustomizeFinalRbacColdStart") != {
        "zeroPodsBeforeStart": True,
        "finalRbacOnly": True,
        "currentGenerationReady": True,
        "singleReadyPod": True,
        "managerRestartCount": 0,
        "helmRemainedZero": True,
        "podUidPreservedAfterHelmRestore": True,
        "destructiveWorkloadAction": False,
        "initialCreationOnly": True,
    }:
        raise AcceptanceError("RECEIPT_LIFECYCLE_SCHEMA_INVALID")
    if evidence.get("helmSecretColdStart") != {
        "negativeCacheSyncDenied": True,
        "positiveKubeletRetryReady": True,
        "readVerbsAllowed": len(HELM_SECRET_ROWS),
        "writeDenied": True,
        "samePodRecovered": True,
        "destructiveWorkloadAction": False,
        "initialCreationOnly": True,
    }:
        raise AcceptanceError("RECEIPT_LIFECYCLE_SCHEMA_INVALID")
    if evidence.get("readinessNegatives") != {
        "pods": {
            "phase": "install",
            "reason": "InstallFailed",
            "authorizationMessageBound": True,
            "workloadHealthy": True,
        },
        "replicasets": {
            "phase": "upgrade",
            "reason": "UpgradeFailed",
            "authorizationMessageBound": True,
            "currentGenerationFailureObserved": True,
            "injectedFailureBound": True,
            "rollbackReason": "RollbackSucceeded",
            "helmRemediationRollback": "acceptance-only",
            "priorConfigRestored": True,
            "workloadHealthy": True,
        },
    }:
        raise AcceptanceError("RECEIPT_LIFECYCLE_SCHEMA_INVALID")
    if evidence.get("releaseLifecycle") != {
        "installReason": "InstallSucceeded",
        "upgradeReason": "UpgradeSucceeded",
        "upgradeUsedCommonMetadata": True,
        "rollbackReason": "RollbackSucceeded",
        "remediateLastFailure": True,
        "rollbackRestoredPriorConfig": True,
        "helmRemediationRollback": "acceptance-only",
        "protectedConvergenceRollbackTested": False,
    }:
        raise AcceptanceError("RECEIPT_LIFECYCLE_SCHEMA_INVALID")


def build_receipt(
    *,
    expected_commit: str,
    result: str,
    phase: State,
    primary_error_code: str | None,
    cleanup_error_code: str | None,
    tools: Mapping[str, object],
    pins: Mapping[str, str],
    evidence: Mapping[str, object],
    cleanup: Mapping[str, bool],
) -> dict[str, object]:
    if result not in {"PASS", "FAIL"}:
        raise AcceptanceError("RECEIPT_RESULT_INVALID")
    if SHA_RE.fullmatch(expected_commit) is None:
        raise AcceptanceError("RECEIPT_COMMIT_INVALID")
    for error_code in (primary_error_code, cleanup_error_code):
        if error_code is not None and SAFE_CODE_RE.fullmatch(error_code) is None:
            raise AcceptanceError("RECEIPT_ERROR_INVALID")
    if result == "PASS":
        validate_pass_components(
            phase=phase,
            primary_error_code=primary_error_code,
            cleanup_error_code=cleanup_error_code,
            tools=tools,
            pins=pins,
            evidence=evidence,
            cleanup=cleanup,
        )
    receipt: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "FluxRbacKindAcceptanceReceipt",
        "commit": expected_commit,
        "result": result,
        "phase": phase.value,
        "primaryErrorCode": primary_error_code,
        "cleanupErrorCode": cleanup_error_code,
        "completedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "scope": dict(SCOPE_RECEIPT),
        "tools": dict(sorted(tools.items())),
        "pins": {
            "flux": pins.get("FLUX_VERSION"),
            "kindNode": pins.get("KIND_NODE_IMAGE"),
            "registry": REGISTRY_IMAGE,
            "sourceController": pins.get("FLUX_SOURCE_CONTROLLER_IMAGE"),
            "kustomizeController": pins.get("FLUX_KUSTOMIZE_CONTROLLER_IMAGE"),
            "helmController": pins.get("FLUX_HELM_CONTROLLER_IMAGE"),
        },
        "evidence": dict(evidence),
        "cleanup": dict(cleanup),
    }
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise AcceptanceError("RECEIPT_OVERSIZED")
    forbidden_keys = {
        "path",
        "kubeconfig",
        "clusterName",
        "networkName",
        "registryAddress",
        "registryPort",
        "stdout",
        "stderr",
        "token",
        "secret",
    }

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            if any(str(key) in forbidden_keys for key in value):
                raise AcceptanceError("RECEIPT_FIELD_FORBIDDEN")
            for nested in value.values():
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)
        elif isinstance(value, str):
            if "-----BEGIN " in value or "system:serviceaccount:" in value:
                raise AcceptanceError("RECEIPT_VALUE_FORBIDDEN")

    inspect(receipt)
    return receipt


def receipt_payload(receipt: Mapping[str, object]) -> bytes:
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > MAX_RECEIPT_BYTES:
        raise AcceptanceError("RECEIPT_OVERSIZED")
    return payload


def receipt_digest(receipt: Mapping[str, object]) -> str:
    return f"sha256:{hashlib.sha256(receipt_payload(receipt)).hexdigest()}"


def write_receipt(path: Path, receipt: Mapping[str, object]) -> str:
    payload = receipt_payload(receipt)
    staging = receipt_staging_path(path)
    if path.exists() or path.is_symlink() or staging.exists() or staging.is_symlink():
        raise AcceptanceError("RECEIPT_WRITE_FAILED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(staging, flags, 0o600)
    except OSError:
        raise AcceptanceError("RECEIPT_WRITE_FAILED") from None
    try:
        write_all(descriptor, payload)
        os.fsync(descriptor)
    except OSError:
        raise AcceptanceError("RECEIPT_WRITE_FAILED") from None
    finally:
        os.close(descriptor)
    try:
        os.link(staging, path, follow_symlinks=False)
        fsync_directory(path.parent)
        staging.unlink()
        fsync_directory(path.parent)
    except OSError:
        raise AcceptanceError("RECEIPT_WRITE_FAILED") from None
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AcceptanceError("RECEIPT_MODE_INVALID")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Run Flux RBAC acceptance in a wholly self-created isolated kind cluster."
    )
    argument_parser.add_argument(
        "--expected-commit",
        required=True,
        help="Exact clean, pushed 40-hex branch head to bind into the receipt.",
    )
    argument_parser.add_argument(
        "--receipt",
        required=True,
        type=Path,
        help="New absolute path outside the repository for the mode-0600 receipt.",
    )
    return argument_parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        require_isolated_interpreter()
    except AcceptanceError as error:
        print(f"FAIL {error.code}", file=sys.stderr)
        return 2
    arguments = parser().parse_args(argv)
    runner = Runner()
    owned: OwnedResources | None = None
    harness: AcceptanceHarness | None = None
    pins: dict[str, str] = {}
    primary_error_code: str | None = None
    cleanup_error_code: str | None = None
    cleanup: dict[str, bool] = {
        "clusterAbsent": False,
        "registryAbsent": False,
        "networkAbsent": False,
        "imageAbsent": False,
        "kubeconfigAbsent": False,
        "temporaryRootAbsent": False,
        "journalRetainedUntilReceipt": False,
    }
    receipt_path: Path
    try:
        if SHA_RE.fullmatch(arguments.expected_commit) is None:
            raise AcceptanceError("EXPECTED_COMMIT_INVALID")
        runner.resolve_tools()
        validate_launch_context(runner, arguments.expected_commit)
        journal_path = default_journal_path()
        prior_recovery = recover_previous(runner, journal_path)
        if not runner.tools_bound():
            runner.resolve_tools()
        receipt_path = validate_receipt_path(
            arguments.receipt,
            journal_path=journal_path,
        )
        git_preflight(runner, arguments.expected_commit)
        if not runner.docker_bound():
            runner.bind_local_docker()
        pins = parse_versions_payload(
            runner.run(
                (
                    "git",
                    "cat-file",
                    "blob",
                    f"{arguments.expected_commit}:{VERSIONS_RELATIVE}",
                )
            ).stdout
        )
    except AcceptanceError as error:
        print(f"FAIL {error.code}", file=sys.stderr)
        return 2

    interrupted = False
    old_handlers: dict[int, object] = {}

    def stop(_signal_number: int, _frame: object) -> None:
        nonlocal interrupted
        if interrupted:
            return
        interrupted = True
        raise AcceptanceError("SIGNAL_RECEIVED")

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[number] = signal.getsignal(number)
        signal.signal(number, stop)
    try:
        harness = AcceptanceHarness(
            runner,
            arguments.expected_commit,
            pins,
            journal_path=journal_path,
            receipt_path=receipt_path,
            prior_recovery=prior_recovery,
        )
        try:
            harness.run()
            owned = harness.owned
        except AcceptanceError as error:
            owned = harness.owned
            primary_error_code = error.code
        except Exception:
            owned = harness.owned
            primary_error_code = "UNEXPECTED_FAILURE"
        finally:
            if owned is not None:
                try:
                    owned.prepare_for_cleanup()
                    cleanup = owned.cleanup()
                except AcceptanceError:
                    cleanup_error_code = "CLEANUP_FAILED"
                    try:
                        cleanup = owned.verify_absent(include_journal=False)
                        cleanup["journalRetainedUntilReceipt"] = (
                            owned.journal_path.exists()
                        )
                    except AcceptanceError:
                        cleanup = {key: False for key in cleanup}
        result = (
            "PASS"
            if primary_error_code is None
            and cleanup_error_code is None
            and harness.machine.current is State.COMPLETE
            else "FAIL"
        )
        receipt = build_receipt(
            expected_commit=arguments.expected_commit,
            result=result,
            phase=harness.machine.current,
            primary_error_code=primary_error_code,
            cleanup_error_code=cleanup_error_code,
            tools=harness.tools,
            pins=harness.pins,
            evidence=harness.evidence,
            cleanup=cleanup,
        )
        expected_receipt_digest = receipt_digest(receipt)
        if owned is not None:
            owned.bind_receipt(expected_receipt_digest, cleanup)
        observed_receipt_digest = write_receipt(receipt_path, receipt)
        if observed_receipt_digest != expected_receipt_digest:
            raise AcceptanceError("RECEIPT_DIGEST_MISMATCH")
        if owned is not None and all(cleanup.values()):
            owned.close_journal()
            owned.remove_closed_journal()
        if result == "PASS":
            print("PASS: bounded receipt written after zero-residue verification")
            return 0
        suffix = " after signal" if interrupted else ""
        print(
            f"FAIL primary={primary_error_code} cleanup={cleanup_error_code}{suffix}: bounded receipt written",
            file=sys.stderr,
        )
        return 1
    finally:
        for number, previous in old_handlers.items():
            signal.signal(number, previous)


if __name__ == "__main__":
    raise SystemExit(main())
