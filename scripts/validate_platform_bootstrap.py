#!/usr/bin/env python3
"""Render and validate the owner-attended #189 bootstrap without live writes."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts/ci/platform_release_contract.py"
CLOSURE_PATH = ROOT / "scripts/ci/platform_bootstrap_closure.py"
ADMISSION_POLICY_PATH = ROOT / "bootstrap/flux/release-selector/admission-policy.json"
ADMISSION_BINDING_PATH = ROOT / "bootstrap/flux/release-selector/admission-binding.json"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
NAMESPACE = "flux-system"
SELECTOR = "platform-release-selector"
SITES = ("naranjo-online", "lidersea-com")
PRIVATE_IPV4 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

INVENTORY = (
    ("selector-serviceaccount", "serviceaccount", SELECTOR),
    (
        "selector-admission-policy",
        "validatingadmissionpolicy.admissionregistration.k8s.io",
        SELECTOR,
    ),
    (
        "selector-admission-binding",
        "validatingadmissionpolicybinding.admissionregistration.k8s.io",
        SELECTOR,
    ),
    ("selector-role", "role.rbac.authorization.k8s.io", SELECTOR),
    ("selector-rolebinding", "rolebinding.rbac.authorization.k8s.io", SELECTOR),
    (
        "parent-impersonation-role",
        "role.rbac.authorization.k8s.io",
        "flux-controller-impersonation",
    ),
    (
        "parent-impersonation-rolebinding",
        "rolebinding.rbac.authorization.k8s.io",
        "flux-controller-impersonation",
    ),
    ("naranjo-site-serviceaccount", "serviceaccount", "naranjo-online-reconciler"),
    ("naranjo-site-role", "role.rbac.authorization.k8s.io", "flux-release-reconciler"),
    ("naranjo-site-rolebinding", "rolebinding.rbac.authorization.k8s.io", "naranjo-online-reconciler"),
    ("lidersea-site-serviceaccount", "serviceaccount", "lidersea-com-reconciler"),
    ("lidersea-site-role", "role.rbac.authorization.k8s.io", "flux-release-reconciler"),
    ("lidersea-site-rolebinding", "rolebinding.rbac.authorization.k8s.io", "lidersea-com-reconciler"),
    ("selector-network-dns", "networkpolicy.networking.k8s.io", SELECTOR + "-dns"),
    (
        "selector-network-public",
        "networkpolicy.networking.k8s.io",
        SELECTOR + "-public-https",
    ),
    (
        "selector-network-api",
        "networkpolicy.networking.k8s.io",
        SELECTOR + "-kube-apiserver",
    ),
    ("selector-cronjob", "cronjob.batch", SELECTOR),
    ("source", "gitrepository.source.toolkit.fluxcd.io", "flux-system"),
    (
        "naranjo-kustomization",
        "kustomization.kustomize.toolkit.fluxcd.io",
        "naranjo-online-reconciler",
    ),
    (
        "lidersea-kustomization",
        "kustomization.kustomize.toolkit.fluxcd.io",
        "lidersea-com-reconciler",
    ),
)
SUSPENDABLE = {
    "selector-cronjob",
    "naranjo-kustomization",
    "lidersea-kustomization",
}
MIGRATABLE_ROLE_COMPONENTS = {
    "parent-impersonation-role",
    "naranjo-site-role",
    "lidersea-site-role",
}
PREEXISTING_PARENT_COMPONENTS = {
    "parent-impersonation-role",
    "parent-impersonation-rolebinding",
    "naranjo-site-serviceaccount",
    "naranjo-site-role",
    "naranjo-site-rolebinding",
    "lidersea-site-serviceaccount",
    "lidersea-site-role",
    "lidersea-site-rolebinding",
}
IDENTITY_SCHEMA = "https://snaraj.dev/schemas/platform-release-identity/v1"
SELECTOR_USERNAME = "system:serviceaccount:flux-system:platform-release-selector"
FLUX_RECONCILE_ANNOTATION = "reconcile.fluxcd.io/requestedAt"
KUBECTL_LAST_APPLIED_ANNOTATION = (
    "kubectl.kubernetes.io/last-applied-configuration"
)
SELECTOR_ANNOTATION_PREFIX = "release-selector.platform.snaraj.dev/"
ANNOTATIONS = (
    "schema",
    "release-id",
    "release-tag",
    "release-target-sha",
    "tag-object-sha",
    "main-ci",
    "platform-release",
    "selector-image-digest",
    "identity-sha256",
)
SITE_FACT_KEYS = (
    "naranjo-chart-digest", "naranjo-chart-version",
    "lidersea-chart-digest", "lidersea-chart-version",
)
REMOTE_OUTPUT_KEYS = frozenset((*ANNOTATIONS, "selector-build-sha", *SITE_FACT_KEYS))
SELECTOR_ANNOTATIONS = frozenset(
    SELECTOR_ANNOTATION_PREFIX + name for name in ANNOTATIONS
)
SOURCE_SPEC_FIELDS = frozenset(
    ("ignore", "interval", "ref", "sparseCheckout", "timeout", "url")
)


def closure_module():
    spec = importlib.util.spec_from_file_location("platform_bootstrap_closure", CLOSURE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("bootstrap closure validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def selector_digest(value: str) -> str:
    if not DIGEST_RE.fullmatch(value) or value == "sha256:" + "0" * 64:
        raise SystemExit("selector image digest must be one nonzero sha256")
    return value


def selector_build_sha(value: object) -> str:
    if (
        not isinstance(value, str)
        or SHA_RE.fullmatch(value) is None
        or value == "0" * 40
    ):
        raise SystemExit("selector build source must be one nonzero canonical SHA")
    return value


def endpoint_cidrs(values: list[str]) -> list[str]:
    if not 1 <= len(values) <= 16 or len(values) != len(set(values)):
        raise SystemExit("supply one to sixteen unique private API /32 endpoints")
    parsed = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise SystemExit("API endpoint is not a canonical CIDR") from error
        if (
            network.version != 4
            or network.prefixlen != 32
            or not any(network.subnet_of(private) for private in PRIVATE_IPV4)
        ):
            raise SystemExit("API endpoints must be RFC1918 IPv4 /32 values")
        parsed.append(str(network))
    return sorted(parsed)


def server_endpoint(value: str, cidrs: list[str]) -> None:
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise SystemExit("API server must use a canonical private IPv4 address") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or address.version != 4
        or not any(address in private for private in PRIVATE_IPV4)
        or port != 6443
        or value not in {f"https://{address}:6443", f"https://{address}:6443/"}
        or f"{address}/32" not in cidrs
    ):
        raise SystemExit("API server must be one supplied private backend on HTTPS 6443")


def validate_endpoint_slices(value: dict[str, object], cidrs: list[str]) -> None:
    if value.get("apiVersion") != "discovery.k8s.io/v1" or value.get("kind") != "EndpointSliceList":
        raise SystemExit("API endpoint capture is not an EndpointSliceList")
    items = value.get("items")
    if not isinstance(items, list) or not items:
        raise SystemExit("kubernetes.default has no EndpointSlice")
    observed: list[str] = []
    for item in items:
        if not isinstance(item, dict) or item.get("addressType") != "IPv4":
            raise SystemExit("API EndpointSlice address family is foreign")
        meta = item.get("metadata")
        ports = item.get("ports")
        endpoints = item.get("endpoints")
        if (
            not isinstance(meta, dict)
            or meta.get("namespace") != "default"
            or meta.get("deletionTimestamp") is not None
            or not isinstance(meta.get("labels"), dict)
            or meta["labels"].get("kubernetes.io/service-name") != "kubernetes"
            or not isinstance(ports, list)
            or len(ports) != 1
            or not isinstance(ports[0], dict)
            or ports[0].get("name") != "https"
            or ports[0].get("protocol") != "TCP"
            or ports[0].get("port") != 6443
            or not isinstance(endpoints, list)
            or not endpoints
        ):
            raise SystemExit("API EndpointSlice identity or HTTPS port is foreign")
        for endpoint in endpoints:
            conditions = endpoint.get("conditions") if isinstance(endpoint, dict) else None
            addresses = endpoint.get("addresses") if isinstance(endpoint, dict) else None
            if (
                not isinstance(conditions, dict)
                or conditions.get("ready") is not True
                or conditions.get("terminating") is True
                or conditions.get("serving") is False
                or not isinstance(addresses, list)
                or len(addresses) != 1
            ):
                raise SystemExit("API endpoint is not uniquely ready")
            try:
                address = ipaddress.ip_address(addresses[0])
            except ValueError as error:
                raise SystemExit("API endpoint address is invalid") from error
            if (
                address.version != 4
                or not any(address in private for private in PRIVATE_IPV4)
                or str(address) != addresses[0]
            ):
                raise SystemExit("API endpoint must be canonical RFC1918 IPv4")
            observed.append(f"{address}/32")
    if len(observed) != len(set(observed)) or sorted(observed) != cidrs:
        raise SystemExit("supplied API endpoint set differs from live ready backends")


def provenance_binds_source(predicate: object, sha: str) -> bool:
    if not isinstance(predicate, dict):
        return False
    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        return False
    external = build_definition.get("externalParameters")
    metadata = run_details.get("metadata")
    if not isinstance(external, dict) or not isinstance(metadata, dict):
        return False
    config_source = external.get("configSource")
    completeness = metadata.get("buildkit_completeness")
    return (
        build_definition.get("buildType")
        == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
        and config_source
        == {
            "uri": f"https://github.com/snaraj/website-infrastructure.git#{sha}",
            "digest": {"sha1": sha},
            "path": "cmd/platform-release-selector/Dockerfile",
        }
        and isinstance(completeness, dict)
        and completeness.get("resolvedDependencies") is True
        and metadata.get("buildkit_hermetic") is True
    )


def validate_attestations(path: Path, digest: str, build_sha: str) -> None:
    selector_digest(digest)
    build_sha = selector_build_sha(build_sha)
    records = path.read_text(encoding="utf-8").splitlines()
    if not records or path.stat().st_size > 4 * 1024 * 1024:
        raise SystemExit("selector attestation receipt count or size is invalid")
    for line in records:
        envelope = json.loads(line)
        if not isinstance(envelope, dict) or envelope.get("payloadType") != "application/vnd.in-toto+json":
            raise SystemExit("selector attestation envelope is foreign")
        payload = envelope.get("payload")
        if not isinstance(payload, str):
            raise SystemExit("selector attestation payload is absent")
        try:
            statement = json.loads(base64.b64decode(payload, validate=True))
        except (ValueError, json.JSONDecodeError) as error:
            raise SystemExit("selector attestation payload is invalid") from error
        if (
            not isinstance(statement, dict)
            or statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
        ):
            raise SystemExit("selector attestation predicate type is foreign")
        subjects = statement.get("subject")
        expected_hex = digest.removeprefix("sha256:")
        if (
            not isinstance(subjects, list)
            or not any(
                isinstance(item, dict)
                and isinstance(item.get("digest"), dict)
                and item["digest"].get("sha256") == expected_hex
                for item in subjects
            )
            or not provenance_binds_source(statement.get("predicate"), build_sha)
        ):
            raise SystemExit("selector attestation does not bind image digest and source SHA")


def metadata(name: str, **extra: object) -> dict[str, object]:
    return {"name": name, "namespace": NAMESPACE, **extra}


def target_annotations(path: Path | None, digest: str) -> dict[str, str]:
    if path is None:
        raise SystemExit("target source requires validated target annotations")
    value = load(path)
    if set(value) != REMOTE_OUTPUT_KEYS:
        raise SystemExit("target annotation inventory is incomplete or foreign")
    if not all(isinstance(item, str) for item in value.values()):
        raise SystemExit("target annotation values must be strings")
    tag, sha = local_release()
    if (
        value["schema"] != IDENTITY_SCHEMA
        or value["release-tag"] != tag
        or value["release-target-sha"] != sha
        or value["selector-image-digest"] != digest
        or selector_build_sha(value["selector-build-sha"])
        != value["selector-build-sha"]
        or not re.fullmatch(r"[1-9][0-9]*", value["release-id"])
        or not SHA_RE.fullmatch(value["tag-object-sha"])
        or not re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", value["main-ci"])
        or not re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", value["platform-release"])
        or not DIGEST_RE.fullmatch(value["identity-sha256"])
    ):
        raise SystemExit("target annotations do not bind the exact local release")
    return {key: str(value[key]) for key in ANNOTATIONS}


def target_oci_repository(site: str, path: Path | None) -> dict[str, object]:
    if site not in SITES or path is None:
        raise SystemExit("target OCIRepository requires one exact site and identity")
    facts = load(path)
    if set(facts) != REMOTE_OUTPUT_KEYS:
        raise SystemExit("target OCIRepository identity receipt is incomplete")
    prefix = "naranjo" if site == "naranjo-online" else "lidersea"
    digest = facts[f"{prefix}-chart-digest"]
    version = facts[f"{prefix}-chart-version"]
    if (
        not isinstance(digest, str)
        or DIGEST_RE.fullmatch(digest) is None
        or digest == "sha256:" + "0" * 64
        or not isinstance(version, str)
        or re.fullmatch(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is None
    ):
        raise SystemExit("target OCIRepository chart facts are invalid")
    repository = "naranjo.online" if site == "naranjo-online" else "lidersea.com"
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "OCIRepository",
        "metadata": {
            "annotations": {"platform.snaraj.dev/chart-release": version},
            "name": site + "-chart",
            "namespace": site,
        },
        "spec": {
            "interval": "10m0s",
            "layerSelector": {
                "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                "operation": "copy",
            },
            "ref": {"digest": digest},
            "timeout": "60s",
            "url": f"oci://ghcr.io/snaraj/charts/{site}",
            "verify": {
                "matchOIDCIdentity": [{
                    "issuer": r"^https://token\.actions\.githubusercontent\.com$",
                    "subject": (
                        rf"^https://github\.com/snaraj/{repository.replace('.', r'\.')}/"
                        r"\.github/workflows/release-publisher\.yml@refs/heads/main$"
                    ),
                }],
                "provider": "cosign",
            },
        },
    }


def desired(
    component: str,
    digest: str,
    cidrs: list[str],
    source_state: str = "target",
    target_path: Path | None = None,
    build_sha: str | None = None,
) -> dict[str, object]:
    selector_digest(digest)
    cidrs = endpoint_cidrs(cidrs)
    labels = {"app.kubernetes.io/name": SELECTOR, "app.kubernetes.io/part-of": SELECTOR}
    if component == "selector-serviceaccount":
        return {
            "apiVersion": "v1",
            "automountServiceAccountToken": False,
            "kind": "ServiceAccount",
            "metadata": metadata(SELECTOR),
        }
    if component == "selector-admission-policy":
        return load(ADMISSION_POLICY_PATH)
    if component == "selector-admission-binding":
        return load(ADMISSION_BINDING_PATH)
    if component == "selector-role":
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": metadata(SELECTOR),
            "rules": [
                {
                    "apiGroups": ["source.toolkit.fluxcd.io"],
                    "resourceNames": ["flux-system"],
                    "resources": ["gitrepositories"],
                    "verbs": ["get", "patch"],
                },
                {
                    "apiGroups": ["kustomize.toolkit.fluxcd.io"],
                    "resourceNames": [
                        "naranjo-online-reconciler", "lidersea-com-reconciler",
                    ],
                    "resources": ["kustomizations"],
                    "verbs": ["get"],
                },
            ],
        }
    if component == "selector-rolebinding":
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": metadata(SELECTOR),
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": SELECTOR},
            "subjects": [{"kind": "ServiceAccount", "name": SELECTOR, "namespace": NAMESPACE}],
        }
    if component == "parent-impersonation-role":
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": metadata("flux-controller-impersonation"),
            "rules": [{
                "apiGroups": [""],
                "resourceNames": [
                    "naranjo-online-reconciler", "lidersea-com-reconciler",
                ],
                "resources": ["serviceaccounts"],
                "verbs": ["impersonate"],
            }],
        }
    if component == "parent-impersonation-rolebinding":
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": metadata("flux-controller-impersonation"),
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "flux-controller-impersonation",
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "kustomize-controller",
                "namespace": NAMESPACE,
            }],
        }
    if component in {"naranjo-site-serviceaccount", "lidersea-site-serviceaccount"}:
        site = "naranjo-online" if component.startswith("naranjo") else "lidersea-com"
        return {
            "apiVersion": "v1",
            "automountServiceAccountToken": False,
            "kind": "ServiceAccount",
            "metadata": metadata(site + "-reconciler"),
        }
    if component in {
        "naranjo-site-role", "naranjo-site-rolebinding",
        "lidersea-site-role", "lidersea-site-rolebinding",
    }:
        site = "naranjo-online" if component.startswith("naranjo") else "lidersea-com"
        if component.endswith("rolebinding"):
            return {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": site + "-reconciler", "namespace": site},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "flux-release-reconciler",
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": site + "-reconciler",
                    "namespace": NAMESPACE,
                }],
            }
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "flux-release-reconciler", "namespace": site},
            "rules": [
                {
                    "apiGroups": ["source.toolkit.fluxcd.io"],
                    "resources": ["ocirepositories"],
                    "verbs": ["list"],
                },
                {
                    "apiGroups": ["source.toolkit.fluxcd.io"],
                    "resources": ["ocirepositories"],
                    "verbs": ["create"],
                },
                {
                    "apiGroups": ["source.toolkit.fluxcd.io"],
                    "resourceNames": [site + "-chart"],
                    "resources": ["ocirepositories"],
                    "verbs": ["get", "update", "patch"],
                },
                {
                    "apiGroups": ["helm.toolkit.fluxcd.io"],
                    "resources": ["helmreleases"],
                    "verbs": ["list"],
                },
                {
                    "apiGroups": ["helm.toolkit.fluxcd.io"],
                    "resources": ["helmreleases"],
                    "verbs": ["create"],
                },
                {
                    "apiGroups": ["helm.toolkit.fluxcd.io"],
                    "resourceNames": [site],
                    "resources": ["helmreleases"],
                    "verbs": ["get", "update", "patch"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resources": ["networkpolicies"],
                    "verbs": ["list"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resources": ["networkpolicies"],
                    "verbs": ["create"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resourceNames": ["default-deny"],
                    "resources": ["networkpolicies"],
                    "verbs": ["get", "update", "patch"],
                },
            ],
        }
    selector_match = {"matchLabels": {"app.kubernetes.io/name": SELECTOR}}
    if component == "selector-network-dns":
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata(SELECTOR + "-dns"),
            "spec": {
                "egress": [{
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                    "to": [{
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }],
                }],
                "podSelector": selector_match,
                "policyTypes": ["Egress"],
            },
        }
    if component == "selector-network-public":
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata(SELECTOR + "-public-https"),
            "spec": {
                "egress": [{
                    "ports": [{"port": 443, "protocol": "TCP"}],
                    "to": [{"ipBlock": {
                        "cidr": "0.0.0.0/0",
                        "except": [
                            "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                            "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                            "224.0.0.0/4", "240.0.0.0/4",
                        ],
                    }}],
                }],
                "podSelector": selector_match,
                "policyTypes": ["Egress"],
            },
        }
    if component == "selector-network-api":
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata(
                SELECTOR + "-kube-apiserver",
                annotations={"platform.snaraj.dev/readiness": "private-api-endpoint-set"},
            ),
            "spec": {
                "egress": [{
                    "ports": [{"port": 6443, "protocol": "TCP"}],
                    "to": [{"ipBlock": {"cidr": cidr}} for cidr in cidrs],
                }],
                "podSelector": selector_match,
                "policyTypes": ["Egress"],
            },
        }
    if component == "selector-cronjob":
        build_sha = selector_build_sha(build_sha)
        return {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": metadata(SELECTOR),
            "spec": {
                "concurrencyPolicy": "Forbid",
                "failedJobsHistoryLimit": 3,
                "jobTemplate": {"spec": {
                    "activeDeadlineSeconds": 600,
                    "backoffLimit": 0,
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "automountServiceAccountToken": True,
                            "containers": [{
                                "env": [
                                    {"name": "EXPECTED_SELECTOR_BUILD_SHA", "value": build_sha},
                                    {"name": "EXPECTED_SELECTOR_IMAGE_DIGEST", "value": digest},
                                ],
                                "image": "ghcr.io/snaraj/website-infrastructure/platform-release-selector@" + digest,
                                "imagePullPolicy": "IfNotPresent",
                                "name": "selector",
                                "resources": {
                                    "limits": {"cpu": "100m", "memory": "64Mi"},
                                    "requests": {"cpu": "5m", "memory": "16Mi"},
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                                "volumeMounts": [{
                                    "mountPath": "/var/run/release-selector",
                                    "name": "sigstore-scratch",
                                }],
                            }],
                            "enableServiceLinks": False,
                            "restartPolicy": "Never",
                            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                            "serviceAccountName": SELECTOR,
                            "volumes": [{
                                "emptyDir": {"medium": "Memory", "sizeLimit": "2Mi"},
                                "name": "sigstore-scratch",
                            }],
                        },
                    },
                    "ttlSecondsAfterFinished": 3600,
                }},
                "schedule": "7,37 * * * *",
                "startingDeadlineSeconds": 300,
                "successfulJobsHistoryLimit": 1,
                "suspend": True,
            },
        }
    if component == "source":
        if source_state != "target":
            raise SystemExit("bootstrap never creates a legacy predecessor source")
        values = target_annotations(target_path, digest)
        source_tag = values["release-tag"]
        return {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": metadata("flux-system", annotations={
                "release-selector.platform.snaraj.dev/" + key: values[key]
                for key in ANNOTATIONS
            }),
            "spec": {
                "ignore": "/*\n!/kubernetes/\n/kubernetes/*\n!/kubernetes/websites/\n/kubernetes/websites/*\n!/kubernetes/websites/naranjo-online/\n!/kubernetes/websites/naranjo-online/**\n!/kubernetes/websites/lidersea-com/\n!/kubernetes/websites/lidersea-com/**\n",
                "interval": "1m0s",
                "ref": {"tag": source_tag},
                "sparseCheckout": ["kubernetes/websites/naranjo-online", "kubernetes/websites/lidersea-com"],
                "timeout": "60s",
                "url": "https://github.com/snaraj/website-infrastructure.git",
            },
        }
    if component in {"naranjo-kustomization", "lidersea-kustomization"}:
        site = "naranjo-online" if component.startswith("naranjo") else "lidersea-com"
        return {
            "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
            "kind": "Kustomization",
            "metadata": metadata(site + "-reconciler"),
            "spec": {
                "deletionPolicy": "Orphan",
                "force": False,
                "interval": "10m0s",
                "path": "./kubernetes/websites/" + site,
                "prune": False,
                "retryInterval": "1m0s",
                "serviceAccountName": site + "-reconciler",
                "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
                "suspend": True,
                "timeout": "5m0s",
                "wait": True,
            },
        }
    raise SystemExit("unknown bootstrap component")


def legacy_role(component: str) -> dict[str, object]:
    """Return the one exact pre-#189 Role shape eligible for narrowing."""
    if component == "parent-impersonation-role":
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": metadata("flux-controller-impersonation"),
            "rules": [{
                "apiGroups": [""],
                "resourceNames": [
                    "root-reconciler",
                    "platform-prerequisites-reconciler",
                    "admission-reconciler",
                    "platform-services-reconciler",
                    "naranjo-online-reconciler",
                    "lidersea-com-reconciler",
                ],
                "resources": ["serviceaccounts"],
                "verbs": ["impersonate"],
            }],
        }
    if component in {"naranjo-site-role", "lidersea-site-role"}:
        site = "naranjo-online" if component.startswith("naranjo") else "lidersea-com"
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "flux-release-reconciler", "namespace": site},
            "rules": [
                {
                    "apiGroups": ["source.toolkit.fluxcd.io"],
                    "resources": ["ocirepositories"],
                    "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
                },
                {
                    "apiGroups": ["helm.toolkit.fluxcd.io"],
                    "resources": ["helmreleases"],
                    "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
                },
            ],
        }
    raise SystemExit("Role is not an eligible bootstrap predecessor")


def strip_default(mapping: dict[str, object], key: str, value: object) -> None:
    if key in mapping and mapping[key] == value:
        del mapping[key]


def normalized(value: dict[str, object], component: str) -> dict[str, object]:
    result = copy.deepcopy(value)
    result.pop("status", None)
    metadata_value = result.get("metadata")
    if not isinstance(metadata_value, dict):
        raise SystemExit("live object metadata is absent")
    if metadata_value.get("deletionTimestamp") is not None:
        raise SystemExit("live object is deleting")
    finalizers = metadata_value.get("finalizers", [])
    allowed_finalizers = (
        ([], ["finalizers.fluxcd.io"])
        if component in {"source", "naranjo-kustomization", "lidersea-kustomization"}
        else ([],)
    )
    if finalizers not in allowed_finalizers:
        raise SystemExit("live object carries a foreign finalizer")
    if metadata_value.get("ownerReferences") not in (None, []):
        raise SystemExit("live object carries an owner")
    for key in (
        "creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp",
        "finalizers", "generateName", "generation", "managedFields",
        "ownerReferences", "resourceVersion", "selfLink", "uid",
    ):
        metadata_value.pop(key, None)
    annotations = metadata_value.get("annotations", {})
    if not isinstance(annotations, dict):
        raise SystemExit("live object annotations are malformed")
    volatile_annotations: set[str] = set()
    if component in PREEXISTING_PARENT_COMPONENTS:
        volatile_annotations.add(KUBECTL_LAST_APPLIED_ANNOTATION)
    if component in {
        "source",
        "naranjo-kustomization",
        "lidersea-kustomization",
    }:
        volatile_annotations.add(FLUX_RECONCILE_ANNOTATION)
    for annotation in volatile_annotations:
        if annotation in annotations and not isinstance(annotations[annotation], str):
            raise SystemExit("live volatile annotation is malformed")
        annotations.pop(annotation, None)
    for key in ("annotations", "labels"):
        if metadata_value.get(key) == {}:
            metadata_value.pop(key)
    if component == "selector-admission-policy":
        constraints = result.get("spec", {}).get("matchConstraints", {})
        if isinstance(constraints, dict):
            strip_default(constraints, "namespaceSelector", {})
            strip_default(constraints, "objectSelector", {})
    if component == "selector-admission-binding":
        resources = result.get("spec", {}).get("matchResources", {})
        if isinstance(resources, dict):
            strip_default(resources, "namespaceSelector", {})
            strip_default(resources, "objectSelector", {})
    if component == "selector-rolebinding":
        subjects = result.get("subjects")
        if subjects is None:
            result["subjects"] = []
        elif not isinstance(subjects, list):
            raise SystemExit("selector RoleBinding subjects are malformed")
    if component == "selector-cronjob":
        spec = result["spec"]
        assert isinstance(spec, dict)
        job_template = spec["jobTemplate"]
        strip_default(job_template, "metadata", {})
        job = job_template["spec"]
        for key, default in (
            ("completionMode", "NonIndexed"), ("completions", 1),
            ("manualSelector", False), ("parallelism", 1), ("suspend", False),
            ("podReplacementPolicy", "TerminatingOrFailed"),
        ):
            strip_default(job, key, default)
        pod = job["template"]["spec"]
        if pod.get("serviceAccount") == pod.get("serviceAccountName"):
            pod.pop("serviceAccount", None)
        for key, default in (
            ("dnsPolicy", "ClusterFirst"), ("schedulerName", "default-scheduler"),
            ("terminationGracePeriodSeconds", 30),
        ):
            strip_default(pod, key, default)
        container = pod["containers"][0]
        strip_default(container, "terminationMessagePath", "/dev/termination-log")
        strip_default(container, "terminationMessagePolicy", "File")
    return result


def selector_admission_allows(
    old: dict[str, object] | None,
    new: dict[str, object],
    request: dict[str, str],
) -> bool:
    """Mirror the native policy for hostile, dependency-free patch fixtures."""
    matches = (
        request.get("username") == SELECTOR_USERNAME
        and request.get("operation") == "UPDATE"
        and request.get("group") == "source.toolkit.fluxcd.io"
        and request.get("version") == "v1"
        and request.get("resource") == "gitrepositories"
        and request.get("subresource", "") == ""
    )
    if not matches:
        return True
    if old is None:
        return False
    try:
        old_metadata = nested(old.get("metadata"), "old source metadata")
        new_metadata = nested(new.get("metadata"), "new source metadata")
        old_spec = nested(old.get("spec"), "old source spec")
        new_spec = nested(new.get("spec"), "new source spec")
        old_ref = nested(old_spec.get("ref"), "old source ref")
        new_ref = nested(new_spec.get("ref"), "new source ref")
    except SystemExit:
        return False
    if (
        request.get("namespace") != NAMESPACE
        or request.get("name") != "flux-system"
        or old.get("apiVersion") != "source.toolkit.fluxcd.io/v1"
        or new.get("apiVersion") != old.get("apiVersion")
        or old.get("kind") != "GitRepository"
        or new.get("kind") != old.get("kind")
        or old_metadata.get("name") != "flux-system"
        or new_metadata.get("name") != old_metadata.get("name")
        or old_metadata.get("namespace") != NAMESPACE
        or new_metadata.get("namespace") != old_metadata.get("namespace")
    ):
        return False
    old_generation = old_metadata.get("generation")
    new_generation = new_metadata.get("generation")
    if (
        type(old_generation) is not int
        or old_generation < 1
        or type(new_generation) is not int
        or new_generation != old_generation + 1
    ):
        return False
    # Admission observes the API server's generation increment and may observe
    # managedFields churn. Mirror the native policy by comparing every other
    # client-controlled metadata field exactly while excluding only those two
    # server-managed fields and the separately validated annotations.
    server_managed = {"annotations", "generation", "managedFields"}
    old_metadata_without_annotations = {
        key: value for key, value in old_metadata.items()
        if key not in server_managed
    }
    new_metadata_without_annotations = {
        key: value for key, value in new_metadata.items()
        if key not in server_managed
    }
    if (
        old_metadata_without_annotations != new_metadata_without_annotations
        or ("status" in old) != ("status" in new)
        or old.get("status") != new.get("status")
        or set(old_spec) != SOURCE_SPEC_FIELDS
        or set(new_spec) != SOURCE_SPEC_FIELDS
        or set(old_ref) != {"tag"}
        or set(new_ref) != {"tag"}
        or any(new_spec[field] != old_spec[field] for field in SOURCE_SPEC_FIELDS - {"ref"})
    ):
        return False
    old_match = TAG_RE.fullmatch(str(old_ref.get("tag", "")))
    new_match = TAG_RE.fullmatch(str(new_ref.get("tag", "")))
    if old_match is None or new_match is None:
        return False
    old_version = tuple(int(part) for part in old_match.groups())
    new_version = tuple(int(part) for part in new_match.groups())
    if new_version != (old_version[0], old_version[1], old_version[2] + 1):
        return False
    old_annotations = old_metadata.get("annotations")
    new_annotations = new_metadata.get("annotations")
    if not isinstance(old_annotations, dict) or not isinstance(new_annotations, dict):
        return False
    old_public = {
        key: value for key, value in old_annotations.items()
        if not key.startswith(SELECTOR_ANNOTATION_PREFIX)
    }
    old_reserved = {
        key: value for key, value in old_annotations.items()
        if key.startswith(SELECTOR_ANNOTATION_PREFIX)
    }
    new_public = {
        key: value for key, value in new_annotations.items()
        if not key.startswith(SELECTOR_ANNOTATION_PREFIX)
    }
    new_reserved = {
        key: value for key, value in new_annotations.items()
        if key.startswith(SELECTOR_ANNOTATION_PREFIX)
    }
    if (
        old_public != new_public
        or set(old_reserved) != SELECTOR_ANNOTATIONS
        or set(new_reserved) != SELECTOR_ANNOTATIONS
        or not all(isinstance(item, str) for item in new_reserved.values())
    ):
        return False
    value = lambda name: new_reserved[SELECTOR_ANNOTATION_PREFIX + name]
    zero_sha = "0" * 40
    zero_digest = "sha256:" + "0" * 64
    return (
        value("schema") == IDENTITY_SCHEMA
        and value("release-tag") == new_ref["tag"]
        and re.fullmatch(r"[1-9][0-9]*", value("release-id")) is not None
        and SHA_RE.fullmatch(value("release-target-sha")) is not None
        and value("release-target-sha") != zero_sha
        and SHA_RE.fullmatch(value("tag-object-sha")) is not None
        and value("tag-object-sha") != zero_sha
        and re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", value("main-ci")) is not None
        and re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", value("platform-release")) is not None
        and DIGEST_RE.fullmatch(value("selector-image-digest")) is not None
        and value("selector-image-digest") != zero_digest
        and DIGEST_RE.fullmatch(value("identity-sha256")) is not None
        and value("identity-sha256") != zero_digest
    )


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("live object must be one JSON object")
    return value


def nested(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label} is not a JSON object")
    return value


def list_items(path: Path, api_version: str, kind: str) -> list[dict[str, object]]:
    value = load(path)
    metadata_value = value.get("metadata", {})
    items = value.get("items")
    if (
        value.get("apiVersion") != api_version
        or value.get("kind") != kind
        or not isinstance(metadata_value, dict)
        or metadata_value.get("continue") not in (None, "")
        or not isinstance(items, list)
        or not all(isinstance(item, dict) for item in items)
    ):
        raise SystemExit("cluster-wide consumer collection is incomplete or foreign")
    return items


def validate_consumer_files(arguments: argparse.Namespace) -> None:
    paths = {
        "kustomizations": (arguments.kustomizations_live, "kustomize.toolkit.fluxcd.io/v1", "KustomizationList"),
        "helmcharts": (arguments.helmcharts_live, "source.toolkit.fluxcd.io/v1", "HelmChartList"),
        "helmreleases": (arguments.helmreleases_live, "helm.toolkit.fluxcd.io/v2", "HelmReleaseList"),
        "externalartifacts": (arguments.externalartifacts_live, "source.toolkit.fluxcd.io/v1", "ExternalArtifactList"),
    }
    if any(path is None for path, _, _ in paths.values()) or arguments.phase is None:
        raise SystemExit("consumer validation requires all four served collections and phase")
    collections = {
        name: list_items(path, api_version, kind)
        for name, (path, api_version, kind) in paths.items()
    }
    closure = closure_module()
    try:
        consumers = closure.enumerate_git_consumers(collections)
        closure.validate_consumers(
            consumers,
            "initial" if arguments.phase == "initial" else "post",
        )
    except closure.ClosureError as error:
        raise SystemExit(str(error)) from error
    if not consumers:
        return
    expected = {
        "naranjo-online-reconciler": "naranjo-kustomization",
        "lidersea-com-reconciler": "lidersea-kustomization",
    }
    observed: dict[str, dict[str, object]] = {}
    for item in collections["kustomizations"]:
        metadata_value = item.get("metadata")
        if not isinstance(metadata_value, dict):
            raise SystemExit("Kustomization consumer metadata is malformed")
        name = metadata_value.get("name")
        if metadata_value.get("namespace") == NAMESPACE and name in expected:
            if name in observed:
                raise SystemExit("duplicate bootstrap parent consumer")
            assert isinstance(name, str)
            observed[name] = item
    expected_present = {
        item["key"].rsplit("|", 1)[-1] for item in consumers
    }
    if set(observed) != expected_present:
        raise SystemExit("bootstrap parent consumer objects are incomplete")
    suspend = "true" if arguments.phase in {"initial", "contained"} else "any"
    for name in sorted(expected_present):
        component = expected[name]
        wanted = desired(
            component,
            arguments.selector_digest,
            arguments.api_cidr,
            "target",
            arguments.target_annotations,
            arguments.selector_build_sha,
        )
        check(component, observed[name], wanted, suspend)


def validate_site_chain_files(values: list[str], restore_site: str | None = None) -> None:
    closure = closure_module()
    expected = closure.expected_site_chain()
    objects: dict[str, object] = {}
    for value in values:
        key, separator, raw_path = value.partition("=")
        if not separator or key not in expected or key in objects or not raw_path:
            raise SystemExit("site execution-chain path binding is incomplete or foreign")
        objects[key] = load(Path(raw_path))
    try:
        if restore_site is not None:
            closure.validate_site_restore_boundary(objects, restore_site)
            print("restore-ready")
        else:
            print(closure.validate_site_chain_state(objects))
    except closure.ClosureError as error:
        raise SystemExit(str(error)) from error


def validate_run_record(actual: dict[str, object], evidence: dict[str, object]) -> None:
    repository = nested(actual.get("repository"), "workflow repository")
    if (
        actual.get("id") != evidence.get("run_id")
        or actual.get("run_attempt") != evidence.get("run_attempt")
        or actual.get("path") != evidence.get("workflow")
        or actual.get("event") != evidence.get("event")
        or actual.get("head_branch") != "main"
        or actual.get("head_sha") != evidence.get("head_sha")
        or repository.get("full_name") != "snaraj/website-infrastructure"
        or actual.get("status") != "completed"
        or actual.get("conclusion") != "success"
    ):
        raise SystemExit("live workflow attempt differs from release identity")


def validate_remote_identity(
    digest: str,
    identity_path: Path,
    bundle_path: Path,
    release_path: Path,
    ref_path: Path,
    tag_path: Path,
    main_path: Path,
    platform_path: Path,
) -> dict[str, str]:
    tag, sha = local_release()
    tree_sha = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", f"{sha}^{{tree}}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if SHA_RE.fullmatch(tree_sha) is None:
        raise SystemExit("local release tree SHA is invalid")
    ref = load(ref_path)
    tag_record = load(tag_path)
    ref_object = nested(ref.get("object"), "tag ref object")
    tag_object = nested(tag_record.get("object"), "annotated tag target")
    tag_sha = ref_object.get("sha")
    if (
        ref.get("ref") != f"refs/tags/{tag}"
        or ref_object.get("type") != "tag"
        or not isinstance(tag_sha, str)
        or not SHA_RE.fullmatch(tag_sha)
        or tag_record.get("sha") != tag_sha
        or tag_record.get("tag") != tag
        or tag_object.get("sha") != sha
        or tag_object.get("type") != "commit"
    ):
        raise SystemExit("live annotated tag differs from the exact local release")
    identity_bytes = identity_path.read_bytes()
    identity = json.loads(identity_bytes)
    if not isinstance(identity, dict):
        raise SystemExit("release identity is not one object")
    main = nested(identity.get("main_ci"), "main CI identity")
    platform = nested(identity.get("platform_release"), "platform Release identity")
    selector = nested(identity.get("selector"), "selector identity")
    provenance = nested(selector.get("provenance"), "selector provenance")
    build_sha = selector_build_sha(provenance.get("source_sha"))
    sites = nested(identity.get("sites"), "site identities")
    site_facts: dict[str, str] = {}
    for slug, prefix in (("naranjo-online", "naranjo"), ("lidersea-com", "lidersea")):
        site = nested(sites.get(slug), f"{slug} identity")
        chart = nested(site.get("chart"), f"{slug} chart identity")
        version = chart.get("version")
        manifest_digest = chart.get("manifest_digest")
        if (
            not isinstance(version, str)
            or re.fullmatch(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is None
            or not isinstance(manifest_digest, str)
            or DIGEST_RE.fullmatch(manifest_digest) is None
        ):
            raise SystemExit("site chart identity is invalid")
        site_facts[f"{prefix}-chart-version"] = version
        site_facts[f"{prefix}-chart-digest"] = manifest_digest
    result = subprocess.run(
        [
            "python3", "-I", "-B", str(CONTRACT_PATH),
            "selector-image-from-release", "--release-json", str(release_path),
            "--identity", str(identity_path), "--bundle", str(bundle_path),
            "--tag", tag, "--source-sha", sha,
            "--tag-object-sha", tag_sha, "--source-tree-sha", tree_sha,
            "--selector-build-sha", build_sha,
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0 or result.stdout.strip() != digest:
        raise SystemExit("immutable candidate Release or selector digest is foreign")
    validate_run_record(load(main_path), main)
    validate_run_record(load(platform_path), platform)
    release = nested(identity.get("release"), "release identity")
    tag_identity = nested(identity.get("tag"), "tag identity")
    annotations = {
        "schema": IDENTITY_SCHEMA,
        "release-id": str(release["id"]),
        "release-tag": tag,
        "release-target-sha": sha,
        "tag-object-sha": str(tag_identity["object_sha"]),
        "main-ci": f"{main['run_id']}/{main['run_attempt']}",
        "platform-release": f"{platform['run_id']}/{platform['run_attempt']}",
        "selector-image-digest": digest,
        "identity-sha256": "sha256:" + hashlib.sha256(identity_bytes).hexdigest(),
    }
    result = {**annotations, "selector-build-sha": build_sha, **site_facts}
    if set(result) != REMOTE_OUTPUT_KEYS:
        raise SystemExit("derived target annotations are incomplete")
    return result


def check(component: str, live: dict[str, object], expected: dict[str, object], suspend: str) -> None:
    observed = normalized(live, component)
    wanted = copy.deepcopy(expected)
    if component in SUSPENDABLE and suspend == "any":
        observed_spec = observed.get("spec")
        if not isinstance(observed_spec, dict):
            raise SystemExit("suspendable object has no spec")
        actual = observed_spec.get("suspend")
        if not isinstance(actual, bool):
            raise SystemExit("suspendable object has no boolean suspend state")
        wanted["spec"]["suspend"] = actual
    elif component in SUSPENDABLE:
        wanted["spec"]["suspend"] = suspend == "true"
    if observed != wanted:
        raise SystemExit("live object is not the exact bootstrap component")


def replacement(component: str, live: dict[str, object], expected: dict[str, object], suspend: bool) -> dict[str, object]:
    check(component, live, expected, "any")
    metadata_value = live.get("metadata")
    assert isinstance(metadata_value, dict)
    resource_version = metadata_value.get("resourceVersion")
    uid = metadata_value.get("uid")
    if not isinstance(resource_version, str) or not resource_version or not isinstance(uid, str) or not uid:
        raise SystemExit("replace requires live UID and resourceVersion")
    result = copy.deepcopy(expected)
    result["metadata"]["resourceVersion"] = resource_version
    result["metadata"]["uid"] = uid
    live_annotations = metadata_value.get("annotations", {})
    if (
        isinstance(live_annotations, dict)
        and FLUX_RECONCILE_ANNOTATION in live_annotations
    ):
        result["metadata"].setdefault("annotations", {})[
            FLUX_RECONCILE_ANNOTATION
        ] = live_annotations[FLUX_RECONCILE_ANNOTATION]
    result["spec"]["suspend"] = suspend
    return result


def role_migration_request(
    component: str,
    live: dict[str, object],
    expected: dict[str, object],
) -> dict[str, object]:
    if component not in MIGRATABLE_ROLE_COMPONENTS:
        raise SystemExit("Role is not eligible for bootstrap migration")
    if normalized(live, component) != legacy_role(component):
        raise SystemExit("live Role is not the exact legacy predecessor")
    metadata_value = live.get("metadata")
    assert isinstance(metadata_value, dict)
    resource_version = metadata_value.get("resourceVersion")
    uid = metadata_value.get("uid")
    if not all(isinstance(value, str) and value for value in (resource_version, uid)):
        raise SystemExit("Role migration requires live UID and resourceVersion")
    result = copy.deepcopy(expected)
    result["metadata"]["resourceVersion"] = resource_version
    result["metadata"]["uid"] = uid
    live_annotations = metadata_value.get("annotations", {})
    if (
        isinstance(live_annotations, dict)
        and KUBECTL_LAST_APPLIED_ANNOTATION in live_annotations
    ):
        result["metadata"].setdefault("annotations", {})[
            KUBECTL_LAST_APPLIED_ANNOTATION
        ] = live_annotations[KUBECTL_LAST_APPLIED_ANNOTATION]
    return result


def validate_role_migration_result(
    component: str,
    before: dict[str, object],
    after: dict[str, object],
    expected: dict[str, object],
) -> None:
    role_migration_request(component, before, expected)
    if normalized(after, component) != expected:
        raise SystemExit("migrated Role is not the exact narrowed target")
    before_metadata = before.get("metadata")
    after_metadata = after.get("metadata")
    assert isinstance(before_metadata, dict) and isinstance(after_metadata, dict)
    before_uid, after_uid = before_metadata.get("uid"), after_metadata.get("uid")
    before_rv = before_metadata.get("resourceVersion")
    after_rv = after_metadata.get("resourceVersion")
    if not isinstance(before_uid, str) or before_uid != after_uid:
        raise SystemExit("Role UID changed during migration")
    if (
        not all(isinstance(value, str) and value for value in (before_rv, after_rv))
        or before_rv == after_rv
    ):
        raise SystemExit("Role resourceVersion did not advance during migration")


def rolebinding_state(
    live: dict[str, object], expected: dict[str, object], quarantined: bool
) -> None:
    wanted = copy.deepcopy(expected)
    if quarantined:
        wanted["subjects"] = []
    if normalized(live, "selector-rolebinding") != wanted:
        raise SystemExit("selector RoleBinding is foreign or in the opposite authority state")


def rolebinding_transition(
    live: dict[str, object], expected: dict[str, object], quarantine: bool
) -> dict[str, object]:
    rolebinding_state(live, expected, not quarantine)
    metadata_value = live.get("metadata")
    assert isinstance(metadata_value, dict)
    resource_version = metadata_value.get("resourceVersion")
    uid = metadata_value.get("uid")
    if (
        not isinstance(resource_version, str)
        or not resource_version
        or not isinstance(uid, str)
        or not uid
    ):
        raise SystemExit("RoleBinding transition requires live UID and resourceVersion")
    result = copy.deepcopy(expected)
    result["metadata"]["resourceVersion"] = resource_version
    result["metadata"]["uid"] = uid
    if quarantine:
        result["subjects"] = []
    return result


def selector_quiescent(
    cronjob: dict[str, object],
    jobs: dict[str, object],
    pods: dict[str, object],
) -> None:
    cron_metadata = cronjob.get("metadata")
    if not isinstance(cron_metadata, dict):
        raise SystemExit("selector CronJob metadata is absent")
    cron_uid = cron_metadata.get("uid")
    if (
        cron_metadata.get("name") != SELECTOR
        or cron_metadata.get("namespace") != NAMESPACE
        or not isinstance(cron_uid, str)
        or not cron_uid
    ):
        raise SystemExit("selector CronJob identity is foreign")
    if jobs.get("kind") != "JobList" or pods.get("kind") != "PodList":
        raise SystemExit("selector execution inventory kind is foreign")
    job_items = jobs.get("items")
    pod_items = pods.get("items")
    if not isinstance(job_items, list) or not isinstance(pod_items, list):
        raise SystemExit("selector execution inventory is malformed")
    selector_jobs: dict[str, str] = {}
    for item in job_items:
        if not isinstance(item, dict):
            raise SystemExit("Job inventory contains a non-object")
        metadata_value = item.get("metadata")
        if not isinstance(metadata_value, dict):
            raise SystemExit("Job metadata is absent")
        owners = metadata_value.get("ownerReferences", [])
        if not isinstance(owners, list):
            raise SystemExit("Job owner lineage is malformed")
        selector_owners = [
            owner for owner in owners
            if isinstance(owner, dict)
            and owner.get("kind") == "CronJob"
            and owner.get("name") == SELECTOR
        ]
        if not selector_owners:
            continue
        if len(owners) != 1 or len(selector_owners) != 1:
            raise SystemExit("selector Job has foreign owner lineage")
        owner = selector_owners[0]
        job_uid = metadata_value.get("uid")
        job_name = metadata_value.get("name")
        if (
            owner.get("uid") != cron_uid
            or owner.get("controller") is not True
            or metadata_value.get("namespace") != NAMESPACE
            or not isinstance(job_uid, str)
            or not job_uid
            or not isinstance(job_name, str)
            or not job_name.startswith(SELECTOR + "-")
            or job_uid in selector_jobs
        ):
            raise SystemExit("selector Job identity is foreign")
        selector_jobs[job_uid] = job_name
        status = item.get("status", {})
        conditions = status.get("conditions", []) if isinstance(status, dict) else []
        terminal = isinstance(conditions, list) and any(
            isinstance(condition, dict)
            and condition.get("type") in {"Complete", "Failed"}
            and condition.get("status") == "True"
            for condition in conditions
        )
        if not terminal:
            raise SystemExit("selector Job is still active")
    for item in pod_items:
        if not isinstance(item, dict):
            raise SystemExit("Pod inventory contains a non-object")
        spec = item.get("spec")
        if not isinstance(spec, dict) or spec.get("serviceAccountName") != SELECTOR:
            continue
        metadata_value = item.get("metadata")
        owners = metadata_value.get("ownerReferences", []) if isinstance(metadata_value, dict) else []
        labels = metadata_value.get("labels", {}) if isinstance(metadata_value, dict) else {}
        if (
            not isinstance(metadata_value, dict)
            or metadata_value.get("namespace") != NAMESPACE
            or not isinstance(owners, list)
            or len(owners) != 1
            or not isinstance(owners[0], dict)
            or owners[0].get("kind") != "Job"
            or owners[0].get("controller") is not True
            or selector_jobs.get(str(owners[0].get("uid"))) != owners[0].get("name")
            or not isinstance(labels, dict)
            or labels.get("app.kubernetes.io/name") != SELECTOR
            or labels.get("app.kubernetes.io/part-of") != SELECTOR
        ):
            raise SystemExit("selector Pod has foreign owner lineage")
        status = item.get("status")
        if not isinstance(status, dict) or status.get("phase") not in {"Succeeded", "Failed"}:
            raise SystemExit("selector Pod is still active")


def ready(component: str, live: dict[str, object], expected: dict[str, object], tag: str, sha: str) -> None:
    if not TAG_RE.fullmatch(tag) or not SHA_RE.fullmatch(sha):
        raise SystemExit("readiness tag or SHA is invalid")
    check(component, live, expected, "false" if component in SUSPENDABLE else "any")
    metadata_value = live.get("metadata", {})
    status = live.get("status", {})
    generation = metadata_value.get("generation")
    if not isinstance(generation, int) or generation <= 0 or status.get("observedGeneration") != generation:
        raise SystemExit("live object status does not observe the current generation")
    raw_conditions = status.get("conditions", [])
    if not isinstance(raw_conditions, list):
        raise SystemExit("live object conditions are malformed")
    conditions = [
        item for item in raw_conditions
        if isinstance(item, dict) and item.get("type") == "Ready"
    ]
    if len(conditions) != 1 or conditions[0].get("status") != "True" or conditions[0].get("observedGeneration") != generation:
        raise SystemExit("live object has no unique current Ready condition")
    revision = tag + "@sha1:" + sha
    if component == "source":
        if status.get("artifact", {}).get("revision") != revision:
            raise SystemExit("source artifact revision is not exact")
    elif status.get("lastAppliedRevision") != revision or status.get("lastAttemptedRevision") != revision:
        raise SystemExit("site reconciler revision is not exact")


def local_release() -> tuple[str, str]:
    status = subprocess.run(
        [
            "git", "-C", str(ROOT), "status", "--porcelain=v1",
            "--untracked-files=all",
        ],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout
    if status:
        raise SystemExit("bootstrap checkout must be clean and complete")
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    tags = subprocess.run(
        ["git", "-C", str(ROOT), "tag", "--points-at", head, "--list", "v*"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.splitlines()
    if not SHA_RE.fullmatch(head) or len(tags) != 1 or not TAG_RE.fullmatch(tags[0]):
        raise SystemExit("bootstrap must run from one exact immutable platform tag")
    tag_ref = "refs/tags/" + tags[0]
    tag_type = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-t", tag_ref],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    peeled = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", tag_ref + "^{commit}"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    if tag_type != "tag" or peeled != head:
        raise SystemExit("bootstrap local tag must be annotated and peel to HEAD")
    current = tuple(int(item) for item in tags[0][1:].split("."))
    if current[:2] != (0, 1) or current[2] < 33:
        raise SystemExit("bootstrap release precedes the canonical v0.1.40 floor")
    return tags[0], head


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "inventory", "preflight", "api-endpoints", "attestation", "remote",
            "render", "check", "replace", "ready", "check-rolebinding-quarantine",
            "role-migration-request", "role-migration-result",
            "quarantine-rolebinding", "restore-rolebinding", "selector-quiescence",
            "consumers", "site-chain",
            "helm-binding-check", "helm-binding-transition", "helm-binding-result",
            "helm-bindings-quarantined",
            "oci-check", "oci-migration-patch", "oci-migration-result",
            "site-children", "oci-ready", "helmrelease-ready",
            "parent-attempted",
        ),
    )
    parser.add_argument("--component", choices=tuple(item[0] for item in INVENTORY))
    parser.add_argument("--selector-digest", default="sha256:" + "0" * 64)
    parser.add_argument("--selector-build-sha")
    parser.add_argument("--api-cidr", action="append", default=[])
    parser.add_argument("--server")
    parser.add_argument("--live", type=Path)
    parser.add_argument("--suspend", choices=("any", "true", "false"), default="any")
    parser.add_argument("--source-state", choices=("target",), default="target")
    parser.add_argument("--target-annotations", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--release-json", type=Path)
    parser.add_argument("--ref-json", type=Path)
    parser.add_argument("--tag-json", type=Path)
    parser.add_argument("--main-run-json", type=Path)
    parser.add_argument("--platform-run-json", type=Path)
    parser.add_argument("--cronjob-live", type=Path)
    parser.add_argument("--jobs-live", type=Path)
    parser.add_argument("--pods-live", type=Path)
    parser.add_argument("--kustomizations-live", type=Path)
    parser.add_argument("--helmcharts-live", type=Path)
    parser.add_argument("--helmreleases-live", type=Path)
    parser.add_argument("--externalartifacts-live", type=Path)
    parser.add_argument("--phase", choices=("initial", "post", "contained"))
    parser.add_argument("--site-chain-live", action="append", default=[])
    parser.add_argument("--site", choices=SITES)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--naranjo-live", type=Path)
    parser.add_argument("--lidersea-live", type=Path)
    parser.add_argument("--networkpolicy-live", type=Path)
    parser.add_argument("--oci-live", type=Path)
    parser.add_argument("--helmrelease-live", type=Path)
    parser.add_argument("--parent-live", type=Path)
    parser.add_argument("--quarantined", choices=("true", "false"))
    parser.add_argument("--tag")
    parser.add_argument("--sha")
    arguments = parser.parse_args()
    if arguments.command == "inventory":
        for component, resource, name in INVENTORY:
            print(component, resource, name)
        return
    if arguments.command == "preflight":
        selector_digest(arguments.selector_digest)
        cidrs = endpoint_cidrs(arguments.api_cidr)
        if arguments.server is None:
            raise SystemExit("preflight requires the explicit API server")
        server_endpoint(arguments.server, cidrs)
        tag, sha = local_release()
        print(json.dumps({"sha": sha, "tag": tag}, sort_keys=True, separators=(",", ":")))
        return
    if arguments.command == "api-endpoints":
        if arguments.live is None:
            raise SystemExit("API endpoint validation requires live JSON")
        validate_endpoint_slices(load(arguments.live), endpoint_cidrs(arguments.api_cidr))
        return
    if arguments.command == "attestation":
        if arguments.live is None:
            raise SystemExit("attestation validation requires Cosign JSONL")
        validate_attestations(
            arguments.live,
            arguments.selector_digest,
            selector_build_sha(arguments.selector_build_sha),
        )
        return
    if arguments.command == "remote":
        selector_digest(arguments.selector_digest)
        paths = (
            arguments.identity, arguments.bundle, arguments.release_json,
            arguments.ref_json, arguments.tag_json, arguments.main_run_json,
            arguments.platform_run_json,
        )
        if any(path is None for path in paths):
            raise SystemExit("remote validation requires all exact public records")
        print(json.dumps(
            validate_remote_identity(arguments.selector_digest, *paths),
            sort_keys=True, separators=(",", ":"),
        ))
        return
    if arguments.command == "selector-quiescence":
        paths = (arguments.cronjob_live, arguments.jobs_live, arguments.pods_live)
        if any(path is None for path in paths):
            raise SystemExit("selector quiescence requires CronJob, Job and Pod inventories")
        selector_quiescent(*(load(path) for path in paths))
        return
    if arguments.command == "consumers":
        validate_consumer_files(arguments)
        return
    if arguments.command == "site-chain":
        validate_site_chain_files(arguments.site_chain_live, arguments.site)
        return
    if arguments.command in {
        "helm-binding-check", "helm-binding-transition", "helm-binding-result",
        "helm-bindings-quarantined",
    }:
        closure = closure_module()
        expected = closure.expected_site_chain()
        try:
            if arguments.command == "helm-bindings-quarantined":
                if arguments.naranjo_live is None or arguments.lidersea_live is None:
                    raise SystemExit("both Helm RoleBinding live objects are required")
                closure.require_both_helm_bindings_quarantined({
                    "naranjo-online|RoleBinding|helm-reconciler": load(arguments.naranjo_live),
                    "lidersea-com|RoleBinding|helm-reconciler": load(arguments.lidersea_live),
                })
                return
            if arguments.site is None or arguments.quarantined is None:
                raise SystemExit("Helm RoleBinding transition requires site and state")
            wanted = expected[f"{arguments.site}|RoleBinding|helm-reconciler"]
            quarantined = arguments.quarantined == "true"
            if arguments.command == "helm-binding-check":
                if arguments.live is None:
                    raise SystemExit("Helm RoleBinding check requires live JSON")
                closure._binding_state(load(arguments.live), wanted, quarantined)
                return
            if arguments.command == "helm-binding-transition":
                if arguments.live is None:
                    raise SystemExit("Helm RoleBinding transition requires live JSON")
                print(json.dumps(
                    closure.rolebinding_replace(load(arguments.live), wanted, quarantined),
                    sort_keys=True, separators=(",", ":"),
                ))
                return
            if arguments.before is None or arguments.after is None:
                raise SystemExit("Helm RoleBinding result requires before and after JSON")
            closure.validate_rolebinding_result(
                load(arguments.before), load(arguments.after), wanted, quarantined,
            )
        except closure.ClosureError as error:
            raise SystemExit(str(error)) from error
        return
    if arguments.command in {"oci-check", "oci-migration-patch", "oci-migration-result"}:
        if arguments.site is None or arguments.live is None:
            raise SystemExit("OCIRepository migration requires site and live JSON")
        closure = closure_module()
        target = target_oci_repository(arguments.site, arguments.target_annotations)
        live = load(arguments.live)
        try:
            if arguments.command == "oci-check":
                if closure._normalize_oci(live) != closure._normalize_oci(target):
                    raise closure.ClosureError("OCIRepository is not the exact target")
                return
            if arguments.command == "oci-migration-patch":
                print(json.dumps(
                    closure.oci_migration_patch(live, target),
                    sort_keys=True, separators=(",", ":"),
                ))
                return
            if arguments.after is None:
                raise SystemExit("OCIRepository migration result requires poststate JSON")
            closure.validate_oci_result(live, load(arguments.after), target)
        except closure.ClosureError as error:
            raise SystemExit(str(error)) from error
        return
    if arguments.command in {
        "site-children", "oci-ready", "helmrelease-ready", "parent-attempted",
    }:
        if arguments.site is None:
            raise SystemExit("site closure requires one exact site")
        closure = closure_module()
        target_oci = target_oci_repository(arguments.site, arguments.target_annotations)
        children = closure.expected_site_children(arguments.site, target_oci)
        try:
            if arguments.command == "site-children":
                paths = (
                    arguments.networkpolicy_live,
                    arguments.oci_live,
                    arguments.helmrelease_live,
                )
                if any(path is None for path in paths):
                    raise SystemExit("site child closure requires all three live objects")
                closure.validate_site_children(
                    arguments.site,
                    {
                        "networkpolicy": load(arguments.networkpolicy_live),
                        "oci": load(arguments.oci_live),
                        "helmrelease": load(arguments.helmrelease_live),
                    },
                    target_oci,
                )
            elif arguments.command == "oci-ready":
                if arguments.oci_live is None:
                    raise SystemExit("OCI readiness requires the live object")
                closure.validate_oci_ready(load(arguments.oci_live), target_oci)
            elif arguments.command == "helmrelease-ready":
                if arguments.helmrelease_live is None:
                    raise SystemExit("HelmRelease readiness requires the live object")
                closure.validate_helmrelease_ready(
                    load(arguments.helmrelease_live), children["helmrelease"]
                )
            else:
                if arguments.parent_live is None or arguments.tag is None or arguments.sha is None:
                    raise SystemExit("parent attempted proof requires live parent, tag, and SHA")
                expected_parent = desired(
                    ("naranjo-kustomization" if arguments.site == "naranjo-online"
                     else "lidersea-kustomization"),
                    arguments.selector_digest,
                    arguments.api_cidr,
                    "target",
                    arguments.target_annotations,
                    arguments.selector_build_sha,
                )
                expected_parent["spec"]["suspend"] = False
                closure.validate_parent_attempted(
                    arguments.site,
                    load(arguments.parent_live),
                    expected_parent,
                    arguments.tag + "@sha1:" + arguments.sha,
                )
        except closure.ClosureError as error:
            raise SystemExit(str(error)) from error
        return
    if arguments.command in {
        "check-rolebinding-quarantine",
        "quarantine-rolebinding",
        "restore-rolebinding",
    }:
        if arguments.live is None:
            raise SystemExit("RoleBinding authority transition requires live JSON")
        expected = desired(
            "selector-rolebinding", arguments.selector_digest, arguments.api_cidr
        )
        live = load(arguments.live)
        if arguments.command == "check-rolebinding-quarantine":
            rolebinding_state(live, expected, True)
        else:
            print(json.dumps(
                rolebinding_transition(
                    live,
                    expected,
                    arguments.command == "quarantine-rolebinding",
                ),
                sort_keys=True,
                separators=(",", ":"),
            ))
        return
    if arguments.component is None:
        raise SystemExit("component is required")
    expected = desired(
        arguments.component,
        arguments.selector_digest,
        arguments.api_cidr,
        arguments.source_state,
        arguments.target_annotations,
        arguments.selector_build_sha,
    )
    if arguments.command == "render":
        print(json.dumps(expected, sort_keys=True, separators=(",", ":")))
        return
    if arguments.command == "role-migration-result":
        if arguments.before is None or arguments.after is None:
            raise SystemExit("Role migration result requires before and after JSON")
        validate_role_migration_result(
            arguments.component,
            load(arguments.before),
            load(arguments.after),
            expected,
        )
        return
    if arguments.live is None:
        raise SystemExit("live JSON is required")
    live = load(arguments.live)
    if arguments.command == "role-migration-request":
        print(json.dumps(
            role_migration_request(arguments.component, live, expected),
            sort_keys=True,
            separators=(",", ":"),
        ))
    elif arguments.command == "check":
        check(arguments.component, live, expected, arguments.suspend)
    elif arguments.command == "replace":
        if arguments.component not in SUSPENDABLE or arguments.suspend == "any":
            raise SystemExit("replace requires a suspendable component and exact state")
        print(json.dumps(
            replacement(arguments.component, live, expected, arguments.suspend == "true"),
            sort_keys=True, separators=(",", ":"),
        ))
    elif arguments.command == "ready":
        if arguments.component not in {"source", "naranjo-kustomization", "lidersea-kustomization"}:
            raise SystemExit("readiness is defined only for the source and site reconcilers")
        if arguments.tag is None or arguments.sha is None:
            raise SystemExit("readiness requires tag and SHA")
        ready(arguments.component, live, expected, arguments.tag, arguments.sha)


if __name__ == "__main__":
    main()
