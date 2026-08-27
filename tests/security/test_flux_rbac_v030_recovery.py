"""Focused hostile tests for the one-incident v0.1.30 recovery path.

The suite is hermetic: it uses synthetic journal and snapshot metadata and
never opens a kubeconfig, network connection, or privileged host path.
"""

from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TRANSACTION_PATH = ROOT / "bootstrap/flux/rbac-convergence/transaction.py"


def _load_transaction():
    name = "flux_rbac_v030_recovery_under_test"
    spec = importlib.util.spec_from_file_location(name, TRANSACTION_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("transaction module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


transaction = _load_transaction()


def _synthetic_uid(digit):
    return f"{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}"


DEPLOYMENT_UID = _synthetic_uid("1")
SERVICE_UID = _synthetic_uid("7")
SERVICE_ACCOUNT_UID = _synthetic_uid("8")
NETWORK_POLICY_UID = _synthetic_uid("9")
POD_UID = _synthetic_uid("2")
REPLICA_SET_UID = _synthetic_uid("3")
FOREIGN_UID = _synthetic_uid("4")
SUBSTITUTED_UID = _synthetic_uid("5")
POD_UID_2 = _synthetic_uid("6")
SERVICE_CLUSTER_IP = str(ipaddress.ip_address(0xC0000201))
SERVICE_CLUSTER_IP_ALT = str(ipaddress.ip_address(0xC0000202))
POD_IP = str(ipaddress.ip_address(0xC0000265))
POD_IP_2 = str(ipaddress.ip_address(0xC0000266))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def _valid_movement(rows=None):
    verification_rows = copy.deepcopy(
        rows
        or {
            "oci": {"revision": "reviewed"},
            "helm": {"revision": "reviewed"},
            "workload": {"generation": 12, "pods": [{"uid": POD_UID}]},
        }
    )
    verification_rows["workload"].setdefault("pods", [{"uid": POD_UID}])
    return {
        "verificationRows": verification_rows,
        "podProof": {
            "deploymentSha256": "5" * 64,
            "pods": [
                {
                    "podUidSha256": transaction.sha256_bytes(POD_UID.encode()),
                    "podSpecSha256": "6" * 64,
                    "imageIDSha256": "7" * 64,
                    "podMetadataSha256": "8" * 64,
                    "replicaSetMetadataSha256": "9" * 64,
                    "replicaSetTemplateSha256": "a" * 64,
                    "ownerChainSha256": "b" * 64,
                }
            ],
        },
    }


def _incident_fixture():
    role_ids = (
        "converge:Role:lidersea-com:helm-reconciler",
        "converge:Role:naranjo-online:helm-reconciler",
    )
    order = [f"operation-{index}" for index in range(16)] + list(role_ids)
    order.extend(f"operation-{index}" for index in range(18, 23))
    target = {"clusterUid": "1" * 36, "apiServerSha256": "2" * 64}
    plan = {
        "source": {
            "sourceRevision": transaction.RECOVERED_SOURCE_REVISION,
            "tag": transaction.RECOVERED_RELEASE_TAG,
        },
        "target": target,
        "operationOrder": order,
    }
    operations = {
        operation_id: {
            "state": "committed",
            "rollbackState": "restored" if operation_id in role_ids else None,
        }
        for operation_id in order[:18]
    }
    journal = {
        "schema": "legacy-journal-v1",
        "planSha256": transaction.RECOVERED_PLAN_SHA256,
        "sourceRevision": transaction.RECOVERED_SOURCE_REVISION,
        "targetSha256": _sha256(_canonical(target)),
        "attemptId": "3" * 64,
        "state": "recovery-required",
        "phase": "namespaced",
        "sequence": transaction.RECOVERED_INITIAL_SEQUENCE,
        "pendingOperation": None,
        "operations": operations,
        "helmProof": {"state": "not-started"},
        "oracleEvidenceRecords": {"pre-shared": {"sha256": "4" * 64}},
        "verificationCounter": 0,
        "verificationChainSha256": "0" * 64,
        "pendingVerification": None,
        "recoveryRequired": True,
        "forwardFailurePhase": "forward",
        "forwardFailureToken": "FLUX_BASELINE_DRIFT",
        "preSharedOracleSha256": "5" * 64,
        "receiptRecords": {"recovery-required": {"result": "recovery-required"}},
    }
    old = SimpleNamespace(
        JOURNAL_SCHEMA="legacy-journal-v1",
        TRANSACTION_TARGET_COUNT=23,
        canonical_json=_canonical,
        sha256_bytes=_sha256,
        validate_terminal_evidence_document=mock.Mock(),
    )
    return old, plan, journal


def _oci(version, marker):
    upstream_digest = (
        transaction.RECOVERED_TO_CHART_DIGEST
        if version == transaction.RECOVERED_TO_VERSION
        else f"sha256:{marker * 64}"
    )
    return {
        "uid": "oci-uid",
        "resourceVersion": marker,
        "generation": 4,
        "observedGeneration": 4,
        "revision": f"{version}@sha256:{marker * 64}",
        "chartVersion": version,
        "upstreamDigest": upstream_digest,
        "storedArtifactDigest": f"sha256:{marker * 64}",
        "readyReason": "Succeeded",
        "sourceVerifiedReason": "Succeeded",
        "specSha256": "a" * 64,
        "semanticSha256": "d" * 64,
    }


def _helm(version, marker, revision, generation=7):
    chart_digest = (
        transaction.RECOVERED_TO_CHART_DIGEST
        if version == transaction.RECOVERED_TO_VERSION
        else f"sha256:{marker * 64}"
    )
    return {
        "uid": "helm-uid",
        "resourceVersion": marker,
        "generation": generation,
        "observedGeneration": generation,
        "lastAttemptedGeneration": generation,
        "attemptedRevision": version,
        "attemptedRevisionDigest": chart_digest,
        "attemptedReleaseAction": "upgrade",
        "historyRevision": revision,
        "historyChartVersion": version,
        "historyStatus": "deployed",
        "historyAction": "upgrade",
        "historyOciDigest": chart_digest,
        "historyDigest": f"sha256:{marker * 64}",
        "historyConfigDigest": f"sha256:{marker * 64}",
        "inventory": [{"id": "deployment"}],
        "readyReason": "Succeeded",
        "specSha256": "b" * 64,
        "semanticSha256": "e" * 64,
    }


def _owned_objects(marker):
    static = [
        {
            "kind": "Service",
            "name": "naranjo-online",
            "apiVersion": "v1",
            "uid": SERVICE_UID,
            "semanticSha256": marker * 64,
            "proofAnnotation": None,
            "semanticWithoutProofSha256": marker * 64,
        },
        {
            "kind": "ServiceAccount",
            "name": "naranjo-online",
            "apiVersion": "v1",
            "uid": SERVICE_ACCOUNT_UID,
            "semanticSha256": marker * 64,
            "proofAnnotation": None,
            "semanticWithoutProofSha256": marker * 64,
        },
        {
            "kind": "NetworkPolicy",
            "name": "ingress-to-naranjo-online",
            "apiVersion": "networking.k8s.io/v1",
            "uid": NETWORK_POLICY_UID,
            "semanticSha256": marker * 64,
            "proofAnnotation": None,
            "semanticWithoutProofSha256": marker * 64,
        },
    ]
    return static + [
        {
            "kind": "Deployment",
            "name": "naranjo-online",
            "apiVersion": "apps/v1",
            "uid": DEPLOYMENT_UID,
            "semanticSha256": marker * 64,
            "proofAnnotation": None,
            "semanticWithoutProofSha256": marker * 64,
        }
    ]


def _workload(marker, generation):
    replicas = 1 if marker == "2" else 2
    return {
        "uid": DEPLOYMENT_UID,
        "generation": generation,
        "replicas": replicas,
        "templateSha256": marker * 64,
        "semanticSha256": marker * 64,
        "proofAnnotation": None,
        "semanticWithoutProofSha256": marker * 64,
        "pods": [
            {
                "uid": POD_UID,
                "restartCounts": [0],
                "images": [
                    transaction.RECOVERED_TO_IMAGE
                    if marker == "2"
                    else "old-reviewed-image"
                ],
            },
            *([{
                "uid": POD_UID_2,
                "restartCounts": [0],
                "images": [
                    transaction.RECOVERED_TO_IMAGE
                    if marker == "2"
                    else "old-reviewed-image"
                ],
            }] if replicas == 2 else []),
        ],
        "ownedObjects": _owned_objects(marker),
    }


def _raw_deployment():
    template_labels = {
        "app.kubernetes.io/name": "naranjo-online",
        "app.kubernetes.io/instance": "naranjo-online",
        "app.kubernetes.io/managed-by": "Helm",
        "app.kubernetes.io/version": transaction.RECOVERED_TO_VERSION,
    }
    metadata_labels = {
        **template_labels,
        "helm.toolkit.fluxcd.io/name": "naranjo-online",
        "helm.toolkit.fluxcd.io/namespace": "naranjo-online",
    }

    def probe(path, period, timeout, failure):
        return {
            "httpGet": {"path": path, "port": "http", "scheme": "HTTP"},
            "failureThreshold": failure,
            "periodSeconds": period,
            "timeoutSeconds": timeout,
            "successThreshold": 1,
            "initialDelaySeconds": 0,
        }

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "naranjo-online",
            "namespace": "naranjo-online",
            "uid": DEPLOYMENT_UID,
            "resourceVersion": "20",
            "generation": 21 + transaction.RECOVERED_WORKLOAD_GENERATION_STEP_COUNT,
            "labels": copy.deepcopy(metadata_labels),
            "annotations": {
                "meta.helm.sh/release-name": "naranjo-online",
                "meta.helm.sh/release-namespace": "naranjo-online",
                "platform.snaraj.dev/deployment-ready": "true",
                "platform.snaraj.dev/media-storage-ready": "false",
                "deployment.kubernetes.io/revision": transaction.RECOVERED_TO_DEPLOYMENT_REVISION,
            },
        },
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "progressDeadlineSeconds": 600,
            "minReadySeconds": 0,
            "paused": False,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1},
            },
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "naranjo-online",
                    "app.kubernetes.io/instance": "naranjo-online",
                }
            },
            "template": {
                "metadata": {
                    "labels": copy.deepcopy(template_labels),
                    "creationTimestamp": None,
                },
                "spec": {
                    "serviceAccountName": "naranjo-online",
                    "serviceAccount": "naranjo-online",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Always",
                    "terminationGracePeriodSeconds": 30,
                    "dnsPolicy": "ClusterFirst",
                    "schedulerName": "default-scheduler",
                    "enableServiceLinks": True,
                    "preemptionPolicy": "PreemptLowerPriority",
                    "priority": 0,
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "shareProcessNamespace": False,
                    "hostUsers": True,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": [
                        {
                            "name": "tmp",
                            "emptyDir": {
                                "medium": "Memory",
                                "sizeLimit": "16Mi",
                            },
                        }
                    ],
                    "containers": [
                        {
                            "name": "naranjo-online",
                            "image": transaction.RECOVERED_TO_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "terminationMessagePath": "/dev/termination-log",
                            "terminationMessagePolicy": "File",
                            "stdin": False,
                            "stdinOnce": False,
                            "tty": False,
                            "env": [
                                {"name": "PORT", "value": "8080"},
                                {"name": "MEDIA_ENABLED", "value": "false"},
                                {"name": "PANELS_REFRESH", "value": "false"},
                            ],
                            "ports": [
                                {
                                    "name": "http",
                                    "containerPort": 8080,
                                    "protocol": "TCP",
                                }
                            ],
                            "resources": {
                                "limits": {"cpu": "200m", "memory": "128Mi"},
                                "requests": {"cpu": "25m", "memory": "32Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "readOnlyRootFilesystem": True,
                            },
                            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                            "startupProbe": probe("/livez", 2, 1, 30),
                            "readinessProbe": probe("/readyz", 10, 2, 3),
                            "livenessProbe": probe("/livez", 30, 2, 3),
                        }
                    ],
                },
            },
        },
    }


def _static_metadata(name, uid):
    return {
        "name": name,
        "namespace": "naranjo-online",
        "uid": uid,
        "resourceVersion": "24",
        "creationTimestamp": "2026-08-25T00:00:00Z",
        "labels": {
            "app.kubernetes.io/name": "naranjo-online",
            "app.kubernetes.io/instance": "naranjo-online",
            "app.kubernetes.io/managed-by": "Helm",
            "app.kubernetes.io/version": transaction.RECOVERED_TO_VERSION,
            "helm.toolkit.fluxcd.io/name": "naranjo-online",
            "helm.toolkit.fluxcd.io/namespace": "naranjo-online",
        },
        "annotations": {
            "meta.helm.sh/release-name": "naranjo-online",
            "meta.helm.sh/release-namespace": "naranjo-online",
        },
    }


def _raw_static_objects():
    return {
        "Service": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": _static_metadata("naranjo-online", SERVICE_UID),
            "spec": {
                "clusterIP": SERVICE_CLUSTER_IP,
                "clusterIPs": [SERVICE_CLUSTER_IP],
                "internalTrafficPolicy": "Cluster",
                "ipFamilies": ["IPv4"],
                "ipFamilyPolicy": "SingleStack",
                "ports": [
                    {
                        "name": "http",
                        "port": 8080,
                        "protocol": "TCP",
                        "targetPort": "http",
                    }
                ],
                "selector": {
                    "app.kubernetes.io/name": "naranjo-online",
                    "app.kubernetes.io/instance": "naranjo-online",
                },
                "sessionAffinity": "None",
                "type": "ClusterIP",
            },
            "status": {"loadBalancer": {}},
        },
        "ServiceAccount": {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _static_metadata(
                "naranjo-online", SERVICE_ACCOUNT_UID
            ),
            "automountServiceAccountToken": False,
        },
        "NetworkPolicy": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": _static_metadata(
                "ingress-to-naranjo-online", NETWORK_POLICY_UID
            ),
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": "naranjo-online",
                        "app.kubernetes.io/instance": "naranjo-online",
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": (
                                            "cloudflare-public"
                                        )
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {
                                        "app.kubernetes.io/name": (
                                            "cloudflare-public"
                                        ),
                                        "app.kubernetes.io/instance": (
                                            "naranjo-online-tunnel"
                                        ),
                                    }
                                },
                            }
                        ],
                        "ports": [{"port": 8080, "protocol": "TCP"}],
                    }
                ],
            },
        },
    }


def _sync_workload_with_deployment(workload, deployment):
    semantic_sha256 = transaction.semantic_hash(deployment)
    workload.update(
        {
            "uid": deployment["metadata"]["uid"],
            "generation": deployment["metadata"]["generation"],
            "replicas": deployment["spec"]["replicas"],
            "templateSha256": transaction.sha256_bytes(
                transaction.canonical_json(deployment["spec"]["template"])
            ),
            "semanticSha256": semantic_sha256,
            "semanticWithoutProofSha256": semantic_sha256,
        }
    )
    owned_deployment = workload["ownedObjects"][-1]
    owned_deployment["uid"] = deployment["metadata"]["uid"]
    owned_deployment["semanticSha256"] = semantic_sha256
    owned_deployment["semanticWithoutProofSha256"] = semantic_sha256


def _sync_workload_with_static_objects(workload, objects):
    rows = {row["kind"]: row for row in workload["ownedObjects"]}
    for kind, value in objects.items():
        proof, without_proof = transaction.semantic_without_proof_annotation(
            value
        )
        rows[kind].update(
            {
                "uid": value["metadata"]["uid"],
                "semanticSha256": transaction.semantic_hash(value),
                "proofAnnotation": proof,
                "semanticWithoutProofSha256": without_proof,
            }
        )


def _owner_reference(kind, name, uid):
    return {
        "apiVersion": "apps/v1",
        "blockOwnerDeletion": True,
        "controller": True,
        "kind": kind,
        "name": name,
        "uid": uid,
    }


def _raw_replica_set(deployment):
    labels = copy.deepcopy(deployment["spec"]["template"]["metadata"]["labels"])
    labels["pod-template-hash"] = "reviewedhash"
    selector_labels = copy.deepcopy(deployment["spec"]["selector"]["matchLabels"])
    selector_labels["pod-template-hash"] = "reviewedhash"
    replicas = deployment["spec"]["replicas"]
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "naranjo-online-reviewedhash",
            "namespace": "naranjo-online",
            "uid": REPLICA_SET_UID,
            "resourceVersion": "21",
            "labels": labels,
            "annotations": {
                **copy.deepcopy(deployment["metadata"]["annotations"]),
                "deployment.kubernetes.io/desired-replicas": str(replicas),
                "deployment.kubernetes.io/max-replicas": str(replicas),
            },
            "ownerReferences": [
                _owner_reference("Deployment", "naranjo-online", DEPLOYMENT_UID)
            ],
        },
        "spec": {
            "replicas": replicas,
            "minReadySeconds": 0,
            "selector": {"matchLabels": selector_labels},
            "template": {
                "metadata": {
                    "labels": copy.deepcopy(labels),
                    "creationTimestamp": None,
                },
                "spec": copy.deepcopy(deployment["spec"]["template"]["spec"]),
            },
        },
    }


def _raw_pod(deployment, uid=POD_UID, suffix="abcde"):
    labels = copy.deepcopy(deployment["spec"]["template"]["metadata"]["labels"])
    labels["pod-template-hash"] = "reviewedhash"
    spec = copy.deepcopy(deployment["spec"]["template"]["spec"])
    spec["nodeName"] = "reviewed-node"
    spec["tolerations"] = [
        {
            "effect": "NoExecute",
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "tolerationSeconds": 300,
        },
        {
            "effect": "NoExecute",
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "tolerationSeconds": 300,
        },
    ]
    pod_ip = POD_IP if uid == POD_UID else POD_IP_2
    container_id = "a" * 64 if uid == POD_UID else "b" * 64
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"naranjo-online-reviewedhash-{suffix}",
            "namespace": "naranjo-online",
            "uid": uid,
            "resourceVersion": "22",
            "labels": labels,
            "annotations": {
                "cni.projectcalico.org/containerID": container_id,
                "cni.projectcalico.org/podIP": f"{pod_ip}/32",
                "cni.projectcalico.org/podIPs": f"{pod_ip}/32",
            },
            "ownerReferences": [
                _owner_reference(
                    "ReplicaSet", "naranjo-online-reviewedhash", REPLICA_SET_UID
                )
            ],
        },
        "spec": spec,
        "status": {
            "phase": "Running",
            "podIP": pod_ip,
            "podIPs": [{"ip": pod_ip}],
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [
                {
                    "name": "naranjo-online",
                    "image": transaction.RECOVERED_TO_IMAGE,
                    "imageID": (
                        "containerd://ghcr.io/snaraj/naranjo-online@"
                        + transaction.RECOVERED_TO_IMAGE.rsplit("@", 1)[1]
                    ),
                    "ready": True,
                    "restartCount": 0,
                    "started": True,
                    "state": {"running": {"startedAt": "2026-08-25T00:00:00Z"}},
                }
            ],
        },
    }


def _lidersea_fixture_rows():
    planned_oci = _oci(transaction.RECOVERED_LIDERSEA_FROM_VERSION, "3")
    current_oci = copy.deepcopy(planned_oci)
    current_oci.update(
        resourceVersion="4",
        revision=f"{transaction.RECOVERED_LIDERSEA_TO_VERSION}@{transaction.RECOVERED_LIDERSEA_CHART_DIGEST}",
        chartVersion=transaction.RECOVERED_LIDERSEA_TO_VERSION,
        upstreamDigest=transaction.RECOVERED_LIDERSEA_CHART_DIGEST,
        storedArtifactDigest="sha256:" + "4" * 64,
    )
    planned_helm = _helm(transaction.RECOVERED_LIDERSEA_FROM_VERSION, "3", 12, generation=4)
    current_helm = copy.deepcopy(planned_helm)
    current_helm.update(
        resourceVersion="4",
        attemptedRevision=transaction.RECOVERED_LIDERSEA_TO_VERSION,
        attemptedRevisionDigest=transaction.RECOVERED_LIDERSEA_CHART_DIGEST,
        historyRevision=12 + transaction.RECOVERED_LIDERSEA_HISTORY_STEP_COUNT,
        historyChartVersion=transaction.RECOVERED_LIDERSEA_TO_VERSION,
        historyOciDigest=transaction.RECOVERED_LIDERSEA_CHART_DIGEST,
        historyDigest="sha256:" + "4" * 64,
    )
    planned_workload = _workload("3", 12)
    current_workload = copy.deepcopy(planned_workload)
    current_workload["generation"] = 12 + transaction.RECOVERED_LIDERSEA_WORKLOAD_GENERATION_STEP_COUNT
    for field in ("templateSha256", "semanticSha256", "semanticWithoutProofSha256"):
        current_workload[field] = "4" * 64
    for pod in current_workload["pods"]:
        pod["images"] = [transaction.RECOVERED_LIDERSEA_RUNTIME_IMAGE]
    for item in current_workload["ownedObjects"]:
        item["semanticSha256"] = "4" * 64
        item["semanticWithoutProofSha256"] = "4" * 64
    deployment = {
        "metadata": {
            "name": "lidersea-com",
            "generation": 12 + transaction.RECOVERED_LIDERSEA_WORKLOAD_GENERATION_STEP_COUNT,
            "annotations": {"deployment.kubernetes.io/revision": transaction.RECOVERED_LIDERSEA_DEPLOYMENT_REVISION},
        },
        "spec": {
            "replicas": 2,
            "template": {"spec": {"containers": [{"image": transaction.RECOVERED_LIDERSEA_IMAGE}]}},
        },
    }
    return planned_oci, current_oci, planned_helm, current_helm, planned_workload, current_workload, deployment


def _controller_fixture_rows():
    planned = {"source-controller": {"podRestarts": 3, "generation": 2}}
    current = copy.deepcopy(planned)
    for name, uid in (("kustomize-controller", "kustomize-uid"), ("helm-controller", "helm-uid")):
        planned[name] = {
            "uid": uid,
            "resourceVersion": "1",
            "generation": 5,
            "podUid": f"{uid}-old-pod",
            "podReplicaSetUid": f"{uid}-rs",
            "podRestarts": 0,
            "semanticSha256": "a" * 64,
            "rollbackObject": {"generation": 5},
        }
        current[name] = {
            **planned[name],
            "resourceVersion": "2",
            "generation": 7,
            "podUid": f"{uid}-new-pod",
            "rollbackObject": {"generation": 7},
        }
    return planned, current


def _movement_fixture():
    key_oci = transaction.RECOVERED_NARANJO_OCI
    key_release = transaction.RECOVERED_NARANJO_RELEASE
    planned_flux = {
        "oci": {key_oci: _oci(transaction.RECOVERED_FROM_VERSION, "1")},
        "helm": {
            key_release: _helm(
                transaction.RECOVERED_FROM_VERSION, "1", 19, generation=5
            )
        },
    }
    current_flux = {
        "oci": {key_oci: _oci(transaction.RECOVERED_TO_VERSION, "2")},
        "helm": {key_release: _helm(transaction.RECOVERED_TO_VERSION, "2", 19 + transaction.RECOVERED_RELEASE_STEP_COUNT)},
    }
    planned_workloads = {key_release: _workload("1", 21)}
    current_workloads = {key_release: _workload("2", 21 + transaction.RECOVERED_WORKLOAD_GENERATION_STEP_COUNT)}
    lrows = _lidersea_fixture_rows()
    lkey = transaction.RECOVERED_LIDERSEA_RELEASE
    loci = transaction.RECOVERED_LIDERSEA_OCI
    planned_flux["oci"][loci], current_flux["oci"][loci] = lrows[0], lrows[1]
    planned_flux["helm"][lkey], current_flux["helm"][lkey] = lrows[2], lrows[3]
    planned_workloads[lkey], current_workloads[lkey] = lrows[4], lrows[5]
    planned_controllers, controllers = _controller_fixture_rows()
    public_sites = {"naranjo.online": {"status": 200}}
    deployment = _raw_deployment()
    static_objects = _raw_static_objects()
    planned_static_objects = copy.deepcopy(static_objects)
    for value in planned_static_objects.values():
        value["metadata"]["labels"]["app.kubernetes.io/version"] = (
            transaction.RECOVERED_FROM_VERSION
        )
    replica_set = _raw_replica_set(deployment)
    pods = [_raw_pod(deployment)]
    current_workload = current_workloads[key_release]
    _sync_workload_with_static_objects(
        planned_workloads[key_release], planned_static_objects
    )
    _sync_workload_with_deployment(current_workload, deployment)
    _sync_workload_with_static_objects(current_workload, static_objects)
    plan = {
        "baselines": {
            "flux": planned_flux,
            "workloads": planned_workloads,
            "controllers": copy.deepcopy(planned_controllers),
            "publicSites": copy.deepcopy(public_sites),
        }
    }

    def without_resource_versions(snapshot):
        normalized = copy.deepcopy(snapshot)
        for section in ("oci", "helm"):
            for row in normalized.get(section, {}).values():
                row.pop("resourceVersion", None)
        return normalized

    def collection(_client, url):
        if url.endswith("/deployments"):
            if "/namespaces/lidersea-com/" in url:
                return [copy.deepcopy(lrows[6])]
            return [copy.deepcopy(deployment)]
        if url.endswith("/replicasets"):
            return [copy.deepcopy(replica_set)]
        if url.endswith("/pods"):
            return copy.deepcopy(pods)
        if url.endswith("/services"):
            return [copy.deepcopy(static_objects["Service"])]
        if url.endswith("/serviceaccounts"):
            return [copy.deepcopy(static_objects["ServiceAccount"])]
        if url.endswith("/networkpolicies"):
            return [copy.deepcopy(static_objects["NetworkPolicy"])]
        raise AssertionError(f"unexpected collection: {url}")

    old = SimpleNamespace(
        SITE_INVENTORY_KINDS={
            "Deployment": None,
            "Service": None,
            "ServiceAccount": None,
            "NetworkPolicy": None,
        },
        flux_snapshot=lambda _client: copy.deepcopy(current_flux),
        workload_snapshot=lambda _client: copy.deepcopy(current_workloads),
        validate_helm_workload_inventory=mock.Mock(),
        validate_clean_workload_baseline=mock.Mock(),
        flux_baseline_without_resource_versions=without_resource_versions,
        controller_snapshot=lambda _client: copy.deepcopy(controllers),
        public_health=lambda: copy.deepcopy(public_sites),
        collection_items=collection,
        typed_site_inventory_item=lambda value, _kind: value,
        UID_RE=transaction.UID_RE,
        DNS_RE=transaction.DNS_RE,
        SERVER_METADATA=transaction.SERVER_METADATA,
        live_identity=transaction.live_identity,
        object_is_terminating=transaction.object_is_terminating,
        semantic_hash=transaction.semantic_hash,
        semantic_without_proof_annotation=(
            transaction.semantic_without_proof_annotation
        ),
        validate_controller_image_id=transaction.validate_controller_image_id,
        canonical_json=transaction.canonical_json,
        sha256_bytes=transaction.sha256_bytes,
    )
    return (
        old,
        plan,
        current_flux,
        current_workloads,
        controllers,
        public_sites,
        {
            "deployment": deployment,
            "replicaSet": replica_set,
            "pod": pods[0],
            "pods": pods,
            "service": static_objects["Service"],
            "serviceAccount": static_objects["ServiceAccount"],
            "networkPolicy": static_objects["NetworkPolicy"],
            "static": static_objects,
        },
    )


class ExactIncidentFingerprintTests(unittest.TestCase):
    def test_only_exact_seq47_incident_is_accepted(self):
        old, plan, journal = _incident_fixture()
        transaction.validate_recovered_incident(old, plan, journal)
        old.validate_terminal_evidence_document.assert_not_called()

    def test_identity_and_seq47_mutants_fail_closed(self):
        def mutate_tag(plan, _journal):
            plan["source"]["tag"] = "v0.1.29"

        def mutate_sequence(_plan, journal):
            journal["sequence"] -= 1

        def mutate_token(_plan, journal):
            journal["forwardFailureToken"] = "UNRELATED_FAILURE"

        def mutate_pending(_plan, journal):
            journal["pendingOperation"] = "operation-0"

        def mutate_missing_operation(_plan, journal):
            journal["operations"].pop("operation-0")

        def mutate_restored_set(_plan, journal):
            journal["operations"]["operation-0"]["rollbackState"] = "restored"

        cases = {
            "wrong release": mutate_tag,
            "pre-seq47 journal": mutate_sequence,
            "wrong forward failure": mutate_token,
            "pending mutation": mutate_pending,
            "partial operation inventory": mutate_missing_operation,
            "wrong restored identity": mutate_restored_set,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, journal = _incident_fixture()
                mutate(plan, journal)
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.validate_recovered_incident(old, plan, journal)

    def test_resume_accepts_only_closed_rollback_states_and_inventory(self):
        old, plan, journal = _incident_fixture()
        journal["sequence"] += 1
        journal["operations"]["operation-0"]["rollbackState"] = "restore-intent"
        transaction.validate_recovered_incident(old, plan, journal)

        journal["operations"]["operation-0"]["rollbackState"] = "arbitrary"
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "RECOVERY_INCIDENT_RESUME_INVALID"
        ):
            transaction.validate_recovered_incident(old, plan, journal)

        journal["operations"]["operation-0"]["rollbackState"] = "restored"
        journal["pendingOperation"] = "operation-0"
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "RECOVERY_INCIDENT_RESUME_INVALID"
        ):
            transaction.validate_recovered_incident(old, plan, journal)


class ExactReleaseMovementTests(unittest.TestCase):
    def test_recovered_release_tuple_is_literal_and_exact(self):
        self.assertEqual(transaction.RECOVERED_TO_VERSION, "0.1.49")
        self.assertEqual(transaction.RECOVERED_RELEASE_STEP_COUNT, 6)
        self.assertEqual(transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT, 8)
        self.assertEqual(transaction.RECOVERED_WORKLOAD_GENERATION_STEP_COUNT, 8)
        self.assertEqual(transaction.RECOVERED_TO_DEPLOYMENT_REVISION, "23")
        self.assertEqual(
            transaction.RECOVERED_TO_CHART_DIGEST,
            "sha256:0fbbf8e87b22002d5435c272a19af37a577012ae20ccf0a1be5f6b96c"
            "ca90ad1",
        )
        self.assertEqual(
            transaction.RECOVERED_TO_IMAGE,
            "ghcr.io/snaraj/naranjo-online:v0.1.49@"
            "sha256:05ec0b573e3e8dcfad8c4f84a800410f50f0fbadddd88ad199a46f22764c5633",
        )

    def test_exact_six_release_one_replica_movement_is_accepted(self):
        old, plan, current_flux, current_workloads, _controllers, _sites, _raw = (
            _movement_fixture()
        )
        movement = transaction.accepted_naranjo_movement(old, object(), plan)
        self.assertEqual(
            movement["verificationRows"]["oci"],
            current_flux["oci"][transaction.RECOVERED_NARANJO_OCI],
        )
        self.assertEqual(
            movement["verificationRows"]["workload"],
            current_workloads[transaction.RECOVERED_NARANJO_RELEASE],
        )
        self.assertEqual(
            set(movement["podProof"]), {"deploymentSha256", "pods"}
        )
        self.assertEqual(
            movement["verificationRows"]["helm"]["historyRevision"], 25
        )
        self.assertEqual(
            plan["baselines"]["flux"]["helm"][
                transaction.RECOVERED_NARANJO_RELEASE
            ]["generation"],
            5,
        )
        self.assertEqual(
            movement["verificationRows"]["helm"]["generation"], 7
        )
        self.assertEqual(
            movement["verificationRows"]["workload"]["generation"], 29
        )
        self.assertEqual(
            movement["verificationRows"]["workload"]["replicas"], 1
        )
        self.assertEqual(len(movement["podProof"]["pods"]), 1)
        self.assertEqual(
            set(movement["podProof"]["pods"][0]),
            {
                "podUidSha256",
                "imageIDSha256",
                "podSpecSha256",
                "podMetadataSha256",
                "replicaSetMetadataSha256",
                "replicaSetTemplateSha256",
                "ownerChainSha256",
            },
        )

    def test_lidersea_companion_release_drift_is_exact_and_closed(self):
        cases = {
            "chart digest": lambda flux, workloads: flux["oci"][transaction.RECOVERED_LIDERSEA_OCI].__setitem__("upstreamDigest", "sha256:" + "0" * 64),
            "history step": lambda flux, workloads: flux["helm"][transaction.RECOVERED_LIDERSEA_RELEASE].__setitem__("historyRevision", 12 + transaction.RECOVERED_LIDERSEA_HISTORY_STEP_COUNT + 1),
            "replica shape": lambda flux, workloads: workloads[transaction.RECOVERED_LIDERSEA_RELEASE].__setitem__("replicas", 1),
            "runtime image": lambda flux, workloads: workloads[transaction.RECOVERED_LIDERSEA_RELEASE]["pods"][0].__setitem__("images", ["sha256:" + "0" * 64]),
            "owned identity": lambda flux, workloads: workloads[transaction.RECOVERED_LIDERSEA_RELEASE]["ownedObjects"][0].__setitem__("uid", FOREIGN_UID),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, flux, workloads, _controllers, _sites, _objects = _movement_fixture()
                mutate(flux, workloads)
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.accepted_naranjo_movement(old, object(), plan)

    def test_controller_metadata_rollout_is_exact_and_closed(self):
        planned, current = _controller_fixture_rows()
        transaction.validate_recovered_controller_drift(planned, current)
        for label, mutate in {
            "generation": lambda rows: rows["helm-controller"].__setitem__("generation", 8),
            "deployment uid": lambda rows: rows["helm-controller"].__setitem__("uid", "foreign"),
            "replicaset uid": lambda rows: rows["helm-controller"].__setitem__("podReplicaSetUid", "foreign"),
            "restart": lambda rows: rows["helm-controller"].__setitem__("podRestarts", 1),
            "semantic": lambda rows: rows["helm-controller"].__setitem__("semanticSha256", "b" * 64),
        }.items():
            with self.subTest(label=label):
                mutated = copy.deepcopy(current)
                mutate(mutated)
                with self.assertRaisesRegex(transaction.RecoveryRequired, "RECOVERY_CONTROLLER_DRIFT"):
                    transaction.validate_recovered_controller_drift(planned, mutated)

    def test_exact_terminal_history_movement_is_explicit_and_closed(self):
        old, plan, flux, _workloads, _controllers, _sites, _raw = (
            _movement_fixture()
        )
        planned = plan["baselines"]["flux"]["helm"][
            transaction.RECOVERED_NARANJO_RELEASE
        ]
        live = flux["helm"][transaction.RECOVERED_NARANJO_RELEASE]
        live["historyRevision"] = (
            planned["historyRevision"]
            + transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT
        )
        with self.assertRaisesRegex(
            transaction.RecoveryRequired,
            "RECOVERY_NARANJO_HELM_REVISION_INVALID",
        ):
            transaction.accepted_naranjo_movement(old, object(), plan)
        movement = transaction.accepted_naranjo_movement(
            old,
            object(),
            plan,
            expected_history_steps=transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT,
        )
        self.assertEqual(movement["verificationRows"]["helm"]["historyRevision"], 27)

        for delta in (
            transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT - 1,
            transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT + 1,
        ):
            with self.subTest(delta=delta):
                live["historyRevision"] = planned["historyRevision"] + delta
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_HELM_REVISION_INVALID",
                ):
                    transaction.accepted_naranjo_movement(
                        old,
                        object(),
                        plan,
                        expected_history_steps=(
                            transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT
                        ),
                    )

        live["historyRevision"] = planned["historyRevision"] + 7
        with self.assertRaisesRegex(
            transaction.RecoveryRequired,
            "RECOVERY_NARANJO_HELM_REVISION_INVALID",
        ):
            transaction.accepted_naranjo_movement(
                old, object(), plan, expected_history_steps=7
            )

    def test_only_restored_proof_generation_increment_is_accepted(self):
        for label, generation, observed, attempted in (
            ("one generation", 6, 6, 6),
            ("three generations", 8, 8, 8),
            ("stale observed generation", 7, 6, 7),
            ("stale attempted generation", 7, 7, 6),
        ):
            with self.subTest(label=label):
                old, plan, flux, _workloads, _controllers, _sites, _raw = (
                    _movement_fixture()
                )
                helm = flux["helm"][transaction.RECOVERED_NARANJO_RELEASE]
                helm["generation"] = generation
                helm["observedGeneration"] = observed
                helm["lastAttemptedGeneration"] = attempted
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_HELM_GENERATION_INVALID",
                ):
                    transaction.accepted_naranjo_movement(old, object(), plan)

        for label, field in (
            ("stale planned observed generation", "observedGeneration"),
            ("stale planned attempted generation", "lastAttemptedGeneration"),
        ):
            with self.subTest(label=label):
                old, plan, _flux, _workloads, _controllers, _sites, _raw = (
                    _movement_fixture()
                )
                planned = plan["baselines"]["flux"]["helm"][
                    transaction.RECOVERED_NARANJO_RELEASE
                ]
                planned[field] = planned["generation"] - 1
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_HELM_GENERATION_INVALID",
                ):
                    transaction.accepted_naranjo_movement(old, object(), plan)

    def test_calico_projection_is_bound_into_pod_metadata_proof(self):
        old, plan, _flux, _workloads, _controllers, _sites, _objects = (
            _movement_fixture()
        )
        baseline = transaction.accepted_naranjo_movement(
            old, object(), plan
        )["podProof"]["pods"]

        old, plan, _flux, _workloads, _controllers, _sites, objects = (
            _movement_fixture()
        )
        objects["pod"]["metadata"]["annotations"][
            "cni.projectcalico.org/containerID"
        ] = "c" * 64
        changed = transaction.accepted_naranjo_movement(
            old, object(), plan
        )["podProof"]["pods"]

        self.assertEqual(len(baseline), len(changed))
        changed_metadata_rows = 0
        for before, after in zip(baseline, changed, strict=True):
            self.assertEqual(
                {
                    key: value
                    for key, value in before.items()
                    if key != "podMetadataSha256"
                },
                {
                    key: value
                    for key, value in after.items()
                    if key != "podMetadataSha256"
                },
            )
            changed_metadata_rows += (
                before["podMetadataSha256"] != after["podMetadataSha256"]
            )
        self.assertEqual(changed_metadata_rows, 1)

    def test_patch_release_static_label_churn_is_accepted_after_live_shape_validation(self):
        old, plan, _flux, workloads, _controllers, _sites, objects = (
            _movement_fixture()
        )
        planned_rows = {
            row["kind"]: row
            for row in plan["baselines"]["workloads"][
                transaction.RECOVERED_NARANJO_RELEASE
            ]["ownedObjects"]
        }
        current_rows = {
            row["kind"]: row
            for row in workloads[transaction.RECOVERED_NARANJO_RELEASE][
                "ownedObjects"
            ]
        }
        for kind in ("Service", "ServiceAccount", "NetworkPolicy"):
            self.assertNotEqual(
                planned_rows[kind]["semanticSha256"],
                current_rows[kind]["semanticSha256"],
            )
            labels = objects["static"][kind]["metadata"]["labels"]
            self.assertEqual(
                labels["app.kubernetes.io/version"],
                transaction.RECOVERED_TO_VERSION,
            )
            self.assertEqual(
                labels["helm.toolkit.fluxcd.io/name"], "naranjo-online"
            )
            self.assertEqual(
                labels["helm.toolkit.fluxcd.io/namespace"], "naranjo-online"
            )
        transaction.accepted_naranjo_movement(old, object(), plan)

    def test_static_object_shape_and_identity_mutations_fail_closed(self):
        def service(field, value):
            return lambda objects: objects["Service"]["spec"].__setitem__(
                field, value
            )

        cases = {
            "extra label": lambda objects: objects["Service"]["metadata"][
                "labels"
            ].__setitem__("example.invalid/foreign", "true"),
            "extra annotation": lambda objects: objects["NetworkPolicy"][
                "metadata"
            ]["annotations"].__setitem__("example.invalid/foreign", "true"),
            "Service selector": service(
                "selector", {"app.kubernetes.io/name": "foreign"}
            ),
            "Service port": service(
                "ports",
                [
                    {
                        "name": "http",
                        "port": 8081,
                        "protocol": "TCP",
                        "targetPort": "http",
                    }
                ],
            ),
            "Service type": service("type", "LoadBalancer"),
            "Service extra behavior": service(
                "externalTrafficPolicy", "Local"
            ),
            "Service allocated IP mismatch": service(
                "clusterIPs", [SERVICE_CLUSTER_IP_ALT]
            ),
            "Service allocated IP substitution": lambda objects: (
                objects["Service"]["spec"].__setitem__(
                    "clusterIP", SERVICE_CLUSTER_IP_ALT
                ),
                objects["Service"]["spec"].__setitem__(
                    "clusterIPs", [SERVICE_CLUSTER_IP_ALT]
                ),
            ),
            "ServiceAccount token": lambda objects: objects[
                "ServiceAccount"
            ].__setitem__("automountServiceAccountToken", True),
            "ServiceAccount secret": lambda objects: objects[
                "ServiceAccount"
            ].__setitem__("secrets", [{"name": "token-ref"}]),
            "NetworkPolicy widened peer": lambda objects: objects[
                "NetworkPolicy"
            ]["spec"]["ingress"][0]["from"][0].pop("podSelector"),
            "NetworkPolicy egress": lambda objects: objects[
                "NetworkPolicy"
            ]["spec"].__setitem__("egress", [{}]),
            "NetworkPolicy policy type": lambda objects: objects[
                "NetworkPolicy"
            ]["spec"].__setitem__("policyTypes", ["Ingress"]),
            "version label mismatch": lambda objects: objects["Service"][
                "metadata"
            ]["labels"].__setitem__(
                "app.kubernetes.io/version",
                transaction.RECOVERED_FROM_VERSION,
            ),
            "UID replacement": lambda objects: objects["Service"][
                "metadata"
            ].__setitem__("uid", FOREIGN_UID),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, _flux, workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                mutate(objects["static"])
                _sync_workload_with_static_objects(
                    workloads[transaction.RECOVERED_NARANJO_RELEASE],
                    objects["static"],
                )
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.accepted_naranjo_movement(
                        old, object(), plan
                    )

    def test_static_object_uid_replacement_after_snapshot_fails_closed(self):
        for kind in ("Service", "ServiceAccount", "NetworkPolicy"):
            with self.subTest(kind=kind):
                old, plan, _flux, _workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                objects["static"][kind]["metadata"]["uid"] = FOREIGN_UID
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_STATIC_OBJECT_IDENTITY_INVALID",
                ):
                    transaction.accepted_naranjo_movement(
                        old, object(), plan
                    )

    def test_substituted_planned_static_hash_fails_closed(self):
        old, plan, _flux, _workloads, _controllers, _sites, _objects = (
            _movement_fixture()
        )
        planned_rows = plan["baselines"]["workloads"][
            transaction.RECOVERED_NARANJO_RELEASE
        ]["ownedObjects"]
        service_row = next(
            row for row in planned_rows if row["kind"] == "Service"
        )
        service_row["semanticSha256"] = "f" * 64
        service_row["semanticWithoutProofSha256"] = "f" * 64
        with self.assertRaises(transaction.RecoveryRequired):
            transaction.accepted_naranjo_movement(old, object(), plan)

    def test_known_api_defaults_and_runtime_display_variants_are_accepted(self):
        old, plan, _flux, workloads, _controllers, _sites, objects = (
            _movement_fixture()
        )
        defaulted_keys = (
            "serviceAccount",
            "priority",
            "hostUsers",
            "shareProcessNamespace",
        )
        for name in ("deployment", "replicaSet", "pod"):
            if name == "deployment":
                spec = objects[name]["spec"]["template"]["spec"]
            elif name == "replicaSet":
                spec = objects[name]["spec"]["template"]["spec"]
            else:
                spec = objects[name]["spec"]
            for key in defaulted_keys:
                spec.pop(key, None)
            container = spec["containers"][0]
            container.pop("terminationMessagePolicy", None)
            for probe_name in (
                "startupProbe",
                "readinessProbe",
                "livenessProbe",
            ):
                container[probe_name].pop("successThreshold", None)
                container[probe_name]["httpGet"].pop("host", None)
                container[probe_name]["httpGet"].pop("httpHeaders", None)
        display_image = (
            "ghcr.io/snaraj/naranjo-online@"
            + transaction.RECOVERED_TO_IMAGE.rsplit("@", 1)[1]
        )
        objects["pod"]["status"]["containerStatuses"][0][
            "image"
        ] = display_image
        workloads[transaction.RECOVERED_NARANJO_RELEASE]["pods"][0][
            "images"
        ] = [display_image]
        _sync_workload_with_deployment(
            workloads[transaction.RECOVERED_NARANJO_RELEASE],
            objects["deployment"],
        )

        movement = transaction.accepted_naranjo_movement(old, object(), plan)
        self.assertEqual(len(movement["podProof"]["pods"]), 1)

    def test_adjacent_history_and_workload_generation_deltas_fail_closed(self):
        for field in ("Helm history", "workload generation"):
            expected = (
                transaction.RECOVERED_RELEASE_STEP_COUNT
                if field == "Helm history"
                else transaction.RECOVERED_WORKLOAD_GENERATION_STEP_COUNT
            )
            for label, delta in {"one-short": expected - 1, "one-extra": expected + 1}.items():
                with self.subTest(field=field, label=label):
                    old, plan, flux, workloads, _controllers, _sites, objects = (
                        _movement_fixture()
                    )
                    if field == "Helm history":
                        planned_helm = plan["baselines"]["flux"]["helm"][
                            transaction.RECOVERED_NARANJO_RELEASE
                        ]
                        flux["helm"][transaction.RECOVERED_NARANJO_RELEASE][
                            "historyRevision"
                        ] = planned_helm["historyRevision"] + delta
                    else:
                        planned_workload = plan["baselines"]["workloads"][
                            transaction.RECOVERED_NARANJO_RELEASE
                        ]
                        objects["deployment"]["metadata"]["generation"] = (
                            planned_workload["generation"] + delta
                        )
                        _sync_workload_with_deployment(
                            workloads[transaction.RECOVERED_NARANJO_RELEASE],
                            objects["deployment"],
                        )
                    with self.assertRaises(transaction.RecoveryRequired):
                        transaction.accepted_naranjo_movement(
                            old, object(), plan
                        )

    def test_replica_set_count_mismatches_fail_closed(self):
        for label, mutate in {
            "desired annotation": lambda replica_set: replica_set["metadata"][
                "annotations"
            ].__setitem__("deployment.kubernetes.io/desired-replicas", "2"),
            "max annotation": lambda replica_set: replica_set["metadata"][
                "annotations"
            ].__setitem__("deployment.kubernetes.io/max-replicas", "2"),
            "spec replicas": lambda replica_set: replica_set["spec"].__setitem__(
                "replicas", 2
            ),
        }.items():
            with self.subTest(label=label):
                old, plan, _flux, _workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                mutate(objects["replicaSet"])
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_OWNER_INVALID",
                ):
                    transaction.accepted_naranjo_movement(
                        old, object(), plan
                    )

    def test_coherent_deployment_revision_substitution_fails_closed(self):
        expected_revision = int(transaction.RECOVERED_TO_DEPLOYMENT_REVISION)
        for substituted_revision in (
            str(expected_revision - 1),
            str(expected_revision + 1),
        ):
            with self.subTest(revision=substituted_revision):
                old, plan, _flux, workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                objects["deployment"]["metadata"]["annotations"][
                    "deployment.kubernetes.io/revision"
                ] = substituted_revision
                objects["replicaSet"]["metadata"]["annotations"][
                    "deployment.kubernetes.io/revision"
                ] = substituted_revision
                _sync_workload_with_deployment(
                    workloads[transaction.RECOVERED_NARANJO_RELEASE],
                    objects["deployment"],
                )
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_DEPLOYMENT_METADATA_INVALID",
                ):
                    transaction.accepted_naranjo_movement(old, object(), plan)

    def test_deployment_flux_owner_labels_are_exact_and_closed(self):
        def remove_name(labels):
            labels.pop("helm.toolkit.fluxcd.io/name")

        cases = {
            "missing name": remove_name,
            "wrong namespace": lambda labels: labels.__setitem__(
                "helm.toolkit.fluxcd.io/namespace", "foreign"
            ),
            "extra label": lambda labels: labels.__setitem__(
                "example.invalid/foreign", "true"
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, _flux, _workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                mutate(objects["deployment"]["metadata"]["labels"])
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_DEPLOYMENT_METADATA_INVALID",
                ):
                    transaction.accepted_naranjo_movement(old, object(), plan)

    def test_previous_endpoint_and_coherent_tuple_substitution_fail_closed(self):
        old, plan, flux, _workloads, _controllers, _sites, objects = (
            _movement_fixture()
        )
        flux["oci"][transaction.RECOVERED_NARANJO_OCI]["chartVersion"] = (
            "0.1.45"
        )
        with self.assertRaisesRegex(
            transaction.RecoveryRequired,
            "RECOVERY_NARANJO_VERSION_INVALID",
        ):
            transaction.accepted_naranjo_movement(old, object(), plan)

        old, plan, flux, workloads, _controllers, _sites, objects = (
            _movement_fixture()
        )
        substituted_digest = "sha256:" + "f" * 64
        substituted_image = (
            "ghcr.io/snaraj/naranjo-online:v0.1.46@" + substituted_digest
        )
        flux["oci"][transaction.RECOVERED_NARANJO_OCI][
            "upstreamDigest"
        ] = substituted_digest
        flux["helm"][transaction.RECOVERED_NARANJO_RELEASE][
            "attemptedRevisionDigest"
        ] = substituted_digest
        flux["helm"][transaction.RECOVERED_NARANJO_RELEASE][
            "historyOciDigest"
        ] = substituted_digest
        objects["deployment"]["spec"]["template"]["spec"]["containers"][0][
            "image"
        ] = substituted_image
        for pod in objects["pods"]:
            pod["spec"]["containers"][0]["image"] = substituted_image
            pod["status"]["containerStatuses"][0]["image"] = substituted_image
            pod["status"]["containerStatuses"][0]["imageID"] = (
                "containerd://ghcr.io/snaraj/naranjo-online@"
                + substituted_digest
            )
        _sync_workload_with_deployment(
            workloads[transaction.RECOVERED_NARANJO_RELEASE],
            objects["deployment"],
        )
        for pod in workloads[transaction.RECOVERED_NARANJO_RELEASE]["pods"]:
            pod["images"] = [substituted_image]
        with self.assertRaises(transaction.RecoveryRequired):
            transaction.accepted_naranjo_movement(old, object(), plan)

    def test_matching_live_and_snapshot_pod_count_drift_fails_closed(self):
        for label in ("missing-one", "extra-one"):
            with self.subTest(label=label):
                old, plan, _flux, workloads, _controllers, _sites, objects = (
                    _movement_fixture()
                )
                live_pods = objects["pods"]
                if label == "missing-one":
                    live_pods.pop()
                else:
                    extra_uid = _synthetic_uid("7")
                    live_pods.append(
                        _raw_pod(objects["deployment"], extra_uid, "klmno")
                    )
                with self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "RECOVERY_NARANJO_POD_INVENTORY_INVALID",
                ):
                    transaction.accepted_naranjo_movement(
                        old, object(), plan
                    )

    def test_every_out_of_scope_drift_class_fails_closed(self):
        def oci_identity(_plan, flux, _workloads, _controllers, _sites):
            flux["oci"][transaction.RECOVERED_NARANJO_OCI]["uid"] = "foreign"

        def arbitrary_version(_plan, flux, _workloads, _controllers, _sites):
            flux["oci"][transaction.RECOVERED_NARANJO_OCI][
                "chartVersion"
            ] = "0.1.44"

        def helm_inventory(_plan, flux, _workloads, _controllers, _sites):
            flux["helm"][transaction.RECOVERED_NARANJO_RELEASE]["inventory"] = []

        def skipped_history(_plan, flux, _workloads, _controllers, _sites):
            flux["helm"][transaction.RECOVERED_NARANJO_RELEASE]["historyRevision"] = 10

        def workload_identity(_plan, _flux, workloads, _controllers, _sites):
            workloads[transaction.RECOVERED_NARANJO_RELEASE]["uid"] = "foreign"

        def static_object(_plan, _flux, workloads, _controllers, _sites):
            workloads[transaction.RECOVERED_NARANJO_RELEASE]["ownedObjects"][0][
                "semanticSha256"
            ] = "f" * 64

        def deployment_identity(_plan, _flux, workloads, _controllers, _sites):
            workloads[transaction.RECOVERED_NARANJO_RELEASE]["ownedObjects"][3][
                "uid"
            ] = "foreign"

        def pod_restart(_plan, _flux, workloads, _controllers, _sites):
            workloads[transaction.RECOVERED_NARANJO_RELEASE]["pods"][0][
                "restartCounts"
            ] = [1]

        def foreign_runtime_image(
            _plan, _flux, workloads, _controllers, _sites
        ):
            workloads[transaction.RECOVERED_NARANJO_RELEASE]["pods"][0][
                "images"
            ] = ["ghcr.io/example/foreign@sha256:" + "e" * 64]

        def unrelated_flux(_plan, flux, _workloads, _controllers, _sites):
            flux["oci"]["lidersea-com/unexpected"] = _oci("0.1.99", "9")

        def unrelated_workload(_plan, _flux, workloads, _controllers, _sites):
            workloads["lidersea-com/unexpected"] = _workload("9", 99)

        def controller_drift(_plan, _flux, _workloads, controllers, _sites):
            controllers["source-controller"]["podRestarts"] = 1

        def public_drift(_plan, _flux, _workloads, _controllers, sites):
            sites["naranjo.online"]["status"] = 503

        def oci_semantic_drift(_plan, flux, _workloads, _controllers, _sites):
            flux["oci"][transaction.RECOVERED_NARANJO_OCI][
                "semanticSha256"
            ] = "f" * 64

        def helm_semantic_drift(_plan, flux, _workloads, _controllers, _sites):
            flux["helm"][transaction.RECOVERED_NARANJO_RELEASE][
                "semanticSha256"
            ] = "f" * 64

        def foreign_image(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            deployment = objects["deployment"]
            deployment["spec"]["template"]["spec"]["containers"][0][
                "image"
            ] = "ghcr.io/example/foreign@sha256:" + "f" * 64

        def template_drift(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            deployment = objects["deployment"]
            deployment["spec"]["template"]["metadata"]["labels"][
                "app.kubernetes.io/version"
            ] = "0.1.44"

        def environment_drift(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            deployment = objects["deployment"]
            deployment["spec"]["template"]["spec"]["containers"][0]["env"][2][
                "value"
            ] = "true"

        def security_drift(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            deployment = objects["deployment"]
            deployment["spec"]["template"]["spec"]["containers"][0][
                "securityContext"
            ]["allowPrivilegeEscalation"] = True

        def shared_process_namespace(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            deployment = objects["deployment"]
            deployment["spec"]["template"]["spec"][
                "shareProcessNamespace"
            ] = True

        def extra_deployment_annotation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["deployment"]["metadata"]["annotations"][
                "example.invalid/foreign"
            ] = "accepted-before-fix"

        def foreign_pod_image_id(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["status"]["containerStatuses"][0][
                "imageID"
            ] = "containerd://ghcr.io/example/foreign@sha256:" + "e" * 64

        def unsafe_live_pod_spec(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["spec"]["hostNetwork"] = True
            objects["pod"]["spec"]["hostPID"] = True
            objects["pod"]["spec"]["containers"][0]["securityContext"][
                "privileged"
            ] = True

        def foreign_owner_chain(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["ownerReferences"][0]["uid"] = (
                FOREIGN_UID
            )

        def foreign_replica_template(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["spec"]["template"]["spec"][
                "hostNetwork"
            ] = True

        def extra_owner_reference(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["ownerReferences"].append(
                _owner_reference(
                    "ReplicaSet",
                    "foreign-owner",
                    FOREIGN_UID,
                )
            )

        def substituted_direct_deployment_identity(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            substituted_uid = SUBSTITUTED_UID
            objects["deployment"]["metadata"]["uid"] = substituted_uid
            objects["replicaSet"]["metadata"]["ownerReferences"][0][
                "uid"
            ] = substituted_uid

        def substituted_direct_replicas(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["deployment"]["spec"]["replicas"] = 2

        def substituted_direct_generation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["deployment"]["metadata"]["generation"] += 1

        def pod_finalizer(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["finalizers"] = [
                "example.invalid/hold"
            ]

        def replica_set_finalizer(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["metadata"]["finalizers"] = [
                "example.invalid/hold"
            ]

        def pod_behavior_annotation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["annotations"] = {
                "container.apparmor.security.beta.kubernetes.io/naranjo-online": (
                    "unconfined"
                )
            }

        def calico_annotation(field, value):
            def mutate(
                _plan, _flux, _workloads, _controllers, _sites, objects
            ):
                objects["pod"]["metadata"]["annotations"][field] = value

            return mutate

        def extra_calico_annotation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["annotations"][
                "example.invalid/foreign"
            ] = "true"

        def mismatched_status_pod_ip(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["status"]["podIP"] = POD_IP_2

        def extra_status_pod_ip(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["status"]["podIPs"].append({"ip": POD_IP_2})

        def owned_deployment_projection(
            _plan, _flux, workloads, _controllers, _sites, _objects
        ):
            owned = workloads[transaction.RECOVERED_NARANJO_RELEASE][
                "ownedObjects"
            ][-1]
            owned["semanticSha256"] = "f" * 64
            owned["semanticWithoutProofSha256"] = "f" * 64

        def pod_owner_field(field, value):
            def mutate(
                _plan, _flux, _workloads, _controllers, _sites, objects
            ):
                objects["pod"]["metadata"]["ownerReferences"][0][field] = value

            return mutate

        def replica_owner_field(field, value):
            def mutate(
                _plan, _flux, _workloads, _controllers, _sites, objects
            ):
                objects["replicaSet"]["metadata"]["ownerReferences"][0][
                    field
                ] = value

            return mutate

        def extra_replica_annotation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["metadata"]["annotations"][
                "example.invalid/foreign"
            ] = "true"

        def changed_replica_inherited_annotation(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["metadata"]["annotations"][
                "platform.snaraj.dev/deployment-ready"
            ] = "false"

        def widened_replica_selector(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["spec"]["selector"]["matchLabels"][
                "example.invalid/foreign"
            ] = "true"

        def extra_pod_label(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["metadata"]["labels"][
                "example.invalid/foreign"
            ] = "true"

        def extra_replica_label(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["replicaSet"]["metadata"]["labels"][
                "example.invalid/foreign"
            ] = "true"

        def changed_live_toleration(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["spec"]["tolerations"][0][
                "tolerationSeconds"
            ] = 301

        def invalid_live_node_name(
            _plan, _flux, _workloads, _controllers, _sites, objects
        ):
            objects["pod"]["spec"]["nodeName"] = "INVALID_NODE"

        def adapt(mutate):
            return lambda plan, flux, workloads, controllers, sites, _objects: mutate(
                plan, flux, workloads, controllers, sites
            )

        cases = {
            "OCI identity": adapt(oci_identity),
            "arbitrary chart version": adapt(arbitrary_version),
            "Helm inventory": adapt(helm_inventory),
            "Helm revision skip": adapt(skipped_history),
            "workload identity": adapt(workload_identity),
            "static owned object": adapt(static_object),
            "Deployment identity": adapt(deployment_identity),
            "pod restart": adapt(pod_restart),
            "foreign runtime image": adapt(foreign_runtime_image),
            "unrelated Flux object": adapt(unrelated_flux),
            "unrelated workload": adapt(unrelated_workload),
            "controller drift": adapt(controller_drift),
            "public-site drift": adapt(public_drift),
            "OCI semantic drift": adapt(oci_semantic_drift),
            "Helm semantic drift": adapt(helm_semantic_drift),
            "foreign workload image": foreign_image,
            "raw template drift": template_drift,
            "environment activation": environment_drift,
            "security-context weakening": security_drift,
            "shared process namespace": shared_process_namespace,
            "extra Deployment annotation": extra_deployment_annotation,
            "foreign live Pod imageID": foreign_pod_image_id,
            "unsafe live Pod spec": unsafe_live_pod_spec,
            "foreign Pod owner chain": foreign_owner_chain,
            "foreign ReplicaSet template": foreign_replica_template,
            "extra Pod owner reference": extra_owner_reference,
            "substituted direct Deployment identity": (
                substituted_direct_deployment_identity
            ),
            "substituted direct replicas": substituted_direct_replicas,
            "substituted direct generation": substituted_direct_generation,
            "Pod finalizer": pod_finalizer,
            "ReplicaSet finalizer": replica_set_finalizer,
            "Pod behavior annotation": pod_behavior_annotation,
            "Calico extra annotation": extra_calico_annotation,
            "Calico malformed container ID": calico_annotation(
                "cni.projectcalico.org/containerID", "not-a-container-id"
            ),
            "Calico non-host prefix": calico_annotation(
                "cni.projectcalico.org/podIP", f"{POD_IP}/24"
            ),
            "Calico aggregate mismatch": calico_annotation(
                "cni.projectcalico.org/podIPs", f"{POD_IP_2}/32"
            ),
            "Calico Pod status mismatch": mismatched_status_pod_ip,
            "Calico extra status IP": extra_status_pod_ip,
            "owned Deployment semantic projection": owned_deployment_projection,
            "Pod owner controller": pod_owner_field("controller", False),
            "Pod owner API version": pod_owner_field("apiVersion", "v1"),
            "Pod owner kind": pod_owner_field("kind", "Deployment"),
            "Pod owner block deletion": pod_owner_field(
                "blockOwnerDeletion", False
            ),
            "Pod owner extra field": pod_owner_field("foreign", "value"),
            "ReplicaSet owner name": replica_owner_field(
                "name", "foreign-deployment"
            ),
            "ReplicaSet owner UID": replica_owner_field("uid", FOREIGN_UID),
            "ReplicaSet extra annotation": extra_replica_annotation,
            "ReplicaSet changed inherited annotation": (
                changed_replica_inherited_annotation
            ),
            "ReplicaSet widened selector": widened_replica_selector,
            "Pod extra metadata label": extra_pod_label,
            "ReplicaSet extra metadata label": extra_replica_label,
            "changed live toleration": changed_live_toleration,
            "invalid live node name": invalid_live_node_name,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, flux, workloads, controllers, sites, objects = (
                    _movement_fixture()
                )
                mutate(plan, flux, workloads, controllers, sites, objects)
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.accepted_naranjo_movement(old, object(), plan)


class RecoveryCustodyBindingTests(unittest.TestCase):
    @staticmethod
    def old_fixture():
        receipt = {
            "schema": transaction.CUSTODY_SCHEMA,
            "sourceRevision": transaction.RECOVERED_SOURCE_REVISION,
            "manifestSha256": transaction.RECOVERED_MANIFEST_SHA256,
            "launcherSha256": transaction.RECOVERED_LAUNCHER_SHA256,
            "pythonPath": str(transaction.PYTHON_PATH),
            "pythonSha256": transaction.RECOVERED_PYTHON_SHA256,
            "custodySha256": transaction.RECOVERED_CUSTODY_SHA256,
        }
        old = SimpleNamespace(
            STATE_ROOT=transaction.RECOVERED_STATE_ROOT,
            AUTHORIZED_RELEASE_TAG=transaction.RECOVERED_RELEASE_TAG,
            INSTALLED_LAUNCHER=transaction.INSTALLED_LAUNCHER,
            CUSTODY_SCHEMA=transaction.CUSTODY_SCHEMA,
            PYTHON_PATH=transaction.PYTHON_PATH,
            SOURCE_MANIFEST_REL=transaction.SOURCE_MANIFEST_REL,
            DESIRED_REL=transaction.DESIRED_REL,
            ORACLE_REL=transaction.ORACLE_REL,
            KUBECONFIG_VALIDATOR_REL=transaction.KUBECONFIG_VALIDATOR_REL,
            PLATFORM_CONTRACT_REL=transaction.PLATFORM_CONTRACT_REL,
            VERSIONS_REL=transaction.VERSIONS_REL,
            RELEASE_FRAGMENT_REL="changelog.d/141-flux-rbac-v030-cleanup-state.md",
            load_custody_receipt=mock.Mock(return_value=receipt),
        )
        entries = {
            old.DESIRED_REL: "1" * 64,
            old.ORACLE_REL: "2" * 64,
            old.KUBECONFIG_VALIDATOR_REL: "3" * 64,
            old.PLATFORM_CONTRACT_REL: "4" * 64,
            old.VERSIONS_REL: "5" * 64,
            old.RELEASE_FRAGMENT_REL: "6" * 64,
            "bootstrap/flux/rbac-convergence/transaction.py": (
                transaction.RECOVERED_LAUNCHER_SHA256
            ),
        }
        old.validate_custody = mock.Mock(return_value=entries)
        return old, receipt, entries

    @contextlib.contextmanager
    def patched_old_load(self, old):
        with mock.patch.object(
            transaction, "read_regular", return_value=b"reviewed-v030-transaction"
        ), mock.patch.object(
            transaction,
            "sha256_bytes",
            return_value=transaction.RECOVERED_LAUNCHER_SHA256,
        ), mock.patch.object(
            transaction, "load_module_payload", return_value=old
        ) as load_payload, mock.patch.object(
            transaction,
            "load_module",
            side_effect=AssertionError("hashed path must not be reopened"),
        ):
            yield load_payload

    def test_exact_old_custody_and_closed_entries_are_required(self):
        old, receipt, _entries = self.old_fixture()
        with self.patched_old_load(old) as load_payload:
            loaded, loaded_receipt = transaction.load_recovered_transaction()
        self.assertIs(loaded, old)
        self.assertEqual(loaded_receipt, receipt)
        old.validate_custody.assert_called_once_with(receipt)
        self.assertEqual(
            load_payload.call_args.args[0], b"reviewed-v030-transaction"
        )

    def test_every_old_custody_field_substitution_fails_closed(self):
        mutations = {
            "schema": "foreign-schema",
            "sourceRevision": "a" * 40,
            "manifestSha256": "b" * 64,
            "launcherSha256": "c" * 64,
            "pythonPath": "/foreign/python",
            "pythonSha256": "d" * 64,
            "custodySha256": "e" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                old, receipt, _entries = self.old_fixture()
                old.load_custody_receipt.return_value = {
                    **receipt,
                    field: value,
                }
                with self.patched_old_load(old), self.assertRaisesRegex(
                    transaction.TransactionError,
                    "RECOVERY_OLD_CUSTODY_RECEIPT_INVALID",
                ):
                    transaction.load_recovered_transaction()

    def test_every_old_custody_entry_substitution_fails_closed(self):
        old, _receipt, entries = self.old_fixture()
        cases = {}
        for relative in entries:
            candidate = dict(entries)
            candidate.pop(relative)
            cases[f"missing {relative}"] = candidate
        extra = dict(entries)
        extra[transaction.SOURCE_MANIFEST_REL] = "7" * 64
        cases["foreign source manifest entry"] = extra
        wrong_launcher = dict(entries)
        wrong_launcher["bootstrap/flux/rbac-convergence/transaction.py"] = "8" * 64
        cases["wrong transaction entry"] = wrong_launcher
        for label, candidate in cases.items():
            with self.subTest(label=label):
                old.validate_custody.return_value = candidate
                with self.patched_old_load(old), self.assertRaisesRegex(
                    transaction.TransactionError,
                    "RECOVERY_OLD_CUSTODY_ENTRY_INVALID",
                ):
                    transaction.load_recovered_transaction()

    def test_new_custody_and_release_arguments_are_revalidated(self):
        custody = {
            "schema": transaction.CUSTODY_SCHEMA,
            "sourceRevision": "6" * 40,
            "manifestSha256": "7" * 64,
            "launcherSha256": "8" * 64,
            "pythonPath": str(transaction.PYTHON_PATH),
            "pythonSha256": "9" * 64,
            "custodySha256": "a" * 64,
        }
        entries = {"reviewed": "entry"}
        source = {"sourceTreeSha": "b" * 40}
        with mock.patch.object(
            transaction,
            "validate_runtime_custody",
            return_value=(copy.deepcopy(custody), copy.deepcopy(entries)),
        ) as validate_runtime, mock.patch.object(
            transaction, "load_module", return_value=object()
        ), mock.patch.object(
            transaction, "read_regular", return_value=b"reviewed fragment"
        ), mock.patch.object(
            transaction, "verify_release_identity", return_value=source
        ) as verify_release, mock.patch.object(
            transaction, "validate_custody", return_value=copy.deepcopy(entries)
        ) as validate_custody, mock.patch.object(
            transaction, "verify_custody_source_tree", return_value="c" * 64
        ):
            result = transaction.validate_recovery_release_identity(
                custody, require_main_tip=True
            )
            self.assertEqual(result["sourceManifestSha256"], "7" * 64)
            self.assertEqual(result["custodySha256"], "a" * 64)
            verify_release.assert_called_once()
            self.assertEqual(
                verify_release.call_args.args[:2],
                ("6" * 40, transaction.AUTHORIZED_RELEASE_TAG),
            )
            self.assertIs(verify_release.call_args.kwargs["require_main_tip"], True)
            validate_runtime.assert_called_once_with()
            validate_custody.assert_called_once_with(custody)

            for field, replacement in (
                ("schema", "foreign"),
                ("sourceRevision", "d" * 40),
                ("manifestSha256", "e" * 64),
                ("launcherSha256", "f" * 64),
                ("pythonPath", "/foreign/python"),
                ("pythonSha256", "1" * 64),
                ("custodySha256", "2" * 64),
            ):
                with self.subTest(field=field), self.assertRaisesRegex(
                    transaction.TransactionError,
                    "RECOVERY_RUNTIME_CUSTODY_SUBSTITUTED",
                ):
                    transaction.validate_recovery_release_identity(
                        {**custody, field: replacement}, require_main_tip=True
                    )

    def test_revalidated_runtime_entry_map_must_match(self):
        custody = {
            "schema": transaction.CUSTODY_SCHEMA,
            "sourceRevision": "6" * 40,
            "manifestSha256": "7" * 64,
            "launcherSha256": "8" * 64,
            "pythonPath": str(transaction.PYTHON_PATH),
            "pythonSha256": "9" * 64,
            "custodySha256": "a" * 64,
        }
        runtime_entries = {"reviewed": "entry"}
        with mock.patch.object(
            transaction,
            "validate_runtime_custody",
            return_value=(custody, runtime_entries),
        ), mock.patch.object(
            transaction, "load_module", return_value=object()
        ), mock.patch.object(
            transaction, "read_regular", return_value=b"reviewed fragment"
        ), mock.patch.object(
            transaction,
            "verify_release_identity",
            return_value={"sourceTreeSha": "b" * 40},
        ), mock.patch.object(
            transaction,
            "validate_custody",
            return_value={"substituted": "entry"},
        ), mock.patch.object(
            transaction, "verify_custody_source_tree"
        ) as verify_tree:
            with self.assertRaisesRegex(
                transaction.TransactionError,
                "RECOVERY_RUNTIME_CUSTODY_SUBSTITUTED",
            ):
                transaction.validate_recovery_release_identity(
                    custody, require_main_tip=True
                )
        verify_tree.assert_not_called()


class RecoveryReceiptBindingTests(unittest.TestCase):
    @staticmethod
    def render(movement):
        captured = {}
        custody = {
            "sourceRevision": "1" * 40,
            "manifestSha256": "2" * 64,
            "custodySha256": "3" * 64,
        }
        source = {"tag": transaction.AUTHORIZED_RELEASE_TAG, "tree": "4" * 40}
        journal = SimpleNamespace(
            document={
                "state": "rolled-back",
                "receiptRecords": {
                    "rolled-back": {"recordedAt": "2026-08-25T00:00:00Z"}
                },
                "terminalEvidenceSha256": "5" * 64,
            }
        )

        def publish(path, payload):
            captured[path] = payload

        def read(path, **_kwargs):
            return captured[path]

        with mock.patch.object(
            transaction, "publish_once", side_effect=publish
        ), mock.patch.object(transaction, "read_regular", side_effect=read):
            transaction.publish_recovery_receipt(
                custody, source, object(), journal, movement
            )
        return json.loads(captured[transaction.RECOVERY_RECEIPT_PATH])

    def test_receipt_hashes_the_complete_movement_and_runtime_proof(self):
        movement = _valid_movement()
        receipt = self.render(movement)
        self.assertEqual(
            receipt["acceptedMovementSha256"],
            transaction.sha256_bytes(transaction.canonical_json(movement)),
        )
        self.assertEqual(
            receipt["acceptedPodProofSha256"],
            transaction.sha256_bytes(
                transaction.canonical_json(movement["podProof"])
            ),
        )

        substituted = copy.deepcopy(movement)
        substituted["podProof"]["pods"][0]["podSpecSha256"] = "8" * 64
        substituted_receipt = self.render(substituted)
        self.assertNotEqual(
            receipt["acceptedMovementSha256"],
            substituted_receipt["acceptedMovementSha256"],
        )
        self.assertNotEqual(
            receipt["acceptedPodProofSha256"],
            substituted_receipt["acceptedPodProofSha256"],
        )

    def test_receipt_rejects_missing_runtime_proof(self):
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "RECOVERY_VERIFICATION_ROWS_INVALID"
        ):
            self.render({"verificationRows": {}})

    def test_receipt_rejects_partial_or_unbound_runtime_proof(self):
        cases = {}
        extra = _valid_movement()
        extra["unexpected"] = {}
        cases["extra movement field"] = extra
        empty_row = _valid_movement()
        empty_row["verificationRows"]["oci"] = {}
        cases["empty verification row"] = empty_row
        partial = _valid_movement()
        partial["podProof"]["pods"][0].pop("podMetadataSha256")
        cases["partial Pod proof"] = partial
        wrong_uid = _valid_movement()
        wrong_uid["podProof"]["pods"][0]["podUidSha256"] = "f" * 64
        cases["unbound Pod UID"] = wrong_uid
        empty_pods = _valid_movement()
        empty_pods["podProof"]["pods"] = []
        cases["empty Pod proof"] = empty_pods
        extra_row = _valid_movement()
        extra_row["verificationRows"]["foreign"] = {"value": "unexpected"}
        cases["extra verification row"] = extra_row
        extra_proof = _valid_movement()
        extra_proof["podProof"]["foreign"] = "unexpected"
        cases["extra Pod proof field"] = extra_proof
        malformed_deployment = _valid_movement()
        malformed_deployment["podProof"]["deploymentSha256"] = "invalid"
        cases["malformed Deployment proof hash"] = malformed_deployment
        malformed_image = _valid_movement()
        malformed_image["podProof"]["pods"][0]["imageIDSha256"] = "invalid"
        cases["malformed imageID proof hash"] = malformed_image
        both_empty = _valid_movement()
        both_empty["verificationRows"]["workload"]["pods"] = []
        both_empty["podProof"]["pods"] = []
        cases["empty workload and proof Pod inventories"] = both_empty
        for label, movement in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                transaction.RecoveryRequired,
                "RECOVERY_VERIFICATION_ROWS_INVALID",
            ):
                self.render(movement)


class RecoveryPlanGateTests(unittest.TestCase):
    @staticmethod
    def terminal_fixture():
        old, plan, journal_document = _incident_fixture()
        order = plan["operationOrder"]
        for operation_id in order[18:]:
            journal_document["operations"][operation_id] = {
                "state": "not-started",
                "rollbackState": "prestate-verified",
            }
        journal_document.update(
            {
                "state": "rolled-back",
                "phase": "rolled-back",
                "sequence": transaction.RECOVERED_INITIAL_SEQUENCE + 10,
                "recoveryRequired": False,
            }
        )
        public_oracle = {
            "label": "rollback-terminal",
            "matrixPhase": "rollback",
            "receiptCount": transaction.ORACLE_PHASE_COUNTS["rollback"],
            "receiptsSha256": "6" * 64,
            "file": "oracle.rollback-terminal.reviewed.json",
            "fileSha256": "7" * 64,
        }
        journal_document["oracleEvidenceRecords"] = {
            "rollback-terminal": copy.deepcopy(public_oracle)
        }
        evidence = {
            "bindingGraph": {
                "rows": [],
                "sha256": transaction.sha256_bytes(
                    transaction.canonical_json([])
                ),
            },
            "authorizationEvidence": copy.deepcopy(public_oracle),
            "terminalTargetInventory": [
                {"id": operation_id, "present": False}
                for operation_id in order
            ],
        }
        journal_document["terminalEvidence"] = evidence
        journal_document["terminalEvidenceSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(evidence)
        )
        journal_document["receiptRecords"] = {
            "rolled-back": {
                "result": "rolled-back",
                "evidenceSha256": journal_document[
                    "terminalEvidenceSha256"
                ],
                "recordedAt": "2026-08-26T00:00:00Z",
                "journalSequence": journal_document["sequence"],
                "journalState": "rolled-back",
            }
        }
        journal = SimpleNamespace(document=journal_document)
        old.validate_terminal_evidence_document = (
            transaction.validate_terminal_evidence_document
        )
        old.read_plan = mock.Mock(
            return_value=(plan, transaction.RECOVERED_PLAN_SHA256)
        )
        old.acquire_lock = mock.Mock(return_value=37)
        old.Journal = type("OldJournal", (), {})
        old.JOURNAL_PATH = Path("/reviewed-v030/journal.json")
        old.parse_journal_payload = mock.Mock(
            return_value=journal.document
        )
        old.RECEIPT_ROOT = Path("/reviewed-v030/receipts")
        old.terminal_receipt_payload = transaction.terminal_receipt_payload
        old.read_regular = mock.Mock()
        return old, plan, journal

    @staticmethod
    def receipt_fixture():
        old, plan, journal = RecoveryPlanGateTests.terminal_fixture()
        custody = {
            "sourceRevision": "1" * 40,
            "manifestSha256": "2" * 64,
            "custodySha256": "3" * 64,
        }
        source = {"tag": transaction.AUTHORIZED_RELEASE_TAG, "tree": "4" * 40}
        terminal_document, terminal_payload = old.terminal_receipt_payload(
            journal, "rolled-back"
        )
        old.read_regular.side_effect = lambda path, **_kwargs: (
            b"reviewed terminal journal"
            if path == old.JOURNAL_PATH
            else terminal_payload
        )
        receipt = {
            "schema": transaction.RECOVERY_RECEIPT_SCHEMA,
            "result": "rolled-back",
            "recoveryRelease": transaction.AUTHORIZED_RELEASE_TAG,
            "recoverySourceRevision": custody["sourceRevision"],
            "recoveryManifestSha256": custody["manifestSha256"],
            "recoveryCustodySha256": custody["custodySha256"],
            "recoveryReleaseIdentitySha256": transaction.sha256_bytes(
                transaction.canonical_json(source)
            ),
            "recoveredRelease": transaction.RECOVERED_RELEASE_TAG,
            "recoveredSourceRevision": transaction.RECOVERED_SOURCE_REVISION,
            "recoveredPlanSha256": transaction.RECOVERED_PLAN_SHA256,
            "terminalJournalSha256": transaction.sha256_bytes(
                transaction.canonical_json(journal.document)
            ),
            "terminalEvidenceSha256": journal.document[
                "terminalEvidenceSha256"
            ],
            "acceptedMovementSha256": "8" * 64,
            "acceptedPodProofSha256": "9" * 64,
            "acceptedChartDigest": transaction.RECOVERED_TO_CHART_DIGEST,
            "acceptedImage": transaction.RECOVERED_TO_IMAGE,
            "recordedAt": terminal_document["recordedAt"],
        }
        return old, plan, journal, custody, source, receipt

    def validate(self, old, custody, source, receipt):
        with mock.patch.object(
            transaction,
            "validate_recovery_release_identity",
            return_value=source,
        ) as release, mock.patch.object(
            transaction,
            "load_recovered_transaction",
            return_value=(old, {"old": "custody"}),
        ) as recovered, mock.patch.object(
            transaction,
            "read_regular",
            return_value=transaction.canonical_json(receipt),
        ) as read, mock.patch.object(transaction.os, "close") as close:
            transaction.validate_recovery_receipt_for_plan(custody)
        return release, recovered, read, close

    def test_exact_receipt_and_terminal_old_state_authorize_planning(self):
        old, _plan, _journal, custody, source, receipt = self.receipt_fixture()
        release, recovered, read, close = self.validate(
            old, custody, source, receipt
        )
        release.assert_called_once_with(custody, require_main_tip=False)
        self.assertEqual(recovered.call_count, 2)
        read.assert_called_once_with(
            transaction.RECOVERY_RECEIPT_PATH, owner=0, mode=0o600
        )
        old.acquire_lock.assert_called_once_with()
        old.parse_journal_payload.assert_called_once_with(
            b"reviewed terminal journal"
        )
        old.read_regular.assert_has_calls(
            [
                mock.call(
                    old.JOURNAL_PATH,
                    owner=0,
                    mode=0o600,
                    durable=True,
                ),
                mock.call(
                    old.RECEIPT_ROOT
                    / f"rolled-back.{transaction.RECOVERED_PLAN_SHA256}.json",
                    owner=0,
                    mode=0o600,
                ),
            ]
        )
        close.assert_called_once_with(37)

    def test_absent_partial_and_substituted_recovery_receipts_fail_closed(self):
        old, _plan, _journal, custody, source, receipt = self.receipt_fixture()
        cases = {}
        partial = copy.deepcopy(receipt)
        partial.pop("terminalEvidenceSha256")
        cases["partial receipt"] = partial
        substituted_custody = copy.deepcopy(receipt)
        substituted_custody["recoveryCustodySha256"] = "a" * 64
        cases["substituted recovery custody"] = substituted_custody
        substituted_incident = copy.deepcopy(receipt)
        substituted_incident["recoveredPlanSha256"] = "b" * 64
        cases["substituted recovered plan"] = substituted_incident
        substituted_journal = copy.deepcopy(receipt)
        substituted_journal["terminalJournalSha256"] = "c" * 64
        cases["substituted journal binding"] = substituted_journal
        for label, candidate in cases.items():
            with self.subTest(label=label), self.assertRaises(
                transaction.RecoveryRequired
            ):
                self.validate(old, custody, source, candidate)

        with mock.patch.object(
            transaction,
            "validate_recovery_release_identity",
            return_value=source,
        ), mock.patch.object(
            transaction,
            "read_regular",
            side_effect=transaction.TransactionError("FILE_OPEN_FAILED"),
        ), self.assertRaises(transaction.RecoveryRequired):
            transaction.validate_recovery_receipt_for_plan(custody)

    def test_nonterminal_and_substituted_old_journals_fail_closed(self):
        old, plan, journal, custody, source, receipt = self.receipt_fixture()
        order = plan["operationOrder"]
        journal.document.update(
            {
                "state": "recovery-required",
                "phase": "namespaced",
                "recoveryRequired": True,
                "operations": {
                    operation_id: journal.document["operations"][operation_id]
                    for operation_id in order[:18]
                },
            }
        )
        with self.assertRaises(transaction.RecoveryRequired):
            self.validate(old, custody, source, receipt)

        old, _plan, journal, custody, source, receipt = self.receipt_fixture()
        journal.document["sequence"] += 1
        with self.assertRaises(transaction.RecoveryRequired):
            self.validate(old, custody, source, receipt)

    def test_copied_receipt_cannot_substitute_old_terminal_evidence(self):
        old, _plan, journal, custody, source, receipt = self.receipt_fixture()
        journal.document["terminalEvidence"]["authorizationEvidence"][
            "matrixPhase"
        ] = "final"
        journal.document["terminalEvidenceSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(journal.document["terminalEvidence"])
        )
        receipt["terminalEvidenceSha256"] = journal.document[
            "terminalEvidenceSha256"
        ]
        receipt["terminalJournalSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(journal.document)
        )
        with self.assertRaises(transaction.RecoveryRequired):
            self.validate(old, custody, source, receipt)

    def test_plan_gate_runs_before_target_or_client_loading(self):
        custody = {"sourceRevision": "1" * 40}
        with mock.patch.object(
            transaction,
            "validate_runtime_custody",
            return_value=(custody, {}),
        ), mock.patch.object(
            transaction, "ensure_state_root"
        ), mock.patch.object(
            transaction, "ensure_root_directory"
        ), mock.patch.object(
            transaction, "acquire_lock", return_value=19
        ), mock.patch.object(
            transaction,
            "validate_recovery_receipt_for_plan",
            side_effect=transaction.RecoveryRequired("injected"),
        ) as gate, mock.patch.object(
            transaction, "load_target"
        ) as load_target, mock.patch.object(
            transaction.os, "close"
        ) as close, self.assertRaises(transaction.RecoveryRequired):
            transaction.run_mode("--plan")
        gate.assert_called_once_with(custody)
        load_target.assert_not_called()
        close.assert_called_once_with(19)


class RecoveryWrapperTests(unittest.TestCase):
    @staticmethod
    def fixture():
        plan = {
            "baselines": {
                "flux": {
                    "oci": {transaction.RECOVERED_NARANJO_OCI: {"old": "oci"}},
                    "helm": {
                        transaction.RECOVERED_NARANJO_RELEASE: {"old": "helm"}
                    },
                },
                "workloads": {
                    transaction.RECOVERED_NARANJO_RELEASE: {"old": "workload"}
                },
            }
        }
        rows = {
            "oci": {"new": "oci"},
            "helm": {"new": "helm"},
            "workload": {
                "new": "workload",
                "pods": [{"uid": POD_UID}],
            },
        }
        original = mock.Mock(return_value={"bindingGraph": {}})
        old = SimpleNamespace(
            canonical_json=_canonical,
            sha256_bytes=_sha256,
            RecoveryRequired=transaction.RecoveryRequired,
            verify_rolled_back_state=original,
            write_receipt=mock.Mock(),
        )
        return old, plan, _valid_movement(rows), original

    def test_wrapper_substitutes_only_verification_rows_and_restores_function(self):
        old, plan, movement, original = self.fixture()
        client = object()
        before = copy.deepcopy(plan)

        def rollback(candidate_client, candidate_plan, _journal):
            old.verify_rolled_back_state(
                candidate_client, candidate_plan, object(), proof_started=False
            )

        old.rollback_internal = rollback
        plan_digest = _sha256(_canonical(plan))
        with mock.patch.object(transaction, "RECOVERED_PLAN_SHA256", plan_digest):
            transaction.run_recovered_rollback_once(
                old, client, plan, object(), movement
            )

        self.assertIs(old.verify_rolled_back_state, original)
        old.write_receipt.assert_not_called()
        self.assertEqual(plan, before)
        verified_plan = original.call_args.args[1]
        self.assertEqual(
            verified_plan["baselines"]["flux"]["oci"][
                transaction.RECOVERED_NARANJO_OCI
            ],
            movement["verificationRows"]["oci"],
        )

    def test_wrapper_restores_original_verifier_after_failure(self):
        old, plan, movement, original = self.fixture()
        old.rollback_internal = mock.Mock(side_effect=RuntimeError("injected"))
        with self.assertRaisesRegex(RuntimeError, "injected"):
            transaction.run_recovered_rollback_once(
                old, object(), plan, object(), movement
            )
        self.assertIs(old.verify_rolled_back_state, original)
        old.write_receipt.assert_not_called()


class RecoveryOrchestrationTests(unittest.TestCase):
    @staticmethod
    def fixture(state):
        journal = SimpleNamespace(document={"state": state})
        plan = {"source": "authenticated-v030-plan"}
        client = object()
        kube_context = mock.MagicMock()
        kube_context.__enter__.return_value = client
        kube_context.__exit__.return_value = False
        validator = SimpleNamespace(name="validator")
        oracle = SimpleNamespace(name="oracle")

        def loaded_module(path, _name):
            return validator if "kubeconfig" in str(path) else oracle

        old = SimpleNamespace(
            acquire_lock=mock.Mock(return_value=202),
            read_plan=mock.Mock(
                return_value=(plan, transaction.RECOVERED_PLAN_SHA256)
            ),
            Journal=SimpleNamespace(load=mock.Mock(return_value=journal)),
            write_receipt=mock.Mock(),
            load_target=mock.Mock(return_value={"target": "reviewed"}),
            parse_versions=mock.Mock(return_value={"kubectl": "reviewed"}),
            read_regular=mock.Mock(return_value=b"reviewed versions"),
            custody_path=lambda relative: Path("/reviewed-custody") / relative,
            VERSIONS_REL="versions.env",
            KUBECONFIG_VALIDATOR_REL="scripts/validate_kubeconfig_snapshot.py",
            ORACLE_REL="scripts/flux_rbac_denial_oracle.py",
            load_module=mock.Mock(side_effect=loaded_module),
            KubeClient=mock.Mock(return_value=kube_context),
            validate_plan_bindings=mock.Mock(),
        )

        def terminalize(_old, _client, _plan, candidate, _movement):
            candidate.document["state"] = "rolled-back"

        rollback = mock.Mock(side_effect=terminalize)
        return old, journal, rollback

    @contextlib.contextmanager
    def patched_recovery(self, old, rollback):
        custody = {"sourceRevision": "6" * 40}
        acknowledgement = (
            f"recover-v030-{transaction.RECOVERED_PLAN_SHA256}-with-"
            f"{custody['sourceRevision']}"
        )
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.dict(
                    transaction.os.environ,
                    {"CONFIRM_FLUX_RBAC_RECOVERY": acknowledgement},
                    clear=True,
                )
            )
            stack.enter_context(mock.patch.object(transaction, "ensure_state_root"))
            stack.enter_context(
                mock.patch.object(transaction, "acquire_lock", return_value=101)
            )
            release = stack.enter_context(
                mock.patch.object(
                    transaction,
                    "validate_recovery_release_identity",
                    return_value={"identity": "reviewed"},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    transaction,
                    "load_recovered_transaction",
                    return_value=(old, {"custody": "reviewed"}),
                )
            )
            stack.enter_context(
                mock.patch.object(transaction, "validate_recovered_incident")
            )
            accepted = stack.enter_context(
                mock.patch.object(
                    transaction,
                    "accepted_naranjo_movement",
                    return_value=_valid_movement(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    transaction, "run_recovered_rollback_once", new=rollback
                )
            )
            publish = stack.enter_context(
                mock.patch.object(transaction, "publish_recovery_receipt")
            )
            close = stack.enter_context(mock.patch.object(transaction.os, "close"))
            yield custody, close, publish, accepted, release

    def test_only_terminal_v038_recovery_is_idempotent(self):
        old, journal, rollback = self.fixture("rolled-back")
        previous = sys.modules.get("validate_kubeconfig_snapshot")
        sentinel = SimpleNamespace(name="previous-validator")
        sys.modules["validate_kubeconfig_snapshot"] = sentinel
        try:
            with self.patched_recovery(old, rollback) as (
                custody,
                close,
                publish,
                accepted,
                release,
            ):
                transaction.recover_v030(custody)
                release.assert_called_once_with(
                    custody, require_main_tip=False
                )
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(journal.document["state"], "rolled-back")
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["rolled-back"],
                )
                rollback.assert_not_called()
                publish.assert_called_once()
                self.assertEqual(accepted.call_count, 2)

                old.write_receipt.reset_mock()
                rollback.reset_mock()
                publish.reset_mock()
                transaction.recover_v030(custody)
                self.assertEqual(
                    release.call_args_list,
                    [
                        mock.call(custody, require_main_tip=False),
                        mock.call(custody, require_main_tip=False),
                    ],
                )
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["rolled-back"],
                )
                rollback.assert_not_called()
                publish.assert_called_once()
                self.assertEqual(accepted.call_count, 4)
                self.assertTrue(
                    all(
                        call.kwargs.get("expected_history_steps")
                        == transaction.RECOVERED_TERMINAL_HISTORY_STEP_COUNT
                        for call in accepted.call_args_list
                    )
                )
                self.assertEqual(
                    sorted(call.args[0] for call in close.call_args_list),
                    [101, 101, 202, 202],
                )
        finally:
            if previous is None:
                sys.modules.pop("validate_kubeconfig_snapshot", None)
            else:
                sys.modules["validate_kubeconfig_snapshot"] = previous

    def test_nonterminal_v038_state_fails_before_cluster_access(self):
        old, _journal, rollback = self.fixture("recovery-required")
        with self.patched_recovery(old, rollback) as (
            custody,
            _close,
            publish,
            accepted,
            release,
        ):
            with self.assertRaisesRegex(
                transaction.RecoveryRequired, "RECOVERY_V038_TERMINAL_REQUIRED"
            ):
                transaction.recover_v030(custody)
            release.assert_called_once_with(custody, require_main_tip=False)
        accepted.assert_not_called()
        rollback.assert_not_called()
        publish.assert_not_called()
        old.KubeClient.assert_not_called()
        old.write_receipt.assert_not_called()

    def test_terminal_receipt_failure_restores_validator_and_locks(self):
        old, _journal, rollback = self.fixture("rolled-back")
        previous = sys.modules.get("validate_kubeconfig_snapshot")
        sentinel = SimpleNamespace(name="previous-validator")
        sys.modules["validate_kubeconfig_snapshot"] = sentinel
        try:
            with self.patched_recovery(old, rollback) as (
                custody,
                close,
                publish,
                _accepted,
                release,
            ):
                publish.side_effect = transaction.TransactionError(
                    "injected receipt collision"
                )
                with self.assertRaisesRegex(
                    transaction.TransactionError, "injected receipt collision"
                ):
                    transaction.recover_v030(custody)
                release.assert_called_once_with(
                    custody, require_main_tip=False
                )
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["rolled-back"],
                )
                self.assertEqual(
                    sorted(call.args[0] for call in close.call_args_list),
                    [101, 202],
                )
        finally:
            if previous is None:
                sys.modules.pop("validate_kubeconfig_snapshot", None)
            else:
                sys.modules["validate_kubeconfig_snapshot"] = previous

    def test_runtime_proof_change_between_terminal_reads_fails_before_receipt(self):
        old, _journal, rollback = self.fixture("rolled-back")
        initial = _valid_movement()
        changed = copy.deepcopy(initial)
        changed["podProof"]["pods"][0]["podSpecSha256"] = "c" * 64
        with self.patched_recovery(old, rollback) as (
            custody,
            _close,
            publish,
            accepted,
            release,
        ):
            accepted.side_effect = [initial, changed]
            with self.assertRaisesRegex(
                transaction.RecoveryRequired,
                "RECOVERY_TERMINAL_MOVEMENT_CHANGED",
            ):
                transaction.recover_v030(custody)
            release.assert_called_once_with(
                custody, require_main_tip=False
            )
        publish.assert_not_called()
        rollback.assert_not_called()
        old.write_receipt.assert_not_called()

    def test_resource_version_change_between_valid_terminal_reads_is_accepted(self):
        old, _journal, rollback = self.fixture("rolled-back")
        initial = _valid_movement()
        changed = copy.deepcopy(initial)
        changed["verificationRows"]["oci"]["resourceVersion"] = "999"
        changed["verificationRows"]["helm"]["resourceVersion"] = "1000"
        with self.patched_recovery(old, rollback) as (
            custody,
            _close,
            publish,
            accepted,
            release,
        ):
            accepted.side_effect = [initial, changed]
            transaction.recover_v030(custody)
            release.assert_called_once_with(custody, require_main_tip=False)
        publish.assert_called_once()
        rollback.assert_not_called()
        old.write_receipt.assert_called_once()


class RecoveryDispatchTests(unittest.TestCase):
    def test_parser_and_main_dispatch_only_the_recovery_mode(self):
        self.assertEqual(
            transaction.parser().parse_args(["--", "--recover-v030"]).mode,
            "--recover-v030",
        )
        with mock.patch.object(
            transaction, "validate_process_boundary"
        ) as boundary, mock.patch.object(transaction, "run_recovery_mode") as run:
            self.assertEqual(transaction.main(["--recover-v030"]), 0)
        boundary.assert_called_once_with("--recover-v030")
        run.assert_called_once_with()

    def test_custodied_dispatch_requires_exact_schema_and_mode(self):
        custody = {"sourceRevision": "6" * 40}
        runner = mock.Mock()
        recovery = SimpleNamespace(
            SCHEMA="flux-rbac-v030-recovery-dispatch-v1", run=runner
        )
        with mock.patch.object(
            transaction, "validate_runtime_custody", return_value=(custody, {})
        ), mock.patch.object(
            transaction, "load_module", return_value=recovery
        ) as load, mock.patch("builtins.print"):
            transaction.run_recovery_mode()
        self.assertEqual(load.call_args.kwargs["mode"], 0o600)
        runner.assert_called_once_with(transaction, custody)

        recovery.SCHEMA = "wrong"
        with mock.patch.object(
            transaction, "validate_runtime_custody", return_value=(custody, {})
        ), mock.patch.object(transaction, "load_module", return_value=recovery):
            with self.assertRaisesRegex(
                transaction.TransactionError, "RECOVERY_DISPATCH_IDENTITY_INVALID"
            ):
                transaction.run_recovery_mode()


if __name__ == "__main__":
    unittest.main()
