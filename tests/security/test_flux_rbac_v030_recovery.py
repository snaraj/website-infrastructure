"""Focused hostile tests for the one-incident v0.1.30 recovery path.

The suite is hermetic: it uses synthetic journal and snapshot metadata and
never opens a kubeconfig, network connection, or privileged host path.
"""

from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
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


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


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
        "semanticSha256": marker * 64,
    }


def _helm(version, marker, revision):
    chart_digest = (
        transaction.RECOVERED_TO_CHART_DIGEST
        if version == transaction.RECOVERED_TO_VERSION
        else f"sha256:{marker * 64}"
    )
    return {
        "uid": "helm-uid",
        "resourceVersion": marker,
        "generation": 7,
        "observedGeneration": 7,
        "lastAttemptedGeneration": 7,
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
        "semanticSha256": marker * 64,
    }


def _owned_objects(marker):
    static = [
        {"kind": kind, "name": kind.lower(), "semanticSha256": "c" * 64}
        for kind in ("Service", "ServiceAccount", "NetworkPolicy")
    ]
    return static + [
        {
            "kind": "Deployment",
            "name": "naranjo-online",
            "apiVersion": "apps/v1",
            "uid": "deployment-uid",
            "semanticSha256": marker * 64,
            "proofAnnotation": None,
            "semanticWithoutProofSha256": marker * 64,
        }
    ]


def _workload(marker, generation):
    return {
        "uid": "deployment-uid",
        "generation": generation,
        "replicas": 1,
        "templateSha256": marker * 64,
        "semanticSha256": marker * 64,
        "proofAnnotation": None,
        "semanticWithoutProofSha256": marker * 64,
        "pods": [
            {
                "uid": f"pod-{marker}",
                "restartCounts": [0],
                "images": [
                    transaction.RECOVERED_TO_IMAGE
                    if marker == "2"
                    else "old-reviewed-image"
                ],
            }
        ],
        "ownedObjects": _owned_objects(marker),
    }


def _raw_deployment():
    labels = {
        "app.kubernetes.io/name": "naranjo-online",
        "app.kubernetes.io/instance": "naranjo-online",
        "app.kubernetes.io/managed-by": "Helm",
        "app.kubernetes.io/version": transaction.RECOVERED_TO_VERSION,
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
            "labels": copy.deepcopy(labels),
            "annotations": {
                "platform.snaraj.dev/deployment-ready": "true",
                "platform.snaraj.dev/media-storage-ready": "false",
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
                    "labels": copy.deepcopy(labels),
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


def _movement_fixture():
    key_oci = transaction.RECOVERED_NARANJO_OCI
    key_release = transaction.RECOVERED_NARANJO_RELEASE
    planned_flux = {
        "oci": {key_oci: _oci(transaction.RECOVERED_FROM_VERSION, "1")},
        "helm": {key_release: _helm(transaction.RECOVERED_FROM_VERSION, "1", 8)},
    }
    current_flux = {
        "oci": {key_oci: _oci(transaction.RECOVERED_TO_VERSION, "2")},
        "helm": {key_release: _helm(transaction.RECOVERED_TO_VERSION, "2", 9)},
    }
    planned_workloads = {key_release: _workload("1", 11)}
    current_workloads = {key_release: _workload("2", 12)}
    controllers = {"source-controller": {"podRestarts": 0}}
    public_sites = {"naranjo.online": {"status": 200}}
    deployment = _raw_deployment()
    plan = {
        "baselines": {
            "flux": planned_flux,
            "workloads": planned_workloads,
            "controllers": copy.deepcopy(controllers),
            "publicSites": copy.deepcopy(public_sites),
        }
    }

    def without_resource_versions(snapshot):
        normalized = copy.deepcopy(snapshot)
        for section in ("oci", "helm"):
            for row in normalized.get(section, {}).values():
                row.pop("resourceVersion", None)
        return normalized

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
        collection_items=lambda _client, _url: [copy.deepcopy(deployment)],
        typed_site_inventory_item=lambda value, _kind: value,
    )
    return (
        old,
        plan,
        current_flux,
        current_workloads,
        controllers,
        public_sites,
        deployment,
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
    def test_exact_naranjo_release_movement_is_accepted(self):
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

        def foreign_image(
            _plan, _flux, _workloads, _controllers, _sites, deployment
        ):
            deployment["spec"]["template"]["spec"]["containers"][0][
                "image"
            ] = "ghcr.io/example/foreign@sha256:" + "f" * 64

        def template_drift(
            _plan, _flux, _workloads, _controllers, _sites, deployment
        ):
            deployment["spec"]["template"]["metadata"]["labels"][
                "app.kubernetes.io/version"
            ] = "0.1.44"

        def environment_drift(
            _plan, _flux, _workloads, _controllers, _sites, deployment
        ):
            deployment["spec"]["template"]["spec"]["containers"][0]["env"][2][
                "value"
            ] = "true"

        def security_drift(
            _plan, _flux, _workloads, _controllers, _sites, deployment
        ):
            deployment["spec"]["template"]["spec"]["containers"][0][
                "securityContext"
            ]["allowPrivilegeEscalation"] = True

        def shared_process_namespace(
            _plan, _flux, _workloads, _controllers, _sites, deployment
        ):
            deployment["spec"]["template"]["spec"][
                "shareProcessNamespace"
            ] = True

        def adapt(mutate):
            return lambda plan, flux, workloads, controllers, sites, _deployment: mutate(
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
            "foreign workload image": foreign_image,
            "raw template drift": template_drift,
            "environment activation": environment_drift,
            "security-context weakening": security_drift,
            "shared process namespace": shared_process_namespace,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                old, plan, flux, workloads, controllers, sites, deployment = (
                    _movement_fixture()
                )
                mutate(plan, flux, workloads, controllers, sites, deployment)
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.accepted_naranjo_movement(old, object(), plan)


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
            "workload": {"new": "workload"},
        }
        original = mock.Mock(return_value={"bindingGraph": {}})
        old = SimpleNamespace(
            canonical_json=_canonical,
            sha256_bytes=_sha256,
            RecoveryRequired=transaction.RecoveryRequired,
            verify_rolled_back_state=original,
            write_receipt=mock.Mock(),
        )
        return old, plan, {"verificationRows": rows}, original

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
            stack.enter_context(
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
            stack.enter_context(
                mock.patch.object(
                    transaction,
                    "accepted_naranjo_movement",
                    return_value={
                        "verificationRows": {
                            "oci": {},
                            "helm": {},
                            "workload": {},
                        }
                    },
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
            yield custody, close, publish

    def test_first_recovery_and_terminal_rerun_are_idempotent(self):
        old, journal, rollback = self.fixture("recovery-required")
        previous = sys.modules.get("validate_kubeconfig_snapshot")
        sentinel = SimpleNamespace(name="previous-validator")
        sys.modules["validate_kubeconfig_snapshot"] = sentinel
        try:
            with self.patched_recovery(old, rollback) as (custody, close, publish):
                transaction.recover_v030(custody)
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(journal.document["state"], "rolled-back")
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["recovery-required", "rolled-back"],
                )
                rollback.assert_called_once()
                publish.assert_called_once()

                old.write_receipt.reset_mock()
                rollback.reset_mock()
                publish.reset_mock()
                transaction.recover_v030(custody)
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["rolled-back"],
                )
                rollback.assert_not_called()
                publish.assert_called_once()
                self.assertEqual(
                    sorted(call.args[0] for call in close.call_args_list),
                    [101, 101, 202, 202],
                )
        finally:
            if previous is None:
                sys.modules.pop("validate_kubeconfig_snapshot", None)
            else:
                sys.modules["validate_kubeconfig_snapshot"] = previous

    def test_terminal_receipt_failure_restores_validator_and_locks(self):
        old, _journal, rollback = self.fixture("recovery-required")
        previous = sys.modules.get("validate_kubeconfig_snapshot")
        sentinel = SimpleNamespace(name="previous-validator")
        sys.modules["validate_kubeconfig_snapshot"] = sentinel
        try:
            with self.patched_recovery(old, rollback) as (custody, close, publish):
                publish.side_effect = transaction.TransactionError(
                    "injected receipt collision"
                )
                with self.assertRaisesRegex(
                    transaction.TransactionError, "injected receipt collision"
                ):
                    transaction.recover_v030(custody)
                self.assertIs(
                    sys.modules["validate_kubeconfig_snapshot"], sentinel
                )
                self.assertEqual(
                    [call.args[0] for call in old.write_receipt.call_args_list],
                    ["recovery-required", "rolled-back"],
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
