"""Hostile tests for the small owner-attended #189 bootstrap boundary."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "bootstrap/flux/release-selector/bootstrap.sh"
VALIDATOR = ROOT / "scripts/validate_platform_bootstrap.py"
PREDECESSOR = ROOT / "scripts/ci/validate_platform_predecessor.py"
DIGEST = "sha256:" + "1" * 64
CIDRS = ["192.168.50.10/32"]
TARGET_SHA = "2" * 40
TARGET_TAG = "v0.1.41"


def load_validator():
    spec = importlib.util.spec_from_file_location("platform_bootstrap", VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_predecessor():
    spec = importlib.util.spec_from_file_location("platform_predecessor_test", PREDECESSOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PlatformBootstrapContractTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.module = load_validator()
        cls.predecessor = load_predecessor()

    def assert_denied(self, callback, *args):
        with self.assertRaises(SystemExit):
            callback(*args)

    def test_orchestrator_is_small_explicit_monotonic_and_containing(self):
        text = SCRIPT.read_text(encoding="utf-8")
        executable = [
            line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        # Keep this owner-attended orchestrator reviewable without forcing
        # security-relevant containment into opaque helpers merely to satisfy
        # an arbitrary historical line count.
        self.assertLessEqual(len(executable), 180)
        self.assertTrue(SCRIPT.stat().st_mode & stat.S_IXUSR)
        self.assertIn("--kubeconfig \"$kubeconfig\" --context \"$context\" --server \"$server\"", text)
        self.assertIn("Type $tag to create/resume the suspended bootstrap boundary", text)
        self.assertIn("trap on_failure ERR INT TERM HUP", text)
        self.assertIn("contain || echo 'RECOVERY_REQUIRED", text)
        self.assertIn(
            "quarantine_helm_bindings || echo 'RECOVERY_REQUIRED", text
        )
        self.assertIn("quarantine_authority || echo 'RECOVERY_REQUIRED", text)
        self.assertNotIn("admission_ready || quarantine_authority", text)
        self.assertNotIn("v0.1.39", text)
        self.assertNotIn("predecessor-identity", text)
        self.assertNotIn("validate_platform_predecessor.py", text)
        self.assertIn(
            'public_asset "$work/release.json" "$asset" "$work/$asset" 2',
            text,
        )
        self.assertIn(
            'public_asset "$work/release.json" "$bundle" "$work/$bundle" 2',
            text,
        )
        self.assertIn('(.assets|length==$count)', text)
        self.assertIn('(([.assets[].name]|sort)==($expected|sort))', text)
        self.assertIn("cosign verify-blob --bundle", text)
        self.assertIn('--trusted-root "$trusted_root"', text)
        self.assertIn(
            'trusted_root="${root}/cmd/platform-release-selector/trusted_root.json"',
            text,
        )
        self.assertIn('--bundle "$work/$bundle" --release-json "$work/release.json"', text)
        self.assertIn("cosign verify-attestation --trusted-root", text)
        self.assertIn("--type slsaprovenance1", text)
        self.assertIn("--ignore-not-found", text)
        self.assertIn(" create -f ", text)
        self.assertIn(" replace -f ", text)
        for forbidden in (
            "kubectl apply", "kubectl patch", "kubectl delete",
            " apply -f ", " patch -f ", " delete ",
            "GH_TOKEN", "GITHUB_TOKEN", "secretKeyRef", "create token",
        ):
            self.assertNotIn(forbidden, text)
        validator = VALIDATOR.read_text(encoding="utf-8")
        self.assertIn('"status", "--porcelain=v1"', validator)
        self.assertIn('"cat-file", "-t", tag_ref', validator)
        self.assertIn('tag_ref + "^{commit}"', validator)
        first_contain = text.index("quarantine_authority\ncontain")
        cronjob_create = text.index(
            "ensure selector-cronjob cronjob.batch platform-release-selector"
        )
        quiescence = text.index("wait_quiescent", first_contain)
        admission_policy = text.index(
            "ensure selector-admission-policy validatingadmissionpolicy.admissionregistration.k8s.io"
        )
        admission_binding = text.index(
            "ensure selector-admission-binding validatingadmissionpolicybinding.admissionregistration.k8s.io"
        )
        selector_serviceaccount = text.index("ensure selector-serviceaccount serviceaccount")
        self.assertLess(first_contain, admission_policy)
        self.assertLess(first_contain, cronjob_create)
        self.assertLess(cronjob_create, quiescence)
        self.assertLess(quiescence, admission_policy)
        self.assertLess(admission_policy, admission_binding)
        self.assertLess(admission_binding, selector_serviceaccount)
        resume = text.rsplit("\ncontain\n", 1)[1]
        target_ready = (
            'wait_ready source gitrepository.source.toolkit.fluxcd.io '
            'flux-system "$tag" "$sha" target'
        )
        first_site_resume = (
            "activate_site naranjo-online naranjo-kustomization "
            "naranjo-online-reconciler"
        )
        selector_contained = (
            "replace_suspend selector-cronjob cronjob.batch "
            "platform-release-selector true"
        )
        self.assertEqual(resume.count(target_ready), 1)
        self.assertLess(resume.index(target_ready), resume.index(selector_contained))
        self.assertLess(resume.index(selector_contained), resume.index(first_site_resume))
        self.assertLess(
            resume.index(first_site_resume),
            resume.index("activate_site lidersea-com lidersea-kustomization "),
        )
        self.assertLess(
            resume.index("activate_site lidersea-com lidersea-kustomization "),
            resume.rindex(
                "replace_suspend selector-cronjob cronjob.batch "
                "platform-release-selector false"
            ),
        )
        first_consumer_proof = text.index(
            "capture_consumers contained before-source"
        )
        second_consumer_proof = text.index(
            "capture_consumers contained source-commit"
        )
        source_commit = text.index('source_live="$work/source.live.json"')
        self.assertLess(first_consumer_proof, text.index("migrate_oci naranjo-online"))
        self.assertLess(text.index("migrate_oci lidersea-com"), second_consumer_proof)
        self.assertLess(second_consumer_proof, source_commit)
        activation = text[text.index("activate_site() {"):text.index("exact_existing() {")]
        for before, after in (
            ('prove_helm_revoked "$site"', 'prove_parent_activation_chain_exact "$site"'),
            ('prove_parent_activation_chain_exact "$site"', 'replace_suspend "$component"'),
            ('replace_suspend "$component"', 'wait_site_applied "$site"'),
            ('wait_site_applied "$site"', 'check_site_chain "$site"'),
            ('transition_helm_binding "$site" false', 'wait_ready "$component"'),
        ):
            with self.subTest(site_activation_order=(before, after)):
                self.assertLess(activation.index(before), activation.index(after))
        self.assertEqual(activation.count('prove_parent_activation_chain_exact "$site"'), 2)
        self.assertLess(
            activation.index('check_site_chain "$site"'),
            activation.rindex('prove_parent_activation_chain_exact "$site"'),
        )
        self.assertLess(
            activation.rindex('prove_parent_activation_chain_exact "$site"'),
            activation.rindex('prove_helm_revoked "$site"'),
        )
        self.assertLess(
            activation.rindex('prove_helm_revoked "$site"'),
            activation.index('transition_helm_binding "$site" false'),
        )
        final_cron = text.rindex(
            "replace_suspend selector-cronjob cronjob.batch "
            "platform-release-selector false"
        )
        final_proof = text.rindex("\nhealthy_no_write\n")
        final_success = text.rindex("\nsuccess\n")
        self.assertLess(final_cron, final_proof)
        self.assertLess(final_proof, final_success)

    def test_rendered_inventory_is_exact_suspended_and_calico_post_dnat(self):
        module = self.module
        self.assertEqual(len(module.INVENTORY), 20)
        self.assertEqual(
            {component for component, _, _ in module.INVENTORY},
            {
                "selector-serviceaccount", "selector-admission-policy",
                "selector-admission-binding", "selector-role",
                "selector-rolebinding", "parent-impersonation-role",
                "parent-impersonation-rolebinding", "naranjo-site-serviceaccount",
                "naranjo-site-role", "naranjo-site-rolebinding",
                "lidersea-site-serviceaccount", "lidersea-site-role",
                "lidersea-site-rolebinding", "selector-network-dns",
                "selector-network-public", "selector-network-api",
                "selector-cronjob", "source", "naranjo-kustomization",
                "lidersea-kustomization",
            },
        )
        role = module.desired("selector-role", DIGEST, CIDRS)
        self.assertEqual(role["rules"], [
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
        ])
        self.assertEqual(
            module.desired("parent-impersonation-role", DIGEST, CIDRS)["rules"],
            [{
                "apiGroups": [""],
                "resourceNames": [
                    "naranjo-online-reconciler", "lidersea-com-reconciler",
                ],
                "resources": ["serviceaccounts"],
                "verbs": ["impersonate"],
            }],
        )
        self.assertEqual(
            module.desired("parent-impersonation-rolebinding", DIGEST, CIDRS)["subjects"],
            [{
                "kind": "ServiceAccount",
                "name": "kustomize-controller",
                "namespace": "flux-system",
            }],
        )
        policy = module.desired("selector-admission-policy", DIGEST, CIDRS)
        binding = module.desired("selector-admission-binding", DIGEST, CIDRS)
        self.assertEqual(policy["apiVersion"], "admissionregistration.k8s.io/v1")
        self.assertEqual(policy["kind"], "ValidatingAdmissionPolicy")
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        self.assertEqual(
            policy["spec"]["matchConditions"],
            [{
                "name": "selector-service-account",
                "expression": (
                    "request.userInfo.username == "
                    "'system:serviceaccount:flux-system:platform-release-selector'"
                ),
            }],
        )
        rule = {
            "apiGroups": ["source.toolkit.fluxcd.io"],
            "apiVersions": ["v1"],
            "operations": ["UPDATE"],
            "resources": ["gitrepositories"],
            "scope": "Namespaced",
        }
        self.assertEqual(
            policy["spec"]["matchConstraints"],
            {"matchPolicy": "Exact", "resourceRules": [rule]},
        )
        self.assertEqual(binding["apiVersion"], "admissionregistration.k8s.io/v1")
        self.assertEqual(binding["kind"], "ValidatingAdmissionPolicyBinding")
        self.assertEqual(binding["spec"], {
            "matchResources": {"matchPolicy": "Exact", "resourceRules": [rule]},
            "policyName": "platform-release-selector",
            "validationActions": ["Deny"],
        })
        expressions = "\n".join(
            validation["expression"] for validation in policy["spec"]["validations"]
        )
        for required in (
            "oldObject != null", "request.namespace == 'flux-system'",
            "object.metadata.uid == oldObject.metadata.uid",
            "object.metadata.generation == oldObject.metadata.generation + 1",
            "object.status == oldObject.status",
            "!has(object.spec.ref.branch)", "!has(object.spec.ref.commit)",
            "!has(object.spec.ref.name)", "!has(object.spec.ref.semver)",
            "!has(object.spec.secretRef)", "!has(object.spec.verify)",
            "!has(object.spec.serviceAccountName)",
            "object.spec.url == oldObject.spec.url",
            "object.spec.ignore == oldObject.spec.ignore",
            "object.spec.sparseCheckout == oldObject.spec.sparseCheckout",
            "int(object.spec.ref.tag.split('.')[2]) == int(oldObject.spec.ref.tag.split('.')[2]) + 1",
            "object.metadata.finalizers == oldObject.metadata.finalizers",
            "oldObject.metadata.annotations.filter",
            "object.metadata.annotations.all",
            "release-selector.platform.snaraj.dev/identity-sha256",
        ):
            self.assertIn(required, expressions)
        # GitRepository is a typed CRD in CEL. Struct size() is invalid and
        # server-managed fields legitimately change while admitting a spec
        # update, so neither may be used as a selector boundary.
        self.assertNotIn(".spec.size()", expressions)
        self.assertNotIn(".spec.ref.size()", expressions)
        self.assertNotIn("object.metadata.managedFields", expressions)
        api_policy = module.desired("selector-network-api", DIGEST, CIDRS)
        self.assertEqual(
            api_policy["spec"]["egress"],
            [{
                "ports": [{"port": 6443, "protocol": "TCP"}],
                "to": [{"ipBlock": {"cidr": CIDRS[0]}}],
            }],
        )
        cron = module.desired(
            "selector-cronjob", DIGEST, CIDRS, build_sha=TARGET_SHA
        )
        self.assertIs(cron["spec"]["suspend"], True)
        container = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(
            container["image"],
            "ghcr.io/snaraj/website-infrastructure/platform-release-selector@" + DIGEST,
        )
        self.assertEqual(container["env"], [
            {"name": "EXPECTED_SELECTOR_BUILD_SHA", "value": TARGET_SHA},
            {"name": "EXPECTED_SELECTOR_IMAGE_DIGEST", "value": DIGEST},
        ])
        self.assertEqual(container["volumeMounts"], [{
            "mountPath": "/var/run/release-selector",
            "name": "sigstore-scratch",
        }])
        pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        self.assertEqual(pod["volumes"], [{
            "emptyDir": {"medium": "Memory", "sizeLimit": "2Mi"},
            "name": "sigstore-scratch",
        }])
        self.assertEqual(container["resources"], {
            "limits": {"cpu": "100m", "memory": "64Mi"},
            "requests": {"cpu": "5m", "memory": "16Mi"},
        })
        self.assertEqual(container["securityContext"], {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
        })
        hostile_cronjobs = {}
        for name in ("missing-volume", "missing-mount", "foreign-path", "disk-backed", "widened-size"):
            hostile_cronjobs[name] = copy.deepcopy(cron)
        hostile_cronjobs["missing-volume"]["spec"]["jobTemplate"]["spec"]["template"]["spec"].pop("volumes")
        hostile_cronjobs["missing-mount"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0].pop("volumeMounts")
        hostile_cronjobs["foreign-path"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] = "/tmp"
        hostile_cronjobs["disk-backed"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["volumes"][0]["emptyDir"]["medium"] = ""
        hostile_cronjobs["widened-size"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["volumes"][0]["emptyDir"]["sizeLimit"] = "3Mi"
        for name, hostile in hostile_cronjobs.items():
            with self.subTest(sigstore_scratch=name):
                self.assert_denied(
                    module.check, "selector-cronjob", hostile, cron, "true"
                )
        for component, site in (
            ("naranjo-kustomization", "naranjo-online"),
            ("lidersea-kustomization", "lidersea-com"),
        ):
            value = module.desired(component, DIGEST, CIDRS)
            self.assertEqual(value["spec"]["path"], "./kubernetes/websites/" + site)
            self.assertEqual(value["spec"]["serviceAccountName"], site + "-reconciler")
            self.assertEqual(value["spec"]["sourceRef"], {"kind": "GitRepository", "name": "flux-system"})
            self.assertIs(value["spec"]["prune"], False)
            self.assertIs(value["spec"]["force"], False)
            self.assertEqual(value["spec"]["deletionPolicy"], "Orphan")
            self.assertIs(value["spec"]["suspend"], True)
            self.assertNotIn("dependsOn", value["spec"])

    def test_admission_inventory_is_required_before_selector_rbac(self):
        text = SCRIPT.read_text(encoding="utf-8")
        policy = (
            "ensure selector-admission-policy "
            "validatingadmissionpolicy.admissionregistration.k8s.io "
            "platform-release-selector"
        )
        binding = (
            "ensure selector-admission-binding "
            "validatingadmissionpolicybinding.admissionregistration.k8s.io "
            "platform-release-selector"
        )
        rolebinding = (
            "ensure selector-rolebinding rolebinding.rbac.authorization.k8s.io "
            "platform-release-selector"
        )
        self.assertEqual(text.count(policy), 1)
        self.assertEqual(text.count(binding), 1)
        containment = "quarantine_authority\ncontain"
        self.assertEqual(text.count(containment), 1)
        self.assertLess(text.index(containment), text.index(policy))
        restore = text.rindex("restore_authority")
        self.assertLess(text.index(policy), restore)
        self.assertLess(text.index(binding), restore)
        self.assertIn(rolebinding, text[:text.index("replace_suspend()")])
        for component in ("selector-admission-policy", "selector-admission-binding"):
            expected = self.module.desired(component, DIGEST, CIDRS)
            self.assert_denied(self.module.check, component, {}, expected, "any")

    def test_initial_consumer_recovery_accepts_exact_suspended_singletons_only(self):
        module = self.module
        api_shapes = {
            "kustomizations": (
                "kustomize.toolkit.fluxcd.io/v1", "KustomizationList"
            ),
            "helmcharts": ("source.toolkit.fluxcd.io/v1", "HelmChartList"),
            "helmreleases": ("helm.toolkit.fluxcd.io/v2", "HelmReleaseList"),
            "externalartifacts": (
                "source.toolkit.fluxcd.io/v1", "ExternalArtifactList"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def arguments(parent):
                paths = {}
                for key, (api_version, kind) in api_shapes.items():
                    path = root / f"{key}.json"
                    path.write_text(
                        json.dumps({
                            "apiVersion": api_version,
                            "kind": kind,
                            "items": [parent] if key == "kustomizations" else [],
                            "metadata": {},
                        }),
                        encoding="utf-8",
                    )
                    paths[key + "_live"] = path
                return SimpleNamespace(
                    **paths,
                    phase="initial",
                    selector_digest=DIGEST,
                    api_cidr=CIDRS,
                    target_annotations=None,
                    selector_build_sha=TARGET_SHA,
                )

            for component in (
                "naranjo-kustomization", "lidersea-kustomization"
            ):
                parent = module.desired(component, DIGEST, CIDRS)
                with self.subTest(exact_singleton=component):
                    module.validate_consumer_files(arguments(parent))
                active = copy.deepcopy(parent)
                active["spec"]["suspend"] = False
                with self.subTest(active_singleton=component):
                    self.assert_denied(
                        module.validate_consumer_files, arguments(active)
                    )

            foreign = module.desired("naranjo-kustomization", DIGEST, CIDRS)
            foreign["metadata"]["name"] = "foreign"
            with self.subTest(foreign_singleton=True):
                self.assert_denied(
                    module.validate_consumer_files, arguments(foreign)
                )

    def test_late_admission_drift_cannot_restore_selector_authority(self):
        text = SCRIPT.read_text(encoding="utf-8")
        start = text.index("restore_authority() {")
        end = text.index("\n}\n", start)
        restore = text[start:end]
        policy = (
            "exact_existing selector-admission-policy "
            "validatingadmissionpolicy.admissionregistration.k8s.io "
            "platform-release-selector"
        )
        binding = (
            "exact_existing selector-admission-binding "
            "validatingadmissionpolicybinding.admissionregistration.k8s.io "
            "platform-release-selector"
        )
        rolebinding_get = (
            "get_live rolebinding.rbac.authorization.k8s.io "
            "platform-release-selector"
        )
        dependencies = (
            policy,
            binding,
            "exact_existing selector-serviceaccount serviceaccount "
            "platform-release-selector",
            "exact_existing selector-role role.rbac.authorization.k8s.io "
            "platform-release-selector",
            "exact_existing selector-network-dns "
            "networkpolicy.networking.k8s.io platform-release-selector-dns",
            "exact_existing selector-network-public "
            "networkpolicy.networking.k8s.io platform-release-selector-public-https",
            "exact_existing selector-network-api "
            "networkpolicy.networking.k8s.io platform-release-selector-kube-apiserver",
            "exact_existing selector-cronjob cronjob.batch "
            "platform-release-selector flux-system true",
            "exact_existing parent-impersonation-role "
            "role.rbac.authorization.k8s.io flux-controller-impersonation",
            "exact_existing parent-impersonation-rolebinding "
            "rolebinding.rbac.authorization.k8s.io flux-controller-impersonation",
        )
        for guard in ("wait_quiescent", *dependencies):
            with self.subTest(late_guard=guard):
                self.assertEqual(restore.count(guard), 1)
                self.assertLess(restore.index(guard), restore.index(rolebinding_get))
                # This deletion mutant models the late policy/binding drift
                # that an early preflight cannot exclude.
                self.assertNotIn(guard, restore.replace(guard, "", 1))
        self.assertLess(restore.index("wait_quiescent"), restore.index(policy))
        self.assertLess(restore.index(policy), restore.index(binding))
        for component, mutate in (
            (
                "selector-admission-policy",
                lambda value: value["spec"].update(failurePolicy="Ignore"),
            ),
            (
                "selector-admission-binding",
                lambda value: value["spec"].update(validationActions=["Audit"]),
            ),
        ):
            expected = self.module.desired(component, DIGEST, CIDRS)
            drifted = copy.deepcopy(expected)
            mutate(drifted)
            with self.subTest(late_admission_drift=component):
                self.assert_denied(
                    self.module.check, component, drifted, expected, "any"
                )
        for component, mutate in (
            (
                "selector-role",
                lambda value: value["rules"].append({
                    "apiGroups": [""], "resources": ["secrets"],
                    "verbs": ["get"],
                }),
            ),
            (
                "selector-network-public",
                lambda value: value["spec"]["egress"][0]["to"][0][
                    "ipBlock"
                ].update({"except": []}),
            ),
        ):
            expected = self.module.desired(component, DIGEST, CIDRS)
            drifted = copy.deepcopy(expected)
            mutate(drifted)
            with self.subTest(late_selector_dependency_drift=component):
                self.assert_denied(
                    self.module.check, component, drifted, expected, "any"
                )

    def test_native_admission_denies_hostile_json_patch_fixtures(self):
        module = self.module
        prefix = module.SELECTOR_ANNOTATION_PREFIX
        old = {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": {
                "annotations": {
                    prefix + "schema": module.IDENTITY_SCHEMA,
                    prefix + "release-id": "123",
                    prefix + "release-tag": "v0.1.40",
                    prefix + "release-target-sha": "1" * 40,
                    prefix + "tag-object-sha": "2" * 40,
                    prefix + "main-ci": "10/1",
                    prefix + "platform-release": "11/1",
                    prefix + "selector-image-digest": "sha256:" + "6" * 64,
                    prefix + "identity-sha256": "sha256:" + "3" * 64,
                    "example.invalid/controller": "preserve",
                },
                "creationTimestamp": "2026-08-25T00:00:00Z",
                "finalizers": ["finalizers.fluxcd.io"],
                "generation": 1,
                "managedFields": [{"manager": "source-controller"}],
                "name": "flux-system",
                "namespace": "flux-system",
                "resourceVersion": "10",
                "uid": "uid-fixture-source",
            },
            "spec": {
                "ignore": "closed-ignore",
                "interval": "1m0s",
                "ref": {"tag": "v0.1.40"},
                "sparseCheckout": [
                    "kubernetes/websites/naranjo-online",
                    "kubernetes/websites/lidersea-com",
                ],
                "timeout": "60s",
                "url": "https://github.com/snaraj/website-infrastructure.git",
            },
            "status": {"observedGeneration": 1},
        }
        allowed = copy.deepcopy(old)
        allowed["spec"]["ref"]["tag"] = TARGET_TAG
        allowed["metadata"]["generation"] = 2
        allowed["metadata"]["managedFields"] = [{"manager": "platform-release-selector"}]
        allowed["metadata"]["annotations"].update({
            prefix + "schema": module.IDENTITY_SCHEMA,
            prefix + "release-id": "124",
            prefix + "release-tag": TARGET_TAG,
            prefix + "release-target-sha": TARGET_SHA,
            prefix + "tag-object-sha": "4" * 40,
            prefix + "main-ci": "12/1",
            prefix + "platform-release": "13/1",
            prefix + "selector-image-digest": DIGEST,
            prefix + "identity-sha256": "sha256:" + "5" * 64,
        })
        request = {
            "username": module.SELECTOR_USERNAME,
            "operation": "UPDATE",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "resource": "gitrepositories",
            "subresource": "",
            "namespace": "flux-system",
            "name": "flux-system",
        }
        self.assertTrue(module.selector_admission_allows(old, allowed, request))
        unchanged_generation = copy.deepcopy(allowed)
        unchanged_generation["metadata"]["generation"] = 1
        self.assertFalse(
            module.selector_admission_allows(old, unchanged_generation, request)
        )
        client_metadata_change = copy.deepcopy(allowed)
        client_metadata_change["metadata"]["labels"] = {"foreign.example/owner": "other"}
        self.assertFalse(
            module.selector_admission_allows(old, client_metadata_change, request)
        )

        def apply_patch(value, operations):
            result = copy.deepcopy(value)
            for operation in operations:
                parts = [
                    part.replace("~1", "/").replace("~0", "~")
                    for part in operation["path"].lstrip("/").split("/")
                ]
                parent = result
                for part in parts[:-1]:
                    parent = parent[part]
                if operation["op"] in {"add", "replace"}:
                    parent[parts[-1]] = operation["value"]
                elif operation["op"] == "remove":
                    del parent[parts[-1]]
                else:
                    self.fail("unsupported hostile fixture operation")
            return result

        hostile = {
            "url": [{"op": "replace", "path": "/spec/url", "value": "https://example.invalid/repo.git"}],
            "ref-type": [
                {"op": "remove", "path": "/spec/ref/tag"},
                {"op": "add", "path": "/spec/ref/branch", "value": "main"},
            ],
            "secret-ref": [{"op": "add", "path": "/spec/secretRef", "value": {"name": "credential"}}],
            "ignore": [{"op": "replace", "path": "/spec/ignore", "value": "/*"}],
            "sparse-checkout": [{"op": "replace", "path": "/spec/sparseCheckout", "value": ["kubernetes"]}],
            "finalizer": [{"op": "replace", "path": "/metadata/finalizers", "value": ["foreign.example/finalizer"]}],
            "non-reserved-annotation": [{
                "op": "replace",
                "path": "/metadata/annotations/example.invalid~1controller",
                "value": "mutated",
            }],
        }
        for name, operations in hostile.items():
            with self.subTest(name=name):
                candidate = apply_patch(allowed, operations)
                self.assertFalse(
                    module.selector_admission_allows(old, candidate, request)
                )
        self.assertFalse(module.selector_admission_allows(None, allowed, request))
        self.assertFalse(module.selector_admission_allows(old, old, request))
        foreign_old = copy.deepcopy(old)
        foreign_old["metadata"]["annotations"][prefix + "foreign"] = "value"
        self.assertFalse(
            module.selector_admission_allows(foreign_old, allowed, request)
        )

        controller_request = dict(
            request,
            username="system:serviceaccount:flux-system:source-controller",
        )
        controller_update = copy.deepcopy(old)
        controller_update["metadata"]["finalizers"] = []
        controller_update["status"] = {"observedGeneration": 2}
        self.assertTrue(
            module.selector_admission_allows(old, controller_update, controller_request)
        )

    def endpoint_capture(self):
        return {
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSliceList",
            "items": [{
                "addressType": "IPv4",
                "endpoints": [{
                    "addresses": ["192.168.50.10"],
                    "conditions": {"ready": True, "serving": True, "terminating": False},
                }],
                "metadata": {
                    "labels": {"kubernetes.io/service-name": "kubernetes"},
                    "name": "kubernetes",
                    "namespace": "default",
                },
                "ports": [{"name": "https", "port": 6443, "protocol": "TCP"}],
            }],
        }

    def test_api_destination_requires_explicit_server_and_exact_ready_slice_set(self):
        module = self.module
        module.server_endpoint("https://192.168.50.10:6443", CIDRS)
        module.validate_endpoint_slices(self.endpoint_capture(), CIDRS)
        for cidrs in (
            ["192.0.2.10/32"],
            ["100.64.0.0/32"],
            ["127.0.0.1/32"],
            ["169.254.0.0/32"],
            ["192.168.50.0/31"],
            [CIDRS[0], CIDRS[0]],
        ):
            self.assert_denied(module.endpoint_cidrs, cidrs)
        for server in (
            "https://192.168.50.10:443",
            "https://kubernetes.default.svc:6443",
            "https://192.0.2.10:6443",
            "http://192.168.50.10:6443",
        ):
            self.assert_denied(module.server_endpoint, server, CIDRS)
        for mutation in (
            lambda value: value["items"][0]["ports"][0].update(port=443),
            lambda value: value["items"][0]["endpoints"][0]["conditions"].update(ready=False),
            lambda value: value["items"][0]["endpoints"][0].update(addresses=["192.168.50.11"]),
            lambda value: value["items"][0]["metadata"]["labels"].update({"kubernetes.io/service-name": "foreign"}),
        ):
            capture = self.endpoint_capture()
            mutation(capture)
            self.assert_denied(module.validate_endpoint_slices, capture, CIDRS)

    def test_exact_comparison_and_cas_change_only_suspend(self):
        module = self.module
        expected = module.desired("naranjo-kustomization", DIGEST, CIDRS)
        live = copy.deepcopy(expected)
        live["metadata"].update({
            "creationTimestamp": "2026-08-25T00:00:00Z",
            "finalizers": ["finalizers.fluxcd.io"],
            "generation": 4,
            "resourceVersion": "91",
            "uid": "uid-fixture-kustomization",
        })
        live["spec"]["force"] = False
        live["status"] = {"observedGeneration": 4}
        module.check("naranjo-kustomization", live, expected, "any")
        replacement = module.replacement(
            "naranjo-kustomization", live, expected, False
        )
        self.assertEqual(replacement["metadata"]["resourceVersion"], "91")
        self.assertEqual(replacement["metadata"]["uid"], live["metadata"]["uid"])
        self.assertIs(replacement["spec"]["suspend"], False)
        clean = copy.deepcopy(replacement)
        clean["metadata"].pop("resourceVersion")
        clean["metadata"].pop("uid")
        wanted = copy.deepcopy(expected)
        wanted["spec"]["suspend"] = False
        self.assertEqual(clean, wanted)
        for mutation in (
            lambda value: value["spec"].update(path="./kubernetes"),
            lambda value: value["spec"].update(prune=True),
            lambda value: value["spec"].update(force=True),
            lambda value: value["spec"].pop("force"),
            lambda value: value["metadata"].update(ownerReferences=[{"uid": "foreign"}]),
        ):
            hostile = copy.deepcopy(live)
            mutation(hostile)
            self.assert_denied(
                module.replacement,
                "naranjo-kustomization", hostile, expected, False,
            )

    def test_site_impersonation_prerequisites_are_exact_and_namespaced(self):
        module = self.module
        components = {item[0] for item in module.INVENTORY}
        self.assertTrue({
            "naranjo-site-serviceaccount", "naranjo-site-role",
            "naranjo-site-rolebinding", "lidersea-site-serviceaccount",
            "lidersea-site-role", "lidersea-site-rolebinding",
        }.issubset(components))
        for prefix, site in (("naranjo", "naranjo-online"), ("lidersea", "lidersea-com")):
            serviceaccount = module.desired(
                prefix + "-site-serviceaccount", DIGEST, CIDRS
            )
            self.assertEqual(
                serviceaccount,
                {
                    "apiVersion": "v1",
                    "automountServiceAccountToken": False,
                    "kind": "ServiceAccount",
                    "metadata": {
                        "name": site + "-reconciler",
                        "namespace": "flux-system",
                    },
                },
            )
            role = module.desired(prefix + "-site-role", DIGEST, CIDRS)
            self.assertEqual(role["metadata"], {
                "name": "flux-release-reconciler", "namespace": site,
            })
            self.assertEqual(
                role["rules"],
                [
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
            )
            binding = module.desired(prefix + "-site-rolebinding", DIGEST, CIDRS)
            self.assertEqual(binding["metadata"], {
                "name": site + "-reconciler", "namespace": site,
            })
            self.assertEqual(binding["roleRef"]["name"], "flux-release-reconciler")
            self.assertEqual(binding["subjects"], [{
                "kind": "ServiceAccount",
                "name": site + "-reconciler",
                "namespace": "flux-system",
            }])

    def test_selector_rolebinding_quarantine_is_exact_cas_and_reversible(self):
        module = self.module
        expected = module.desired("selector-rolebinding", DIGEST, CIDRS)
        active = copy.deepcopy(expected)
        active["metadata"].update({"resourceVersion": "19", "uid": "selector-binding-uid"})
        module.rolebinding_state(active, expected, False)
        quarantined = module.rolebinding_transition(active, expected, True)
        self.assertEqual(quarantined["subjects"], [])
        self.assertEqual(quarantined["metadata"]["resourceVersion"], "19")
        self.assertEqual(quarantined["metadata"]["uid"], "selector-binding-uid")
        module.rolebinding_state(quarantined, expected, True)
        restored = module.rolebinding_transition(quarantined, expected, False)
        self.assertEqual(restored["subjects"], expected["subjects"])
        self.assertEqual(restored["metadata"]["uid"], "selector-binding-uid")
        for representation in ("omitted", "null"):
            live_quarantine = copy.deepcopy(quarantined)
            if representation == "omitted":
                live_quarantine.pop("subjects")
            else:
                live_quarantine["subjects"] = None
            with self.subTest(quarantined_subjects=representation):
                module.rolebinding_state(live_quarantine, expected, True)
                request = module.rolebinding_transition(
                    live_quarantine, expected, False
                )
                self.assertEqual(request["subjects"], expected["subjects"])
                self.assertEqual(
                    request["metadata"]["uid"], "selector-binding-uid"
                )
        for name, mutate in {
            "foreign role": lambda value: value["roleRef"].update(name="cluster-admin"),
            "foreign subject": lambda value: value.update(subjects=[{
                "kind": "User", "name": "foreign",
            }]),
            "scalar subjects": lambda value: value.update(subjects="foreign"),
            "missing uid": lambda value: value["metadata"].pop("uid"),
        }.items():
            hostile = copy.deepcopy(active)
            mutate(hostile)
            with self.subTest(name=name):
                self.assert_denied(
                    module.rolebinding_transition, hostile, expected, True
                )

    def test_preflight_guard_quarantines_authority_before_containment_or_repair(self):
        text = SCRIPT.read_text(encoding="utf-8")
        armed_false = text.index("mutations_armed=false")
        trap = text.index("trap on_failure ERR INT TERM HUP")
        confirmation = text.index('[[ $confirmation == "$tag" ]]')
        armed_true = text.index("mutations_armed=true", confirmation)
        boundary = text.index("quarantine_authority\ncontain")
        self.assertLess(armed_false, trap)
        self.assertLess(trap, confirmation)
        self.assertLess(confirmation, armed_true)
        self.assertLess(armed_true, boundary)
        self.assertIn("if [[ $mutations_armed == true ]]", text)
        self.assertIn(
            "quarantine_helm_bindings || echo 'RECOVERY_REQUIRED",
            text,
        )
        self.assertIn("quarantine_authority || echo 'RECOVERY_REQUIRED", text)
        self.assertNotIn("admission_ready || quarantine_authority", text)
        self.assertIn(
            "auth can-i patch gitrepositories.source.toolkit.fluxcd.io "
            "--resource-name=flux-system --namespace=flux-system "
            "--as=system:serviceaccount:flux-system:platform-release-selector",
            text,
        )
        self.assertLess(
            boundary,
            text.index(
                "ensure selector-admission-policy "
                "validatingadmissionpolicy.admissionregistration.k8s.io"
            ),
        )
        self.assertLess(
            text.index("ensure selector-role role.rbac.authorization.k8s.io"),
            text.rindex("\nrestore_authority\n"),
        )
        self.assertLess(text.index("wait_quiescent"), text.rindex("\nrestore_authority\n"))
        self.assertLess(
            text.index("ensure naranjo-site-role role.rbac.authorization.k8s.io"),
            text.index(
                "ensure naranjo-kustomization "
                "kustomization.kustomize.toolkit.fluxcd.io"
            ),
        )

    def test_failure_containment_ignores_repeated_and_mixed_signals(self):
        text = SCRIPT.read_text(encoding="utf-8")
        handler = next(
            line for line in text.splitlines() if line.startswith("on_failure()")
        )
        harness = "\n".join((
            "#!/usr/bin/env bash",
            "set -Eeuo pipefail",
            'work="$STATE/work"',
            'mkdir "$work"',
            'quarantine_helm_bindings() { touch "$STATE/helm-started"; '
            'while [[ ! -e "$STATE/release" ]]; do :; done; '
            'touch "$STATE/helm-done"; }',
            'quarantine_authority() { touch "$STATE/authority-done"; }',
            'contain() { touch "$STATE/contain-done"; }',
            handler,
            "mutations_armed=true",
            "trap on_failure ERR INT TERM HUP",
            'touch "$STATE/armed"',
            "while :; do :; done",
            "",
        ))

        def wait_for(path, process):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if path.exists():
                    return
                if process.poll() is not None:
                    self.fail(f"containment exited before {path.name}")
                time.sleep(0.01)
            self.fail(f"timed out waiting for {path.name}")

        cases = (
            (signal.SIGHUP, signal.SIGHUP),
            (signal.SIGINT, signal.SIGINT),
            (signal.SIGTERM, signal.SIGTERM),
            (signal.SIGTERM, signal.SIGINT, signal.SIGHUP),
        )
        for sequence in cases:
            with self.subTest(signals=sequence), tempfile.TemporaryDirectory(
                prefix="platform-bootstrap-signals."
            ) as directory:
                state = Path(directory)
                script = state / "harness.sh"
                script.write_text(harness, encoding="utf-8")
                environment = os.environ.copy()
                environment["STATE"] = str(state)
                process = subprocess.Popen(
                    ["bash", str(script)],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    wait_for(state / "armed", process)
                    os.kill(process.pid, sequence[0])
                    wait_for(state / "helm-started", process)
                    for item in sequence[1:]:
                        os.kill(process.pid, item)
                    (state / "release").touch()
                    stdout, stderr = process.communicate(timeout=5)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                # Bash exposes a zero status to a signal trap here; the
                # production handler deliberately normalizes that to one.
                self.assertEqual(process.returncode, 1, stderr)
                self.assertEqual(stdout, "")
                self.assertNotIn("RECOVERY_REQUIRED", stderr)
                for marker in ("helm-done", "authority-done", "contain-done"):
                    self.assertTrue((state / marker).is_file(), marker)
                self.assertFalse((state / "work").exists())

    def test_selector_execution_must_be_terminal_and_exactly_owned_before_restore(self):
        module = self.module
        cron = module.desired(
            "selector-cronjob", DIGEST, CIDRS, build_sha=TARGET_SHA
        )
        cron["metadata"]["uid"] = "cron-uid"
        job = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "platform-release-selector-123",
                "namespace": "flux-system",
                "uid": "job-uid",
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "controller": True,
                    "kind": "CronJob",
                    "name": "platform-release-selector",
                    "uid": "cron-uid",
                }],
            },
            "status": {"conditions": [{"type": "Complete", "status": "True"}]},
        }
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "labels": {
                    "app.kubernetes.io/name": "platform-release-selector",
                    "app.kubernetes.io/part-of": "platform-release-selector",
                },
                "name": "platform-release-selector-123-pod",
                "namespace": "flux-system",
                "uid": "pod-uid",
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "controller": True,
                    "kind": "Job",
                    "name": "platform-release-selector-123",
                    "uid": "job-uid",
                }],
            },
            "spec": {"serviceAccountName": "platform-release-selector"},
            "status": {"phase": "Succeeded"},
        }
        jobs = {"apiVersion": "batch/v1", "kind": "JobList", "items": [job]}
        pods = {"apiVersion": "v1", "kind": "PodList", "items": [pod]}
        module.selector_quiescent(cron, jobs, pods)
        mutations = {
            "active job": lambda j, p: j["items"][0].update(status={"active": 1}),
            "active pod": lambda j, p: p["items"][0].update(status={"phase": "Running"}),
            "foreign cron uid": lambda j, p: j["items"][0]["metadata"]
            ["ownerReferences"][0].update(uid="foreign"),
            "standalone token pod": lambda j, p: p["items"][0]["metadata"].update(
                ownerReferences=[]
            ),
            "foreign pod label": lambda j, p: p["items"][0]["metadata"]
            ["labels"].update({"app.kubernetes.io/part-of": "foreign"}),
        }
        for name, mutate in mutations.items():
            changed_jobs = copy.deepcopy(jobs)
            changed_pods = copy.deepcopy(pods)
            mutate(changed_jobs, changed_pods)
            with self.subTest(name=name):
                self.assert_denied(
                    module.selector_quiescent, cron, changed_jobs, changed_pods
                )

    def test_readiness_is_current_unique_and_exact_revision(self):
        module = self.module
        expected = module.desired("naranjo-kustomization", DIGEST, CIDRS)
        expected["spec"]["suspend"] = False
        live = copy.deepcopy(expected)
        live["metadata"]["generation"] = 7
        revision = TARGET_TAG + "@sha1:" + TARGET_SHA
        live["status"] = {
            "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}],
            "lastAppliedRevision": revision,
            "lastAttemptedRevision": revision,
            "observedGeneration": 7,
        }
        module.ready(
            "naranjo-kustomization", live, expected, TARGET_TAG, TARGET_SHA
        )
        stale = copy.deepcopy(live)
        stale["status"]["observedGeneration"] = 6
        self.assert_denied(
            module.ready,
            "naranjo-kustomization", stale, expected, TARGET_TAG, TARGET_SHA,
        )
        duplicate = copy.deepcopy(live)
        duplicate["status"]["conditions"].append(copy.deepcopy(duplicate["status"]["conditions"][0]))
        self.assert_denied(
            module.ready,
            "naranjo-kustomization", duplicate, expected, TARGET_TAG, TARGET_SHA,
        )
        drifted = copy.deepcopy(live)
        drifted["status"]["lastAppliedRevision"] = "v0.1.27@sha1:" + "3" * 40
        self.assert_denied(
            module.ready,
            "naranjo-kustomization", drifted, expected, TARGET_TAG, TARGET_SHA,
        )

    def test_target_annotations_are_exact_and_incomplete_receipts_block_source(self):
        module = self.module
        annotations = {
            "schema": module.IDENTITY_SCHEMA,
            "release-id": "123",
            "release-tag": TARGET_TAG,
            "release-target-sha": TARGET_SHA,
            "tag-object-sha": "4" * 40,
            "main-ci": "10/1",
            "platform-release": "11/1",
            "selector-image-digest": DIGEST,
            "identity-sha256": "sha256:" + "5" * 64,
        }
        remote_output = {
            **annotations,
            "selector-build-sha": TARGET_SHA,
            "naranjo-chart-digest": "sha256:" + "6" * 64,
            "naranjo-chart-version": "0.1.50",
            "lidersea-chart-digest": "sha256:" + "7" * 64,
            "lidersea-chart-version": "0.1.37",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "annotations.json"
            path.write_text(json.dumps(remote_output), encoding="utf-8")
            with mock.patch.object(module, "local_release", return_value=(TARGET_TAG, TARGET_SHA)):
                self.assertEqual(module.target_annotations(path, DIGEST), annotations)
                target = module.desired("source", DIGEST, CIDRS, "target", path)
                self.assertEqual(target["spec"]["ref"], {"tag": TARGET_TAG})
                self.assertEqual(
                    target["metadata"]["annotations"],
                    {
                        "release-selector.platform.snaraj.dev/" + key: value
                        for key, value in annotations.items()
                    },
                )
                live = copy.deepcopy(target)
                live["metadata"].update({
                    "generation": 2,
                    "resourceVersion": "101",
                    "uid": "uid-fixture-ready-source",
                })
                module.check("source", live, target, "any")
                live["status"] = {
                    "artifact": {
                        "revision": TARGET_TAG + "@sha1:" + TARGET_SHA,
                    },
                    "conditions": [{
                        "type": "Ready",
                        "status": "True",
                        "observedGeneration": 2,
                    }],
                    "observedGeneration": 2,
                }
                module.ready("source", live, target, TARGET_TAG, TARGET_SHA)
                hostile = dict(remote_output, **{"release-id": "0"})
                path.write_text(json.dumps(hostile), encoding="utf-8")
                self.assert_denied(module.target_annotations, path, DIGEST)
        self.assert_denied(module.desired, "source", DIGEST, CIDRS)

    def test_verified_attestation_must_bind_digest_and_source(self):
        module = self.module
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "selector", "digest": {"sha256": DIGEST.removeprefix("sha256:")}}],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                    "externalParameters": {
                        "configSource": {
                            "uri": f"https://github.com/snaraj/website-infrastructure.git#{TARGET_SHA}",
                            "digest": {"sha1": TARGET_SHA},
                            "path": "cmd/platform-release-selector/Dockerfile",
                        }
                    },
                },
                "runDetails": {
                    "metadata": {
                        "buildkit_completeness": {"resolvedDependencies": True},
                        "buildkit_hermetic": True,
                    }
                },
            },
        }
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"sig": "verified-by-cosign-before-this-validator"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attestation.jsonl"
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            module.validate_attestations(path, DIGEST, TARGET_SHA)
            mutations = {
                "statement type": lambda value: value.update(
                    _type="https://in-toto.io/Statement/v0.1"
                ),
                "predicate type": lambda value: value.update(
                    predicateType="https://example.invalid"
                ),
                "subject digest": lambda value: value.update(
                    subject=[{"digest": {"sha256": "7" * 64}}]
                ),
                "source digest": lambda value: value["predicate"]["buildDefinition"]
                ["externalParameters"]["configSource"]["digest"].update(
                    sha1="6" * 40
                ),
                "source URI": lambda value: value["predicate"]["buildDefinition"]
                ["externalParameters"]["configSource"].update(
                    uri="https://example.invalid/repo.git#" + TARGET_SHA
                ),
                "Dockerfile": lambda value: value["predicate"]["buildDefinition"]
                ["externalParameters"]["configSource"].update(path="Dockerfile"),
                "incomplete materials": lambda value: value["predicate"]["runDetails"]
                ["metadata"]["buildkit_completeness"].update(
                    resolvedDependencies=False
                ),
                "nonhermetic build": lambda value: value["predicate"]["runDetails"]
                ["metadata"].update(buildkit_hermetic=False),
                "decoy source SHA": lambda value: value["predicate"].update(
                    decoy=TARGET_SHA
                )
                or value["predicate"]["buildDefinition"]["externalParameters"]
                ["configSource"]["digest"].update(sha1="6" * 40),
            }
            for name, mutate in mutations.items():
                hostile_statement = copy.deepcopy(statement)
                mutate(hostile_statement)
                hostile = copy.deepcopy(envelope)
                hostile["payload"] = base64.b64encode(
                    json.dumps(hostile_statement).encode()
                ).decode()
                path.write_text(json.dumps(hostile) + "\n", encoding="utf-8")
                with self.subTest(name=name):
                    self.assert_denied(
                        module.validate_attestations, path, DIGEST, TARGET_SHA
                    )



if __name__ == "__main__":
    unittest.main()
