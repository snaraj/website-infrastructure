"""Offline contracts for the closed Flux bootstrap live-state verifier."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "bootstrap" / "flux" / "bootstrap.sh"
BASH = shutil.which("bash")
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


def embedded_python(label: str) -> str:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    match = re.search(
        rf"<<'{re.escape(label)}'.*?\n(?P<body>.*?)\n{re.escape(label)}(?:\n|$)",
        text,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing embedded program {label}")
    return match.group("body")


class FluxLiveStateStaticContractTests(unittest.TestCase):
    def test_bootstrap_closes_shell_git_target_and_remote_identity(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        for fragment in (
            "BASH_ENV|ENV|BASH_FUNC_*|LD_*",
            "ulimit -S -c 0",
            "ulimit -H -c 0",
            '"${git_binary}" --no-replace-objects',
            "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null",
            '[[ ! -e "${repo_root}/.git/info/grafts" ]]',
            "for-each-ref --format='%(refname)' refs/replace",
            "critical_inventory='100755 bootstrap/flux/bootstrap.sh",
            'git_repo cat-file blob "${EXPECTED_REPOSITORY_HEAD}:${critical_path}"',
            'cmp -s -- "${critical_worktree_copy}" "${critical_blob_copy}"',
            "EXPECTED_KUBERNETES_CA_SHA256",
            "EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256",
            'sha256sum -- "${kube_system_uid}"',
            "verify_remote_main || fail",
            'rb"([0-9a-f]{40})\\trefs/heads/main\\n"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertLess(text.index("BASH_ENV|ENV|BASH_FUNC_*|LD_*"), text.index("uname -s"))
        self.assertLess(text.index("ulimit -H -c 0"), text.index("uname -s"))
        self.assertEqual(text.count("ls-remote"), 1)

    def test_apply_and_verify_paths_gate_on_reviewed_live_state(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        for fragment in (
            "--apply-sync || \"${mode}\" == --verify",
            "KUBECTL_EXTERNAL_DIFF='/usr/bin/diff -u -N'",
            "--field-manager=kubectl-client-side-apply",
            'capture_live_json "${live_deployments}" -n flux-system get deployments',
            'capture_live_json "${live_service_accounts}" get serviceaccounts --all-namespaces',
            'capture_live_json "${live_role_bindings}" get rolebindings --all-namespaces',
            'capture_live_json "${live_cluster_role_bindings}" get clusterrolebindings',
            "PY_FLUX_LIVE_STATE",
            "verify_reviewed_live_state controllers || fail",
            "verify_reviewed_live_state full || fail",
            "/bin/bash \"${repo_root}/bootstrap/flux/verify-sops-age-secret.sh\"",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotRegex(text, r"(?m)^\s*kubectl\s")
        self.assertNotIn("cat \"${live_", text)

    def test_ca_program_binds_embedded_der_hash_without_disclosure(self):
        program = embedded_python("PY_KUBERNETES_CA")
        certificate_der = b"offline-test-ca-der"
        certificate_text = base64.b64encode(certificate_der).decode("ascii")
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + certificate_text
            + "\n-----END CERTIFICATE-----\n"
        ).encode("ascii")
        document = {
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": base64.b64encode(pem).decode("ascii")
                    }
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            environment = {
                **os.environ,
                "KUBECONFIG_SNAPSHOT_FILE": str(path),
                "EXPECTED_KUBERNETES_CA_SHA256": hashlib.sha256(certificate_der).hexdigest(),
            }
            accepted = subprocess.run(
                [sys.executable, "-I", "-c", program],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            environment["EXPECTED_KUBERNETES_CA_SHA256"] = "0" * 64
            rejected = subprocess.run(
                [sys.executable, "-I", "-c", program],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout + rejected.stderr, "")
            self.assertNotIn(certificate_text, rejected.stdout + rejected.stderr)

    def test_remote_main_parser_accepts_only_the_exact_reviewed_ref(self):
        program = embedded_python("PY_REMOTE_MAIN")
        reviewed = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "remote-main.ref"
            environment = {
                **os.environ,
                "REMOTE_MAIN_RESULT": str(path),
                "EXPECTED_REPOSITORY_HEAD": reviewed,
            }
            path.write_bytes(f"{reviewed}\trefs/heads/main\n".encode("ascii"))
            accepted = subprocess.run(
                [sys.executable, "-I", "-c", program],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            for invalid in (
                f"{'b' * 40}\trefs/heads/main\n",
                f"{reviewed}\trefs/heads/other\n",
                f"{reviewed}\trefs/heads/main\n{reviewed}\trefs/tags/main\n",
            ):
                path.write_bytes(invalid.encode("ascii"))
                rejected = subprocess.run(
                    [sys.executable, "-I", "-c", program],
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout + rejected.stderr, "")

    @unittest.skipUnless(BASH, "Bash is required for startup-environment rejection")
    def test_bash_startup_environment_fails_before_target_or_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            startup = Path(directory) / "startup.sh"
            startup.write_text("inherited_hook() { :; }\n", encoding="utf-8")
            environment = {**os.environ, "BASH_ENV": str(startup)}
            result = subprocess.run(
                [BASH, str(BOOTSTRAP), "--generate"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "FAIL Flux operation made no cluster mutation.\n")


class FluxLiveStateAdversarialTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.program = embedded_python("PY_FLUX_LIVE_STATE")
        definitions = cls.program.rsplit("\ntry:\n    main()", 1)[0]
        cls.base_environment = {
            "FLUX_EXPECTED_VERSION": "v2.9.3",
            "FLUX_EXPECTED_SOURCE_IMAGE": "ghcr.io/fluxcd/source-controller:v1.9.3@sha256:" + "1" * 64,
            "FLUX_EXPECTED_KUSTOMIZE_IMAGE": "ghcr.io/fluxcd/kustomize-controller:v1.9.4@sha256:" + "2" * 64,
            "FLUX_EXPECTED_HELM_IMAGE": "ghcr.io/fluxcd/helm-controller:v1.6.3@sha256:" + "3" * 64,
        }
        saved = os.environ.copy()
        os.environ.update(cls.base_environment)
        try:
            cls.contract = {}
            exec(compile(definitions, "<flux-live-contract>", "exec"), cls.contract)
            cls.fixture = cls.build_fixture()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    @classmethod
    def metadata(
        cls,
        name,
        namespace,
        labels,
        annotations=None,
        deployment=False,
        flux_finalizer=False,
    ):
        actual_annotations = {
            cls.contract["LAST_APPLIED"]: json.dumps(
                {"kind": "Fixture", "metadata": {"name": name}}, separators=(",", ":")
            )
        }
        actual_annotations.update(annotations or {})
        if deployment:
            actual_annotations["deployment.kubernetes.io/revision"] = "1"
        value = {
            "name": name,
            "uid": "00000000-0000-0000-0000-000000000000",
            "resourceVersion": "1",
            "creationTimestamp": "2026-08-09T00:00:00Z",
            "labels": labels,
            "annotations": actual_annotations,
        }
        if namespace is not None:
            value["namespace"] = namespace
        if flux_finalizer:
            value["finalizers"] = [cls.contract["FLUX_FINALIZER"]]
        return value

    @staticmethod
    def list_document(items):
        return {"apiVersion": "v1", "kind": "List", "items": items}

    @classmethod
    def build_fixture(cls):
        c = cls.contract
        deployments = []
        deployment_contract = {
            "source-controller": (
                cls.base_environment["FLUX_EXPECTED_SOURCE_IMAGE"],
                ["--no-cross-namespace-refs=true"],
                True,
                10,
            ),
            "kustomize-controller": (
                cls.base_environment["FLUX_EXPECTED_KUSTOMIZE_IMAGE"],
                [
                    "--no-cross-namespace-refs=true",
                    "--no-remote-bases=true",
                    "--default-service-account=default",
                ],
                False,
                60,
            ),
            "helm-controller": (
                cls.base_environment["FLUX_EXPECTED_HELM_IMAGE"],
                ["--no-cross-namespace-refs=true", "--default-service-account=default"],
                False,
                600,
            ),
        }
        for name, (image, args, source, grace) in deployment_contract.items():
            template_metadata = {
                "annotations": {"prometheus.io/port": "8080", "prometheus.io/scrape": "true"},
                "labels": {"app": name, **c["flux_labels"](name)},
            }
            spec = {
                "replicas": 1,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": template_metadata,
                    "spec": c["expected_pod"](name, image, args, source, grace),
                },
            }
            if source:
                spec["strategy"] = {"type": "Recreate"}
            deployments.append(
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": cls.metadata(
                        name,
                        "flux-system",
                        c["flux_labels"](name, True),
                        deployment=True,
                    ),
                    "spec": spec,
                }
            )

        service_accounts = [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": cls.metadata(name, namespace, c["flux_labels"](name)),
            }
            for namespace, name in sorted(c["CONTROLLER_SERVICE_ACCOUNTS"])
        ]
        for namespace, name in sorted(c["ACCESS_SERVICE_ACCOUNTS"]):
            service_accounts.append(
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": cls.metadata(name, namespace, {}),
                    "automountServiceAccountToken": False,
                }
            )

        roles = []
        for key, rules in c["access_role_rules"]().items():
            namespace, name = key
            roles.append(
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": cls.metadata(name, namespace, {}),
                    "rules": rules,
                }
            )
        cluster_roles = []
        for name, rules in c["cluster_role_rules"]().items():
            cluster_roles.append(
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": cls.metadata(name, None, c["expected_cluster_role_labels"](name)),
                    "rules": rules,
                }
            )
        role_bindings = []
        for key, expected in c["expected_bindings"]().items():
            namespace, name = key
            role_bindings.append(
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": cls.metadata(name, namespace, {}),
                    "roleRef": expected[0],
                    "subjects": expected[1],
                }
            )
        cluster_bindings = []
        for name, expected in c["expected_cluster_bindings"]().items():
            cluster_bindings.append(
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": cls.metadata(name, None, c["flux_labels"]()),
                    "roleRef": expected[0],
                    "subjects": expected[1],
                }
            )

        namespaces = []
        for name in ("flux-system", "cloudflare-public", "naranjo-online", "lidersea-com", "kyverno"):
            if name == "flux-system":
                # The reviewed controller overlay adds enforce/audit Pod
                # Security to the namespace the generated export only warns
                # about, so the reviewed live namespace carries both sets.
                labels = {
                    **c["flux_labels"](),
                    **c["PSA_LABELS"],
                    "kubernetes.io/metadata.name": name,
                }
                annotations = {}
            else:
                labels = {**c["PSA_LABELS"], "kubernetes.io/metadata.name": name}
                annotations = {"kustomize.toolkit.fluxcd.io/prune": "disabled"}
                if name == "kyverno":
                    annotations["platform.snaraj.dev/readiness"] = (
                        "blocked-until-reviewed-controller-digests-and-runtime-evidence"
                    )
            namespaces.append(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": cls.metadata(name, None, labels, annotations),
                    "spec": {"finalizers": ["kubernetes"]},
                }
            )

        git_repository = {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": cls.metadata("flux-system", "flux-system", {}, flux_finalizer=True),
            "spec": {
                "ignore": "/*\n!/kubernetes\n!/policies\n",
                "interval": "1m0s",
                "ref": {"branch": "main"},
                "sparseCheckout": ["kubernetes", "policies"],
                "timeout": "60s",
                "url": "https://github.com/snaraj/website-infrastructure.git",
            },
        }
        kustomization = {
            "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
            "kind": "Kustomization",
            "metadata": cls.metadata("flux-system", "flux-system", {}, flux_finalizer=True),
            "spec": {
                "interval": "10m0s",
                "path": "./kubernetes/reconciliation",
                "prune": True,
                "retryInterval": "1m0s",
                "serviceAccountName": "root-reconciler",
                "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
                "timeout": "5m0s",
                "wait": True,
            },
        }
        return {
            "deployments": cls.list_document(deployments),
            "service_accounts": cls.list_document(service_accounts),
            "roles": cls.list_document(roles),
            "role_bindings": cls.list_document(role_bindings),
            "cluster_roles": cls.list_document(cluster_roles),
            "cluster_role_bindings": cls.list_document(cluster_bindings),
            "namespaces": cls.list_document(namespaces),
            "git_repository": git_repository,
            "kustomization": kustomization,
        }

    def run_fixture(self, fixture, *, scope="full"):
        with tempfile.TemporaryDirectory() as directory:
            environment = {**os.environ, **self.base_environment, "FLUX_LIVE_SCOPE": scope}
            variable_names = {
                "deployments": "FLUX_LIVE_DEPLOYMENTS",
                "service_accounts": "FLUX_LIVE_SERVICE_ACCOUNTS",
                "roles": "FLUX_LIVE_ROLES",
                "role_bindings": "FLUX_LIVE_ROLE_BINDINGS",
                "cluster_roles": "FLUX_LIVE_CLUSTER_ROLES",
                "cluster_role_bindings": "FLUX_LIVE_CLUSTER_ROLE_BINDINGS",
                "namespaces": "FLUX_LIVE_NAMESPACES",
                "git_repository": "FLUX_LIVE_GIT_REPOSITORY",
                "kustomization": "FLUX_LIVE_KUSTOMIZATION",
            }
            for key, variable in variable_names.items():
                path = Path(directory) / f"{key}.json"
                path.write_text(json.dumps(fixture[key]), encoding="utf-8")
                environment[variable] = str(path)
            return subprocess.run(
                [sys.executable, "-I", "-c", self.program],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
            )

    def test_exact_reviewed_fixture_is_accepted(self):
        result = self.run_fixture(copy.deepcopy(self.fixture))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")

    def test_controller_checkpoint_accepts_pristine_namespace_default_account(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["namespaces"]["items"] = [
            item
            for item in fixture["namespaces"]["items"]
            if item["metadata"]["name"] == "flux-system"
        ]
        default_account = next(
            item
            for item in fixture["service_accounts"]["items"]
            if item["metadata"].get("namespace") == "flux-system"
            and item["metadata"]["name"] == "default"
        )
        default_account.pop("automountServiceAccountToken")
        default_account["metadata"]["annotations"].pop(self.contract["LAST_APPLIED"])
        result = self.run_fixture(fixture, scope="controllers")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sidecars_args_images_proxy_and_secret_refs_are_rejected(self):
        mutations = []
        sidecar = copy.deepcopy(self.fixture)
        sidecar["deployments"]["items"][0]["spec"]["template"]["spec"]["containers"].append(
            {"name": "sidecar", "image": "example.invalid/sidecar:latest"}
        )
        mutations.append(sidecar)
        extra_arg = copy.deepcopy(self.fixture)
        extra_arg["deployments"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["args"].append("--unsafe=true")
        mutations.append(extra_arg)
        image_drift = copy.deepcopy(self.fixture)
        image_drift["deployments"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["image"] += "-drift"
        mutations.append(image_drift)
        proxy_env = copy.deepcopy(self.fixture)
        proxy_env["deployments"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "HTTPS_PROXY", "value": "http://proxy.invalid"}
        )
        mutations.append(proxy_env)
        secret_env = copy.deepcopy(self.fixture)
        secret_env["deployments"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "unexpected", "key": "token"}}}
        )
        mutations.append(secret_env)
        for fixture in mutations:
            with self.subTest(mutation=len(mutations)):
                self.assertNotEqual(self.run_fixture(fixture).returncode, 0)

    def test_source_path_service_account_and_admission_metadata_drift_are_rejected(self):
        mutations = []
        git_secret = copy.deepcopy(self.fixture)
        git_secret["git_repository"]["spec"]["secretRef"] = {"name": "git-credentials"}
        mutations.append(git_secret)
        git_url = copy.deepcopy(self.fixture)
        git_url["git_repository"]["spec"]["url"] = "https://example.invalid/other.git"
        mutations.append(git_url)
        path = copy.deepcopy(self.fixture)
        path["kustomization"]["spec"]["path"] = "./kubernetes/other"
        mutations.append(path)
        source_ref = copy.deepcopy(self.fixture)
        source_ref["kustomization"]["spec"]["sourceRef"]["name"] = "other"
        mutations.append(source_ref)
        service_account = copy.deepcopy(self.fixture)
        service_account["kustomization"]["spec"]["serviceAccountName"] = "default"
        mutations.append(service_account)
        metadata = copy.deepcopy(self.fixture)
        metadata["git_repository"]["metadata"]["annotations"]["admission.example.invalid/mutated"] = "true"
        mutations.append(metadata)
        for fixture in mutations:
            self.assertNotEqual(self.run_fixture(fixture).returncode, 0)

    def test_service_account_binding_and_namespace_security_drift_are_rejected(self):
        mutations = []
        account = copy.deepcopy(self.fixture)
        target = next(
            item
            for item in account["service_accounts"]["items"]
            if item["metadata"].get("namespace") == "flux-system"
            and item["metadata"]["name"] == "root-reconciler"
        )
        target["automountServiceAccountToken"] = True
        mutations.append(account)
        image_pull = copy.deepcopy(self.fixture)
        target = next(
            item
            for item in image_pull["service_accounts"]["items"]
            if item["metadata"].get("namespace") == "flux-system"
            and item["metadata"]["name"] == "root-reconciler"
        )
        target["imagePullSecrets"] = [{"name": "unexpected"}]
        mutations.append(image_pull)
        binding = copy.deepcopy(self.fixture)
        binding["cluster_role_bindings"]["items"].append(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": self.metadata("unexpected", None, {}),
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "cluster-admin",
                },
                "subjects": [self.contract["sa_subject"]("flux-system", "root-reconciler")],
            }
        )
        mutations.append(binding)
        namespace = copy.deepcopy(self.fixture)
        namespace["namespaces"]["items"][1]["metadata"]["labels"][
            "pod-security.kubernetes.io/enforce"
        ] = "privileged"
        mutations.append(namespace)
        for fixture in mutations:
            self.assertNotEqual(self.run_fixture(fixture).returncode, 0)


if __name__ == "__main__":
    unittest.main()
