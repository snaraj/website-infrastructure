import json
import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_GATE = REPO_ROOT / "scripts" / "release-gate.sh"
FLUX_EVIDENCE_VALIDATOR = REPO_ROOT / "scripts" / "validate_flux_release_evidence.py"
INVENTORY_VALIDATOR = REPO_ROOT / "scripts" / "validate_runtime_inventory_evidence.py"
COMMIT = "a" * 40
GIT_REVISION = "main@sha1:" + COMMIT
NARANJO_IMAGE = "ghcr.io/snaraj/naranjo-online@sha256:" + "1" * 64
LIDERSEA_IMAGE = "ghcr.io/snaraj/lidersea-com@sha256:" + "2" * 64
CLOUDFLARED_IMAGE = "cloudflare/cloudflared:v1@sha256:" + "3" * 64
ADMISSION_IMAGE = "reg.kyverno.io/kyverno/kyverno:v1@sha256:" + "4" * 64
FLUX_SOURCE_IMAGE = "ghcr.io/fluxcd/source-controller:v1@sha256:" + "5" * 64
FLUX_KUSTOMIZE_IMAGE = "ghcr.io/fluxcd/kustomize-controller:v1@sha256:" + "6" * 64
FLUX_HELM_IMAGE = "ghcr.io/fluxcd/helm-controller:v1@sha256:" + "7" * 64
KUBERNETES_VERSION = "v1.36.3"
COREDNS_IMAGE = "registry.k8s.io/coredns/coredns:v1.14.2"
ETCD_IMAGE = "registry.k8s.io/etcd:3.6.8-0"
CILIUM_OPERATOR_IMAGE = "quay.io/cilium/operator-generic:v1.0.0@sha256:" + "8" * 64
CILIUM_IMAGE = "quay.io/cilium/cilium:v1.0.0@sha256:" + "9" * 64

KUSTOMIZATION_NAMES = (
    "flux-system",
    "platform-prerequisites",
    "admission",
    "platform-services",
    "naranjo-online",
    "lidersea-com",
)
SOURCE_IDENTITIES = (
    ("flux-system", "flux-system"),
    ("cloudflare-public", "cloudflare-public-source"),
)
# Each site's chart is a published, cosign-verified OCI artifact selected by a
# SemVer range; only the connector still resolves a chart from Git.
CHART_ISSUER = r"^https://token\.actions\.githubusercontent\.com$"


def chart_subject(domain):
    escaped = domain.replace(".", r"\.")
    return (
        r"^https://github\.com/snaraj/"
        + escaped
        + r"/\.github/workflows/release-publisher\.yml"
        r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"
    )


OCI_CHART_SOURCES = {
    ("naranjo-online", "naranjo-online-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/naranjo-online",
        "subject": chart_subject("naranjo.online"),
        "tag": "v0.1.9",
        "digest": "sha256:" + "a" * 64,
    },
    ("lidersea-com", "lidersea-com-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/lidersea-com",
        "subject": chart_subject("lidersea.com"),
        "tag": "v0.1.9",
        "digest": "sha256:" + "b" * 64,
    },
}
# None marks the tag-driven chartRef releases; the connector keeps its Git
# chart source and is therefore the only release with a HelmChart object.
RELEASE_SOURCES = {
    ("naranjo-online", "naranjo-online"): None,
    ("lidersea-com", "lidersea-com"): None,
    ("cloudflare-public", "cloudflare-public"): "cloudflare-public-source",
}
POLICY_NAMES = (
    "disallow-public-services",
    "disallow-tenant-media-payloads",
    "disallow-undiscovered-storage",
    "require-approved-images",
    "require-exact-tenant-networking",
    "require-release-readiness",
    "require-restricted-workloads",
    "require-signed-naranjo-online",
    "require-signed-lidersea-com",
)
NETWORK_POLICY_IDENTITIES = (
    ("cloudflare-public", "default-deny"),
    ("cloudflare-public", "cloudflared-dns"),
    ("cloudflare-public", "cloudflared-edge"),
    ("cloudflare-public", "cloudflared-naranjo-online"),
    ("cloudflare-public", "cloudflared-lidersea-com"),
    ("naranjo-online", "default-deny"),
    ("naranjo-online", "ingress-to-naranjo-online"),
    ("lidersea-com", "default-deny"),
    ("lidersea-com", "ingress-to-lidersea-com"),
)


def function_body(script, name, next_name):
    start = script.index("{}() {{".format(name))
    end = script.index("{}() {{".format(next_name), start)
    return script[start:end]


def ready_condition():
    return {"type": "Ready", "status": "True"}


class ReleaseGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RELEASE_GATE.read_text(encoding="utf-8")
        cls.clean_commit = function_body(
            cls.script, "assert_clean_commit", "assert_storage_disabled"
        )
        live_start = cls.script.index("run_live_gate() {")
        live_end = cls.script.index('\ncase "${1:---check}" in', live_start)
        cls.live = cls.script[live_start:live_end]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self._write_valid_evidence()
        self._write_valid_global_evidence()

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, name, value):
        (self.root / name).write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )

    def _read(self, name):
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def _write_valid_evidence(self):
        kustomizations = []
        for name in KUSTOMIZATION_NAMES:
            spec = {
                "path": "./" + name,
                "prune": True,
                "serviceAccountName": name + "-reconciler",
                "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
            }
            item = {
                "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
                "kind": "Kustomization",
                "metadata": {
                    "namespace": "flux-system",
                    "name": name,
                    "generation": 2,
                },
                "spec": spec,
                "status": {
                    "conditions": [ready_condition()],
                    "observedGeneration": 2,
                    "lastAppliedRevision": GIT_REVISION,
                    "lastAttemptedRevision": GIT_REVISION,
                },
            }
            kustomizations.append(item)
            self._write(
                "desired-flux-kustomization-flux-system-{}.json".format(name),
                {
                    "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
                    "kind": "Kustomization",
                    "metadata": {"namespace": "flux-system", "name": name},
                    "spec": spec,
                },
            )
        self._write("kustomizations.json", {"items": kustomizations})

        sources = []
        for namespace, name in SOURCE_IDENTITIES:
            spec = {
                "url": "https://github.com/snaraj/website-infrastructure.git",
                "ref": {"branch": "main"},
                "ignore": "/*\n!/reviewed\n",
                "sparseCheckout": ["reviewed"],
            }
            sources.append(
                {
                    "apiVersion": "source.toolkit.fluxcd.io/v1",
                    "kind": "GitRepository",
                    "metadata": {
                        "namespace": namespace,
                        "name": name,
                        "generation": 2,
                    },
                    "spec": spec,
                    "status": {
                        "conditions": [ready_condition()],
                        "observedGeneration": 2,
                        "artifact": {"revision": GIT_REVISION},
                    },
                }
            )
            self._write(
                "desired-flux-gitrepository-{}-{}.json".format(namespace, name),
                {
                    "apiVersion": "source.toolkit.fluxcd.io/v1",
                    "kind": "GitRepository",
                    "metadata": {"namespace": namespace, "name": name},
                    "spec": spec,
                },
            )
        self._write("gitrepositories.json", {"items": sources})
        for filename in (
            "buckets.json",
            "externalartifacts.json",
            "helmrepositories.json",
        ):
            self._write(filename, {"items": []})

        chart_sources = []
        for (namespace, name), contract in OCI_CHART_SOURCES.items():
            spec = {
                "interval": "10m0s",
                "layerSelector": {
                    "mediaType": (
                        "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
                    ),
                    "operation": "copy",
                },
                "ref": {"semver": ">=0.1.9 <1.0.0"},
                "timeout": "60s",
                "url": contract["url"],
                "verify": {
                    "matchOIDCIdentity": [
                        {
                            "issuer": CHART_ISSUER,
                            "subject": contract["subject"],
                        }
                    ],
                    "provider": "cosign",
                },
            }
            chart_sources.append(
                {
                    "apiVersion": "source.toolkit.fluxcd.io/v1",
                    "kind": "OCIRepository",
                    "metadata": {
                        "namespace": namespace,
                        "name": name,
                        "generation": 2,
                    },
                    "spec": spec,
                    "status": {
                        "conditions": [ready_condition()],
                        "observedGeneration": 2,
                        "artifact": {
                            "revision": "{}@{}".format(
                                contract["tag"], contract["digest"]
                            ),
                            "digest": contract["digest"],
                        },
                    },
                }
            )
            self._write(
                "desired-flux-ocirepository-{}-{}.json".format(namespace, name),
                {
                    "apiVersion": "source.toolkit.fluxcd.io/v1",
                    "kind": "OCIRepository",
                    "metadata": {"namespace": namespace, "name": name},
                    "spec": spec,
                },
            )
        self._write("ocirepositories.json", {"items": chart_sources})

        releases = []
        charts = []
        for (namespace, name), source_name in RELEASE_SOURCES.items():
            if source_name is None:
                contract = OCI_CHART_SOURCES[(namespace, namespace + "-chart")]
                revision = contract["tag"]
                release_spec = {
                    "chartRef": {
                        "kind": "OCIRepository",
                        "name": namespace + "-chart",
                    },
                    "interval": "10m0s",
                    "releaseName": name,
                    "serviceAccountName": "helm-reconciler",
                }
                release_status = {
                    "conditions": [ready_condition()],
                    "observedGeneration": 3,
                    "lastAttemptedGeneration": 3,
                    "lastAttemptedRevision": revision,
                    "history": [
                        {
                            "name": name,
                            "namespace": namespace,
                            "status": "deployed",
                            "chartVersion": revision,
                        }
                    ],
                }
            else:
                revision = "0.1.0+{}".format(name.replace("-", ""))
                chart_name = "{}-{}".format(name, name)
                chart_spec = {
                    "chart": "./reviewed/" + name,
                    "interval": "10m0s",
                    "reconcileStrategy": "Revision",
                    "sourceRef": {"kind": "GitRepository", "name": source_name},
                }
                release_spec = {
                    "chart": {"spec": chart_spec},
                    "interval": "10m0s",
                    "releaseName": name,
                    "serviceAccountName": "helm-reconciler",
                }
                release_status = {
                    "conditions": [ready_condition()],
                    "observedGeneration": 3,
                    "lastAttemptedGeneration": 3,
                    "lastAttemptedRevision": revision,
                    "helmChart": "{}/{}".format(namespace, chart_name),
                    "history": [
                        {
                            "name": name,
                            "namespace": namespace,
                            "status": "deployed",
                            "chartVersion": revision,
                        }
                    ],
                }
                charts.append(
                    {
                        "metadata": {
                            "namespace": namespace,
                            "name": chart_name,
                            "generation": 4,
                        },
                        "spec": {
                            **chart_spec,
                        },
                        "status": {
                            "conditions": [ready_condition()],
                            "observedGeneration": 4,
                            "observedSourceArtifactRevision": GIT_REVISION,
                            "artifact": {"revision": revision},
                        },
                    }
                )
            releases.append(
                {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "metadata": {
                        "namespace": namespace,
                        "name": name,
                        "generation": 3,
                    },
                    "spec": release_spec,
                    "status": release_status,
                }
            )
            self._write(
                "desired-flux-helmrelease-{}-{}.json".format(namespace, name),
                {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "metadata": {"namespace": namespace, "name": name},
                    "spec": release_spec,
                },
            )
        self._write("helmreleases.json", {"items": releases})
        self._write("helmcharts.json", {"items": charts})

        live_policies = []
        for name in POLICY_NAMES:
            policy = {
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {"name": name},
                "spec": {
                    "admission": True,
                    "validationFailureAction": "Enforce",
                    "webhookConfiguration": {"failurePolicy": "Fail"},
                    "rules": [{"name": "exact-" + name}],
                },
            }
            live_policies.append(policy)
            self._write("desired-policy-{}.json".format(name), policy)
        self._write("policies.json", {"items": live_policies})

        network_policies = []
        for namespace, name in NETWORK_POLICY_IDENTITIES:
            policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"namespace": namespace, "name": name},
                "spec": {
                    "podSelector": {"matchLabels": {"contract": name}},
                    "policyTypes": ["Ingress", "Egress"],
                },
            }
            network_policies.append(policy)
            self._write(
                "desired-networkpolicy-{}-{}.json".format(namespace, name),
                policy,
            )
        self._write("networkpolicies.json", {"items": network_policies})

    @staticmethod
    def _uid(kind, namespace, name):
        return "{}:{}:{}".format(kind, namespace, name)

    @staticmethod
    def _ready_pod_status():
        return {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
        }

    def _write_valid_global_evidence(self):
        namespace_names = (
            "default",
            "kube-node-lease",
            "kube-public",
            "kube-system",
            "flux-system",
            "kyverno",
            "cloudflare-public",
            "naranjo-online",
            "lidersea-com",
        )
        self._write(
            "namespaces.json",
            {
                "items": [
                    {
                        "metadata": {"name": name, "uid": "namespace:" + name},
                        "status": {"phase": "Active"},
                    }
                    for name in namespace_names
                ]
            },
        )
        self._write(
            "nodes.json",
            {"items": [{"metadata": {"name": "pie", "uid": "node:pie"}}]},
        )

        deployment_contract = {
            ("naranjo-online", "naranjo-online"): (NARANJO_IMAGE, 2),
            ("lidersea-com", "lidersea-com"): (LIDERSEA_IMAGE, 2),
            ("cloudflare-public", "cloudflared"): (CLOUDFLARED_IMAGE, 2),
            ("kyverno", "kyverno-admission-controller"): (ADMISSION_IMAGE, 1),
            ("flux-system", "source-controller"): (FLUX_SOURCE_IMAGE, 1),
            ("flux-system", "kustomize-controller"): (FLUX_KUSTOMIZE_IMAGE, 1),
            ("flux-system", "helm-controller"): (FLUX_HELM_IMAGE, 1),
            ("kube-system", "coredns"): (COREDNS_IMAGE, 1),
            ("kube-system", "cilium-operator"): (CILIUM_OPERATOR_IMAGE, 1),
        }
        deployments = []
        deployment_by_identity = {}
        for (namespace, name), (image, replicas) in deployment_contract.items():
            capabilities = {
                "add": ["NET_BIND_SERVICE"]
                if (namespace, name) == ("kube-system", "coredns")
                else []
            }
            template = {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": capabilities,
                            },
                        }
                    ]
                },
            }
            item = {
                "metadata": {
                    "namespace": namespace,
                    "name": name,
                    "uid": self._uid("deployment", namespace, name),
                    "generation": 1,
                },
                "spec": {
                    "replicas": replicas,
                    "selector": {"matchLabels": {"app": name}},
                    "template": template,
                },
                "status": {
                    "observedGeneration": 1,
                    "replicas": replicas,
                    "updatedReplicas": replicas,
                    "readyReplicas": replicas,
                    "availableReplicas": replicas,
                },
            }
            deployments.append(item)
            deployment_by_identity[(namespace, name)] = item
        self._write("deployments.json", {"items": deployments})

        daemonsets = []
        daemonset_contract = {
            ("kube-system", "kube-proxy"): "registry.k8s.io/kube-proxy:"
            + KUBERNETES_VERSION,
            ("kube-system", "cilium"): CILIUM_IMAGE,
        }
        daemonset_by_identity = {}
        for (namespace, name), image in daemonset_contract.items():
            template = {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "hostNetwork": True,
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                            "securityContext": {"privileged": True},
                        }
                    ],
                },
            }
            item = {
                "metadata": {
                    "namespace": namespace,
                    "name": name,
                    "uid": self._uid("daemonset", namespace, name),
                    "generation": 1,
                },
                "spec": {"template": template},
                "status": {
                    "observedGeneration": 1,
                    "desiredNumberScheduled": 1,
                    "currentNumberScheduled": 1,
                    "updatedNumberScheduled": 1,
                    "numberReady": 1,
                    "numberAvailable": 1,
                    "numberMisscheduled": 0,
                },
            }
            daemonsets.append(item)
            daemonset_by_identity[(namespace, name)] = item
        self._write("daemonsets.json", {"items": daemonsets})

        for filename in (
            "statefulsets.json",
            "replicationcontrollers.json",
            "jobs.json",
            "cronjobs.json",
            "horizontalpodautoscalers.json",
        ):
            self._write(filename, {"items": []})

        replicasets = []
        pods = []
        for (namespace, name), deployment in deployment_by_identity.items():
            replica_count = deployment["spec"]["replicas"]
            replicaset_name = name + "-rshash"
            template = copy.deepcopy(deployment["spec"]["template"])
            template["metadata"]["labels"]["pod-template-hash"] = "rshash"
            selector = copy.deepcopy(deployment["spec"]["selector"])
            selector["matchLabels"]["pod-template-hash"] = "rshash"
            replicaset_uid = self._uid("replicaset", namespace, replicaset_name)
            replicasets.append(
                {
                    "metadata": {
                        "namespace": namespace,
                        "name": replicaset_name,
                        "uid": replicaset_uid,
                        "ownerReferences": [
                            {
                                "apiVersion": "apps/v1",
                                "kind": "Deployment",
                                "name": name,
                                "uid": deployment["metadata"]["uid"],
                                "controller": True,
                            }
                        ],
                    },
                    "spec": {
                        "replicas": replica_count,
                        "selector": selector,
                        "template": template,
                    },
                    "status": {
                        "replicas": replica_count,
                        "readyReplicas": replica_count,
                        "availableReplicas": replica_count,
                    },
                }
            )
            for index in range(replica_count):
                pod_name = "{}-{}".format(replicaset_name, index)
                pods.append(
                    {
                        "metadata": {
                            "namespace": namespace,
                            "name": pod_name,
                            "uid": self._uid("pod", namespace, pod_name),
                            "ownerReferences": [
                                {
                                    "apiVersion": "apps/v1",
                                    "kind": "ReplicaSet",
                                    "name": replicaset_name,
                                    "uid": replicaset_uid,
                                    "controller": True,
                                }
                            ],
                        },
                        "spec": copy.deepcopy(template["spec"]),
                        "status": self._ready_pod_status(),
                    }
                )
        self._write("replicasets.json", {"items": replicasets})

        for (namespace, name), daemonset in daemonset_by_identity.items():
            pod_name = name + "-pod"
            pods.append(
                {
                    "metadata": {
                        "namespace": namespace,
                        "name": pod_name,
                        "uid": self._uid("pod", namespace, pod_name),
                        "ownerReferences": [
                            {
                                "apiVersion": "apps/v1",
                                "kind": "DaemonSet",
                                "name": name,
                                "uid": daemonset["metadata"]["uid"],
                                "controller": True,
                            }
                        ],
                    },
                    "spec": copy.deepcopy(daemonset["spec"]["template"]["spec"]),
                    "status": self._ready_pod_status(),
                }
            )

        static_images = {
            "etcd": ETCD_IMAGE,
            "kube-apiserver": "registry.k8s.io/kube-apiserver:" + KUBERNETES_VERSION,
            "kube-controller-manager": "registry.k8s.io/kube-controller-manager:"
            + KUBERNETES_VERSION,
            "kube-scheduler": "registry.k8s.io/kube-scheduler:" + KUBERNETES_VERSION,
        }
        for component, image in static_images.items():
            name = component + "-pie"
            pods.append(
                {
                    "metadata": {
                        "namespace": "kube-system",
                        "name": name,
                        "uid": self._uid("pod", "kube-system", name),
                        "annotations": {"kubernetes.io/config.mirror": "mirror-hash"},
                        "ownerReferences": [
                            {
                                "apiVersion": "v1",
                                "kind": "Node",
                                "name": "pie",
                                "uid": "node:pie",
                                "controller": True,
                            }
                        ],
                    },
                    "spec": {
                        "nodeName": "pie",
                        "hostNetwork": True,
                        "containers": [
                            {
                                "name": component,
                                "image": image,
                                "securityContext": {"privileged": True},
                            }
                        ],
                    },
                    "status": self._ready_pod_status(),
                }
            )
        self._write("pods.json", {"items": pods})

        service_identities = (
            ("default", "kubernetes"),
            ("kube-system", "kube-dns"),
            ("flux-system", "source-controller"),
            ("kyverno", "kyverno-svc"),
            ("naranjo-online", "naranjo-online"),
            ("lidersea-com", "lidersea-com"),
        )
        self._write(
            "services.json",
            {
                "items": [
                    {
                        "metadata": {
                            "namespace": namespace,
                            "name": name,
                            "uid": self._uid("service", namespace, name),
                        },
                        "spec": {"type": "ClusterIP", "ports": [{"port": 443}]},
                    }
                    for namespace, name in service_identities
                ]
            },
        )
        self._write("mutatingwebhooks.json", {"items": []})
        self._write(
            "webhooks.json",
            {
                "items": [
                    {
                        "metadata": {
                            "name": "kyverno-resource-validating-webhook-cfg"
                        },
                        "webhooks": [
                            {
                                "failurePolicy": "Fail",
                                "clientConfig": {
                                    "service": {
                                        "namespace": "kyverno",
                                        "name": "kyverno-svc",
                                    }
                                },
                                "namespaceSelector": {
                                    "matchExpressions": [
                                        {
                                            "key": "kubernetes.io/metadata.name",
                                            "operator": "In",
                                            "values": [
                                                "cloudflare-public",
                                                "naranjo-online",
                                                "lidersea-com",
                                            ],
                                        }
                                    ]
                                },
                            }
                        ],
                    }
                ]
            },
        )

    def _run_validator(self, commit=COMMIT):
        return subprocess.run(
            [sys.executable, "-B", str(FLUX_EVIDENCE_VALIDATOR), str(self.root), commit],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def _run_global_validator(self):
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(INVENTORY_VALIDATOR),
                str(self.root),
                NARANJO_IMAGE,
                LIDERSEA_IMAGE,
                CLOUDFLARED_IMAGE,
                ADMISSION_IMAGE,
                FLUX_SOURCE_IMAGE,
                FLUX_KUSTOMIZE_IMAGE,
                FLUX_HELM_IMAGE,
                KUBERNETES_VERSION,
                COREDNS_IMAGE,
                ETCD_IMAGE,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def _assert_rejected(self):
        result = self._run_validator()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def _assert_global_rejected(self):
        result = self._run_global_validator()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_valid_exact_revision_and_policy_chain_passes(self):
        result = self._run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bound to exact local HEAD", result.stdout)

    def test_valid_exact_global_runtime_inventory_passes(self):
        result = self._run_global_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("global namespace, controller, Pod, Service", result.stdout)

    def test_extra_flux_inventory_object_fails_closed(self):
        fixtures = (
            ("kustomizations.json", "flux-system", "rogue-kustomization"),
            ("gitrepositories.json", "default", "rogue-source"),
            ("ocirepositories.json", "default", "rogue-chart-source"),
            ("ocirepositories.json", "naranjo-online", "second-chart-source"),
            ("helmreleases.json", "default", "rogue-release"),
            ("helmcharts.json", "default", "rogue-chart"),
        )
        for filename, namespace, name in fixtures:
            with self.subTest(filename=filename):
                self._write_valid_evidence()
                value = self._read(filename)
                value["items"].append(
                    {
                        "metadata": {
                            "namespace": namespace,
                            "name": name,
                            "generation": 1,
                        },
                        "status": {
                            "observedGeneration": 1,
                            "conditions": [ready_condition()],
                        },
                    }
                )
                self._write(filename, value)
                self._assert_rejected()

    def test_forbidden_flux_source_kind_fails_closed(self):
        fixtures = (
            "buckets.json",
            "externalartifacts.json",
            "helmrepositories.json",
        )
        for filename in fixtures:
            with self.subTest(filename=filename):
                self._write_valid_evidence()
                self._write(
                    filename,
                    {
                        "items": [
                            {
                                "metadata": {
                                    "namespace": "default",
                                    "name": "rogue-source",
                                }
                            }
                        ]
                    },
                )
                self._assert_rejected()

    def test_live_flux_spec_drift_fails_closed(self):
        mutations = (
            (
                "kustomizations.json",
                lambda item: item["spec"].update(
                    {"patches": [{"patch": "kind: Pod"}]}
                ),
            ),
            (
                "gitrepositories.json",
                lambda item: item["spec"].update(
                    {"proxySecretRef": {"name": "rogue-proxy"}}
                ),
            ),
            (
                "helmreleases.json",
                lambda item: item["spec"]["chartRef"].update(
                    {"name": "unreviewed-chart"}
                ),
            ),
            (
                "ocirepositories.json",
                lambda item: item["spec"]["ref"].update({"semver": ">=0.0.0"}),
            ),
            (
                "helmcharts.json",
                lambda item: item["spec"].update({"chart": "./unreviewed"}),
            ),
        )
        for filename, mutate in mutations:
            with self.subTest(filename=filename):
                self._write_valid_evidence()
                value = self._read(filename)
                mutate(value["items"][0])
                self._write(filename, value)
                self._assert_rejected()

    def test_extra_clusterpolicy_fails_closed(self):
        value = self._read("policies.json")
        value["items"].append(
            {
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {"name": "rogue-mutation-policy"},
                "spec": {"rules": []},
            }
        )
        self._write("policies.json", value)
        self._assert_rejected()

    def test_missing_kustomization_observed_generation_fails_closed(self):
        value = self._read("kustomizations.json")
        value["items"][0]["status"].pop("observedGeneration")
        self._write("kustomizations.json", value)
        self._assert_rejected()

    def test_stale_kustomization_attempt_fails_closed(self):
        value = self._read("kustomizations.json")
        value["items"][1]["status"]["lastAttemptedRevision"] = "main@sha1:" + "b" * 40
        self._write("kustomizations.json", value)
        self._assert_rejected()

    def test_stale_git_source_artifact_fails_closed(self):
        value = self._read("gitrepositories.json")
        value["items"][1]["status"]["artifact"]["revision"] = (
            "main@sha1:" + "b" * 40
        )
        self._write("gitrepositories.json", value)
        self._assert_rejected()

    def test_unverified_or_misattributed_chart_source_fails_closed(self):
        """Every way a live chart source could stop proving its publisher.

        This exercises the captured-evidence validator, not a running Flux
        controller: it proves the successor gate refuses evidence in which a
        site's chart could have come from an unsigned artifact or from the
        wrong signing identity.
        """

        other_subject = chart_subject("lidersea.com")
        mutations = {
            "verification removed": lambda item: item["spec"].pop("verify"),
            "provider downgraded": lambda item: item["spec"]["verify"].update(
                {"provider": "notation"}
            ),
            "keyless identity dropped": lambda item: item["spec"]["verify"].update(
                {"matchOIDCIdentity": []}
            ),
            "second identity widened": lambda item: item["spec"]["verify"][
                "matchOIDCIdentity"
            ].append({"issuer": CHART_ISSUER, "subject": other_subject}),
            "sibling site subject": lambda item: item["spec"]["verify"][
                "matchOIDCIdentity"
            ][0].update({"subject": other_subject}),
            "foreign issuer": lambda item: item["spec"]["verify"][
                "matchOIDCIdentity"
            ][0].update({"issuer": "^https://accounts\\.example\\.invalid$"}),
            "branch ref subject": lambda item: item["spec"]["verify"][
                "matchOIDCIdentity"
            ][0].update(
                {
                    "subject": (
                        r"^https://github\.com/snaraj/naranjo\.online/"
                        r"\.github/workflows/release-publisher\.yml"
                        r"@refs/heads/main$"
                    )
                }
            ),
            "registry credential": lambda item: item["spec"].update(
                {"secretRef": {"name": "ghcr-pull"}}
            ),
            "service account pull": lambda item: item["spec"].update(
                {"serviceAccountName": "puller"}
            ),
            "plaintext registry": lambda item: item["spec"].update({"insecure": True}),
            "registry path swap": lambda item: item["spec"].update(
                {"url": "oci://ghcr.io/snaraj/charts/lidersea-com"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                self._write_valid_evidence()
                value = self._read("ocirepositories.json")
                mutate(value["items"][0])
                self._write("ocirepositories.json", value)
                self._assert_rejected()

    def test_chart_artifact_without_tag_and_digest_fails_closed(self):
        mutations = {
            "tag only": lambda artifact: artifact.update({"revision": "v0.1.9"}),
            "digest only": lambda artifact: artifact.update(
                {"revision": artifact["digest"]}
            ),
            "unstable tag": lambda artifact: artifact.update(
                {"revision": "latest@" + artifact["digest"]}
            ),
            "digest disagrees with revision": lambda artifact: artifact.update(
                {"revision": "v0.1.9@sha256:" + "c" * 64}
            ),
            "all-zero digest": lambda artifact: artifact.update(
                {
                    "revision": "v0.1.9@sha256:" + "0" * 64,
                    "digest": "sha256:" + "0" * 64,
                }
            ),
            "artifact absent": lambda artifact: artifact.clear(),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                self._write_valid_evidence()
                value = self._read("ocirepositories.json")
                mutate(value["items"][0]["status"]["artifact"])
                self._write("ocirepositories.json", value)
                self._assert_rejected()

    def test_site_release_not_bound_to_its_own_chart_source_fails_closed(self):
        mutations = {
            "cross-site chart source": lambda item: item["spec"]["chartRef"].update(
                {"name": "lidersea-com-chart"}
            ),
            "helm chart reintroduced": lambda item: item["status"].update(
                {"helmChart": "naranjo-online/naranjo-online-naranjo-online"}
            ),
            "deployed version is not the resolved one": lambda item: (
                item["status"].update({"lastAttemptedRevision": "v0.1.8"}),
                item["status"]["history"][0].update({"chartVersion": "v0.1.8"}),
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                self._write_valid_evidence()
                value = self._read("helmreleases.json")
                mutate(value["items"][0])
                self._write("helmreleases.json", value)
                self._assert_rejected()

    def test_missing_helmrelease_observed_generation_fails_closed(self):
        value = self._read("helmreleases.json")
        value["items"][0]["status"].pop("observedGeneration")
        self._write("helmreleases.json", value)
        self._assert_rejected()

    def test_unapplied_helmrelease_attempt_fails_closed(self):
        value = self._read("helmreleases.json")
        value["items"][0]["status"]["history"][0]["chartVersion"] = "older"
        self._write("helmreleases.json", value)
        self._assert_rejected()

    def test_stale_helmchart_source_revision_fails_closed(self):
        value = self._read("helmcharts.json")
        value["items"][0]["status"]["observedSourceArtifactRevision"] = (
            "main@sha1:" + "b" * 40
        )
        self._write("helmcharts.json", value)
        self._assert_rejected()

    def test_duplicate_ready_condition_fails_closed(self):
        value = self._read("kustomizations.json")
        value["items"][0]["status"]["conditions"].append(ready_condition())
        self._write("kustomizations.json", value)
        self._assert_rejected()

    def test_live_policy_spec_drift_fails_closed(self):
        value = self._read("policies.json")
        value["items"][0]["spec"]["rules"] = []
        self._write("policies.json", value)
        self._assert_rejected()

    def test_live_network_policy_spec_drift_fails_closed(self):
        value = self._read("networkpolicies.json")
        value["items"][0]["spec"]["egress"] = [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]
        self._write("networkpolicies.json", value)
        self._assert_rejected()

    def test_noncanonical_commit_fails_closed(self):
        result = self._run_validator("a" * 39)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rogue_namespace_fails_closed(self):
        value = self._read("namespaces.json")
        value["items"].append(
            {
                "metadata": {"name": "rogue", "uid": "namespace:rogue"},
                "status": {"phase": "Active"},
            }
        )
        self._write("namespaces.json", value)
        self._assert_global_rejected()

    def test_rogue_deployment_outside_allowlist_fails_closed(self):
        value = self._read("deployments.json")
        rogue = copy.deepcopy(value["items"][0])
        rogue["metadata"].update(
            {"namespace": "default", "name": "rogue", "uid": "deployment:default:rogue"}
        )
        self._write("deployments.json", {"items": value["items"] + [rogue]})
        self._assert_global_rejected()

    def test_rogue_controller_kind_fails_closed(self):
        for filename in (
            "statefulsets.json",
            "replicationcontrollers.json",
            "jobs.json",
            "cronjobs.json",
            "horizontalpodautoscalers.json",
        ):
            with self.subTest(filename=filename):
                self._write_valid_global_evidence()
                self._write(
                    filename,
                    {
                        "items": [
                            {
                                "metadata": {
                                    "namespace": "default",
                                    "name": "rogue",
                                    "uid": filename + ":rogue",
                                }
                            }
                        ]
                    },
                )
                self._assert_global_rejected()

    def test_unowned_privileged_pod_fails_closed(self):
        value = self._read("pods.json")
        rogue = copy.deepcopy(value["items"][0])
        rogue["metadata"].update(
            {"namespace": "default", "name": "rogue", "uid": "pod:default:rogue"}
        )
        rogue["metadata"].pop("ownerReferences", None)
        rogue["spec"]["containers"][0]["securityContext"]["privileged"] = True
        self._write("pods.json", {"items": value["items"] + [rogue]})
        self._assert_global_rejected()

    def test_owned_pod_privilege_and_host_exposure_fail_closed(self):
        mutations = (
            lambda pod: pod["spec"].update({"hostNetwork": True}),
            lambda pod: pod["spec"].update({"hostPID": True}),
            lambda pod: pod["spec"]["containers"][0]["securityContext"].update(
                {"privileged": True}
            ),
            lambda pod: pod["spec"]["containers"][0].update(
                {"ports": [{"containerPort": 8080, "hostPort": 18080}]}
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self._write_valid_global_evidence()
                value = self._read("pods.json")
                mutate(value["items"][0])
                self._write("pods.json", value)
                self._assert_global_rejected()

    def test_forged_active_replicaset_fails_closed(self):
        value = self._read("replicasets.json")
        rogue = copy.deepcopy(value["items"][0])
        rogue["metadata"].update(
            {
                "name": "naranjo-online-evilhash",
                "uid": "replicaset:naranjo-online:naranjo-online-evilhash",
            }
        )
        rogue["spec"]["selector"]["matchLabels"]["pod-template-hash"] = "evilhash"
        rogue["spec"]["template"]["metadata"]["labels"][
            "pod-template-hash"
        ] = "evilhash"
        self._write("replicasets.json", {"items": value["items"] + [rogue]})
        self._assert_global_rejected()

    def test_extra_compliant_owned_pod_fails_closed(self):
        value = self._read("pods.json")
        rogue = copy.deepcopy(value["items"][0])
        rogue["metadata"].update(
            {
                "name": rogue["metadata"]["name"] + "-extra",
                "uid": rogue["metadata"]["uid"] + ":extra",
            }
        )
        self._write("pods.json", {"items": value["items"] + [rogue]})
        self._assert_global_rejected()

    def test_service_inventory_and_exposure_fields_fail_closed(self):
        mutations = (
            lambda service: service["spec"].update({"type": "NodePort"}),
            lambda service: service["spec"].update({"type": "LoadBalancer"}),
            lambda service: service["spec"].update({"externalIPs": ["192.0.2.50"]}),
            lambda service: service["spec"]["ports"][0].update({"nodePort": 30080}),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self._write_valid_global_evidence()
                value = self._read("services.json")
                mutate(value["items"][0])
                self._write("services.json", value)
                self._assert_global_rejected()

        self._write_valid_global_evidence()
        value = self._read("services.json")
        value["items"].append(
            {
                "metadata": {
                    "namespace": "default",
                    "name": "rogue-clusterip",
                    "uid": "service:default:rogue-clusterip",
                },
                "spec": {"type": "ClusterIP", "ports": [{"port": 8080}]},
            }
        )
        self._write("services.json", value)
        self._assert_global_rejected()

    def test_mutating_webhook_fails_closed(self):
        self._write(
            "mutatingwebhooks.json",
            {"items": [{"metadata": {"name": "rogue-mutator"}}]},
        )
        self._assert_global_rejected()

    def test_shell_binds_and_rechecks_clean_head_around_live_reads(self):
        self.assertIn("before_commit=", self.clean_commit)
        self.assertIn("after_commit=", self.clean_commit)
        self.assertIn("status_output=", self.clean_commit)
        self.assertIn("release worktree status could not be read", self.clean_commit)
        self.assertIn("RELEASE_GIT_COMMIT", self.clean_commit)
        # The local Kind runtime stage retired with the embedded site sources;
        # both runtime lanes must die fail-closed before any production read
        # until their post-cutover successor lands.
        self.assertNotIn("test-kind.sh", self.script)
        self.assertIn(
            "transition runtime evidence is PENDING its post-cutover successor",
            self.script,
        )
        self.assertIn("live gate is PENDING its post-cutover successor", self.live)
        # The stub may not read live state, mutate anything, or reach GO.
        for forbidden in (
            "require_live_tools",
            "kubectl",
            "capture_production_state",
            "verify-exposure.sh",
            "GO:",
        ):
            self.assertNotIn(forbidden, self.live)
        # The stub must hand the successor its surviving executable validators.
        self.assertIn("validate_flux_release_evidence.py", self.live)
        self.assertIn("validate_runtime_inventory_evidence.py", self.live)

    def test_retired_live_machinery_is_fully_absent_from_the_shell(self):
        # The captured-evidence validators moved to standalone executable
        # programs; no orphaned live-capture shell may linger where it could
        # be resurrected without review.
        for retired in (
            "capture_production_state",
            "capture_desired_security_policy_state",
            "capture_prod_json",
            "assert_production_state",
            "assert_global_runtime_inventory",
            "assert_flux_revision_and_security_policy_state",
            "desired_deployment_image",
            "exercise_production_admission",
            "write_admission_fixtures",
            "assert_no_live_routes",
            "new_temp_root",
            "--dry-run=server",
        ):
            self.assertNotIn(retired, self.script)
        self.assertNotIn("websites/naranjo.online", self.script)
        self.assertNotIn("websites/lidersea.com", self.script)
        self.assertNotIn("helm-naranjo-online.yaml", self.script)
        self.assertNotIn("helm-lidersea-com.yaml", self.script)
        # Both standalone validators stay wired for the successor and refuse
        # short argv rather than passing vacuously.
        for validator in (FLUX_EVIDENCE_VALIDATOR, INVENTORY_VALIDATOR):
            self.assertTrue(validator.is_file())
            result = subprocess.run(
                [sys.executable, "-B", str(validator)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
