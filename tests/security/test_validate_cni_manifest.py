#!/usr/bin/env python3
import hashlib
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_cni_manifest.py"
SPEC = importlib.util.spec_from_file_location("validate_cni_manifest", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DIGEST = "a" * 64


def cilium_manifest(tunnel="vxlan"):
    routing = """\
  routing-mode: tunnel
  tunnel-protocol: {tunnel}
  tunnel-port: \"{port}\"""".format(
        tunnel=tunnel, port="8472" if tunnel == "vxlan" else "6081"
    )
    if tunnel == "native":
        routing = """\
  routing-mode: native
  ipv4-native-routing-cidr: 10.42.0.0/16"""
    return """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  ipam: cluster-pool
  cluster-pool-ipv4-cidr: 10.42.0.0/16
  mtu: "1450"
  kube-proxy-replacement: "false"
  enable-node-port: "false"
  bpf-lb-sock: "false"
  enable-policy: default
{routing}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cilium
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: cilium-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: cilium-agent
    spec:
      containers:
        - name: cilium-agent
          image: quay.io/cilium/cilium:v1.20.0@sha256:{digest}
          imagePullPolicy: IfNotPresent
""".format(routing=routing, digest=DIGEST)


def calico_manifest(tunnel="vxlan"):
    ipip, vxlan = {
        "vxlan": ("Never", "Always"),
        "ipip": ("Always", "Never"),
        "bgp": ("Never", "Never"),
    }[tunnel]
    backend = "vxlan" if tunnel == "vxlan" else "bird"
    vxlan_port = """\
            - name: FELIX_VXLANPORT
              value: "4789"
""" if tunnel == "vxlan" else ""
    return """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: calico-config
  namespace: kube-system
data:
  calico_backend: {backend}
  veth_mtu: "1450"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  template:
    metadata:
      labels:
        k8s-app: calico-node
    spec:
      containers:
        - name: calico-node
          image: docker.io/calico/node:v3.32.0@sha256:{digest}
          imagePullPolicy: IfNotPresent
          env:
            - name: CALICO_IPV4POOL_CIDR
              value: 10.42.0.0/16
            - name: CALICO_IPV4POOL_IPIP
              value: {ipip}
            - name: CALICO_IPV4POOL_VXLAN
              value: {vxlan}
            - name: FELIX_BPFENABLED
              value: "false"
{vxlan_port}""".format(
        backend=backend, digest=DIGEST, ipip=ipip, vxlan=vxlan,
        vxlan_port=vxlan_port,
    )


def decisions(manifest, provider="cilium", tunnel="vxlan", **overrides):
    values = {
        "POD_CIDR": "10.42.0.0/16",
        "KUBE_PROXY_OPERATION": "installed",
        "CNI_PROVIDER": provider,
        "CNI_VERSION": "v1.20.0" if provider == "cilium" else "v3.32.0",
        "CNI_DATAPLANE": "kube-proxy",
        "CNI_TUNNEL_MODE": tunnel,
        "CNI_MTU": "1450",
        "CNI_HOST_NETWORK_REQUIREMENTS": MODULE.HOST_REQUIREMENTS[(provider, tunnel)],
        "CNI_MANIFEST_SHA256": hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
        "CNI_NETWORK_POLICY_PROVEN": "yes",
    }
    values.update(overrides)
    return "\n".join("{}={}".format(key, value) for key, value in values.items()) + "\n"


class CniManifestTests(unittest.TestCase):
    def assert_rejected(self, manifest, decision_text, fragment):
        errors = MODULE.validate(manifest, decision_text)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_accepts_all_reviewed_provider_tunnel_pairs(self):
        for tunnel in ("vxlan", "geneve", "native"):
            manifest = cilium_manifest(tunnel)
            with self.subTest(provider="cilium", tunnel=tunnel):
                self.assertEqual(MODULE.validate(manifest, decisions(manifest, tunnel=tunnel)), [])
        for tunnel in ("vxlan", "ipip", "bgp"):
            manifest = calico_manifest(tunnel)
            with self.subTest(provider="calico", tunnel=tunnel):
                self.assertEqual(MODULE.validate(
                    manifest, decisions(manifest, provider="calico", tunnel=tunnel)
                ), [])

    def test_rejects_provider_and_opposite_provider_drift(self):
        manifest = cilium_manifest()
        self.assert_rejected(
            manifest, decisions(manifest, CNI_PROVIDER="calico", CNI_VERSION="v3.32.0"),
            "opposite-provider",
        )
        mixed = manifest + """\
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: calico-junk
  namespace: kube-system
"""
        self.assert_rejected(mixed, decisions(mixed), "opposite-provider")

    def test_rejects_alternate_provider_configuration_sources(self):
        manifest = calico_manifest() + """\
---
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: conflicting-pool
spec:
  cidr: 10.99.0.0/16
  vxlanMode: Never
"""
        self.assert_rejected(
            manifest, decisions(manifest, provider="calico"), "alternate provider",
        )
        manifest = cilium_manifest() + """\
---
apiVersion: cilium.io/v2alpha1
kind: CiliumNodeConfig
metadata:
  name: conflicting-node-config
spec:
  defaults:
    kube-proxy-replacement: "true"
"""
        self.assert_rejected(manifest, decisions(manifest), "alternate provider")

    def test_rejects_injected_load_balancer_service_with_external_ips(self):
        manifest = cilium_manifest() + """\
---
apiVersion: v1
kind: Service
metadata:
  name: attacker-public
  namespace: kube-system
spec:
  type: LoadBalancer
  externalIPs:
    - 203.0.113.10
  selector:
    app: attacker
  ports:
    - port: 443
      targetPort: 8443
"""
        self.assert_rejected(manifest, decisions(manifest), "resource contract")

    def test_rejects_unapproved_resource_classes_and_names(self):
        additions = {
            "Namespace": """\
apiVersion: v1
kind: Namespace
metadata:
  name: attacker
""",
            "Secret": """\
apiVersion: v1
kind: Secret
metadata:
  name: cilium-secrets
  namespace: kube-system
type: Opaque
""",
            "workload": """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unrelated-controller
  namespace: kube-system
spec: {}
""",
            "ConfigMap": """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated-config
  namespace: kube-system
data: {}
""",
        }
        for label, addition in additions.items():
            manifest = cilium_manifest() + "---\n" + addition
            with self.subTest(resource=label):
                self.assert_rejected(manifest, decisions(manifest), "resource contract")

    def test_enforces_exact_api_version_name_namespace_and_unique_identity(self):
        drifts = {
            "apiVersion": cilium_manifest().replace("apiVersion: v1", "apiVersion: v2", 1),
            "name": cilium_manifest().replace("name: cilium-config", "name: cilium-config-copy", 1),
            "namespace": cilium_manifest().replace(
                "namespace: kube-system", "namespace: default", 1
            ),
            "missing-apiVersion": cilium_manifest().replace("apiVersion: v1\n", "", 1),
            "missing-name": cilium_manifest().replace("  name: cilium-config\n", "", 1),
        }
        for label, manifest in drifts.items():
            with self.subTest(field=label):
                fragment = "document" if label.startswith("missing") else "resource contract"
                self.assert_rejected(manifest, decisions(manifest), fragment)

        canonical_rbac = """\
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cilium
rules: []
"""
        manifest = cilium_manifest() + canonical_rbac
        self.assertEqual(MODULE.validate(manifest, decisions(manifest)), [])
        namespaced = manifest.replace(
            "  name: cilium\nrules: []",
            "  name: cilium\n  namespace: kube-system\nrules: []",
        )
        self.assert_rejected(namespaced, decisions(namespaced), "resource contract")
        duplicate = manifest + canonical_rbac
        self.assert_rejected(duplicate, decisions(duplicate), "more than once")

    def test_optional_provider_stacks_remain_outside_raw_manifest_contract(self):
        # Hubble Services and Tigera Operator Namespace ownership are useful but
        # deliberately unsupported here; each needs a separate reviewed contract.
        cilium = cilium_manifest() + """\
---
apiVersion: v1
kind: Service
metadata:
  name: hubble-peer
  namespace: kube-system
spec:
  clusterIP: None
"""
        self.assert_rejected(cilium, decisions(cilium), "resource contract")
        calico = calico_manifest() + """\
---
apiVersion: v1
kind: Namespace
metadata:
  name: calico-system
"""
        self.assert_rejected(
            calico, decisions(calico, provider="calico"), "resource contract",
        )

    def test_rejects_kube_proxy_replacement_and_calico_bpf(self):
        manifest = cilium_manifest().replace(
            'kube-proxy-replacement: "false"', 'kube-proxy-replacement: "true"'
        )
        self.assert_rejected(manifest, decisions(manifest), "replacement")
        manifest = calico_manifest().replace('value: "false"', 'value: "true"')
        self.assert_rejected(
            manifest, decisions(manifest, provider="calico"), "BPF",
        )

    def test_rejects_version_cidr_mtu_and_tunnel_drift(self):
        manifest = cilium_manifest().replace("cilium:v1.20.0", "cilium:v1.20.1")
        self.assert_rejected(manifest, decisions(manifest), "CNI_VERSION")
        manifest = cilium_manifest().replace(
            "cluster-pool-ipv4-cidr: 10.42.0.0/16",
            "cluster-pool-ipv4-cidr: 10.44.0.0/16",
        )
        self.assert_rejected(manifest, decisions(manifest), "cluster-pool-ipv4-cidr")
        manifest = calico_manifest().replace('veth_mtu: "1450"', 'veth_mtu: "1500"')
        self.assert_rejected(
            manifest, decisions(manifest, provider="calico"), "veth_mtu",
        )
        manifest = cilium_manifest("geneve").replace("tunnel-protocol: geneve", "tunnel-protocol: vxlan")
        self.assert_rejected(manifest, decisions(manifest, tunnel="geneve"), "tunnel-protocol")

    def test_rejects_incoherent_host_requirement(self):
        manifest = cilium_manifest()
        decision_text = decisions(manifest, CNI_HOST_NETWORK_REQUIREMENTS="udp:6081")
        self.assert_rejected(manifest, decision_text, "CNI_HOST_NETWORK_REQUIREMENTS")

    def test_rejects_mutable_images_and_pull_policy(self):
        manifest = cilium_manifest().replace("@sha256:" + DIGEST, "")
        self.assert_rejected(manifest, decisions(manifest), "immutable digest")
        manifest = cilium_manifest().replace("imagePullPolicy: IfNotPresent", "imagePullPolicy: Always")
        self.assert_rejected(manifest, decisions(manifest), "imagePullPolicy")
        spoofed = cilium_manifest().replace(
            "          imagePullPolicy: IfNotPresent\n", ""
        ).replace(
            "  enable-policy: default\n",
            "  enable-policy: default\n  imagePullPolicy: IfNotPresent\n",
        )
        self.assert_rejected(spoofed, decisions(spoofed), "sibling imagePullPolicy")

    def test_rejects_duplicate_calico_env_even_when_shadow_uses_value_from(self):
        manifest = calico_manifest().replace(
            '            - name: FELIX_BPFENABLED\n              value: "false"',
            '            - name: FELIX_BPFENABLED\n              value: "false"\n'
            '            - name: FELIX_BPFENABLED\n'
            '              valueFrom:\n'
            '                configMapKeyRef:\n'
            '                  name: attacker\n'
            '                  key: bpf',
        )
        self.assert_rejected(
            manifest, decisions(manifest, provider="calico"), "must occur once",
        )

    def test_rejects_missing_fields_sentinels_and_duplicate_decisions(self):
        manifest = cilium_manifest().replace('  mtu: "1450"\n', "")
        self.assert_rejected(manifest, decisions(manifest), "mtu")
        manifest = cilium_manifest().replace("10.42.0.0/16", "REPLACE_POD_CIDR")
        self.assert_rejected(manifest, decisions(manifest), "sentinel")
        manifest = cilium_manifest()
        duplicate = decisions(manifest) + "CNI_PROVIDER=cilium\n"
        self.assert_rejected(manifest, duplicate, "more than once")

    def test_rejects_manifest_hash_drift_and_comment_spoofing(self):
        manifest = cilium_manifest()
        decision_text = decisions(manifest)
        changed = manifest + "# post-review change\n"
        self.assert_rejected(changed, decision_text, "SHA-256")
        spoofed = calico_manifest() + "# cilium-config kube-proxy-replacement: false\n"
        self.assert_rejected(
            spoofed, decisions(spoofed, provider="cilium"), "DaemonSet/cilium",
        )
        commented = cilium_manifest() + "# projectcalico.org is not a live marker\n"
        self.assertEqual(MODULE.validate(commented, decisions(commented)), [])


if __name__ == "__main__":
    unittest.main()
