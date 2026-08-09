#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_kubeadm_config.py"
SPEC = importlib.util.spec_from_file_location("validate_kubeadm_config", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


VALID_CONFIG = """\
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 192.168.50.10
  bindPort: 6443
nodeRegistration:
  name: pi-control
  criSocket: unix:///run/containerd/containerd.sock
  taints: []
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v1.36.3
imageRepository: registry.k8s.io
controlPlaneEndpoint: 192.168.50.10:6443
networking:
  dnsDomain: cluster.local
  podSubnet: 10.42.0.0/16
  serviceSubnet: 10.43.0.0/16
etcd:
  local:
    dataDir: /var/lib/etcd
apiServer:
  extraArgs:
    - name: admission-control-config-file
      value: /etc/kubernetes/admission/psa.yaml
    - name: audit-policy-file
      value: /etc/kubernetes/audit/audit-policy.yaml
    - name: audit-log-path
      value: /var/log/kubernetes/audit/audit.log
    - name: audit-log-maxage
      value: 30
    - name: audit-log-maxbackup
      value: 10
    - name: audit-log-maxsize
      value: 100
    - name: encryption-provider-config
      value: /etc/kubernetes/encryption/encryption-config.yaml
    - name: encryption-provider-config-automatic-reload
      value: true
    - name: service-account-extend-token-expiration
      value: false
  extraVolumes:
    - name: psa-config
      hostPath: /etc/kubernetes/admission/psa.yaml
      mountPath: /etc/kubernetes/admission/psa.yaml
      readOnly: true
      pathType: File
    - name: audit-policy
      hostPath: /etc/kubernetes/audit/audit-policy.yaml
      mountPath: /etc/kubernetes/audit/audit-policy.yaml
      readOnly: true
      pathType: File
    - name: audit-log
      hostPath: /var/log/kubernetes/audit
      mountPath: /var/log/kubernetes/audit
      readOnly: false
      pathType: DirectoryOrCreate
    - name: encryption-config
      hostPath: /etc/kubernetes/encryption/encryption-config.yaml
      mountPath: /etc/kubernetes/encryption/encryption-config.yaml
      readOnly: true
      pathType: File
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
failSwapOn: true
failCgroupV1: true
protectKernelDefaults: true
readOnlyPort: 0
rotateCertificates: true
seccompDefault: true
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: nftables
detectLocalMode: ClusterCIDR
clusterCIDR: 10.42.0.0/16
"""

# Resolve the checked-in template so the positive fixture exercises every
# field that operators will actually use on the Pi.
TEMPLATE = Path(__file__).resolve().parents[2] / "bootstrap" / "pi" / "kubeadm-config.yaml.example"
VALID_CONFIG = TEMPLATE.read_text(encoding="utf-8")
for sentinel, value in {
    "REPLACE_PI_STABLE_PRIVATE_IP": "192.168.50.10",
    "REPLACE_PI_NODE_NAME": "pi-control",
    "REPLACE_PI_PRIVATE_KUBERNETES_HOSTNAME": "pi-control.home.arpa",
    "REPLACE_CONFLICT_CHECKED_POD_CIDR": "10.42.0.0/16",
    "REPLACE_CONFLICT_CHECKED_SERVICE_CIDR": "10.43.0.0/16",
    "REPLACE_REVIEWED_PROXY_MODE": "nftables",
}.items():
    VALID_CONFIG = VALID_CONFIG.replace(sentinel, value)


class KubeadmConfigTests(unittest.TestCase):
    def assert_rejected(self, config, fragment):
        errors = MODULE.validate(config)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_accepts_exact_reviewed_contract(self):
        self.assertEqual(MODULE.validate(VALID_CONFIG), [])

    def test_accepts_explicit_iptables_mode(self):
        self.assertEqual(MODULE.validate(VALID_CONFIG.replace("mode: nftables", "mode: iptables")), [])

    def test_rejects_runtime_version_endpoint_and_taints_drift(self):
        self.assert_rejected(VALID_CONFIG.replace(MODULE.CRI_SOCKET, "unix:///var/run/cri-dockerd.sock"), "criSocket")
        self.assert_rejected(VALID_CONFIG.replace("v1.36.3", "v1.36.2"), "kubernetesVersion")
        self.assert_rejected(VALID_CONFIG.replace("controlPlaneEndpoint: 192.168.50.10:6443",
                                                  "controlPlaneEndpoint: 192.168.50.11:6443"),
                             "controlPlaneEndpoint")
        self.assert_rejected(VALID_CONFIG.replace("taints: []", "taints:\n    - key: node-role.kubernetes.io/control-plane"),
                             "taints")

    def test_rejects_public_or_overlapping_networks(self):
        self.assert_rejected(VALID_CONFIG.replace("192.168.50.10", "8.8.8.8"), "RFC1918")
        self.assert_rejected(VALID_CONFIG.replace("serviceSubnet: 10.43.0.0/16", "serviceSubnet: 10.42.0.0/17"),
                             "must not overlap")
        self.assert_rejected(VALID_CONFIG.replace("podSubnet: 10.42.0.0/16", "podSubnet: 10.42.1.0/16"),
                             "canonical RFC1918")

    def test_rejects_external_or_moved_etcd(self):
        self.assert_rejected(VALID_CONFIG.replace("dataDir: /var/lib/etcd", "dataDir: /srv/etcd"), "etcd.local")
        external = VALID_CONFIG.replace("  local:\n    dataDir: /var/lib/etcd",
                                        "  external:\n    endpoints:\n      - https://192.168.50.20:2379")
        self.assert_rejected(external, "stacked local")

    def test_rejects_api_server_security_weakening(self):
        self.assert_rejected(VALID_CONFIG.replace("encryption-provider-config-automatic-reload\n      value: \"true\"",
                                                  "encryption-provider-config-automatic-reload\n      value: \"false\""),
                             "extraArgs")
        self.assert_rejected(VALID_CONFIG.replace("mountPath: /var/log/kubernetes/audit\n      readOnly: false",
                                                  "mountPath: /var/log/kubernetes/audit\n      readOnly: true"),
                             "extraVolumes")
        self.assert_rejected(VALID_CONFIG.replace("audit-log-maxage\n      value: \"30\"",
                                                  "audit-log-maxage\n      value: \"1\""),
                             "extraArgs")

    def test_rejects_kubelet_and_proxy_security_weakening(self):
        self.assert_rejected(VALID_CONFIG.replace("readOnlyPort: 0", "readOnlyPort: 10255"), "readOnlyPort")
        self.assert_rejected(VALID_CONFIG.replace("anonymous:\n    enabled: false", "anonymous:\n    enabled: true"),
                             "authentication.anonymous")
        self.assert_rejected(VALID_CONFIG.replace("detectLocalMode: ClusterCIDR", "detectLocalMode: BridgeInterface"),
                             "detectLocalMode")
        self.assert_rejected(VALID_CONFIG.replace("mode: nftables", "mode: ipvs"), "mode")

    def test_rejects_unreviewed_security_fields(self):
        self.assert_rejected(
            VALID_CONFIG.replace("imagePullPolicy: IfNotPresent", "imagePullPolicy: Always"),
            "imagePullPolicy",
        )

        always_allow = VALID_CONFIG.replace(
            "    - name: node-ip\n      value: 192.168.50.10",
            "    - name: node-ip\n      value: 192.168.50.10\n"
            "    - name: authorization-mode\n      value: AlwaysAllow",
        )
        self.assert_rejected(always_allow, "kubeletExtraArgs")

        exposed_etcd = VALID_CONFIG.replace(
            "      - name: quota-backend-bytes\n        value: \"8589934592\"",
            "      - name: quota-backend-bytes\n        value: \"8589934592\"\n"
            "      - name: listen-client-urls\n        value: http://0.0.0.0:2379",
        )
        self.assert_rejected(exposed_etcd, "etcd.local.extraArgs")

        exposed_controller = VALID_CONFIG.replace(
            "apiServer:\n",
            "controllerManager:\n  extraArgs:\n"
            "    - name: bind-address\n      value: 0.0.0.0\napiServer:\n",
        )
        self.assert_rejected(exposed_controller, "unexpected controllerManager")

    def test_rejects_sentinels_ignored_preflights_and_duplicate_documents(self):
        self.assert_rejected(VALID_CONFIG.replace("pi-control", "REPLACE_PI_NODE"), "sentinel")
        self.assert_rejected(VALID_CONFIG.replace("  taints: []", "  taints: []\n  ignorePreflightErrors: []"),
                             "preflight")
        duplicate = VALID_CONFIG + "---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\n"
        self.assert_rejected(duplicate, "duplicate InitConfiguration")


if __name__ == "__main__":
    unittest.main()
