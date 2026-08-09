#!/usr/bin/env python3
"""Validate this repository's pinned, multi-document kubeadm configuration.

The bootstrap host deliberately does not need PyYAML.  This module accepts only
the small, indentation-based YAML subset used by the reviewed kubeadm template;
unsupported YAML features fail closed instead of being interpreted loosely.
"""

import argparse
import ipaddress
import re
import sys
from pathlib import Path


# These pins join kubeadm to the locally installed containerd runtime and exact
# upstream Kubernetes release; bootstrap must not drift to host defaults.
CRI_SOCKET = "unix:///run/containerd/containerd.sock"
KUBERNETES_VERSION = "v1.36.3"
IMAGE_REPOSITORY = "registry.k8s.io"

# API_SERVER_ARGS is the reviewed control-plane hardening contract: PSA, audit,
# at-rest encryption, and bounded service-account tokens are all mandatory.
API_SERVER_ARGS = {
    "admission-control-config-file": "/etc/kubernetes/admission/psa.yaml",
    "audit-policy-file": "/etc/kubernetes/audit/audit-policy.yaml",
    "audit-log-path": "/var/log/kubernetes/audit/audit.log",
    "audit-log-maxage": "30",
    "audit-log-maxbackup": "10",
    "audit-log-maxsize": "100",
    "encryption-provider-config": "/etc/kubernetes/encryption/encryption-config.yaml",
    "encryption-provider-config-automatic-reload": "true",
    "service-account-extend-token-expiration": "false",
}

# API_SERVER_VOLUMES makes every hardening file available to the static Pod with
# the narrowest mount mode, leaving only the audit directory writable.
API_SERVER_VOLUMES = {
    "psa-config": {
        "hostPath": "/etc/kubernetes/admission/psa.yaml",
        "mountPath": "/etc/kubernetes/admission/psa.yaml",
        "readOnly": "true",
        "pathType": "File",
    },
    "audit-policy": {
        "hostPath": "/etc/kubernetes/audit/audit-policy.yaml",
        "mountPath": "/etc/kubernetes/audit/audit-policy.yaml",
        "readOnly": "true",
        "pathType": "File",
    },
    "audit-log": {
        "hostPath": "/var/log/kubernetes/audit",
        "mountPath": "/var/log/kubernetes/audit",
        "readOnly": "false",
        "pathType": "DirectoryOrCreate",
    },
    "encryption-config": {
        "hostPath": "/etc/kubernetes/encryption/encryption-config.yaml",
        "mountPath": "/etc/kubernetes/encryption/encryption-config.yaml",
        "readOnly": "true",
        "pathType": "File",
    },
}

# ETCD_ARGS keeps the single-node stacked store compact and bounded enough for Pi
# storage while preserving an explicit local maintenance policy.
ETCD_ARGS = {
    "auto-compaction-mode": "periodic",
    "auto-compaction-retention": "1h",
    "quota-backend-bytes": "8589934592",
}

# DOCUMENT_KEYS rejects surprise kubeadm fields rather than accepting a setting
# this repository does not validate or know how to recover.
DOCUMENT_KEYS = {
    "InitConfiguration": {
        "apiVersion", "kind", "localAPIEndpoint", "nodeRegistration",
    },
    "ClusterConfiguration": {
        "apiVersion", "kind", "clusterName", "kubernetesVersion",
        "controlPlaneEndpoint", "imageRepository", "certificatesDir",
        "networking", "apiServer", "etcd",
    },
    "KubeletConfiguration": {
        "apiVersion", "kind", "cgroupDriver", "failSwapOn", "failCgroupV1",
        "protectKernelDefaults", "readOnlyPort", "authentication",
        "authorization", "rotateCertificates", "seccompDefault",
        "serverTLSBootstrap", "enforceNodeAllocatable", "containerLogMaxFiles",
        "containerLogMaxSize",
    },
    "KubeProxyConfiguration": {
        "apiVersion", "kind", "mode", "clusterCIDR", "detectLocalMode",
    },
}

# EXPECTED_DOCUMENTS is the exact four-document upstream kubeadm API surface used
# to initialize the node, cluster, kubelet, and retained kube-proxy.
EXPECTED_DOCUMENTS = {
    "InitConfiguration": "kubeadm.k8s.io/v1beta4",
    "ClusterConfiguration": "kubeadm.k8s.io/v1beta4",
    "KubeletConfiguration": "kubelet.config.k8s.io/v1beta1",
    "KubeProxyConfiguration": "kubeproxy.config.k8s.io/v1alpha1",
}

# Cluster and API addressing stays in private IPv4 space and is later checked
# against the Pi's live routes before kubeadm may run.
RFC1918 = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class ConfigSyntaxError(ValueError):
    """The input is outside the intentionally supported YAML subset."""


# _strip_scalar accepts only the scalar and empty-list shapes present in the
# reviewed template, rejecting comments or quoting ambiguity early.
def _strip_scalar(raw, line_number):
    value = raw.strip()
    if value == "[]":
        return []
    if not value:
        raise ConfigSyntaxError("empty scalar at line {}".format(line_number))
    if value[0:1] in ("'", '"'):
        if len(value) < 2 or value[-1] != value[0]:
            raise ConfigSyntaxError("unterminated quoted scalar at line {}".format(line_number))
        value = value[1:-1]
    elif " #" in value:
        raise ConfigSyntaxError("inline comments are unsupported at line {}".format(line_number))
    return value


# _tokenize converts two-space indentation into a minimal token stream and blocks
# aliases, tags, block scalars, and tabs that the small parser cannot prove.
def _tokenize(document, first_line):
    tokens = []
    for offset, original in enumerate(document.splitlines()):
        line_number = first_line + offset
        line = original.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line:
            raise ConfigSyntaxError("tabs are unsupported at line {}".format(line_number))
        indent = len(line) - len(line.lstrip(" "))
        if indent % 2:
            raise ConfigSyntaxError("indentation must use two-space levels at line {}".format(line_number))
        content = line[indent:]
        if re.search(r"(?:^|\s)[&*!][^\s]*", content) or content.endswith(("|", ">")):
            raise ConfigSyntaxError("advanced YAML features are unsupported at line {}".format(line_number))
        tokens.append((indent, content, line_number))
    if not tokens:
        raise ConfigSyntaxError("empty YAML document")
    return tokens


# _split_pair limits mappings to Kubernetes-style plain keys and one value field.
def _split_pair(content, line_number):
    match = re.fullmatch(r"([A-Za-z0-9_.-]+):(?:\s*(.*))?", content)
    if not match:
        raise ConfigSyntaxError("unsupported mapping syntax at line {}".format(line_number))
    return match.group(1), match.group(2) or ""


# _parse_mapping builds one indentation level while treating duplicate keys as a
# syntax failure rather than applying YAML's inconsistent last-value behavior.
def _parse_mapping(tokens, index, indent, initial=None):
    result = {} if initial is None else dict(initial)
    while index < len(tokens):
        line_indent, content, line_number = tokens[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise ConfigSyntaxError("unexpected indentation at line {}".format(line_number))
        if content.startswith("-"):
            break
        key, raw = _split_pair(content, line_number)
        if key in result:
            raise ConfigSyntaxError("duplicate key {} at line {}".format(key, line_number))
        index += 1
        if raw:
            result[key] = _strip_scalar(raw, line_number)
            continue
        if index >= len(tokens) or tokens[index][0] <= indent:
            raise ConfigSyntaxError("key {} has no value at line {}".format(key, line_number))
        result[key], index = _parse_block(tokens, index, indent + 2)
    return result, index


# _parse_sequence supports only the scalar and mapping list forms kubeadm emits,
# keeping nested interpretation deterministic without PyYAML on the Pi.
def _parse_sequence(tokens, index, indent):
    result = []
    while index < len(tokens):
        line_indent, content, line_number = tokens[index]
        if line_indent < indent:
            break
        if line_indent != indent or not content.startswith("-"):
            raise ConfigSyntaxError("unsupported sequence indentation at line {}".format(line_number))
        raw = content[1:].strip()
        index += 1
        if not raw:
            if index >= len(tokens) or tokens[index][0] <= indent:
                raise ConfigSyntaxError("empty sequence item at line {}".format(line_number))
            item, index = _parse_block(tokens, index, indent + 2)
        elif re.match(r"[A-Za-z0-9_.-]+:", raw):
            key, value = _split_pair(raw, line_number)
            if not value:
                # In a mapping sequence item ("- key:"), the key is at the
                # virtual indent one level below the dash and its value begins
                # another level below that. Parse only this explicit shape.
                if index >= len(tokens) or tokens[index][0] != indent + 4:
                    raise ConfigSyntaxError("nested sequence value has invalid indentation at line {}".format(line_number))
                nested, index = _parse_block(tokens, index, indent + 4)
                initial = {key: nested}
            else:
                initial = {key: _strip_scalar(value, line_number)}
            item, index = _parse_mapping(tokens, index, indent + 2, initial=initial)
        else:
            item = _strip_scalar(raw, line_number)
            if index < len(tokens) and tokens[index][0] > indent:
                raise ConfigSyntaxError("scalar sequence item has nested content at line {}".format(line_number))
        result.append(item)
    return result, index


# _parse_block chooses mapping or sequence only from the first token at the exact
# expected depth, so surprising indentation cannot be normalized silently.
def _parse_block(tokens, index, indent):
    if index >= len(tokens) or tokens[index][0] != indent:
        line_number = tokens[index][2] if index < len(tokens) else tokens[-1][2]
        raise ConfigSyntaxError("unexpected indentation near line {}".format(line_number))
    if tokens[index][1].startswith("-"):
        return _parse_sequence(tokens, index, indent)
    return _parse_mapping(tokens, index, indent)


# parse_documents separates the kubeadm YAML stream and keys each unique document
# by kind, which lets the encryption validator reuse the same strict parser.
def parse_documents(text):
    """Parse the strict subset and return documents keyed by Kubernetes kind."""
    chunks = []
    current = []
    first_line = 1
    chunk_start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip() == "---":
            if current and any(item.strip() and not item.lstrip().startswith("#") for item in current):
                chunks.append(("\n".join(current), chunk_start))
            current = []
            chunk_start = number + 1
        else:
            if not current:
                first_line = chunk_start
            current.append(line)
    if current and any(item.strip() and not item.lstrip().startswith("#") for item in current):
        chunks.append(("\n".join(current), first_line))

    documents = {}
    for chunk, start in chunks:
        tokens = _tokenize(chunk, start)
        parsed, index = _parse_block(tokens, 0, 0)
        if index != len(tokens) or not isinstance(parsed, dict):
            raise ConfigSyntaxError("document at line {} is not one mapping".format(start))
        kind = parsed.get("kind")
        if not isinstance(kind, str):
            raise ConfigSyntaxError("document at line {} has no scalar kind".format(start))
        if kind in documents:
            raise ConfigSyntaxError("duplicate {} document".format(kind))
        documents[kind] = parsed
    return documents


# _mapping gives validation code a safe empty view while exact-shape checks still
# record the original type error for the operator.
def _mapping(value):
    return value if isinstance(value, dict) else {}


# _is_rfc1918 handles both host addresses and canonical networks against the same
# private ranges used throughout bootstrap review.
def _is_rfc1918(address_or_network):
    return any(address_or_network.subnet_of(network) if hasattr(address_or_network, "subnet_of") else address_or_network in network
               for network in RFC1918)


# _private_ipv4 returns a normalized address only when it is valid private IPv4.
def _private_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or not _is_rfc1918(address):
        return None
    return address


# _private_network additionally requires canonical CIDR notation so rendered and
# reviewed network identities cannot differ textually.
def _private_network(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if network.version != 4 or not _is_rfc1918(network):
        return None
    return network


# _named_list turns kubeadm's repeated name/value shape into a unique keyed map,
# making duplicate security flags impossible to hide in ordering.
def _named_list(value, label, errors):
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        errors.append("{} must be a list of name/value mappings".format(label))
        return None
    result = {}
    for item in value:
        name = item.get("name")
        if not isinstance(name, str) or name in result:
            errors.append("{} contains a missing or duplicate name".format(label))
            return None
        result[name] = {key: val for key, val in item.items() if key != "name"}
    return result


# _require_scalar records exact-value drift while allowing the validator to report
# the rest of the configuration's violations in the same run.
def _require_scalar(mapping, key, expected, label, errors):
    if mapping.get(key) != expected:
        errors.append("{}.{} must be {}".format(label, key, expected))


# _require_keys closes each reviewed mapping against both missing and unexpected
# kubeadm fields.
def _require_keys(mapping, expected, label, errors):
    """Require an exact mapping shape so unsupported settings fail closed."""
    if not isinstance(mapping, dict):
        errors.append("{} must be a mapping".format(label))
        return False
    actual = set(mapping)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        errors.append("{} must contain exactly the reviewed fields ({})".format(label, "; ".join(detail)))
        return False
    return True


# _flatten_named_values accepts only entries containing name plus one scalar value,
# the shape used by kubeadm v1beta4 extraArgs.
def _flatten_named_values(value, label, errors):
    named = _named_list(value, label, errors)
    if named is None:
        return None
    flattened = {}
    for name, fields in named.items():
        if set(fields) != {"value"} or not isinstance(fields.get("value"), str):
            errors.append("{} entries must contain exactly name and scalar value".format(label))
            return None
        flattened[name] = fields["value"]
    return flattened


# validate composes parser, topology, runtime, storage, audit, encryption, kubelet,
# and kube-proxy invariants into the final gate before full Kubernetes bootstrap.
def validate(text):
    errors = []
    if re.search(r"(?:REPLACE_|UNRESOLVED)", text, flags=re.IGNORECASE):
        errors.append("replacement sentinel remains")
    if re.search(r"^\s*(?:ignorePreflightErrors|skipPhases)\s*:", text, flags=re.MULTILINE):
        errors.append("ignored preflight errors and skipped phases are forbidden")

    try:
        documents = parse_documents(text)
    except ConfigSyntaxError as error:
        return errors + [str(error)]

    if set(documents) != set(EXPECTED_DOCUMENTS):
        missing = sorted(set(EXPECTED_DOCUMENTS) - set(documents))
        unexpected = sorted(set(documents) - set(EXPECTED_DOCUMENTS))
        errors.append("configuration must contain exactly the four reviewed document kinds"
                      + ("; missing " + ", ".join(missing) if missing else "")
                      + ("; unexpected " + ", ".join(unexpected) if unexpected else ""))
    for kind, api_version in EXPECTED_DOCUMENTS.items():
        document = documents.get(kind, {})
        _require_keys(document, DOCUMENT_KEYS[kind], kind, errors)
        if document.get("apiVersion") != api_version:
            errors.append("{} apiVersion must be {}".format(kind, api_version))

    # InitConfiguration binds the node to containerd and one discovered LAN IP;
    # no additional kubelet flags may enter through this bootstrap path.
    init = documents.get("InitConfiguration", {})
    node = _mapping(init.get("nodeRegistration"))
    _require_keys(
        node,
        {"criSocket", "imagePullPolicy", "imagePullSerial", "name", "taints", "kubeletExtraArgs"},
        "nodeRegistration",
        errors,
    )
    _require_scalar(node, "criSocket", CRI_SOCKET, "nodeRegistration", errors)
    _require_scalar(node, "imagePullPolicy", "IfNotPresent", "nodeRegistration", errors)
    _require_scalar(node, "imagePullSerial", "true", "nodeRegistration", errors)
    if node.get("taints") != []:
        errors.append("nodeRegistration.taints must be [] so the reviewed single node is schedulable")
    node_name = node.get("name", "")
    if not isinstance(node_name, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", node_name):
        errors.append("nodeRegistration.name must be a normalized DNS name")

    endpoint = _mapping(init.get("localAPIEndpoint"))
    _require_keys(endpoint, {"advertiseAddress", "bindPort"}, "localAPIEndpoint", errors)
    advertise = _private_ipv4(endpoint.get("advertiseAddress", ""))
    if advertise is None:
        errors.append("localAPIEndpoint.advertiseAddress must be one explicit RFC1918 IPv4 address")
    _require_scalar(endpoint, "bindPort", "6443", "localAPIEndpoint", errors)

    kubelet_args = _flatten_named_values(node.get("kubeletExtraArgs"), "nodeRegistration.kubeletExtraArgs", errors)
    if kubelet_args is not None:
        expected_kubelet_args = {"node-ip": str(advertise)} if advertise is not None else None
        if kubelet_args != expected_kubelet_args:
            errors.append("nodeRegistration.kubeletExtraArgs must contain only node-ip matching advertiseAddress")

    # ClusterConfiguration fixes the single-node stacked-etcd topology and makes
    # the API endpoint, pod CIDR, and service CIDR agree across all consumers.
    cluster = documents.get("ClusterConfiguration", {})
    _require_scalar(cluster, "clusterName", "pi-production", "ClusterConfiguration", errors)
    _require_scalar(cluster, "kubernetesVersion", KUBERNETES_VERSION, "ClusterConfiguration", errors)
    _require_scalar(cluster, "imageRepository", IMAGE_REPOSITORY, "ClusterConfiguration", errors)
    _require_scalar(cluster, "certificatesDir", "/etc/kubernetes/pki", "ClusterConfiguration", errors)
    control_endpoint = cluster.get("controlPlaneEndpoint", "")
    control_match = re.fullmatch(r"([0-9.]+):6443", control_endpoint) if isinstance(control_endpoint, str) else None
    control_address = _private_ipv4(control_match.group(1)) if control_match else None
    if control_address is None or advertise is None or control_address != advertise:
        errors.append("controlPlaneEndpoint must match the RFC1918 advertise address on port 6443")

    networking = _mapping(cluster.get("networking"))
    _require_keys(networking, {"dnsDomain", "podSubnet", "serviceSubnet"}, "networking", errors)
    _require_scalar(networking, "dnsDomain", "cluster.local", "networking", errors)
    pod_network = _private_network(networking.get("podSubnet", ""))
    service_network = _private_network(networking.get("serviceSubnet", ""))
    if pod_network is None:
        errors.append("networking.podSubnet must be one canonical RFC1918 IPv4 CIDR")
    if service_network is None:
        errors.append("networking.serviceSubnet must be one canonical RFC1918 IPv4 CIDR")
    if pod_network and service_network and pod_network.overlaps(service_network):
        errors.append("podSubnet and serviceSubnet must not overlap")
    if advertise and any(advertise in network for network in (pod_network, service_network) if network):
        errors.append("the API advertise address must not fall inside a pod or service CIDR")

    etcd = _mapping(cluster.get("etcd"))
    _require_keys(etcd, {"local"}, "etcd", errors)
    if set(etcd) != {"local"} or "external" in etcd:
        errors.append("etcd must use only the reviewed stacked local configuration")
    local_etcd = _mapping(etcd.get("local"))
    _require_keys(local_etcd, {"dataDir", "extraArgs"}, "etcd.local", errors)
    _require_scalar(local_etcd, "dataDir", "/var/lib/etcd", "etcd.local", errors)
    etcd_args = _flatten_named_values(local_etcd.get("extraArgs"), "etcd.local.extraArgs", errors)
    if etcd_args is not None and etcd_args != ETCD_ARGS:
        errors.append("etcd.local.extraArgs must exactly match the reviewed local maintenance settings")

    # Static-Pod arguments and mounts are compared as complete maps so dropping a
    # hardening file or adding an unreviewed host path cannot pass validation.
    api_server = _mapping(cluster.get("apiServer"))
    _require_keys(api_server, {"certSANs", "extraArgs", "extraVolumes"}, "apiServer", errors)
    cert_sans = api_server.get("certSANs")
    if not isinstance(cert_sans, list) or len(cert_sans) != 2 or not all(isinstance(item, str) for item in cert_sans):
        errors.append("apiServer.certSANs must contain exactly the advertise IP and one private DNS name")
    else:
        private_dns = cert_sans[1]
        dns_valid = (
            re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", private_dns)
            and "*" not in private_dns
            and _private_ipv4(private_dns) is None
        )
        if advertise is None or cert_sans[0] != str(advertise) or not dns_valid:
            errors.append("apiServer.certSANs must contain exactly the advertise IP and one normalized private DNS name")

    args = _flatten_named_values(api_server.get("extraArgs"), "apiServer.extraArgs", errors)
    if args is not None and args != API_SERVER_ARGS:
        errors.append("apiServer.extraArgs must exactly match the reviewed PSA, audit, encryption, and token flags")

    volumes = _named_list(api_server.get("extraVolumes"), "apiServer.extraVolumes", errors)
    if volumes is not None and volumes != API_SERVER_VOLUMES:
        errors.append("apiServer.extraVolumes must exactly match the reviewed read-only configs and writable audit log")

    # KubeletConfiguration enforces cgroup v2/systemd, swap refusal, webhook auth,
    # seccomp, and bounded logs suitable for the Ubuntu Pi host.
    kubelet = documents.get("KubeletConfiguration", {})
    for key, expected in {
        "cgroupDriver": "systemd",
        "failSwapOn": "true",
        "failCgroupV1": "true",
        "protectKernelDefaults": "true",
        "readOnlyPort": "0",
        "rotateCertificates": "true",
        "seccompDefault": "true",
        "serverTLSBootstrap": "false",
        "containerLogMaxFiles": "5",
        "containerLogMaxSize": "10Mi",
    }.items():
        _require_scalar(kubelet, key, expected, "KubeletConfiguration", errors)
    authentication = _mapping(kubelet.get("authentication"))
    _require_keys(authentication, {"anonymous", "webhook"}, "authentication", errors)
    _require_keys(_mapping(authentication.get("anonymous")), {"enabled"}, "authentication.anonymous", errors)
    _require_keys(_mapping(authentication.get("webhook")), {"enabled"}, "authentication.webhook", errors)
    _require_scalar(_mapping(authentication.get("anonymous")), "enabled", "false", "authentication.anonymous", errors)
    _require_scalar(_mapping(authentication.get("webhook")), "enabled", "true", "authentication.webhook", errors)
    authorization = _mapping(kubelet.get("authorization"))
    _require_keys(authorization, {"mode"}, "authorization", errors)
    _require_scalar(authorization, "mode", "Webhook", "authorization", errors)
    if kubelet.get("enforceNodeAllocatable") != ["pods"]:
        errors.append("KubeletConfiguration.enforceNodeAllocatable must be exactly [pods]")

    # kube-proxy remains installed by design; its cluster CIDR must be identical
    # to the pod subnet handed to the separately reviewed CNI manifest.
    proxy = documents.get("KubeProxyConfiguration", {})
    if proxy.get("mode") not in {"iptables", "nftables"}:
        errors.append("KubeProxyConfiguration.mode must be explicitly iptables or nftables")
    _require_scalar(proxy, "detectLocalMode", "ClusterCIDR", "KubeProxyConfiguration", errors)
    if pod_network is None or proxy.get("clusterCIDR") != str(pod_network):
        errors.append("KubeProxyConfiguration.clusterCIDR must exactly match networking.podSubnet")

    return errors


# main exposes the reusable validator as a fail-closed bootstrap command.
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args(argv)
    try:
        text = args.config.read_text(encoding="utf-8")
    except OSError as error:
        print("FAIL unable to read kubeadm config: {}".format(error), file=sys.stderr)
        return 1
    errors = validate(text)
    if errors:
        for error in errors:
            print("FAIL " + error, file=sys.stderr)
        return 1
    print("PASS kubeadm config matches the reviewed security, runtime, and topology contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
