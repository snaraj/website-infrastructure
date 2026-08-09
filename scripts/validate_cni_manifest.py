#!/usr/bin/env python3
"""Fail closed unless a rendered CNI manifest matches reviewed Pi decisions.

This validator intentionally uses only the Python standard library.  It does
not attempt to be a general YAML parser: it recognizes the line-oriented
shapes emitted by the reviewed Cilium and Calico manifests and rejects an
ambiguous or incomplete contract.
"""

import argparse
import hashlib
import ipaddress
import re
import sys
from pathlib import Path


# HOST_REQUIREMENTS binds each reviewed dataplane mode to the host firewall
# opening it needs; an unreviewed provider/tunnel pair has no permissive default.
HOST_REQUIREMENTS = {
    ("cilium", "vxlan"): "udp:8472",
    ("cilium", "geneve"): "udp:6081",
    ("cilium", "native"): "none",
    ("calico", "vxlan"): "udp:4789",
    ("calico", "ipip"): "ip-proto:4",
    ("calico", "bgp"): "tcp:179",
}

# REQUIRED_DECISIONS is the human-approved handoff between Pi discovery and CNI
# installation, including a byte-level manifest digest and policy proof.
REQUIRED_DECISIONS = {
    "POD_CIDR",
    "KUBE_PROXY_OPERATION",
    "CNI_PROVIDER",
    "CNI_VERSION",
    "CNI_DATAPLANE",
    "CNI_TUNNEL_MODE",
    "CNI_MTU",
    "CNI_HOST_NETWORK_REQUIREMENTS",
    "CNI_MANIFEST_SHA256",
    "CNI_NETWORK_POLICY_PROVEN",
}

# These expressions define the deliberately small text grammar accepted without
# a third-party YAML dependency on the bootstrap host.
SENTINEL = re.compile(
    r"(?:REPLACE_|UNRESOLVED|__+[A-Z0-9][A-Z0-9_]*__+|<+REPLACE[^>]*>+)",
    re.IGNORECASE,
)
DECISION_LINE = re.compile(r"([A-Z][A-Z0-9_]*)=([^\s#=]+)")
SEMVER = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+")
IMAGE = re.compile(
    r"(?P<repository>"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    r")(?::(?P<tag>[A-Za-z0-9][A-Za-z0-9_.-]{0,127}))?"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
)
# Pod addressing stays within private IPv4 space so the route-overlap review can
# reason about it alongside the service and residential LAN networks.
RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

# Exact resource identities from the reviewed, canonical raw-manifest path.
# This is intentionally not a prefix/regex allowlist.  New upstream resources,
# optional Cilium features (including Hubble, Envoy, ingress, and metrics
# Services), and Tigera Operator resources must be reviewed and enumerated
# before this gate will accept them.  In particular, no Service, Secret, or
# Namespace is currently part of either bootstrap contract.
CILIUM_CRDS = frozenset({
    "ciliumbgpadvertisements.cilium.io",
    "ciliumbgpclusterconfigs.cilium.io",
    "ciliumbgpnodeconfigoverrides.cilium.io",
    "ciliumbgpnodeconfigs.cilium.io",
    "ciliumbgppeerconfigs.cilium.io",
    "ciliumcidrgroups.cilium.io",
    "ciliumclusterwideenvoyconfigs.cilium.io",
    "ciliumclusterwidenetworkpolicies.cilium.io",
    "ciliumdatapathplugins.cilium.io",
    "ciliumegressgatewaypolicies.cilium.io",
    "ciliumendpoints.cilium.io",
    "ciliumendpointslices.cilium.io",
    "ciliumenvoyconfigs.cilium.io",
    "ciliumgatewayclassconfigs.cilium.io",
    "ciliumidentities.cilium.io",
    "ciliuml2announcementpolicies.cilium.io",
    "ciliumloadbalancerippools.cilium.io",
    "ciliumlocalredirectpolicies.cilium.io",
    "ciliumnetworkpolicies.cilium.io",
    "ciliumnodeconfigs.cilium.io",
    "ciliumnodes.cilium.io",
    "ciliumpodippools.cilium.io",
})

CALICO_CRDS = frozenset({
    "bgpconfigurations.crd.projectcalico.org",
    "bgpfilters.crd.projectcalico.org",
    "bgppeers.crd.projectcalico.org",
    "blockaffinities.crd.projectcalico.org",
    "caliconodestatuses.crd.projectcalico.org",
    "clusterinformations.crd.projectcalico.org",
    "clusternetworkpolicies.policy.networking.k8s.io",
    "felixconfigurations.crd.projectcalico.org",
    "globalnetworkpolicies.crd.projectcalico.org",
    "globalnetworksets.crd.projectcalico.org",
    "hostendpoints.crd.projectcalico.org",
    "ipamblocks.crd.projectcalico.org",
    "ipamconfigs.crd.projectcalico.org",
    "ipamhandles.crd.projectcalico.org",
    "ippools.crd.projectcalico.org",
    "ipreservations.crd.projectcalico.org",
    "kubecontrollersconfigurations.crd.projectcalico.org",
    "networkpolicies.crd.projectcalico.org",
    "networksets.crd.projectcalico.org",
    "stagedglobalnetworkpolicies.crd.projectcalico.org",
    "stagedkubernetesnetworkpolicies.crd.projectcalico.org",
    "stagednetworkpolicies.crd.projectcalico.org",
    "tiers.crd.projectcalico.org",
})


# _namespaced_id makes kube-system scope explicit in every reviewed workload
# identity rather than relying on kubectl's current namespace.
def _namespaced_id(api_version, kind, name):
    return api_version, kind, "kube-system", name


# _cluster_id represents cluster-scoped resources without conflating them with
# resources whose namespace field was accidentally omitted.
def _cluster_id(api_version, kind, name):
    return api_version, kind, None, name


RESOURCE_CONTRACTS = {
    "cilium": frozenset({
        _namespaced_id("v1", "ConfigMap", "cilium-config"),
        _namespaced_id("v1", "ServiceAccount", "cilium"),
        _namespaced_id("v1", "ServiceAccount", "cilium-operator"),
        _namespaced_id("apps/v1", "DaemonSet", "cilium"),
        _namespaced_id("apps/v1", "Deployment", "cilium-operator"),
        _namespaced_id("policy/v1", "PodDisruptionBudget", "cilium-operator"),
        _namespaced_id("rbac.authorization.k8s.io/v1", "Role", "cilium-config-agent"),
        _namespaced_id(
            "rbac.authorization.k8s.io/v1", "RoleBinding", "cilium-config-agent"
        ),
        _cluster_id("rbac.authorization.k8s.io/v1", "ClusterRole", "cilium"),
        _cluster_id("rbac.authorization.k8s.io/v1", "ClusterRole", "cilium-operator"),
        _cluster_id("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "cilium"),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "cilium-operator"
        ),
    } | {
        _cluster_id("apiextensions.k8s.io/v1", "CustomResourceDefinition", name)
        for name in CILIUM_CRDS
    }),
    "calico": frozenset({
        _namespaced_id("v1", "ConfigMap", "calico-config"),
        _namespaced_id("v1", "ServiceAccount", "calico-cni-plugin"),
        _namespaced_id("v1", "ServiceAccount", "calico-kube-controllers"),
        _namespaced_id("v1", "ServiceAccount", "calico-node"),
        _namespaced_id("apps/v1", "DaemonSet", "calico-node"),
        _namespaced_id("apps/v1", "Deployment", "calico-kube-controllers"),
        _namespaced_id(
            "policy/v1", "PodDisruptionBudget", "calico-kube-controllers"
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRole", "calico-cni-plugin"
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRole", "calico-kube-controllers"
        ),
        _cluster_id("rbac.authorization.k8s.io/v1", "ClusterRole", "calico-node"),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRole", "calico-tier-getter"
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "calico-cni-plugin"
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1",
            "ClusterRoleBinding",
            "calico-kube-controllers",
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "calico-node"
        ),
        _cluster_id(
            "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "calico-tier-getter"
        ),
    } | {
        _cluster_id("apiextensions.k8s.io/v1", "CustomResourceDefinition", name)
        for name in CALICO_CRDS
    }),
}


# _unquote normalizes only simple matching quotes supported by this validator's
# intentionally narrow YAML subset.
def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
        return value[1:-1]
    return value


# _without_comment preserves a quoted # while removing only real YAML comments,
# preventing policy checks from accepting configuration hidden in comment text.
def _without_comment(line):
    """Remove a YAML comment without treating a quoted # as a comment."""
    quote = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"' and character == "\\" and not escaped:
            escaped = True
            continue
        if character in ("'", '"') and not escaped:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        if character == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
        escaped = False
    return line.rstrip()


# _clean_lines records indentation and source lines once; tabs are rejected
# because mixed indentation makes the reviewed manifest shape ambiguous.
def _clean_lines(text, errors):
    lines = []
    for number, original in enumerate(text.splitlines(), 1):
        if "\t" in original:
            errors.append("manifest contains a tab at line {}".format(number))
            continue
        line = _without_comment(original)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line[indent:], number))
    return lines


# _documents recognizes explicit YAML document boundaries so resource identity
# checks cannot accidentally merge two Kubernetes objects.
def _documents(text):
    documents = []
    current = []
    for line in text.splitlines():
        if _without_comment(line).strip() == "---":
            if any(_without_comment(item).strip() for item in current):
                documents.append("\n".join(current))
            current = []
            continue
        if _without_comment(line).strip() == "...":
            if any(_without_comment(item).strip() for item in current):
                documents.append("\n".join(current))
            current = []
            continue
        current.append(line)
    if any(_without_comment(item).strip() for item in current):
        documents.append("\n".join(current))
    return documents


# _top_scalar reads one unambiguous document identity field and reports duplicates
# rather than taking whichever apiVersion or kind appears first.
def _top_scalar(document, key, errors):
    matches = []
    for indent, content, number in _clean_lines(document, errors):
        if indent != 0:
            continue
        match = re.fullmatch(r"{}:\s*(.+)".format(re.escape(key)), content)
        if match:
            matches.append((_unquote(match.group(1)), number))
    if len(matches) > 1:
        errors.append("document contains duplicate top-level {} fields".format(key))
    return matches[0][0] if len(matches) == 1 else None


# _direct_mapping extracts only immediate scalar children used by reviewed CNI
# ConfigMaps; nested or block-style alternatives are not silently interpreted.
def _direct_mapping(document, mapping_name, errors):
    lines = _clean_lines(document, errors)
    headers = [index for index, item in enumerate(lines)
               if item[0] == 0 and item[1] == mapping_name + ":"]
    if len(headers) > 1:
        errors.append("document contains duplicate top-level {} mappings".format(mapping_name))
        return {}
    if not headers:
        return {}
    result = {}
    for indent, content, number in lines[headers[0] + 1:]:
        if indent <= 0:
            break
        if indent != 2:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+):(?:\s*(.*))?", content)
        if not match:
            continue
        key, raw = match.group(1), match.group(2) or ""
        if key in result:
            errors.append("{} contains duplicate key {}".format(mapping_name, key))
            continue
        if raw and raw not in ("|", "|-", ">", ">-"):
            result[key] = _unquote(raw)
    return result


# _metadata uses the same direct-mapping rule for stable name and namespace proof.
def _metadata(document, errors):
    return _direct_mapping(document, "metadata", errors)


# _resource_index gives every document a concrete identity and retains its source
# text for provider-specific checks later in the validation pipeline.
def _resource_index(manifest, errors):
    resources = []
    for index, document in enumerate(_documents(manifest), 1):
        api_version = _top_scalar(document, "apiVersion", errors)
        kind = _top_scalar(document, "kind", errors)
        metadata = _metadata(document, errors)
        resources.append({
            "apiVersion": api_version,
            "kind": kind,
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "document": document,
            "index": index,
        })
    return resources


# _validate_resource_contract is the primary supply-chain allowlist: every
# rendered object must be a reviewed identity for the selected provider.
def _validate_resource_contract(resources, provider, errors):
    """Reject every document outside the exact reviewed provider identities."""
    contract = RESOURCE_CONTRACTS.get(provider)
    if contract is None:
        return
    seen = set()
    for resource in resources:
        identity = (
            resource["apiVersion"],
            resource["kind"],
            resource["namespace"],
            resource["name"],
        )
        if None in identity[:2] or resource["name"] is None:
            errors.append(
                "CNI document {} must define scalar apiVersion, kind, and metadata.name"
                .format(resource["index"])
            )
            continue
        if identity not in contract:
            scope = resource["namespace"] or "<cluster>"
            errors.append(
                "{}/{}/{}/{} is outside the strict {} raw-manifest resource contract"
                .format(
                    resource["apiVersion"], resource["kind"], scope,
                    resource["name"], provider,
                )
            )
            continue
        if identity in seen:
            errors.append(
                "{}/{} resource identity occurs more than once"
                .format(resource["kind"], resource["name"])
            )
        seen.add(identity)


# _resource selects exactly one required kube-system object for deeper validation.
def _resource(resources, kind, name, errors):
    matches = [item for item in resources if item["kind"] == kind and item["name"] == name]
    if len(matches) != 1:
        errors.append("manifest must contain exactly one {}/{} resource".format(kind, name))
        return None
    if matches[0]["namespace"] != "kube-system":
        errors.append("{}/{} must explicitly use namespace kube-system".format(kind, name))
    return matches[0]


# _line_scalars finds repeated simple fields such as container images while
# rejecting block scalars that this dependency-free parser cannot prove safely.
def _line_scalars(text, key, errors):
    values = []
    pattern = re.compile(r"{}:\s*(.+)".format(re.escape(key)))
    for _indent, content, number in _clean_lines(text, errors):
        match = pattern.fullmatch(content)
        if match:
            raw = match.group(1)
            if raw in ("|", "|-", ">", ">-"):
                errors.append("{} uses an unsupported block scalar at line {}".format(key, number))
            else:
                values.append(_unquote(raw))
    return values


# _named_scalar_values reads environment-style name/value entries used by the
# canonical DaemonSets without pretending to support general YAML traversal.
def _named_scalar_values(document, errors):
    """Collect scalar values in list mappings shaped as - name: X / value: Y."""
    lines = _clean_lines(document, errors)
    values = {}
    for index, (indent, content, _number) in enumerate(lines):
        match = re.fullmatch(r"-\s+name:\s*([A-Za-z0-9_.-]+)", content)
        if not match:
            continue
        name = match.group(1)
        for child_indent, child, _child_number in lines[index + 1:]:
            if child_indent <= indent:
                break
            value_match = re.fullmatch(r"value:\s*(.+)", child) if child_indent == indent + 2 else None
            if value_match:
                values.setdefault(name, []).append(_unquote(value_match.group(1)))
                break
    return values


# _named_occurrences lets callers reject duplicated environment controls even if
# duplicate values happen to be identical.
def _named_occurrences(document, errors):
    counts = {}
    for _indent, content, _number in _clean_lines(document, errors):
        match = re.fullmatch(r"-\s+name:\s*([A-Za-z0-9_.-]+)", content)
        if match:
            name = match.group(1)
            counts[name] = counts.get(name, 0) + 1
    return counts


# _image_records associates each immutable image with its sibling pull policy so
# digest pinning and offline-friendly IfNotPresent behavior are proved together.
def _image_records(manifest, errors):
    """Return image/pull-policy pairs tied to one container list item."""
    lines = _clean_lines(manifest, errors)
    records = []
    if any(re.match(r"-\s+image:", content) for _indent, content, _number in lines):
        errors.append("container image fields must not use inline list-item YAML")
    if re.search(r"(?:\{|,)\s*image\s*:", manifest):
        errors.append("container image fields must not use flow-style YAML")
    for index, (indent, content, number) in enumerate(lines):
        match = re.fullmatch(r"image:\s*(.+)", content)
        if not match:
            continue
        image = _unquote(match.group(1))
        parent_indent = indent - 2
        parent = None
        for candidate in range(index - 1, -1, -1):
            candidate_indent, candidate_content, _candidate_number = lines[candidate]
            if candidate_indent < parent_indent:
                break
            if (candidate_indent == parent_indent and
                    re.fullmatch(r"-\s+name:\s*[A-Za-z0-9_.-]+", candidate_content)):
                parent = candidate
                break
        if parent is None:
            errors.append("image at line {} is not inside an explicit named container mapping".format(number))
            records.append((image, None))
            continue
        end = len(lines)
        for candidate in range(parent + 1, len(lines)):
            if candidate > index and lines[candidate][0] <= parent_indent:
                end = candidate
                break
        policies = []
        for policy_indent, policy_content, _policy_number in lines[parent + 1:end]:
            policy = re.fullmatch(r"imagePullPolicy:\s*(.+)", policy_content)
            if policy_indent == indent and policy:
                policies.append(_unquote(policy.group(1)))
        if len(policies) != 1:
            errors.append("image at line {} must have exactly one sibling imagePullPolicy".format(number))
            records.append((image, None))
        else:
            records.append((image, policies[0]))
    return records


# _require_mapping_value appends a precise contract violation without ending the
# run early, allowing the operator to repair one reviewed manifest in one pass.
def _require_mapping_value(mapping, key, expected, label, errors):
    if mapping.get(key) != expected:
        errors.append("{}.{} must be exactly {}".format(label, key, expected))


# _require_named_value requires both exact value and singular occurrence for a
# Calico environment control.
def _require_named_value(values, occurrences, key, expected, errors):
    if occurrences.get(key) != 1 or values.get(key) != [expected]:
        errors.append("calico-node env {} must occur once with value {}".format(key, expected))


# _parse_decisions accepts only unindented KEY=VALUE evidence, rejecting unknown
# formatting that could make human and machine review disagree.
def _parse_decisions(text, errors):
    decisions = {}
    if SENTINEL.search(text):
        errors.append("decisions contain an unresolved replacement sentinel")
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        match = DECISION_LINE.fullmatch(line)
        if not match:
            errors.append("decisions contain a malformed line at {}".format(number))
            continue
        key, value = match.groups()
        if key in decisions:
            errors.append("decision {} occurs more than once".format(key))
            continue
        decisions[key] = value
    missing = sorted(REQUIRED_DECISIONS - set(decisions))
    if missing:
        errors.append("decisions are missing required CNI fields: " + ", ".join(missing))
    return decisions


# _validate_decision_contract constrains the human choices to the kube-proxy-
# retaining, private-IPv4 matrix this single-node kubeadm design supports.
def _validate_decision_contract(decisions, errors):
    provider = decisions.get("CNI_PROVIDER")
    tunnel = decisions.get("CNI_TUNNEL_MODE")
    version = decisions.get("CNI_VERSION", "")
    if provider not in {"cilium", "calico"}:
        errors.append("CNI_PROVIDER must be exactly cilium or calico")
    if not SEMVER.fullmatch(version):
        errors.append("CNI_VERSION must be one exact semantic-version token")
    if decisions.get("KUBE_PROXY_OPERATION") != "installed":
        errors.append("KUBE_PROXY_OPERATION must be installed")
    if decisions.get("CNI_DATAPLANE") != "kube-proxy":
        errors.append("CNI_DATAPLANE must be kube-proxy; replacement is forbidden")
    expected_host = HOST_REQUIREMENTS.get((provider, tunnel))
    if expected_host is None:
        errors.append("CNI provider/tunnel pair is outside the reviewed matrix")
    elif decisions.get("CNI_HOST_NETWORK_REQUIREMENTS") != expected_host:
        errors.append("CNI_HOST_NETWORK_REQUIREMENTS must be {} for {}/{}".format(
            expected_host, provider, tunnel
        ))
    mtu = decisions.get("CNI_MTU", "")
    if not mtu.isdigit() or not 576 <= int(mtu) <= 9000:
        errors.append("CNI_MTU must be an integer from 576 through 9000")
    if decisions.get("CNI_NETWORK_POLICY_PROVEN") != "yes":
        errors.append("CNI_NETWORK_POLICY_PROVEN must be yes")
    try:
        pod_cidr = ipaddress.ip_network(decisions.get("POD_CIDR", ""), strict=True)
    except ValueError:
        pod_cidr = None
    if (pod_cidr is None or pod_cidr.version != 4 or
            not any(pod_cidr.subnet_of(network) for network in RFC1918)):
        errors.append("POD_CIDR must be one canonical RFC1918 IPv4 network")


# _validate_images proves every container is digest-pinned and that the provider's
# core DaemonSet tag matches the separately reviewed CNI version.
def _validate_images(manifest, resources, provider, version, errors):
    records = _image_records(manifest, errors)
    raw_images = [image for image, _policy in records]
    if not raw_images:
        errors.append("manifest contains no container images")
        return
    parsed = []
    for value in raw_images:
        match = IMAGE.fullmatch(value)
        if not match:
            errors.append("container image is not one immutable digest reference: {}".format(value))
        else:
            parsed.append(match.groupdict())
    if any(policy != "IfNotPresent" for _image, policy in records):
        errors.append("every container image must explicitly use imagePullPolicy IfNotPresent")

    daemon_name = "cilium" if provider == "cilium" else "calico-node"
    daemon = next((item for item in resources
                   if item["kind"] == "DaemonSet" and item["name"] == daemon_name), None)
    if daemon is None:
        return
    daemon_images = []
    for value in _line_scalars(daemon["document"], "image", errors):
        match = IMAGE.fullmatch(value)
        if match:
            daemon_images.append(match.groupdict())
    suffix = "/cilium" if provider == "cilium" else "/node"
    core = [item for item in daemon_images if item["repository"].endswith(suffix)]
    if not core:
        errors.append("{}/{} contains no reviewed core {} image".format(
            "DaemonSet", daemon_name, provider
        ))
    elif any(item["tag"] != version for item in core):
        errors.append("core {} image tag must exactly match CNI_VERSION {}".format(provider, version))

    repositories = [item["repository"] for item in parsed]
    if provider == "cilium" and any("/calico/" in name or "/tigera/" in name for name in repositories):
        errors.append("Cilium manifest contains an opposite-provider image")
    if provider == "calico" and any("/cilium/" in name for name in repositories):
        errors.append("Calico manifest contains an opposite-provider image")


# _validate_cilium binds Cilium's ConfigMap to the approved CIDR, MTU, tunnel,
# policy mode, and retained kube-proxy architecture.
def _validate_cilium(resources, decisions, errors):
    daemon = _resource(resources, "DaemonSet", "cilium", errors)
    config_resource = _resource(resources, "ConfigMap", "cilium-config", errors)
    if daemon is None or config_resource is None:
        return
    data = _direct_mapping(config_resource["document"], "data", errors)
    expected = {
        "ipam": "cluster-pool",
        "cluster-pool-ipv4-cidr": decisions.get("POD_CIDR"),
        "mtu": decisions.get("CNI_MTU"),
        "kube-proxy-replacement": "false",
        "enable-node-port": "false",
        "bpf-lb-sock": "false",
        "enable-policy": "default",
    }
    for key, value in expected.items():
        _require_mapping_value(data, key, value, "cilium-config.data", errors)
    tunnel = decisions.get("CNI_TUNNEL_MODE")
    if tunnel in {"vxlan", "geneve"}:
        _require_mapping_value(data, "routing-mode", "tunnel", "cilium-config.data", errors)
        _require_mapping_value(data, "tunnel-protocol", tunnel, "cilium-config.data", errors)
        port = "8472" if tunnel == "vxlan" else "6081"
        _require_mapping_value(data, "tunnel-port", port, "cilium-config.data", errors)
    elif tunnel == "native":
        _require_mapping_value(data, "routing-mode", "native", "cilium-config.data", errors)
        _require_mapping_value(
            data, "ipv4-native-routing-cidr", decisions.get("POD_CIDR"),
            "cilium-config.data", errors,
        )


# _validate_calico binds Calico's ConfigMap and DaemonSet environment to the same
# approved CIDR, MTU, tunnel, and non-BPF dataplane decision.
def _validate_calico(resources, decisions, errors):
    daemon = _resource(resources, "DaemonSet", "calico-node", errors)
    config_resource = _resource(resources, "ConfigMap", "calico-config", errors)
    if daemon is None or config_resource is None:
        return
    data = _direct_mapping(config_resource["document"], "data", errors)
    tunnel = decisions.get("CNI_TUNNEL_MODE")
    backend = "vxlan" if tunnel == "vxlan" else "bird"
    _require_mapping_value(data, "calico_backend", backend, "calico-config.data", errors)
    _require_mapping_value(data, "veth_mtu", decisions.get("CNI_MTU"), "calico-config.data", errors)

    values = _named_scalar_values(daemon["document"], errors)
    occurrences = _named_occurrences(daemon["document"], errors)
    _require_named_value(
        values, occurrences, "CALICO_IPV4POOL_CIDR", decisions.get("POD_CIDR"), errors
    )
    _require_named_value(values, occurrences, "FELIX_BPFENABLED", "false", errors)
    modes = {
        "vxlan": ("Never", "Always"),
        "ipip": ("Always", "Never"),
        "bgp": ("Never", "Never"),
    }
    if tunnel in modes:
        ipip, vxlan = modes[tunnel]
        _require_named_value(values, occurrences, "CALICO_IPV4POOL_IPIP", ipip, errors)
        _require_named_value(values, occurrences, "CALICO_IPV4POOL_VXLAN", vxlan, errors)
    if tunnel == "vxlan":
        _require_named_value(values, occurrences, "FELIX_VXLANPORT", "4789", errors)


# _reject_opposite_provider catches mixed bundles that could evade checks focused
# only on the selected provider's required resources.
def _reject_opposite_provider(resources, provider, manifest, errors):
    if provider == "cilium":
        opposite_name = re.compile(r"(?:^|[-.])(calico|tigera)(?:[-.]|$)", re.IGNORECASE)
        opposite_api = re.compile(r"(?:projectcalico[.]org|operator[.]tigera[.]io)", re.IGNORECASE)
    else:
        opposite_name = re.compile(r"(?:^|[-.])cilium(?:[-.]|$)", re.IGNORECASE)
        opposite_api = re.compile(r"(?:^|[^A-Za-z0-9])cilium[.]io(?:[^A-Za-z0-9]|$)", re.IGNORECASE)
    names = [item["name"] for item in resources if item["name"]]
    clean = "\n".join(_without_comment(line) for line in manifest.splitlines())
    if any(opposite_name.search(name) for name in names) or opposite_api.search(clean):
        errors.append("manifest contains opposite-provider resource markers")


# _reject_alternate_configuration_sources preserves one authoritative raw-
# manifest configuration path instead of allowing competing operators or CRs.
def _reject_alternate_configuration_sources(resources, provider, errors):
    """Keep one authoritative bootstrap configuration path per provider."""
    if provider == "cilium":
        forbidden = {"CiliumNodeConfig"}
    elif provider == "calico":
        forbidden = {"Installation", "IPPool", "FelixConfiguration", "BGPConfiguration"}
    else:
        return
    found = sorted({item["kind"] for item in resources if item["kind"] in forbidden})
    if found:
        errors.append(
            "manifest contains alternate provider configuration sources: " + ", ".join(found)
        )


# _reject_replacement_modes searches all supported spellings so Cilium or Calico
# cannot silently take over service routing from the retained kube-proxy.
def _reject_replacement_modes(manifest, errors):
    clean = "\n".join(_without_comment(line) for line in manifest.splitlines())
    for match in re.finditer(
            r"(?im)^\s*(?:kubeProxyReplacement|kube-proxy-replacement):\s*['\"]?([^\s'\"]+)",
            clean):
        if match.group(1).lower() != "false":
            errors.append("Cilium kube-proxy replacement must remain false")
    for match in re.finditer(r"(?i)--kube-proxy-replacement(?:=|\s+)([^\s'\"]+)", clean):
        if match.group(1).lower() != "false":
            errors.append("Cilium kube-proxy replacement command argument is forbidden")
    if re.search(r"(?im)^\s*(?:bpfEnabled|bpf-enabled|linuxDataplane):\s*['\"]?(?:true|BPF)['\"]?\s*$", clean):
        errors.append("Calico BPF dataplane is forbidden")
    named = _named_scalar_values(manifest, errors)
    if any(value.lower() == "true" for value in named.get("FELIX_BPFENABLED", [])):
        errors.append("Calico FELIX_BPFENABLED=true is forbidden")


# validate composes byte identity, reviewed decisions, exact resource inventory,
# provider settings, and image provenance into one fail-closed install gate.
def validate(manifest, decision_text, actual_manifest_sha256=None):
    """Return contract violations; an empty list means the gate passed."""
    errors = []
    if SENTINEL.search(manifest):
        errors.append("manifest contains an unresolved replacement sentinel")
    decisions = _parse_decisions(decision_text, errors)
    _validate_decision_contract(decisions, errors)

    expected_digest = decisions.get("CNI_MANIFEST_SHA256", "")
    actual_digest = actual_manifest_sha256 or hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        errors.append("CNI_MANIFEST_SHA256 must be one lowercase SHA-256 digest")
    elif expected_digest != actual_digest:
        errors.append("rendered CNI manifest SHA-256 does not match decisions")

    resources = _resource_index(manifest, errors)
    provider = decisions.get("CNI_PROVIDER")
    _validate_resource_contract(resources, provider, errors)
    _reject_replacement_modes(manifest, errors)
    _reject_opposite_provider(resources, provider, manifest, errors)
    _reject_alternate_configuration_sources(resources, provider, errors)
    if provider == "cilium":
        _validate_cilium(resources, decisions, errors)
    elif provider == "calico":
        _validate_calico(resources, decisions, errors)
    _validate_images(manifest, resources, provider, decisions.get("CNI_VERSION", ""), errors)
    return errors


# main reads raw bytes for the digest proof, reports every discovered violation,
# and returns a process status suitable for bootstrap scripts and CI.
def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--decisions", type=Path,
        default=root / "bootstrap" / "pi" / "decisions.env.local",
    )
    args = parser.parse_args(argv)
    try:
        manifest_bytes = args.manifest.read_bytes()
        decision_bytes = args.decisions.read_bytes()
        manifest = manifest_bytes.decode("utf-8")
        decisions = decision_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        print("FAIL unable to read UTF-8 CNI inputs: {}".format(error), file=sys.stderr)
        return 1
    errors = validate(manifest, decisions, hashlib.sha256(manifest_bytes).hexdigest())
    if errors:
        for error in errors:
            print("FAIL " + error, file=sys.stderr)
        return 1
    print("PASS rendered CNI manifest matches the reviewed provider, network, and image contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
