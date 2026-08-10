"""Validate the captured global runtime inventory against exact pins.

Extracted verbatim from the retired release-gate.sh --live lane so the unit
suite keeps executing this validator while the post-cutover successor gate is
built. argv: STATE_ROOT then the ten pinned runtime images/versions
(naranjo, lidersea, cloudflared, admission, three Flux controllers,
Kubernetes version, CoreDNS, etcd) exactly as versions.env defines them.
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
naranjo_image = sys.argv[2]
lidersea_image = sys.argv[3]
cloudflared_image = sys.argv[4]
admission_image = sys.argv[5]
flux_source_image = sys.argv[6]
flux_kustomize_image = sys.argv[7]
flux_helm_image = sys.argv[8]
kubernetes_version = sys.argv[9]
coredns_image = sys.argv[10]
etcd_image = sys.argv[11]


def load_items(name):
    document = json.loads((root / name).read_text(encoding="utf-8"))
    items = document.get("items")
    if not isinstance(items, list):
        raise SystemExit(f"{name} does not contain one Kubernetes item list")
    if any(not isinstance(item, dict) for item in items):
        raise SystemExit(f"{name} contains a non-object item")
    return items


def metadata(item):
    value = item.get("metadata", {})
    return value if isinstance(value, dict) else {}


def namespaced_identity(item):
    return metadata(item).get("namespace"), metadata(item).get("name")


def exact_namespaced_map(items, expected, kind):
    identities = [namespaced_identity(item) for item in items]
    if len(identities) != len(expected) or set(identities) != expected:
        raise SystemExit(f"live {kind} inventory differs from the exact release set")
    result = {}
    for item in items:
        identity = namespaced_identity(item)
        uid = metadata(item).get("uid")
        if not isinstance(uid, str) or not uid:
            raise SystemExit(f"{kind} {identity[0]}/{identity[1]} has no stable UID")
        result[identity] = item
    return result


def dynamic_namespaced_map(items, kind):
    result = {}
    uids = set()
    for item in items:
        identity = namespaced_identity(item)
        uid = metadata(item).get("uid")
        if (
            not all(isinstance(value, str) and value for value in identity)
            or identity in result
            or not isinstance(uid, str)
            or not uid
            or uid in uids
        ):
            raise SystemExit(f"live {kind} inventory has an invalid or duplicate identity")
        result[identity] = item
        uids.add(uid)
    return result


def one_controller_owner(item, kind, identity):
    owners = metadata(item).get("ownerReferences", [])
    if not isinstance(owners, list):
        raise SystemExit(f"{kind} {identity[0]}/{identity[1]} has invalid owner references")
    controllers = [
        owner
        for owner in owners
        if isinstance(owner, dict) and owner.get("controller") is True
    ]
    if len(owners) != 1 or len(controllers) != 1:
        raise SystemExit(f"{kind} {identity[0]}/{identity[1]} lacks one exact controller owner")
    return controllers[0]


def pod_spec(item):
    value = item.get("spec", {})
    return value if isinstance(value, dict) else {}


def container_images(spec):
    regular = spec.get("containers", [])
    init = spec.get("initContainers", [])
    if (
        not isinstance(regular, list)
        or not regular
        or not isinstance(init, list)
        or any(not isinstance(container, dict) for container in regular + init)
    ):
        return None
    images = [container.get("image") for container in regular + init]
    if any(not isinstance(image, str) or not image for image in images):
        return None
    return images


def assert_no_host_port(spec, label):
    containers = (
        spec.get("containers", [])
        + spec.get("initContainers", [])
        + spec.get("ephemeralContainers", [])
    )
    for container in containers:
        for port in container.get("ports", []):
            if port.get("hostPort") not in {None, 0}:
                raise SystemExit(f"{label} declares a hostPort")


def assert_restricted_spec(spec, label, allowed_capabilities=()):
    if any(spec.get(field) is True for field in ("hostNetwork", "hostPID", "hostIPC")):
        raise SystemExit(f"{label} enters a host namespace")
    if any("hostPath" in volume for volume in spec.get("volumes", [])):
        raise SystemExit(f"{label} mounts a hostPath")
    containers = (
        spec.get("containers", [])
        + spec.get("initContainers", [])
        + spec.get("ephemeralContainers", [])
    )
    for container in containers:
        security = container.get("securityContext", {})
        capabilities = security.get("capabilities", {})
        added = capabilities.get("add", [])
        if (
            security.get("privileged") is True
            or security.get("allowPrivilegeEscalation") is True
            or security.get("procMount") == "Unmasked"
            or not isinstance(added, list)
            or any(value not in allowed_capabilities for value in added)
        ):
            raise SystemExit(f"{label} contains a privileged container capability")
    assert_no_host_port(spec, label)


def stable_deployment(item, identity):
    meta = metadata(item)
    spec = item.get("spec", {})
    status = item.get("status", {})
    replicas = spec.get("replicas")
    generation = meta.get("generation")
    if (
        type(replicas) is not int
        or replicas < 1
        or type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or status.get("replicas") != replicas
        or status.get("updatedReplicas") != replicas
        or status.get("readyReplicas") != replicas
        or status.get("availableReplicas") != replicas
        or status.get("unavailableReplicas") not in {None, 0}
    ):
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} is not exactly stable")
    return replicas


def stable_daemonset(item, identity):
    meta = metadata(item)
    status = item.get("status", {})
    generation = meta.get("generation")
    desired = status.get("desiredNumberScheduled")
    if (
        type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or type(desired) is not int
        or desired != 1
        or status.get("currentNumberScheduled") != desired
        or status.get("updatedNumberScheduled") != desired
        or status.get("numberReady") != desired
        or status.get("numberAvailable") != desired
        or status.get("numberMisscheduled") not in {None, 0}
        or status.get("numberUnavailable") not in {None, 0}
    ):
        raise SystemExit(f"DaemonSet {identity[0]}/{identity[1]} is not exactly stable")
    return desired


namespace_items = load_items("namespaces.json")
expected_namespaces = {
    "default",
    "kube-node-lease",
    "kube-public",
    "kube-system",
    "flux-system",
    "kyverno",
    "cloudflare-public",
    "naranjo-online",
    "lidersea-com",
}
namespace_names = [metadata(item).get("name") for item in namespace_items]
if len(namespace_names) != len(expected_namespaces) or set(namespace_names) != expected_namespaces:
    raise SystemExit("live Namespace inventory differs from the exact release set")
for item in namespace_items:
    if item.get("status", {}).get("phase") != "Active" or metadata(item).get("deletionTimestamp") is not None:
        raise SystemExit("an expected Namespace is not exactly Active")

nodes = load_items("nodes.json")
if len(nodes) != 1:
    raise SystemExit("global inventory requires exactly one production node")
node_name = metadata(nodes[0]).get("name")
node_uid = metadata(nodes[0]).get("uid")
if (
    not isinstance(node_name, str)
    or not node_name
    or not isinstance(node_uid, str)
    or not node_uid
):
    raise SystemExit("production node identity is unavailable")

base_deployments = {
    ("naranjo-online", "naranjo-online"),
    ("lidersea-com", "lidersea-com"),
    ("cloudflare-public", "cloudflared"),
    ("kyverno", "kyverno-admission-controller"),
    ("flux-system", "source-controller"),
    ("flux-system", "kustomize-controller"),
    ("flux-system", "helm-controller"),
    ("kube-system", "coredns"),
}
provider_variants = {
    "cilium": (
        ("kube-system", "cilium-operator"),
        ("kube-system", "cilium"),
    ),
    "calico": (
        ("kube-system", "calico-kube-controllers"),
        ("kube-system", "calico-node"),
    ),
}
deployment_items = load_items("deployments.json")
daemonset_items = load_items("daemonsets.json")
deployment_identities = set(namespaced_identity(item) for item in deployment_items)
daemonset_identities = set(namespaced_identity(item) for item in daemonset_items)
provider = None
for candidate, (provider_deployment, provider_daemonset) in provider_variants.items():
    if (
        deployment_identities == base_deployments | {provider_deployment}
        and daemonset_identities
        == {("kube-system", "kube-proxy"), provider_daemonset}
    ):
        provider = candidate
        break
if provider is None:
    raise SystemExit("live Deployment/DaemonSet inventory is outside the exact kubeadm/CNI release variants")
provider_deployment, provider_daemonset = provider_variants[provider]
deployments = exact_namespaced_map(
    deployment_items, base_deployments | {provider_deployment}, "Deployment"
)
daemonsets = exact_namespaced_map(
    daemonset_items,
    {("kube-system", "kube-proxy"), provider_daemonset},
    "DaemonSet",
)

for filename, kind in (
    ("statefulsets.json", "StatefulSet"),
    ("replicationcontrollers.json", "ReplicationController"),
    ("jobs.json", "Job"),
    ("cronjobs.json", "CronJob"),
    ("horizontalpodautoscalers.json", "HorizontalPodAutoscaler"),
):
    if load_items(filename):
        raise SystemExit(f"live {kind} inventory must be empty")

expected_deployment_images = {
    ("naranjo-online", "naranjo-online"): naranjo_image,
    ("lidersea-com", "lidersea-com"): lidersea_image,
    ("cloudflare-public", "cloudflared"): cloudflared_image,
    ("kyverno", "kyverno-admission-controller"): admission_image,
    ("flux-system", "source-controller"): flux_source_image,
    ("flux-system", "kustomize-controller"): flux_kustomize_image,
    ("flux-system", "helm-controller"): flux_helm_image,
    ("kube-system", "coredns"): coredns_image,
}
provider_image = {
    "cilium": re.compile(r"quay[.]io/cilium/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z"),
    "calico": re.compile(r"docker[.]io/calico/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z"),
}[provider]
deployment_replicas = {}
for identity, deployment in deployments.items():
    deployment_replicas[identity] = stable_deployment(deployment, identity)
    template = deployment.get("spec", {}).get("template", {}).get("spec", {})
    images = container_images(template)
    if images is None:
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} has invalid container images")
    if identity == provider_deployment:
        if any(provider_image.fullmatch(image) is None or image.endswith("@sha256:" + "0" * 64) for image in images):
            raise SystemExit("CNI controller Deployment image is outside the reviewed provider registry/digest contract")
    elif images != [expected_deployment_images[identity]]:
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} image inventory differs from exact desired state")
    allowed_capabilities = {"NET_BIND_SERVICE"} if identity == ("kube-system", "coredns") else set()
    assert_restricted_spec(
        template,
        f"Deployment {identity[0]}/{identity[1]} template",
        allowed_capabilities,
    )

daemonset_desired = {}
for identity, daemonset in daemonsets.items():
    daemonset_desired[identity] = stable_daemonset(daemonset, identity)
    template = daemonset.get("spec", {}).get("template", {}).get("spec", {})
    images = container_images(template)
    if images is None:
        raise SystemExit(f"DaemonSet {identity[0]}/{identity[1]} has invalid container images")
    if identity == ("kube-system", "kube-proxy"):
        if images != [f"registry.k8s.io/kube-proxy:{kubernetes_version}"]:
            raise SystemExit("kube-proxy image differs from the exact reviewed Kubernetes version")
    elif any(provider_image.fullmatch(image) is None or image.endswith("@sha256:" + "0" * 64) for image in images):
        raise SystemExit("CNI DaemonSet image is outside the reviewed provider registry/digest contract")
    assert_no_host_port(template, f"DaemonSet {identity[0]}/{identity[1]} template")

replicasets = dynamic_namespaced_map(load_items("replicasets.json"), "ReplicaSet")
deployment_uids = {
    metadata(item)["uid"]: identity for identity, item in deployments.items()
}
active_replicasets = {}
replicaset_parent = {}
replicaset_identity_by_uid = {}
for identity, replicaset in replicasets.items():
    owner = one_controller_owner(replicaset, "ReplicaSet", identity)
    parent = deployment_uids.get(owner.get("uid"))
    if (
        owner.get("apiVersion") != "apps/v1"
        or owner.get("kind") != "Deployment"
        or parent is None
        or owner.get("name") != parent[1]
        or identity[0] != parent[0]
        or not identity[1].startswith(parent[1] + "-")
    ):
        raise SystemExit(f"ReplicaSet {identity[0]}/{identity[1]} is outside the exact Deployment UID chain")
    replicas = replicaset.get("spec", {}).get("replicas")
    if type(replicas) is not int or replicas < 0:
        raise SystemExit(f"ReplicaSet {identity[0]}/{identity[1]} has an invalid replica count")
    replicaset_parent[metadata(replicaset)["uid"]] = parent
    replicaset_identity_by_uid[metadata(replicaset)["uid"]] = identity
    if replicas:
        deployment = deployments[parent]
        deployment_selector = json.loads(
            json.dumps(deployment.get("spec", {}).get("selector", {}))
        )
        replicaset_selector = json.loads(
            json.dumps(replicaset.get("spec", {}).get("selector", {}))
        )
        deployment_template = json.loads(
            json.dumps(deployment.get("spec", {}).get("template", {}))
        )
        replicaset_template = json.loads(
            json.dumps(replicaset.get("spec", {}).get("template", {}))
        )
        selector_hash = replicaset_selector.get("matchLabels", {}).pop(
            "pod-template-hash", None
        )
        template_hash = replicaset_template.get("metadata", {}).get(
            "labels", {}
        ).pop("pod-template-hash", None)
        if (
            not isinstance(selector_hash, str)
            or not selector_hash
            or template_hash != selector_hash
            or replicaset_selector != deployment_selector
            or replicaset_template != deployment_template
            or replicas != deployment_replicas[parent]
            or replicaset.get("status", {}).get("readyReplicas") != replicas
            or replicaset.get("status", {}).get("availableReplicas") != replicas
        ):
            raise SystemExit(f"active ReplicaSet {identity[0]}/{identity[1]} differs from its exact stable Deployment")
        if parent in active_replicasets:
            raise SystemExit(f"Deployment {parent[0]}/{parent[1]} has more than one active ReplicaSet")
        active_replicasets[parent] = metadata(replicaset)["uid"]
    elif any(replicaset.get("status", {}).get(field, 0) not in {None, 0} for field in ("replicas", "readyReplicas", "availableReplicas")):
        raise SystemExit(f"inactive ReplicaSet {identity[0]}/{identity[1]} still has live replicas")
if set(active_replicasets) != set(deployments):
    raise SystemExit("each exact Deployment must have one and only one active ReplicaSet")

daemonset_uids = {
    metadata(item)["uid"]: identity for identity, item in daemonsets.items()
}
pod_counts = {identity: 0 for identity in deployments}
pod_counts.update({identity: 0 for identity in daemonsets})
static_expected = {
    ("kube-system", f"etcd-{node_name}"),
    ("kube-system", f"kube-apiserver-{node_name}"),
    ("kube-system", f"kube-controller-manager-{node_name}"),
    ("kube-system", f"kube-scheduler-{node_name}"),
}
static_seen = set()
pod_uids = set()
for pod in load_items("pods.json"):
    identity = namespaced_identity(pod)
    uid = metadata(pod).get("uid")
    if (
        identity[0] not in expected_namespaces
        or not isinstance(identity[1], str)
        or not identity[1]
        or not isinstance(uid, str)
        or not uid
        or uid in pod_uids
        or metadata(pod).get("deletionTimestamp") is not None
    ):
        raise SystemExit("live Pod inventory has an invalid, duplicate, or deleting identity")
    pod_uids.add(uid)
    spec = pod_spec(pod)
    images = container_images(spec)
    if images is None:
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} has invalid container images")
    owners = metadata(pod).get("ownerReferences", [])
    elevated = False
    expected_images = None
    restricted_allowed_capabilities = set()
    mirror_annotation = metadata(pod).get("annotations", {}).get(
        "kubernetes.io/config.mirror"
    )
    if identity in static_expected and mirror_annotation not in {None, ""}:
        if owners:
            owner = one_controller_owner(pod, "mirror Pod", identity)
            if (
                owner.get("apiVersion") != "v1"
                or owner.get("kind") != "Node"
                or owner.get("name") != node_name
                or owner.get("uid") != node_uid
            ):
                raise SystemExit(
                    f"mirror Pod {identity[0]}/{identity[1]} has an unexpected Node owner"
                )
        if (
            identity in static_seen
            or spec.get("nodeName") != node_name
            or spec.get("initContainers")
            or spec.get("ephemeralContainers")
        ):
            raise SystemExit(f"unowned Pod {identity[0]}/{identity[1]} is not one exact kubeadm mirror Pod")
        static_seen.add(identity)
        elevated = True
        component = identity[1][:-len(node_name) - 1]
        expected_images = {
            "etcd": [etcd_image],
            "kube-apiserver": [f"registry.k8s.io/kube-apiserver:{kubernetes_version}"],
            "kube-controller-manager": [f"registry.k8s.io/kube-controller-manager:{kubernetes_version}"],
            "kube-scheduler": [f"registry.k8s.io/kube-scheduler:{kubernetes_version}"],
        }.get(component)
    else:
        if not owners:
            raise SystemExit(
                f"unowned Pod {identity[0]}/{identity[1]} is not one exact kubeadm mirror Pod"
            )
        owner = one_controller_owner(pod, "Pod", identity)
        owner_uid = owner.get("uid")
        if owner.get("apiVersion") != "apps/v1" or owner.get("kind") not in {"ReplicaSet", "DaemonSet"}:
            raise SystemExit(f"Pod {identity[0]}/{identity[1]} has an unapproved controller kind")
        if owner.get("kind") == "ReplicaSet":
            parent = replicaset_parent.get(owner_uid)
            if (
                parent is None
                or active_replicasets.get(parent) != owner_uid
                or owner.get("name") != replicaset_identity_by_uid.get(owner_uid, (None, None))[1]
                or identity[0] != parent[0]
                or not identity[1].startswith(owner.get("name", "") + "-")
            ):
                raise SystemExit(f"Pod {identity[0]}/{identity[1]} is outside the active Deployment UID chain")
            pod_counts[parent] += 1
            expected_images = container_images(
                deployments[parent].get("spec", {}).get("template", {}).get("spec", {})
            )
            if parent == ("kube-system", "coredns"):
                restricted_allowed_capabilities = {"NET_BIND_SERVICE"}
        else:
            parent = daemonset_uids.get(owner_uid)
            if (
                parent is None
                or owner.get("name") != parent[1]
                or identity[0] != parent[0]
                or not identity[1].startswith(parent[1] + "-")
            ):
                raise SystemExit(f"Pod {identity[0]}/{identity[1]} is outside the exact DaemonSet UID chain")
            pod_counts[parent] += 1
            elevated = True
            expected_images = container_images(
                daemonsets[parent].get("spec", {}).get("template", {}).get("spec", {})
            )
    if images != expected_images:
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} image inventory differs from its exact controller")
    if pod.get("status", {}).get("phase") != "Running":
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} is not Running")
    ready = [
        condition
        for condition in pod.get("status", {}).get("conditions", [])
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    if len(ready) != 1 or ready[0].get("status") != "True":
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} is not exactly Ready")
    assert_no_host_port(spec, f"Pod {identity[0]}/{identity[1]}")
    if not elevated:
        assert_restricted_spec(
            spec,
            f"Pod {identity[0]}/{identity[1]}",
            restricted_allowed_capabilities,
        )
if static_seen != static_expected:
    raise SystemExit("live kubeadm mirror Pod inventory is incomplete")
expected_pod_counts = dict(deployment_replicas)
expected_pod_counts.update(daemonset_desired)
if pod_counts != expected_pod_counts:
    raise SystemExit("live controller-owned Pod counts differ from exact stable controller replicas")

expected_services = {
    ("default", "kubernetes"),
    ("kube-system", "kube-dns"),
    ("flux-system", "source-controller"),
    ("kyverno", "kyverno-svc"),
    ("naranjo-online", "naranjo-online"),
    ("lidersea-com", "lidersea-com"),
}
services = exact_namespaced_map(load_items("services.json"), expected_services, "Service")
for identity, service in services.items():
    spec = service.get("spec", {})
    if (
        spec.get("type", "ClusterIP") != "ClusterIP"
        or spec.get("externalIPs")
        or spec.get("externalName")
        or spec.get("healthCheckNodePort") not in {None, 0}
        or any(port.get("nodePort") not in {None, 0} for port in spec.get("ports", []))
    ):
        raise SystemExit(f"Service {identity[0]}/{identity[1]} has a direct-origin exposure field")

if load_items("mutatingwebhooks.json"):
    raise SystemExit("live MutatingWebhookConfiguration inventory must be empty")
validating = load_items("webhooks.json")
if len(validating) != 1 or metadata(validating[0]).get("name") != "kyverno-resource-validating-webhook-cfg":
    raise SystemExit("live ValidatingWebhookConfiguration inventory differs from the exact Kyverno boundary")
tenant_namespaces = {"cloudflare-public", "naranjo-online", "lidersea-com"}
webhooks = validating[0].get("webhooks", [])
if not isinstance(webhooks, list) or not webhooks:
    raise SystemExit("exact Kyverno validating webhook set is unavailable")
for webhook in webhooks:
    service = webhook.get("clientConfig", {}).get("service", {})
    selector = webhook.get("namespaceSelector", {})
    expressions = selector.get("matchExpressions", [])
    if (
        webhook.get("failurePolicy") != "Fail"
        or service.get("namespace") != "kyverno"
        or service.get("name") != "kyverno-svc"
        or selector.get("matchLabels")
        or not isinstance(expressions, list)
        or len(expressions) != 1
        or expressions[0].get("key") != "kubernetes.io/metadata.name"
        or expressions[0].get("operator") != "In"
        or set(expressions[0].get("values", [])) != tenant_namespaces
        or len(expressions[0].get("values", [])) != len(tenant_namespaces)
    ):
        raise SystemExit("live Kyverno validating webhook does not fail closed over the exact tenant set")

print(
    "release-gate: PASS exact global namespace, controller, Pod, Service, and admission inventories are closed"
)
