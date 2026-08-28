"""Reference fail-closed primitives for the #189 bootstrap closure review.

This is isolated design evidence, not repository code and not a live executor.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping


class ClosureError(ValueError):
    pass


SITES = ("naranjo-online", "lidersea-com")
GIT_GVR = "source.toolkit.fluxcd.io/v1/gitrepositories"
TARGET_SOURCE = f"{GIT_GVR}|flux-system|flux-system"
SEMVER = ">=0.1.9 <1.0.0"
RELEASE_ANNOTATION = "platform.snaraj.dev/chart-release"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
VOLATILE_ANNOTATIONS = {"kubectl.kubernetes.io/last-applied-configuration"}

CONSUMER_GVRS = {
    "kustomizations": "kustomize.toolkit.fluxcd.io/v1/kustomizations",
    "helmcharts": "source.toolkit.fluxcd.io/v1/helmcharts",
    "helmreleases": "helm.toolkit.fluxcd.io/v2/helmreleases",
    "externalartifacts": "source.toolkit.fluxcd.io/v1/externalartifacts",
}
EXPECTED_POST_CONSUMERS = {
    f"{CONSUMER_GVRS['kustomizations']}|flux-system|naranjo-online-reconciler",
    f"{CONSUMER_GVRS['kustomizations']}|flux-system|lidersea-com-reconciler",
}


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ClosureError(f"{label} is malformed")
    return value


def _identity(item: dict, gvr: str) -> tuple[str, str, str]:
    metadata = _mapping(item.get("metadata"), "consumer metadata")
    namespace, name = metadata.get("namespace"), metadata.get("name")
    if not isinstance(namespace, str) or not namespace or not isinstance(name, str) or not name:
        raise ClosureError("consumer identity is incomplete")
    return namespace, name, f"{gvr}|{namespace}|{name}"


def _record_reference(
    result: list[dict[str, str]], gvr: str, item: dict, source: object
) -> None:
    ref = _mapping(source, "sourceRef")
    kind = ref.get("kind")
    if not isinstance(kind, str) or not kind:
        raise ClosureError("sourceRef kind is incomplete")
    if kind != "GitRepository":
        return
    namespace, _, key = _identity(item, gvr)
    name = ref.get("name")
    source_namespace = ref.get("namespace", namespace)
    api_version = ref.get("apiVersion", "source.toolkit.fluxcd.io/v1")
    if not all(isinstance(value, str) and value for value in (name, source_namespace, api_version)):
        raise ClosureError("GitRepository source identity is incomplete")
    result.append(
        {
            "key": key,
            "source": f"{api_version}/gitrepositories|{source_namespace}|{name}",
        }
    )


def enumerate_git_consumers(collections: Mapping[str, object]) -> list[dict[str, str]]:
    """Enumerate every effective GitRepository reference in the four served APIs."""
    if set(collections) != set(CONSUMER_GVRS):
        raise ClosureError("consumer API inventory is incomplete or foreign")
    result: list[dict[str, str]] = []
    seen_objects: set[str] = set()
    for resource, gvr in CONSUMER_GVRS.items():
        items = collections[resource]
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise ClosureError(f"{resource} inventory is malformed")
        for item in items:
            namespace, name, key = _identity(item, gvr)
            del namespace, name
            if key in seen_objects:
                raise ClosureError("duplicate consumer object identity")
            seen_objects.add(key)
            spec = _mapping(item.get("spec"), "consumer spec")
            if resource == "helmreleases":
                chart = spec.get("chart")
                chart_ref = spec.get("chartRef")
                if chart is not None and chart_ref is not None:
                    raise ClosureError("HelmRelease has both chart and chartRef")
                if chart is None:
                    continue
                chart = _mapping(chart, "HelmRelease chart")
                chart_spec = _mapping(chart.get("spec"), "HelmRelease inline chart spec")
                if "sourceRef" not in chart_spec:
                    raise ClosureError("HelmRelease inline sourceRef is absent")
                _record_reference(result, gvr, item, chart_spec["sourceRef"])
            else:
                if "sourceRef" not in spec:
                    # ExternalArtifact's installed CRD does not require this
                    # optional field. An absent ref is not an effective source
                    # consumer; the other two kinds require it by schema.
                    if resource == "externalartifacts":
                        continue
                    raise ClosureError(f"{resource} sourceRef is absent")
                _record_reference(result, gvr, item, spec["sourceRef"])
    result.sort(key=lambda value: value["key"])
    return result


def validate_consumers(consumers: list[dict[str, str]], phase: str) -> None:
    if phase not in {"pre", "initial", "post"}:
        raise ClosureError("consumer phase is invalid")
    if not all(isinstance(item, dict) and set(item) == {"key", "source"} for item in consumers):
        raise ClosureError("consumer receipt is malformed")
    keys = [item["key"] for item in consumers]
    if len(keys) != len(set(keys)):
        raise ClosureError("duplicate GitRepository consumer")
    actual = set(keys)
    if phase == "pre":
        valid_keys = actual == set()
    elif phase == "initial":
        valid_keys = actual.issubset(EXPECTED_POST_CONSUMERS)
    else:
        valid_keys = actual == EXPECTED_POST_CONSUMERS
    if not valid_keys or any(item["source"] != TARGET_SOURCE for item in consumers):
        raise ClosureError("legacy or foreign GitRepository consumer exists")


def _meta(name: str, namespace: str) -> dict:
    return {"name": name, "namespace": namespace}


def _rule(groups: list[str], resources: list[str], verbs: list[str], names=None) -> dict:
    result = {"apiGroups": groups, "resources": resources, "verbs": verbs}
    if names is not None:
        result["resourceNames"] = names
    return result


def expected_site_chain() -> dict[str, dict]:
    result: dict[str, dict] = {}
    lifecycle = ["get", "list", "watch", "create", "update", "patch", "delete"]
    readonly = ["get", "list", "watch"]
    for site in SITES:
        values = {
            "Role|flux-controller-impersonation": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": _meta("flux-controller-impersonation", site),
                "rules": [_rule([""], ["serviceaccounts"], ["impersonate"], ["helm-reconciler"])],
            },
            "RoleBinding|flux-controller-impersonation": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": _meta("flux-controller-impersonation", site),
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "flux-controller-impersonation"},
                "subjects": [{"kind": "ServiceAccount", "name": "helm-controller", "namespace": "flux-system"}],
            },
            "ServiceAccount|helm-reconciler": {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": _meta("helm-reconciler", site),
                "automountServiceAccountToken": False,
            },
            "RoleBinding|helm-reconciler": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": _meta("helm-reconciler", site),
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "helm-reconciler"},
                "subjects": [{"kind": "ServiceAccount", "name": "helm-reconciler", "namespace": site}],
            },
        }
        rules = [_rule([""], ["configmaps", "secrets", "services", "serviceaccounts"], lifecycle)]
        if site == "naranjo-online":
            rules.append(_rule([""], ["persistentvolumeclaims"], lifecycle))
        rules.extend(
            [
                _rule([""], ["pods"], readonly),
                _rule(["apps"], ["deployments"], lifecycle),
                _rule(["apps"], ["replicasets"], readonly),
                _rule(["networking.k8s.io"], ["networkpolicies"], lifecycle),
            ]
        )
        values["Role|helm-reconciler"] = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": _meta("helm-reconciler", site),
            "rules": rules,
        }
        for suffix, value in values.items():
            result[f"{site}|{suffix}"] = value
    return result


def _normalized_metadata(metadata: object) -> dict:
    metadata = _mapping(metadata, "metadata")
    allowed = {
        "annotations", "creationTimestamp", "deletionGracePeriodSeconds",
        "deletionTimestamp", "finalizers", "generateName", "generation",
        "labels", "managedFields", "name", "namespace", "ownerReferences",
        "resourceVersion", "selfLink", "uid",
    }
    if set(metadata) - allowed or metadata.get("generateName") not in (None, ""):
        raise ClosureError("metadata has a foreign field")
    if metadata.get("deletionTimestamp") is not None or metadata.get("ownerReferences") not in (None, []):
        raise ClosureError("object is deleting or owned")
    if metadata.get("finalizers") not in (None, []):
        raise ClosureError("object has a foreign finalizer")
    result = {key: copy.deepcopy(metadata[key]) for key in ("name", "namespace", "labels") if key in metadata}
    annotations = {
        key: value
        for key, value in _mapping(metadata.get("annotations", {}), "annotations").items()
        if key not in VOLATILE_ANNOTATIONS
    }
    if annotations:
        result["annotations"] = annotations
    return result


def _normalize_rbac(value: dict) -> dict:
    allowed = {
        "apiVersion", "automountServiceAccountToken", "kind", "metadata",
        "roleRef", "rules", "subjects",
    }
    if set(value) - allowed:
        raise ClosureError("site execution-chain object has a foreign field")
    result = {
        "apiVersion": value.get("apiVersion"),
        "kind": value.get("kind"),
        "metadata": _normalized_metadata(value.get("metadata")),
    }
    for key in ("automountServiceAccountToken", "roleRef", "subjects"):
        if key in value:
            result[key] = copy.deepcopy(value[key])
    if value.get("kind") == "RoleBinding" and "subjects" not in result:
        # Kubernetes may omit an empty `omitempty` slice on the GET response.
        result["subjects"] = []
    if "rules" in value:
        if not isinstance(value["rules"], list):
            raise ClosureError("RBAC rules are malformed")
        rules = []
        for rule in value["rules"]:
            rule = _mapping(rule, "RBAC rule")
            if set(rule) - {"apiGroups", "resources", "verbs", "resourceNames"}:
                raise ClosureError("RBAC rule has a foreign field")
            normalized = {}
            for key in ("apiGroups", "resources", "verbs", "resourceNames"):
                if key in rule:
                    if not isinstance(rule[key], list) or not all(isinstance(item, str) for item in rule[key]):
                        raise ClosureError("RBAC rule list is malformed")
                    normalized[key] = sorted(rule[key])
            rules.append(normalized)
        result["rules"] = sorted(rules, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(result.get("subjects"), list):
        result["subjects"] = sorted(
            result["subjects"], key=lambda item: json.dumps(item, sort_keys=True)
        )
    return result


def validate_site_chain(objects: Mapping[str, object]) -> None:
    expected = expected_site_chain()
    if set(objects) != set(expected):
        raise ClosureError("site execution-chain inventory is not exactly ten objects")
    for key in sorted(expected):
        live = _mapping(objects[key], key)
        if _normalize_rbac(live) != _normalize_rbac(expected[key]):
            raise ClosureError(f"site execution-chain object is foreign: {key}")


def validate_site_chain_state(objects: Mapping[str, object]) -> str:
    """Accept only an exact chain with both Helm bindings active or both revoked."""
    expected = expected_site_chain()
    if set(objects) != set(expected):
        raise ClosureError("site execution-chain inventory is not exactly ten objects")
    binding_keys = {
        f"{site}|RoleBinding|helm-reconciler" for site in SITES
    }
    for key in sorted(set(expected) - binding_keys):
        live = _mapping(objects[key], key)
        if _normalize_rbac(live) != _normalize_rbac(expected[key]):
            raise ClosureError(f"site execution-chain object is foreign: {key}")
    states: list[str] = []
    for key in sorted(binding_keys):
        live = _mapping(objects[key], key)
        if _normalize_rbac(live) == _normalize_rbac(expected[key]):
            states.append("active")
            continue
        quarantined = copy.deepcopy(expected[key])
        quarantined["subjects"] = []
        if _normalize_rbac(live) == _normalize_rbac(quarantined):
            states.append("quarantined")
            continue
        raise ClosureError(f"site execution-chain object is foreign: {key}")
    return states[0] if len(set(states)) == 1 else "mixed"


def validate_site_restore_boundary(objects: Mapping[str, object], site: str) -> None:
    """Prove the exact ten-object chain at one ordered binding restore."""
    if site not in SITES:
        raise ClosureError("site restore boundary is foreign")
    expected = expected_site_chain()
    if set(objects) != set(expected):
        raise ClosureError("site execution-chain inventory is not exactly ten objects")
    expected_binding_states = {
        "naranjo-online": {
            "naranjo-online": "quarantined",
            "lidersea-com": "quarantined",
        },
        "lidersea-com": {
            "naranjo-online": "active",
            "lidersea-com": "quarantined",
        },
    }[site]
    for key in sorted(expected):
        wanted = copy.deepcopy(expected[key])
        if key.endswith("|RoleBinding|helm-reconciler"):
            binding_site = key.split("|", 1)[0]
            if expected_binding_states[binding_site] == "quarantined":
                wanted["subjects"] = []
        live = _mapping(objects[key], key)
        if _normalize_rbac(live) != _normalize_rbac(wanted):
            raise ClosureError(f"site restore boundary object is foreign: {key}")


def _binding_state(live: dict, expected: dict, quarantined: bool) -> None:
    wanted = copy.deepcopy(expected)
    if quarantined:
        wanted["subjects"] = []
    if _normalize_rbac(live) != _normalize_rbac(wanted):
        raise ClosureError("helm RoleBinding authority state is foreign")


def rolebinding_replace(live: dict, expected: dict, quarantine: bool) -> dict:
    _binding_state(live, expected, not quarantine)
    metadata = _mapping(live.get("metadata"), "RoleBinding metadata")
    if not all(isinstance(metadata.get(key), str) and metadata[key] for key in ("uid", "resourceVersion")):
        raise ClosureError("RoleBinding transition lacks UID/resourceVersion")
    request = copy.deepcopy(live)
    request.pop("status", None)
    request_meta = request["metadata"]
    for key in ("creationTimestamp", "generation", "managedFields", "selfLink"):
        request_meta.pop(key, None)
    request["subjects"] = [] if quarantine else copy.deepcopy(expected["subjects"])
    return request


def validate_rolebinding_result(before: dict, after: dict, expected: dict, quarantined: bool) -> None:
    _binding_state(before, expected, not quarantined)
    _binding_state(after, expected, quarantined)
    before_meta = _mapping(before.get("metadata"), "before metadata")
    after_meta = _mapping(after.get("metadata"), "after metadata")
    if before_meta.get("uid") != after_meta.get("uid") or not isinstance(after_meta.get("uid"), str):
        raise ClosureError("RoleBinding UID changed")
    before_rv, after_rv = before_meta.get("resourceVersion"), after_meta.get("resourceVersion")
    if not all(isinstance(value, str) and value for value in (before_rv, after_rv)) or before_rv == after_rv:
        raise ClosureError("RoleBinding resourceVersion did not advance")
    for field in ("annotations", "labels"):
        if before_meta.get(field) != after_meta.get(field):
            raise ClosureError(f"RoleBinding {field} changed")


def require_both_helm_bindings_quarantined(objects: Mapping[str, object]) -> None:
    expected = expected_site_chain()
    for site in SITES:
        key = f"{site}|RoleBinding|helm-reconciler"
        if key not in objects:
            raise ClosureError("helm RoleBinding quarantine inventory is incomplete")
        _binding_state(_mapping(objects[key], key), expected[key], True)


def _normalize_oci(value: dict) -> dict:
    metadata = _mapping(value.get("metadata"), "OCI metadata")
    finalizers = metadata.get("finalizers", [])
    if not isinstance(finalizers, list) or any(item != "finalizers.fluxcd.io" for item in finalizers):
        raise ClosureError("OCIRepository has a foreign finalizer")
    spec = copy.deepcopy(_mapping(value.get("spec"), "OCI spec"))
    # The installed structural schema defaults the public-registry provider.
    # It is the sole desired-state default omitted by the reviewed manifest.
    if spec.get("provider") == "generic":
        spec.pop("provider")
    result = {
        "apiVersion": value.get("apiVersion"),
        "kind": value.get("kind"),
        "metadata": _normalized_metadata({**metadata, "finalizers": []}),
        "spec": spec,
    }
    return result


def oci_migration_patch(live: dict, target: dict) -> list[dict]:
    target_spec = _mapping(target.get("spec"), "target OCI spec")
    target_ref = _mapping(target_spec.get("ref"), "target OCI ref")
    digest = target_ref.get("digest")
    if set(target_ref) != {"digest"} or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest) or digest == "sha256:" + "0" * 64:
        raise ClosureError("target OCI digest is invalid")
    target_meta = _mapping(target.get("metadata"), "target OCI metadata")
    annotations = _mapping(target_meta.get("annotations"), "target OCI annotations")
    release = annotations.get(RELEASE_ANNOTATION)
    if set(annotations) != {RELEASE_ANNOTATION} or not isinstance(release, str) or not re.fullmatch(r"0\.[1-9][0-9]*\.[1-9][0-9]*", release):
        raise ClosureError("target OCI annotation is invalid")
    expected_old = copy.deepcopy(target)
    expected_old["metadata"].pop("annotations", None)
    expected_old["spec"]["ref"] = {"semver": SEMVER}
    if _normalize_oci(live) != _normalize_oci(expected_old):
        raise ClosureError("live OCIRepository is not the exact old semver state")
    metadata = _mapping(live.get("metadata"), "live OCI metadata")
    uid, resource_version = metadata.get("uid"), metadata.get("resourceVersion")
    if not all(isinstance(value, str) and value for value in (uid, resource_version)):
        raise ClosureError("OCI migration lacks UID/resourceVersion")
    raw_annotations = metadata.get("annotations")
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/spec/ref", "value": {"semver": SEMVER}},
    ]
    mutations = [
        {"op": "replace", "path": "/spec/ref", "value": {"digest": digest}},
    ]
    if raw_annotations is None:
        operations.append({"op": "test", "path": "/metadata", "value": copy.deepcopy(metadata)})
        mutations.append({"op": "add", "path": "/metadata/annotations", "value": {RELEASE_ANNOTATION: release}})
    else:
        raw_annotations = _mapping(raw_annotations, "live OCI annotations")
        operations.append({"op": "test", "path": "/metadata/annotations", "value": copy.deepcopy(raw_annotations)})
        mutations.append({"op": "add", "path": "/metadata/annotations/platform.snaraj.dev~1chart-release", "value": release})
    return operations + mutations


def validate_oci_result(before: dict, after: dict, target: dict) -> None:
    if _normalize_oci(after) != _normalize_oci(target):
        raise ClosureError("OCIRepository poststate is not exact target")
    before_meta = _mapping(before.get("metadata"), "before OCI metadata")
    after_meta = _mapping(after.get("metadata"), "after OCI metadata")
    if before_meta.get("uid") != after_meta.get("uid"):
        raise ClosureError("OCIRepository UID changed")
    if before_meta.get("resourceVersion") == after_meta.get("resourceVersion"):
        raise ClosureError("OCIRepository resourceVersion did not advance")


def normalized_parent_inventory(site: str, entries: object) -> list[dict[str, str]]:
    if site not in SITES or not isinstance(entries, list):
        raise ClosureError("parent inventory is malformed")
    expected = {
        (f"{site}_default-deny_networking.k8s.io_NetworkPolicy", "v1"),
        (f"{site}_{site}-chart_source.toolkit.fluxcd.io_OCIRepository", "v1"),
        (f"{site}_{site}_helm.toolkit.fluxcd.io_HelmRelease", "v2"),
    }
    observed = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "v"}:
            raise ClosureError("parent inventory entry is malformed")
        pair = (entry["id"], entry["v"])
        if not all(isinstance(item, str) and item for item in pair):
            raise ClosureError("parent inventory identity is incomplete")
        observed.append(pair)
    if len(observed) != 3 or set(observed) != expected:
        raise ClosureError("parent inventory is not the exact three-object closure")
    return [{"id": identity, "v": version} for identity, version in sorted(observed)]


def _normalized_child(value: dict, kind: str) -> dict:
    """Close child desired state while removing only API-server metadata.

    The first bootstrap deliberately does not use a broad SSA comparison:
    fields retained from a foreign manager are authority-bearing desired state
    and therefore remain visible here.
    """
    if set(value) - {"apiVersion", "kind", "metadata", "spec", "status"}:
        raise ClosureError("site child has a foreign top-level field")
    if value.get("kind") != kind:
        raise ClosureError("site child kind is foreign")
    metadata = _mapping(value.get("metadata"), "site child metadata")
    finalizers = metadata.get("finalizers", [])
    allowed_finalizers = (
        ["finalizers.fluxcd.io"]
        if kind in {"OCIRepository", "HelmRelease", "Kustomization"}
        else []
    )
    if finalizers not in ([], allowed_finalizers):
        raise ClosureError("site child has a foreign finalizer")
    closed_metadata = _normalized_metadata({**metadata, "finalizers": []})
    spec = copy.deepcopy(_mapping(value.get("spec"), "site child spec"))
    if kind == "OCIRepository" and spec.get("provider") == "generic":
        spec.pop("provider")
    return {
        "apiVersion": value.get("apiVersion"),
        "kind": kind,
        "metadata": closed_metadata,
        "spec": spec,
    }


def expected_site_children(site: str, oci: dict) -> dict[str, dict]:
    if site not in SITES:
        raise ClosureError("site child identity is foreign")
    release = {
        "apiVersion": "helm.toolkit.fluxcd.io/v2",
        "kind": "HelmRelease",
        "metadata": {
            "annotations": {
                "platform.snaraj.dev/readiness":
                    "active-via-signature-verified-chart",
            },
            "name": site,
            "namespace": site,
        },
        "spec": {
            "chartRef": {"kind": "OCIRepository", "name": site + "-chart"},
            "driftDetection": {"mode": "enabled"},
            "install": {"remediation": {"retries": 0}},
            "interval": "10m0s",
            "maxHistory": 2,
            "releaseName": site,
            "serviceAccountName": "helm-reconciler",
            "suspend": False,
            "upgrade": {
                "cleanupOnFail": True,
                "remediation": {"retries": 0, "strategy": "rollback"},
            },
            "values": {"deploymentReady": True},
        },
    }
    network = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny", "namespace": site},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    }
    return {"networkpolicy": network, "oci": copy.deepcopy(oci), "helmrelease": release}


def validate_site_children(site: str, objects: Mapping[str, object], oci: dict) -> None:
    expected = expected_site_children(site, oci)
    if set(objects) != set(expected):
        raise ClosureError("site child inventory is not exactly three objects")
    for key, kind in (
        ("networkpolicy", "NetworkPolicy"),
        ("oci", "OCIRepository"),
        ("helmrelease", "HelmRelease"),
    ):
        live = _mapping(objects[key], f"{site} {key}")
        if _normalized_child(live, kind) != _normalized_child(expected[key], kind):
            raise ClosureError(f"{site} {key} desired state is foreign")


def _current_true_condition(value: dict, condition_type: str) -> None:
    metadata = _mapping(value.get("metadata"), "readiness metadata")
    status = _mapping(value.get("status"), "readiness status")
    generation = metadata.get("generation")
    conditions = status.get("conditions")
    if (
        type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or not isinstance(conditions, list)
    ):
        raise ClosureError("readiness does not observe the current generation")
    matches = [
        condition for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == condition_type
    ]
    if (
        len(matches) != 1
        or matches[0].get("status") != "True"
        or matches[0].get("observedGeneration") not in (None, generation)
    ):
        raise ClosureError(f"{condition_type} is not uniquely current and true")


def validate_oci_ready(value: dict, target: dict) -> None:
    if _normalized_child(value, "OCIRepository") != _normalized_child(
        target, "OCIRepository"
    ):
        raise ClosureError("OCIRepository desired state is foreign")
    _current_true_condition(value, "SourceVerified")
    _current_true_condition(value, "Ready")


def validate_helmrelease_ready(value: dict, target: dict) -> None:
    if _normalized_child(value, "HelmRelease") != _normalized_child(
        target, "HelmRelease"
    ):
        raise ClosureError("HelmRelease desired state is foreign")
    _current_true_condition(value, "Ready")


def validate_parent_attempted(
    site: str,
    value: dict,
    expected: dict,
    revision: str,
) -> None:
    """Require the parent to have applied exactly its three-child inventory.

    A wait:true parent cannot be Ready while Helm authority is quarantined, so
    lastAttemptedRevision plus the closed inventory is the safe intermediate
    boundary. Terminal Ready is proved separately after restoring that site's
    exact Helm RoleBinding.
    """
    if not isinstance(revision, str) or not re.fullmatch(
        r"v0\.1\.[1-9][0-9]*@sha1:[0-9a-f]{40}", revision
    ):
        raise ClosureError("parent revision is invalid")
    if _normalized_child(value, "Kustomization") != _normalized_child(
        expected, "Kustomization"
    ):
        raise ClosureError("parent desired state is foreign")
    metadata = _mapping(value.get("metadata"), "parent metadata")
    status = _mapping(value.get("status"), "parent status")
    generation = metadata.get("generation")
    if (
        type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or status.get("lastAttemptedRevision") != revision
    ):
        raise ClosureError("parent did not attempt the exact current revision")
    inventory = _mapping(status.get("inventory"), "parent inventory")
    if set(inventory) != {"entries"}:
        raise ClosureError("parent inventory fields are incomplete or foreign")
    normalized_parent_inventory(site, inventory.get("entries"))
