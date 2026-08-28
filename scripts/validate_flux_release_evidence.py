"""Validate captured Flux revision and network-policy live evidence.

Extracted verbatim from the retired release-gate.sh --live lane so the unit
suite keeps executing this validator while the post-cutover successor gate is
built. argv: STATE_ROOT RELEASE_GIT_COMMIT. STATE_ROOT holds the kubectl JSON
captures and server-normalized desired NetworkPolicy JSON the successor must
produce.
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("release Git commit is unavailable or non-canonical")
expected_git_revision = "main@sha1:" + commit


def load_items(name):
    document = json.loads((root / name).read_text(encoding="utf-8"))
    items = document.get("items")
    if not isinstance(items, list):
        raise SystemExit(f"{name} does not contain one Kubernetes item list")
    return items


def metadata(item):
    value = item.get("metadata", {})
    return value if isinstance(value, dict) else {}


def status(item):
    value = item.get("status", {})
    return value if isinstance(value, dict) else {}


def one_ready(item, kind, identity):
    conditions = status(item).get("conditions", [])
    ready = [
        condition
        for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    if len(ready) != 1 or ready[0].get("status") != "True":
        raise SystemExit(f"{kind} {identity} does not have exactly one Ready=True condition")


def one_source_verified(item, identity, generation):
    conditions = status(item).get("conditions", [])
    verified = [
        condition
        for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == "SourceVerified"
    ]
    if (
        len(verified) != 1
        or verified[0].get("status") != "True"
        or verified[0].get("reason") != "Succeeded"
        or verified[0].get("observedGeneration") != generation
    ):
        raise SystemExit(
            f"OCIRepository {identity} does not have exact SourceVerified=True/Succeeded"
        )


def exact_generation(item, kind, identity):
    generation = metadata(item).get("generation")
    observed = status(item).get("observedGeneration")
    if (
        type(generation) is not int
        or generation < 1
        or type(observed) is not int
        or observed != generation
    ):
        raise SystemExit(f"{kind} {identity} has not observed its exact current generation")
    return generation


def by_identity(items, namespace, name, kind):
    matches = [
        item
        for item in items
        if metadata(item).get("namespace") == namespace
        and metadata(item).get("name") == name
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one {kind} {namespace}/{name}, found {len(matches)}"
        )
    return matches[0]


def exact_namespaced_inventory(items, expected, kind):
    identities = []
    for item in items:
        if not isinstance(item, dict):
            raise SystemExit(f"{kind} inventory contains a non-object item")
        identities.append(
            (metadata(item).get("namespace"), metadata(item).get("name"))
        )
    if len(identities) != len(expected) or set(identities) != expected:
        raise SystemExit(f"live {kind} inventory differs from the exact release set")


def desired_flux_object(kind, api_version, namespace, name):
    path = root / "desired-flux-{}-{}-{}.json".format(
        kind.lower(), namespace, name
    )
    desired = json.loads(path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != api_version
        or desired.get("kind") != kind
        or metadata(desired).get("namespace") != namespace
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(f"desired {kind} normalization is invalid: {namespace}/{name}")
    return desired


kustomization_identities = {
    ("flux-system", "flux-system"),
    ("flux-system", "platform-prerequisites"),
    ("flux-system", "platform-services"),
    ("flux-system", "naranjo-online"),
    ("flux-system", "lidersea-com"),
}
kustomizations = load_items("kustomizations.json")
exact_namespaced_inventory(
    kustomizations, kustomization_identities, "Kustomization"
)
for name in (
    "flux-system",
    "platform-prerequisites",
    "platform-services",
    "naranjo-online",
    "lidersea-com",
):
    identity = "flux-system/" + name
    item = by_identity(kustomizations, "flux-system", name, "Kustomization")
    desired = desired_flux_object(
        "Kustomization",
        "kustomize.toolkit.fluxcd.io/v1",
        "flux-system",
        name,
    )
    exact_generation(item, "Kustomization", identity)
    one_ready(item, "Kustomization", identity)
    current_status = status(item)
    if (
        current_status.get("lastAppliedRevision") != expected_git_revision
        or current_status.get("lastAttemptedRevision") != expected_git_revision
    ):
        raise SystemExit(
            f"Kustomization {identity} is not applied and attempted at exact local HEAD"
        )
    if item.get("spec") != desired.get("spec"):
        raise SystemExit(f"Kustomization {identity} spec differs from exact desired state")


# Only this repository's own desired state and the connector chart still come
# from Git. Each site's chart is a published, signature-verified OCI artifact,
# so a live GitRepository in a site namespace is itself a finding.
source_identities = {
    ("flux-system", "flux-system"),
    ("cloudflare-public", "cloudflare-public-source"),
}
gitrepositories = load_items("gitrepositories.json")
exact_namespaced_inventory(gitrepositories, source_identities, "GitRepository")
for namespace, name in sorted(source_identities):
    identity = f"{namespace}/{name}"
    item = by_identity(gitrepositories, namespace, name, "GitRepository")
    desired = desired_flux_object(
        "GitRepository", "source.toolkit.fluxcd.io/v1", namespace, name
    )
    exact_generation(item, "GitRepository", identity)
    one_ready(item, "GitRepository", identity)
    spec = item.get("spec", {})
    artifact = status(item).get("artifact", {})
    if (
        spec.get("url") != "https://github.com/snaraj/website-infrastructure.git"
        or spec.get("ref") != {"branch": "main"}
        or not isinstance(artifact, dict)
        or artifact.get("revision") != expected_git_revision
    ):
        raise SystemExit(f"GitRepository {identity} is not the exact current main artifact")
    if spec != desired.get("spec"):
        raise SystemExit(f"GitRepository {identity} spec differs from exact desired state")


for filename, kind in (
    ("buckets.json", "Bucket"),
    ("externalartifacts.json", "ExternalArtifact"),
    ("helmrepositories.json", "HelmRepository"),
):
    if load_items(filename):
        raise SystemExit(f"live {kind} inventory must be empty")


# Chart sources: exactly two, one per site, each verified against that site's
# own keyless publisher identity. Flux selects the exact OCI manifest digest;
# the human chart release annotation is audit metadata, not a mutable selector.
oci_chart_sources = {
    ("naranjo-online", "naranjo-online-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/naranjo-online",
        "tag": "0.1.54",
        "digest": "sha256:7223dd78f308c1e211da71f6e062195724aaedc47962b0a04907eeb0baf2d7bb",
        "artifact_digest": "sha256:56d37664cfedcddafcc9bd440b69e27b1f386012b9fe55868dd7d0e8d773a494",
        "subject": (
            r"^https://github\.com/snaraj/naranjo\.online/\.github/workflows/"
            r"release-publisher\.yml@refs/heads/main$"
        ),
    },
    ("lidersea-com", "lidersea-com-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/lidersea-com",
        "tag": "0.1.37",
        "digest": "sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc",
        "artifact_digest": "sha256:1190b1297885d233a01f362467a00eb8f32c49ca5843edeb8af53d5a25f21b3b",
        "subject": (
            r"^https://github\.com/snaraj/lidersea\.com/\.github/workflows/"
            r"release-publisher\.yml@refs/heads/main$"
        ),
    },
}
EXPECTED_CHART_ISSUER = r"^https://token\.actions\.githubusercontent\.com$"
ocirepositories = load_items("ocirepositories.json")
exact_namespaced_inventory(
    ocirepositories, set(oci_chart_sources), "OCIRepository"
)
chart_artifact_revisions = {}
for (namespace, name), contract in sorted(oci_chart_sources.items()):
    identity = f"{namespace}/{name}"
    item = by_identity(ocirepositories, namespace, name, "OCIRepository")
    desired = desired_flux_object(
        "OCIRepository", "source.toolkit.fluxcd.io/v1", namespace, name
    )
    generation = exact_generation(item, "OCIRepository", identity)
    one_ready(item, "OCIRepository", identity)
    one_source_verified(item, identity, generation)
    spec = item.get("spec", {})
    verify = spec.get("verify", {})
    identities = verify.get("matchOIDCIdentity") if isinstance(verify, dict) else None
    if (
        spec.get("url") != contract["url"]
        or spec.get("ref") != {"digest": contract["digest"]}
        or spec.get("secretRef") is not None
        or spec.get("serviceAccountName") is not None
        or spec.get("insecure") not in (None, False)
        or not isinstance(verify, dict)
        or verify.get("provider") != "cosign"
        or verify.get("secretRef") is not None
        or not isinstance(identities, list)
        or len(identities) != 1
        or identities[0]
        != {"issuer": EXPECTED_CHART_ISSUER, "subject": contract["subject"]}
    ):
        raise SystemExit(
            f"OCIRepository {identity} is not the exact anonymous, cosign-verified chart source"
        )
    annotations = metadata(item).get("annotations", {})
    if (
        not isinstance(annotations, dict)
        or annotations.get("platform.snaraj.dev/chart-release") != contract["tag"]
    ):
        raise SystemExit(
            f"OCIRepository {identity} lacks its reviewed audit-only chart release annotation"
        )
    if spec != desired.get("spec"):
        raise SystemExit(f"OCIRepository {identity} spec differs from exact desired state")
    artifact = status(item).get("artifact", {})
    revision = artifact.get("revision") if isinstance(artifact, dict) else None
    digest = artifact.get("digest") if isinstance(artifact, dict) else None
    # With ref.digest, source-controller v1.9.3 reports the upstream OCI
    # manifest digest as the bare revision. With layerSelector.operation=copy,
    # artifact.digest is the separately receipt-bound chart-layer digest.
    if (
        revision != contract["digest"]
        or digest != contract["artifact_digest"]
    ):
        raise SystemExit(
            f"OCIRepository {identity} is not ready at its exact immutable chart digest"
        )
    chart_artifact_revisions[(namespace, name)] = (
        contract["tag"],
        contract["digest"],
    )


helmreleases = load_items("helmreleases.json")
helmcharts = load_items("helmcharts.json")
# The connector keeps a Git chart, so it is the only release that still
# materializes a HelmChart object; the two sites resolve their charts through
# chartRef and must NOT have one.
release_sources = {
    ("naranjo-online", "naranjo-online"): ("naranjo-online", "naranjo-online-chart"),
    ("lidersea-com", "lidersea-com"): ("lidersea-com", "lidersea-com-chart"),
    ("cloudflare-public", "cloudflare-public"): None,
}
git_chart_sources = {
    ("cloudflare-public", "cloudflare-public"): "cloudflare-public-source",
}
expected_chart_identities = {
    (namespace, f"{namespace}-{name}")
    for namespace, name in git_chart_sources
}
exact_namespaced_inventory(helmreleases, set(release_sources), "HelmRelease")
exact_namespaced_inventory(helmcharts, expected_chart_identities, "HelmChart")
for (namespace, name), chart_source in release_sources.items():
    identity = f"{namespace}/{name}"
    release = by_identity(helmreleases, namespace, name, "HelmRelease")
    desired_release = desired_flux_object(
        "HelmRelease", "helm.toolkit.fluxcd.io/v2", namespace, name
    )
    if chart_source is not None and release.get("spec", {}).get("values") != {
        "deploymentReady": True
    }:
        raise SystemExit(
            f"HelmRelease {identity} values are not exactly deploymentReady=true"
        )
    if release.get("spec") != desired_release.get("spec"):
        raise SystemExit(f"HelmRelease {identity} spec differs from exact desired state")
    generation = exact_generation(release, "HelmRelease", identity)
    one_ready(release, "HelmRelease", identity)
    release_status = status(release)
    attempted_generation = release_status.get("lastAttemptedGeneration")
    attempted_revision = release_status.get("lastAttemptedRevision")
    if type(attempted_generation) is not int or attempted_generation != generation:
        raise SystemExit(f"HelmRelease {identity} did not attempt its exact current generation")
    if not isinstance(attempted_revision, str) or not attempted_revision:
        raise SystemExit(f"HelmRelease {identity} has no attempted source revision")
    history = release_status.get("history")
    if not isinstance(history, list) or not history or not isinstance(history[0], dict):
        raise SystemExit(f"HelmRelease {identity} has no successful release history")
    latest = history[0]
    if (
        latest.get("name") != name
        or latest.get("namespace") != namespace
        or latest.get("status") != "deployed"
        or latest.get("chartVersion") != attempted_revision
    ):
        raise SystemExit(
            f"HelmRelease {identity} attempted revision is not its latest deployed revision"
        )
    if chart_source is not None:
        # Digest-selected site release: the chart it deployed must be the exact
        # reviewed tag+digest pair its verified OCIRepository carries, and the
        # HelmRelease must reference that source rather than a HelmChart.
        if release.get("spec", {}).get("chartRef") != {
            "kind": "OCIRepository",
            "name": chart_source[1],
        }:
            raise SystemExit(
                f"HelmRelease {identity} does not resolve its chart through its own verified OCI source"
            )
        if release_status.get("helmChart") is not None:
            raise SystemExit(
                f"HelmRelease {identity} must not materialize a HelmChart on the chartRef path"
            )
        chart_tag, chart_digest = chart_artifact_revisions[chart_source]
        digest_qualified_version = chart_tag + "+" + chart_digest[7:19]
        if (
            attempted_revision != digest_qualified_version
            or release_status.get("lastAttemptedRevisionDigest") != chart_digest
            or latest.get("ociDigest") not in (None, chart_digest)
        ):
            raise SystemExit(
                f"HelmRelease {identity} deployed a chart version its verified source does not currently resolve"
            )
        continue
    chart_reference = release_status.get("helmChart")
    if not isinstance(chart_reference, str) or chart_reference.count("/") != 1:
        raise SystemExit(f"HelmRelease {identity} has no canonical HelmChart reference")
    chart_namespace, chart_name = chart_reference.split("/", 1)
    expected_chart_name = f"{namespace}-{name}"
    if chart_namespace != namespace or chart_name != expected_chart_name:
        raise SystemExit(f"HelmRelease {identity} references an unexpected HelmChart")
    chart_identity = f"{chart_namespace}/{chart_name}"
    chart = by_identity(helmcharts, chart_namespace, chart_name, "HelmChart")
    exact_generation(chart, "HelmChart", chart_identity)
    one_ready(chart, "HelmChart", chart_identity)
    chart_spec = chart.get("spec", {})
    desired_chart_spec = desired_release.get("spec", {}).get("chart", {}).get("spec")
    chart_status = status(chart)
    chart_artifact = chart_status.get("artifact", {})
    if (
        chart_spec.get("reconcileStrategy") != "Revision"
        or chart_spec.get("sourceRef")
        != {"kind": "GitRepository", "name": git_chart_sources[(namespace, name)]}
        or chart_spec != desired_chart_spec
        or chart_status.get("observedSourceArtifactRevision")
        != expected_git_revision
        or not isinstance(chart_artifact, dict)
        or chart_artifact.get("revision") != attempted_revision
    ):
        raise SystemExit(
            f"HelmRelease {identity} is not applied from its exact current Git artifact"
        )


# Exact post-activation tenant NetworkPolicy inventory. The two website
# default-denies are reconciled directly from their website paths; the signed
# charts independently supply only the exact per-site application policies.
# The pre-activation capture did not contain those two default-denies, so their
# first reconciliation is an expected creation, not a drift exemption. The
# older cloudflare-public default-deny keeps its observed live name until its
# separately authorized platform transition.
expected_network_policies = {
    ("cloudflare-public", "default-deny-all"),
    ("cloudflare-public", "cloudflared-dns"),
    ("cloudflare-public", "cloudflared-edge"),
    ("cloudflare-public", "cloudflared-naranjo-online"),
    ("cloudflare-public", "cloudflared-lidersea-com"),
    ("naranjo-online", "default-deny"),
    ("naranjo-online", "ingress-to-naranjo-online"),
    ("lidersea-com", "default-deny"),
    ("lidersea-com", "ingress-to-lidersea-com"),
}


def exact_site_application_policy_spec(namespace):
    """The signed chart's sole allow for one website namespace."""

    policy_types = ["Ingress"]
    spec = {
        "podSelector": {
            "matchLabels": {
                "app.kubernetes.io/name": namespace,
                "app.kubernetes.io/instance": namespace,
            }
        },
        "policyTypes": policy_types,
        "ingress": [
            {
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "cloudflare-public"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {
                                "app.kubernetes.io/name": "cloudflare-public",
                                "app.kubernetes.io/instance": namespace + "-tunnel",
                            }
                        },
                    }
                ],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }
        ],
    }
    if namespace == "lidersea-com":
        spec["policyTypes"] = ["Ingress", "Egress"]
        spec["egress"] = []
    return spec

# EVERY tenant namespace is REQUIRED to carry a namespace-wide default-deny: a
# policy whose podSelector is `{}`, isolating every Pod for both directions. A
# default is only a default if it selects every Pod — a podSelector-SCOPED deny
# leaves any pod that does not match it completely unrestricted.
namespaces_requiring_namespace_wide_default_deny = {
    "cloudflare-public",
    "naranjo-online",
    "lidersea-com",
}
expected_default_deny_identities = {
    ("cloudflare-public", "default-deny-all"),
    ("naranjo-online", "default-deny"),
    ("lidersea-com", "default-deny"),
}
exact_default_deny_spec = {
    "podSelector": {},
    "policyTypes": ["Ingress", "Egress"],
}

tenant_namespaces = set(namespaces_requiring_namespace_wide_default_deny)
tenant_network_policies = [
    policy
    for policy in load_items("networkpolicies.json")
    if metadata(policy).get("namespace") in tenant_namespaces
]
live_network_policies = {
    (metadata(policy).get("namespace"), metadata(policy).get("name")): policy
    for policy in tenant_network_policies
}
if (
    len(tenant_network_policies) != len(expected_network_policies)
    or set(live_network_policies) != expected_network_policies
):
    raise SystemExit("live tenant NetworkPolicy inventory differs from exact desired state")
for namespace in sorted(namespaces_requiring_namespace_wide_default_deny):
    namespace_wide = [
        name
        for (found_namespace, name), policy in live_network_policies.items()
        if found_namespace == namespace
        and (found_namespace, name) in expected_default_deny_identities
        and policy.get("spec") == exact_default_deny_spec
    ]
    if not namespace_wide:
        raise SystemExit(
            f"tenant namespace has no exact namespace-wide default-deny: {namespace}"
        )
for namespace, name in sorted(expected_network_policies):
    desired_path = root / f"desired-networkpolicy-{namespace}-{name}.json"
    desired = json.loads(desired_path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != "networking.k8s.io/v1"
        or desired.get("kind") != "NetworkPolicy"
        or metadata(desired).get("namespace") != namespace
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(
            f"desired NetworkPolicy normalization is invalid: {namespace}/{name}"
        )
    if name == f"ingress-to-{namespace}" and desired.get("spec") != (
        exact_site_application_policy_spec(namespace)
    ):
        raise SystemExit(
            f"desired signed-chart application NetworkPolicy is not exact: {namespace}/{name}"
        )
    if (namespace, name) in expected_default_deny_identities and (
        desired.get("spec") != exact_default_deny_spec
    ):
        raise SystemExit(
            f"desired namespace-wide default-deny is not exact: {namespace}/{name}"
        )
    if live_network_policies[(namespace, name)].get("spec") != desired.get("spec"):
        raise SystemExit(
            f"live NetworkPolicy spec differs from exact desired state: {namespace}/{name}"
        )

print(
    "release-gate: PASS Flux sources, Helm revisions, and live security-policy specs are bound to exact local HEAD"
)
