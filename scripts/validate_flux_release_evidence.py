"""Validate captured Flux revision and security-policy live evidence.

Extracted verbatim from the retired release-gate.sh --live lane so the unit
suite keeps executing this validator while the post-cutover successor gate is
built. argv: STATE_ROOT RELEASE_GIT_COMMIT. STATE_ROOT holds the kubectl JSON
captures and server-normalized desired-policy JSON the successor must produce.
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
    ("flux-system", "admission"),
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
    "admission",
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
# own keyless publisher identity. The artifact digest is what makes the running
# chart content-addressed even though the SemVer range selected it by tag.
CHART_TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
oci_chart_sources = {
    ("naranjo-online", "naranjo-online-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/naranjo-online",
        "subject": (
            r"^https://github\.com/snaraj/naranjo\.online/\.github/workflows/"
            r"release-publisher\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"
        ),
    },
    ("lidersea-com", "lidersea-com-chart"): {
        "url": "oci://ghcr.io/snaraj/charts/lidersea-com",
        "subject": (
            r"^https://github\.com/snaraj/lidersea\.com/\.github/workflows/"
            r"release-publisher\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"
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
    exact_generation(item, "OCIRepository", identity)
    one_ready(item, "OCIRepository", identity)
    spec = item.get("spec", {})
    verify = spec.get("verify", {})
    identities = verify.get("matchOIDCIdentity") if isinstance(verify, dict) else None
    if (
        spec.get("url") != contract["url"]
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
    if spec != desired.get("spec"):
        raise SystemExit(f"OCIRepository {identity} spec differs from exact desired state")
    artifact = status(item).get("artifact", {})
    revision = artifact.get("revision") if isinstance(artifact, dict) else None
    digest = artifact.get("digest") if isinstance(artifact, dict) else None
    # Flux records an OCI artifact revision as "<tag>@<digest>". Both halves are
    # load-bearing: the tag is the release identity the owner reads, the digest
    # is what actually ran, and a revision carrying only one of them means the
    # controller resolved something this contract cannot pin.
    if (
        not isinstance(revision, str)
        or revision.count("@") != 1
        or not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise SystemExit(f"OCIRepository {identity} has no tag-and-digest artifact revision")
    chart_tag, chart_digest = revision.split("@", 1)
    if (
        CHART_TAG_RE.fullmatch(chart_tag) is None
        or chart_digest != digest
        or chart_digest == "sha256:" + ("0" * 64)
    ):
        raise SystemExit(
            f"OCIRepository {identity} artifact is not one stable release tag bound to its digest"
        )
    chart_artifact_revisions[(namespace, name)] = (chart_tag, revision)


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
        # Tag-driven site release: the chart it deployed must be the exact
        # version its own verified OCIRepository currently resolves, and the
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
        chart_tag, chart_revision = chart_artifact_revisions[chart_source]
        if attempted_revision not in {chart_tag, chart_tag.lstrip("v"), chart_revision}:
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


required_policies = {
    "disallow-public-services",
    "disallow-tenant-media-payloads",
    "disallow-undiscovered-storage",
    "require-approved-images",
    "require-exact-tenant-networking",
    "require-release-readiness",
    "require-restricted-workloads",
    "require-signed-naranjo-online",
    "require-signed-lidersea-com",
}
live_policies = {
    metadata(policy).get("name"): policy for policy in load_items("policies.json")
}
if len(live_policies) != len(required_policies) or set(live_policies) != required_policies:
    raise SystemExit("live ClusterPolicy inventory differs from the exact desired state")
for name in sorted(required_policies):
    live = live_policies.get(name)
    if live is None:
        raise SystemExit(f"required live ClusterPolicy is missing: {name}")
    desired_path = root / f"desired-policy-{name}.json"
    desired = json.loads(desired_path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != "kyverno.io/v1"
        or desired.get("kind") != "ClusterPolicy"
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(f"desired ClusterPolicy normalization is invalid: {name}")
    if live.get("spec") != desired.get("spec"):
        raise SystemExit(f"live ClusterPolicy spec differs from exact desired state: {name}")


expected_network_policies = {
    ("cloudflare-public", "default-deny"),
    ("cloudflare-public", "cloudflared-dns"),
    ("cloudflare-public", "cloudflared-edge"),
    ("cloudflare-public", "cloudflared-naranjo-online"),
    ("cloudflare-public", "cloudflared-lidersea-com"),
    ("naranjo-online", "default-deny"),
    ("naranjo-online", "cloudflared-to-naranjo-online"),
    ("lidersea-com", "default-deny"),
    ("lidersea-com", "cloudflared-to-lidersea-com"),
}
tenant_namespaces = {identity[0] for identity in expected_network_policies}
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
    if live_network_policies[(namespace, name)].get("spec") != desired.get("spec"):
        raise SystemExit(
            f"live NetworkPolicy spec differs from exact desired state: {namespace}/{name}"
        )

print(
    "release-gate: PASS Flux sources, Helm revisions, and live security-policy specs are bound to exact local HEAD"
)
