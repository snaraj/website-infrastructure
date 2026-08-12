"""The modeled tag-driven release-sync state machine of ADR 0016.

One published release moves through five decisions, and every one of them can
refuse:

    published version
      -> SemVer resolution        (in range? newer than what we run?)
      -> verification decision    (signed, by this exact site's publisher?)
      -> digest-bound upgrade     (does an artifact carry a real image digest?)
      -> rollout health           (did the workload actually become ready?)
      -> rollback                 (if not, return to the last good release)

This module is the executable statement of that contract, written against the
mock registry and mock Kubernetes API beside it. It is NOT source-controller or
helm-controller: it verifies no cryptography, resolves no real registry, and
reconciles no cluster. What a battery built on it can honestly claim is that
the contract fails closed on each hostile input it enumerates, and that the
field values it consumes are the ones the committed manifests carry.

Every refusal is a distinct outcome value rather than a bare boolean so a test
cannot pass by refusing for the wrong reason — a denial that fires for an
unintended cause is as much a defect as a missing one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .kubernetes_api import (
    DEPLOYMENT,
    HELM_RELEASE,
    OCI_REPOSITORY,
    MockKubernetesApi,
    NotFound,
    ready_condition,
)
from .oci_registry import ZERO_DIGEST, RegistryClient

STABLE_TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
# The closed range grammar of validate_signature_policy.CHART_SEMVER_RANGES:
# one inclusive floor and one exclusive major ceiling, nothing else.
SEMVER_RANGE_RE = re.compile(
    r">=(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*) "
    r"<(0|[1-9][0-9]*)\.0\.0\Z"
)


class SourceOutcome(Enum):
    """What one chart-source reconcile decided."""

    SUSPENDED = "suspended"
    RANGE_UNGRAMMATICAL = "range-ungrammatical"
    NO_MATCHING_VERSION = "no-matching-version"
    TAG_REUSE_REFUSED = "tag-reuse-refused"
    DOWNGRADE_REFUSED = "downgrade-refused"
    VERIFICATION_FAILED = "verification-failed"
    ARTIFACT_UNCHANGED = "artifact-unchanged"
    ARTIFACT_UPDATED = "artifact-updated"


class ReleaseOutcome(Enum):
    """What one release reconcile decided."""

    SUSPENDED = "suspended"
    CHART_REF_INVALID = "chart-ref-invalid"
    CROSS_NAMESPACE_REFUSED = "cross-namespace-refused"
    SOURCE_NOT_READY = "source-not-ready"
    SENTINEL_REFUSED = "sentinel-refused"
    UNCHANGED = "unchanged"
    UPGRADED = "upgraded"


class RolloutOutcome(Enum):
    """What one rollout observation decided."""

    HEALTHY = "healthy"
    FAILED = "failed"
    ROLLED_BACK = "rolled-back"
    NO_PREVIOUS_RELEASE = "no-previous-release"


@dataclass(frozen=True)
class SourceResult:
    outcome: SourceOutcome
    version: str | None = None
    digest: str | None = None
    detail: str = ""

    @property
    def revision(self) -> str | None:
        if self.version is None or self.digest is None:
            return None
        return "{}@{}".format(self.version, self.digest)


@dataclass(frozen=True)
class ReleaseResult:
    outcome: ReleaseOutcome
    version: str | None = None
    image: str | None = None
    detail: str = ""


def parse_range(value):
    """Return ``(floor, ceiling)`` version tuples, or ``None`` if ungrammatical."""

    if not isinstance(value, str):
        return None
    match = SEMVER_RANGE_RE.fullmatch(value)
    if match is None:
        return None
    floor = tuple(int(part) for part in match.groups()[:3])
    ceiling = (int(match.group(4)), 0, 0)
    return (floor, ceiling) if floor < ceiling else None


def parse_tag(value):
    """Return a comparable version tuple for a stable ``vX.Y.Z`` tag."""

    if not isinstance(value, str):
        return None
    match = STABLE_TAG_RE.fullmatch(value)
    return tuple(int(part) for part in match.groups()) if match else None


def resolve_range(tags, semver_range):
    """Return the newest stable tag inside the range, or ``None``.

    Non-stable tags (``latest``, ``v1.2.3-rc1``, ``sha-<commit>``, signature
    tags) have no parse and are therefore never candidates — a mutable or
    prerelease name cannot become the thing the cluster runs.
    """

    bounds = parse_range(semver_range)
    if bounds is None:
        return None
    floor, ceiling = bounds
    candidates = []
    for tag in tags or ():
        parsed = parse_tag(tag)
        if parsed is not None and floor <= parsed < ceiling:
            candidates.append((parsed, tag))
    if not candidates:
        return None
    return max(candidates)[1]


def identity_matches(identity, matchers):
    """Return whether a signing identity satisfies any configured matcher.

    Both fields must match their pattern for the SAME matcher entry: an issuer
    accepted from one entry and a subject from another would let two partial
    identities combine into an authority neither one holds.
    """

    if identity is None or not matchers:
        return False
    for matcher in matchers:
        issuer_pattern = matcher.get("issuer")
        subject_pattern = matcher.get("subject")
        if not isinstance(issuer_pattern, str) or not isinstance(subject_pattern, str):
            continue
        try:
            issuer_ok = re.search(issuer_pattern, identity.issuer) is not None
            subject_ok = re.search(subject_pattern, identity.subject) is not None
        except re.error:
            continue
        if issuer_ok and subject_ok:
            return True
    return False


def _repository_path(url):
    """Return the registry path of an ``oci://host/path`` URL, or ``None``."""

    if not isinstance(url, str) or not url.startswith("oci://"):
        return None
    remainder = url[len("oci://"):]
    if "/" not in remainder:
        return None
    return remainder.split("/", 1)[1]


def reconcile_source(
    api: MockKubernetesApi,
    client: RegistryClient,
    namespace: str,
    name: str,
) -> SourceResult:
    """Model one chart-source reconcile end to end."""

    source = api.get(OCI_REPOSITORY, namespace, name)
    spec = source.spec
    if spec.get("suspend", False):
        return SourceResult(SourceOutcome.SUSPENDED)

    repository = _repository_path(spec.get("url"))
    semver_range = spec.get("ref", {}).get("semver")
    if repository is None or parse_range(semver_range) is None:
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "InvalidSelector")],
            },
        )
        return SourceResult(SourceOutcome.RANGE_UNGRAMMATICAL)

    tags = client.list_tags(repository)
    selected = resolve_range(tags, semver_range)
    current = source.status.get("artifact", {}) or {}
    current_version = current.get("version")
    if selected is None:
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "NoMatchingVersion")],
            },
        )
        return SourceResult(SourceOutcome.NO_MATCHING_VERSION)

    digest, _ = client.manifest(repository, selected)
    if digest is None:
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "ManifestUnavailable")],
            },
        )
        return SourceResult(SourceOutcome.NO_MATCHING_VERSION)

    # A version already resolved must keep resolving to the same content. A
    # changed digest under an unchanged tag is the reassignment ADR 0014 calls
    # an incident, and the safe response is to keep running what we have.
    if current_version == selected and current.get("digest") not in (None, digest):
        return SourceResult(
            SourceOutcome.TAG_REUSE_REFUSED,
            version=current_version,
            digest=current.get("digest"),
            detail="published version was reassigned to different content",
        )

    if current_version is not None:
        previous = parse_tag(current_version)
        candidate = parse_tag(selected)
        if previous is not None and candidate is not None and candidate < previous:
            return SourceResult(
                SourceOutcome.DOWNGRADE_REFUSED,
                version=current_version,
                digest=current.get("digest"),
                detail="resolved version is older than the running release",
            )

    identity = client.signature_identity(repository, digest)
    verify = spec.get("verify") or {}
    if verify.get("provider") != "cosign" or not identity_matches(
        identity, verify.get("matchOIDCIdentity") or []
    ):
        # Fail closed and keep any existing artifact: an unverifiable new
        # release must never become the running one, and must never remove the
        # release that is already verified and running.
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "VerificationFailed")],
            },
        )
        return SourceResult(
            SourceOutcome.VERIFICATION_FAILED,
            version=selected,
            digest=digest,
            detail="chart signature is absent or not this publisher's identity",
        )

    unchanged = current_version == selected and current.get("digest") == digest
    api.patch_status(
        OCI_REPOSITORY,
        namespace,
        name,
        {
            "observedGeneration": source.metadata.generation,
            "artifact": {
                "version": selected,
                "digest": digest,
                "revision": "{}@{}".format(selected, digest),
            },
            "conditions": [ready_condition(True, "Succeeded")],
        },
    )
    return SourceResult(
        SourceOutcome.ARTIFACT_UNCHANGED if unchanged else SourceOutcome.ARTIFACT_UPDATED,
        version=selected,
        digest=digest,
    )


def reconcile_release(
    api: MockKubernetesApi,
    client: RegistryClient,
    namespace: str,
    name: str,
) -> ReleaseResult:
    """Model one release reconcile against an already-reconciled source."""

    release = api.get(HELM_RELEASE, namespace, name)
    spec = release.spec
    if spec.get("suspend", False):
        # Suspension is total: no read of the source, no upgrade, no status
        # write. A suspended release leaves no trace of having considered one.
        return ReleaseResult(ReleaseOutcome.SUSPENDED)

    chart_ref = spec.get("chartRef") or {}
    if chart_ref.get("kind") != OCI_REPOSITORY or not chart_ref.get("name"):
        return ReleaseResult(ReleaseOutcome.CHART_REF_INVALID)
    if chart_ref.get("namespace", namespace) != namespace:
        return ReleaseResult(ReleaseOutcome.CROSS_NAMESPACE_REFUSED)

    try:
        source = api.get(OCI_REPOSITORY, namespace, chart_ref["name"])
    except NotFound:
        return ReleaseResult(ReleaseOutcome.SOURCE_NOT_READY, detail="no such source")
    artifact = source.status.get("artifact") or {}
    if not source.is_ready() or not artifact.get("version"):
        return ReleaseResult(ReleaseOutcome.SOURCE_NOT_READY)

    repository = _repository_path(source.spec.get("url"))
    chart_manifest = client.manifest(repository, artifact["version"])[1] or {}
    chart_image_digest = chart_manifest.get("imageDigest")
    values = spec.get("values") or {}
    image = values.get("image") or {}
    # The platform override wins while it exists (ADR 0016 keeps it until the
    # publishers embed the digest); the chart's own embedded digest is used
    # once the override is gone. Either way an all-zeros or absent digest is
    # the fail-closed sentinel and stops the upgrade.
    effective_digest = image.get("digest") or chart_image_digest
    repository_name = image.get("repository")
    if (
        not repository_name
        or effective_digest in (None, "", ZERO_DIGEST)
        or values.get("deploymentReady") is not True
    ):
        return ReleaseResult(
            ReleaseOutcome.SENTINEL_REFUSED,
            version=artifact["version"],
            detail="release sentinel still refuses deployment",
        )

    reference = "{}@{}".format(repository_name, effective_digest)
    history = list(release.status.get("history", []))
    if history and history[0].get("chartVersion") == artifact["version"] and history[
        0
    ].get("image") == reference:
        return ReleaseResult(
            ReleaseOutcome.UNCHANGED, version=artifact["version"], image=reference
        )

    entry = {
        "chartVersion": artifact["version"],
        "chartDigest": artifact["digest"],
        "image": reference,
        "status": "deployed",
    }
    api.patch_status(
        HELM_RELEASE,
        namespace,
        name,
        {
            "observedGeneration": release.metadata.generation,
            "lastAttemptedGeneration": release.metadata.generation,
            "lastAttemptedRevision": artifact["version"],
            "history": [entry] + history,
            "conditions": [ready_condition(True, "ReconciliationSucceeded")],
        },
    )
    api.apply(
        DEPLOYMENT,
        "apps/v1",
        namespace,
        name,
        {"image": reference, "chartVersion": artifact["version"]},
    )
    return ReleaseResult(
        ReleaseOutcome.UPGRADED, version=artifact["version"], image=reference
    )


def observe_rollout(
    api: MockKubernetesApi, namespace: str, name: str, healthy: bool
) -> RolloutOutcome:
    """Record the workload's observed health for the current release."""

    deployment = api.get(DEPLOYMENT, namespace, name)
    api.patch_status(
        DEPLOYMENT,
        namespace,
        name,
        {
            "observedGeneration": deployment.metadata.generation,
            "readyReplicas": 1 if healthy else 0,
            "conditions": [
                ready_condition(
                    healthy,
                    "MinimumReplicasAvailable" if healthy else "ProgressDeadlineExceeded",
                )
            ],
        },
    )
    return RolloutOutcome.HEALTHY if healthy else RolloutOutcome.FAILED


def remediate(api: MockKubernetesApi, namespace: str, name: str) -> RolloutOutcome:
    """Return the workload to the previous successful release, if there is one.

    Remediation is digest-bound like everything else: it redeploys a recorded
    history entry, never a re-resolved tag, so a rollback cannot be steered by
    whatever the registry currently serves.
    """

    release = api.get(HELM_RELEASE, namespace, name)
    history = list(release.status.get("history", []))
    if len(history) < 2:
        return RolloutOutcome.NO_PREVIOUS_RELEASE
    failed, previous = history[0], history[1]
    failed = dict(failed)
    failed["status"] = "failed"
    api.patch_status(
        HELM_RELEASE,
        namespace,
        name,
        {
            "history": [dict(previous)] + [failed] + history[2:],
            "lastAttemptedRevision": previous["chartVersion"],
            "conditions": [ready_condition(True, "RollbackSucceeded")],
        },
    )
    api.apply(
        DEPLOYMENT,
        "apps/v1",
        namespace,
        name,
        {"image": previous["image"], "chartVersion": previous["chartVersion"]},
    )
    return RolloutOutcome.ROLLED_BACK
