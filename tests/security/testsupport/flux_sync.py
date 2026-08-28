"""The modeled digest-selected release-sync state machine of ADR 0016.

One published release moves through five decisions, and every one of them can
refuse:

    published chart digest
      -> immutable selection      (exact nonzero sha256 manifest?)
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

import hashlib
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

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

SITE_IMAGE_REPOSITORIES = {
    "naranjo-online": "ghcr.io/snaraj/naranjo-online",
    "lidersea-com": "ghcr.io/snaraj/lidersea-com",
}


class SourceOutcome(Enum):
    """What one chart-source reconcile decided."""

    SUSPENDED = "suspended"
    DIGEST_INVALID = "digest-invalid"
    ARTIFACT_UNAVAILABLE = "artifact-unavailable"
    VERIFICATION_FAILED = "verification-failed"
    ARTIFACT_UNCHANGED = "artifact-unchanged"
    ARTIFACT_UPDATED = "artifact-updated"


class ReleaseOutcome(Enum):
    """What one release reconcile decided."""

    SUSPENDED = "suspended"
    CHART_REF_INVALID = "chart-ref-invalid"
    CROSS_NAMESPACE_REFUSED = "cross-namespace-refused"
    SOURCE_NOT_READY = "source-not-ready"
    VALUES_REFUSED = "values-refused"
    CHART_IDENTITY_REFUSED = "chart-identity-refused"
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
        return self.digest


@dataclass(frozen=True)
class ReleaseResult:
    outcome: ReleaseOutcome
    version: str | None = None
    image: str | None = None
    detail: str = ""


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
    ref = spec.get("ref")
    requested_digest = ref.get("digest") if isinstance(ref, dict) else None
    if (
        repository is None
        or not isinstance(ref, dict)
        or set(ref) != {"digest"}
        or not isinstance(requested_digest, str)
        or DIGEST_RE.fullmatch(requested_digest) is None
        or requested_digest == ZERO_DIGEST
    ):
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "InvalidDigest")],
            },
        )
        return SourceResult(SourceOutcome.DIGEST_INVALID)

    current = source.status.get("artifact", {}) or {}
    manifest_digest, manifest = client.manifest(repository, requested_digest)
    if manifest_digest != requested_digest or not isinstance(manifest, dict):
        api.patch_status(
            OCI_REPOSITORY,
            namespace,
            name,
            {
                "observedGeneration": source.metadata.generation,
                "conditions": [ready_condition(False, "ArtifactUnavailable")],
            },
        )
        return SourceResult(SourceOutcome.ARTIFACT_UNAVAILABLE)

    annotations = manifest.get("annotations") or {}
    version = annotations.get("org.opencontainers.image.version")
    if not isinstance(version, str) or not version:
        return SourceResult(SourceOutcome.ARTIFACT_UNAVAILABLE)

    identity = client.signature_identity(repository, requested_digest)
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
            version=version,
            digest=requested_digest,
            detail="chart signature is absent or not this publisher's identity",
        )

    unchanged = current.get("revision") == requested_digest
    stored_digest = "sha256:" + hashlib.sha256(
        ("stored:" + requested_digest).encode("utf-8")
    ).hexdigest()
    api.patch_status(
        OCI_REPOSITORY,
        namespace,
        name,
        {
            "observedGeneration": source.metadata.generation,
            "artifact": {
                "version": version,
                "digest": stored_digest,
                "revision": requested_digest,
            },
            "conditions": [ready_condition(True, "Succeeded")],
        },
    )
    return SourceResult(
        SourceOutcome.ARTIFACT_UNCHANGED if unchanged else SourceOutcome.ARTIFACT_UPDATED,
        version=version,
        digest=requested_digest,
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
    if chart_ref.get("namespace", namespace) != namespace:
        return ReleaseResult(ReleaseOutcome.CROSS_NAMESPACE_REFUSED)
    if chart_ref != {
        "kind": OCI_REPOSITORY,
        "name": "{}-chart".format(namespace),
    }:
        return ReleaseResult(ReleaseOutcome.CHART_REF_INVALID)
    values = spec.get("values")
    if values != {"deploymentReady": True}:
        return ReleaseResult(
            ReleaseOutcome.VALUES_REFUSED,
            detail="platform values must contain exactly deploymentReady=true",
        )

    try:
        source = api.get(OCI_REPOSITORY, namespace, chart_ref["name"])
    except NotFound:
        return ReleaseResult(ReleaseOutcome.SOURCE_NOT_READY, detail="no such source")
    artifact = source.status.get("artifact") or {}
    upstream_digest = artifact.get("revision")
    if (
        not source.is_ready()
        or not artifact.get("version")
        or not isinstance(upstream_digest, str)
        or upstream_digest != (source.spec.get("ref") or {}).get("digest")
    ):
        return ReleaseResult(ReleaseOutcome.SOURCE_NOT_READY)

    repository = _repository_path(source.spec.get("url"))
    manifest_digest, chart_manifest = client.manifest(repository, upstream_digest)
    chart_manifest = chart_manifest or {}
    image_repository = chart_manifest.get("imageRepository")
    image_digest = chart_manifest.get("imageDigest")
    if (
        manifest_digest != upstream_digest
        or image_repository != SITE_IMAGE_REPOSITORIES.get(namespace)
        or not isinstance(image_digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest)
        or image_digest == ZERO_DIGEST
    ):
        return ReleaseResult(
            ReleaseOutcome.CHART_IDENTITY_REFUSED,
            version=artifact.get("version"),
            detail="verified chart does not carry this site's canonical workload identity",
        )

    reference = "{}@{}".format(image_repository, image_digest)
    attempted_revision = "{}+{}".format(
        artifact["version"], upstream_digest.removeprefix("sha256:")[:12]
    )
    history = list(release.status.get("history", []))
    if history and history[0].get("chartVersion") == attempted_revision and history[
        0
    ].get("image") == reference:
        return ReleaseResult(
            ReleaseOutcome.UNCHANGED, version=artifact["version"], image=reference
        )

    entry = {
        "chartVersion": attempted_revision,
        "chartDigest": upstream_digest,
        "ociDigest": upstream_digest,
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
            "lastAttemptedRevision": attempted_revision,
            "lastAttemptedRevisionDigest": upstream_digest,
            "history": [entry] + history,
            "conditions": [ready_condition(True, "ReconciliationSucceeded")],
        },
    )
    api.apply(
        DEPLOYMENT,
        "apps/v1",
        namespace,
        name,
        {"image": reference, "chartVersion": attempted_revision},
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
            "lastAttemptedRevisionDigest": previous["chartDigest"],
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
