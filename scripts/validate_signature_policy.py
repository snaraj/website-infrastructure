#!/usr/bin/env python3
"""Validate the closed signature/identity contracts of reviewed desired state.

Two families live here because they answer the same question at two different
moments of one release:

* the Kyverno ``require-signed-<site>`` policies would decide, at admission
  time, whether the *image* a Pod names was signed by that site's publisher;
* the per-site OCIRepository chart sources decide, at reconcile time, whether
  the *chart* Flux is about to resolve was signed by the same publisher.

Only the second is a live runtime control. Kyverno is NOT installed on the
cluster and is not authorized to be (confirmed with the platform lane
2026-08-22; the runbook locks out both the report-only and the enforcing stage
pending issues #100/#101/#102). The ``require-signed-*`` policies are therefore
CI assertions and future desired state, not a second line of defence operating
today — do not reason about them as one. They are still pinned here byte for
byte, and still kept in step with the chart-source identity below, because CI
evaluates them and checks their parity against the Conftest corpus: an obsolete
identity in those files would be a false claim this repository makes about
itself, and it would be inherited the moment an install is authorized.

Both bind the identical certificate identity tuple — one site repository, one
workflow file, the protected ``main`` branch ref only, the GitHub Actions OIDC
issuer — so a chart and an image can never be accepted from different
authorities, and the two site tuples can never couple (AGENTS.md safety
invariant 14).
"""

import argparse
import os
import re
import stat
import sys
from pathlib import Path


MAX_POLICY_BYTES = 64 * 1024
ALLOWED_ACTIONS = ("Audit", "Enforce")
# Publisher identities live in the standalone site repositories. Each site's
# release-publisher workflow is selected by workflow_dispatch from the
# protected `main` branch and refuses any other event or ref in its own
# reviewed code, so the certificate identity ends in @refs/heads/main.
#
# The branch ref is the STRONGER anchor here, not a relaxation of a tag ref. A
# workflow run at a ref executes the workflow definition AT THAT REF, so the
# ref in the certificate identity names whichever control gates writes to it.
# In these repositories the branch ruleset on `refs/heads/main` restricts
# creation, deletion, force-push and updates with no bypass actors, while the
# tag ruleset makes tags immutable ONCE CREATED but does not restrict creation
# at all. A tag-ref identity is therefore satisfiable by anyone holding
# `contents: write` — push a branch carrying a rewritten publisher, tag it, run
# it — whereas a `refs/heads/main` identity can only be minted by a definition
# that already passed the protected-branch gate.
SIGNATURE_CONTRACTS = {
    "naranjo-online": "release-publisher.yml",
    "lidersea-com": "release-publisher.yml",
}
SIGNATURE_REPOSITORIES = {
    "naranjo-online": "naranjo.online",
    "lidersea-com": "lidersea.com",
}
SIGNATURE_DESCRIPTIONS = {
    "naranjo-online": "Verify the exact GitHub workflow signature and SLSA provenance bundle.",
    "lidersea-com": "Verify the exact lidersea.com workflow signature and SLSA provenance bundle.",
}
EXPECTED_STAGING_POLICY_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - require-restricted-workloads.yaml
  - disallow-public-services.yaml
  - require-approved-images.yaml
  - disallow-undiscovered-storage.yaml
  - disallow-tenant-media-payloads.yaml
  - require-zero-site-capacity.yaml
  - require-exact-tenant-networking.yaml
  - require-release-readiness.yaml
  - require-replicaset-admission-identity.yaml
  - require-signed-naranjo-online.yaml
  - require-signed-lidersea-com.yaml
"""
EXPECTED_PROMOTED_POLICY_KUSTOMIZATION = (
    EXPECTED_STAGING_POLICY_KUSTOMIZATION.replace(
        "  - require-zero-site-capacity.yaml\n", ""
    )
)
POLICY_KUSTOMIZATION_INVENTORIES = {
    "staging": EXPECTED_STAGING_POLICY_KUSTOMIZATION,
    "promoted": EXPECTED_PROMOTED_POLICY_KUSTOMIZATION,
}
# The published chart repository each site's release publisher pushes to. It is
# part of the site's identity tuple exactly like its image repository is; the
# platform never renames or shares these paths.
CHART_REPOSITORIES = {
    "naranjo-online": "oci://ghcr.io/snaraj/charts/naranjo-online",
    "lidersea-com": "oci://ghcr.io/snaraj/charts/lidersea-com",
}
# Reviewed SemVer window per site. The LOWER bound is a ratchet: it is the
# oldest release the cluster may resolve to, so a deleted or re-pointed newer
# tag cannot roll a site backwards without a reviewed PR raising it. The UPPER
# bound is the production-graduation gate of ADR 0014 expressed as a Flux
# policy: while release-policy.env records `no` for a site, its range must
# exclude major 1 and above, which validate_repository.py re-checks against the
# tracked gate so the two can never disagree silently.
CHART_SEMVER_RANGES = {
    "naranjo-online": ">=0.1.9 <1.0.0",
    "lidersea-com": ">=0.1.9 <1.0.0",
}
# Helm charts pushed with `helm push` carry exactly this layer media type.
# Pinning it means a non-chart layer smuggled into the same artifact is not
# what source-controller extracts.
CHART_LAYER_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
CHART_OIDC_ISSUER_PATTERN = r"^https://token\.actions\.githubusercontent\.com$"
# The protected `main` branch ref only. This is ONE fully anchored literal ref
# — `$` closes it — so it is exactly as narrow as the stable-tag pattern it
# replaces: any tag ref, any other branch, any `refs/heads/*` wildcard, and any
# unanchored variant all fail to match. What changes is WHICH single ref is
# trusted, and the one named here is the ref the protected-branch ruleset
# guards with no bypass actors.
CHART_BRANCH_REF_PATTERN = r"@refs/heads/main$"
CHART_SEMVER_RANGE_RE = re.compile(
    r">=(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*) "
    r"<(0|[1-9][0-9]*)\.0\.0\Z"
)
EXPECTED_ADMISSION_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - kyverno/controllers.yaml
  - ../../../policies/kyverno
"""
EXPECTED_RECONCILIATION_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - platform-prerequisites.yaml
  - admission.yaml
  - platform-services.yaml
  - naranjo-online.yaml
  - lidersea-com.yaml
"""
EXPECTED_FLUX_SYSTEM_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - controllers
  - access.yaml
  - gotk-sync.yaml
"""
EXPECTED_FLUX_SYNC = """apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: flux-system
  namespace: flux-system
spec:
  # The root reconciler needs only desired-state manifests. Sparse checkout
  # limits clone material while ignore rules independently bound the artifact.
  ignore: |
    /*
    !/kubernetes
    !/policies
  interval: 1m0s
  ref:
    branch: main
  sparseCheckout:
    - kubernetes
    - policies
  timeout: 60s
  url: https://github.com/snaraj/website-infrastructure.git
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: flux-system
  namespace: flux-system
spec:
  interval: 10m0s
  path: ./kubernetes/reconciliation
  prune: true
  retryInterval: 1m0s
  serviceAccountName: root-reconciler
  sourceRef:
    kind: GitRepository
    name: flux-system
  timeout: 5m0s
  wait: true
"""


def _canonical_text_errors(text, label):
    """Reject alternate YAML encodings before comparing normalized policy text."""

    errors = []
    try:
        encoded = text.encode("utf-8", "strict")
    except UnicodeError:
        return [label + " is not valid UTF-8"]
    if len(encoded) > MAX_POLICY_BYTES:
        errors.append(label + " exceeds the 64 KiB policy ceiling")
    if not text.endswith("\n"):
        errors.append(label + " must end with one LF")
    if "\r" in text:
        errors.append(label + " must use LF line endings")
    if "\t" in text:
        errors.append(label + " must not contain tabs")
    if text.startswith("\ufeff"):
        errors.append(label + " must not contain a UTF-8 BOM")
    if any(ord(character) < 32 and character != "\n" for character in text):
        errors.append(label + " contains a forbidden control character")
    return errors


def expected_policy_body(slug, workflow, action):
    """Return the one normalized source form for a site/action pair."""

    if SIGNATURE_CONTRACTS.get(slug) != workflow:
        raise ValueError("site and workflow are not one approved signature identity")
    if action not in ALLOWED_ACTIONS:
        raise ValueError("signature policy action is not Audit or Enforce")
    subject = (
        "https://github.com/snaraj/"
        + SIGNATURE_REPOSITORIES[slug]
        + "/.github/workflows/"
        + workflow
        + "@refs/heads/main"
    )
    description = SIGNATURE_DESCRIPTIONS[slug]
    return """apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-{slug}
  annotations:
    policies.kyverno.io/category: Software Supply Chain Security
    policies.kyverno.io/description: {description}
spec:
  admission: true
  background: false
  validationFailureAction: {action}
  webhookConfiguration:
    failurePolicy: Fail
    timeoutSeconds: 30
  rules:
    - name: verify-{slug}-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [{slug}]
      verifyImages:
        - imageReferences: ["ghcr.io/snaraj/{slug}@sha256:*"]
          mutateDigest: false
          required: true
          verifyDigest: true
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: {subject}
                    issuer: https://token.actions.githubusercontent.com
                    rekor:
                      url: https://rekor.sigstore.dev
    - name: verify-{slug}-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [{slug}]
      verifyImages:
        - imageReferences: ["ghcr.io/snaraj/{slug}@sha256:*"]
          type: SigstoreBundle
          mutateDigest: false
          required: true
          verifyDigest: true
          attestations:
            - type: https://slsa.dev/provenance/v1
              attestors:
                - count: 1
                  entries:
                    - keyless:
                        subject: {subject}
                        issuer: https://token.actions.githubusercontent.com
                        rekor:
                          url: https://rekor.sigstore.dev
              conditions:
                - all:
                    - key: "{{{{ buildDefinition.buildType }}}}"
                      operator: Equals
                      value: https://actions.github.io/buildtypes/workflow/v1
""".format(
        slug=slug,
        action=action,
        subject=subject,
        description=description,
    )


def chart_source_certificate_subject(slug):
    """Return the exact cosign subject pattern for one site's chart publisher.

    Anchored at both ends and built only from that site's own repository and
    workflow file, so a chart signed by the sibling site, by another workflow
    in the same repository, or by a run of the right workflow at any ref other
    than protected `main` — a tag ref included — is not a match. This is the
    same tuple ``expected_policy_body`` binds for images.
    """

    if slug not in SIGNATURE_CONTRACTS:
        raise ValueError("site is outside the closed signature allowlist")
    domain = SIGNATURE_REPOSITORIES[slug].replace(".", r"\.")
    workflow = SIGNATURE_CONTRACTS[slug].replace(".", r"\.")
    return (
        r"^https://github\.com/snaraj/"
        + domain
        + r"/\.github/workflows/"
        + workflow
        + CHART_BRANCH_REF_PATTERN
    )


def chart_source_semver_bounds(slug):
    """Return (lower, upper) SemVer tuples for one site's reviewed range.

    The range grammar is deliberately tiny: one inclusive lower bound and one
    exclusive major-boundary upper bound. Anything else — an unbounded range, a
    caret/tilde shorthand, a prerelease qualifier, a second clause — has no
    parse here and is therefore rejected before the graduation-gate comparison
    in ``validate_repository.py`` can be reasoned about at all.
    """

    if slug not in CHART_SEMVER_RANGES:
        raise ValueError("site is outside the closed chart-source allowlist")
    match = CHART_SEMVER_RANGE_RE.fullmatch(CHART_SEMVER_RANGES[slug])
    if match is None:
        raise ValueError("chart SemVer range is outside the closed grammar")
    lower = tuple(int(part) for part in match.groups()[:3])
    upper = (int(match.group(4)), 0, 0)
    if lower >= upper:
        raise ValueError("chart SemVer range is empty")
    return lower, upper


def expected_chart_source_body(slug):
    """Return the one normalized OCIRepository source form for a site."""

    if slug not in CHART_REPOSITORIES:
        raise ValueError("site is outside the closed chart-source allowlist")
    # Raise before rendering if the committed range is ungrammatical, so a
    # malformed constant can never be baked into an "expected" document.
    chart_source_semver_bounds(slug)
    return """apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: {slug}-chart
  namespace: {slug}
spec:
  interval: 10m0s
  layerSelector:
    mediaType: {media_type}
    operation: copy
  ref:
    semver: "{semver}"
  timeout: 60s
  url: {url}
  verify:
    matchOIDCIdentity:
      - issuer: {issuer}
        subject: {subject}
    provider: cosign
""".format(
        slug=slug,
        media_type=CHART_LAYER_MEDIA_TYPE,
        semver=CHART_SEMVER_RANGES[slug],
        url=CHART_REPOSITORIES[slug],
        issuer=CHART_OIDC_ISSUER_PATTERN,
        subject=chart_source_certificate_subject(slug),
    )


def chart_source_errors(text, slug):
    """Reject any chart source outside one site's exact closed contract.

    Whole-document equality (after the leading comment block) is the point: a
    missing ``verify`` block, a widened SemVer range, a swapped registry path,
    the sibling site's subject, an added ``secretRef``/``serviceAccountName``/
    ``proxySecretRef``, a ``ref.tag``/``ref.digest`` override, or ``insecure``
    all change the body and are all denied by the same comparison, with no
    per-field allowlist to keep in sync.
    """

    errors = _canonical_text_errors(text, "chart source")
    if slug not in CHART_REPOSITORIES:
        errors.append("chart source site is outside the closed allowlist")
        return errors
    if errors:
        return errors
    if _policy_body(text) != expected_chart_source_body(slug):
        errors.append(
            "chart source does not match the pinned {} OCIRepository contract".format(
                slug
            )
        )
    return errors


def _policy_body(text):
    """Ignore only a contiguous leading comment block; policy YAML stays exact."""

    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines) and lines[index].startswith("#"):
        index += 1
    return "".join(lines[index:])


def signature_policy_action(text, slug, workflow):
    """Return Audit/Enforce only when the entire semantic source is canonical."""

    if (
        SIGNATURE_CONTRACTS.get(slug) != workflow
        or _canonical_text_errors(text, "signature policy")
    ):
        return None
    body = _policy_body(text)
    for action in ALLOWED_ACTIONS:
        if body == expected_policy_body(slug, workflow, action):
            return action
    return None


def signature_policy_errors(text, slug, workflow, allowed_actions=ALLOWED_ACTIONS):
    """Reject duplicate, reordered, extra, commented-out, or weakened semantics."""

    errors = _canonical_text_errors(text, "signature policy")
    if SIGNATURE_CONTRACTS.get(slug) != workflow:
        errors.append("site/workflow signature identity is outside the closed allowlist")
        return errors
    actions = tuple(allowed_actions)
    if not actions or any(action not in ALLOWED_ACTIONS for action in actions):
        errors.append("signature policy action allowlist is invalid")
        return errors
    if errors:
        return errors
    body = _policy_body(text)
    if not any(body == expected_policy_body(slug, workflow, action) for action in actions):
        errors.append(
            "signature policy body does not match the pinned {} contract".format(
                "/".join(actions)
            )
        )
    return errors


def signature_policy_kustomization_errors(text, allowed_inventories):
    """Require one explicitly allowed exact resource-only policy inventory."""

    errors = _canonical_text_errors(text, "Kyverno policy Kustomization")
    inventories = tuple(allowed_inventories)
    if not inventories or any(
        inventory not in POLICY_KUSTOMIZATION_INVENTORIES
        for inventory in inventories
    ):
        errors.append("Kyverno policy Kustomization inventory allowlist is invalid")
        return errors
    if errors:
        return errors
    if text not in {
        POLICY_KUSTOMIZATION_INVENTORIES[inventory]
        for inventory in inventories
    }:
        errors.append(
            "Kyverno policy Kustomization must match the exact {} resource inventory".format(
                "/".join(inventories)
            )
        )
    return errors


def admission_kustomization_errors(text):
    """Forbid parent transforms that could rename or weaken child policies."""

    errors = _canonical_text_errors(text, "admission Kustomization")
    if errors:
        return errors
    if text != EXPECTED_ADMISSION_KUSTOMIZATION:
        errors.append(
            "admission Kustomization must contain only the exact controller and policy resources"
        )
    return errors


def reconciliation_kustomization_errors(text):
    """Forbid root transforms that could rename the Flux admission boundary."""

    errors = _canonical_text_errors(text, "reconciliation Kustomization")
    if errors:
        return errors
    if text != EXPECTED_RECONCILIATION_KUSTOMIZATION:
        errors.append(
            "reconciliation Kustomization must match the exact Flux resource inventory"
        )
    return errors


def flux_system_kustomization_errors(text):
    """Forbid bootstrap transforms around the root Flux synchronization object."""

    errors = _canonical_text_errors(text, "Flux system Kustomization")
    if errors:
        return errors
    if text != EXPECTED_FLUX_SYSTEM_KUSTOMIZATION:
        errors.append(
            "Flux system Kustomization must match the exact bootstrap inventory"
        )
    return errors


def flux_sync_errors(text):
    """Pin the public source and root reconciler without patch/postBuild escapes."""

    errors = _canonical_text_errors(text, "Flux root synchronization")
    if errors:
        return errors
    if text != EXPECTED_FLUX_SYNC:
        errors.append("Flux root synchronization must match the exact source contract")
    return errors


def _read_bounded(path):
    """Read one regular, non-symlink policy file without trusting its contents."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("policy input must be one regular non-symlink file")
    if metadata.st_size > MAX_POLICY_BYTES:
        raise ValueError("policy input exceeds the 64 KiB ceiling")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            metadata.st_dev,
            metadata.st_ino,
        ) != (opened.st_dev, opened.st_ino):
            raise ValueError("policy input changed before it could be read")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_POLICY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_POLICY_BYTES:
                raise ValueError("policy input exceeds the 64 KiB ceiling")
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        return data.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ValueError("policy input is not valid UTF-8") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    policy = subparsers.add_parser("policy")
    policy.add_argument("--file", type=Path, required=True)
    policy.add_argument("--site", choices=sorted(SIGNATURE_CONTRACTS), required=True)
    policy.add_argument("--workflow", required=True)
    policy.add_argument(
        "--action", action="append", choices=ALLOWED_ACTIONS, dest="actions"
    )
    kustomization = subparsers.add_parser("kustomization")
    kustomization.add_argument("--file", type=Path, required=True)
    kustomization.add_argument(
        "--inventory",
        action="append",
        choices=sorted(POLICY_KUSTOMIZATION_INVENTORIES),
        required=True,
        dest="inventories",
    )
    admission_kustomization = subparsers.add_parser("admission-kustomization")
    admission_kustomization.add_argument("--file", type=Path, required=True)
    reconciliation_kustomization = subparsers.add_parser(
        "reconciliation-kustomization"
    )
    reconciliation_kustomization.add_argument("--file", type=Path, required=True)
    flux_system_kustomization = subparsers.add_parser("flux-system-kustomization")
    flux_system_kustomization.add_argument("--file", type=Path, required=True)
    flux_sync = subparsers.add_parser("flux-sync")
    flux_sync.add_argument("--file", type=Path, required=True)
    chart_source = subparsers.add_parser("chart-source")
    chart_source.add_argument("--file", type=Path, required=True)
    chart_source.add_argument(
        "--site", choices=sorted(CHART_REPOSITORIES), required=True
    )
    args = parser.parse_args(argv)
    try:
        text = _read_bounded(args.file)
    except (OSError, ValueError) as error:
        print("ERROR {}".format(error), file=sys.stderr)
        return 1
    if args.command == "policy":
        errors = signature_policy_errors(
            text,
            args.site,
            args.workflow,
            tuple(args.actions or ALLOWED_ACTIONS),
        )
    elif args.command == "kustomization":
        errors = signature_policy_kustomization_errors(text, tuple(args.inventories))
    elif args.command == "admission-kustomization":
        errors = admission_kustomization_errors(text)
    elif args.command == "reconciliation-kustomization":
        errors = reconciliation_kustomization_errors(text)
    elif args.command == "flux-system-kustomization":
        errors = flux_system_kustomization_errors(text)
    elif args.command == "chart-source":
        errors = chart_source_errors(text, args.site)
    else:
        errors = flux_sync_errors(text)
    if errors:
        for error in errors:
            print("ERROR " + error, file=sys.stderr)
        return 1
    if args.command == "chart-source":
        # Do not claim the image-admission contract for the reconcile-time
        # chart contract: the two bind the same identity tuple at different
        # moments and an operator reading a transcript must be able to tell
        # which one actually ran.
        print("PASS closed cosign-verified chart source contract")
    else:
        print("PASS closed Kyverno image-signature policy contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
