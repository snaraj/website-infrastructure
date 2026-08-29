#!/usr/bin/env python3
"""Validate the closed Flux OCI signature and release-identity contracts.

Each site source binds one repository, publisher workflow, protected-main ref,
OIDC issuer, immutable chart digest, and namespace. Whole-document comparisons
keep the two site tuples independent and reject alternate source credentials,
mutable selectors, or post-render transforms.
"""

import argparse
import os
import re
import stat
import sys
from pathlib import Path


MAX_POLICY_BYTES = 64 * 1024
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
# The published chart repository each site's release publisher pushes to. It is
# part of the site's identity tuple exactly like its image repository is; the
# platform never renames or shares these paths.
CHART_REPOSITORIES = {
    "naranjo-online": "oci://ghcr.io/snaraj/charts/naranjo-online",
    "lidersea-com": "oci://ghcr.io/snaraj/charts/lidersea-com",
}
# One reviewed human release label paired with the immutable OCI manifest
# digest Flux actually consumes. The annotation is audit metadata; only the
# digest is load-bearing. Publication must independently prove tag -> digest
# and the exact-site keyless signature before changing either value.
CHART_RELEASES = {
    "naranjo-online": {
        "tag": "0.1.62",
        "digest": "sha256:12bab1e17f838615f81d3901cc08fec8a9e8741bf1023c7b06c83ca6442cabc2",
    },
    "lidersea-com": {
        "tag": "0.1.40",
        "digest": "sha256:004eaecfcc3dbbe2693e4c400be3dbf755a7972d40b7a5b5755b64e10afb354b",
    },
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
CHART_RELEASE_TAG_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
CHART_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
EXPECTED_FLUX_SYSTEM_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - controllers
  - access.yaml
"""
EXPECTED_FLUX_SYNC = """apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: flux-system
  namespace: flux-system
  annotations:
    # STOP: this is a non-applicable review template. The owner-attended #189
    # bootstrap renders all canonical identity values from the signed v0.1.43
    # Release and creates these objects directly. Kustomize never consumes this
    # file, and the schema-invalid scalars below prevent accidental kubectl use.
    release-selector.platform.snaraj.dev/schema: BOOTSTRAP_RENDERS_CANONICAL_IDENTITY
    release-selector.platform.snaraj.dev/release-id: "0"
    release-selector.platform.snaraj.dev/release-tag: v0.1.43
    release-selector.platform.snaraj.dev/release-target-sha: "0000000000000000000000000000000000000000"
    release-selector.platform.snaraj.dev/tag-object-sha: "0000000000000000000000000000000000000000"
    release-selector.platform.snaraj.dev/main-ci: "0/0"
    release-selector.platform.snaraj.dev/platform-release: "0/0"
    release-selector.platform.snaraj.dev/selector-image-digest: BOOTSTRAP_RENDERS_SIGNED_DIGEST
    release-selector.platform.snaraj.dev/identity-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
spec:
  # Both sparse checkout and ignore rules independently exclude bootstrap,
  # controllers, RBAC, Cloudflare and every unrelated platform path.
  ignore: |
    /*
    !/kubernetes/
    /kubernetes/*
    !/kubernetes/websites/
    /kubernetes/websites/*
    !/kubernetes/websites/naranjo-online/
    !/kubernetes/websites/naranjo-online/**
    !/kubernetes/websites/lidersea-com/
    !/kubernetes/websites/lidersea-com/**
  interval: 1m0s
  ref:
    tag: v0.1.43
  sparseCheckout: BOOTSTRAP_RENDERS_EXACT_TWO_PATHS
  timeout: 60s
  url: https://github.com/snaraj/website-infrastructure.git
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: naranjo-online-reconciler
  namespace: flux-system
spec:
  deletionPolicy: Orphan
  force: false
  interval: 10m0s
  path: ./kubernetes/websites/naranjo-online
  prune: false
  retryInterval: 1m0s
  serviceAccountName: naranjo-online-reconciler
  sourceRef: BOOTSTRAP_RENDERS_VERIFIED_SOURCE
  suspend: false
  timeout: 5m0s
  wait: true
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: lidersea-com-reconciler
  namespace: flux-system
spec:
  deletionPolicy: Orphan
  force: false
  interval: 10m0s
  path: ./kubernetes/websites/lidersea-com
  prune: false
  retryInterval: 1m0s
  serviceAccountName: lidersea-com-reconciler
  sourceRef: BOOTSTRAP_RENDERS_VERIFIED_SOURCE
  suspend: false
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


def chart_source_certificate_subject(slug):
    """Return the exact cosign subject pattern for one site's chart publisher.

    Anchored at both ends and built only from that site's own repository and
    workflow file, so a chart signed by the sibling site, by another workflow
    in the same repository, or by a run of the right workflow at any ref other
    than protected `main` — a tag ref included — is not a match. This is the
    same exact tuple the site publisher records for the chart.
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


def chart_source_release(slug):
    """Return and validate one site's reviewed ``(tag, digest)`` pair."""

    release = CHART_RELEASES.get(slug)
    if not isinstance(release, dict):
        raise ValueError("site is outside the closed chart-source allowlist")
    tag = release.get("tag")
    digest = release.get("digest")
    if (
        not isinstance(tag, str)
        or CHART_RELEASE_TAG_RE.fullmatch(tag) is None
        or tag == "0.0.0"
    ):
        raise ValueError("chart release tag is outside the closed grammar")
    if (
        not isinstance(digest, str)
        or CHART_DIGEST_RE.fullmatch(digest) is None
        or set(digest.removeprefix("sha256:")) == {"0"}
    ):
        raise ValueError("chart release digest is not canonical and nonzero")
    return tag, digest


def expected_chart_source_body(slug):
    """Return the one normalized OCIRepository source form for a site."""

    if slug not in CHART_REPOSITORIES:
        raise ValueError("site is outside the closed chart-source allowlist")
    tag, digest = chart_source_release(slug)
    return """apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  annotations:
    platform.snaraj.dev/chart-release: "{tag}"
  name: {slug}-chart
  namespace: {slug}
spec:
  interval: 10m0s
  layerSelector:
    mediaType: {media_type}
    operation: copy
  ref:
    digest: {digest}
  timeout: 60s
  url: {url}
  verify:
    matchOIDCIdentity:
      - issuer: {issuer}
        subject: {subject}
    provider: cosign
""".format(
        slug=slug,
        tag=tag,
        digest=digest,
        media_type=CHART_LAYER_MEDIA_TYPE,
        url=CHART_REPOSITORIES[slug],
        issuer=CHART_OIDC_ISSUER_PATTERN,
        subject=chart_source_certificate_subject(slug),
    )


def chart_source_errors(text, slug):
    """Reject any chart source outside one site's exact closed contract.

    Whole-document equality (after the leading comment block) is the point: a
    missing ``verify`` block, a moved digest, a swapped registry path,
    the sibling site's subject, an added ``secretRef``/``serviceAccountName``/
    ``proxySecretRef``, a ``ref.tag``/``ref.semver`` override, or ``insecure``
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
    if args.command == "flux-system-kustomization":
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
        print("PASS closed cosign-verified chart source contract")
    else:
        print("PASS closed Flux source and reconciliation contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
