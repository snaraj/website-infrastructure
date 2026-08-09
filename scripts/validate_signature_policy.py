#!/usr/bin/env python3
"""Validate the two Kyverno signature policies against closed source contracts."""

import argparse
import os
import stat
import sys
from pathlib import Path


MAX_POLICY_BYTES = 64 * 1024
ALLOWED_ACTIONS = ("Audit", "Enforce")
SIGNATURE_CONTRACTS = {
    "naranjo-online": "publish-naranjo-online-image.yml",
    "lidersea-com": "publish-lidersea-com-image.yml",
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
        "https://github.com/snaraj/website-infrastructure/.github/workflows/"
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
    else:
        errors = flux_sync_errors(text)
    if errors:
        for error in errors:
            print("ERROR " + error, file=sys.stderr)
        return 1
    print("PASS closed Kyverno image-signature policy contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
