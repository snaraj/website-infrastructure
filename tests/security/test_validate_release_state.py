"""Exercise the strict release-state parser against complete YAML fixtures."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("validate_release_state.py")

NONZERO_DIGEST = "sha256:" + ("a" * 64)
SITE_DOMAINS = {
    "naranjo-online": "naranjo.online",
    "lidersea-com": "lidersea.com",
}


def write_lf(path, text):
    """Write deterministic UTF-8/LF fixture bytes on every host platform."""

    if "\r" in text or not text.endswith("\n"):
        raise AssertionError("canonical fixture must be LF terminated")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def release_path(root, name):
    return root / str(MODULE.RELEASE_CONTRACTS[name]["release"])


def parent_path(root, name):
    return root / str(MODULE.RELEASE_CONTRACTS[name]["parent"])


def website_release_text(
    name,
    *,
    suspended=True,
    ready=False,
    digest=MODULE.ZERO_DIGEST,
    repository=None,
    extra_values="",
):
    """Return one complete canonical website HelmRelease fixture."""

    domain = SITE_DOMAINS[name]
    repository = repository or "ghcr.io/snaraj/{}".format(name)
    return (
        "apiVersion: helm.toolkit.fluxcd.io/v2\n"
        "kind: HelmRelease\n"
        "metadata:\n"
        "  name: {name}\n"
        "  namespace: {name}\n"
        "  annotations:\n"
        "    platform.snaraj.dev/readiness: {readiness}\n"
        "spec:\n"
        "  suspend: {suspended}\n"
        "  interval: 10m0s\n"
        "  releaseName: {name}\n"
        "  serviceAccountName: helm-reconciler\n"
        "  driftDetection:\n"
        "    mode: enabled\n"
        "  chart:\n"
        "    spec:\n"
        "      chart: ./chart\n"
        "      reconcileStrategy: Revision\n"
        "      sourceRef:\n"
        "        kind: GitRepository\n"
        "        name: {name}-source\n"
        "      interval: 10m0s\n"
        "  install:\n"
        "    remediation:\n"
        "      retries: 0\n"
        "  upgrade:\n"
        "    cleanupOnFail: true\n"
        "    remediation:\n"
        "      retries: 0\n"
        "      strategy: rollback\n"
        "  values:\n"
        "    deploymentReady: {ready}\n"
        "    image:\n"
        "      repository: {repository}\n"
        "      digest: {digest}\n"
        "{extra_values}"
    ).format(
        name=name,
        domain=domain,
        readiness=MODULE.RELEASE_CONTRACTS[name]["readiness"],
        suspended=str(suspended).lower(),
        ready=str(ready).lower(),
        repository=repository,
        digest=digest,
        extra_values=extra_values,
    )


def cloudflare_release_text(*, suspended=True, token_revision="not-configured"):
    """Return the complete canonical non-image HelmRelease fixture."""

    return (
        "apiVersion: helm.toolkit.fluxcd.io/v2\n"
        "kind: HelmRelease\n"
        "metadata:\n"
        "  name: cloudflare-public\n"
        "  namespace: cloudflare-public\n"
        "  annotations:\n"
        "    platform.snaraj.dev/readiness: "
        "suspended-until-sops-token-and-cloudflare-plan\n"
        "spec:\n"
        "  suspend: {suspended}\n"
        "  interval: 10m0s\n"
        "  releaseName: cloudflare-public\n"
        "  serviceAccountName: helm-reconciler\n"
        "  chart:\n"
        "    spec:\n"
        "      chart: ./kubernetes/platform/cloudflare-public/chart\n"
        "      reconcileStrategy: Revision\n"
        "      sourceRef:\n"
        "        kind: GitRepository\n"
        "        name: cloudflare-public-source\n"
        "      interval: 10m0s\n"
        "  install:\n"
        "    remediation:\n"
        "      retries: 0\n"
        "  upgrade:\n"
        "    cleanupOnFail: true\n"
        "    remediation:\n"
        "      retries: 0\n"
        "      strategy: rollback\n"
        "  values:\n"
        "    tunnel:\n"
        "      tokenRevision: {token_revision}\n"
    ).format(
        suspended=str(suspended).lower(),
        token_revision=token_revision,
    )


def parent_text(name, *, suspended=True):
    """Return one complete canonical parent Kustomization fixture."""

    parent_name = Path(str(MODULE.RELEASE_CONTRACTS[name]["parent"])).stem
    contract = MODULE.RELEASE_CONTRACTS[name]
    prefix = (
        "apiVersion: kustomize.toolkit.fluxcd.io/v1\n"
        "kind: Kustomization\n"
        "metadata:\n"
        "  name: {parent_name}\n"
        "  namespace: flux-system\n"
        "spec:\n"
    ).format(parent_name=parent_name)
    if name == "cloudflare-public":
        prefix += (
            "  decryption:\n"
            "    provider: sops\n"
            "    secretRef:\n"
            "      name: sops-age\n"
        )
    prefix += "  dependsOn:\n"
    prefix += "".join(
        "    - name: {}\n".format(dependency)
        for dependency in contract["parent_dependencies"]
    )
    return prefix + (
        "  interval: 10m0s\n"
        "  path: {path}\n"
        "  prune: true\n"
        "  retryInterval: 1m0s\n"
        "  serviceAccountName: {service_account}\n"
        "  sourceRef:\n"
        "    kind: GitRepository\n"
        "    name: flux-system\n"
        "  suspend: {suspended}\n"
        "  timeout: 5m0s\n"
        "  wait: false\n"
    ).format(
        path=contract["parent_path"],
        service_account=contract["parent_service_account"],
        suspended=str(suspended).lower(),
    )


def write_complete_tree(root):
    """Write all closed release identities and their parent manifests."""

    for name in SITE_DOMAINS:
        write_lf(release_path(root, name), website_release_text(name))
    write_lf(
        release_path(root, "cloudflare-public"),
        cloudflare_release_text(),
    )
    for name in MODULE.RELEASE_CONTRACTS:
        write_lf(parent_path(root, name), parent_text(name))


class StrictReleaseStateTests(unittest.TestCase):
    """Keep release-state interpretation exact, closed, and fail-safe."""

    def test_current_repository_sites_are_initial_and_suspended(self):
        for name in SITE_DOMAINS:
            with self.subTest(name=name):
                self.assertEqual(MODULE.site_phase(name, REPO_ROOT), "initial")
        self.assertTrue(MODULE.all_helm_releases_suspended(REPO_ROOT))
        for name in MODULE.RELEASE_CONTRACTS:
            with self.subTest(parent=name):
                self.assertTrue(MODULE.load_parent_suspension(name, REPO_ROOT))

    def test_complete_temporary_states_distinguish_initial_promoted_and_mixed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "initial")

            write_lf(
                release_path(root, "naranjo-online"),
                website_release_text(
                    "naranjo-online",
                    ready=True,
                    digest=NONZERO_DIGEST,
                ),
            )
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "promoted")
            self.assertEqual(
                MODULE.site_phase(
                    "naranjo-online",
                    root,
                    NONZERO_DIGEST,
                ),
                "promoted",
            )
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.site_phase(
                    "naranjo-online",
                    root,
                    "sha256:" + ("b" * 64),
                )

            for ready, digest in (
                (False, NONZERO_DIGEST),
                (True, MODULE.ZERO_DIGEST),
            ):
                with self.subTest(ready=ready, digest=digest):
                    write_lf(
                        release_path(root, "naranjo-online"),
                        website_release_text(
                            "naranjo-online",
                            ready=ready,
                            digest=digest,
                        ),
                    )
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.site_phase("naranjo-online", root)

    def test_duplicate_critical_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            variants = (
                canonical.replace(
                    b"kind: HelmRelease\n",
                    b"kind: HelmRelease\nkind: HelmRelease\n",
                    1,
                ),
                canonical.replace(
                    b"  name: naranjo-online\n",
                    b"  name: naranjo-online\n  name: naranjo-online\n",
                    1,
                ),
                canonical.replace(
                    b"  suspend: true\n",
                    b"  suspend: true\n  suspend: true\n",
                    1,
                ),
            )
            for index, candidate in enumerate(variants):
                with self.subTest(index=index):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

            parent = parent_path(root, "naranjo-online")
            parent.write_bytes(
                parent.read_bytes().replace(
                    b"  suspend: true\n",
                    b"  suspend: true\n  suspend: true\n",
                    1,
                )
            )
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.load_parent_suspension("naranjo-online", root)

    def test_block_scalar_suspend_decoy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            release.write_bytes(
                release.read_bytes().replace(
                    b"spec:\n  suspend: true\n",
                    b"decoy: |\n  suspend: true\nspec:\n  suspend: false\n",
                    1,
                )
            )
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.load_helm_release("naranjo-online", root)

    def test_duplicate_values_and_mapping_decoys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            duplicates = (
                canonical.replace(
                    b"  values:\n",
                    b"  values:\n  values:\n",
                    1,
                ),
                canonical.replace(
                    b"    deploymentReady: false\n",
                    b"    deploymentReady: false\n    deploymentReady: true\n",
                    1,
                ),
                canonical.replace(
                    b"      repository: ghcr.io/snaraj/naranjo-online\n",
                    b"      repository: ghcr.io/snaraj/naranjo-online\n"
                    b"      repository: ghcr.io/snaraj/naranjo-online\n",
                    1,
                ),
            )
            for index, candidate in enumerate(duplicates):
                with self.subTest(index=index):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

            decoy = (
                b"decoy:\n"
                b"  values:\n"
                b"    deploymentReady: true\n"
                b"    image:\n"
                b"      repository: ghcr.io/snaraj/naranjo-online\n"
                + ("      digest: {}\n".format(NONZERO_DIGEST)).encode("ascii")
            )
            release.write_bytes(canonical.replace(b"spec:\n", decoy + b"spec:\n", 1))
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.site_phase("naranjo-online", root)

    def test_non_lf_controls_unicode_separators_and_non_utf8_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            variants = (
                canonical.replace(b"\n", b"\r\n"),
                canonical.replace(
                    b"  name: naranjo-online\n",
                    b"\tname: naranjo-online\n",
                    1,
                ),
                canonical.replace(b"\n", b"\x0b", 1),
                canonical.replace(b"\n", b"\x0c", 1),
                canonical.replace(b"\n", b"\x1e", 1),
                canonical.replace(b"\n", "\u0085".encode("utf-8"), 1),
                canonical.replace(b"\n", "\u2028".encode("utf-8"), 1),
                canonical.replace(b"\n", "\u2029".encode("utf-8"), 1),
                canonical[:-1] + b"\xff\n",
            )
            for index, candidate in enumerate(variants):
                with self.subTest(index=index):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

    def test_document_markers_are_rejected_everywhere(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            variants = (
                b"---\n" + canonical,
                canonical + b"---\n",
                canonical + b"...\n",
                canonical + b"--- # second document\n",
                canonical.replace(b"  values:\n", b"  ---\n  values:\n", 1),
            )
            for index, candidate in enumerate(variants):
                with self.subTest(index=index):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

    def test_closed_helm_release_rejects_external_inputs_and_identity_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            variants = {
                "release-name": canonical.replace(
                    b"  releaseName: naranjo-online\n",
                    b"  releaseName: lidersea-com\n",
                    1,
                ),
                "service-account": canonical.replace(
                    b"  serviceAccountName: helm-reconciler\n",
                    b"  serviceAccountName: default\n",
                    1,
                ),
                # Cross-site chart paths are structurally identical now
                # (./chart); the equivalent modern bypass is pointing one
                # site's release at the OTHER site's Flux source.
                "cross-site-source": canonical.replace(
                    b"        name: naranjo-online-source\n",
                    b"        name: lidersea-com-source\n",
                    1,
                ),
                "source-kind": canonical.replace(
                    b"        kind: GitRepository\n",
                    b"        kind: OCIRepository\n",
                    1,
                ),
                "source-name": canonical.replace(
                    b"        name: naranjo-online-source\n",
                    b"        name: cloudflare-public-source\n",
                    1,
                ),
                "values-from": canonical.replace(
                    b"  values:\n",
                    b"  valuesFrom:\n"
                    b"    - kind: ConfigMap\n"
                    b"      name: mutable-overrides\n"
                    b"  values:\n",
                    1,
                ),
                "chart-values-files": canonical.replace(
                    b"      sourceRef:\n",
                    b"      valuesFiles:\n"
                    b"        - values-production.yaml\n"
                    b"      sourceRef:\n",
                    1,
                ),
                "post-renderer": canonical.replace(
                    b"  values:\n",
                    b"  postRenderers:\n"
                    b"    - kustomize:\n"
                    b"        images:\n"
                    b"          - name: ghcr.io/snaraj/naranjo-online\n"
                    b"            newName: ghcr.io/snaraj/lidersea-com\n"
                    b"  values:\n",
                    1,
                ),
                "unsupported-top-level": canonical.replace(
                    b"spec:\n",
                    b"unreviewed: value\nspec:\n",
                    1,
                ),
                "unsupported-inline-value": website_release_text(
                    "naranjo-online",
                    extra_values="    assetPath: ./static/site-assets\n",
                ).encode("utf-8"),
            }
            for label, candidate in variants.items():
                with self.subTest(label=label):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

    def test_closed_parent_rejects_transforms_and_identity_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            parent = parent_path(root, "naranjo-online")
            canonical = parent.read_bytes()
            variants = {
                "namespace": canonical.replace(
                    b"  namespace: flux-system\n",
                    b"  namespace: default\n",
                    1,
                ),
                "path": canonical.replace(
                    b"  path: ./kubernetes/websites/naranjo-online\n",
                    b"  path: ./kubernetes/websites/lidersea-com\n",
                    1,
                ),
                "service-account": canonical.replace(
                    b"  serviceAccountName: naranjo-online-reconciler\n",
                    b"  serviceAccountName: default\n",
                    1,
                ),
                "source": canonical.replace(
                    b"    name: flux-system\n",
                    b"    name: another-source\n",
                    1,
                ),
                "dependency": canonical.replace(
                    b"    - name: platform-services\n",
                    b"    - name: unreviewed-service\n",
                    1,
                ),
                "post-build": canonical.replace(
                    b"  suspend: true\n",
                    b"  postBuild:\n"
                    b"    substitute:\n"
                    b"      UNREVIEWED: value\n"
                    b"  suspend: true\n",
                    1,
                ),
                "image-transform": canonical.replace(
                    b"  suspend: true\n",
                    b"  images:\n"
                    b"    - name: ghcr.io/snaraj/naranjo-online\n"
                    b"      newName: ghcr.io/snaraj/lidersea-com\n"
                    b"  suspend: true\n",
                    1,
                ),
                "wait": canonical.replace(b"  wait: false\n", b"  wait: true\n", 1),
            }
            for label, candidate in variants.items():
                with self.subTest(label=label):
                    parent.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_parent_suspension("naranjo-online", root)
                    parent.write_bytes(canonical)

    def test_wrong_identity_namespace_and_repository_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            canonical = release.read_bytes()
            variants = (
                canonical.replace(
                    b"  name: naranjo-online\n",
                    b"  name: lidersea-com\n",
                    1,
                ),
                canonical.replace(
                    b"  namespace: naranjo-online\n",
                    b"  namespace: lidersea-com\n",
                    1,
                ),
                canonical.replace(
                    b"      repository: ghcr.io/snaraj/naranjo-online\n",
                    b"      repository: ghcr.io/snaraj/lidersea-com\n",
                    1,
                ),
            )
            for index, candidate in enumerate(variants):
                with self.subTest(index=index):
                    release.write_bytes(candidate)
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
                    release.write_bytes(canonical)

    def test_comments_are_allowed_without_expanding_the_manifest_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            release.write_bytes(
                release.read_bytes().replace(
                    b"spec:\n",
                    b"# reviewed comment\n  # indented reviewed comment\nspec:\n",
                    1,
                )
            )
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "initial")

    def test_token_revision_requires_a_canonical_non_magic_string(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "cloudflare-public")
            for token in (
                "null",
                "Null",
                "true",
                "false",
                "on",
                "123",
                ".nan",
                ".inf",
                "rev-",
                "REV-production",
            ):
                with self.subTest(token=token):
                    write_lf(
                        release,
                        cloudflare_release_text(token_revision=token),
                    )
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("cloudflare-public", root)

            for token in (
                "not-configured",
                "UNRESOLVED",
                "rev-rotation-20260809",
                "rev-a1b2c3d4",
            ):
                with self.subTest(token=token):
                    write_lf(
                        release,
                        cloudflare_release_text(token_revision=token),
                    )
                    state = MODULE.load_helm_release("cloudflare-public", root)
                    self.assertEqual(
                        state.values[("tunnel", "tokenRevision")],
                        token,
                    )

    def test_reader_rejects_non_regular_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            non_regular = root / "directory.yaml"
            non_regular.mkdir()
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.load_simple_mapping_file(non_regular)

            oversized = root / "oversized.yaml"
            oversized.write_bytes(
                b"a" * MODULE.MAX_RELEASE_YAML_BYTES + b"\n"
            )
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.load_simple_mapping_file(oversized)

    def test_reader_rejects_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target.yaml"
            link = root / "link.yaml"
            write_lf(target, "key: value\n")
            try:
                os.symlink(target, link)
            except (NotImplementedError, OSError) as error:
                self.skipTest("symlink creation is unavailable: {}".format(error))
            with self.assertRaises(MODULE.CanonicalYamlError):
                MODULE.load_simple_mapping_file(link)

    def test_all_helm_suspended_checks_each_closed_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            self.assertTrue(MODULE.all_helm_releases_suspended(root))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    MODULE.main(["--root", str(root), "all-helm-suspended"]),
                    0,
                )
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

            for name in MODULE.RELEASE_CONTRACTS:
                with self.subTest(name=name):
                    write_complete_tree(root)
                    if name == "cloudflare-public":
                        candidate = cloudflare_release_text(suspended=False)
                    else:
                        candidate = website_release_text(name, suspended=False)
                    write_lf(release_path(root, name), candidate)
                    self.assertFalse(MODULE.all_helm_releases_suspended(root))

            write_complete_tree(root)
            write_lf(
                release_path(root, "cloudflare-public"),
                cloudflare_release_text(suspended=False),
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    MODULE.main(["--root", str(root), "all-helm-suspended"]),
                    1,
                )
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

    def test_emit_values_is_exact_for_the_closed_inline_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            write_lf(
                release_path(root, "naranjo-online"),
                website_release_text("naranjo-online"),
            )
            expected = (
                "deploymentReady: false\n"
                "image:\n"
                "  repository: ghcr.io/snaraj/naranjo-online\n"
                "  digest: {}\n"
            ).format(MODULE.ZERO_DIGEST)
            state = MODULE.load_helm_release("naranjo-online", root)
            self.assertEqual(state.values_text, expected)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = MODULE.main(
                    [
                        "--root",
                        str(root),
                        "emit-values",
                        "--release",
                        "naranjo-online",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(stdout.getvalue(), expected)
            self.assertEqual(stderr.getvalue(), "")

    def test_relative_path_scalar_is_accepted_by_complete_mapping_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory).resolve() / "values.yaml"
            write_lf(
                values,
                "chart:\n"
                "  path: ./chart\n"
                "reconciliation:\n"
                "  path: ./kubernetes/websites/naranjo-online\n",
            )
            self.assertEqual(
                MODULE.load_simple_mapping_file(values),
                {
                    ("chart",): None,
                    ("chart", "path"): "./chart",
                    ("reconciliation",): None,
                    (
                        "reconciliation",
                        "path",
                    ): "./kubernetes/websites/naranjo-online",
                },
            )


if __name__ == "__main__":
    unittest.main()
