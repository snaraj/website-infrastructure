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
NONZERO_TAG = "v1.2.3"
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
    tag=MODULE.ZERO_TAG,
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
        "  chartRef:\n"
        "    kind: OCIRepository\n"
        "    name: {name}-chart\n"
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
        "      tag: {tag}\n"
        "      digest: {digest}\n"
        "{extra_values}"
    ).format(
        name=name,
        domain=domain,
        readiness=MODULE.RELEASE_CONTRACTS[name]["readiness"],
        suspended=str(suspended).lower(),
        ready=str(ready).lower(),
        repository=repository,
        tag=tag,
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
        "    connectors:\n"
        + "".join(
            "      {}:\n        tokenRevision: {}\n".format(site, token_revision)
            for site in MODULE.PUBLIC_CONNECTOR_SITES
        )
    ).format(
        suspended=str(suspended).lower(),
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

    def test_current_repository_sites_are_suspended_in_a_reviewed_phase(self):
        """The committed tree stays a safe desired state as promotions land.

        Pre-promotion each live site is 'initial' (the all-zeros digest
        sentinel); a reviewed digest promotion moves a site to 'promoted'
        while BOTH suspension gates stay true (the runbook's staged flow —
        activation is a separate reviewed arc). The strict parser refuses
        every incoherent mixture outright, and this pin keeps rejecting any
        live tree whose sites leave those two phases or whose suspensions
        loosen outside that arc.
        """

        for name in SITE_DOMAINS:
            with self.subTest(name=name):
                self.assertIn(
                    MODULE.site_phase(name, REPO_ROOT),
                    ("initial", "promoted"),
                )
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
                    tag=NONZERO_TAG,
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
            # The expected-tag guard is the tag's exact counterpart: a caller
            # that names the release it verified must find that release here.
            self.assertEqual(
                MODULE.site_phase("naranjo-online", root, None, NONZERO_TAG),
                "promoted",
            )
            for wrong_tag in ("v9.9.9", "latest", "0.1.9", MODULE.ZERO_TAG):
                with self.subTest(expected_tag=wrong_tag):
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.site_phase("naranjo-online", root, None, wrong_tag)

            # Every half-advanced combination of the three-field identity is
            # an unsafe mixed state, including the two that move the release
            # NAME and the release BYTES apart.
            for ready, digest, tag in (
                (False, NONZERO_DIGEST, NONZERO_TAG),
                (True, MODULE.ZERO_DIGEST, MODULE.ZERO_TAG),
                (True, NONZERO_DIGEST, MODULE.ZERO_TAG),
                (True, MODULE.ZERO_DIGEST, NONZERO_TAG),
                (False, MODULE.ZERO_DIGEST, NONZERO_TAG),
                (False, NONZERO_DIGEST, MODULE.ZERO_TAG),
            ):
                with self.subTest(ready=ready, digest=digest, tag=tag):
                    write_lf(
                        release_path(root, "naranjo-online"),
                        website_release_text(
                            "naranjo-online",
                            ready=ready,
                            digest=digest,
                            tag=tag,
                        ),
                    )
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.site_phase("naranjo-online", root)

            # A tag outside the release grammar is refused by the closed line
            # allowlist before any value is interpreted.
            for bad_tag in ("latest", "0.1.9", "v0.1", "vmain", "v01.2.3"):
                with self.subTest(bad_tag=bad_tag):
                    write_lf(
                        release_path(root, "naranjo-online"),
                        website_release_text(
                            "naranjo-online",
                            ready=True,
                            digest=NONZERO_DIGEST,
                            tag=bad_tag,
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
                # Since site charts arrive as published OCI artifacts, the
                # cross-site bypass is pointing one site's release at the
                # OTHER site's signature-verified chart source — the two
                # identity tuples must never couple.
                "cross-site-chart-source": canonical.replace(
                    b"    name: naranjo-online-chart\n",
                    b"    name: lidersea-com-chart\n",
                    1,
                ),
                "chart-source-kind": canonical.replace(
                    b"    kind: OCIRepository\n",
                    b"    kind: HelmChart\n",
                    1,
                ),
                "chart-source-name": canonical.replace(
                    b"    name: naranjo-online-chart\n",
                    b"    name: cloudflare-public-source\n",
                    1,
                ),
                # An explicit chartRef namespace is the only field that could
                # reach another tenant's chart artifact at all.
                "chart-source-namespace": canonical.replace(
                    b"    name: naranjo-online-chart\n",
                    b"    name: naranjo-online-chart\n    namespace: lidersea-com\n",
                    1,
                ),
                # Reintroducing a Git-tracked inline chart beside the published
                # source would restore branch-head deployment.
                "inline-chart-reintroduced": canonical.replace(
                    b"  chartRef:\n    kind: OCIRepository\n"
                    b"    name: naranjo-online-chart\n",
                    b"  chart:\n"
                    b"    spec:\n"
                    b"      chart: ./chart\n"
                    b"      reconcileStrategy: Revision\n"
                    b"      sourceRef:\n"
                    b"        kind: GitRepository\n"
                    b"        name: naranjo-online-source\n"
                    b"      interval: 10m0s\n",
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
                    for site in MODULE.PUBLIC_CONNECTOR_SITES:
                        self.assertEqual(
                            state.values[("connectors", site, "tokenRevision")],
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
                "  tag: {}\n"
                "  digest: {}\n"
            ).format(MODULE.ZERO_TAG, MODULE.ZERO_DIGEST)
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
