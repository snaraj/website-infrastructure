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

SITE_NAMES = ("naranjo-online", "lidersea-com")


def write_lf(path, text):
    """Write deterministic UTF-8/LF fixture bytes on every host platform."""

    if "\r" in text or not text.endswith("\n"):
        raise AssertionError("canonical fixture must be LF terminated")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def release_path(root, name):
    return root / str(MODULE.RELEASE_CONTRACTS[name]["release"])


def website_release_text(
    name,
    *,
    suspended=True,
    deployment_ready=True,
    extra_values="",
    max_history: "str | None" = "2",
    managed_by: "str | None" = "fluxcd",
):
    """Return one complete canonical website HelmRelease fixture.

    ``max_history`` and ``managed_by`` are parameterised, and ``None`` omits
    each line or mapping entirely, so both closed-shape guards can be shown to
    reject absence and substitution rather than merely accepting the canonical
    fixture.
    """

    return (
        "apiVersion: helm.toolkit.fluxcd.io/v2\n"
        "kind: HelmRelease\n"
        "metadata:\n"
        "  name: {name}\n"
        "  namespace: {name}\n"
        "{managed_by}"
        "  annotations:\n"
        "    platform.snaraj.dev/readiness: {readiness}\n"
        "spec:\n"
        "  suspend: {suspended}\n"
        "  interval: 10m0s\n"
        "{max_history}"
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
        "    deploymentReady: {deployment_ready}\n"
        "{extra_values}"
    ).format(
        name=name,
        readiness=MODULE.RELEASE_CONTRACTS[name]["readiness"],
        suspended=str(suspended).lower(),
        deployment_ready=str(deployment_ready).lower(),
        extra_values=extra_values,
        max_history=(
            "" if max_history is None else "  maxHistory: {}\n".format(max_history)
        ),
        managed_by=(
            ""
            if managed_by is None
            else "  labels:\n    app.kubernetes.io/managed-by: {}\n".format(
                managed_by
            )
        ),
    )


def cloudflare_release_text(
    *,
    suspended=True,
    token_revision="not-configured",
    max_history: "str | None" = "2",
):
    """Return the complete canonical non-image HelmRelease fixture.

    ``max_history`` is parameterised, and ``None`` omits the line entirely, for
    the same reason as the website fixture above.
    """

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
        "{max_history}"
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
        max_history=(
            "" if max_history is None else "  maxHistory: {}\n".format(max_history)
        ),
    )


def write_complete_tree(root):
    """Write all closed release identities.

    The two website parents are bootstrap-owned runtime objects. Their exact
    rendering and hostile-shape coverage lives in the bootstrap contract
    suite, not in this repository release-state parser.
    """

    for name in SITE_NAMES:
        write_lf(release_path(root, name), website_release_text(name))
    write_lf(
        release_path(root, "cloudflare-public"),
        cloudflare_release_text(),
    )


class StrictReleaseStateTests(unittest.TestCase):
    """Keep release-state interpretation exact, closed, and fail-safe."""

    def test_current_repository_uses_exact_values_only(self):
        """The chart source, not HelmRelease values, owns image identity."""

        for name in SITE_NAMES:
            with self.subTest(name=name):
                release = MODULE.load_helm_release(name, REPO_ROOT)
                self.assertFalse(release.suspended)
                self.assertFalse(MODULE.load_parent_suspension(name, REPO_ROOT))
                self.assertEqual(release.values, {("deploymentReady",): "true"})
                self.assertEqual(release.values_text, "deploymentReady: true\n")

        self.assertTrue(
            MODULE.load_helm_release("cloudflare-public", REPO_ROOT).suspended
        )
        self.assertTrue(
            MODULE.load_parent_suspension("cloudflare-public", REPO_ROOT)
        )

    def test_temporary_site_states_are_only_staged_or_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "staged")

            write_lf(
                release_path(root, "naranjo-online"),
                website_release_text("naranjo-online", suspended=False),
            )
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "active")


    def test_site_values_reject_every_extra_or_image_override(self):
        hostile_values = {
            "readiness false": {"deployment_ready": False},
            "image digest": {
                "extra_values": "    image:\n      digest: sha256:" + "a" * 64 + "\n"
            },
            "image tag": {"extra_values": "    image:\n      tag: v1.2.3\n"},
            "repository": {
                "extra_values": "    image:\n      repository: example.invalid/site\n"
            },
            "unreviewed scalar": {"extra_values": "    featureFlag: true\n"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_complete_tree(root)
            release = release_path(root, "naranjo-online")
            for label, kwargs in hostile_values.items():
                with self.subTest(label=label):
                    write_lf(release, website_release_text("naranjo-online", **kwargs))
                    with self.assertRaises(MODULE.CanonicalYamlError):
                        MODULE.load_helm_release("naranjo-online", root)
            write_lf(release, website_release_text("naranjo-online"))
            self.assertEqual(
                MODULE.load_helm_release("naranjo-online", root).values,
                {("deploymentReady",): "true"},
            )

    def test_site_management_label_is_exact_and_required(self):
        """Both direct site paths carry one stable source-owned marker."""

        for name in SITE_NAMES:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                release = release_path(root, name)
                for value in (None, "Helm", "flux", "FluxCD"):
                    with self.subTest(name=name, managed_by=value):
                        write_lf(
                            release,
                            website_release_text(name, managed_by=value),
                        )
                        with self.assertRaises(MODULE.CanonicalYamlError):
                            MODULE.load_helm_release(name, root)

                write_lf(release, website_release_text(name))
                self.assertTrue(MODULE.load_helm_release(name, root).suspended)

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
                    b"    deploymentReady: true\n",
                    b"    deploymentReady: true\n    deploymentReady: true\n",
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
                b"    deploymentReady: false\n"
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

    def test_wrong_identity_namespace_and_chart_source_are_rejected(self):
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
                    b"    name: naranjo-online-chart\n",
                    b"    name: lidersea-com-chart\n",
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
            self.assertEqual(MODULE.site_phase("naranjo-online", root), "staged")

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

    def test_release_retention_must_be_the_exact_bounded_literal(self):
        """Every retention form but the reviewed literal must fail closed.

        Helm stores each release revision as a Secret in the release namespace
        and prunes history to maxHistory-1 BEFORE writing the new revision, so
        retention that can reach the namespace Secret budget makes the prune
        free nothing and the create fail against quota — wedging that release
        permanently, with no reconcile able to recover it. Omitting the field
        is the same failure by another route, because helm-controller then
        applies its own five-revision default. Each identity is asserted
        separately: a Secret budget is a per-namespace fact, so one release
        passing proves nothing about another.
        """

        for name in ("naranjo-online", "lidersea-com", "cloudflare-public"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                release = release_path(root, name)

                # Absent, unbounded, and merely-different values alike: the
                # contract pins one reviewed literal, so drift in either
                # direction is a hard failure rather than a release that stops
                # working several deploys later. `1` is rejected too — it is
                # inside any budget but retains no rollback target for the
                # `strategy: rollback` remediation these releases declare.
                for mutation in (None, "0", "1", "3", "5"):
                    with self.subTest(name=name, max_history=mutation):
                        if name == "cloudflare-public":
                            text = cloudflare_release_text(max_history=mutation)
                        else:
                            text = website_release_text(name, max_history=mutation)
                        write_lf(release, text)
                        with self.assertRaises(MODULE.CanonicalYamlError):
                            MODULE.load_helm_release(name, root)

                # Vacuity control: the same fixture builder at the reviewed
                # value must load, so the rejections above are the retention
                # guard firing and not some unrelated shape error.
                if name == "cloudflare-public":
                    write_lf(release, cloudflare_release_text())
                else:
                    write_lf(release, website_release_text(name))
                self.assertTrue(MODULE.load_helm_release(name, root).suspended)

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
            expected = "deploymentReady: true\n"
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
