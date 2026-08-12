"""Require transition rendering to consume authoritative Flux values.

Three batteries, deliberately layered:

* ``ReleaseRenderOverrideTests`` pins the renderer's structure, including
  the ratchet that would have caught this module's motivating defect —
  after the site charts moved to their own repositories the transition
  branch still demanded ``helm-<site>.yaml`` artifacts nothing produced,
  so every pull request would have gone red the moment one site left the
  ``initial`` release state.
* ``SiteReleasePolicyTests`` executes the real release policy against
  synthetic site HelmReleases, proving each phase's denial set exactly.
* ``PromotedRenderStateTests`` and ``RenderDeterminismModeTests`` execute
  the real ``render-manifests.sh`` and ``verify-render-determinism.sh``
  against disposable repository copies, in both the green and the red
  direction, because a string pin cannot prove a gate still fires.
"""

import json
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
RENDER = REPO_ROOT / "scripts" / "render-manifests.sh"
DETERMINISM = REPO_ROOT / "scripts" / "ci" / "verify-render-determinism.sh"
RELEASE_POLICY = REPO_ROOT / "policies" / "release-conftest"

BASH = shutil.which("bash")
CONFTEST = shutil.which("conftest")
PYTHON3 = shutil.which("python3")
RENDER_TOOLCHAIN = all(
    shutil.which(tool)
    for tool in ("helm", "kustomize", "kubeconform", "conftest", "kyverno")
)

ZERO_DIGEST = "sha256:" + "0" * 64
# A canonical but deliberately synthetic digest: this battery proves the
# gate's shape, never a particular site's released artifact, so no real
# promotion value is duplicated here (safety invariant 14).
REVIEWED_DIGEST = "sha256:" + "ab" * 32

# Loop variables the renderer expands inside an artifact path. Anything else
# interpolated into an artifact reference fails the ratchet below rather than
# being silently skipped.
SITES = ("naranjo-online", "lidersea-com")
# The two release-state values the fixtures rewrite. Matching the line shape
# rather than one particular value is what keeps this battery independent of
# whether a promotion has already merged into the base branch.
READY_LINE = re.compile(r"^    deploymentReady: (?:true|false)$", re.MULTILINE)
DIGEST_LINE = re.compile(r"^      digest: sha256:[0-9a-f]{64}$", re.MULTILINE)
ARTIFACT_REFERENCE = re.compile(r"\$\{ARTIFACT_ROOT\}/([A-Za-z0-9._${}-]+\.yaml)")
INTERPOLATION = re.compile(r"\$\{[^}]*\}")
# Two Kustomize roots are built outside the declared target list; each is
# asserted to keep its own `kustomize build` and both follow the same
# path-to-artifact naming rule the declared targets use.
EXTRA_KUSTOMIZE_ROOTS = ("kubernetes/flux-system", "policies/kyverno")


def bash_array(script, name):
    """Return the raw entries of one ``declare -a NAME=( ... )`` block."""

    opener = "declare -a {}=(\n".format(name)
    start = script.index(opener) + len(opener)
    end = script.index("\n)\n", start)
    return [
        line.strip().strip('"')
        for line in script[start:end].splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def site_release_document(
    site="naranjo-online",
    *,
    suspend=True,
    ready=False,
    digest=ZERO_DIGEST,
    omit_digest=False,
    omit_ready=False,
):
    """Render one site HelmRelease exactly as Kustomize emits it."""

    image = "" if omit_digest else "      digest: {}\n".format(digest)
    readiness = (
        ""
        if omit_ready
        else "    deploymentReady: {}\n".format("true" if ready else "false")
    )
    return textwrap.dedent(
        """\
        apiVersion: helm.toolkit.fluxcd.io/v2
        kind: HelmRelease
        metadata:
          name: {site}
          namespace: {site}
        spec:
          releaseName: {site}
          serviceAccountName: helm-reconciler
          suspend: {suspend}
          values:
        {readiness}    image:
        {image}      repository: ghcr.io/snaraj/{site}
        """
    ).format(
        site=site,
        suspend="true" if suspend else "false",
        readiness=readiness,
        image=image,
    )


def release_policy_denials(path):
    """Return the exact denial messages the release policy raises."""

    completed = subprocess.run(
        [
            required_tool(CONFTEST, "conftest is required"),
            "test",
            "--policy",
            str(RELEASE_POLICY),
            "--output",
            "json",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            "conftest produced no JSON report ({}): {}{}".format(
                error, completed.stdout, completed.stderr
            )
        )
    denials = {
        failure["msg"] for result in report for failure in result.get("failures") or ()
    }
    # A denial set and a zero exit would mean the machine-readable report and
    # the gate's own verdict disagree about whether the artifact was accepted;
    # a raise, not an assert, so the guard survives ``python -O``.
    if bool(denials) != (completed.returncode != 0):
        raise AssertionError(
            "conftest verdict {} contradicts its report {}".format(
                completed.returncode, sorted(denials)
            )
        )
    return denials


class ReleaseRenderOverrideTests(unittest.TestCase):
    """Keep scaffold defaults inert while proving each effective safe phase."""

    @classmethod
    def setUpClass(cls):
        cls.script = RENDER.read_text(encoding="utf-8")

    def test_closed_chart_rows_cover_only_the_platform_chart(self):
        """Site charts render in their own repositories; only the platform
        cloudflare-public chart remains a local render target."""

        self.assertIn(
            "cloudflare-public|cloudflare-public|kubernetes/platform/cloudflare-public/chart",
            self.script,
        )
        for removed in (
            "websites/naranjo.online/chart",
            "websites/lidersea.com/chart",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, self.script)

    def test_transition_and_release_use_exact_helmrelease_values(self):
        mode_gate = self.script.index("if [[ \"$MODE\" != '--scaffold' ]]")
        emit = self.script.index("validate_release_state.py\" emit-values")
        args = self.script.index('helm_values_args=(--values "$release_values")')
        lint = self.script.index('helm lint "$chart_path" "${helm_values_args[@]}"')
        template = self.script.index(
            'helm template "$release_name" "$chart_path" --namespace "$namespace"'
        )

        self.assertLess(mode_gate, emit)
        self.assertLess(emit, args)
        self.assertLess(args, lint)
        self.assertLess(lint, template)
        self.assertIn('--release "$release_name" >"$release_values"', self.script)
        self.assertIn('"${helm_values_args[@]}" >"$output"', self.script)

    def test_renderer_requires_an_exact_authoritative_transition_plan(self):
        self.assertIn("--scaffold|--transition|--release", self.script)
        self.assertIn(
            'validate_release_transition.py\" plan \\\n    --expect-mode "$mode_name"',
            self.script,
        )
        self.assertIn('((${#release_plan_lines[@]} == 6))', self.script)
        for record in (
            "mode=${mode_name}",
            "^naranjo-online=(initial|staged|active)$",
            "^lidersea-com=(initial|staged|active)$",
            "^cloudflare-public=(initial|staged|active)$",
            "^any-website-active=(true|false)$",
            "^any-workload-active=(true|false)$",
        ):
            with self.subTest(record=record):
                self.assertIn(record, self.script)
        self.assertNotIn("eval ", self.script)
        self.assertNotIn("source <", self.script)

    def test_transition_proves_each_site_at_its_classified_phase(self):
        """Each site is proven from the Flux root this repository renders."""

        self.assertIn('[naranjo-online]="$naranjo_phase"', self.script)
        self.assertIn('[lidersea-com]="$lidersea_phase"', self.script)
        self.assertIn(
            'assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-'
            '${website}.yaml" \\\n      "$website" "${WEBSITE_PHASES[$website]}"',
            self.script,
        )
        for phase_arm in ("    initial)\n", "    staged)\n", "    active)\n"):
            with self.subTest(phase_arm=phase_arm.strip()):
                self.assertIn(phase_arm, self.script)
        # An unclassifiable phase must stop the gate rather than fall through
        # a case statement into an unproven success.
        self.assertIn(
            'die "website ${website} carries an unclassifiable phase: ${phase}"',
            self.script,
        )

    def test_site_phase_proof_asserts_both_required_and_forbidden_denials(self):
        """`initial` and `staged` both stay suspended, so presence alone is
        not proof; the absent set is what proves a staged site's reviewed
        digest and readiness reached the rendered artifact."""

        helper = self.script[self.script.index("assert_site_release_phase() {"):]
        helper = helper[: helper.index("\n}\n")]
        self.assertIn("local -a required=() forbidden=()", helper)
        for fragment in (
            'suspended="HelmRelease ${website} remains suspended"',
            'not_ready="HelmRelease ${website} is not marked ready"',
            'zero_digest="HelmRelease ${website} still names the all-zero image digest"',
            'uncanonical="HelmRelease ${website} does not name a canonical image digest"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        self.assertIn('required=("$suspended" "$not_ready" "$zero_digest")', helper)
        self.assertIn('forbidden=("$not_ready" "$zero_digest" "$uncanonical")', helper)
        self.assertIn('for fragment in "${required[@]}"', helper)
        self.assertIn('for fragment in "${forbidden[@]}"', helper)

    def test_scaffold_proves_both_sites_through_the_same_phase_helper(self):
        scaffold = self.script[self.script.index("if [[ \"$MODE\" == '--scaffold' ]]"):]
        scaffold = scaffold[: scaffold.index("elif [[ \"$MODE\" == '--release' ]]")]
        for site, phase in (
            ("naranjo-online", "naranjo_phase"),
            ("lidersea-com", "lidersea_phase"),
        ):
            with self.subTest(site=site):
                self.assertIn(
                    'assert_site_release_phase "${{ARTIFACT_ROOT}}/'
                    'kubernetes-websites-{}.yaml" \\\n    {} "${}"'.format(
                        site, site, phase
                    ),
                    scaffold,
                )

    def test_every_release_proof_requires_its_artifact_to_exist(self):
        """A missing artifact makes Conftest exit non-zero for a reason that
        is not a policy denial; both proof helpers refuse it explicitly."""

        for guard in (
            'die "missing artifact for release proof: $(basename -- "$manifest")"',
            'die "missing rendered site artifact: $(basename -- "$manifest")"',
        ):
            with self.subTest(guard=guard):
                self.assertIn(guard, self.script)

    def test_retired_site_chart_artifacts_are_never_referenced(self):
        """The regression this module exists for: the transition branch kept
        naming chart renders that left with the site repositories."""

        for retired in ("helm-naranjo-online.yaml", "helm-lidersea-com.yaml"):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, self.script)

    def test_release_proofs_only_name_artifacts_this_renderer_produces(self):
        """The static ratchet under the whole defect class: an artifact the
        renderer asserts over must be one the same renderer writes."""

        produced = {
            "helm-{}.yaml".format(row.split("|", 1)[0])
            for row in bash_array(self.script, "CHART_ROWS")
        }
        for target in bash_array(self.script, "KUSTOMIZE_TARGETS"):
            produced.add(target.replace("/", "-") + ".yaml")
        for extra in EXTRA_KUSTOMIZE_ROOTS:
            self.assertIn(
                'kustomize build "${{REPO_ROOT}}/{}"'.format(extra), self.script
            )
            produced.add(extra.replace("/", "-") + ".yaml")

        expansions = {
            "${release_name}": [
                row.split("|", 1)[0] for row in bash_array(self.script, "CHART_ROWS")
            ],
            "${output_name}": [
                target.replace("/", "-")
                for target in bash_array(self.script, "KUSTOMIZE_TARGETS")
            ],
            "${website}": list(SITES),
        }
        referenced = set()
        for raw in ARTIFACT_REFERENCE.findall(self.script):
            candidates = [raw]
            for variable, values in expansions.items():
                expanded = []
                for candidate in candidates:
                    if variable in candidate:
                        expanded.extend(
                            candidate.replace(variable, value) for value in values
                        )
                    else:
                        expanded.append(candidate)
                candidates = expanded
            for candidate in candidates:
                self.assertIsNone(
                    INTERPOLATION.search(candidate),
                    "teach this ratchet the loop variable in {!r}".format(raw),
                )
                referenced.add(candidate)

        self.assertGreaterEqual(
            len(referenced), 8, "the artifact-reference parse went vacuous"
        )
        self.assertEqual(
            referenced - produced,
            set(),
            "release proofs name artifacts this renderer never writes",
        )

    def test_active_workload_requires_controller_admission_and_core_policies(self):
        workload_gate = self.script.index(
            "if [[ \"$any_workload_active\" == 'true' ]]"
        )
        for artifact in (
            "kubernetes-flux-system.yaml",
            "kubernetes/platform/admission/kyverno/controllers.yaml",
            '"${CORE_POLICY_FILES[@]}"',
        ):
            with self.subTest(artifact=artifact):
                self.assertGreater(
                    self.script.index(artifact, workload_gate), workload_gate
                )
        self.assertIn(
            "Flux controller artifact is required whenever a workload is active",
            self.script,
        )
        website_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", workload_gate
        )
        workload_block = self.script[workload_gate:website_gate]
        self.assertNotIn("policies-kyverno.yaml", workload_block)
        self.assertNotIn("kubernetes-platform-admission.yaml", workload_block)

    def test_live_or_outer_reconcilable_website_adds_production_proof(self):
        active_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", self.script.index("else\n  # Transition mode")
        )
        for artifact in (
            "kubernetes-platform-prerequisites.yaml",
            "policies-kyverno.yaml",
        ):
            with self.subTest(artifact=artifact):
                self.assertGreater(self.script.index(artifact, active_gate), active_gate)
        self.assertIn(
            "a live or outer-reconcilable website refuses the still-active zero-site-capacity admission policy",
            self.script,
        )
        self.assertIn("active website parent", self.script)

    def test_transition_cloudflare_requires_unresolved_or_release_proof(self):
        self.assertIn("if [[ \"$cloudflare_phase\" == 'initial' ]]", self.script)
        self.assertIn(
            "'cloudflared tunnel token revision remains unresolved'", self.script
        )
        self.assertIn(
            '"${ARTIFACT_ROOT}/helm-cloudflare-public.yaml"', self.script
        )

    def test_scaffold_has_no_override_and_temporary_values_are_removed(self):
        self.assertIn("helm_values_args=()", self.script)
        self.assertIn("temporary_values+=(\"$release_values\")", self.script)
        self.assertIn("trap cleanup_temporary_values EXIT", self.script)
        self.assertIn('rm -f -- "$temporary_value"', self.script)

    def test_determinism_gate_renders_the_authoritative_mode(self):
        script = DETERMINISM.read_text(encoding="utf-8")
        # The defect shape: a render flag pinned to scaffold, which the
        # renderer refuses outright once any release leaves `initial`.
        self.assertNotIn('render-manifests.sh" --', script)
        self.assertIn(
            'mode="$(python3 -B "${repo_root}/scripts/validate_release_transition.py" '
            'select-mode)"',
            script,
        )
        self.assertIn("scaffold|transition|release) ;;", script)
        self.assertIn(
            'bash "${repo_root}/scripts/render-manifests.sh" "--${mode}"', script
        )


@unittest.skipUnless(CONFTEST, "conftest is required")
class SiteReleasePolicyTests(unittest.TestCase):
    """Prove the release policy's site-HelmRelease rules, both directions.

    These rules are the hermetic successor to the chart-level readiness and
    digest denials: the site charts render in their own repositories, so the
    HelmRelease values this repository still renders are the only reviewed
    readiness/digest evidence the pull-request gate can prove.
    """

    def denials(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yaml"
            path.write_text(site_release_document(**kwargs), encoding="utf-8")
            return release_policy_denials(path)

    def test_initial_site_denies_suspension_readiness_and_the_zero_digest(self):
        self.assertEqual(
            self.denials(),
            {
                "HelmRelease naranjo-online remains suspended",
                "HelmRelease naranjo-online is not marked ready",
                "HelmRelease naranjo-online still names the all-zero image digest",
            },
        )

    def test_staged_site_denies_only_its_remaining_suspension(self):
        """The promoted digest and readiness must be visible in the render,
        so the sole surviving denial is the deliberate suspension."""

        self.assertEqual(
            self.denials(ready=True, digest=REVIEWED_DIGEST),
            {"HelmRelease naranjo-online remains suspended"},
        )

    def test_active_site_is_accepted_outright(self):
        self.assertEqual(
            self.denials(suspend=False, ready=True, digest=REVIEWED_DIGEST), set()
        )

    def test_promoted_digest_without_readiness_is_denied(self):
        """Both an explicit `false` and an absent flag are unready: the rule's
        default must be the closed one, or a values block that simply omits
        readiness would render an unproven site release acceptable."""

        for label, kwargs in (
            ("explicitly false", {"ready": False}),
            ("absent", {"omit_ready": True}),
        ):
            with self.subTest(label=label):
                self.assertIn(
                    "HelmRelease naranjo-online is not marked ready",
                    self.denials(suspend=False, digest=REVIEWED_DIGEST, **kwargs),
                )

    def test_ready_site_without_a_canonical_digest_is_denied(self):
        for label, kwargs in (
            ("absent", {"omit_digest": True}),
            ("not a digest", {"digest": "v0.1.9"}),
            ("short", {"digest": "sha256:abc"}),
            ("uppercase", {"digest": "sha256:" + "AB" * 32}),
        ):
            with self.subTest(label=label):
                self.assertIn(
                    "HelmRelease naranjo-online does not name a canonical image digest",
                    self.denials(suspend=False, ready=True, **kwargs),
                )

    def test_both_sites_are_covered_by_the_same_closed_rules(self):
        for site in SITES:
            with self.subTest(site=site):
                self.assertIn(
                    "HelmRelease {} still names the all-zero image digest".format(site),
                    self.denials(site=site),
                )

    def test_the_platform_connector_release_is_untouched_by_the_site_rules(self):
        """cloudflare-public carries a tunnel revision, not an image digest;
        the site rules must not invent a denial for it."""

        document = textwrap.dedent(
            """\
            apiVersion: helm.toolkit.fluxcd.io/v2
            kind: HelmRelease
            metadata:
              name: cloudflare-public
              namespace: cloudflare-public
            spec:
              suspend: true
              values:
                connectors:
                  naranjo-online:
                    tokenRevision: not-configured
                  lidersea-com:
                    tokenRevision: not-configured
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yaml"
            path.write_text(document, encoding="utf-8")
            self.assertEqual(
                release_policy_denials(path),
                {"HelmRelease cloudflare-public remains suspended"},
            )


def disposable_checkout(destination):
    """Copy the tracked desired state into a disposable render root."""

    shutil.copytree(
        REPO_ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", ".artifacts", "__pycache__"),
    )
    return destination


def _rewrite_release(root, site, ready, digest):
    """Set one site's release state without assuming its current state.

    The tracked file is ``initial`` today and ``staged`` the moment that
    site's promotion merges. A fixture keyed on the initial sentinels would
    turn this whole battery — and therefore every pull request — red at
    exactly that moment, which is the class of defect this module exists to
    close. The rewrite is therefore state-independent: it matches whichever
    value is present and asserts the *result*, never the input.
    """

    path = root / "kubernetes" / "websites" / site / "release.yaml"
    rewritten, readiness_count = READY_LINE.subn(
        "    deploymentReady: {}".format("true" if ready else "false"),
        path.read_text(encoding="utf-8"),
    )
    rewritten, digest_count = DIGEST_LINE.subn(
        "      digest: {}".format(digest), rewritten
    )
    if (readiness_count, digest_count) != (1, 1):
        raise AssertionError(
            "release fixture for {} exposed {} readiness and {} digest "
            "line(s); expected exactly one of each".format(
                site, readiness_count, digest_count
            )
        )
    expected_readiness = "    deploymentReady: {}\n".format(
        "true" if ready else "false"
    )
    if expected_readiness not in rewritten or digest not in rewritten:
        raise AssertionError("release rewrite for {} did not take effect".format(site))
    path.write_text(rewritten, encoding="utf-8")


def promote(root, site=SITES[0], digest=REVIEWED_DIGEST):
    """Leave one site in the ``staged`` phase, whatever it started in."""

    _rewrite_release(root, site, True, digest)


def demote(root, sites=SITES):
    """Leave every named site in the ``initial`` phase.

    Every state-dependent test calls this first, so the battery's verdict is
    the same before and after any promotion merges into the base branch.
    """

    for site in sites:
        _rewrite_release(root, site, False, ZERO_DIGEST)


def render(root, mode):
    return subprocess.run(
        [
            required_tool(BASH, "bash is required"),
            str(root / "scripts" / "render-kubernetes.sh"),
            "--{}".format(mode),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def selected_mode(root):
    completed = subprocess.run(
        [
            required_tool(PYTHON3, "python3 is required"),
            "-B",
            str(root / "scripts" / "validate_release_transition.py"),
            "--root",
            str(root),
            "select-mode",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


@unittest.skipUnless(
    RENDER_TOOLCHAIN and BASH and PYTHON3, "the pinned render toolchain is required"
)
class PromotedRenderStateTests(unittest.TestCase):
    """Execute the real renderer across the release states CI selects.

    ``initial`` state selects ``scaffold`` and ``staged`` selects
    ``transition``; before this battery existed the second was unreachable
    in this repository, so a merged promotion would have turned every later
    pull request red.
    """

    def checkout(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return disposable_checkout(Path(directory.name) / "repository")

    def test_initial_state_still_renders_in_scaffold_mode(self):
        root = self.checkout()
        demote(root)
        self.assertEqual(selected_mode(root), "scaffold")
        completed = render(root, "scaffold")
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("static artifact(s) passed", completed.stdout)

    def test_promoted_state_renders_and_passes_in_transition_mode(self):
        root = self.checkout()
        demote(root)
        promote(root)
        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("static artifact(s) passed", completed.stdout)
        rendered = (
            root / ".artifacts" / "rendered" / "kubernetes-websites-naranjo-online.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(REVIEWED_DIGEST, rendered)

    def test_promoted_state_whose_render_drops_the_promotion_fails_closed(self):
        """The exact property the retired chart render used to prove: source
        that claims promotion but renders the inert sentinel is denied."""

        root = self.checkout()
        demote(root)
        promote(root)
        kustomization = (
            root / "kubernetes" / "websites" / "naranjo-online" / "kustomization.yaml"
        )
        kustomization.write_text(
            kustomization.read_text(encoding="utf-8")
            + textwrap.dedent(
                """\
                patches:
                  - target:
                      kind: HelmRelease
                      name: naranjo-online
                    patch: |-
                      - op: replace
                        path: /spec/values/image/digest
                        value: {}
                """
            ).format(ZERO_DIGEST),
            encoding="utf-8",
        )
        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "staged website naranjo-online still denies: HelmRelease "
            "naranjo-online still names the all-zero image digest",
            completed.stderr,
        )

    def test_a_site_proof_without_its_rendered_artifact_fails_closed(self):
        """Reproduce the motivating defect's shape — a release proof whose
        artifact is not produced — and require an honest refusal."""

        root = self.checkout()
        demote(root)
        promote(root)
        script = root / "scripts" / "render-manifests.sh"
        script.write_text(
            script.read_text(encoding="utf-8").replace(
                "  kubernetes/websites/naranjo-online\n", "", 1
            ),
            encoding="utf-8",
        )
        completed = render(root, "transition")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "missing rendered site artifact: kubernetes-websites-naranjo-online.yaml",
            completed.stderr,
        )


@unittest.skipUnless(BASH and PYTHON3, "bash and python3 are required")
class RenderDeterminismModeTests(unittest.TestCase):
    """Execute the determinism gate against a controlled renderer.

    The real renderer is deterministic, so proving the gate still fails on
    nondeterminism needs a renderer that is not. The subject under test is
    the real ``verify-render-determinism.sh``; only its two collaborators
    are stubbed, which is also how the mode it selects becomes observable.
    """

    NONDETERMINISTIC = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
        out="${root}/.artifacts/rendered"
        mkdir -p "$out"
        printf 'mode: %s\\n' "$1" >"${out}/mode.yaml"
        pass=0
        [[ -f "${root}/.passes" ]] && pass="$(cat "${root}/.passes")"
        pass=$((pass + 1))
        printf '%s' "$pass" >"${root}/.passes"
        printf 'pass: %s\\n' "$pass" >"${out}/unstable.yaml"
        """
    )
    DETERMINISTIC = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
        mkdir -p "${root}/.artifacts/rendered"
        printf 'mode: %s\\n' "$1" >"${root}/.artifacts/rendered/mode.yaml"
        """
    )

    def harness(self, renderer, mode_stdout, mode_exit=0):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name) / "repository"
        (root / "scripts" / "ci").mkdir(parents=True)
        shutil.copy2(DETERMINISM, root / "scripts" / "ci" / DETERMINISM.name)
        (root / "scripts" / "render-manifests.sh").write_text(
            renderer, encoding="utf-8"
        )
        (root / "scripts" / "validate_release_transition.py").write_text(
            "import sys\nprint({!r})\nsys.exit({:d})\n".format(mode_stdout, mode_exit),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                required_tool(BASH, "bash is required"),
                str(root / "scripts" / "ci" / DETERMINISM.name),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return root, completed

    def test_the_selected_mode_reaches_the_renderer_and_the_verdict(self):
        for mode in ("scaffold", "transition", "release"):
            with self.subTest(mode=mode):
                root, completed = self.harness(self.DETERMINISTIC, mode)
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                self.assertIn(
                    "PASS two independent {} renders are byte-identical".format(mode),
                    completed.stdout,
                )
                self.assertEqual(
                    (root / ".artifacts" / "rendered" / "mode.yaml").read_text(
                        encoding="utf-8"
                    ),
                    "mode: --{}\n".format(mode),
                )

    def test_two_differing_renders_fail_closed(self):
        _, completed = self.harness(self.NONDETERMINISTIC, "transition")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "two transition renders differ; rendered evidence is not reproducible",
            completed.stderr,
        )
        self.assertIn("unstable.yaml", completed.stderr)

    def test_an_unavailable_mode_stops_the_gate_before_rendering(self):
        root, completed = self.harness(self.DETERMINISTIC, "transition", mode_exit=1)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "authoritative release transition mode is unavailable", completed.stderr
        )
        self.assertFalse((root / ".artifacts").exists())

    def test_an_unrecognized_mode_stops_the_gate_before_rendering(self):
        root, completed = self.harness(self.DETERMINISTIC, "scaffold --release")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsafe release transition mode", completed.stderr)
        self.assertFalse((root / ".artifacts").exists())


class ReleaseStateFixtureTests(unittest.TestCase):
    """Keep the rewrite targets honest against the tracked release file.

    Deliberately not an assertion about which phase the tracked file is in:
    it is `initial` today and `staged` once that site's promotion merges, and
    a battery that pinned either one would go red on the other. What must
    hold in both states is that the two values the fixtures rewrite are
    present, exactly once each, in the shape the rewrite matches.
    """

    def test_the_tracked_site_release_exposes_both_rewrite_targets(self):
        for site in SITES:
            with self.subTest(site=site):
                text = (
                    REPO_ROOT / "kubernetes" / "websites" / site / "release.yaml"
                ).read_text(encoding="utf-8")
                self.assertRegex(text, READY_LINE)
                self.assertRegex(text, DIGEST_LINE)
                self.assertEqual(len(READY_LINE.findall(text)), 1)
                self.assertEqual(len(DIGEST_LINE.findall(text)), 1)


if __name__ == "__main__":
    unittest.main()
