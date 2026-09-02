"""Require transition rendering to consume authoritative Flux values.

Three batteries, deliberately layered:

* ``ReleaseRenderOverrideTests`` pins the renderer's structure, including
  the ratchet that would have caught this module's motivating defect —
  after the site charts moved to their own repositories the transition
  branch still demanded ``helm-<site>.yaml`` artifacts nothing produced,
  so every pull request would have gone red the moment one site left the
  dormant staged release state.
* ``SiteReleasePolicyTests`` executes the real release policy against
  synthetic site HelmReleases, proving each phase's denial set exactly.
* ``SiteRenderStateTests`` and ``RenderDeterminismModeTests`` execute
  the real ``render-manifests.sh`` and ``verify-render-determinism.sh``
  against disposable repository copies, in both the green and the red
  direction, because a string pin cannot prove a gate still fires.
"""

import json
import os
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
REPOSITORY_POLICY = REPO_ROOT / "policies" / "conftest"
CAPACITY_DENY_FIXTURE = (
    REPO_ROOT / "tests" / "kubernetes" / "fixtures" / "deny"
    / "reviewed-capacity-bypasses.yaml"
)

BASH = shutil.which("bash")
CONFTEST = shutil.which("conftest")
PYTHON3 = shutil.which("python3")
RENDER_TOOLCHAIN = all(
    shutil.which(tool)
    for tool in ("helm", "kustomize", "conftest")
)

# Loop variables the renderer expands inside an artifact path. Anything else
# interpolated into an artifact reference fails the ratchet below rather than
# being silently skipped.
SITES = ("naranjo-online", "lidersea-com")
READY_LINE = re.compile(r"^    deploymentReady: true$", re.MULTILINE)
ARTIFACT_REFERENCE = re.compile(r"\$\{ARTIFACT_ROOT\}/([A-Za-z0-9._${}-]+\.yaml)")
INTERPOLATION = re.compile(r"\$\{[^}]*\}")
# One Kustomize root is built outside the declared target list; it is
# asserted to keep its own `kustomize build` and follows the same
# path-to-artifact naming rule the declared targets use.
EXTRA_KUSTOMIZE_ROOTS = ("kubernetes/flux-system",)


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
    deployment_ready=True,
):
    """Render one site HelmRelease exactly as Kustomize emits it."""

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
            deploymentReady: {deployment_ready}
        """
    ).format(
        site=site,
        suspend="true" if suspend else "false",
        deployment_ready="true" if deployment_ready else "false",
    )


def conftest_policy_denials(policy, path):
    """Return the exact denial messages one Conftest policy surface raises."""

    completed = subprocess.run(
        [
            required_tool(CONFTEST, "conftest is required"),
            "test",
            "--policy",
            str(policy),
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


def release_policy_denials(path):
    """Return the exact denial messages the release policy raises."""

    return conftest_policy_denials(RELEASE_POLICY, path)


def capacity_deny_documents():
    """Return the six named single-mutation capacity documents."""

    documents = []
    for document in re.split(
        r"(?m)^---\s*$", CAPACITY_DENY_FIXTURE.read_text(encoding="utf-8")
    ):
        case = re.search(r"(?m)^# capacity-deny-case: (\S+)$", document)
        namespace = re.search(r"(?m)^  namespace: (\S+)$", document)
        if case is None or namespace is None:
            raise AssertionError("capacity deny fixture has an unnamed document")
        documents.append((case.group(1), namespace.group(1), document.lstrip()))
    return documents


FORMER_BROAD_CAPACITY_PREDICATE = """valid_reviewed_capacity_quota if {
  input.metadata.name == "namespace-budget"
  annotations := object.get(input.metadata, "annotations", {})
  object.get(annotations, "platform.snaraj.dev/readiness", "") == "reviewed-pi-capacity"
  regex.match("^[0-9a-f]{64}$", object.get(annotations, "platform.snaraj.dev/capacity-evidence-sha256", ""))
  hard := object.get(input.spec, "hard", {})
  object.keys(hard) == {"pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory"}
  to_number(hard.pods) >= 2
  every key in {"requests.cpu", "requests.memory", "limits.cpu", "limits.memory"} {
    regex.match("^[1-9][0-9]*(?:m|Ki|Mi|Gi)?$", hard[key])
  }
}"""


def restore_broad_capacity_predicate(path):
    """Mutate one copied policy back to the pre-#201 syntactic predicate."""

    text = path.read_text(encoding="utf-8")
    start = text.index("valid_reviewed_capacity_quota if {")
    end = text.index("\n}\n", start) + len("\n}")
    path.write_text(
        text[:start] + FORMER_BROAD_CAPACITY_PREDICATE + text[end:],
        encoding="utf-8",
        newline="\n",
    )


@unittest.skipUnless(CONFTEST, "conftest is required")
class CapacityPolicyContractTests(unittest.TestCase):
    """Bind all six reviewed-capacity fields across both Rego surfaces."""

    CASES = {
        "audit-sha256",
        "pods",
        "requests.cpu",
        "requests.memory",
        "limits.cpu",
        "limits.memory",
    }

    @classmethod
    def setUpClass(cls):
        cls.documents = capacity_deny_documents()
        if {case for case, _, _ in cls.documents} != cls.CASES:
            raise AssertionError("capacity deny fixture does not cover the exact six fields")

    def _write_document(self, root, case, document):
        path = root / (case.replace(".", "-") + ".yaml")
        path.write_text(document, encoding="utf-8", newline="\n")
        return path

    def test_every_wrong_field_has_one_exact_reason_on_both_surfaces(self):
        surfaces = (
            (
                REPOSITORY_POLICY,
                lambda namespace: (
                    "ResourceQuota {}/namespace-budget must be either the exact "
                    "zero-Pod gate or a hash-bound reviewed namespace budget"
                ).format(namespace),
            ),
            (
                RELEASE_POLICY,
                lambda namespace: (
                    "site capacity gate remains closed or lacks a hash-bound "
                    "reviewed budget in namespace {}"
                ).format(namespace),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case, namespace, document in self.documents:
                manifest = self._write_document(root, case, document)
                for policy, reason in surfaces:
                    with self.subTest(case=case, policy=policy.name):
                        self.assertEqual(
                            conftest_policy_denials(policy, manifest),
                            {reason(namespace)},
                        )

    def test_former_broad_predicate_is_killed_on_both_surfaces(self):
        policy_files = (
            (REPOSITORY_POLICY, "kubernetes.rego"),
            (RELEASE_POLICY, "deployment-readiness.rego"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for policy, filename in policy_files:
                mutated_policy = root / policy.name
                shutil.copytree(policy, mutated_policy)
                restore_broad_capacity_predicate(mutated_policy / filename)
                for case, _, document in self.documents:
                    manifest = self._write_document(root, policy.name + "-" + case, document)
                    with self.subTest(case=case, policy=policy.name):
                        self.assertEqual(
                            conftest_policy_denials(mutated_policy, manifest),
                            set(),
                            "the former broad predicate must accept this mutant so "
                            "the committed deny case is proven to kill it",
                        )


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
        self.assertIn('((${#release_plan_lines[@]} == 7))', self.script)
        for record in (
            "mode=${mode_name}",
            "^naranjo-online=(staged|active)$",
            "^lidersea-com=(staged|active)$",
            "^cloudflare-public=(initial|staged|active)$",
            "^platform-services-suspended=(true|false)$",
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
        for phase_arm in ("    staged)\n", "    active)\n"):
            with self.subTest(phase_arm=phase_arm.strip()):
                self.assertIn(phase_arm, self.script)
        # An unclassifiable phase must stop the gate rather than fall through
        # a case statement into an unproven success.
        self.assertIn(
            'die "website ${website} carries an unclassifiable phase: ${phase}"',
            self.script,
        )

    def test_site_phase_proof_asserts_both_required_and_forbidden_denials(self):
        """Staged sites require suspension and the exact values/source shape."""

        helper = self.script[self.script.index("assert_site_release_phase() {"):]
        helper = helper[: helper.index("\n}\n")]
        self.assertIn("local -a required=() forbidden=()", helper)
        for fragment in (
            'suspended="HelmRelease ${website} remains suspended"',
            'invalid_values="HelmRelease ${website} values must contain exactly '
            'deploymentReady: true"',
            'unverified="chart source ${website}/${website}-chart does not '
            'require cosign verification"',
            'unbound="chart source ${website}/${website}-chart does not bind '
            'exactly one keyless publisher identity"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        self.assertIn('required=("$suspended")', helper)
        self.assertIn(
            'forbidden=("$invalid_values" "$unverified" "$unbound")', helper
        )
        self.assertIn('for fragment in "${required[@]}"', helper)
        self.assertIn('for fragment in "${forbidden[@]}"', helper)

    def test_every_site_release_denial_is_in_the_closed_phase_vocabulary(self):
        """The vocabulary must name every denial a site root can produce.

        `assert_site_release_phase` decides a phase is correct by matching a
        closed set of fragments. A release-policy rule that can fire on a site
        artifact but appears in neither the required nor the forbidden set is
        invisible to that decision, so adding one silently widens what a
        `staged` site is allowed to be denied for. This derives the site-scoped
        rule set from the policy source and requires the helper to name it.
        """

        policy = (RELEASE_POLICY / "deployment-readiness.rego").read_text(
            encoding="utf-8"
        )
        helper = self.script[self.script.index("assert_site_release_phase() {"):]
        helper = helper[: helper.index("\n}\n")]
        # The kinds a site root actually renders, derived from its own
        # Kustomize inputs rather than hardcoded, so adding a third object to
        # a site root widens this test automatically.
        site_root = REPO_ROOT / "kubernetes" / "websites" / SITES[0]
        rendered_kinds = {
            match.group(1)
            for path in sorted(site_root.glob("*.yaml"))
            if path.name != "kustomization.yaml"
            for match in re.finditer(
                r"(?m)^kind: ([A-Za-z]+)$", path.read_text(encoding="utf-8")
            )
        }
        self.assertEqual(rendered_kinds, {"HelmRelease", "NetworkPolicy", "OCIRepository"})
        # Every sprintf message a site-scoped rule can emit for those kinds.
        # A ResourceQuota rule is also site-scoped but renders from the
        # platform prerequisites root, so it can never reach this artifact.
        messages = set()
        for block in policy.split("deny contains msg if {")[1:]:
            body = block.split("\n}", 1)[0]
            if "site_namespaces" not in body:
                continue
            kind = re.search(r'input\.kind\s*==\s*"([A-Za-z]+)"', body)
            if kind is None or kind.group(1) not in rendered_kinds:
                continue
            match = re.search(r'msg\s*:=\s*sprintf\(\s*"([^"]+)"', body)
            if match:
                messages.add(match.group(1))
        self.assertGreaterEqual(
            len(messages), 3, "site-scoped denial extraction found too few rules"
        )
        for message in sorted(messages):
            # Match on the literal tail after the LAST format specifier. The
            # leading stem alone is not distinctive — every chart-source rule
            # begins "chart source %s/%s" — so a stem comparison would accept
            # any new rule in an existing family, which is precisely the case
            # this test exists to catch.
            tail = re.split(r"%[a-zA-Z]", message)[-1].strip()
            with self.subTest(message=message):
                self.assertTrue(
                    tail, "denial message has no literal tail to match: " + message
                )
                self.assertIn(
                    tail,
                    helper,
                    "site denial not in the closed phase vocabulary: " + message,
                )

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

    def test_active_workload_proof_remains_proportional(self):
        workload_gate = self.script.index(
            "if [[ \"$any_workload_active\" == 'true' ]]"
        )
        website_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", workload_gate
        )
        workload_block = self.script[workload_gate:website_gate]
        self.assertIn("kubernetes-flux-system.yaml", workload_block)
        self.assertIn(
            "Flux controller artifact is required whenever a workload is active",
            self.script,
        )
        self.assertNotIn("admission_suspended", self.script)
        self.assertNotIn("policies-kyverno.yaml", workload_block)
        self.assertNotIn("kubernetes-platform-admission.yaml", workload_block)

    def test_live_or_outer_reconcilable_website_adds_production_proof(self):
        active_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", self.script.index("else\n  # Transition mode")
        )
        self.assertGreater(
            self.script.index("kubernetes-platform-prerequisites.yaml", active_gate),
            active_gate,
        )
        self.assertNotIn("policies-kyverno.yaml", self.script)
        self.assertNotIn("require-zero-site-capacity.yaml", self.script)
        self.assertIn("active website", self.script)

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
        # renderer refuses outright when its selected authoritative mode drifts.
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
    """Prove the exact values-only site HelmRelease rule both directions."""

    def denials(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yaml"
            path.write_text(site_release_document(**kwargs), encoding="utf-8")
            return release_policy_denials(path)

    def values_denials(self, values_block, *, site="naranjo-online"):
        document = site_release_document(site=site, suspend=False)
        document, count = re.subn(
            r"(?ms)^  values:\n    deploymentReady: true\n",
            values_block,
            document,
        )
        self.assertEqual(count, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yaml"
            path.write_text(document, encoding="utf-8")
            return release_policy_denials(path)

    def assert_invalid_values(self, values_block, *, site="naranjo-online"):
        self.assertEqual(
            self.values_denials(values_block, site=site),
            {
                "HelmRelease {} values must contain exactly "
                "deploymentReady: true".format(site)
            },
        )

    def test_staged_site_denies_only_its_suspension(self):
        self.assertEqual(
            self.denials(),
            {"HelmRelease naranjo-online remains suspended"},
        )

    def test_false_readiness_is_denied_alongside_suspension(self):
        self.assertEqual(
            self.denials(deployment_ready=False),
            {
                "HelmRelease naranjo-online remains suspended",
                "HelmRelease naranjo-online values must contain exactly "
                "deploymentReady: true",
            },
        )

    def test_active_site_is_accepted_outright(self):
        self.assertEqual(self.denials(suspend=False), set())

    def test_false_or_absent_readiness_is_denied(self):
        """Both explicit false and omission take the single closed arm."""

        for label, values_block in (
            ("explicitly false", "  values:\n    deploymentReady: false\n"),
            ("absent", "  values: {}\n"),
        ):
            with self.subTest(label=label):
                self.assert_invalid_values(values_block)

    def test_any_image_digest_override_is_denied(self):
        for label, digest in (
            ("absent", None),
            ("not a digest", "v0.1.9"),
            ("short", "sha256:abc"),
            ("uppercase", "sha256:" + "AB" * 32),
            ("canonical", "sha256:" + "ab" * 32),
        ):
            digest_line = "" if digest is None else "      digest: {}\n".format(digest)
            with self.subTest(label=label):
                self.assert_invalid_values(
                    "  values:\n"
                    "    deploymentReady: true\n"
                    "    image:\n"
                    "      repository: ghcr.io/snaraj/naranjo-online\n"
                    + digest_line
                )

    def test_any_image_tag_override_is_denied(self):
        for label, tag in (
            ("absent", None),
            ("floating alias", "latest"),
            ("unprefixed", "0.1.9"),
            ("branch name", "vmain"),
            ("partial", "v0.1"),
            ("leading zero", "v0.01.9"),
            ("a digest", "sha256:" + "ab" * 32),
            ("canonical", "v9.9.9"),
        ):
            tag_line = "" if tag is None else "      tag: {}\n".format(tag)
            with self.subTest(label=label):
                self.assert_invalid_values(
                    "  values:\n"
                    "    deploymentReady: true\n"
                    "    image:\n"
                    "      repository: ghcr.io/snaraj/naranjo-online\n"
                    "      digest: sha256:" + ("a" * 64) + "\n"
                    + tag_line
                )

    def test_a_partial_image_override_is_denied_on_either_half(self):
        """Even former tag/digest sentinels cannot recreate an override lane."""

        for label, image_block in (
            ("tag only", "      tag: v9.9.9\n"),
            ("digest only", "      digest: sha256:" + ("a" * 64) + "\n"),
        ):
            with self.subTest(label=label):
                self.assert_invalid_values(
                    "  values:\n"
                    "    deploymentReady: true\n"
                    "    image:\n"
                    + image_block
                )

    def test_a_non_string_leaf_is_denied_not_skipped(self):
        """Every former image leaf type remains a hostile extra value."""

        digest = "sha256:" + "ab" * 32
        for label, value in (
            ("null", "null"),
            ("boolean", "true"),
            ("number", "5"),
            ("list", "[]"),
            ("map", "{}"),
        ):
            for field in ("digest", "tag"):
                other = (
                    "      tag: v1.2.3\n"
                    if field == "digest"
                    else "      digest: {}\n".format(digest)
                )
                with self.subTest(field=field, shape=label):
                    self.assert_invalid_values(
                        "  values:\n"
                        "    deploymentReady: true\n"
                        "    image:\n"
                        "      repository: ghcr.io/snaraj/naranjo-online\n"
                        + other
                        + "      {}: {}\n".format(field, value)
                    )

    def test_a_degenerate_image_mapping_is_denied_not_skipped(self):
        """Null, scalar, list, and malformed mappings all fail closed."""

        for label, block in (
            ("null image", "  values:\n    deploymentReady: true\n    image:\n"),
            ("scalar image", "  values:\n    deploymentReady: true\n    image: nope\n"),
            ("list image", "  values:\n    deploymentReady: true\n    image:\n      - a\n"),
            ("null values", "  values:\n"),
            ("scalar values", "  values: nope\n"),
        ):
            with self.subTest(label=label):
                self.assert_invalid_values(block)

    def test_both_sites_are_covered_by_the_same_closed_rules(self):
        for site in SITES:
            with self.subTest(site=site):
                self.assertEqual(
                    self.denials(site=site),
                    {"HelmRelease {} remains suspended".format(site)},
                )

    def test_the_platform_connector_release_is_untouched_by_the_site_rules(self):
        """The site values rule must not apply to cloudflare-public."""

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


def _set_site_suspension(root, site, suspended):
    """Normalize the values-only HelmRelease gate in a phase fixture."""

    relative = Path("kubernetes/websites") / site / "release.yaml"
    path = root / relative
    rewritten, count = re.subn(
        r"(?m)^  suspend: (?:true|false)$",
        "  suspend: {}".format("true" if suspended else "false"),
        path.read_text(encoding="utf-8"),
    )
    if count != 1:
        raise AssertionError(
            "site fixture exposed {} suspension lines: {}".format(
                count, relative
            )
        )
    path.write_text(rewritten, encoding="utf-8")


def stage_sites(root, sites=SITES):
    """Suspend every named values-only release under its direct reconciler."""

    for site in sites:
        _set_site_suspension(root, site, True)


def render(root, mode):
    # These tests exercise the renderer's release-policy and artifact-flow
    # behavior. Supply a no-network schema collaborator so an empty local
    # kubeconform cache cannot stop the test before the targeted hostile
    # mutation reaches Conftest. The real kubeconform invocation/tool contract
    # is covered independently by the renderer and CI contract suites.
    tool_root = root / ".test-bin"
    tool_root.mkdir(exist_ok=True)
    kubeconform = tool_root / "kubeconform"
    kubeconform.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    kubeconform.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = str(tool_root) + os.pathsep + environment.get("PATH", "")
    return subprocess.run(
        [
            required_tool(BASH, "bash is required"),
            str(root / "scripts" / "render-kubernetes.sh"),
            "--{}".format(mode),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
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
class SiteRenderStateTests(unittest.TestCase):
    """Execute the real renderer across the release states CI selects.

    Direct site Kustomizations always select both website paths, so staged and
    active values-only HelmReleases both select ``transition``. Neither state
    introduces an admission or aggregate reconciliation prerequisite.
    """

    def checkout(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return disposable_checkout(Path(directory.name) / "repository")

    def test_staged_state_renders_in_direct_transition_mode(self):
        root = self.checkout()
        stage_sites(root)
        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("static artifact(s) passed", completed.stdout)

    def test_active_site_renders_and_passes_in_transition_mode(self):
        root = self.checkout()
        stage_sites(root)
        _set_site_suspension(root, SITES[0], False)
        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("static artifact(s) passed", completed.stdout)
        rendered = (
            root / ".artifacts" / "rendered" / "kubernetes-websites-naranjo-online.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("    deploymentReady: true\n", rendered)
        self.assertNotIn("    image:\n", rendered)

    def test_active_render_that_adds_an_image_override_fails_closed(self):
        """Kustomize cannot reintroduce image identity below the chart source."""

        root = self.checkout()
        stage_sites(root)
        _set_site_suspension(root, SITES[0], False)
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
                      - op: add
                        path: /spec/values/image
                        value:
                          repository: ghcr.io/snaraj/naranjo-online
                          tag: v9.9.9
                          digest: sha256:{digest}
                """
            ).format(digest="a" * 64),
            encoding="utf-8",
        )
        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "HelmRelease naranjo-online values must contain exactly "
            "deploymentReady: true",
            completed.stdout + completed.stderr,
        )

    def test_a_render_that_strips_chart_signature_verification_fails_closed(self):
        """The chart-source counterpart of the image-override case above.

        ``validate_signature_policy.py chart-source`` compares the committed
        ``source.yaml`` byte-for-byte, but it reads the FILE. A Kustomize patch
        can leave that file pristine and still emit an OCIRepository with no
        ``verify`` block, which would let Flux accept an unsigned or
        wrong-publisher chart. Only a check over the rendered artifact can see
        that, so this proves the render gate does.
        """

        root = self.checkout()
        stage_sites(root)
        kustomization = (
            root / "kubernetes" / "websites" / "naranjo-online" / "kustomization.yaml"
        )
        kustomization.write_text(
            kustomization.read_text(encoding="utf-8")
            + textwrap.dedent(
                """\
                patches:
                  - target:
                      group: source.toolkit.fluxcd.io
                      version: v1
                      kind: OCIRepository
                      name: naranjo-online-chart
                    patch: |-
                      - op: remove
                        path: /spec/verify
                """
            ),
            encoding="utf-8",
        )
        # The committed file is untouched, so the source-file contract still
        # passes; the denial must come from the render.
        source_gate = subprocess.run(
            [
                required_tool(PYTHON3, "python3 is required"),
                "-B",
                str(root / "scripts" / "validate_signature_policy.py"),
                "chart-source",
                "--file",
                str(root / "kubernetes/websites/naranjo-online/source.yaml"),
                "--site",
                "naranjo-online",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(source_gate.returncode, 0, source_gate.stderr)

        self.assertEqual(selected_mode(root), "transition")
        completed = render(root, "transition")
        self.assertNotEqual(
            completed.returncode,
            0,
            "a render without chart signature verification was accepted",
        )
        self.assertIn(
            "must verify chart signatures against this workload's exact keyless "
            "publisher identity",
            completed.stdout + completed.stderr,
        )

    def test_a_site_proof_without_its_rendered_artifact_fails_closed(self):
        """Reproduce the motivating defect's shape — a release proof whose
        artifact is not produced — and require an honest refusal."""

        root = self.checkout()
        stage_sites(root)
        _set_site_suspension(root, SITES[0], False)
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
    """Keep the tracked site release values closed to readiness only."""

    def test_the_tracked_site_release_has_one_exact_value_and_no_image(self):
        for site in SITES:
            with self.subTest(site=site):
                text = (
                    REPO_ROOT / "kubernetes" / "websites" / site / "release.yaml"
                ).read_text(encoding="utf-8")
                self.assertRegex(text, READY_LINE)
                self.assertEqual(len(READY_LINE.findall(text)), 1)
                self.assertEqual(
                    text.split("  values:\n", 1)[1],
                    "    deploymentReady: true\n",
                )
                self.assertNotIn("    image:\n", text)


if __name__ == "__main__":
    unittest.main()
