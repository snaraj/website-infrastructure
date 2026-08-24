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
    for tool in ("helm", "kustomize", "kubeconform", "conftest", "kyverno")
)

ZERO_DIGEST = "sha256:" + "0" * 64
# A canonical but deliberately synthetic digest: this battery proves the
# gate's shape, never a particular site's released artifact, so no real
# promotion value is duplicated here (safety invariant 14).
REVIEWED_DIGEST = "sha256:" + "ab" * 32
# The tag half of the same synthetic identity. `v0.0.0` is the fail-closed
# sentinel the release policy denies exactly as it denies the all-zero digest;
# the reviewed value is deliberately not any site's real published release.
ZERO_TAG = "v0.0.0"
REVIEWED_TAG = "v9.9.9"

# Loop variables the renderer expands inside an artifact path. Anything else
# interpolated into an artifact reference fails the ratchet below rather than
# being silently skipped.
SITES = ("naranjo-online", "lidersea-com")
# The two release-state values the fixtures rewrite. Matching the line shape
# rather than one particular value is what keeps this battery independent of
# whether a promotion has already merged into the base branch.
READY_LINE = re.compile(r"^    deploymentReady: (?:true|false)$", re.MULTILINE)
DIGEST_LINE = re.compile(r"^      digest: sha256:[0-9a-f]{64}$", re.MULTILINE)
TAG_LINE = re.compile(r"^      tag: v[0-9]+\.[0-9]+\.[0-9]+$", re.MULTILINE)
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
    tag=ZERO_TAG,
    omit_digest=False,
    omit_tag=False,
    omit_ready=False,
):
    """Render one site HelmRelease exactly as Kustomize emits it."""

    image = "" if omit_digest else "      digest: {}\n".format(digest)
    image += "" if omit_tag else "      tag: {}\n".format(tag)
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
            # The release tag is gated exactly like the digest, so its two
            # arms and the degenerate-shape arm belong to the same closed
            # vocabulary: a denial outside it is invisible to the phase proof.
            'sentinel_tag="HelmRelease ${website} still names the sentinel release tag"',
            'uncanonical_tag="HelmRelease ${website} does not name a canonical release tag"',
            'malformed_image="HelmRelease ${website} does not state a well-formed image mapping"',
            'nonstring_digest="HelmRelease ${website} does not state a string image digest"',
            'nonstring_tag="HelmRelease ${website} does not state a string release tag"',
            # A site root renders that site's chart source as well as its
            # release, so the vocabulary is exhaustive only if it names the
            # chart-source denials too. A correct chart source produces
            # neither in any phase, so both are forbidden and never required.
            'unverified="chart source ${website}/${website}-chart does not '
            'require cosign verification"',
            'unbound="chart source ${website}/${website}-chart does not bind '
            'exactly one keyless publisher identity"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        self.assertIn(
            'required=("$suspended" "$not_ready" "$zero_digest" "$sentinel_tag")',
            helper,
        )
        self.assertIn(
            'forbidden=("$uncanonical" "$uncanonical_tag" "$malformed_image" '
            '"$nonstring_digest" "$nonstring_tag" "$unverified" "$unbound")',
            helper,
        )
        self.assertIn(
            'forbidden=("$not_ready" "$zero_digest" "$uncanonical" '
            '"$sentinel_tag" "$uncanonical_tag" "$malformed_image" '
            '"$nonstring_digest" "$nonstring_tag" "$unverified" "$unbound")',
            helper,
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
        self.assertEqual(rendered_kinds, {"HelmRelease", "OCIRepository"})
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
            len(messages), 5, "site-scoped denial extraction found too few rules"
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

    def test_scaffold_accepts_the_enforcing_base_signature_policy_render(self):
        """Report-only is an install overlay, not the desired-state base.

        The base signature policies stay Enforce/Fail while reconciliation is
        dormant. Scaffold mode must validate those rendered bytes positively;
        expecting an Audit denial here would make the release gate demand a
        weaker policy than the transaction source actually commits.
        """

        scaffold = self.script[self.script.index("if [[ \"$MODE\" == '--scaffold' ]]"):]
        scaffold = scaffold[: scaffold.index("elif [[ \"$MODE\" == '--release' ]]")]
        self.assertIn(
            'conftest test --policy "${REPO_ROOT}/policies/release-conftest" \\\n'
            '    "${ARTIFACT_ROOT}/policies-kyverno.yaml"',
            scaffold,
        )
        self.assertNotIn(
            "signature admission policy require-signed-naranjo-online is not enforced",
            scaffold,
        )
        self.assertNotIn(
            "signature admission policy require-signed-lidersea-com is not enforced",
            scaffold,
        )

    def test_release_core_policy_inventory_matches_the_renderer(self):
        """Every renderer-required core policy is release-gated by identity."""

        policy = (RELEASE_POLICY / "deployment-readiness.rego").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"core_admission_policies := \{\n(?P<body>.*?)\n\}", policy, re.DOTALL
        )
        if match is None:
            raise AssertionError("release core-policy inventory disappeared")
        inventory = set(
            re.findall(r'^\s+"([a-z0-9-]+)",?$', match.group("body"), re.MULTILINE)
        )
        expected = set(bash_array(self.script, "CORE_POLICY_FILES"))
        self.assertEqual(
            inventory,
            expected,
            "release Conftest and the renderer disagree on the exact core "
            "admission-policy inventory",
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
            "obsolete require-zero-site-capacity.yaml is active; restoration "
            "requires a coordinated inventory, overlay, render-lock, and "
            "validator recut",
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
                "HelmRelease naranjo-online still names the sentinel release tag",
            },
        )

    def test_staged_site_denies_only_its_remaining_suspension(self):
        """The promoted digest and readiness must be visible in the render,
        so the sole surviving denial is the deliberate suspension."""

        self.assertEqual(
            self.denials(ready=True, digest=REVIEWED_DIGEST, tag=REVIEWED_TAG),
            {"HelmRelease naranjo-online remains suspended"},
        )

    def test_active_site_is_accepted_outright(self):
        self.assertEqual(
            self.denials(
                suspend=False, ready=True, digest=REVIEWED_DIGEST, tag=REVIEWED_TAG
            ),
            set(),
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
                    self.denials(
                        suspend=False,
                        digest=REVIEWED_DIGEST,
                        tag=REVIEWED_TAG,
                        **kwargs
                    ),
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
                    self.denials(
                        suspend=False, ready=True, tag=REVIEWED_TAG, **kwargs
                    ),
                )

    def test_ready_site_without_a_canonical_release_tag_is_denied(self):
        """The tag is legibility, but a LYING tag is worse than no tag.

        A reference that names a release the digest beside it never carried
        would make `kubectl describe pod` confidently wrong, so every shape
        that is not one exact SemVer release name is refused here — including
        a floating alias, the bare unprefixed version, and the digest wearing
        the tag field's clothes.
        """

        for label, kwargs in (
            ("absent", {"omit_tag": True}),
            ("floating alias", {"tag": "latest"}),
            ("unprefixed", {"tag": "0.1.9"}),
            ("branch name", {"tag": "vmain"}),
            ("partial", {"tag": "v0.1"}),
            ("leading zero", {"tag": "v0.01.9"}),
            ("a digest", {"tag": "sha256:" + "ab" * 32}),
        ):
            with self.subTest(label=label):
                self.assertIn(
                    "HelmRelease naranjo-online does not name a canonical release tag",
                    self.denials(
                        suspend=False, ready=True, digest=REVIEWED_DIGEST, **kwargs
                    ),
                )

    def test_a_half_advanced_release_identity_is_denied_on_either_half(self):
        """Tag and digest advance together or the release is refused.

        Each subtest advances exactly ONE half of the pair; the other keeps its
        fail-closed sentinel. Both directions must still be denied, so a
        promotion that renamed the release without changing the bytes — or
        changed the bytes without renaming the release — can never render as an
        acceptable active site.
        """

        for label, kwargs, expected in (
            (
                "tag advanced, digest sentinel",
                {"tag": REVIEWED_TAG},
                "HelmRelease naranjo-online still names the all-zero image digest",
            ),
            (
                "digest advanced, tag sentinel",
                {"digest": REVIEWED_DIGEST},
                "HelmRelease naranjo-online still names the sentinel release tag",
            ),
        ):
            with self.subTest(label=label):
                self.assertIn(
                    expected, self.denials(suspend=False, ready=True, **kwargs)
                )

    def test_a_non_string_leaf_is_denied_not_skipped(self):
        """The LEAF half of the same fail-open class, and the harder half.

        The container shapes below (`spec`/`values`/`image`) were closed by the
        `is_object` guards. The leaves were not, and a guarded accessor is the
        wrong instrument for them: making `site_image_digest` UNDEFINED on a
        non-string does not hand the denial to `not`, because in Rego
        `not <undefined rule>` succeeds while `not <builtin>(<undefined rule>)`
        does not — and every consumer passes the accessor to a builtin. That
        construction silently turned six DENIED digest shapes into admitted
        ones, which is a reversal wearing the shape of a fix.

        The type check therefore lives in its own arm, over a total accessor.
        Every shape below must produce its own denial; a corpus that stops at
        the container levels never reaches this rule at all.
        """

        digest = "sha256:" + "ab" * 32
        for label, value in (
            ("null", "null"),
            ("boolean", "true"),
            ("number", "5"),
            ("list", "[]"),
            ("map", "{}"),
        ):
            for field, expected in (
                ("digest", "does not state a string image digest"),
                ("tag", "does not state a string release tag"),
            ):
                other = (
                    "      tag: v1.2.3\n"
                    if field == "digest"
                    else "      digest: {}\n".format(digest)
                )
                document = textwrap.dedent(
                    """\
                    apiVersion: helm.toolkit.fluxcd.io/v2
                    kind: HelmRelease
                    metadata:
                      name: naranjo-online
                      namespace: naranjo-online
                    spec:
                      suspend: false
                      values:
                        deploymentReady: true
                        image:
                          repository: ghcr.io/snaraj/naranjo-online
                    """
                ) + other + "      {}: {}\n".format(field, value)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "release.yaml"
                    path.write_text(document, encoding="utf-8")
                    with self.subTest(field=field, shape=label):
                        # EXACTLY the type denial, not merely "a denial fired".
                        # Without the `is_string` precondition on the pattern
                        # arms the same object also trips the canonical-shape
                        # rule, because `regex.match` ERRORS on a non-string
                        # and an errored builtin under `not` fires. That is a
                        # superset — safe, but it means the refusal is riding
                        # on builtin-error semantics again, which is the exact
                        # fragility that produced this bug. Asserting the exact
                        # set keeps the two rules' responsibilities separate
                        # and makes the precondition load bearing.
                        self.assertEqual(
                            release_policy_denials(path),
                            {"HelmRelease naranjo-online " + expected},
                        )

    def test_a_well_formed_release_produces_no_leaf_type_denial(self):
        """The true negative the arms above must not cost.

        A type arm that fires on a correct release would be worse than the
        fail-open it replaced, so the accepted shape is asserted explicitly
        rather than assumed from the other rows being green.
        """

        self.assertEqual(
            self.denials(
                suspend=False,
                ready=True,
                digest=REVIEWED_DIGEST,
                tag=REVIEWED_TAG,
            ),
            set(),
        )

    def test_a_degenerate_image_mapping_is_denied_not_skipped(self):
        """Rego's nested object.get fails OPEN on a non-object receiver.

        A null, scalar, or list `image` makes the accessor raise a builtin type
        error; under OPA's default non-strict mode the enclosing deny body goes
        undefined and the rule silently does not fire. Each shape below must
        produce a denial of its own instead.
        """

        for label, block in (
            ("null image", "  values:\n    deploymentReady: true\n    image:\n"),
            ("scalar image", "  values:\n    deploymentReady: true\n    image: nope\n"),
            ("list image", "  values:\n    deploymentReady: true\n    image:\n      - a\n"),
            ("null values", "  values:\n"),
            ("scalar values", "  values: nope\n"),
        ):
            document = textwrap.dedent(
                """\
                apiVersion: helm.toolkit.fluxcd.io/v2
                kind: HelmRelease
                metadata:
                  name: naranjo-online
                  namespace: naranjo-online
                spec:
                  suspend: false
                """
            ) + block
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "release.yaml"
                path.write_text(document, encoding="utf-8")
                with self.subTest(label=label):
                    self.assertIn(
                        "HelmRelease naranjo-online does not state a "
                        "well-formed image mapping",
                        release_policy_denials(path),
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


def _rewrite_release(root, site, ready, digest, tag):
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
    # The release identity is one three-field state, so a fixture that moved
    # readiness and the digest without the tag would synthesise exactly the
    # half-advanced combination the classifier refuses.
    rewritten, tag_count = TAG_LINE.subn("      tag: {}".format(tag), rewritten)
    if (readiness_count, digest_count, tag_count) != (1, 1, 1):
        raise AssertionError(
            "release fixture for {} exposed {} readiness, {} digest and {} tag "
            "line(s); expected exactly one of each".format(
                site, readiness_count, digest_count, tag_count
            )
        )
    expected_readiness = "    deploymentReady: {}\n".format(
        "true" if ready else "false"
    )
    if (
        expected_readiness not in rewritten
        or digest not in rewritten
        or "      tag: {}\n".format(tag) not in rewritten
    ):
        raise AssertionError("release rewrite for {} did not take effect".format(site))
    path.write_text(rewritten, encoding="utf-8")


def promote(root, site=SITES[0], digest=REVIEWED_DIGEST, tag=REVIEWED_TAG):
    """Leave one site in the ``staged`` phase, whatever it started in."""

    _rewrite_release(root, site, True, digest, tag)


def demote(root, sites=SITES):
    """Leave every named site in the ``initial`` phase.

    Every state-dependent test calls this first, so the battery's verdict is
    the same before and after any promotion merges into the base branch.
    """

    for site in sites:
        _rewrite_release(root, site, False, ZERO_DIGEST, ZERO_TAG)


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

    def test_scaffold_render_that_downgrades_a_signature_policy_fails_closed(self):
        """A post-validation render mutation cannot bypass the release gate.

        The signature-policy Kustomization itself has an exact source-inventory
        guard. Mutating that input would be refused before rendering and could
        make this test pass for the wrong reason. Instead the disposable
        renderer corrupts only its already source-validated artifact, after the
        general Conftest pass and immediately before scaffold release proof.
        The exact release-policy denial below is therefore the only satisfying
        result.
        """

        root = self.checkout()
        demote(root)
        script = root / "scripts" / "render-manifests.sh"
        source = script.read_text(encoding="utf-8")
        marker = (
            "if [[ \"$MODE\" == '--scaffold' ]]; then\n"
            "  # These are negative controls, not readiness evidence. They "
            "prove the checked-in\n"
        )
        self.assertEqual(source.count(marker), 1)
        mutation = textwrap.dedent(
            """\
            mutated="${ARTIFACT_ROOT}/policies-kyverno.yaml.mutated"
            awk '
              $0 == "  name: require-signed-naranjo-online" { target = 1 }
              target && !changed && $0 == "  validationFailureAction: Enforce" {
                sub(/Enforce$/, "Audit")
                changed = 1
              }
              { print }
              END { if (changed != 1) exit 1 }
            ' "${ARTIFACT_ROOT}/policies-kyverno.yaml" >"$mutated"
            mv -- "$mutated" "${ARTIFACT_ROOT}/policies-kyverno.yaml"
            """
        )
        script.write_text(
            source.replace(marker, mutation + marker, 1), encoding="utf-8"
        )
        self.assertEqual(
            (root / "policies" / "kyverno" / "kustomization.yaml").read_text(
                encoding="utf-8"
            ),
            (REPO_ROOT / "policies" / "kyverno" / "kustomization.yaml").read_text(
                encoding="utf-8"
            ),
            "the mutation must not trip the earlier source-inventory guard",
        )
        self.assertEqual(selected_mode(root), "scaffold")
        completed = render(root, "scaffold")
        self.assertNotEqual(
            completed.returncode,
            0,
            "a rendered Audit signature policy bypassed the scaffold gate",
        )
        self.assertIn(
            "signature admission policy require-signed-naranjo-online is not enforced",
            completed.stdout + completed.stderr,
        )

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

    def test_a_render_that_strips_chart_signature_verification_fails_closed(self):
        """The chart-source counterpart of the promotion-drop case above.

        ``validate_signature_policy.py chart-source`` compares the committed
        ``source.yaml`` byte-for-byte, but it reads the FILE. A Kustomize patch
        can leave that file pristine and still emit an OCIRepository with no
        ``verify`` block, which would let Flux accept an unsigned or
        wrong-publisher chart. Only a check over the rendered artifact can see
        that, so this proves the render gate does.
        """

        root = self.checkout()
        demote(root)
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

        self.assertEqual(selected_mode(root), "scaffold")
        completed = render(root, "scaffold")
        self.assertNotEqual(
            completed.returncode,
            0,
            "a render without chart signature verification was accepted",
        )
        self.assertIn(
            "must verify chart signatures against this site's exact keyless "
            "publisher identity",
            completed.stdout + completed.stderr,
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
