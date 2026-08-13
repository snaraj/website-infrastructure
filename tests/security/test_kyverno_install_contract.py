"""Offline contracts for the staged, bound, reversible Kyverno install.

Nothing here contacts a cluster. The properties pinned are the ones that make an
admission install survivable on a one-node cluster with one operator:

* the rollout is two stages and the fail-open one cannot be skipped;
* stage 1 and stage 2 differ ONLY in policy action fields;
* every rule in every committed policy has a report-only downgrade, so adding a
  rule cannot silently ship an enforcing rule into the fail-open stage;
* neither install root registers a webhook configuration, because registration
  belongs to the controller after the ordered health wait;
* the admission namespace is excluded from its own interception, along with
  kube-system and flux-system;
* the render lock still describes the working tree;
* the sizing fits inside the namespace budget, which fits inside the node.

``InstallerGuardTests`` is the behavioural class. It builds a SYNTHETIC
repository — its own versions.env, render lock, and stubbed ``kustomize`` and
``kubectl`` on PATH, in the shape ``test_flux_install_contract`` established —
and drives the real installer through its guards in both directions. A synthetic
repository is necessary rather than convenient: in the real one the Kyverno
controller pins do not exist, so every apply path is refused at the pin guard by
design. ``RealRepositoryTests`` pins exactly that refusal.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the installer"
KUSTOMIZE = shutil.which("kustomize")

ROOT = Path(__file__).resolve().parents[2]
INSTALL_ROOT = ROOT / "kubernetes" / "platform" / "admission-install"
ENFORCE = INSTALL_ROOT / "enforce"
REPORT_ONLY = INSTALL_ROOT / "report-only"
LOCK = INSTALL_ROOT / "render.lock"
INSTALLER = ROOT / "scripts" / "install-kyverno-admission.sh"
RUNBOOK = ROOT / "docs" / "runbooks" / "kyverno-install.md"
POLICIES = ROOT / "policies" / "kyverno"
ADMISSION = ROOT / "kubernetes" / "platform" / "admission"
PREREQUISITES = ROOT / "kubernetes" / "platform" / "prerequisites"
VERSIONS = ROOT / "versions.env"

# The three namespaces whose interception would make the cluster unrecoverable:
# the control plane, the reconciler that repairs admission, and admission itself.
LOCKOUT_NAMESPACES = ("kube-system", "flux-system", "kyverno")

# The reviewed policy set. Named here rather than globbed so that deleting a
# policy is a test failure instead of a quietly smaller expectation.
CORE_POLICIES = (
    "disallow-public-services",
    "disallow-tenant-media-payloads",
    "disallow-undiscovered-storage",
    "require-approved-images",
    "require-exact-tenant-networking",
    "require-release-readiness",
    "require-replicaset-admission-identity",
    "require-restricted-workloads",
    "require-zero-site-capacity",
)
SIGNATURE_POLICIES = ("require-signed-lidersea-com", "require-signed-naranjo-online")


def read(path):
    return path.read_text(encoding="utf-8")


def write_exact(path, text):
    """Write fixture bytes with LF endings on every test host."""

    path.write_bytes(text.encode("utf-8"))


def capture(pattern, text, description):
    """Return a required capture group, failing loudly when nothing matched.

    Verification code that CRASHES on an input it cannot parse reports nothing
    useful: an ``AttributeError`` on ``None.group`` reads as a broken test
    rather than as the missing check it actually is, and a battery that errors
    where it meant to assert is a false green waiting to happen. Every parse in
    this module goes through here (or through ``first_index`` below), so an
    unreadable input surfaces as a named coverage gap instead.
    """

    match = re.search(pattern, text)
    if match is None:
        raise AssertionError(
            "{}: nothing matched {!r}; the subject's shape changed and this "
            "check silently stopped covering it".format(description, pattern)
        )
    return match.group(1)


def first_index(lines, needle, description):
    """Index of the first line containing ``needle``, or a stated failure."""

    for index, line in enumerate(lines):
        if needle in line:
            return index
    raise AssertionError(
        "{}: no recorded invocation contains {!r}".format(description, needle)
    )


def lock_value(key):
    for line in read(LOCK).splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise AssertionError("render.lock has no " + key)


def kustomize_version():
    """The ambient kustomize's own version string, or None when it is absent."""

    if KUSTOMIZE is None:
        return None
    completed = subprocess.run(
        [KUSTOMIZE, "version"], capture_output=True, text=True, check=False
    )
    return completed.stdout.strip()


def kustomize_is_pinned():
    """Whether the ambient renderer is the one versions.env pins.

    The threshold is `versions.env`, NEVER `render.lock`. Reading it from the
    lock made the gate decide whether the gate ran: editing one token of
    `render.tool.version` desynchronised the comparison, every render-dependent
    test SKIPPED, and the suite reported OK while five load-bearing checks —
    including the only killer of a silently edited render — stopped running. A
    verification gate must not read its threshold from the artifact it verifies.

    `RendererBindingTests` closes the other half: it pins lock == versions.env
    unconditionally, and turns a present-but-mismatched kustomize into a FAILURE
    rather than a skip, because a skip on mismatch is a self-disabling guard.
    """

    if KUSTOMIZE is None:
        return False
    return kustomize_version() == pinned_version("KUSTOMIZE_VERSION")


def render(stage):
    completed = subprocess.run(
        [required_tool(KUSTOMIZE, "kustomize is required"), "build", str(INSTALL_ROOT / stage)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return completed.stdout


def pinned_version(key):
    for line in read(VERSIONS).splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise AssertionError("versions.env has no " + key)


def kubectl_is_pinned():
    """Whether the ambient kubectl is the one versions.env pins.

    It usually is not: `scripts/ci/install-tools.sh` provisions the policy
    validators, not kubectl, so a CI runner uses whatever its image ships. The
    installer's tool-binding guard then refuses BEFORE the pin guard — correct
    behaviour, and the reason the real-repository refusal below is asserted
    against whichever guard is reachable rather than against one message.
    """

    kubectl = shutil.which("kubectl")
    if kubectl is None:
        return False
    completed = subprocess.run(
        [kubectl, "version", "--client", "--output=json"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r'"gitVersion":\s*"([^"]+)"', completed.stdout)
    # `is not None` rather than a truthiness test: it is the form that actually
    # narrows the Optional for a static checker, and this file must not contain
    # a single unguarded access on a match object.
    if match is None:
        return False
    return match.group(1) == pinned_version("KUBERNETES_VERSION")


KUSTOMIZE_VERSION = kustomize_version()
PINNED_RENDERER = kustomize_is_pinned()
PINNED_KUBECTL = kubectl_is_pinned()
NEEDS_RENDERER = "kustomize is not installed; render comparisons skipped"
NEEDS_KUSTOMIZE = "kustomize is not installed"

# The stage difference the runbook and the pull request body both claim, as
# numbers. Asserting only that each differing line is one of these three fields
# is blind to a field that STOPS differing — a stage-1 rule silently flipped to
# the enforcing value disappears from the difference list instead of failing it.
# The counts are what make a disappearance loud.
STAGE_DIFFERENCE_COUNTS = {
    "failureAction": 33,
    "failurePolicy": 11,
    "validationFailureAction": 11,
}

# The reviewed rule inventory: every rule name each committed policy declares,
# in declaration order.
#
# Two mechanisms make this load-bearing rather than decorative. (1) `kyverno
# test` reports a row referencing a VANISHED rule as Pass/Excluded — including
# rows whose declared result is `fail` — so renaming a rule out of existence
# leaves a fully green policy suite while the rule stops running. Only a
# structural pin binding names to a reviewed list catches it. (2) The
# report-only downgrade ops address rules by POSITION, and a position is not an
# identity: this list is what the ops' own `test` bindings are checked against,
# so an inserted or reordered rule is a named failure here as well as a render
# failure there.
#
# Base-coupled by construction: it describes the committed policy set, so a pull
# request that adds, renames, or reorders a rule updates it, and that update is
# the review of the stage-1 semantics the change implies.
REVIEWED_RULE_NAMES = {
    "disallow-public-services": (
        "disallow-public-service",
        "disallow-ingress",
        "disallow-gateway-api",
    ),
    "disallow-tenant-media-payloads": (
        "reject-configmap-binary-data",
        "bound-configmap-control-data",
        "bound-secret-control-data",
    ),
    "disallow-undiscovered-storage": (
        "disallow-persistent-storage-resources",
        "disallow-stateful-claim-templates",
        "allow-only-site-scratch-volumes",
        "allow-only-tunnel-token-volume",
        "allow-only-own-instance-token-env",
        "disallow-legacy-service-account-token-secrets",
        "disallow-disk-pressure-toleration",
        "disallow-wildcard-toleration",
    ),
    "require-approved-images": (
        "require-approved-digest",
        "require-canonical-naranjo-image",
        "require-canonical-lidersea-image",
        "require-canonical-cloudflared-image",
    ),
    "require-exact-tenant-networking": (
        "exact-default-deny",
        "exact-site-ingress-and-no-egress",
        "exact-tunnel-cross-namespace-egress",
    ),
    "require-release-readiness": (
        "require-connector-identity-tuple",
        "require-replicaset-owned-by-exact-deployment",
        "require-site-deployment-readiness",
        "require-tunnel-token-revision",
    ),
    "require-replicaset-admission-identity": (
        "require-replicaset-controller-and-live-owner-uid",
    ),
    "require-restricted-workloads": (
        "require-restricted-tenant-namespace",
        "require-restricted-pod",
        "require-secure-containers",
        "disallow-host-ports",
        "require-approved-service-account",
        "require-container-resources",
    ),
    "require-signed-lidersea-com": (
        "verify-lidersea-com-signature",
        "verify-lidersea-com-provenance",
    ),
    "require-signed-naranjo-online": (
        "verify-naranjo-online-signature",
        "verify-naranjo-online-provenance",
    ),
    "require-zero-site-capacity": ("require-capacity-not-ready-quota",),
}


def rule_names(policy):
    """The rule names a committed policy declares, in declaration order."""

    return re.findall(r"(?m)^    - name: (\S+)$", read(POLICIES / (policy + ".yaml")))


# The kinds whose objects live OUTSIDE a namespace, reviewed here as a literal
# so the row set of the scope regression cannot silently shrink with the
# artifact it tests: a check whose inputs are derived from the file under test
# disables itself the moment that file is edited.
REVIEWED_CLUSTER_SCOPED_KINDS = (
    "CustomResourceDefinition",
    "ClusterRole",
    "ClusterRoleBinding",
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
    "ClusterPolicy",
    "PriorityClass",
    "Namespace",
)
# Of those, the two no install phase ever applies: webhook registration is the
# controller's act, so no attempt of this installer can have journaled one.
NEVER_JOURNALED_KINDS = (
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
)

# The install phase table, and the scope of every kind in it.
#
# These two lists are a PARTITION, and the partition is the thing that has to be
# pinned. The installer derives "is this journal entry cluster-scoped?" from
# `CLUSTER_SCOPED_KINDS` and "could this install have journaled it?" from the
# phase table. Adding a genuinely cluster-scoped kind to a phase WITHOUT adding
# it to the cluster-scoped list makes the installer treat it as namespaced: the
# journal accepts it with `namespace: kyverno`, the rollback issues
# `kubectl -n kyverno delete <Kind> <name>`, kubectl ignores `--namespace` for a
# root-scoped object, and the delete goes out cluster-wide — P0-1 reopened for
# that one kind, while the run prints "at the scope its kind declares".
#
# Nothing in the installer can catch that: both halves would be internally
# consistent. Only a reviewed partition can, and the phase table is exactly what
# the component-export promotion will edit, so this is a live trap rather than a
# hypothetical.
REVIEWED_PHASE_KINDS = {
    "namespace": ("Namespace",),
    "bounds": ("ResourceQuota", "LimitRange"),
    "network": ("NetworkPolicy",),
    "crds": ("CustomResourceDefinition",),
    "controller-prerequisites": (
        "ConfigMap",
        "ServiceAccount",
        "ClusterRole",
        "ClusterRoleBinding",
        "Role",
        "RoleBinding",
        "Service",
        "PodDisruptionBudget",
        "PriorityClass",
    ),
    "controller": ("Deployment",),
    "policies": ("ClusterPolicy", "Policy"),
}
# Every kind above that Kubernetes scopes INSIDE a namespace. The complement of
# REVIEWED_CLUSTER_SCOPED_KINDS over the phase table, stated rather than derived
# so that adding a kind to the phase table fails until someone declares which
# side of the partition it is on.
REVIEWED_NAMESPACED_KINDS = (
    "ResourceQuota",
    "LimitRange",
    "NetworkPolicy",
    "ConfigMap",
    "ServiceAccount",
    "Role",
    "RoleBinding",
    "Service",
    "Deployment",
    "PodDisruptionBudget",
    "Policy",
)


class ParseGuardTests(unittest.TestCase):
    """The parse helpers report a coverage gap; they never crash into one.

    This module reads its subjects — the installer, the overlays, the recorded
    kubectl invocations — by pattern. A pattern that stops matching because the
    subject changed shape means the check it fed has silently stopped covering
    anything, which is the most valuable failure this battery can produce and
    the easiest one to lose to an AttributeError on None.
    """

    def test_an_unmatched_pattern_fails_as_a_named_gap(self):
        with self.assertRaises(AssertionError) as raised:
            capture(r"(nothing-like-this)", "some other text", "the subject")
        self.assertIn("the subject", str(raised.exception))
        self.assertIn("silently stopped covering it", str(raised.exception))

    def test_a_missing_invocation_fails_as_a_named_gap(self):
        with self.assertRaises(AssertionError) as raised:
            first_index(["apply -f one", "apply -f two"], "delete", "the probe")
        self.assertIn("the probe", str(raised.exception))
        self.assertIn("no recorded invocation", str(raised.exception))

    def test_a_matching_pattern_returns_its_capture(self):
        # Vacuity floor: a helper that always raised would make every caller
        # above red, but a helper that returned the wrong group would be silent.
        self.assertEqual(capture(r"phase-(\w+)\.yaml", "apply -f phase-network.yaml", "x"), "network")
        self.assertEqual(first_index(["a", "b", "c"], "c", "x"), 2)


class RendererBindingTests(unittest.TestCase):
    """The renderer identity is pinned INDEPENDENTLY of the file it gates.

    ``render.lock`` records which kustomize produced its digests, and the whole
    render-dependent half of this battery only runs when the ambient renderer
    matches. Deriving "matches" from the lock let the lock decide whether the
    lock was checked: one token edited inside it and five load-bearing tests
    skipped while the suite printed OK. The pin is `versions.env`, which those
    tests do not verify and a render change has no reason to touch.
    """

    def test_the_lock_records_the_independently_pinned_renderer(self):
        # No skip: this must be true on every machine, with or without
        # kustomize installed, because it is a statement about two committed
        # files and nothing else.
        self.assertEqual(lock_value("render.tool.name"), "kustomize")
        self.assertEqual(
            lock_value("render.tool.version"),
            pinned_version("KUSTOMIZE_VERSION"),
            "render.lock must record the renderer versions.env pins; a lock that "
            "names a different one silently disables every render comparison",
        )

    @unittest.skipIf(KUSTOMIZE is None, NEEDS_KUSTOMIZE)
    def test_an_installed_kustomize_must_be_the_pinned_one(self):
        # FAIL, not skip. A machine that has kustomize but the wrong one used to
        # skip five checks and report OK; now the mismatch is the finding.
        self.assertEqual(
            KUSTOMIZE_VERSION,
            pinned_version("KUSTOMIZE_VERSION"),
            "this machine renders with a kustomize versions.env does not pin; "
            "the render comparisons cannot be trusted and are not skipped away",
        )


class StagedRolloutTests(unittest.TestCase):
    """Stage 1 is fail-open, stage 2 is the committed bytes, and stage 1 is a
    strict base of stage 2 rather than a parallel copy of it."""

    def test_report_only_is_an_overlay_of_enforce(self):
        # If the stages were siblings they could drift into two different
        # controllers, two different networks, or two different bounds. Making
        # stage 1 an overlay of stage 2 makes that structurally impossible.
        index = read(REPORT_ONLY / "kustomization.yaml")
        self.assertRegex(index, r"(?m)^resources:\s*\n\s+-\s+\.\./enforce\s*$")

    def test_enforce_composes_the_flux_admission_root(self):
        # The operator must apply the same bytes Flux will later reconcile.
        index = read(ENFORCE / "kustomization.yaml")
        self.assertRegex(index, r"(?m)^\s+-\s+\.\./\.\./admission\s*$")

    def test_every_committed_rule_has_a_report_only_downgrade(self):
        """The regression this exists for: a rule added to a committed policy
        without a matching downgrade op still ENFORCES during the fail-open
        stage, which is exactly the state stage 1 exists to make impossible.

        Counting ops was not enough, and #87 proved it. A downgrade op names a
        rule by POSITION, and #87 inserted a rule at index 0 of
        require-release-readiness: the three existing ops kept applying, to
        three DIFFERENT rules, and the fourth rule reached the fail-open stage
        carrying `failureAction: Enforce`. Both changes were correct alone and
        the merge was textually clean.

        So the assertion is by NAME in both directions: every op is preceded by
        a `test` op binding its index to the rule name it was written for, and
        the ordered list of bound names must equal the policy's declared rule
        names exactly — same names, same order, same COUNT. A rule added by
        anyone breaks here, loudly, instead of shipping enforcing.
        """

        for name in CORE_POLICIES:
            policy = read(POLICIES / (name + ".yaml"))
            declared = rule_names(name)
            enforcing = re.findall(r"(?m)^        failureAction: \S+$", policy)
            patch = read(REPORT_ONLY / "patches" / ("audit-" + name + ".yaml"))
            bound = re.findall(
                r"(?m)^- op: test\n  path: /spec/rules/(\d+)/name\n  value: (\S+)$",
                patch,
            )
            indices = re.findall(
                r"(?m)^  path: /spec/rules/(\d+)/validate/failureAction$", patch
            )
            actions = re.findall(r"(?m)^  value: (\S+)$", patch)
            with self.subTest(policy=name):
                self.assertEqual(
                    len(enforcing),
                    len(declared),
                    "every rule in a core policy declares its own failureAction",
                )
                self.assertEqual(
                    [bound_name for _, bound_name in bound],
                    declared,
                    "every downgrade op is bound to the rule NAME it was "
                    "written for, and the bound names are the policy's rules "
                    "in order — a rule added, renamed or reordered fails here",
                )
                self.assertEqual(
                    [index for index, _ in bound],
                    indices,
                    "each name binding sits at the index its replace op patches",
                )
                self.assertEqual(
                    indices,
                    [str(index) for index in range(len(declared))],
                    "one downgrade op per rule, at consecutive indices",
                )
                self.assertEqual(
                    set(actions),
                    {"Audit", *declared},
                    "the only values in the patch are the bound rule names and Audit",
                )

    def test_every_reviewed_policy_declares_the_reviewed_rules(self):
        """Renaming a rule out of existence is invisible to `kyverno test`.

        Every Test row referencing a vanished rule reports Pass/Excluded —
        INCLUDING rows whose declared result is `fail` — so a one-word rename
        leaves the whole policy suite green while the rule stops running at
        admission. Nothing in a policy test can catch it; only binding the
        declared names to a reviewed list can, and that list has to cover all
        ten policies rather than the ones a sibling change happened to touch.
        """

        self.assertEqual(
            sorted(REVIEWED_RULE_NAMES),
            sorted(CORE_POLICIES + SIGNATURE_POLICIES),
            "the reviewed rule inventory covers every reviewed policy",
        )
        for name in CORE_POLICIES + SIGNATURE_POLICIES:
            with self.subTest(policy=name):
                self.assertEqual(
                    rule_names(name),
                    list(REVIEWED_RULE_NAMES[name]),
                    "the policy's declared rule names are the reviewed ones, "
                    "in order; a rename or a reorder is a coverage change",
                )

    def test_no_reviewed_policy_stops_after_the_first_matching_rule(self):
        """`spec.applyRules: One` is the third one-word neutering axis.

        Kyverno stops processing a policy after the FIRST rule that matches and
        produces a result, so one line on the seven-rule storage policy leaves
        six rules never evaluated at admission — with `kyverno test` green, the
        structural battery green, and `make check-fast` green, because a rule
        that never runs produces no failed row. `admission: true` and the
        userInfo narrowing are pinned above; this is the axis they left open,
        and it is pinned across all ten policies rather than the two a sibling
        change already covers.

        Absent is the default (`All`), so absent-or-exactly-`All` is the
        contract: pinning only the value would miss the field being ADDED to a
        policy that does not carry the line today.
        """

        for name in CORE_POLICIES + SIGNATURE_POLICIES:
            policy = read(POLICIES / (name + ".yaml"))
            declared = re.findall(r"(?m)^  applyRules:\s*(\S+)\s*$", policy)
            with self.subTest(policy=name):
                self.assertNotRegex(
                    policy,
                    r"(?m)^\s+applyRules:\s*One\s*$",
                    "applyRules: One stops every rule after the first that "
                    "matches; the reviewed policies evaluate every rule",
                )
                self.assertIn(
                    declared,
                    ([], ["All"]),
                    "applyRules is absent (the All default) or exactly All",
                )

    def test_every_reviewed_policy_actually_runs_at_admission(self):
        """`spec.admission: false` is one word per policy and stops every rule
        in it from running at admission at all — background scan only.

        A policy can be `validationFailureAction: Enforce`, carry
        `failurePolicy: Fail`, and still never be consulted by the webhook. So
        "the policy is enforcing" is not a claim any action field can support on
        its own, and this is the half that is cheapest to lose silently.
        """

        for name in CORE_POLICIES + SIGNATURE_POLICIES:
            with self.subTest(policy=name):
                self.assertRegex(
                    read(POLICIES / (name + ".yaml")), r"(?m)^  admission: true\s*$"
                )

    def test_no_reviewed_policy_narrows_by_user_identity(self):
        """The userInfo `MatchResources` fields narrow a rule to principals
        bound to a named role. `clusterRoles: [no-such-cluster-role]` matches
        NOBODY while every policy test still reports a pass, because rows that
        fall outside a match are reported Pass/Skip/Excluded rather than failed.
        None of the reviewed policies has any reason to select by identity."""

        for name in CORE_POLICIES + SIGNATURE_POLICIES:
            policy = read(POLICIES / (name + ".yaml"))
            for field in ("clusterRoles", "subjects", "roles"):
                with self.subTest(policy=name, field=field):
                    self.assertNotRegex(policy, r"(?m)^\s+" + field + r":")

    def test_the_signature_policies_need_no_rule_downgrade(self):
        # A vacuity guard on the test above: these two carry verifyImages rules
        # with no validate block, so an "every policy has a patch file" rule
        # would be asserting a file that must not exist.
        for name in SIGNATURE_POLICIES:
            policy = read(POLICIES / (name + ".yaml"))
            with self.subTest(policy=name):
                self.assertIn(
                    "  validationFailureAction: Enforce",
                    policy.splitlines(),
                    "stage 2 must reject an unsigned or wrong-identity image; "
                    "the report-only overlay performs the only Audit downgrade",
                )
                self.assertNotIn("failureAction:", policy)
                self.assertFalse(
                    (REPORT_ONLY / "patches" / ("audit-" + name + ".yaml")).exists()
                )

    def test_the_spec_level_downgrade_covers_every_policy_by_kind(self):
        index = read(REPORT_ONLY / "kustomization.yaml")
        self.assertIn("path: /spec/validationFailureAction", index)
        self.assertIn("path: /spec/webhookConfiguration/failurePolicy", index)
        self.assertIn("value: Ignore", index)

    @unittest.skipUnless(PINNED_RENDERER, NEEDS_RENDERER)
    def test_the_two_stages_differ_only_in_action_fields(self):
        """The blast-radius claim in the runbook, made checkable: promoting from
        stage 1 to stage 2 must not also change the controller, the network, the
        bounds, or the policy logic."""

        enforce = render("enforce").splitlines()
        report_only = render("report-only").splitlines()
        self.assertEqual(len(enforce), len(report_only))
        differences = [
            (left.strip(), right.strip())
            for left, right in zip(enforce, report_only)
            if left != right
        ]
        self.assertTrue(differences, "the stages must not be identical")
        for left, right in differences:
            with self.subTest(line=left):
                self.assertIn(
                    left.split(":", 1)[0],
                    {"failureAction", "validationFailureAction", "failurePolicy"},
                )
                self.assertIn(right.split(":", 1)[1].strip(), {"Audit", "Ignore"})
        # A field that STOPS differing is invisible to the loop above: a stage-1
        # rule flipped to the enforcing value simply leaves the difference list.
        # The counts are what make that disappearance a failure, and they are the
        # same three numbers the pull request body and the runbook state.
        counted = {}
        for left, _ in differences:
            field = left.split(":", 1)[0]
            counted[field] = counted.get(field, 0) + 1
        self.assertEqual(
            counted,
            STAGE_DIFFERENCE_COUNTS,
            "the two stages differ in a different NUMBER of action fields than "
            "reviewed; a field that stopped differing is a stage-1 rule that no "
            "longer downgrades",
        )

    @unittest.skipUnless(PINNED_RENDERER, NEEDS_RENDERER)
    def test_neither_stage_can_be_mistaken_for_the_other(self):
        enforce = render("enforce")
        report_only = render("report-only")
        self.assertNotIn("failurePolicy: Ignore", enforce)
        self.assertIn("failurePolicy: Fail", enforce)
        self.assertNotIn("failurePolicy: Fail", report_only)
        self.assertIn("failurePolicy: Ignore", report_only)
        self.assertNotIn("failureAction: Enforce", report_only)
        self.assertIn("failureAction: Enforce", enforce)


class WebhookRegistrationTests(unittest.TestCase):
    """Registration is the controller's act, after the health wait. Neither
    install root may hand the API server a webhook nobody proved answers."""

    @unittest.skipUnless(PINNED_RENDERER, NEEDS_RENDERER)
    def test_no_install_stage_declares_a_webhook_configuration(self):
        for stage in ("report-only", "enforce"):
            with self.subTest(stage=stage):
                self.assertNotIn("kind: ValidatingWebhookConfiguration", render(stage))
                self.assertNotIn("kind: MutatingWebhookConfiguration", render(stage))

    def test_the_flux_admission_root_still_carries_the_staging_sentinel(self):
        # Vacuity guard: the removal patch must be removing something. If the
        # committed sentinel ever stops declaring a webhook, the patch becomes a
        # no-op and the assertion above would pass for the wrong reason.
        controllers = read(ADMISSION / "kyverno" / "controllers.yaml")
        self.assertIn("kind: ValidatingWebhookConfiguration", controllers)
        self.assertIn("failurePolicy: Fail", controllers)

    def test_the_removal_is_scoped_to_the_install_root(self):
        index = read(ENFORCE / "kustomization.yaml")
        self.assertIn("$patch: delete", index)
        self.assertIn("kyverno-resource-validating-webhook-cfg", index)

    def test_the_installer_refuses_a_render_that_declares_one(self):
        installer = read(INSTALLER)
        self.assertIn(
            "FORBIDDEN_KINDS='ValidatingWebhookConfiguration|MutatingWebhookConfiguration'",
            installer,
        )
        self.assertIn("webhook registration is the controller's act", installer)

    def test_the_sentinel_selector_defect_is_recorded_where_it_was_found(self):
        # The finding this transaction had to resolve: an `In` list of namespace
        # NAMES is fail-open for any namespace created later. The corrected
        # semantics live in the engine configuration as a NotIn exclusion.
        sentinel = read(ADMISSION / "kyverno" / "controllers.yaml")
        self.assertIn("operator: In", sentinel)
        config = read(ENFORCE / "config.yaml")
        self.assertIn('"operator":"NotIn"', config)
        self.assertNotIn('"operator":"In"', config)


class EngineConfigurationTests(unittest.TestCase):
    """The exclusions that stop an admission controller from locking out its own
    cluster, proven in the bytes rather than trusted from a comment."""

    def setUp(self):
        self.text = read(ENFORCE / "config.yaml")

    def test_the_engine_filters_every_lockout_namespace(self):
        for namespace in LOCKOUT_NAMESPACES:
            with self.subTest(namespace=namespace):
                self.assertIn("[*/*,{},*]".format(namespace), self.text)

    def test_the_webhook_selector_excludes_every_lockout_namespace(self):
        parsed = json.loads(
            capture(
                r"(?m)^  webhooks: '(.*)'$",
                self.text,
                "the webhooks key must be a quoted JSON object",
            )
        )
        expressions = parsed["namespaceSelector"]["matchExpressions"]
        self.assertEqual(len(expressions), 1)
        expression = expressions[0]
        self.assertEqual(expression["key"], "kubernetes.io/metadata.name")
        self.assertEqual(
            expression["operator"],
            "NotIn",
            "an inclusion list is fail-open for every namespace created later",
        )
        self.assertEqual(sorted(expression["values"]), sorted(LOCKOUT_NAMESPACES))

    def test_the_kubelet_identity_is_excluded(self):
        # Without this, a webhook outage becomes a node outage: every static Pod
        # and kubelet-initiated write is judged by policies written for tenants.
        self.assertIn("excludeGroups: system:nodes", self.text)

    def test_registry_mutation_stays_off(self):
        # The image policies match fully qualified digests; silently rewriting a
        # short reference would let a name pass a check written for a digest.
        self.assertIn('enableDefaultRegistryMutation: "false"', self.text)

    def test_replicasets_reach_the_admission_identity_rule(self):
        self.assertNotIn("[ReplicaSet,*,*]", self.text)
        self.assertNotIn("[ReplicaSet/?*,*,*]", self.text)


class NamespaceTwinTests(unittest.TestCase):
    """The operator-applied namespace and the one Flux will adopt are one
    desired state, not two."""

    @staticmethod
    def _kyverno_document(text):
        for document in re.split(r"(?m)^---\s*$", text):
            if re.search(r"(?m)^  name: kyverno\s*$", document):
                return document
        raise AssertionError("no kyverno Namespace document")

    def test_the_install_namespace_matches_the_reconciled_one(self):
        install = self._kyverno_document(read(ENFORCE / "namespace.yaml"))
        reconciled = self._kyverno_document(read(PREREQUISITES / "namespaces.yaml"))
        normalise = lambda text: sorted(  # noqa: E731 - a local shape, not an API
            line.rstrip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
        self.assertEqual(normalise(install), normalise(reconciled))

    def test_restricted_pod_security_is_enforced_not_merely_warned(self):
        install = read(ENFORCE / "namespace.yaml")
        for mode in ("enforce", "audit", "warn"):
            with self.subTest(mode=mode):
                self.assertIn(
                    "pod-security.kubernetes.io/{}: restricted".format(mode), install
                )


class OrderingContractTests(unittest.TestCase):
    """The ordering defect #85 hit, and the one this repository already carries:
    a namespace closed before its allows exist can never become healthy."""

    def setUp(self):
        self.installer = read(INSTALLER)

    def test_the_phase_order_puts_network_before_the_controller(self):
        ordered = capture(
            r"(?m)^PHASE_NAMES=\((.*)\)$", self.installer, "the installer's phase order"
        ).split()
        self.assertEqual(
            ordered,
            [
                "namespace",
                "bounds",
                "network",
                "crds",
                "controller-prerequisites",
                "controller",
                "policies",
            ],
        )

    def test_there_is_no_webhook_phase(self):
        ordered = capture(
            r"(?m)^PHASE_NAMES=\((.*)\)$", self.installer, "the installer's phase order"
        ).split()
        self.assertNotIn("webhooks", ordered)

    def test_the_health_wait_happens_after_the_controller_phase(self):
        controller = self.installer.index("if [[ \"$phase\" == 'controller' ]]")
        wait = self.installer.index("--for=condition=Available deployment", controller)
        policies = self.installer.index("applied phases", wait)
        self.assertLess(controller, wait)
        self.assertLess(wait, policies)

    def test_the_deny_and_its_allows_are_one_document(self):
        # The whole reason the closure is safe: kustomize emits them into the
        # same phase file, so there is no window in which the namespace is
        # closed and unreachable.
        policies = read(ENFORCE / "network-policies.yaml")
        self.assertIn("name: default-deny", policies)
        for name in (
            "kyverno-admission-webhook",
            "kyverno-dns",
            "kyverno-kube-apiserver",
            "kyverno-public-https",
        ):
            with self.subTest(policy=name):
                self.assertIn("name: " + name, policies)

    def test_the_reconciled_default_deny_still_has_no_allows_of_its_own(self):
        """Vacuity guard AND a live finding: kubernetes/platform/prerequisites
        declares a bare default-deny for kyverno and the admission Kustomization
        dependsOn it with wait:true. Reconciled without these allows on the
        cluster, the controller can never become Available. If prerequisites
        ever grows its own allows, this ordering argument must be re-derived."""

        reconciled = read(PREREQUISITES / "network-policies.yaml")
        kyverno_policies = [
            document
            for document in re.split(r"(?m)^---\s*$", reconciled)
            if re.search(r"(?m)^  namespace: kyverno\s*$", document)
        ]
        self.assertEqual(len(kyverno_policies), 1)
        self.assertIn("name: default-deny", kyverno_policies[0])

    def test_the_committed_destination_is_the_fail_closed_sentinel(self):
        # RFC 5737 TEST-NET-1: applied as committed, these policies grant
        # nothing. The count is over real destinations, not the prose that
        # explains them, and it must equal what the installer substitutes.
        destinations = re.findall(
            r"(?m)^\s+cidr:\s+(\S+)\s*$", read(ENFORCE / "network-policies.yaml")
        )
        self.assertEqual(destinations.count("192.0.2.10/32"), 1)
        self.assertEqual(destinations.count("192.0.2.20/32"), 1)
        self.assertIn("WEBHOOK_SOURCE_SENTINEL_CIDR='192.0.2.10/32'", self.installer)
        self.assertIn("RUNTIME_API_SENTINEL_CIDR='192.0.2.20/32'", self.installer)


class AdmissionNetworkShapeTests(unittest.TestCase):
    """The reviewed admission flows, pinned HERE and not only in the rego.

    `policies/conftest/kubernetes.rego` denies a widened admission NetworkPolicy,
    and the deny fixture proves the denial fires. But the rego is the thing doing
    the denying, so a change that widens a rego arm AND the real manifest
    together passes conftest by construction — the reviewer reproduced exactly
    that, opening the public-HTTPS egress to all of 172.16.0.0/12 with every
    gate green. A policy layer cannot be the sole guard of the bytes it judges.

    These assertions read the committed manifest directly. They stay red under
    that composed change no matter what the rego says, which is what makes the
    rego's kills unconditional rather than conditional on the rego being intact.
    """

    # The private, loopback, link-local, CGNAT, multicast, and reserved blocks
    # the public-HTTPS egress excludes. Every entry removed is a LAN, node, or
    # neighbouring-namespace destination granted to a rule whose only reason to
    # exist is Sigstore and GHCR.
    EXCLUDED_RANGES = [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]

    def setUp(self):
        self.documents = {}
        for document in re.split(
            r"(?m)^---\s*$", read(ENFORCE / "network-policies.yaml")
        ):
            match = re.search(r"(?m)^  name: (\S+)\s*$", document)
            if match is not None:
                self.documents[match.group(1)] = document

    def _document(self, name):
        self.assertIn(name, self.documents, "the reviewed network contract lost " + name)
        return self.documents[name]

    @staticmethod
    def _values(document, field):
        # `- port: 443` and `  protocol: TCP` are both list-item bodies, so the
        # sequence dash is optional rather than absent.
        return re.findall(r"(?m)^\s+(?:- )?" + field + r":\s+(\S+)\s*$", document)

    def test_the_reviewed_flows_are_exactly_these_five(self):
        self.assertEqual(
            sorted(self.documents),
            [
                "default-deny",
                "kyverno-admission-webhook",
                "kyverno-dns",
                "kyverno-kube-apiserver",
                "kyverno-public-https",
            ],
        )

    def test_the_default_deny_isolates_both_directions(self):
        # Ingress-only isolation leaves egress unrestricted for every Pod in the
        # namespace and makes the four allows below decorative.
        document = self._document("default-deny")
        self.assertIn("podSelector: {}", document)
        self.assertEqual(
            re.findall(r"(?m)^\s+- (Ingress|Egress)\s*$", document),
            ["Ingress", "Egress"],
        )

    def test_the_webhook_ingress_is_one_host_on_one_port(self):
        document = self._document("kyverno-admission-webhook")
        self.assertEqual(self._values(document, "cidr"), ["192.0.2.10/32"])
        self.assertNotIn("except:", document)
        self.assertEqual(self._values(document, "port"), ["9443"])
        self.assertEqual(self._values(document, "protocol"), ["TCP"])

    def test_the_runtime_api_egress_is_a_separate_fail_closed_shape(self):
        document = self._document("kyverno-kube-apiserver")
        self.assertEqual(self._values(document, "cidr"), ["192.0.2.20/32"])
        self.assertNotIn("except:", document)
        self.assertEqual(self._values(document, "port"), ["65535"])
        self.assertEqual(self._values(document, "protocol"), ["TCP"])

    def test_the_public_https_egress_excludes_every_reviewed_range(self):
        document = self._document("kyverno-public-https")
        cidrs = self._values(document, "cidr")
        self.assertEqual(cidrs, ["0.0.0.0/0"])
        excluded = re.findall(r"(?m)^\s+- (\d\S+/\d+)\s*$", document)
        self.assertEqual(
            excluded,
            self.EXCLUDED_RANGES,
            "a shorter exclusion list is a wider allow: every entry removed is a "
            "LAN or node destination granted",
        )
        self.assertEqual(self._values(document, "port"), ["443"])
        self.assertEqual(self._values(document, "protocol"), ["TCP"])

    def test_the_dns_egress_is_the_cluster_resolver_only(self):
        document = self._document("kyverno-dns")
        self.assertIn("kubernetes.io/metadata.name: kube-system", document)
        self.assertIn("k8s-app: kube-dns", document)
        self.assertNotIn("cidr:", document)
        self.assertEqual(self._values(document, "port"), ["53", "53"])
        self.assertEqual(self._values(document, "protocol"), ["TCP", "UDP"])


class ResourceBoundsTests(unittest.TestCase):
    """Admission is bounded by the API server, not by a comment."""

    def setUp(self):
        self.bounds = read(ENFORCE / "resource-controls.yaml")
        self.patch = read(ENFORCE / "patches" / "controller-runtime.yaml")

    def test_the_namespace_budget_is_a_hard_quota(self):
        for entry in (
            'pods: "4"',
            "requests.cpu: 400m",
            "requests.memory: 768Mi",
            'limits.cpu: "2"',
            "limits.memory: 1536Mi",
            # The Secret bound was written down and left unpinned: a regenerated
            # lock could raise it without a single test noticing, which is
            # exactly the "certificate rotation defect becomes unbounded etcd
            # growth" case the file's own comment says it exists to stop.
            'secrets: "8"',
        ):
            with self.subTest(entry=entry):
                self.assertIn(entry, self.bounds)

    def test_the_limit_range_defaults_stay_inside_the_namespace_budget(self):
        """The LimitRange is what an unresourced container inherits, so its
        ceiling is a real allocation, not documentation.

        Unpinned, a promotion pull request could set the default limit to the
        whole namespace budget — contradicting the file's own comment that the
        defaults MATCH the patched controller values — and every gate would stay
        green. Both halves are pinned, and pinned to the SAME numbers the
        controller patch carries, so the two cannot drift apart silently.
        """

        limits = capture(
            r"(?ms)^\s+- default:\s*\n(.*?)\n\s+type: Container\s*$",
            self.bounds,
            "the container-defaults LimitRange",
        )
        self.assertEqual(
            [line.strip() for line in limits.splitlines() if line.strip()],
            [
                "cpu: 500m",
                "memory: 384Mi",
                "defaultRequest:",
                "cpu: 100m",
                "memory: 192Mi",
            ],
            "the LimitRange defaults must equal the patched controller values",
        )

    def test_the_patched_requests_fit_the_quota_twice_over(self):
        # Two controllers at these requests, plus the same again as rolling
        # surge, is exactly the quota. A patch that raised either value without
        # raising the quota would make a rolling update unschedulable.
        self.assertIn("cpu: 100m", self.patch)
        self.assertIn("memory: 192Mi", self.patch)
        self.assertIn("cpu: 500m", self.patch)
        self.assertIn("memory: 384Mi", self.patch)
        self.assertIn("requests.cpu: 400m", self.bounds)
        self.assertIn("requests.memory: 768Mi", self.bounds)

    def test_replica_count_is_not_forced_by_the_runtime_patch(self):
        self.assertNotIn("path: /spec/replicas", self.patch)
        self.assertIn("capacity/availability decision", self.patch)

    def test_admission_outranks_the_workloads_it_protects(self):
        # An evicted admission controller with an enforcing webhook registered
        # turns every matching write into a failure, so it must not be the first
        # thing the kubelet kills. Consumption is bounded by the quota instead.
        self.assertIn("value: system-cluster-critical", self.patch)


class RenderLockTests(unittest.TestCase):
    """The lock is the installer's expectation; a stale one is a gate that
    stopped describing the thing it gates."""

    def test_the_installer_classifies_scope_by_kind_and_only_by_kind(self):
        """Scope must be a property of the KIND, never of the journal's
        namespace field.

        `kubectl` IGNORES `--namespace` for a root-scoped resource — `kubectl -n
        kyverno delete ClusterRole cluster-admin` issues the CLUSTER-SCOPED
        request and returns 0 — so a validator that reads "this line has a
        namespace, therefore it is bounded to the install namespace" accepts a
        cluster-scoped kind carrying a namespace and then deletes it
        cluster-wide. This pins the reviewed kind list the derivation uses, as a
        literal: a check whose own input list is read out of the file under test
        shrinks silently when that file is edited.
        """

        installer = read(INSTALLER)
        declared = capture(
            r"(?m)^CLUSTER_SCOPED_KINDS='([^']+)'$",
            installer,
            "the installer's cluster-scoped kind list",
        ).split("|")
        self.assertEqual(
            declared,
            list(REVIEWED_CLUSTER_SCOPED_KINDS),
            "the reviewed cluster-scoped kinds and the installer's own list "
            "have diverged; the scope regression rows would stop covering the "
            "difference",
        )
        # Both the validator and the delete must dispatch on that list, or they
        # can disagree — and kubectl resolves a disagreement in the dangerous
        # direction.
        self.assertEqual(
            len(
                re.findall(
                    r'\[\[ "\$kind" =~ \^\(\$\{CLUSTER_SCOPED_KINDS\}\)\$ \]\]', installer
                )
            ),
            3,
            "the journal writer, the journal validator and the rollback delete "
            "all derive scope from the same kind list",
        )

    def test_every_phase_kind_declares_which_side_of_the_scope_split_it_is_on(self):
        """The partition between the phase table and the cluster-scoped list.

        Both halves can be internally consistent and still wrong together: a
        cluster-scoped kind added to a phase but not to `CLUSTER_SCOPED_KINDS`
        is journaled as namespaced, accepted with `namespace: kyverno`, and then
        deleted CLUSTER-WIDE, because kubectl ignores `--namespace` for a
        root-scoped object. Nothing inside the installer can detect that, so the
        partition is pinned here — and the phase table is precisely what the
        component-export promotion will edit.
        """

        installer = read(INSTALLER)
        block = capture(
            r"(?s)declare -A PHASE_KINDS=\(\n(.*?)\n\)", installer, "the phase table"
        )
        declared = {
            phase: tuple(kinds.split("|"))
            for phase, kinds in re.findall(r"\[([a-z0-9-]+)\]='([^']+)'", block)
        }
        self.assertEqual(
            declared,
            REVIEWED_PHASE_KINDS,
            "the installer's phase table and the reviewed one have diverged",
        )
        cluster_scoped = set(REVIEWED_CLUSTER_SCOPED_KINDS)
        namespaced = set(REVIEWED_NAMESPACED_KINDS)
        self.assertEqual(
            cluster_scoped & namespaced,
            set(),
            "a kind cannot be both cluster-scoped and namespaced",
        )
        for phase, kinds in REVIEWED_PHASE_KINDS.items():
            for kind in kinds:
                with self.subTest(phase=phase, kind=kind):
                    self.assertEqual(
                        (kind in cluster_scoped) ^ (kind in namespaced),
                        True,
                        "every kind an install phase applies must be declared "
                        "cluster-scoped or namespaced exactly once; an "
                        "undeclared kind is journaled at the wrong scope and "
                        "deleted cluster-wide on rollback",
                    )
        # The reverse direction, so the namespaced list cannot grow entries that
        # no phase applies and quietly widen what a journal may name.
        self.assertEqual(
            namespaced,
            {kind for kinds in REVIEWED_PHASE_KINDS.values() for kind in kinds}
            - cluster_scoped,
            "the reviewed namespaced kinds are exactly the phase kinds that are "
            "not cluster-scoped",
        )

    def test_the_inventory_names_are_the_cluster_scoped_objects(self):
        names = lock_value("inventory.cluster-scoped.names").split(",")
        self.assertEqual(len(names), int(lock_value("inventory.cluster-scoped")))
        self.assertIn("Namespace/kyverno", names)
        for policy in CORE_POLICIES + SIGNATURE_POLICIES:
            with self.subTest(policy=policy):
                self.assertIn("ClusterPolicy/" + policy, names)

    def test_no_webhook_configuration_is_in_the_applied_inventory(self):
        self.assertNotIn(
            "WebhookConfiguration", lock_value("inventory.cluster-scoped.names")
        )

    def test_the_runtime_webhook_sweep_is_enumerated_and_labelled(self):
        """Kyverno's own webhook configurations are not in any render, so
        rollback and break-glass cannot find them by inventory.

        The names are the exact `*WebhookConfigurationName` constants at the
        pinned v1.18.2 tag (`pkg/config/config.go`). Pinning the WHOLE set, not
        a sample, is the point: the first transcription omitted
        `kyverno-cel-exception-validating-webhook-cfg`, which v1.18.2 creates
        with `failurePolicy: Fail`, so an omitted name is a configuration the
        emergency path never deletes by name. The label sweep is the backstop
        for an upstream rename, never the primary.
        """

        self.assertEqual(
            lock_value("runtime.webhooks.validating").split(","),
            [
                "kyverno-policy-validating-webhook-cfg",
                "kyverno-resource-validating-webhook-cfg",
                "kyverno-exception-validating-webhook-cfg",
                "kyverno-cel-exception-validating-webhook-cfg",
                "kyverno-global-context-validating-webhook-cfg",
                "kyverno-cleanup-validating-webhook-cfg",
                "kyverno-ttl-validating-webhook-cfg",
            ],
        )
        self.assertEqual(
            lock_value("runtime.webhooks.mutating").split(","),
            [
                "kyverno-policy-mutating-webhook-cfg",
                "kyverno-resource-mutating-webhook-cfg",
                "kyverno-verify-mutating-webhook-cfg",
            ],
        )
        self.assertEqual(
            lock_value("runtime.webhooks.label"), "webhook.kyverno.io/managed-by=kyverno"
        )

    @unittest.skipUnless(PINNED_RENDERER, NEEDS_RENDERER)
    def test_the_lock_still_describes_the_working_tree(self):
        for stage in ("report-only", "enforce"):
            rendered = render(stage)
            with self.subTest(stage=stage):
                self.assertEqual(
                    hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                    lock_value(stage + ".sha256"),
                    "regenerate render.lock with --render in the same change",
                )
                self.assertEqual(
                    len(re.findall(r"(?m)^kind:", rendered)),
                    int(lock_value(stage + ".objects")),
                )


class RealRepositoryTests(unittest.TestCase):
    """The apply is deferred, and the reason is executable rather than written
    down: the controller pins are a platform-lane decision that has not been
    taken, so every apply path in the real repository stops at the pin guard."""

    def test_versions_env_carries_no_kyverno_controller_pin(self):
        versions = read(VERSIONS)
        self.assertIn("KYVERNO_CLI_VERSION=", versions)
        for pin in (
            "KYVERNO_VERSION",
            "KYVERNO_CHART_VERSION",
            "KYVERNO_ADMISSION_CONTROLLER_IMAGE",
            "KYVERNO_REPORTS_CONTROLLER_IMAGE",
            "KYVERNO_KYVERNOPRE_IMAGE",
        ):
            with self.subTest(pin=pin):
                self.assertNotRegex(versions, r"(?m)^" + pin + "=")

    def test_the_installer_names_every_pin_it_requires(self):
        installer = read(INSTALLER)
        for pin in (
            "KYVERNO_VERSION",
            "KYVERNO_CHART_VERSION",
            "KYVERNO_ADMISSION_CONTROLLER_IMAGE",
            "KYVERNO_REPORTS_CONTROLLER_IMAGE",
            "KYVERNO_KYVERNOPRE_IMAGE",
        ):
            with self.subTest(pin=pin):
                self.assertIn(pin, installer)

    def test_stage_two_is_recorded_as_not_authorized(self):
        """The split this pull request landed under, made executable.

        Round A lands the transaction; promoting to stage 2 is blocked on three
        tracked findings and is NOT authorized by this branch. That decision
        lives in `render.lock` rather than only in the runbook, because the
        operator reaching for the promotion is the reader least likely to have
        re-read the runbook.
        """

        self.assertEqual(lock_value("stage.enforce.authorized"), "no")
        blockers = lock_value("stage.enforce.blocked-by")
        for issue in ("#100", "#101", "#102", "runtime-network-canary"):
            with self.subTest(issue=issue):
                self.assertIn(issue, blockers)

    def test_stage_one_is_recorded_as_not_authorized(self):
        self.assertEqual(lock_value("stage.report-only.authorized"), "no")
        blockers = lock_value("stage.report-only.blocked-by")
        self.assertIn("#101", blockers)
        self.assertIn("runtime-network-canary", blockers)

    def test_the_runbook_states_that_stage_two_is_not_authorized(self):
        """Pinned as STRUCTURE, not as a substring.

        The first version of this test asserted only that "NOT AUTHORIZED"
        appeared somewhere in the file — and the quoted script output inside the
        section contains that string, so renaming the heading to "Stage 2 notes"
        left the suite green. That is precisely the text-pinned-guard defect this
        round exists to remove, reproduced in a test written during the round.
        The heading is now pinned as a heading, and it must appear BEFORE the
        first promotion instruction, because a warning a reader reaches after
        the command is not a warning.
        """

        runbook = read(RUNBOOK)
        heading = re.search(r"(?m)^## STAGE 2 IS \*\*NOT AUTHORIZED\*\*\s*$", runbook)
        if heading is None:
            raise AssertionError(
                "the runbook has no STAGE 2 IS NOT AUTHORIZED heading; a reader "
                "who sees only this document must not reach the promotion "
                "believing it is sanctioned"
            )
        self.assertLess(
            heading.start(),
            runbook.index("--stage enforce"),
            "the refusal must precede the first promotion instruction",
        )
        for issue in ("#100", "#101", "#102", "runtime-network-canary"):
            with self.subTest(issue=issue):
                self.assertIn(issue, runbook)

    @unittest.skipUnless(BASH, BASH_REQUIRED)
    def test_applying_stage_two_in_the_real_repository_is_refused_by_name(self):
        """A script that refuses beats a document that asks. The refusal fires
        before any tool is bound, so it does not depend on the machine."""

        completed = subprocess.run(
            [
                required_tool(BASH, BASH_REQUIRED),
                str(INSTALLER),
                "--stage",
                "enforce",
                "--apply",
                "--journal",
                os.path.join(
                    os.environ.get("TMPDIR", "/tmp"), "never-written.journal"
                ),
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("stage enforce is NOT AUTHORIZED", completed.stderr)
        for issue in ("#100", "#101", "#102", "runtime-network-canary"):
            with self.subTest(issue=issue):
                self.assertIn(issue, completed.stderr)

    @unittest.skipUnless(BASH, BASH_REQUIRED)
    def test_applying_stage_one_in_the_real_repository_is_refused_before_tools(self):
        completed = subprocess.run(
            [
                required_tool(BASH, BASH_REQUIRED),
                str(INSTALLER),
                "--stage",
                "report-only",
                "--apply",
                "--journal",
                os.path.join(os.environ.get("TMPDIR", "/tmp"), "never-written-stage1.journal"),
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("stage report-only is NOT AUTHORIZED", completed.stderr)
        self.assertIn("#101", completed.stderr)
        self.assertIn("runtime-network-canary", completed.stderr)

    def test_the_staged_controller_digest_is_still_the_all_zero_sentinel(self):
        controllers = read(ADMISSION / "kyverno" / "controllers.yaml")
        self.assertIn("@sha256:" + "0" * 64, controllers)

    @unittest.skipUnless(BASH and PINNED_RENDERER, NEEDS_RENDERER)
    def test_planning_the_real_repository_fails_closed(self):
        """Every apply path in THIS repository refuses, and names why.

        Which guard refuses depends on the machine. The version-pinned Windows
        renderer used for local render comparison cannot satisfy the separately
        pinned Linux executable hash, while Linux CI may reach the kubectl
        version guard or the intentionally missing controller pins. Every one
        is a valid earlier fail-closed boundary; the assertion names them rather
        than pretending a version match implies immutable tool identity.
        """

        for stage in ("report-only", "enforce"):
            completed = subprocess.run(
                [required_tool(BASH, BASH_REQUIRED), str(INSTALLER), "--stage", stage, "--plan"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
            )
            with self.subTest(stage=stage, pinned_kubectl=PINNED_KUBECTL):
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("PLAN only", completed.stdout)
                if PINNED_KUBECTL:
                    self.assertIn(
                        "versions.env has no reviewed KYVERNO_VERSION", completed.stderr
                    )
                    self.assertIn("platform-lane decision", completed.stderr)
                    # The render matched the lock before the pin guard fired, so
                    # the refusal is about the missing decision and nothing else.
                    self.assertIn("matches render.lock", completed.stdout)
                else:
                    self.assertRegex(
                        completed.stderr,
                        r"(?:kustomize executable sha256 [0-9a-f]{64} does not "
                        r"match versions\.env KUSTOMIZE_LINUX_AMD64_SHA256|"
                        r"kubectl is \S+; versions\.env pins "
                        + re.escape(pinned_version("KUBERNETES_VERSION"))
                        + r")",
                    )


class RunbookTests(unittest.TestCase):
    """The ceremony states its gates rather than implying them."""

    def setUp(self):
        self.text = read(RUNBOOK)

    def test_the_status_is_an_explicit_no_go(self):
        self.assertIn("NO-GO", self.text)

    def test_the_hard_gate_toward_flux_is_stated(self):
        self.assertIn("suspend", self.text)
        self.assertIn("precondition", self.text)

    def test_the_break_glass_procedure_is_a_command_not_a_description(self):
        self.assertIn("--break-glass", self.text)
        self.assertIn(
            "kubectl delete validatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno",
            self.text,
        )

    def test_stage_two_has_its_own_gate(self):
        self.assertIn("--stage report-only", self.text)
        self.assertIn("--stage enforce", self.text)
        self.assertIn("PolicyReport", self.text)

    def test_the_promotion_step_points_back_at_the_blocker_table(self):
        """A reader arriving at `#step-5-promote-to-stage-2` by anchor sees the
        gate list and no reason to believe the promotion is blocked — the four
        conditions in step 4 all read as things an operator could satisfy. The
        section carries the refusal itself, before its own first command."""

        heading = first_index(
            self.text.splitlines(), "## Step 5 — promote to stage 2", "the promotion step"
        )
        section = "\n".join(self.text.splitlines()[heading:])
        command = section.index("./scripts/install-kyverno-admission.sh")
        preamble = section[:command]
        self.assertIn("NOT AUTHORIZED", preamble)
        for issue in ("#100", "#101", "#102", "runtime-network-canary"):
            with self.subTest(issue=issue):
                self.assertIn(issue, preamble)

    def test_no_reboot_is_authorised_here(self):
        self.assertIn("reboot", self.text)


# --- behavioural harness -----------------------------------------------------

# A synthetic render whose SHAPE is what the installer classifies: 15 documents,
# 4 of them cluster-scoped, two carrying distinct network sentinels, one pinned
# image, and the engine exclusions the guards look for. Field meaning is
# irrelevant here — kubectl is stubbed — but every property a guard reads must
# be genuinely present, or an acceptance test would pass by dying early.
PINNED_IMAGE = (
    "reg.kyverno.io/kyverno/kyverno:v1.18.2@sha256:"
    "1111111111111111111111111111111111111111111111111111111111111111"
)
PINNED_CANARY_IMAGE = (
    "registry.k8s.io/e2e-test-images/agnhost:2.56@sha256:"
    "2222222222222222222222222222222222222222222222222222222222222222"
)
SYNTHETIC_DOCUMENTS = [
    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n",
    "apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: namespace-budget\n  namespace: kyverno\n",
    "apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: container-defaults\n  namespace: kyverno\n",
    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
    "  name: default-deny\n  namespace: kyverno\n",
    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
    "  name: kyverno-admission-webhook\n  namespace: kyverno\nspec:\n"
    "  ingress:\n    - from:\n        - ipBlock:\n            cidr: 192.0.2.10/32\n",
    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
    "  name: kyverno-dns\n  namespace: kyverno\n",
    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
    "  name: kyverno-kube-apiserver\n  namespace: kyverno\nspec:\n"
    "  egress:\n    - to:\n        - ipBlock:\n            cidr: 192.0.2.20/32\n"
    "      ports:\n        - port: 65535\n",
    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
    "  name: kyverno-public-https\n  namespace: kyverno\n",
    "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n"
    "  name: clusterpolicies.kyverno.io\n",
    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: kyverno\n  namespace: kyverno\ndata:\n"
    "  excludeGroups: system:nodes\n"
    "  resourceFilters: >-\n    [*/*,kube-system,*] [*/*,flux-system,*] [*/*,kyverno,*]\n"
    "  webhooks: '{\"namespaceSelector\":{\"matchExpressions\":[{\"key\":"
    "\"kubernetes.io/metadata.name\",\"operator\":\"NotIn\",\"values\":"
    "[\"kube-system\",\"flux-system\",\"kyverno\"]}]}}'\n",
    "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: kyverno-admission-controller\n"
    "  namespace: kyverno\n",
    "apiVersion: v1\nkind: Service\nmetadata:\n  name: kyverno-svc\n  namespace: kyverno\n",
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: kyverno-admission-controller\n"
    "  namespace: kyverno\nspec:\n  template:\n    spec:\n      containers:\n"
    "      - name: kyverno\n        image: " + PINNED_IMAGE + "\n",
    "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: alpha\nspec:\n"
    "  webhookConfiguration:\n    failurePolicy: Ignore\n  rules:\n"
    "  - name: one\n    validate:\n        failureAction: Audit\n",
    "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: beta\nspec:\n"
    "  webhookConfiguration:\n    failurePolicy: Ignore\n  rules:\n"
    "  - name: one\n    validate:\n        failureAction: Audit\n",
]
SYNTHETIC_RENDER = "---\n".join(SYNTHETIC_DOCUMENTS)
# The stage-2 twin: the identical objects with the two action fields flipped,
# which is exactly the relationship the real overlays have.
SYNTHETIC_ENFORCE_RENDER = SYNTHETIC_RENDER.replace(
    "failurePolicy: Ignore", "failurePolicy: Fail"
).replace("failureAction: Audit", "failureAction: Enforce")
SYNTHETIC_CLUSTER_SCOPED = (
    "Namespace/kyverno,CustomResourceDefinition/clusterpolicies.kyverno.io,"
    "ClusterPolicy/alpha,ClusterPolicy/beta"
)

# The stubbed kubectl. It reproduces the report shapes the guards classify and
# appends every invocation to KYVERNO_STUB_LOG so ordering can be asserted.
_KUBECTL_STUB = r"""#!/usr/bin/env bash
args="$*"
printf '%s\n' "$args" >>"${KYVERNO_STUB_LOG:-/dev/null}"
scenario="${KYVERNO_STUB_SCENARIO:-clean}"
case "$args" in
  "version --client"*) printf '{"clientVersion": {"gitVersion": "%s"}}\n' "${KYVERNO_STUB_KUBECTL_VERSION:-v1.36.3}"; exit 0 ;;
  "config view"*context*) printf 'reviewed-cluster\n'; exit 0 ;;
  "config view"*cluster.server*)
    printf '%s\n' "${KYVERNO_STUB_KUBECONFIG_SERVER:-https://198.51.100.7:6443}"; exit 0 ;;
esac
case "$args" in
  *"get service kubernetes"*) printf '192.0.2.30|443\n'; exit 0 ;;
  *"get endpoints kubernetes"*addresses*) printf '203.0.113.20\n203.0.113.21\n'; exit 0 ;;
  *"get endpoints kubernetes"*ports*) printf '6443\n'; exit 0 ;;
  *"get nodes -l node-role.kubernetes.io/control-plane"*) printf '203.0.113.10\n203.0.113.11\n'; exit 0 ;;
  *"get namespace kyverno"*install-render-sha256*) printf '%s\n' "${KYVERNO_STUB_LIVE_BINDING}"; exit 0 ;;
  *"get pod kyverno-network-canary"*)
    echo 'Error from server (NotFound): pods "kyverno-network-canary" not found' >&2; exit 1 ;;
  *"create -f"*network-canary.yaml*)
    target="${args##*create -f }"
    sed 's/^/CANARY /' "$target" >>"${KYVERNO_STUB_LOG:-/dev/null}"
    printf 'pod/kyverno-network-canary created\n'; exit 0 ;;
  *"annotate namespace kyverno"*) printf 'namespace/kyverno annotated\n'; exit 0 ;;
  *"--dry-run=client"*)
    if [[ "$scenario" == client-invalid ]]; then
      echo 'error: strict decoding error: unknown field "spec.bogus"' >&2; exit 1; fi
    target=''; previous=''
    for argument in "$@"; do
      [[ "$previous" != '-f' ]] || target="$argument"
      previous="$argument"
    done
    if grep -q '^kind: ClusterPolicy$' "$target" 2>/dev/null &&
       [[ ! -f "${KYVERNO_STUB_CRD_READY}" ]]; then
      echo 'no matches for kind "ClusterPolicy" in version "kyverno.io/v1"; ensure CRDs are installed first' >&2
      exit 1
    fi
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do printf 'object/%s created (dry run)\n' "$i"; done
    exit 0 ;;
  *"get namespace kyverno"*)
    if [[ "$scenario" == namespace-present ]]; then printf 'namespace/kyverno\n'; exit 0; fi
    echo 'Error from server (NotFound): namespaces "kyverno" not found' >&2; exit 1 ;;
  *"get ClusterPolicy "*)
    if [[ "$scenario" == policy-present ]]; then printf 'clusterpolicy.kyverno.io/alpha\n'; exit 0; fi
    # A DENIED read is not an absent object. This scenario is the one the
    # absence probe used to record as "nothing exists".
    if [[ "$scenario" == probe-unreadable ]]; then
      echo 'Error from server (Forbidden): clusterpolicies.kyverno.io is forbidden' >&2; exit 1; fi
    echo 'Error from server (NotFound)' >&2; exit 1 ;;
  *"get CustomResourceDefinition "*)
    echo 'Error from server (NotFound)' >&2; exit 1 ;;
  *"get deployment -l app.kubernetes.io/part-of=kyverno"*)
    case "$scenario" in
      enforce-ready|enforce-no-reports|enforce-already|enforce-rule-enforcing|enforce-foreign-reports|enforce-rule-unreadable)
        printf 'kyverno-admission-controller|1|1|1|1|1\n'; exit 0 ;;
      enforce-unhealthy) printf 'kyverno-admission-controller|1|1|2|2|1\n'; exit 0 ;;
      enforce-stale) printf 'kyverno-admission-controller|2|1|1|1|1\n'; exit 0 ;;
    esac
    exit 0 ;;
  # The DEPRECATED spec-level action, and the rule-level one Kyverno actually
  # prefers, are answered separately so a scenario can disagree between them —
  # which is the whole shape a gate reading only the spec level cannot see.
  *"get clusterpolicy "*validationFailureAction*)
    case "$scenario" in
      enforce-ready|enforce-no-reports|enforce-rule-enforcing|enforce-foreign-reports|enforce-rule-unreadable)
        printf 'Audit\n'; exit 0 ;;
      enforce-already) printf 'Enforce\n'; exit 0 ;;
    esac
    exit 0 ;;
  *"get clusterpolicy "*"rules[*]"*)
    case "$scenario" in
      # An EMPTY answer is legitimate here (verifyImages rules carry no validate
      # block), so emptiness cannot be the refusal — which is exactly why the
      # read's own status has to be.
      enforce-rule-unreadable)
        echo 'Error from server (Forbidden): clusterpolicies.kyverno.io is forbidden' >&2; exit 1 ;;
      enforce-rule-enforcing) printf 'Audit\nEnforce\n'; exit 0 ;;
      enforce-ready|enforce-no-reports|enforce-foreign-reports) printf 'Audit\n\n'; exit 0 ;;
    esac
    exit 0 ;;
  # Report RESULTS name the policy that produced them, so evidence can be bound
  # to the reviewed policy set instead of counted.
  *"get policyreports"*)
    case "$scenario" in
      enforce-ready|enforce-rule-enforcing|enforce-already) printf 'alpha|%s\nbeta|%s\n' "$(date -u +%s)" "$(date -u +%s)" ;;
      enforce-foreign-reports) printf 'some-unrelated-policy|%s\n' "$(date -u +%s)" ;;
    esac
    exit 0 ;;
  *"wait "*)
    if [[ "$scenario" == network-canary-fail && "$args" == *"pod/kyverno-network-canary"* ]]; then
      echo 'timed out waiting for canary' >&2
      exit 1
    fi
    if [[ "$args" == *"--for=condition=Established crd/clusterpolicies.kyverno.io"* ]]; then
      : >"${KYVERNO_STUB_CRD_READY}"
    fi
    exit 0 ;;
  *"apply -f"*)
    target=''; previous=''
    for argument in "$@"; do
      [[ "$previous" != '-f' ]] || target="$argument"
      previous="$argument"
    done
    if [[ -f "$target" ]]; then
      grep -h 'cidr:' "$target" 2>/dev/null | sed 's/^/CIDR /' >>"${KYVERNO_STUB_LOG:-/dev/null}" || true
      grep -h 'port:' "$target" 2>/dev/null | sed 's/^/PORT /' >>"${KYVERNO_STUB_LOG:-/dev/null}" || true
      # What was APPLIED, not what was announced: the recorded action fields are
      # how a test can tell a demotion that shipped the fail-open bytes from one
      # that shipped the enforcing bytes and printed the fail-open message.
      grep -hE '(failurePolicy|failureAction):' "$target" 2>/dev/null |
        sed -E 's/^[[:space:]]*/ACTION /' >>"${KYVERNO_STUB_LOG:-/dev/null}" || true
    fi
    if [[ -n "${KYVERNO_STUB_FAIL_PHASE:-}" && "$args" == *"phase-${KYVERNO_STUB_FAIL_PHASE}.yaml"* ]]; then
      echo 'Error from server: simulated apply failure' >&2; exit 1; fi
    # Ctrl-C / a supervisor TERM / a closed session, arriving mid-transaction.
    # bash defers the signal until this command returns, so the installer takes
    # it exactly between two applies — the state the handler exists for.
    if [[ -n "${KYVERNO_STUB_SIGNAL_PHASE:-}" && "$args" == *"phase-${KYVERNO_STUB_SIGNAL_PHASE}.yaml"* ]]; then
      kill -TERM "$PPID" 2>/dev/null || true; fi
    printf 'applied\n'; exit 0 ;;
  *"delete validatingwebhookconfiguration kyverno-policy-validating-webhook-cfg"*)
    if [[ "$scenario" == webhook-delete-failure ]]; then
      echo 'Error from server (Forbidden): simulated exact-name delete failure' >&2
      exit 1
    fi
    printf 'deleted\n'; exit 0 ;;
  *"delete "*) printf 'deleted\n'; exit 0 ;;
  *"get validatingwebhookconfiguration kyverno-"*|*"get mutatingwebhookconfiguration kyverno-"*)
    if [[ "$scenario" == webhook-read-forbidden ]]; then
      echo 'Error from server (Forbidden): webhookconfiguration is forbidden' >&2; exit 1; fi
    if [[ "$scenario" == residue && "$args" == *"kyverno-resource-validating-webhook-cfg"* ]]; then
      printf 'validatingwebhookconfiguration.admissionregistration.k8s.io/kyverno-resource-validating-webhook-cfg\n'; exit 0; fi
    echo 'Error from server (NotFound)' >&2; exit 1 ;;
  *"get validatingwebhookconfiguration"*|*"get mutatingwebhookconfiguration"*)
    # The deletes above SUCCEED in this scenario and only the READ fails, which
    # is the sharp form of the defect: the sweep did everything it was asked to
    # and the proof still cannot observe the result. Discarding this status was
    # what turned an unobservable cluster into a "clean" one.
    if [[ "$scenario" == webhook-read-forbidden ]]; then
      echo 'Error from server (Forbidden): validatingwebhookconfigurations is forbidden' >&2; exit 1; fi
    if [[ "$scenario" == residue ]]; then printf 'validatingwebhookconfiguration.admissionregistration.k8s.io/kyverno-resource-validating-webhook-cfg\n'; fi
    exit 0 ;;
  *"get customresourcedefinition"*)
    if [[ "$scenario" == crd-read-forbidden ]]; then
      echo 'Error from server (Forbidden): customresourcedefinitions is forbidden' >&2; exit 1; fi
    if [[ "$scenario" == residue-crd ]]; then
      printf 'customresourcedefinition.apiextensions.k8s.io/clusterpolicies.kyverno.io\n'; fi
    exit 0 ;;
esac
echo "stub kubectl: unhandled args: $args" >&2
exit 99
"""


@unittest.skipUnless(BASH, "bash is unavailable")
class InstallerGuardTests(unittest.TestCase):
    """Behavioural: every guard, driven in both directions, against a synthetic
    repository and stubbed binaries. Nothing contacts a cluster."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(
            tempfile.mkdtemp(prefix="kyverno-install-gate.", dir=os.environ.get("TMPDIR"))
        )
        # The tool stubs live OUTSIDE the synthetic repository on purpose: the
        # installer refuses a tool resolved from inside the checkout, and one
        # test proves that by placing a copy inside.
        cls.bin = cls.base / "bin"
        cls.bin.mkdir()
        cls.repo = cls.base / "repo"
        (cls.repo / "scripts").mkdir(parents=True)
        (cls.repo / "kubernetes" / "platform" / "admission-install").mkdir(parents=True)

        cls.render = cls.base / "render.yaml"
        write_exact(cls.render, SYNTHETIC_RENDER)
        cls.enforce_render = cls.base / "render-enforce.yaml"
        write_exact(cls.enforce_render, SYNTHETIC_ENFORCE_RENDER)
        digest = hashlib.sha256(cls.render.read_bytes()).hexdigest()
        enforce_digest = hashlib.sha256(cls.enforce_render.read_bytes()).hexdigest()
        objects = len(re.findall(r"(?m)^kind:", SYNTHETIC_RENDER))
        (cls.repo / "kubernetes" / "platform" / "admission-install" / "render.lock").write_text(
            "\n".join(
                [
                    "render.tool.name=kustomize",
                    "render.tool.version=v5.8.1",
                    "report-only.sha256=" + digest,
                    "report-only.objects=" + str(objects),
                    "enforce.sha256=" + enforce_digest,
                    "enforce.objects=" + str(objects),
                    "inventory.cluster-scoped=4",
                    "inventory.namespaced=11",
                    "inventory.cluster-scoped.names=" + SYNTHETIC_CLUSTER_SCOPED,
                    # The synthetic repository is where the promotion gate is
                    # exercised, so it is authorized. The REAL repository is not,
                    # and RealRepositoryTests pins that refusal.
                    "stage.enforce.authorized=yes",
                    "stage.enforce.blocked-by=nothing (synthetic fixture)",
                    "stage.enforce.minimum-observation-seconds=0",
                    "stage.report-only.authorized=yes",
                    "stage.report-only.blocked-by=nothing (synthetic fixture)",
                    "runtime.controllers.names=kyverno-admission-controller",
                    "runtime.webhooks.label=webhook.kyverno.io/managed-by=kyverno",
                    # TWO names per kind, deliberately: with one, a sweep that
                    # only ever removed the first entry would look complete.
                    "runtime.webhooks.validating=kyverno-resource-validating-webhook-cfg,"
                    "kyverno-policy-validating-webhook-cfg",
                    "runtime.webhooks.mutating=kyverno-resource-mutating-webhook-cfg,"
                    "kyverno-policy-mutating-webhook-cfg",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (cls.repo / "versions.env").write_text(
            "\n".join(
                [
                    "KUSTOMIZE_VERSION=v5.8.1",
                    "KUBERNETES_VERSION=v1.36.3",
                    "KYVERNO_VERSION=v1.18.2",
                    "KYVERNO_CHART_VERSION=3.6.2",
                    "KYVERNO_ADMISSION_CONTROLLER_IMAGE=" + PINNED_IMAGE,
                    "KYVERNO_REPORTS_CONTROLLER_IMAGE=" + PINNED_IMAGE,
                    "KYVERNO_KYVERNOPRE_IMAGE=" + PINNED_IMAGE,
                    "KYVERNO_NETWORK_CANARY_IMAGE=" + PINNED_CANARY_IMAGE,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        cls.installer = cls.repo / "scripts" / "install-kyverno-admission.sh"
        shutil.copy(INSTALLER, cls.installer)
        cls.installer.chmod(0o755)

        kustomize = cls.bin / "kustomize"
        kustomize.write_text(
            "#!/usr/bin/env bash\n"
            'if [[ "$1" == "version" ]]; then printf \'%s\\n\' "${KYVERNO_STUB_KUSTOMIZE_VERSION:-v5.8.1}"; exit 0; fi\n'
            'case "$2" in\n'
            '  */enforce) cat "${KYVERNO_STUB_RENDER_ENFORCE}" ;;\n'
            '  *) cat "${KYVERNO_STUB_RENDER}" ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        kustomize.chmod(0o755)
        kubectl = cls.bin / "kubectl"
        kubectl.write_text(_KUBECTL_STUB, encoding="utf-8")
        kubectl.chmod(0o755)
        cls.bash_env = cls.base / "bash-env"
        write_exact(
            cls.bash_env,
            "stat() { printf '%s\\n' \"${KYVERNO_STUB_NETWORK_MODE:-600}\"; }\n",
        )

        with (cls.repo / "versions.env").open("a", encoding="utf-8") as versions:
            versions.write(
                "KUSTOMIZE_LINUX_AMD64_SHA256={}\n".format(
                    hashlib.sha256(kustomize.read_bytes()).hexdigest()
                )
            )
            versions.write(
                "KUBECTL_LINUX_AMD64_SHA256={}\n".format(
                    hashlib.sha256(kubectl.read_bytes()).hexdigest()
                )
            )

        cls.kubeconfig = cls.base / "kubeconfig"
        cls.kubeconfig.write_text("# stubbed; kubectl config view is stubbed too\n", encoding="utf-8")
        cls.network_contract = cls.base / "runtime-network.contract"
        write_exact(
            cls.network_contract,
            "\n".join(
                [
                    "SCHEMA=website-infrastructure-kyverno-network-v1",
                    "CNI_IDENTITY=synthetic-cni",
                    "KUBE_PROXY_MODE=iptables",
                    "POLICY_DATAPLANE=service-vip",
                    "KUBERNETES_SERVICE_CIDR=192.0.2.30/32",
                    "KUBERNETES_SERVICE_PORT=443",
                    "KUBERNETES_ENDPOINT_CIDRS=203.0.113.20/32,203.0.113.21/32",
                    "KUBERNETES_ENDPOINT_PORT=6443",
                    "WEBHOOK_SOURCE_CIDRS=203.0.113.10/32,203.0.113.11/32",
                    "DNS_NAME=kubernetes.default.svc",
                    "",
                ]
            ),
        )
        cls.network_contract.chmod(0o600)
        cls.stage1_journal = cls.base / "stage1-evidence.journal"
        target_digest = hashlib.sha256(
            b"https://198.51.100.7:6443"
        ).hexdigest()
        network_digest = hashlib.sha256(cls.network_contract.read_bytes()).hexdigest()
        entries = []
        cluster_scoped = {"Namespace", "CustomResourceDefinition", "ClusterPolicy"}
        for document in SYNTHETIC_DOCUMENTS:
            kind = capture(
                r"(?m)^kind: (\S+)$", document, "the synthetic object kind"
            )
            name = capture(
                r"(?m)^  name: (\S+)$", document, "the synthetic object name"
            )
            namespace = "" if kind in cluster_scoped else "kyverno"
            entries.append("{}|{}|{}".format(kind, namespace, name))
        write_exact(
            cls.stage1_journal,
            "@transaction-v3|report-only|{}|{}|{}|{}\n{}\n".format(
                digest,
                target_digest,
                network_digest,
                "a" * 64,
                "\n".join(entries),
            ),
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def _run(self, *arguments, bin_dir=None, **overrides):
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            [str(bin_dir or self.bin), environment.get("PATH", "")]
        )
        environment["KYVERNO_STUB_RENDER"] = str(self.render)
        environment["KYVERNO_STUB_RENDER_ENFORCE"] = str(self.enforce_render)
        environment["KUBECONFIG"] = str(self.kubeconfig)
        environment["KYVERNO_INSTALL_CONTEXT"] = "reviewed-context"
        environment["KYVERNO_INSTALL_SERVER"] = "https://198.51.100.7:6443"
        environment["KYVERNO_RUNTIME_NETWORK_CONTRACT"] = str(self.network_contract)
        environment["KYVERNO_REPORT_ONLY_JOURNAL"] = str(self.stage1_journal)
        environment["KYVERNO_STUB_LIVE_BINDING"] = "{}|{}|{}".format(
            hashlib.sha256(self.render.read_bytes()).hexdigest(),
            hashlib.sha256(self.network_contract.read_bytes()).hexdigest(),
            hashlib.sha256(self.stage1_journal.read_bytes()).hexdigest(),
        ) + "|{}|1700000000".format("a" * 64)
        # Git for Windows reports every ordinary NTFS fixture as 0644 even
        # after chmod. BASH_ENV shadows only the synthetic process's `stat`;
        # Linux CI exercises the production command, while mutations can still
        # drive the 0600 refusal through KYVERNO_STUB_NETWORK_MODE.
        environment["BASH_ENV"] = str(self.bash_env)
        environment["KYVERNO_STUB_NETWORK_MODE"] = "600"
        environment["KYVERNO_STUB_LOG"] = str(self.base / "invocations.log")
        crd_ready = self.base / "crd-ready"
        crd_ready.unlink(missing_ok=True)
        environment["KYVERNO_STUB_CRD_READY"] = str(crd_ready)
        for key, value in overrides.items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        (self.base / "invocations.log").write_text("", encoding="utf-8")
        return subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), str(self.installer), *arguments],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.repo),
        )

    def _invocations(self):
        return (self.base / "invocations.log").read_text(encoding="utf-8").splitlines()

    def _write_bound_journal(
        self,
        path,
        entries,
        stage="report-only",
        render_digest=None,
        target_digest=None,
        network_digest=None,
    ):
        """Write the v2 provenance header before intentionally mutated entries."""

        render = self.render if stage == "report-only" else self.enforce_render
        header = "@transaction-v3|{}|{}|{}|{}|{}\n".format(
            stage,
            render_digest or hashlib.sha256(render.read_bytes()).hexdigest(),
            target_digest
            or hashlib.sha256(b"https://198.51.100.7:6443").hexdigest(),
            network_digest
            or hashlib.sha256(self.network_contract.read_bytes()).hexdigest(),
            "b" * 64,
        )
        write_exact(path, header + entries)
        return path

    @contextlib.contextmanager
    def _network_case(self, text):
        original = self.network_contract.read_bytes()
        write_exact(self.network_contract, text)
        try:
            yield
        finally:
            self.network_contract.write_bytes(original)

    def _deletes(self):
        return [line for line in self._invocations() if " delete " in line]

    def _applied_actions(self):
        """The policy-action lines of every file the stub was asked to apply.

        Asserting a mode's MESSAGE proves only that it reached the message. This
        is what it actually sent.
        """

        return [
            line[len("ACTION ") :]
            for line in self._invocations()
            if line.startswith("ACTION ")
        ]

    @contextlib.contextmanager
    def _render_case(self, text, stage="report-only", **lock_overrides):
        """Drive the installer against a hand-built render, lock re-derived.

        The digest and inventory guards run FIRST, so a behavioural probe of any
        later guard has to present bytes the lock accepts — otherwise the test
        would pass by dying at the digest comparison and prove nothing about the
        guard it was written for. The lock is restored unconditionally.
        """

        path = self.base / "render-case.yaml"
        write_exact(path, text)
        lock = self.repo / "kubernetes" / "platform" / "admission-install" / "render.lock"
        original = lock.read_text(encoding="utf-8")
        overrides = dict(lock_overrides)
        overrides.setdefault(
            stage + ".sha256", hashlib.sha256(path.read_bytes()).hexdigest()
        )
        overrides.setdefault(
            stage + ".objects", str(len(re.findall(r"(?m)^kind:", text)))
        )
        rewritten = []
        for line in original.splitlines():
            key = line.split("=", 1)[0]
            if key in overrides:
                line = key + "=" + overrides.pop(key)
            rewritten.append(line)
        rewritten.extend(key + "=" + value for key, value in overrides.items())
        lock.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        try:
            yield str(path)
        finally:
            lock.write_text(original, encoding="utf-8")

    @contextlib.contextmanager
    def _versions_case(self, old, new):
        versions = self.repo / "versions.env"
        original = versions.read_text(encoding="utf-8")
        self.assertIn(old, original, "the synthetic versions.env changed shape")
        versions.write_text(original.replace(old, new), encoding="utf-8")
        try:
            yield
        finally:
            versions.write_text(original, encoding="utf-8")

    # --- the accepted shapes, so every refusal below is load-bearing ---------

    def test_a_bound_plan_is_accepted(self):
        completed = self._run("--stage", "report-only", "--plan")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("matches render.lock", completed.stdout)
        self.assertIn("pre-apply absence probe clean", completed.stdout)
        self.assertIn("PLAN only; no mutation attempted", completed.stdout)

    def test_a_plan_mutates_nothing(self):
        completed = self._run("--stage", "report-only", "--plan")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        applies = [line for line in self._invocations() if " apply -f" in line]
        self.assertTrue(applies, "the plan must reach the client-side validation")
        for invocation in applies:
            with self.subTest(invocation=invocation):
                self.assertIn("--dry-run=client", invocation)
        for invocation in self._invocations():
            with self.subTest(invocation=invocation):
                self.assertNotIn(" delete ", invocation)

    # --- binding ------------------------------------------------------------

    def test_an_unpinned_kustomize_is_refused(self):
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_KUSTOMIZE_VERSION="v5.7.0"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("kustomize is v5.7.0; versions.env pins v5.8.1", completed.stderr)

    def test_an_unpinned_kubectl_is_refused(self):
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_KUBECTL_VERSION="v1.30.0"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("kubectl is v1.30.0; versions.env pins v1.36.3", completed.stderr)

    def test_a_tool_resolved_from_inside_the_checkout_is_refused(self):
        """The hostile-PATH case: a repository that can supply its own kubectl
        can supply one that reports whatever the gate wants to hear."""

        inside = self.repo / "hostile-bin"
        inside.mkdir(exist_ok=True)
        for tool in ("kustomize", "kubectl"):
            shutil.copy(self.bin / tool, inside / tool)
            (inside / tool).chmod(0o755)
        completed = self._run("--stage", "report-only", "--plan", bin_dir=inside)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("resolves inside the checkout", completed.stderr)

    def test_version_spoofing_external_binaries_are_refused_by_bytes(self):
        """Correct self-reported versions cannot substitute executable identity."""

        for tool in ("kustomize", "kubectl"):
            with self.subTest(tool=tool):
                spoof = self.base / ("spoof-" + tool)
                spoof.mkdir(exist_ok=True)
                for candidate in ("kustomize", "kubectl"):
                    shutil.copy(self.bin / candidate, spoof / candidate)
                    (spoof / candidate).chmod(0o755)
                with (spoof / tool).open("ab") as executable:
                    executable.write(b"\n# version string unchanged; bytes are hostile\n")
                completed = self._run(
                    "--stage", "report-only", "--plan", bin_dir=spoof
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "{} executable sha256".format(tool), completed.stderr
                )
                self.assertIn("does not match versions.env", completed.stderr)

    def test_a_render_that_does_not_match_the_lock_is_refused(self):
        tampered = self.base / "tampered.yaml"
        write_exact(tampered, SYNTHETIC_RENDER + "\n# one extra byte\n")
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=str(tampered)
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match render.lock", completed.stderr)

    def test_an_unpinned_image_in_the_render_is_refused(self):
        substituted = self.base / "unpinned.yaml"
        text = SYNTHETIC_RENDER.replace(PINNED_IMAGE, "docker.io/library/kyverno:latest")
        write_exact(substituted, text)
        lock = self.repo / "kubernetes" / "platform" / "admission-install" / "render.lock"
        original = lock.read_text(encoding="utf-8")
        lock.write_text(
            original.replace(
                hashlib.sha256(SYNTHETIC_RENDER.encode("utf-8")).hexdigest(),
                hashlib.sha256(text.encode("utf-8")).hexdigest(),
            ),
            encoding="utf-8",
        )
        try:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=str(substituted)
            )
        finally:
            lock.write_text(original, encoding="utf-8")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("render names an unpinned image", completed.stderr)

    def test_an_unset_target_is_refused(self):
        for variable in ("KUBECONFIG", "KYVERNO_INSTALL_CONTEXT", "KYVERNO_INSTALL_SERVER"):
            completed = self._run("--stage", "report-only", "--plan", **{variable: None})
            with self.subTest(variable=variable):
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(variable, completed.stderr)

    def test_a_context_pointing_at_another_server_is_refused(self):
        completed = self._run(
            "--stage",
            "report-only",
            "--plan",
            KYVERNO_STUB_KUBECONFIG_SERVER="https://203.0.113.9:6443",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("targets a different server", completed.stderr)

    def test_an_operator_hostname_is_not_reused_as_a_pod_network_peer(self):
        # The operator kubeconfig URL is identity only. Pods use the reviewed
        # kubernetes.default Service or endpoint path from the private contract.
        journal = self.base / "hostname-target.journal"
        completed = self._run(
            "--stage",
            "report-only",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_KUBECONFIG_SERVER="https://control-plane.invalid:6443",
            KYVERNO_INSTALL_SERVER="https://control-plane.invalid:6443",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        destinations = [
            line.split()[-1] for line in self._invocations() if line.startswith("CIDR ")
        ]
        self.assertIn("192.0.2.30/32", destinations)
        self.assertTrue(all("control-plane.invalid" not in peer for peer in destinations))
        journal.unlink()

    def test_the_network_sentinels_are_replaced_by_the_private_contract(self):
        """The committed bytes grant nothing; selected-CNI and HA peers come
        from a private contract cross-checked against the target cluster."""

        journal = self.base / "substitution.journal"
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        destinations = [
            line.split()[-1] for line in self._invocations() if line.startswith("CIDR ")
        ]
        self.assertIn("203.0.113.10/32", destinations)
        self.assertIn("203.0.113.11/32", destinations)
        self.assertIn("192.0.2.30/32", destinations)
        self.assertNotIn("198.51.100.7/32", destinations)
        self.assertNotIn("192.0.2.10/32", destinations)
        self.assertNotIn("192.0.2.20/32", destinations)
        journal.unlink()

    def test_a_render_with_the_wrong_sentinel_count_is_refused(self):
        text = SYNTHETIC_RENDER.replace("cidr: 192.0.2.20/32", "cidr: 203.0.113.99/32", 1)
        altered = self.base / "no-sentinel.yaml"
        write_exact(altered, text)
        lock = self.repo / "kubernetes" / "platform" / "admission-install" / "render.lock"
        original = lock.read_text(encoding="utf-8")
        lock.write_text(
            original.replace(
                hashlib.sha256(SYNTHETIC_RENDER.encode("utf-8")).hexdigest(),
                hashlib.sha256(text.encode("utf-8")).hexdigest(),
            ),
            encoding="utf-8",
        )
        try:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=str(altered)
            )
        finally:
            lock.write_text(original, encoding="utf-8")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("network sentinel 192.0.2.20/32; expected one", completed.stderr)

    # --- transactionality ---------------------------------------------------

    def test_a_preexisting_namespace_is_never_adopted(self):
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_SCENARIO="namespace-present"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refuses to adopt an object it did not create", completed.stderr)

    def test_a_preexisting_cluster_scoped_object_is_never_adopted(self):
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_SCENARIO="policy-present"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing to adopt a foreign object", completed.stderr)

    def test_an_invalid_render_fails_client_validation(self):
        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_SCENARIO="client-invalid"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("client-side strict validation failed", completed.stderr)

    def test_an_apply_without_a_journal_is_refused(self):
        completed = self._run("--stage", "report-only", "--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires --journal", completed.stderr)

    def test_an_apply_runs_the_phases_in_the_reviewed_order(self):
        journal = self.base / "ordered.journal"
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        applied = [
            capture(r"phase-([a-z-]+)\.yaml", line, "the applied phase file")
            for line in self._invocations()
            if re.search(r"apply -f \S*phase-[a-z-]+\.yaml", line)
            and "--dry-run=client" not in line
        ]
        self.assertEqual(
            applied,
            [
                "namespace",
                "bounds",
                "network",
                "crds",
                "controller-prerequisites",
                "controller",
                "policies",
            ],
        )
        # The health wait sits between the controller and the policies, which is
        # the whole ordering claim: nothing that triggers webhook registration
        # runs before the backend is Available.
        log = self._invocations()
        crd_wait = first_index(log, "--for=condition=Established", "the CRD wait")
        wait = first_index(log, "--for=condition=Available", "the controller health wait")
        crds = first_index(log, "phase-crds.yaml", "the CRD phase")
        prerequisites = first_index(
            log,
            "phase-controller-prerequisites.yaml",
            "the controller prerequisites phase",
        )
        controller = first_index(log, "phase-controller.yaml", "the controller phase")
        policies = next(
            (
                index
                for index, line in enumerate(log)
                if "phase-policies.yaml" in line and "--dry-run=client" not in line
            ),
            None,
        )
        self.assertIsNotNone(policies, "the policies apply phase vanished")
        self.assertLess(crds, crd_wait)
        self.assertLess(crd_wait, prerequisites)
        self.assertLess(prerequisites, controller)
        self.assertLess(controller, wait)
        self.assertLess(wait, policies)
        policy_validation = first_index(
            log,
            "phase-policies.yaml --dry-run=client",
            "strict policy validation after CRD discovery",
        )
        self.assertLess(crd_wait, policy_validation)
        self.assertLess(policy_validation, policies)
        journal.unlink()

    def test_precontroller_canary_uses_exact_identity_and_precedes_deployment(self):
        journal = self.base / "canary-order.journal"
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        log = self._invocations()
        prerequisites = first_index(
            log, "phase-controller-prerequisites.yaml", "controller prerequisites"
        )
        create = first_index(log, "create -f", "the pre-controller canary create")
        wait = first_index(
            log, "pod/kyverno-network-canary --timeout=60s", "the canary success wait"
        )
        delete = first_index(
            log, "delete pod kyverno-network-canary --wait=true", "canary cleanup"
        )
        controller = first_index(log, "phase-controller.yaml", "controller apply")
        self.assertLess(prerequisites, create)
        self.assertLess(create, wait)
        self.assertLess(wait, delete)
        self.assertLess(delete, controller)
        manifest = "\n".join(line for line in log if line.startswith("CANARY "))
        for exact in (
            "CANARY   name: kyverno-network-canary",
            "CANARY     app.kubernetes.io/name: kyverno",
            "CANARY     app.kubernetes.io/component: admission-controller",
            "CANARY     app.kubernetes.io/part-of: kyverno",
            "CANARY   automountServiceAccountToken: false",
            "CANARY   serviceAccountName: kyverno-admission-controller",
            "CANARY       command: [/agnhost, connect, --timeout=10s, kubernetes.default.svc:443]",
        ):
            self.assertIn(exact, manifest)
        self.assertIn(PINNED_CANARY_IMAGE, manifest)
        journal.unlink()

    def test_precontroller_canary_failure_rolls_back_and_cleans_the_pod(self):
        journal = self.base / "canary-failure.journal"
        completed = self._run(
            "--stage",
            "report-only",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="network-canary-fail",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("pre-controller network canary DNS/API path", completed.stderr)
        self.assertTrue(
            any(
                "delete pod kyverno-network-canary" in line
                for line in self._invocations()
            )
        )
        self.assertTrue(
            any("delete Namespace kyverno" in line for line in self._invocations())
        )
        journal.unlink()

    def test_the_journal_records_every_object_with_its_scope(self):
        journal = self.base / "recorded.journal"
        self._run("--stage", "report-only", "--apply", "--journal", str(journal))
        entries = journal.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(entries), len(SYNTHETIC_DOCUMENTS) + 1)
        self.assertTrue(entries[0].startswith("@transaction-v3|report-only|"))
        self.assertIn("Namespace||kyverno", entries)
        self.assertIn("ClusterPolicy||alpha", entries)
        self.assertIn("Deployment|kyverno|kyverno-admission-controller", entries)
        journal.unlink()

    def test_a_failed_phase_rolls_back_and_proves_no_residue(self):
        journal = self.base / "rollback.journal"
        completed = self._run(
            "--stage",
            "report-only",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_FAIL_PHASE="controller",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("phase controller failed; rolling back", completed.stderr)
        self.assertIn("residue probe clean", completed.stdout)
        deletes = [line for line in self._invocations() if " delete " in line]
        # Every journaled identity, plus the webhook configurations Kyverno
        # would have registered for itself and which no render contains.
        self.assertTrue(any("delete ClusterPolicy alpha" in line for line in deletes))
        self.assertTrue(any("delete Namespace kyverno" in line for line in deletes))
        self.assertTrue(
            any("validatingwebhookconfiguration" in line for line in deletes),
            "rollback must sweep the runtime-registered webhook configurations",
        )
        journal.unlink()

    def test_rollback_removes_the_journal_in_reverse_order(self):
        journal = self.base / "reverse.journal"
        self._write_bound_journal(
            journal,
            "Namespace||kyverno\nConfigMap|kyverno|kyverno\nClusterPolicy||alpha\n",
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        deletes = [line for line in self._invocations() if line.startswith("--kubeconfig") and " delete " in line]
        ordered = [
            line
            for line in deletes
            if re.search(r"delete (ClusterPolicy alpha|ConfigMap kyverno|Namespace kyverno)", line)
        ]
        self.assertEqual(len(ordered), 3)
        self.assertIn("delete ClusterPolicy alpha", ordered[0])
        self.assertIn("delete ConfigMap kyverno", ordered[1])
        self.assertIn("delete Namespace kyverno", ordered[2])
        journal.unlink()

    def test_rollback_refuses_an_enforce_journal_without_deleting(self):
        journal = self.base / "enforce-is-not-delete.journal"
        self._write_bound_journal(
            journal, "ClusterPolicy||alpha\n", stage="enforce"
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must never be used as a delete program", completed.stderr)
        self.assertIn("use --demote", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_journal_bound_to_another_render(self):
        journal = self.base / "foreign-render.journal"
        self._write_bound_journal(
            journal, "ClusterPolicy||alpha\n", render_digest="c" * 64
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("render digest does not match", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_journal_bound_to_another_target(self):
        journal = self.base / "foreign-target.journal"
        self._write_bound_journal(
            journal, "ClusterPolicy||alpha\n", target_digest="d" * 64
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("target digest does not match", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_journal_bound_to_another_network_contract(self):
        journal = self.base / "foreign-network.journal"
        self._write_bound_journal(
            journal, "ClusterPolicy||alpha\n", network_digest="e" * 64
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("runtime-network digest does not match", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_a_completed_rollback_journal_cannot_be_replayed(self):
        journal = self.base / "replay.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        first = self._run("--rollback", "--journal", str(journal))
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        second = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("already rolled back; replay is refused", second.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_fails_closed_when_residue_remains(self):
        journal = self.base / "residue.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback", "--journal", str(journal), KYVERNO_STUB_SCENARIO="residue"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("residue:", completed.stderr)
        self.assertIn("--break-glass", completed.stderr)
        journal.unlink()

    def test_break_glass_removes_only_the_webhook_configurations(self):
        completed = self._run("--break-glass")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("the API server no longer calls admission", completed.stdout)
        deletes = [line for line in self._invocations() if " delete " in line]
        self.assertTrue(deletes)
        for line in deletes:
            with self.subTest(line=line):
                self.assertIn("webhookconfiguration", line)

    # --- the stage gate -----------------------------------------------------

    def test_enforce_is_refused_on_a_cluster_with_no_report_only_stage(self):
        """The staged rollout cannot be skipped: stage 2 on an empty cluster is
        the single apply that registers a fail-closed webhook against a backend
        nobody proved."""

        completed = self._run("--stage", "enforce", "--plan")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("stage report-only has not been applied", completed.stderr)

    def test_enforce_is_refused_while_the_controller_is_unhealthy(self):
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-unhealthy"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not ready", completed.stderr)
        self.assertIn("desired=2, updated=2, available=1", completed.stderr)

    def test_enforce_is_refused_while_the_controller_generation_is_stale(self):
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-stale"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not current", completed.stderr)
        self.assertIn("generation 2, observed 1", completed.stderr)

    def test_enforce_is_refused_without_report_evidence(self):
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-no-reports"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("produced no fresh timestamped report", completed.stderr)

    def test_enforce_is_accepted_once_report_only_is_proven(self):
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-ready"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("stage report-only evidence accepted", completed.stdout)

    def test_enforce_does_not_probe_for_absence(self):
        # Asking stage 2 the question stage 1 asks — "does any of this already
        # exist?" — would refuse every promotion, because stage 1 created it all.
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-ready"
        )
        self.assertNotIn("absence probe", completed.stdout)

    def test_a_failed_promotion_demotes_instead_of_deleting(self):
        """Stage 2 creates nothing, so its undo is the reverse promotion. A
        rollback-by-deletion here would tear down a healthy installation to
        revert two changed fields."""

        journal = self.base / "promotion.journal"
        completed = self._run(
            "--stage",
            "enforce",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="enforce-ready",
            KYVERNO_STUB_FAIL_PHASE="policies",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("demoted to stage report-only", completed.stdout)
        self.assertEqual(
            self._deletes(),
            [],
            "a failed promotion must not delete the installation",
        )
        # And the automatic recovery must have applied the FAIL-OPEN bytes, not
        # merely announced them: this is the same path --demote takes by hand.
        actions = self._applied_actions()
        self.assertIn("failurePolicy: Ignore", actions)
        self.assertIn("failureAction: Audit", actions)
        journal.unlink()

    def test_demote_reapplies_the_report_only_bytes(self):
        completed = self._run("--demote")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("the webhook is fail-open", completed.stdout)
        self.assertEqual(self._deletes(), [])

    def test_demote_applies_the_fail_open_bytes_and_not_the_enforcing_ones(self):
        """`--demote` is the documented undo for stage 2 AND the automatic
        recovery from a failed promotion, so it is the emergency de-escalation
        path. Asserting its exit code, its message, and that it deleted nothing
        never looks at WHAT IT APPLIED: pointed at the enforcing render it would
        ship the fail-CLOSED bytes and still print "the webhook is fail-open".
        """

        completed = self._run("--demote")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        actions = self._applied_actions()
        self.assertTrue(actions, "the demotion applied no policy-action bytes at all")
        self.assertIn("failurePolicy: Ignore", actions)
        self.assertIn("failureAction: Audit", actions)
        self.assertNotIn("failurePolicy: Fail", actions)
        self.assertNotIn("failureAction: Enforce", actions)

    # --- the refusals, driven by INPUT rather than by the source text --------
    #
    # Every guard below was previously "pinned" by grepping the installer for
    # its own die message. That kills a mutant which DELETES the block — the
    # string goes with it — and survives one that replaces the condition with a
    # constant that never matches, or that deletes the CALL SITE while leaving
    # the function intact. These feed the input that should trip each guard.

    WEBHOOK_DOCUMENT = (
        "apiVersion: admissionregistration.k8s.io/v1\n"
        "kind: ValidatingWebhookConfiguration\n"
        "metadata:\n  name: kyverno-resource-validating-webhook-cfg\n"
    )

    def test_an_enforcing_render_is_refused_under_the_report_only_stage(self):
        # The stage is a property of the BYTES, not of the flag. This is the
        # guard that caught the stage-1-fail-closed mutant, and it had no test
        # of its own feeding it a render that should trip it.
        with self._render_case(SYNTHETIC_ENFORCE_RENDER) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("still contains an Enforce rule action", completed.stderr)

    def test_a_fail_open_render_is_refused_under_the_enforce_stage(self):
        with self._render_case(SYNTHETIC_RENDER, stage="enforce") as rendered:
            completed = self._run(
                "--stage",
                "enforce",
                "--plan",
                KYVERNO_STUB_RENDER_ENFORCE=rendered,
                KYVERNO_STUB_SCENARIO="enforce-ready",
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("declares no fail-closed webhook policy", completed.stderr)

    def test_a_render_missing_a_lockout_exclusion_is_refused(self):
        for namespace in LOCKOUT_NAMESPACES:
            text = SYNTHETIC_RENDER.replace(
                "[*/*,{},*]".format(namespace), "[*/*,some-tenant,*]"
            )
            with self._render_case(text) as rendered:
                completed = self._run(
                    "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
                )
            with self.subTest(namespace=namespace):
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "does not filter the {} namespace".format(namespace),
                    completed.stderr,
                )

    def test_a_render_whose_selector_is_an_inclusion_is_refused(self):
        # An inclusion list is fail-open for every namespace created later.
        text = SYNTHETIC_RENDER.replace('"operator":"NotIn"', '"operator":"In"')
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not a NotIn exclusion", completed.stderr)

    def test_a_render_that_declares_a_webhook_configuration_is_refused(self):
        text = SYNTHETIC_RENDER + "---\n" + self.WEBHOOK_DOCUMENT
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("webhook registration is the controller's act", completed.stderr)
        self.assertEqual(self._deletes(), [])

    def test_a_render_that_carries_a_secret_is_refused(self):
        text = SYNTHETIC_RENDER + (
            "---\napiVersion: v1\nkind: Secret\nmetadata:\n"
            "  name: kyverno-svc-tls\n  namespace: kyverno\n"
        )
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("this install carries no credential", completed.stderr)

    def test_a_render_with_an_unclassified_kind_is_refused(self):
        text = SYNTHETIC_RENDER + (
            "---\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n"
            "  name: sweeper\n  namespace: kyverno\n"
        )
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unclassified kind: CronJob", completed.stderr)

    def test_an_unreviewed_cluster_scoped_object_in_the_render_is_refused(self):
        text = SYNTHETIC_RENDER + (
            "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
            "metadata:\n  name: kyverno-extra\n"
        )
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "render has 5 cluster-scoped objects; render.lock records 4",
            completed.stderr,
        )

    def test_a_render_whose_documents_do_not_split_is_refused(self):
        # Two objects concatenated with no separator: the render counts two
        # `kind:` lines and the splitter produces one document, so an object
        # would be applied that no journal entry could ever roll back.
        text = SYNTHETIC_RENDER + (
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n"
            "  name: kyverno-extra\n  namespace: kyverno\n"
        )
        with self._render_case(text) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("journaled 15 identities for 16 rendered objects", completed.stderr)

    def test_an_inventory_name_absent_from_the_render_is_refused(self):
        # A ghost name in the reviewed inventory would otherwise shrink the
        # absence probe to objects that happen to exist in the bytes.
        with self._render_case(
            SYNTHETIC_RENDER,
            **{
                "inventory.cluster-scoped.names": SYNTHETIC_CLUSTER_SCOPED
                + ",ClusterPolicy/ghost"
            }
        ) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "reviewed inventory names ClusterPolicy/ghost but the render does not "
            "contain it",
            completed.stderr,
        )

    def test_a_self_inconsistent_lock_is_refused(self):
        # The object-count comparison can only disagree with the digest on a
        # lock somebody hand-edited — which is precisely the case a reviewer
        # regenerating one field and not the other produces.
        with self._render_case(SYNTHETIC_RENDER, **{"report-only.objects": "14"}) as rendered:
            completed = self._run(
                "--stage", "report-only", "--plan", KYVERNO_STUB_RENDER=rendered
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "render has 15 objects; render.lock records 14", completed.stderr
        )

    def test_a_renderer_that_did_not_produce_the_lock_is_refused(self):
        # versions.env and render.lock agreeing is a separate property from the
        # ambient tool matching versions.env; both are guards, and this is the
        # one that catches a lock regenerated by a different kustomize.
        with self._versions_case("KUSTOMIZE_VERSION=v5.8.1", "KUSTOMIZE_VERSION=v5.9.0"):
            completed = self._run(
                "--stage",
                "report-only",
                "--plan",
                KYVERNO_STUB_KUSTOMIZE_VERSION="v5.9.0",
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("render.lock digests were produced by v5.8.1", completed.stderr)

    def test_a_pin_carrying_the_all_zero_sentinel_digest_is_refused(self):
        # The guard that stops today's committed sentinel from being installed.
        sentinel = PINNED_IMAGE.rsplit("@", 1)[0] + "@sha256:" + "0" * 64
        with self._versions_case(
            "KYVERNO_ADMISSION_CONTROLLER_IMAGE=" + PINNED_IMAGE,
            "KYVERNO_ADMISSION_CONTROLLER_IMAGE=" + sentinel,
        ):
            completed = self._run("--stage", "report-only", "--plan")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("still carries the all-zero sentinel digest", completed.stderr)

    def test_an_operator_target_in_test_net_does_not_collide_with_runtime_sentinels(self):
        # Operator identity and Pod network paths are separate namespaces of
        # data. Even a synthetic target equal to an old sentinel cannot alter
        # the selected-CNI contract substitution.
        completed = self._run(
            "--stage",
            "report-only",
            "--plan",
            KYVERNO_STUB_KUBECONFIG_SERVER="https://192.0.2.0:6443",
            KYVERNO_INSTALL_SERVER="https://192.0.2.0:6443",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_a_contract_service_vip_mismatch_is_refused(self):
        original = self.network_contract.read_bytes()
        write_exact(
            self.network_contract,
            original.decode("utf-8").replace(
                "KUBERNETES_SERVICE_CIDR=192.0.2.30/32",
                "KUBERNETES_SERVICE_CIDR=192.0.2.31/32",
            ),
        )
        try:
            completed = self._run("--stage", "report-only", "--plan")
        finally:
            self.network_contract.write_bytes(original)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "does not match the live kubernetes.default Service VIP/port",
            completed.stderr,
        )

    def test_runtime_contract_mode_is_enforced(self):
        completed = self._run(
            "--stage",
            "report-only",
            "--plan",
            KYVERNO_STUB_NETWORK_MODE="644",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("mode must be 0600", completed.stderr)

    def test_runtime_contract_rejects_extra_keys(self):
        text = self.network_contract.read_text(encoding="utf-8") + "SURPRISE=value\n"
        with self._network_case(text):
            completed = self._run("--stage", "report-only", "--plan")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("key inventory is not exact", completed.stderr)

    def test_runtime_contract_rejects_an_incomplete_ha_source_set(self):
        text = self.network_contract.read_text(encoding="utf-8").replace(
            "WEBHOOK_SOURCE_CIDRS=203.0.113.10/32,203.0.113.11/32",
            "WEBHOOK_SOURCE_CIDRS=203.0.113.10/32",
        )
        with self._network_case(text):
            completed = self._run("--stage", "report-only", "--plan")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("every live control-plane InternalIP", completed.stderr)

    def test_runtime_contract_rejects_an_incomplete_api_endpoint_set(self):
        text = self.network_contract.read_text(encoding="utf-8").replace(
            "KUBERNETES_ENDPOINT_CIDRS=203.0.113.20/32,203.0.113.21/32",
            "KUBERNETES_ENDPOINT_CIDRS=203.0.113.20/32",
        )
        with self._network_case(text):
            completed = self._run("--stage", "report-only", "--plan")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("complete live Kubernetes API endpoint set", completed.stderr)

    def test_endpoint_dataplane_expands_every_endpoint_and_port_6443(self):
        text = self.network_contract.read_text(encoding="utf-8").replace(
            "POLICY_DATAPLANE=service-vip", "POLICY_DATAPLANE=endpoint"
        )
        journal = self.base / "endpoint-dataplane.journal"
        with self._network_case(text):
            completed = self._run(
                "--stage", "report-only", "--apply", "--journal", str(journal)
            )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        rendered = "\n".join(self._invocations())
        self.assertIn("CIDR             cidr: 203.0.113.20/32", rendered)
        self.assertIn("CIDR             cidr: 203.0.113.21/32", rendered)
        self.assertIn("PORT         - port: 6443", rendered)
        self.assertNotIn("192.0.2.20/32", rendered)
        self.assertNotIn("port: 65535", rendered)
        journal.unlink()

    def test_operator_target_is_compared_exactly_even_when_opaque(self):
        completed = self._run(
            "--stage",
            "report-only",
            "--plan",
            KYVERNO_STUB_KUBECONFIG_SERVER="https://999.999.999.999:6443",
            KYVERNO_INSTALL_SERVER="https://999.999.999.999:6443",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    # --- the journal is untrusted input --------------------------------------

    def test_rollback_refuses_a_journal_naming_a_foreign_cluster_scoped_object(self):
        """The journal outlives the process by design, so it is the one input to
        a privileged delete that something other than an apply can author. Read
        verbatim, `--rollback` is "delete whatever this file names"."""

        journal = self.base / "foreign.journal"
        self._write_bound_journal(
            journal, "Namespace||kube-system\nClusterRole||cluster-admin\n"
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("render.lock's reviewed inventory does not contain", completed.stderr)
        self.assertEqual(
            self._deletes(),
            [],
            "a refused rollback must not have deleted a prefix of the journal first",
        )
        journal.unlink()

    def test_rollback_refuses_a_journal_naming_another_namespace(self):
        journal = self.base / "foreign-namespaced.journal"
        self._write_bound_journal(
            journal,
            "ClusterPolicy||alpha\nConfigMap|kube-system|kube-root-ca.crt\n",
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("outside the kyverno namespace", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_malformed_journal(self):
        journal = self.base / "malformed.journal"
        self._write_bound_journal(journal, "Namespace||kyverno|extra\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not kind|namespace|name", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_every_cluster_scoped_kind_that_carries_a_namespace(self):
        """The bypass the namespace-string check left open, closed per kind.

        `validate_journal` used to branch on whether the namespace FIELD was
        empty: empty meant "cluster-scoped, prove it is in the reviewed
        inventory", non-empty meant "namespaced, prove it is in `kyverno`". A
        cluster-scoped kind written WITH a namespace therefore took the second
        branch and was accepted on the strength of the namespace alone — and
        `kubectl` IGNORES `--namespace` for a root-scoped resource, so the
        delete went out on the cluster-scoped path and returned 0. Verified
        against the pinned kubectl v1.36.3 driving a logging stub API server:
        `-n kyverno delete clusterrole cluster-admin` issues
        `DELETE /apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin`,
        with no namespace segment at all.

        The delete COUNT is the assertion, not the exit code: a refusal that
        arrives after a valid prefix has already been deleted is not a refusal.
        """

        for kind in REVIEWED_CLUSTER_SCOPED_KINDS:
            journal = self.base / "scoped.journal"
            self._write_bound_journal(
                journal, "{}|{}|{}\n".format(kind, "kyverno", "cluster-admin")
            )
            completed = self._run("--rollback", "--journal", str(journal))
            with self.subTest(kind=kind):
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(
                    self._deletes(),
                    [],
                    "a journal naming a cluster-scoped kind must be refused "
                    "before ANY delete, including the runtime webhook sweep",
                )
                self.assertIn(
                    "refusing the entire rollback without deleting anything",
                    completed.stderr,
                )
                if kind not in NEVER_JOURNALED_KINDS:
                    self.assertIn("scope follows the KIND", completed.stderr)
            journal.unlink()

    def test_rollback_refuses_a_namespaced_kind_that_carries_no_namespace(self):
        # The same binding in the other direction: a namespaced kind written
        # without a namespace would otherwise take the cluster-scoped branch and
        # be measured against an inventory it can never be in.
        journal = self.base / "unscoped.journal"
        self._write_bound_journal(journal, "ConfigMap||kyverno\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("with no namespace", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_kind_no_phase_of_this_install_applies(self):
        # The journal writer classifies every document through the phase table,
        # so a kind absent from it is a kind no attempt of this installer wrote.
        journal = self.base / "unphased.journal"
        self._write_bound_journal(
            journal, "Pod|kyverno|kyverno-admission-controller\n"
        )
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("which no phase of this install applies", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_journal_whose_kind_is_not_a_kind(self):
        # Shipped with the journal work and unpinned: without it, arbitrary text
        # reaches `kubectl delete` as its type argument.
        journal = self.base / "kind-shape.journal"
        self._write_bound_journal(journal, "Config-Map|kyverno|kyverno\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("names no kind", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_a_journal_whose_name_is_a_flag(self):
        """Unpinned until now, and the only thing standing between a journal
        line and `kubectl -n kyverno delete ConfigMap --all`: the name shape is
        what stops a FLAG being parsed as an object name."""

        journal = self.base / "name-shape.journal"
        self._write_bound_journal(journal, "ConfigMap|kyverno|--all\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("names no object", completed.stderr)
        self.assertEqual(self._deletes(), [])
        journal.unlink()

    def test_rollback_refuses_an_empty_journal_instead_of_disarming_admission(self):
        """An empty journal is not a completed rollback.

        Without the refusal the whole file validates vacuously, the runtime
        webhook sweep still runs — silently removing the configurations that
        make admission work — and the run reports `rollback complete`. The zero
        delete count is the assertion: the sweep must not have happened.
        """

        journal = self.base / "empty.journal"
        self._write_bound_journal(journal, "\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("journal records no object", completed.stderr)
        self.assertEqual(self._deletes(), [])
        self.assertNotIn("rollback complete", completed.stdout)
        journal.unlink()

    def test_an_apply_refuses_a_journal_that_already_records_an_attempt(self):
        # `--apply` truncates the journal it is given. Truncating one that
        # already holds an earlier attempt's identities destroys the only record
        # of what that attempt created, at the moment it is most needed.
        journal = self.base / "occupied.journal"
        journal.write_text("Namespace||kyverno\n", encoding="utf-8")
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("journal already records an attempt", completed.stderr)
        self.assertEqual(
            journal.read_text(encoding="utf-8"),
            "Namespace||kyverno\n",
            "the earlier attempt's record must survive the refusal",
        )
        journal.unlink()

    def test_an_apply_refuses_a_journal_inside_the_checkout(self):
        # The runbook required this and nothing enforced it. A record inside the
        # working tree does not survive a checkout or a clean, and it makes the
        # repository the author of a privileged delete program.
        journal = self.repo / "inside.journal"
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("journal path is inside the checkout", completed.stderr)
        self.assertFalse(journal.exists(), "the refusal must not create the file")

    @unittest.skipIf(os.name == "nt", "Git Bash cannot express POSIX mode bits on NTFS")
    def test_the_journal_is_created_unreadable_to_others(self):
        # The record of what a privileged apply touched is also the delete
        # program the next --rollback runs. Created under umask 077 so it is not
        # world-readable and not writable by anything but its owner.
        journal = self.base / "mode.journal"
        completed = self._run(
            "--stage", "report-only", "--apply", "--journal", str(journal)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertEqual(
            journal.stat().st_mode & 0o777,
            0o600,
            "the transaction record is created private, not world-readable",
        )
        journal.unlink()

    def test_a_plan_never_writes_the_operators_journal(self):
        # A mode that mutates nothing on the cluster must not truncate the
        # record of an earlier attempt either.
        journal = self.base / "preserved.journal"
        journal.write_text("Namespace||kyverno\n", encoding="utf-8")
        completed = self._run(
            "--stage", "report-only", "--plan", "--journal", str(journal)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertEqual(journal.read_text(encoding="utf-8"), "Namespace||kyverno\n")
        journal.unlink()

    def test_an_apply_refuses_a_symlinked_journal(self):
        # The journal path is a write primitive: this process truncates it and
        # then writes the identities a later --rollback will delete.
        target = self.base / "journal-symlink-target"
        target.write_text("", encoding="utf-8")
        link = self.base / "journal-symlink"
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target)
        try:
            completed = self._run(
                "--stage", "report-only", "--apply", "--journal", str(link)
            )
        finally:
            link.unlink()
            target.unlink()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("journal path is a symlink", completed.stderr)

    def test_an_interrupted_apply_rolls_back_rather_than_leaving_a_partial_cluster(self):
        """`trap cleanup EXIT` swept the work directory and nothing else, so a
        Ctrl-C, a supervisor TERM, or a closed session between two phases left a
        half-installed cluster with no automatic undo."""

        for phase in (
            "namespace",
            "bounds",
            "network",
            "crds",
            "controller-prerequisites",
            "controller",
            "policies",
        ):
            with self.subTest(phase=phase):
                journal = self.base / ("interrupted-" + phase + ".journal")
                completed = self._run(
                    "--stage",
                    "report-only",
                    "--apply",
                    "--journal",
                    str(journal),
                    KYVERNO_STUB_SIGNAL_PHASE=phase,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "received SIGTERM during the transaction", completed.stderr
                )
                self.assertIn("interrupted attempt rolled back", completed.stderr)
                deletes = self._deletes()
                self.assertTrue(
                    any("delete Namespace kyverno" in line for line in deletes),
                    "an interrupted attempt must undo the namespace it created",
                )
                journal.unlink()

    def test_an_interrupted_apply_demands_recovery_when_residue_remains(self):
        # The half that matters more: an interrupt whose rollback cannot PROVE
        # it finished must not exit quietly on an unproven state.
        journal = self.base / "interrupted-residue.journal"
        completed = self._run(
            "--stage",
            "report-only",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_SIGNAL_PHASE="network",
            KYVERNO_STUB_SCENARIO="residue",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("RECOVERY REQUIRED", completed.stderr)
        self.assertIn(str(journal), completed.stderr)
        journal.unlink()

    def test_an_interrupted_promotion_demotes_and_never_deletes(self):
        journal = self.base / "interrupted-promotion.journal"
        completed = self._run(
            "--stage",
            "enforce",
            "--apply",
            "--journal",
            str(journal),
            KYVERNO_STUB_SIGNAL_PHASE="network",
            KYVERNO_STUB_SCENARIO="enforce-ready",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("interrupted promotion demoted to report-only", completed.stderr)
        self.assertEqual(
            self._deletes(),
            [],
            "an interrupted promotion must not uninstall the stage-1 objects",
        )
        self.assertIn("failurePolicy: Ignore", self._applied_actions())
        self.assertIn("failureAction: Audit", self._applied_actions())
        journal.unlink()

    def test_rollback_sweeps_every_reviewed_runtime_webhook_name(self):
        journal = self.base / "sweep.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run("--rollback", "--journal", str(journal))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        deletes = self._deletes()
        for kind, names in (
            (
                "validatingwebhookconfiguration",
                (
                    "kyverno-resource-validating-webhook-cfg",
                    "kyverno-policy-validating-webhook-cfg",
                ),
            ),
            (
                "mutatingwebhookconfiguration",
                (
                    "kyverno-resource-mutating-webhook-cfg",
                    "kyverno-policy-mutating-webhook-cfg",
                ),
            ),
        ):
            for name in names:
                with self.subTest(name=name):
                    self.assertTrue(
                        any(
                            "delete {} {}".format(kind, name) in line
                            for line in deletes
                        ),
                        "the reviewed runtime webhook sweep lost " + name,
                    )
            with self.subTest(label=kind):
                self.assertTrue(
                    any(
                        "delete {} -l webhook.kyverno.io/managed-by=kyverno".format(kind)
                        in line
                        for line in deletes
                    ),
                    "the label sweep is the backstop when a name changes upstream",
                )
        journal.unlink()

    def test_rollback_fails_closed_when_a_kyverno_crd_remains(self):
        journal = self.base / "crd-residue.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback", "--journal", str(journal), KYVERNO_STUB_SCENARIO="residue-crd"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("kyverno.io CRD(s) remain", completed.stderr)
        journal.unlink()

    def test_rollback_fails_closed_when_the_namespace_remains(self):
        journal = self.base / "namespace-residue.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="namespace-present",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("the kyverno namespace remains", completed.stderr)
        journal.unlink()

    # --- break-glass ---------------------------------------------------------

    def test_break_glass_does_not_require_an_addressable_server(self):
        """The IPv4 constraint exists for the NetworkPolicy substitution, and
        break-glass applies no NetworkPolicy. Inheriting it let the emergency
        path refuse at exactly the moment the cluster was refusing writes."""

        completed = self._run(
            "--break-glass",
            KYVERNO_STUB_KUBECONFIG_SERVER="https://control-plane.invalid:6443",
            KYVERNO_INSTALL_SERVER="https://control-plane.invalid:6443",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("the API server no longer calls admission", completed.stdout)

    def test_break_glass_still_binds_the_target_identity(self):
        # Relaxing the address requirement must not relax WHICH cluster.
        completed = self._run(
            "--break-glass", KYVERNO_STUB_KUBECONFIG_SERVER="https://203.0.113.9:6443"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("targets a different server", completed.stderr)

    def test_break_glass_proves_the_webhooks_are_actually_gone(self):
        # Every deletion in the sweep is best-effort by design, so success has
        # to be a proven absence: a permission error would otherwise produce
        # exit 0 and a false recovery instruction while fail-closed hooks stay.
        completed = self._run("--break-glass", KYVERNO_STUB_SCENARIO="residue")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("break-glass did NOT clear admission", completed.stderr)

    def test_break_glass_reports_each_delete_failure_and_attempts_the_full_sweep(self):
        completed = self._run(
            "--break-glass", KYVERNO_STUB_SCENARIO="webhook-delete-failure"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("failed to delete reviewed", completed.stderr)
        self.assertIn("admission is NOT proven clear", completed.stderr)
        invocations = "\n".join(self._invocations())
        for name in (
            "kyverno-policy-validating-webhook-cfg",
            "kyverno-resource-validating-webhook-cfg",
            "kyverno-policy-mutating-webhook-cfg",
            "kyverno-resource-mutating-webhook-cfg",
        ):
            self.assertIn("delete", invocations)
            self.assertIn(name, invocations)

    def test_rollback_delete_failure_leaves_controller_inventory_untouched(self):
        journal = self.base / "webhook-delete-failure.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="webhook-delete-failure",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("controller objects were left in place", completed.stderr)
        self.assertFalse(
            any("delete ClusterPolicy alpha" in line for line in self._invocations())
        )
        journal.unlink()

    def test_break_glass_refuses_when_it_cannot_READ_the_webhook_configurations(self):
        """An unreadable cluster is not a clean cluster.

        The residue proof discarded kubectl's exit status twice — `2>/dev/null`
        dropped the message and `|| true` dropped the status — so a FAILED read
        produced an empty stream, `grep -c` printed 0, and the proof concluded
        "clean". Break-glass then exited 0 announcing that the API server no
        longer calls admission, while fail-closed webhooks were still
        registered. It matters most here of all, because break-glass exists to
        be trusted while the cluster is already refusing writes.

        In this scenario the DELETES succeed and only the READ fails, which is
        the sharp form: the sweep did everything it was asked to and the proof
        still cannot observe the result.
        """

        completed = self._run(
            "--break-glass", KYVERNO_STUB_SCENARIO="webhook-read-forbidden"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot prove", completed.stderr)
        self.assertIn("admission is NOT proven clear", completed.stderr)
        self.assertNotIn(
            "the API server no longer calls admission",
            completed.stdout,
            "an unproven sweep must not be announced as a completed one",
        )

    def test_rollback_refuses_when_it_cannot_READ_the_webhook_configurations(self):
        journal = self.base / "unreadable-webhooks.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="webhook-read-forbidden",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot prove", completed.stderr)
        self.assertNotIn("rollback complete", completed.stdout)
        journal.unlink()

    def test_rollback_refuses_when_it_cannot_READ_the_custom_resource_definitions(self):
        journal = self.base / "unreadable-crds.journal"
        self._write_bound_journal(journal, "ClusterPolicy||alpha\n")
        completed = self._run(
            "--rollback",
            "--journal",
            str(journal),
            KYVERNO_STUB_SCENARIO="crd-read-forbidden",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot prove CRD residue", completed.stderr)
        self.assertIn("NOT proven complete", completed.stderr)
        self.assertNotIn("residue probe clean", completed.stdout)
        journal.unlink()

    def test_an_unreadable_absence_probe_stops_the_install(self):
        """The same class on the APPLY path, which is the more dangerous half.

        `probe_absence` discarded the read's status too, so a DENIED answer for
        a reviewed cluster-scoped object was recorded as "it does not exist" and
        the transaction proceeded to create objects over state it had never
        observed. Only an explicit not-found is absence now.
        """

        completed = self._run(
            "--stage", "report-only", "--plan", KYVERNO_STUB_SCENARIO="probe-unreadable"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("could not determine whether", completed.stderr)
        self.assertNotIn("pre-apply absence probe clean", completed.stdout)

    # --- the promotion gate reads the authoritative field --------------------

    def test_enforce_is_refused_when_a_policy_already_enforces(self):
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-already"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("the cluster is not in the report-only stage", completed.stderr)

    def test_enforce_is_refused_when_the_authoritative_rule_action_enforces(self):
        """`.spec.validationFailureAction` is the DEPRECATED field, and
        report-only/kustomization.yaml says so: Kyverno prefers the rule's own
        `validate.failureAction`. A cluster reading `Audit` at the spec level
        with every rule enforcing is exactly what the promotion gate must not
        accept as proof that stage 1 is what is running."""

        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-rule-enforcing"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "authoritative validate.failureAction is Enforce", completed.stderr
        )

    def test_enforce_is_refused_when_the_rule_level_action_cannot_be_READ(self):
        """The third `2>/dev/null || true`, on the promotion gate's own
        authoritative read.

        The spec-level read four lines above is fail-closed because an empty
        answer is impossible there. Here an empty answer is LEGITIMATE — a
        verifyImages rule carries no validate block — so a discarded status made
        a denied or timed-out read indistinguishable from "every rule reports
        Audit", and the gate would print `evidence accepted` and promote the
        cluster-wide webhook to fail-closed on a cluster it never read.
        """

        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-rule-unreadable"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot read ClusterPolicy", completed.stderr)
        self.assertIn("NOT proven to be what is running", completed.stderr)
        self.assertNotIn("evidence accepted", completed.stdout)

    def test_enforce_is_refused_when_no_report_names_a_reviewed_policy(self):
        # A stale report from something else entirely is not evidence that this
        # policy set was ever evaluated.
        completed = self._run(
            "--stage", "enforce", "--plan", KYVERNO_STUB_SCENARIO="enforce-foreign-reports"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "no fresh timestamped report naming a reviewed policy", completed.stderr
        )


if __name__ == "__main__":
    unittest.main()
