"""Pin the workload image-reference grammar in BOTH policy engines at once.

The owner reads `kubectl describe pod` to answer "what is running". Before this
contract a tenant reference was `repository@sha256:<hex>` and answered that
question with a content address; it may now carry the published release tag in
front of the digest — `repository:vMAJOR.MINOR.PATCH@sha256:<hex>` — which is
already the shape of the connector, Flux and Kyverno images in the rendered
inventory.

Two properties have to hold together, and a green suite in either engine alone
proves neither:

* The DIGEST is still mandatory and still anchored. A tag is legibility; it is
  never what resolves, never what cosign verifies, and never a substitute for
  the immutable reference (safety invariant 6).
* The tag grammar is CLOSED. `latest`, a branch name, the unprefixed version,
  and a second registry host smuggled into the tag position are each refused,
  because a legible reference that lies is worse than an illegible one.

Conftest/Rego and Kyverno/CEL are hand-written mirrors of the same rules, and
comparing their source text only proves the text agrees. Every row below is
therefore fed to BOTH engines and any allow/deny disagreement is a failure —
the differential harness, not matching constants.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFTEST_POLICY = REPO_ROOT / "policies" / "conftest"
KYVERNO_POLICY = REPO_ROOT / "policies" / "kyverno" / "require-approved-images.yaml"
FIXTURES = REPO_ROOT / "tests" / "kubernetes" / "fixtures"
CONFTEST = shutil.which("conftest")
KYVERNO = shutil.which("kyverno")

DIGEST = "sha256:" + "11" * 32

# One row per reference shape: the fixture that carries it, and the exact
# conftest denial it must produce (None = must be accepted outright). The
# fixtures are one document per file on purpose — a multi-document deny fixture
# asserted at file level hides the weakening of any single arm.
CANONICAL = "container {name} must use the canonical image repository for namespace naranjo-online"
APPROVED = "container {name} image must use an approved registry and full digest"

# Kyverno's counterpart rules, named individually. Asserting the POLICY was
# rejected is not enough: two rules cover overlapping ground here, so
# neutering either one on its own leaves the fixture still rejected by the
# other and a policy-level assertion sees nothing. This was a real survivor in
# this change's own mutation matrix — opening `require-canonical-naranjo-image`
# to accept any tag left the suite green because `require-approved-digest`
# still caught the same Pod. Rule-level expectations are what closed it.
DIGEST_RULE = "require-approved-digest"
CANONICAL_RULE = "require-canonical-naranjo-image"

ROWS = (
    ("allow/tagged-release-reference.yaml", "tagged", (), frozenset()),
    (
        "deny/image-floating-tag.yaml",
        "image-floating-tag",
        (CANONICAL,),
        frozenset({DIGEST_RULE, CANONICAL_RULE}),
    ),
    (
        "deny/image-tag-without-digest.yaml",
        "image-tag-without-digest",
        (CANONICAL, APPROVED),
        frozenset({DIGEST_RULE, CANONICAL_RULE}),
    ),
    (
        "deny/image-unprefixed-release-tag.yaml",
        "image-unprefixed-release-tag",
        (CANONICAL,),
        frozenset({DIGEST_RULE, CANONICAL_RULE}),
    ),
    (
        "deny/image-tag-smuggling-a-registry.yaml",
        "image-tag-smuggling-a-registry",
        (CANONICAL, APPROVED),
        frozenset({DIGEST_RULE, CANONICAL_RULE}),
    ),
    (
        "deny/image-sibling-site-repository-tagged.yaml",
        "image-sibling-site-repository-tagged",
        (CANONICAL,),
        frozenset({CANONICAL_RULE}),
    ),
)


def conftest_denials(path):
    """Return the exact denial messages the tenant policy raises."""

    completed = subprocess.run(
        [
            CONFTEST,
            "test",
            "--policy",
            str(CONFTEST_POLICY),
            "--output",
            "json",
            "--no-color",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    return {
        failure.get("msg", "")
        for document in json.loads(completed.stdout)
        for failure in document.get("failures", [])
    }


FAILING_RULE = re.compile(r"^\d+ - (\S+) ")


def kyverno_failing_rules(path):
    """Return the exact set of require-approved-images rules that refused."""

    completed = subprocess.run(
        [KYVERNO, "apply", str(KYVERNO_POLICY), "--resource", str(path)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    summary = None
    rules = set()
    for line in completed.stdout.splitlines():
        matched = FAILING_RULE.match(line.strip())
        if matched:
            rules.add(matched.group(1))
        elif line.startswith("pass:") and "fail:" in line:
            summary = int(line.split("fail:", 1)[1].split(",", 1)[0].strip())
    if summary is None:
        raise AssertionError(
            "kyverno apply produced no summary line for {}".format(path.name)
        )
    # The parsed rule names and the engine's own count must agree, or this
    # harness is reading output it does not understand and every row below is
    # measuring nothing.
    if len(rules) != summary:
        raise AssertionError(
            "kyverno reported {} failures but {} rule names were parsed for "
            "{}".format(summary, len(rules), path.name)
        )
    return rules


@unittest.skipUnless(CONFTEST, "conftest is required")
class ImageReferenceGrammarTests(unittest.TestCase):
    def test_every_row_produces_exactly_its_expected_conftest_denials(self):
        """Behaviour, per message — not "the file was rejected".

        A file-level assertion cannot tell a fixture that is denied for the
        reason it exists from one that is denied for an unrelated reason, so a
        weakened image rule would stay invisible behind some other denial.
        """

        for relative, container, expected, _rules in ROWS:
            path = FIXTURES / relative
            with self.subTest(fixture=relative):
                self.assertTrue(path.is_file(), "missing fixture: " + relative)
                self.assertEqual(
                    conftest_denials(path),
                    {template.format(name=container) for template in expected},
                )

    def test_the_digest_is_what_the_tag_may_never_replace(self):
        """The one row that matters most, stated on its own.

        Permitting a tag is only safe because the digest requirement did not
        move. If this ever passes, the change stopped being about legibility.
        """

        path = FIXTURES / "deny" / "image-tag-without-digest.yaml"
        self.assertIn(
            APPROVED.format(name="image-tag-without-digest"),
            conftest_denials(path),
        )

    def test_the_accepted_reference_carries_a_tag_and_a_digest(self):
        """The allow fixture must actually exercise the new shape.

        A positive control that quietly reverted to the digest-only form would
        make every denial row above prove nothing about the tagged grammar.
        """

        text = (FIXTURES / "allow" / "tagged-release-reference.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "image: ghcr.io/snaraj/naranjo-online:v0.1.9@" + DIGEST, text
        )

    @unittest.skipUnless(KYVERNO, "kyverno is required")
    def test_both_engines_agree_on_every_reference_shape(self):
        """The differential harness.

        Rego and CEL express the same grammar in two languages; comparing the
        expressions proves the text agrees, never that the behaviour does. Feed
        each shape to both and fail on any disagreement.
        """

        for relative, _container, expected, rules in ROWS:
            path = FIXTURES / relative
            failing = kyverno_failing_rules(path)
            with self.subTest(fixture=relative, axis="verdict"):
                self.assertEqual(
                    bool(failing),
                    bool(expected),
                    "conftest and kyverno disagree about {}".format(relative),
                )
            # Which RULE refused is part of the contract. Two rules overlap on
            # most of these shapes, so a policy-level verdict cannot tell a
            # working pair from one working rule carrying a neutered one.
            with self.subTest(fixture=relative, axis="rules"):
                self.assertEqual(
                    failing,
                    set(rules),
                    "the wrong kyverno rules refused {}".format(relative),
                )


if __name__ == "__main__":
    unittest.main()
