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

ROWS = (
    ("allow/tagged-release-reference.yaml", "tagged", ()),
    (
        "deny/image-floating-tag.yaml",
        "image-floating-tag",
        (CANONICAL,),
    ),
    (
        "deny/image-tag-without-digest.yaml",
        "image-tag-without-digest",
        (CANONICAL, APPROVED),
    ),
    (
        "deny/image-unprefixed-release-tag.yaml",
        "image-unprefixed-release-tag",
        (CANONICAL,),
    ),
    (
        "deny/image-tag-smuggling-a-registry.yaml",
        "image-tag-smuggling-a-registry",
        (CANONICAL, APPROVED),
    ),
    (
        "deny/image-sibling-site-repository-tagged.yaml",
        "image-sibling-site-repository-tagged",
        (CANONICAL,),
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


def kyverno_rejects(path):
    """Return True when require-approved-images refuses the fixture."""

    completed = subprocess.run(
        [KYVERNO, "apply", str(KYVERNO_POLICY), "--resource", str(path)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    for line in completed.stdout.splitlines():
        if line.startswith("pass:") and "fail:" in line:
            failures = line.split("fail:", 1)[1].split(",", 1)[0].strip()
            return int(failures) > 0
    raise AssertionError(
        "kyverno apply produced no summary line for {}".format(path.name)
    )


@unittest.skipUnless(CONFTEST, "conftest is required")
class ImageReferenceGrammarTests(unittest.TestCase):
    def test_every_row_produces_exactly_its_expected_conftest_denials(self):
        """Behaviour, per message — not "the file was rejected".

        A file-level assertion cannot tell a fixture that is denied for the
        reason it exists from one that is denied for an unrelated reason, so a
        weakened image rule would stay invisible behind some other denial.
        """

        for relative, container, expected in ROWS:
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

        for relative, _container, expected in ROWS:
            path = FIXTURES / relative
            with self.subTest(fixture=relative):
                self.assertEqual(
                    kyverno_rejects(path),
                    bool(expected),
                    "conftest and kyverno disagree about {}".format(relative),
                )


if __name__ == "__main__":
    unittest.main()
