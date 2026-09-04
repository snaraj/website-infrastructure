"""Pin the promoter's proof-based receipt for promotion pull requests (#309).

The fixture is a real one: a bare ``origin`` holding a copy of the tracked
tree, a promoter clone of it, and a genuine promotion cut with the tool's own
``apply_promotion`` and pushed to a promoter branch — so the head under proof
was produced by exactly the code the proof re-runs. Each mutation test changes
ONE thing on that branch and asserts the verdict flips for that reason and no
other, which is what keeps the three proofs from being decorative.

The registry, Release and cosign answers come from
``test_promote_releases_contract``'s byte-honest ``FakeFleet``: every digest is
computed from the bytes it names, so a mutated digest cannot pass by accident.

Also here, because they are the same commission: the tick constant and the
runbook cadence pinned together, and both sites' Flux intervals pinned against
the validators that assert them.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from .support import REPO_ROOT, load_script
from .test_promote_releases_contract import (
    FakeFleet,
    OWNER_EMAIL,
    OWNER_ID,
    quiet_git_environment,
    tracked_copy,
)
# The SAME module object the fake fleet was built against, deliberately: a
# second `load_script` copy would define a second `Refusal` class, and the
# receipt step's whole distinction between "this pull request is wrong" and
# "the world is unreachable" is which exception it catches.
from .test_promote_releases_contract import MODULE
READY = load_script("ready_check.py", module_name="receipt_contract_ready_check")
SIGNATURE_POLICY = load_script(
    "validate_signature_policy.py", module_name="receipt_contract_signature_policy"
)
RELEASE_STATE = load_script(
    "validate_release_state.py", module_name="receipt_contract_release_state"
)
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "release-promotion.md"
AGENTS = REPO_ROOT / "AGENTS.md"
SITES = ("naranjo-online", "lidersea-com")
# The helper is never run: the scripted runner answers for it. Its NAME is what
# the contract cares about, and it carries no workstation path.
HELPER = "/nonexistent/receipt-token-helper"
TOKEN = "receipt-token-fixture-value-with-no-credential-shape"


def app_comment(head: str, body: str = "", at: str = "2026-09-04T00:00:00Z") -> dict:
    """A comment as GitHub lists it, carrying the review App's exact actor
    and, by default, a validator-shaped APPROVE receipt."""

    return {
        "user": {
            "login": READY.REVIEWS_APP,
            "id": READY.REVIEWS_APP_USER_ID,
            "type": "Bot",
        },
        "performed_via_github_app": {"id": READY.REVIEWS_APP_ID},
        "body": body or f"HEAD: {head}\nVERDICT: APPROVE\n\nMutation matrix and claim audit: supported.\n\n- Someone (adversarial reviewer)",
        "created_at": at,
    }


def owner_comment(body: str, at: str) -> dict:
    return {"user": {"login": MODULE.ASSIGNEE, "id": OWNER_ID, "type": "User"}, "body": body, "created_at": at}


class ProofFixture:
    """A real promoter clone, a real cut, and a scripted world around it."""

    def __init__(self, case: unittest.TestCase):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.env = quiet_git_environment()
        source = tracked_copy(base / "source")
        self.origin = base / "origin.git"
        self.git("clone", "-q", "--bare", str(source), str(self.origin), cwd=base)
        self.repo = base / "repo"
        self.git("clone", "-q", str(self.origin), str(self.repo), cwd=base)
        self.author = base / "author"
        self.git("clone", "-q", str(self.origin), str(self.author), cwd=base)

        committed = MODULE.load_receipt(REPO_ROOT)["records"]["naranjo-online"]["chartTag"]
        major, minor, patch = committed.split(".")
        self.version = f"{major}.{minor}.{int(patch) + 1}"
        self.fleet = FakeFleet(version=self.version)
        self.fleet.gh[f"repos/{self.fleet.site}/releases/latest"] = {"tag_name": f"v{self.version}"}
        self.fleet.gh["repos/snaraj/lidersea.com/releases/latest"] = {"tag_name": "v0.1.41"}
        self.fleet.gh["user"] = {"login": MODULE.ASSIGNEE, "id": OWNER_ID, "name": "t"}
        # A real, throwaway SSH signing key: the cut is signed with it and
        # GitHub is scripted to register its public half for the owner, so the
        # identity proof verifies a genuine signature rather than a stub.
        self.key = base / "signing-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(self.key)], check=True, capture_output=True)
        self.fleet.gh[f"users/{MODULE.ASSIGNEE}/ssh_signing_keys"] = [[{"key": self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()}]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues?state=open&labels=delivery-lane&per_page=100"] = [
            [{"number": 285, "title": "deploy-assurance[site-drift/naranjo-online]"}]
        ]
        self.comments = []
        self.state = "open"
        self.draft = True
        self.review_armed = True
        self.checks = [
            {"name": name, "app": {"slug": READY.REQUIRED_CHECK_APP}, "status": "completed", "conclusion": "success"}
            for name in READY.REQUIRED_CHECKS
        ]
        self.calls = []
        self.label_delete_failures = 0
        # Hostile forge knobs: move the head the instant a named write lands,
        # or let a valid receipt arrive between the proof and the post.
        self.move_head_after = None
        self.inject_receipt_before_post = False
        # Withdraw the subject while the token is being minted: closed,
        # readied, or its review attention removed, the head unchanged.
        self.after_token = None
        self.log_lines = []
        self._log = MODULE.log
        MODULE.log = self.log_lines.append
        case.addCleanup(self.close)

        self.base = self.git("rev-parse", "main", cwd=self.author).strip()
        self.branch = MODULE.branch_name(self.base, 285, {"naranjo-online": self.version})
        self.captured = MODULE.utc_today()
        self.head = ""
        self.body = ""

    # -- lifecycle ---------------------------------------------------------
    def close(self):
        MODULE.log = self._log
        self.tmp.cleanup()

    def git(self, *argv, cwd=None) -> str:
        done = subprocess.run(
            ["git", *argv], cwd=str(cwd or self.repo), capture_output=True, text=True, check=True, env=self.env
        )
        return done.stdout

    # -- the head under proof ---------------------------------------------
    def cut(self, mutate=None, message=None, sign=True, key=None, email=OWNER_EMAIL, committer_email=None, author_email=None) -> str:
        """Produce a genuine promotion commit on the promoter branch.

        ``mutate`` receives the author checkout after ``apply_promotion`` has
        written the surface, so a test can change exactly one thing;
        ``message`` receives the composed commit message and returns the one
        to commit, so a test can make the head claim something false;
        ``sign``, ``key`` and ``email`` let a test commit unsigned, with a key
        GitHub does not register, or under a foreign identity;
        ``committer_email`` forges the committer half alone, ``author_email``
        the author half alone.
        """

        selections = MODULE.discover_selections(self.author)
        acquired = {
            "naranjo-online": MODULE.acquire(
                selections["naranjo-online"], self.version, self.fleet.registry(), self.fleet.github(), self.fleet.cosign()
            )
        }
        MODULE.apply_promotion(self.author, selections, acquired, 285, "#285", self.captured)
        if mutate is not None:
            mutate(self.author)
        self.git("add", "-A", cwd=self.author)
        # The real title, body and message, composed the way the tick composes
        # them: the receipt's claim audit re-composes exactly these.
        accounting = MODULE.accounting_line(self.base, *MODULE.Workspace(self.author, self.run).numstat(self.base))
        self.body = MODULE.pr_body(selections, acquired, [285], self.base, accounting)
        composed = f"{MODULE.pr_title(selections, {'naranjo-online': self.version})}\n\n{self.body}"
        if message is not None:
            composed = message(composed)
        signing = ["-c", "gpg.format=ssh", "-c", f"user.signingkey={key or self.key}", "-S"] if sign else []
        halves = {}
        if committer_email:
            halves.update({"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": committer_email})
        if author_email:
            halves.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": author_email})
        self.run(
            ["git", "-c", "user.name=t", "-c", f"user.email={email}", *signing[:4], "commit", "-q", *signing[4:], "-F", "-"],
            cwd=self.author, input_text=composed, env=halves or None,
        )
        self.head = self.git("rev-parse", "HEAD", cwd=self.author).strip()
        self.git("push", "-q", "origin", f"HEAD:refs/heads/{self.branch}", cwd=self.author)
        self.wire()
        return self.head

    def wire(self):
        """Point the scripted GitHub at the branch this fixture pushed."""

        labels = MODULE.PR_LABELS + (MODULE.REVIEW_LABELS if self.review_armed else ())
        pull = {
            "number": 300,
            "draft": self.draft,
            "state": self.state,
            "user": {"login": MODULE.ASSIGNEE},
            "head": {"ref": self.branch, "sha": self.head, "repo": {"full_name": MODULE.REPOSITORY}},
            "base": {"ref": "main", "repo": {"full_name": MODULE.REPOSITORY, "default_branch": "main"}},
            "labels": [{"name": name} for name in labels],
            "body": self.body,
        }
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/commits/{self.head}/check-runs?per_page=100"] = {
            "total_count": len(self.checks), "check_runs": list(self.checks),
        }
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls?state=open&per_page=100"] = [[pull]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"] = pull
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{self.head}"] = {"behind_by": 0}
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/300/comments?per_page=100"] = [self.comments]

    # -- the scripted world ------------------------------------------------
    def run(self, argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
        argv = list(argv)
        self.calls.append({
            "argv": tuple(argv), "env": dict(env) if env else None,
            "timeout": timeout, "quiet": quiet_output,
        })
        if argv[0] == "git":
            merged = dict(self.env)
            merged.update(env or {})
            return MODULE.run_command(argv, cwd=cwd, input_text=input_text, env=merged)
        if argv[0] == HELPER:
            if self.inject_receipt_before_post:
                # A valid receipt lands while the token is being minted: the
                # last interval before the post.
                self.inject_receipt_before_post = False
                self.comments.append(app_comment(self.head))
                self.wire()
            if self.move_head_after == "token":
                self.move_head_after, self.head = None, "d" * 40
                self.wire()
            if self.after_token == "close":
                self.state = "closed"
            elif self.after_token == "ready":
                self.draft = False
            elif self.after_token == "disarm":
                self.review_armed = False
            if self.after_token:
                self.after_token = None
                self.wire()
            return TOKEN + "\n"
        if argv[:3] == ["gh", "pr", "comment"]:
            body = Path(argv[argv.index("--body-file") + 1]).read_text(encoding="utf-8")
            self.comments.append(app_comment(self.head, body))
            if self.move_head_after == "post":
                self.move_head_after, self.head = None, "d" * 40
            self.wire()
            return "https://github.com/snaraj/website-infrastructure/pull/300#issuecomment-1\n"
        if argv[:3] == ["gh", "pr", "ready"]:
            raise AssertionError("NO TOOL FLIPS READY, promoter included: the tick must never run this")
        if argv[:2] == ["gh", "api"] and "-X" in argv and argv[argv.index("-X") + 1] != "GET":
            path = argv[argv.index("--input") - 1] if "--input" in argv else argv[-1]
            self.calls[-1]["write"] = path
            if path.endswith(f"/labels/{READY.REVIEW_ATTENTION_LABEL}") and argv[argv.index("-X") + 1] == "DELETE":
                if self.label_delete_failures:
                    self.label_delete_failures -= 1
                    raise MODULE.Refusal("`gh api` exited 1: HTTP 502")
                self.review_armed = False
                if self.move_head_after == "label":
                    self.move_head_after, self.head = None, "d" * 40
                self.wire()
            elif path.endswith("/issues/300/labels") and argv[argv.index("-X") + 1] == "POST":
                self.review_armed = True
                self.wire()
            return "[]" if "/labels" in path else "{}"
        if Path(argv[0]).name.startswith("python") or argv[0] == sys.executable:
            # The receipt validator really runs: a composed receipt that the
            # repository's own validator would reject must never be posted.
            if self.move_head_after == "validate":
                # The head moves before the token is minted.
                self.move_head_after, self.head = None, "d" * 40
                self.wire()
            return MODULE.run_command(argv, cwd=cwd, input_text=input_text, env=env)
        return self.fleet.run(argv, cwd=cwd, input_text=input_text, env=env)

    def workspace(self):
        space = MODULE.Workspace(self.repo, self.run)
        space.refresh()
        return space

    def github(self):
        return MODULE.GitHub(run=self.run, fetch=self.fleet.fetch)

    def prove(self):
        pr = MODULE.owned_pull_request(self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"])
        pr["behind_by"] = self.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{self.head}"].get("behind_by")
        return MODULE.prove_promotion(self.workspace(), self.github(), self.fleet.registry(), self.fleet.cosign(), pr)

    def step(self, dry_run=False, helper=HELPER):
        pr = MODULE.owned_pull_request(self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"])
        pr["behind_by"] = 0
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(MODULE.RECEIPT_TOKEN_COMMAND_ENV, None)
            if helper:
                os.environ[MODULE.RECEIPT_TOKEN_COMMAND_ENV] = helper
            MODULE.post_receipts(
                self.workspace(), self.github(), self.fleet.registry(), self.fleet.cosign(), [pr], dry_run, self.run
            )

    def receipt_pass(self, dry_run=False, helper=HELPER):
        """The whole standalone step: lock, reads, plan, proofs, summary."""

        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(MODULE.RECEIPT_TOKEN_COMMAND_ENV, None)
            if helper:
                os.environ[MODULE.RECEIPT_TOKEN_COMMAND_ENV] = helper
            return MODULE.receipt_pass(
                self.repo, dry_run, registry=self.fleet.registry(), github=self.github(),
                cosign=self.fleet.cosign(), run=self.run,
            )

    def posted(self):
        return [call for call in self.calls if call["argv"][:3] == ("gh", "pr", "comment")]

    def writes(self):
        return [call for call in self.calls if "write" in call]

    def worktrees(self):
        listing = self.git("worktree", "list", "--porcelain")
        return [line for line in listing.splitlines() if line.startswith("worktree ")]


class HonestHeadTests(unittest.TestCase):
    """An untouched promoter cut earns an APPROVE, and the receipt is real."""

    def setUp(self):
        self.fixture = ProofFixture(self)
        self.head = self.fixture.cut()

    def test_an_untouched_cut_is_approved_and_the_receipt_validates(self):
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "APPROVE")
        self.assertIsNone(
            MODULE.RECEIPTS.denial(body, self.head, "pull-request"),
            "the composed receipt must satisfy the repository's own validator",
        )
        self.assertLessEqual(len(body.encode("utf-8")), MODULE.RECEIPTS.RECEIPT_BYTE_CEILING)
        self.assertTrue(body.startswith(f"HEAD: {self.head}\nVERDICT: APPROVE\n"))
        self.assertEqual(body.strip().splitlines()[-1], MODULE.RECEIPT_SIGNATURE)
        # The figures are the re-derived ones, not values read from the head.
        record = self.fixture.fleet.expected_record()
        for figure in (
            record["manifestDigest"], record["chartConfigDigest"], record["chartLayerDigest"],
            record["arm64Digest"], record["release"]["assetDigest"], record["release"]["sourceSha"],
        ):
            self.assertIn(figure, body)
        self.assertIn(f"releases/tag/v{self.fixture.version}", body)
        self.assertIn("kubernetes/websites/naranjo-online/source.yaml", body)
        for required in ("Confinement", "Re-derivation", "Novelty", "Claim audit", "Identity", "NO TOOL FLIPS READY"):
            self.assertIn(required, body)

    def test_a_two_workload_receipt_still_fits_the_contract_ceiling(self):
        # A promotion can move both sites at once; the ceiling is enforced by
        # the validator, so a receipt that outgrows it would be refused rather
        # than posted. Compose the widest realistic shape and prove it fits.
        verdict, _ = self.fixture.prove()
        self.assertEqual(verdict, "APPROVE")
        selection = MODULE.discover_selections(REPO_ROOT)["naranjo-online"]
        statement = MODULE.workload_statement(selection, self.fixture.fleet.expected_record())
        surface = [f"some/directory/with/a/long/name/file-{n}.py" for n in range(13)]
        widest = MODULE.approve_receipt(self.head, self.head, surface, [statement, statement], "2026-09-04")
        self.assertIsNone(MODULE.RECEIPTS.denial(widest, self.head, "pull-request"))
        self.assertLess(len(widest.encode("utf-8")), MODULE.RECEIPTS.RECEIPT_BYTE_CEILING)

    def test_the_cli_exposes_the_receipt_step_and_the_step_runs_under_the_lock(self):
        output = subprocess.run(
            [sys.executable, "-B", str(REPO_ROOT / "scripts" / "promote_releases.py"), "--help"],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertIn("receipt", output)
        held = MODULE.acquire_lock(self.fixture.repo / ".git" / "promoter.lock")
        self.assertIsNotNone(held)
        self.assertEqual(MODULE.receipt_pass(self.fixture.repo, True, run=self.fixture.run), 0)
        self.assertTrue(any("another tick holds the lock" in line for line in self.fixture.log_lines))
        MODULE.release_lock(held)

    def test_the_scratch_worktree_is_removed_on_every_exit(self):
        before = self.fixture.worktrees()
        self.fixture.prove()
        self.assertEqual(self.fixture.worktrees(), before, "a proof must leave no worktree behind")
        workspace = self.fixture.workspace()
        with self.assertRaises(ZeroDivisionError):
            with MODULE.scratch_worktree(workspace, self.fixture.base):
                raise ZeroDivisionError("the body failed")
        self.assertEqual(self.fixture.worktrees(), before, "a failed proof must leave no worktree behind")


class MutationTests(unittest.TestCase):
    """Each proof fails on exactly its own mutation."""

    def setUp(self):
        self.fixture = ProofFixture(self)

    def test_an_extra_file_in_the_diff_fails_confinement_only(self):
        def mutate(root):
            (root / "docs" / "assurance" / "smuggled-note.md").write_text("extra\n", encoding="utf-8")

        head = self.fixture.cut(mutate)
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Confinement failed", body)
        self.assertIn("docs/assurance/smuggled-note.md", body)
        self.assertIsNone(MODULE.RECEIPTS.denial(body, head, "pull-request"))
        # PR #312 round 3, finding 5: the receipt describes the audit that failed.
        self.assertIn("changes paths outside the promotion surface", body)
        self.assertIn("proof Confinement IS the audit", body)
        self.assertNotIn("does not re-derive", body)

    def test_a_changed_digest_line_fails_re_derivation(self):
        def mutate(root):
            path = root / "kubernetes" / "websites" / "naranjo-online" / "source.yaml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("sha256:", "sha256:" + "0", 1), encoding="utf-8")

        head = self.fixture.cut(mutate)
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Re-derivation failed", body)
        self.assertIn("kubernetes/websites/naranjo-online/source.yaml", body)
        self.assertIsNone(MODULE.RECEIPTS.denial(body, head, "pull-request"))
        self.assertIn("does not re-derive from `main`", body)
        self.assertIn("proof Re-derivation IS the audit", body)
        self.assertNotIn("changes paths outside", body)

    def test_a_mutated_committed_receipt_digest_fails_re_derivation(self):
        def mutate(root):
            path = root / MODULE.RECEIPT_JSON
            document = json.loads(path.read_text(encoding="utf-8"))
            record = document["records"]["naranjo-online"]
            record["release"]["assetDigest"] = "sha256:" + "b" * 64
            path.write_text(MODULE.render_receipt_json(document), encoding="utf-8")

        head = self.fixture.cut(mutate)
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Re-derivation failed", body)
        self.assertIn(MODULE.RECEIPT_JSON.as_posix(), body)
        self.assertIsNone(MODULE.RECEIPTS.denial(body, head, "pull-request"))

    def test_a_forged_capture_date_fails_re_derivation(self):
        def mutate(root):
            path = root / MODULE.RECEIPT_JSON
            document = json.loads(path.read_text(encoding="utf-8"))
            document["capturedDate"] = "2019-01-01"
            path.write_text(MODULE.render_receipt_json(document), encoding="utf-8")

        head = self.fixture.cut(mutate)
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Re-derivation failed", body)
        self.assertIn("2019-01-01", body)
        self.assertIsNone(MODULE.RECEIPTS.denial(body, head, "pull-request"))

    def test_an_unreadable_committed_receipt_is_a_named_refusal_not_a_traceback(self):
        # The head's receipt file is untrusted bytes; malformed JSON must reach
        # the verdict as a refusal with a name, never as an exception that
        # escapes the tick's handlers.
        def mutate(root):
            (root / MODULE.RECEIPT_JSON).write_text("{ not json", encoding="utf-8")

        head = self.fixture.cut(mutate)
        verdict, body = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("is unreadable", body)
        self.assertIsNone(MODULE.RECEIPTS.denial(body, head, "pull-request"))

    def test_an_existing_app_receipt_at_this_head_yields_nothing(self):
        head = self.fixture.cut()
        self.fixture.comments.append(app_comment(head))
        self.fixture.wire()
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(any("a receipt already binds" in line for line in self.fixture.log_lines))
        # A receipt at ANOTHER head, and a lookalike from a non-App actor, are
        # both invisible: novelty binds the exact head AND the App's actor.
        self.fixture.comments[:] = [app_comment("f" * 40)]
        outsider = app_comment(head)
        outsider["user"] = {"login": "mallory", "id": 4242, "type": "User"}
        self.fixture.comments.append(outsider)
        self.fixture.wire()
        self.assertEqual(self.fixture.prove()[0], "APPROVE")

    def test_a_stale_base_yields_nothing(self):
        head = self.fixture.cut()
        self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{head}"] = {"behind_by": 4}
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(any("behind main" in line for line in self.fixture.log_lines))
        self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{head}"] = {}
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(any("base freshness is unknown" in line for line in self.fixture.log_lines))

    def test_a_registry_error_is_a_skip_not_a_verdict(self):
        self.fixture.cut()
        del self.fixture.fleet.manifest_answers[
            (self.fixture.fleet.chart_repo, self.fixture.version, MODULE.OCI_MANIFEST)
        ]
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(
            any(line.startswith("PROOF re-derivation ") and "skipped: could not complete" in line
                for line in self.fixture.log_lines),
            self.fixture.log_lines,
        )

    def test_a_ceremony_refusal_is_a_skip_not_a_verdict(self):
        self.fixture.cut()
        self.fixture.fleet.gh[f"repos/{self.fixture.fleet.site}/releases/tags/v{self.fixture.version}"]["immutable"] = False
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(any("not an immutable final release" in line for line in self.fixture.log_lines))

    def test_a_request_changes_posts_and_retires_review_attention_too(self):
        # AGENTS.md, Verdict format: posting the verdict also removes
        # `requires-review`, whichever way the verdict went.
        def mutate(root):
            (root / "README.md").write_text(
                (root / "README.md").read_text(encoding="utf-8") + "\nsmuggled\n", encoding="utf-8"
            )

        self.fixture.cut(mutate)
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1)
        self.assertIn("VERDICT: REQUEST-CHANGES", self.fixture.comments[-1]["body"])
        self.assertEqual(
            len([call for call in self.fixture.writes() if call["write"].endswith("/labels/requires-review")]),
            1,
            "a REQUEST-CHANGES retires the review-attention label like an APPROVE does",
        )
        self.assertFalse(self.fixture.review_armed)
        self.assertTrue(any("requires-review removed (with the REQUEST-CHANGES receipt)" in line
                            for line in self.fixture.log_lines))

    def test_an_unsigned_head_is_a_request_changes(self):
        # PR #312 round 1, finding 1: the receipt attests a signed head, so
        # the proof verifies the signature instead of assuming it.
        self.fixture.cut(sign=False)
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Identity failed: the head commit's signature does not verify", receipt)
        self.assertTrue(any(line.startswith("PROOF identity ") and "failed:" in line for line in self.fixture.log_lines))
        # PR #312 round 2, finding 3: the receipt names the proof that failed
        # and says nothing about proofs that did not.
        self.assertIn("is not a commit the owner's credential signed under the owner's identity", receipt)
        self.assertIn("proof Identity IS the audit", receipt)
        self.assertNotIn("does not re-derive", receipt)
        self.assertNotIn("promotion surface", receipt)

    def test_a_foreign_author_alone_is_a_request_changes(self):
        # PR #312 round 3, finding 2: the author half of the contract on its
        # own — committer and signature are the owner's.
        self.fixture.cut(author_email="someone@example.invalid")
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Identity failed: the head commit's author or committer is not the owner's noreply identity", receipt)

    def test_a_foreign_committer_alone_is_a_request_changes(self):
        # PR #312 round 2, finding 2: the committer half of the contract,
        # exercised on its own — author and signature are the owner's.
        self.fixture.cut(committer_email="someone@example.invalid")
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Identity failed: the head commit's author or committer is not the owner's noreply identity", receipt)

    def test_a_head_signed_by_an_unregistered_key_is_a_request_changes(self):
        other = self.fixture.key.parent / "other-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "other", "-f", str(other)], check=True, capture_output=True)
        self.fixture.cut(key=other)
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("does not verify against the owner's registered signing keys", receipt)

    def test_a_foreign_identity_is_a_request_changes(self):
        self.fixture.cut(email="someone@example.invalid")
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Identity failed: the head commit's author or committer is not the owner's noreply identity", receipt)

    def test_an_honest_head_carries_the_identity_proof(self):
        self.fixture.cut()
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "APPROVE")
        self.assertIn("5. Identity.", receipt)
        self.assertTrue(any(line.startswith("PROOF identity ") and "held:" in line for line in self.fixture.log_lines))

    def test_a_mode_only_mutation_is_a_request_changes(self):
        # PR #312 round 1, finding 2: same bytes, different tree entry.
        def mutate(root):
            (root / "README.md").chmod(0o755)

        self.fixture.cut(mutate)
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Re-derivation failed", receipt)
        self.assertIn("README.md", receipt)

    def test_a_false_body_claim_is_a_request_changes(self):
        # Finding 1 (2026-09-04): the receipt used to CLAIM a body audit it
        # never did. The body is a pure function of the re-derived records
        # and the recorded accounting; one changed byte fails proof 4.
        self.fixture.cut()
        pull = self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"]
        self.assertIn("Accounting (measured", pull["body"])
        pull["body"] = pull["body"].replace("Accounting (measured", "Accounting (estimated")
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Claim audit failed: the pull request body does not re-compose", receipt)
        self.assertIn("proof Claim audit IS the audit", receipt)
        self.assertNotIn("does not re-derive", receipt)
        self.assertTrue(any(line.startswith("PROOF claim-audit ") and "failed:" in line
                            for line in self.fixture.log_lines))

    def test_a_false_commit_message_claim_is_a_request_changes(self):
        self.fixture.cut(message=lambda composed: composed + "\nAlso promotes lidersea.com 9.9.9.\n")
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "REQUEST-CHANGES")
        self.assertIn("Claim audit failed: the head commit's message does not re-compose", receipt)

    def test_an_honest_head_passes_the_claim_audit_it_reports(self):
        self.fixture.cut()
        verdict, receipt = self.fixture.prove()
        self.assertEqual(verdict, "APPROVE")
        self.assertIn("4. Claim audit.", receipt)
        self.assertTrue(any(line.startswith("PROOF claim-audit ") and "held:" in line
                            for line in self.fixture.log_lines))

    def test_a_head_that_the_branch_does_not_carry_is_never_judged(self):
        head = self.fixture.cut()
        pull = self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"]
        pull["head"] = dict(pull["head"], sha="c" * 40)
        self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{'c' * 40}"] = {"behind_by": 0}
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(any("does not point at the head" in line for line in self.fixture.log_lines))
        self.assertNotEqual(head, "c" * 40)


class PostingTests(unittest.TestCase):
    """The posting path: the App, the token, and the label."""

    def setUp(self):
        self.fixture = ProofFixture(self)
        self.head = self.fixture.cut()

    def test_an_approve_posts_as_the_app_and_retires_review_attention(self):
        self.fixture.step()
        posts = self.fixture.posted()
        self.assertEqual(len(posts), 1)
        argv = posts[0]["argv"]
        self.assertEqual(argv[:5], ("gh", "pr", "comment", "300", "--repo"))
        self.assertIn("--body-file", argv)
        body = self.fixture.comments[-1]["body"]
        self.assertIn(f"HEAD: {self.head}", body)
        self.assertIn("VERDICT: APPROVE", body)
        deletes = [call for call in self.fixture.writes() if call["write"].endswith("/labels/requires-review")]
        self.assertEqual(len(deletes), 1)
        self.assertIn("DELETE", deletes[0]["argv"])

    def test_a_failed_label_retirement_is_finished_on_the_next_tick(self):
        # Finding 3 (2026-09-04): the post succeeded, the label DELETE did
        # not. The head is terminal from the moment the receipt binds it, so
        # the next tick owes it exactly the retirement and nothing else.
        self.fixture.label_delete_failures = 1
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1)
        self.assertTrue(self.fixture.review_armed, "the failed DELETE left the label armed")
        self.assertTrue(any("FAILED decision=skip-this-tick" in line for line in self.fixture.log_lines))
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1, "the bound head was not judged or posted again")
        self.assertFalse(self.fixture.review_armed, "the second tick finished the retirement")
        self.assertTrue(any("requires-review removed (a receipt already binds this head)" in line
                            for line in self.fixture.log_lines))

    def test_a_retirement_outrun_by_a_moved_head_is_re_armed_on_the_next_tick(self):
        # Design reset (round 3): no compensation write. The label DELETE
        # landed by number, the head moved, and the replacement head is left
        # without review attention and without a receipt. The next tick reads
        # that state and re-arms the label before judging.
        self.fixture.move_head_after = "label"
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1)
        self.assertFalse(self.fixture.review_armed, "the retirement outran the moved head")
        self.fixture.step()
        self.assertTrue(self.fixture.review_armed, "the next tick re-armed the replacement head")
        self.assertTrue(any(call["write"].endswith("/issues/300/labels") and "POST" in call["argv"] for call in self.fixture.writes()))
        self.assertTrue(any("re-armed at" in line and "no receipt binds this head" in line for line in self.fixture.log_lines))
        self.assertEqual(len(self.fixture.posted()), 1, "a head the branch does not carry is still never judged")

    def test_a_tick_never_runs_gh_pr_ready(self):
        # The fixture raises on `gh pr ready`; a whole pass must never reach it.
        self.assertEqual(self.fixture.receipt_pass(), 0)
        self.assertEqual([call for call in self.fixture.calls if call["argv"][:3] == ("gh", "pr", "ready")], [])

    def test_a_head_that_moves_after_the_post_keeps_its_review_attention(self):
        # Round 2, finding 3, as the reviewer staged it: the receipt posted at
        # the old head, then the head moved before the retirement. The label
        # belongs to the replacement head, which no receipt has judged.
        self.fixture.move_head_after = "post"
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1)
        self.assertTrue(self.fixture.review_armed, "the replacement head keeps its review attention")
        self.assertEqual([call for call in self.fixture.writes() if call["write"].endswith("/labels/requires-review")], [])
        self.assertTrue(any("kept; the head moved past" in line for line in self.fixture.log_lines))

    def test_a_head_that_moves_during_token_acquisition_is_not_posted(self):
        # PR #312 round 1, finding 3: the last pre-post read covers the head
        # as well as the receipt set.
        self.fixture.move_head_after = "token"
        self.fixture.step()
        self.assertEqual(self.fixture.posted(), [])
        self.assertTrue(any("the head moved during token acquisition; nothing was posted" in line
                            for line in self.fixture.log_lines))

    def test_a_receipt_attests_the_head_whatever_the_state_becomes(self):
        # Design reset (PR #312 round 3): a receipt binds the head it names
        # and nothing about the pull request's state, which the Ready rule
        # reads at flip time. A subject closed, readied or disarmed while the
        # token is minted still receives its head-bound record.
        for change in ("close", "ready", "disarm"):
            with self.subTest(change=change):
                fixture = ProofFixture(self)
                head = fixture.cut()
                fixture.after_token = change
                fixture.step()
                self.assertEqual(len(fixture.posted()), 1, change)
                self.assertIn(f"HEAD: {head}", fixture.comments[-1]["body"])

    def test_a_head_is_judged_whatever_state_the_pull_request_is_in(self):
        # Design reset (PR #312 round 3): no state gate in the receipt path.
        # A head that is already out of Draft, or whose review attention was
        # removed by hand, is still judged (the label is re-armed first) and
        # still receives its head-bound record.
        for change in ("ready", "disarm"):
            with self.subTest(change=change):
                fixture = ProofFixture(self)
                head = fixture.cut()
                if change == "ready":
                    fixture.draft = False
                else:
                    fixture.review_armed = False
                fixture.wire()
                fixture.step()
                self.assertEqual(len(fixture.posted()), 1, change)
                self.assertIn(f"HEAD: {head}", fixture.comments[-1]["body"])
                self.assertFalse(fixture.review_armed, "either verdict retires the label")

    def test_a_head_that_moves_before_the_token_mints_no_token(self):
        # PR #312 round 3, finding 3: the pre-token read is bound on its own —
        # a head that moved before the mint gets no credential minted for it.
        self.fixture.move_head_after = "validate"
        self.fixture.step()
        self.assertEqual(self.fixture.posted(), [])
        self.assertEqual([call for call in self.fixture.calls if call["argv"][0] == HELPER], [], "no token was minted")
        self.assertTrue(any("the head moved between proof and post; nothing was posted" in line for line in self.fixture.log_lines))

    def test_an_unconfigured_helper_runs_no_proof(self):
        # PR #312 round 3, finding 4: without a way to post, nothing is proved.
        self.fixture.step(helper="")
        self.assertEqual([call for call in self.fixture.calls if call["argv"][0] == "cosign"], [], "no cosign call")
        self.assertEqual([call for call in self.fixture.calls if call["argv"][:2] == ("git", "fetch") and any("refs/heads/" in a for a in call["argv"])], [], "the branch was never fetched")
        self.assertEqual([line for line in self.fixture.log_lines if line.startswith("PROOF ")], [], "no proof ran")

    def test_a_malformed_app_comment_is_not_a_receipt(self):
        # Round 2, finding 4: a HEAD-only App comment is text, not a verdict.
        self.fixture.comments.append(app_comment(self.head, body=f"HEAD: {self.head}\n"))
        self.fixture.wire()
        self.fixture.step()
        self.assertEqual(len(self.fixture.posted()), 1, "the head was judged and received its real receipt")
        self.assertFalse(self.fixture.review_armed)
        self.assertFalse(any("already binds this head" in line for line in self.fixture.log_lines))

    def test_a_receipt_arriving_during_the_proof_is_not_posted_twice(self):
        # Round 2, finding 4: novelty is re-read immediately before the post.
        self.fixture.inject_receipt_before_post = True
        self.fixture.step()
        self.assertEqual(self.fixture.posted(), [])
        self.assertTrue(any("arrived at" in line and "during the proof; nothing was posted" in line
                            for line in self.fixture.log_lines))

    def test_the_token_reaches_exactly_one_subprocess_and_only_through_its_environment(self):
        self.fixture.step()
        carrying = [call for call in self.fixture.calls if (call["env"] or {}).get("GH_TOKEN") == TOKEN]
        self.assertEqual(len(carrying), 1, "exactly one command may hold the token")
        self.assertEqual(carrying[0]["argv"][:3], ("gh", "pr", "comment"))
        for call in self.fixture.calls:
            self.assertNotIn(TOKEN, " ".join(call["argv"]), "the token is never an argument")
            if call["argv"][:3] != ("gh", "pr", "comment"):
                self.assertNotEqual((call["env"] or {}).get("GH_TOKEN"), TOKEN)
        for line in self.fixture.log_lines:
            self.assertNotIn(TOKEN, line, "the token is never logged")
        self.assertFalse(
            (self.fixture.repo / ".git" / "promoter-receipt.md").exists(),
            "the composed receipt file is removed after posting",
        )

    def test_an_unconfigured_helper_composes_and_posts_nothing(self):
        self.fixture.step(helper="")
        self.assertEqual(self.fixture.posted(), [])
        self.assertEqual(self.fixture.writes(), [])
        self.assertTrue(any("receipt posting not configured" in line for line in self.fixture.log_lines))

    def test_a_dry_run_proves_and_validates_but_posts_nothing(self):
        self.fixture.step(dry_run=True)
        self.assertEqual(self.fixture.posted(), [])
        self.assertEqual(self.fixture.writes(), [])
        self.assertTrue(any("WOULD post a validated receipt" in line for line in self.fixture.log_lines))

    def test_a_head_that_moves_between_proof_and_post_aborts(self):
        original = self.fixture.wire

        def move_head_on_live_read():
            original()
            pull = dict(self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"])
            pull["head"] = dict(pull["head"], sha="d" * 40)
            self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"] = pull

        pr = MODULE.owned_pull_request(self.fixture.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls/300"])
        pr["behind_by"] = 0
        workspace = self.fixture.workspace()
        judged = MODULE.prove_promotion(workspace, self.fixture.github(), self.fixture.fleet.registry(), self.fixture.fleet.cosign(), pr)
        move_head_on_live_read()
        posted = MODULE.post_receipt(
            workspace, self.fixture.github(), self.fixture.run, HELPER, 300, self.head, judged[1], False
        )
        self.assertFalse(posted)
        self.assertEqual(self.fixture.posted(), [])
        self.assertTrue(any("head moved between proof and post" in line for line in self.fixture.log_lines))

    def test_a_receipt_the_validator_rejects_is_never_posted(self):
        workspace = self.fixture.workspace()
        with self.assertRaises(MODULE.Refusal):
            MODULE.post_receipt(
                workspace, self.fixture.github(), self.fixture.run, HELPER, 300, self.head,
                "HEAD: " + self.head + "\nVERDICT: MAYBE\n\n- Promoter (adversarial reviewer)\n", False,
            )
        self.assertEqual(self.fixture.posted(), [])
        self.assertFalse((self.fixture.repo / ".git" / "promoter-receipt.md").exists())

class CallTracingTests(unittest.TestCase):
    """Owner direction 2026-09-04, after a `cosign verify` held the full
    600-second command bound and left one line ten minutes later: every long
    call announces itself with its budget and reports what it cost, cosign is
    bounded short with one retry, and each tick ends in one summary line."""

    def setUp(self):
        self.fixture = ProofFixture(self)

    def test_cosign_is_bounded_short_and_retried_exactly_once(self):
        self.assertEqual((MODULE.COSIGN_TIMEOUT_SECONDS, MODULE.COSIGN_ATTEMPTS), (120, 2))
        self.assertLess(MODULE.COSIGN_TIMEOUT_SECONDS, MODULE.COMMAND_TIMEOUT_SECONDS)
        stalls = []

        def stalling(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["cosign", "verify"]:
                stalls.append(timeout)
                raise MODULE.Refusal(f"`cosign verify` exceeded {timeout}s and its process group was killed")
            return self.fixture.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)

        cosign = MODULE.Cosign(run=stalling, pinned_version="v3.1.3")
        with self.assertRaisesRegex(MODULE.Refusal, "exceeded 120s"):
            cosign.verify_chart("ghcr.io/snaraj/charts/naranjo-online", "sha256:" + "a" * 64, "subject")
        self.assertEqual(stalls, [MODULE.COSIGN_TIMEOUT_SECONDS] * MODULE.COSIGN_ATTEMPTS,
                         "each attempt carries the short budget, and there are exactly two")
        lines = self.fixture.log_lines
        self.assertTrue(any("START cosign-verify-chart" in line and "attempt=1/2" in line and "budget=120s" in line for line in lines), lines)
        self.assertTrue(any("FAILED decision=retry" in line and "attempt=1/2" in line for line in lines), lines)
        self.assertTrue(any("FAILED decision=refuse" in line and "attempt=2/2" in line for line in lines), lines)
        # A recovering second attempt is a logged retry, not a refusal.
        self.fixture.log_lines.clear()
        attempts = []

        def flaky(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["cosign", "verify"]:
                attempts.append(argv)
                if len(attempts) == 1:
                    raise MODULE.Refusal("`cosign verify` exceeded 120s and its process group was killed")
            return self.fixture.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)

        MODULE.Cosign(run=flaky, pinned_version="v3.1.3").verify_chart(
            self.fixture.fleet.chart_repo, self.fixture.fleet.manifest_digest, "subject"
        )
        self.assertEqual(len(attempts), 2)
        self.assertTrue(any("FAILED decision=retry" in line for line in self.fixture.log_lines))
        self.assertTrue(any("DONE cosign-verify-chart" in line and line.endswith("OK") for line in self.fixture.log_lines))

    def test_run_command_really_enforces_the_budget_it_is_given(self):
        # The budget is only a claim until a subprocess is actually killed by
        # it; this is the one test that proves the number reaches the kernel.
        with self.assertRaisesRegex(MODULE.Refusal, r"exceeded 1s and its process group was killed"):
            MODULE.run_command(["sh", "-c", "sleep 30"], timeout=1)

    def test_a_credential_bearing_command_never_has_its_output_recorded(self):
        # `quiet_output` exists for one call whose STDOUT IS THE CREDENTIAL.
        with self.assertRaisesRegex(MODULE.Refusal, "deliberately not recorded"):
            MODULE.run_command(["sh", "-c", "echo super-secret-token-value; exit 3"], quiet_output=True)
        for line in self.fixture.log_lines:
            self.assertNotIn("super-secret-token-value", line)
        # Without it the ordinary path DOES quote the failed command's output,
        # which is exactly why the flag is load-bearing rather than cosmetic.
        with self.assertRaises(MODULE.Refusal):
            MODULE.run_command(["sh", "-c", "echo ordinary-diagnostic; exit 3"])
        self.assertTrue(any("ordinary-diagnostic" in line for line in self.fixture.log_lines))

    def test_one_pass_traces_every_long_call_and_ends_in_one_summary(self):
        self.fixture.cut()
        self.assertEqual(self.fixture.receipt_pass(), 0)
        # `MODULE.log` is captured before it stamps, so these are the messages
        # themselves; the runbook's line shapes are these plus the timestamp.
        lines = self.fixture.log_lines
        starts = [line for line in lines if line.startswith("START ")]
        dones = [line for line in lines if line.startswith("DONE ")]
        self.assertEqual(len(starts), len(dones), "every START is answered by exactly one DONE")
        for kind in ("registry-token", "registry-manifest", "registry-blob",
                     "cosign-version", "cosign-verify-chart", "cosign-verify-provenance",
                     "github-api", "github-list", "release-asset", "git-fetch",
                     "receipt-token", "receipt-post"):
            named = [line for line in starts if line.startswith(f"START {kind} ")]
            self.assertTrue(named, (kind, starts))
            for line in named:
                self.assertRegex(line, r" budget=\d+s$")
        self.assertTrue(any(line.startswith("START git-fetch origin main budget=") for line in starts),
                        "the tick's first fetch is traced like every other call")
        self.assertTrue(any(line.startswith("START cosign-version ") and line.endswith("budget=120s") for line in starts),
                        "the cosign version check carries cosign's short budget")
        for line in dones:
            self.assertRegex(line, r"elapsed=\d+\.\d+s (OK$|FAILED decision=\S+ reason=)")
        for proof, outcome in (("novelty", "held"), ("confinement", "held"), ("re-derivation", "held"), ("claim-audit", "held")):
            self.assertTrue(
                any(line.startswith(f"PROOF {proof} ") and f" {outcome}" in line and "elapsed=" in line for line in lines),
                (proof, lines),
            )
        # The summary is one line, and it names this pull request's outcome.
        summaries = [line for line in lines if line.startswith("SUMMARY ")]
        self.assertEqual(len(summaries), 1, summaries)
        self.assertIn("receipt-300=posted:APPROVE", summaries[0])
        self.assertRegex(summaries[0], r"^SUMMARY receipt elapsed=\d+\.\d+s dry-run=False ")

    def test_no_secret_reaches_any_logged_line(self):
        self.fixture.cut()
        self.fixture.receipt_pass()
        for line in self.fixture.log_lines:
            self.assertNotIn(TOKEN, line)
            self.assertNotIn("GH_TOKEN", line)
            self.assertNotIn("Authorization", line)
            self.assertNotIn("Bearer ", line)
            self.assertNotIn("anonymous-pull", line, "the registry pull token is a credential too")

    def test_a_failed_call_names_the_decision_its_caller_would_take(self):
        # The same failure costs a cut everything and a receipt one tick; the
        # line says which, so nobody has to correlate two lines to find out.
        self.fixture.cut()
        with MODULE.failure_decision("skip-this-tick"), self.assertRaises(MODULE.Refusal):
            with MODULE.timed_call("registry-manifest", "example:1", 60):
                raise MODULE.Refusal("registry unreachable")
        self.assertTrue(any("decision=skip-this-tick" in line and "reason=registry unreachable" in line
                            for line in self.fixture.log_lines))
        self.fixture.log_lines.clear()
        with self.assertRaises(MODULE.Refusal):
            with MODULE.timed_call("registry-manifest", "example:1", 60):
                raise MODULE.Refusal("registry unreachable")
        self.assertTrue(any("decision=refuse" in line for line in self.fixture.log_lines),
                        "outside any declared block the default decision is the strict one")

    def test_a_refused_initial_fetch_leaves_a_start_and_a_done_line(self):
        # Finding 4 (2026-09-04): a forced initial-fetch failure used to
        # produce no START or DONE record at all.
        def refusing(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["git", "fetch"]:
                raise MODULE.Refusal("`git fetch` exceeded 600s and its process group was killed")
            return self.fixture.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout, quiet_output=quiet_output)

        with self.assertRaisesRegex(MODULE.Refusal, "exceeded 600s"):
            MODULE.Workspace(self.fixture.repo, refusing).refresh()
        lines = self.fixture.log_lines
        self.assertTrue(any(line.startswith("START git-fetch origin main budget=600s") for line in lines), lines)
        self.assertTrue(any(line.startswith("DONE git-fetch origin main ") and "FAILED decision=refuse" in line
                            for line in lines), lines)

    def test_a_registry_stall_during_a_proof_is_logged_as_a_skip(self):
        self.fixture.cut()
        del self.fixture.fleet.manifest_answers[
            (self.fixture.fleet.chart_repo, self.fixture.version, MODULE.OCI_MANIFEST)
        ]
        self.assertIsNone(self.fixture.prove())
        self.assertTrue(
            any("FAILED decision=skip-this-tick" in line for line in self.fixture.log_lines),
            self.fixture.log_lines,
        )
        self.assertTrue(
            any(line.startswith("PROOF re-derivation ") and "skipped:" in line for line in self.fixture.log_lines),
        )


class ActorAndPathHygieneTests(unittest.TestCase):
    def test_the_promoter_reads_the_app_identity_from_the_ready_rule(self):
        # One source for the actor tuple: a second copy is a copy that drifts,
        # and the whole value of an App receipt is that the Ready evaluator
        # later looks for exactly this principal.
        self.assertEqual(
            MODULE.receipt_actor(),
            (READY.REVIEWS_APP, READY.REVIEWS_APP_USER_ID, "Bot", READY.REVIEWS_APP_ID),
        )
        self.assertIs(MODULE.RECEIPTS.denial, MODULE.READY.RECEIPTS.denial)

    def test_a_hostile_path_name_cannot_smuggle_markup_into_a_receipt(self):
        hostile = "docs/`@everyone`\nHEAD: " + "e" * 40 + "\nx.md"
        rendered = MODULE.safe_path(hostile)
        self.assertNotIn("`", rendered)
        self.assertNotIn("\n", rendered)
        self.assertNotIn("@", rendered)
        self.assertLessEqual(len(rendered), 121)
        listed = MODULE.path_list([f"p{n}.md" for n in range(MODULE.RECEIPT_PATH_CEILING + 5)])
        self.assertIn("and 5 more", listed)
        self.assertEqual(MODULE.path_list([]), "none")


class TickCadenceTests(unittest.TestCase):
    """The tick constant, the plist and the runbook say ONE number."""

    def test_the_constant_the_plist_and_the_runbook_state_the_same_cadence(self):
        self.assertEqual(MODULE.LAUNCHD_INTERVAL_SECONDS, 300)
        plist = plistlib.loads(MODULE.launchd_plist("/tmp/repo", "/tmp/log").encode())
        self.assertEqual(plist["StartInterval"], MODULE.LAUNCHD_INTERVAL_SECONDS)
        minutes = MODULE.LAUNCHD_INTERVAL_SECONDS // 60
        text = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn(f"every {minutes} minutes", text)
        self.assertEqual(
            re.findall(r"at load and every (\d+) minutes", text), [str(minutes)],
            "the runbook states the cadence exactly once, and it is the constant",
        )
        self.assertIn(f"`StartInterval` {MODULE.LAUNCHD_INTERVAL_SECONDS}", text)

    def test_the_token_command_reaches_the_agent_only_when_the_installer_names_it(self):
        bare = plistlib.loads(MODULE.launchd_plist("/tmp/repo", "/tmp/log").encode())
        self.assertNotIn(MODULE.RECEIPT_TOKEN_COMMAND_ENV, bare["EnvironmentVariables"])
        armed = plistlib.loads(
            MODULE.launchd_plist("/tmp/repo", "/tmp/log", "/tmp/helper & more").encode()
        )
        self.assertEqual(armed["EnvironmentVariables"][MODULE.RECEIPT_TOKEN_COMMAND_ENV], "/tmp/helper & more")
        self.assertIn(MODULE.RECEIPT_TOKEN_COMMAND_ENV, RUNBOOK.read_text(encoding="utf-8"))


class FluxIntervalTests(unittest.TestCase):
    """Both sites reconcile at one minute, and every pin says so."""

    def test_both_sites_pin_one_minute_on_both_objects(self):
        for slug in SITES:
            for name in ("source.yaml", "release.yaml"):
                path = REPO_ROOT / "kubernetes" / "websites" / slug / name
                body = [
                    line for line in path.read_text(encoding="utf-8").splitlines()
                    if line.startswith("  interval:")
                ]
                self.assertEqual(body, ["  interval: 1m0s"], f"{slug}/{name}")

    def test_the_validators_pin_the_same_bound(self):
        self.assertEqual(SIGNATURE_POLICY.CHART_SOURCE_INTERVAL, "1m0s")
        for slug in SITES:
            self.assertIn(
                "  interval: 1m0s\n", SIGNATURE_POLICY.expected_chart_source_body(slug)
            )
            self.assertEqual(RELEASE_STATE.RELEASE_CONTRACTS[slug]["interval"], "1m0s")
        # The suspended connector is untouched: the shorter bound is the SITES'.
        self.assertEqual(RELEASE_STATE.RELEASE_CONTRACTS["cloudflare-public"]["interval"], "10m0s")

    def test_a_widened_interval_is_denied_by_the_signature_validator(self):
        path = REPO_ROOT / "kubernetes" / "websites" / "naranjo-online" / "source.yaml"
        text = path.read_text(encoding="utf-8")
        self.assertEqual(SIGNATURE_POLICY.chart_source_errors(text, "naranjo-online"), [])
        widened = text.replace("  interval: 1m0s\n", "  interval: 10m0s\n", 1)
        self.assertNotEqual(widened, text)
        self.assertTrue(SIGNATURE_POLICY.chart_source_errors(widened, "naranjo-online"))

    def test_no_flux_receiver_or_webhook_is_introduced(self):
        # The loop was shortened by polling, deliberately: a Receiver would add
        # an inbound path, a shared secret and a new object (issue #309).
        for path in sorted((REPO_ROOT / "kubernetes").rglob("*.yaml")):
            self.assertNotIn(
                "kind: Receiver", path.read_text(encoding="utf-8"), f"{path} introduces a Flux Receiver"
            )


class ContractTextTests(unittest.TestCase):
    def test_agents_states_the_earned_receipt_and_keeps_the_ready_rule_verbatim(self):
        text = AGENTS.read_text(encoding="utf-8")
        self.assertIn("NO TOOL FLIPS READY, promoter included", text)
        self.assertIn("is review evidence and nothing else: NO TOOL FLIPS READY, promoter included", text)
        # PR #312 round 1, finding 4: the tool's own claims say the same.
        self.assertIn("It holds\nno readiness authority: under AGENTS.md the coordinator flips Ready", MODULE.__doc__)
        self.assertNotIn("flips Ready ONLY", MODULE.__doc__)
        source = Path(MODULE.__file__).read_text(encoding="utf-8")
        self.assertNotIn("armed both review lanes", source)
        self.assertIn("and armed {', '.join(REVIEW_LABELS)}", source)
        # PR #312 round 2, finding 3: every tracked claim matches execution.
        self.assertNotIn("Nothing is read from the pull request", MODULE.__doc__)
        self.assertIn("be audited against those records, never believed", MODULE.__doc__)
        self.assertIn("A receipt attests\n  the head and nothing about the pull request's state", MODULE.__doc__)
        self.assertIn("all five proofs hold", source)
        self.assertNotIn("all four proofs hold", source)
        self.assertNotIn("runs\n        # every proof", source)
        index = (REPO_ROOT / "scripts" / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("arms both review lanes", index)
        self.assertIn("arms `requires-review`", index)
        self.assertIn("five proofs", index)
        self.assertIn("A promotion pull request's receipt is EARNED, not requested", text)
        self.assertIn("the security lane reviews every change to\n  the promoter's CODE", text)
        # The promoter's paragraph and the tool must name the same label set.
        for label in MODULE.PR_LABELS:
            self.assertIn(f"`{label}`", text)
        self.assertNotIn("and arm `requires-review` and\n  `cybersecurity-review-requested`", text)

    def test_the_runbook_lists_every_traced_call_shape(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("### Reading the log", text)
        # Every kind the tool can emit is documented, and the documented budget
        # is the constant: a new traced call with no runbook line is a red test.
        for kind in ("registry-token", "registry-manifest", "registry-blob",
                     "release-asset", "cosign-verify-chart", "cosign-verify-provenance",
                     "github-api", "github-list", "github-write", "github-command",
                     "git-fetch", "git-push", "gate", "receipt-token", "receipt-post"):
            self.assertIn(f"`{kind}`", text, kind)
        flowed = " ".join(text.split())
        self.assertIn(
            f"bounded at {MODULE.COSIGN_TIMEOUT_SECONDS} seconds per attempt with exactly one retry",
            flowed,
            "the runbook states cosign's budget, and it is the constant",
        )
        for decision in ("retry", "refuse", "skip-this-tick"):
            self.assertIn(decision, text)

    def test_the_runbook_documents_what_is_proven_and_what_is_not_automated(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("## Receipts by proof", text)
        self.assertIn("**What is NOT automated.** Ready and merge.", text)
        self.assertIn("reports itself unconfigured and composes nothing; no proof runs", text)
        self.assertNotIn("still runs every proof", text)
        self.assertIn("5. **Identity.**", text)
        self.assertIn("definitive failure of proof 2, 3, 4 or 5", text)
        self.assertIn("interval: 1m0s", text.replace("`interval: 1m0s`", "interval: 1m0s"))
        self.assertIn("no Flux `Receiver`", text)
        self.assertIn(MODULE.RECEIPT_TOKEN_COMMAND_ENV, text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
