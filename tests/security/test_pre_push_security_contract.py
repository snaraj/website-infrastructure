#!/usr/bin/env python3
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .support import hermetic_git_environment, load_script, required_tool


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "pre-push-security.sh"
HISTORY = ROOT / "scripts" / "validate_publication_history.py"
# Loaded for its published-label table alone. The battery still drives the
# validator as a subprocess, exactly as the hook does; importing it here only
# lets an assertion compare emitted labels against the module's own vocabulary
# instead of restating that vocabulary in a list that would drift.
HISTORY_MODULE = load_script("validate_publication_history.py")
HOOK = ROOT / ".githooks" / "pre-push"
BASH = shutil.which("bash")
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)
BASH_REQUIRED = "bash is required for the pre-push contract"
GITLEAKS = shutil.which("gitleaks")
GITLEAKS_REQUIRED = "the pinned Gitleaks is required for policy behavior"
if GITLEAKS is None:
    candidate = (
        ROOT / ".artifacts" / "test-tools" / "gitleaks-v8.30.1" / "gitleaks.exe"
    )
    if candidate.is_file():
        GITLEAKS = str(candidate)


def run_git(repository, *arguments, **kwargs):
    # Every fixture git invocation pins its own author/committer from the
    # fixture repository's local config: ambient GIT_AUTHOR_*/GIT_COMMITTER_*
    # exports override `git config` identity and would otherwise rewrite the
    # very history a fixture is asserting on (see hermetic_git_environment).
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True,
        capture_output=True, env=hermetic_git_environment(repository), **kwargs
    )


def initialize_history_repository(directory):
    repository = Path(directory) / "history-repo"
    repository.mkdir()
    run_git(repository, "init", "-q")
    run_git(repository, "config", "user.name", "Synthetic")
    run_git(repository, "config", "user.email", "synthetic@example.invalid")
    run_git(repository, "config", "core.autocrlf", "false")
    (repository / "README.md").write_text("synthetic history\n", encoding="utf-8")
    run_git(repository, "add", "README.md")
    run_git(repository, "commit", "-qm", "baseline")
    baseline = run_git(repository, "rev-parse", "HEAD", text=True).stdout.strip()
    return repository, baseline


def run_history_validator(repository, baseline, candidate, *options):
    # The validator only observes history the fixtures already built, so no
    # identity is pinned here; the scrub still keeps ambient GIT_DIR-style
    # redirection from pointing its git subprocesses at a foreign repository.
    return subprocess.run(
        [sys.executable, "-I", str(HISTORY), *options, baseline, candidate],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        env=hermetic_git_environment(),
    )


def synthetic_sops_documents():
    recipient = "age1pq1" + ("q" * 58)

    def envelope(value):
        encoded = base64.b64encode(value).decode("ascii")
        iv = base64.b64encode(b"i" * 12).decode("ascii")
        tag = base64.b64encode(b"t" * 16).decode("ascii")
        return "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]".format(
            encoded, iv, tag
        )

    age_payload = base64.b64encode(
        b"age-encryption.org/v1\n-> X25519 synthetic\n--- synthetic\n"
    ).decode("ascii")
    armored_lines = "\n".join(
        "        " + age_payload[index:index + 64]
        for index in range(0, len(age_payload), 64)
    )
    config = (
        "creation_rules:\n"
        "  - path_regex: ^kubernetes/.+\\.sops\\.ya?ml$\n"
        "    encrypted_regex: ^(data|stringData)$\n"
        "    age:\n"
        "      - " + recipient + "\n"
    )
    secret = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: pi-websites-tunnel-token\n"
        "  namespace: cloudflare-public\n"
        "type: Opaque\n"
        "stringData:\n"
        "  token: " + envelope(b"synthetic-token-value") + "\n"
        "sops:\n"
        "  age:\n"
        "    - recipient: " + recipient + "\n"
        "      enc: |\n"
        "        -----BEGIN AGE ENCRYPTED FILE-----\n"
        + armored_lines + "\n"
        "        -----END AGE ENCRYPTED FILE-----\n"
        '  lastmodified: "2026-08-09T00:00:00Z"\n'
        "  mac: " + envelope(b"synthetic-mac") + "\n"
        "  encrypted_regex: ^(data|stringData)$\n"
        "  version: 3.13.3\n"
    )
    return config, secret


def synthetic_api_encryption_configuration(secret):
    return (
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "resources:\n"
        "  - resources:\n"
        "      - secrets\n"
        "    providers:\n"
        "      - secretbox:\n"
        "          keys:\n"
        "            - name: key-2026-08\n"
        "              secret: " + secret + "\n"
        "      - identity: {}\n"
    )


@unittest.skipUnless(BASH, "bash is required for the pre-push contract")
class PrePushSecurityContractTests(unittest.TestCase):
    def test_shell_sources_parse(self):
        for path in (SCRIPT, HOOK):
            with self.subTest(path=path.name):
                subprocess.run(
                    [required_tool(BASH, BASH_REQUIRED), "-n", str(path)],
                    check=True,
                )

    def test_hook_is_bound_to_one_exact_non_delete_branch_update(self):
        text = HOOK.read_text(encoding="utf-8")
        self.assertIn('[[ "${remote_name}" == origin ]]', text)
        self.assertIn("https://github.com/snaraj/website-infrastructure.git", text)
        self.assertIn('[[ "${updates}" -eq 1', text)
        self.assertIn('[[ "${local_ref}" == refs/heads/* ]]', text)
        self.assertIn('[[ "${remote_ref}" == refs/heads/* ]]', text)
        self.assertIn('[[ "${local_ref}" == "${remote_ref}" ]]', text)
        self.assertIn('! "${local_sha}" =~ ^0{40}$', text)
        self.assertIn('merge-base --is-ancestor "${remote_sha}" "${local_sha}"', text)
        self.assertIn('ls-remote --exit-code "${remote_url}"', text)
        self.assertIn('"${advertised_ref}" == refs/heads/main', text)
        self.assertIn(
            'pre-push-security.sh" "${baseline}" "${candidate}"', text
        )

    def test_gate_requires_clean_full_history_and_pinned_redacted_scan(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for fragment in (
            "rev-parse --is-shallow-repository",
            "diff --cached --quiet",
            "ls-files --others --exclude-standard",
            '"${repo_root}" all',
            "validate_publication_history.py",
            '"${baseline}" "${candidate}"',
            '"${candidate_path}" -I -B -c',
            "GITLEAKS_VERSION",
            "gitleaks git",
            "--redact",
            "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path=",
            "--max-archive-depth=1",
            "--max-decode-depth=1",
            "--max-target-megabytes=2",
            '--log-opts="${baseline}..${candidate}"',
            "trap abort HUP INT TERM",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_mocked_hook_passes_the_exact_git_supplied_commit_to_history_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "repo"
            repo.mkdir()
            (repo / "scripts").mkdir()
            (repo / ".githooks").mkdir()
            (repo / "policies").mkdir()
            shutil.copy2(SCRIPT, repo / "scripts" / SCRIPT.name)
            shutil.copy2(HISTORY, repo / "scripts" / HISTORY.name)
            shutil.copy2(HOOK, repo / ".githooks" / HOOK.name)
            (repo / "scripts" / "validate_repository.py").write_text(
                "import sys\n"
                "raise SystemExit(0 if sys.argv[1:] == ['all'] else 91)\n",
                encoding="utf-8",
            )
            for module in (
                "validate_image_release", "validate_release_state",
                "validate_release_transition", "workload_registry",
                "validate_signature_policy",
            ):
                (repo / "scripts" / (module + ".py")).write_text(
                    "# exact synthetic dependency\n", encoding="utf-8"
                )
            (repo / "policies" / "gitleaks.toml").write_text(
                'title = "synthetic"\n', encoding="utf-8"
            )
            (repo / "versions.env").write_text(
                "GITLEAKS_VERSION=v8.30.1\n", encoding="utf-8"
            )
            binary_dir = repo / "tool-bin"
            binary_dir.mkdir()
            mock_binary = binary_dir / "gitleaks"
            with mock_binary.open("w", encoding="utf-8", newline="\n") as output:
                output.write(
                    "#!/usr/bin/env bash\n"
                    "if [[ \"${1:-}\" == version ]]; then printf '8.30.1'; exit 0; fi\n"
                    "printf '%s\\n' \"$@\" > \"${MOCK_GITLEAKS_LOG}\"\n"
                )
            mock_binary.chmod(0o700)
            run_git(repo, "init", "-q")
            run_git(repo, "config", "user.name", "Synthetic")
            run_git(repo, "config", "user.email", "synthetic@example.invalid")
            run_git(repo, "config", "core.autocrlf", "false")
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-qm", "baseline fixture")
            baseline = run_git(repo, "rev-parse", "HEAD", text=True).stdout.strip()
            advertised_remote = base / "advertised.git"
            run_git(base, "init", "--bare", "-q", str(advertised_remote))
            run_git(
                repo, "push", "-q", str(advertised_remote),
                baseline + ":refs/heads/main",
            )
            advertised_url = advertised_remote.resolve().as_uri()
            for exact_remote in (
                "https://github.com/snaraj/website-infrastructure.git",
                "git" + "@" + "github.com:snaraj/website-infrastructure.git",
            ):
                run_git(
                    repo, "config", "--add",
                    "url." + advertised_url + ".insteadOf", exact_remote,
                )
            run_git(repo, "update-ref", "refs/remotes/origin/main", baseline)
            (repo / "safe.txt").write_text("outgoing fixture\n", encoding="utf-8")
            run_git(repo, "add", "safe.txt")
            run_git(repo, "commit", "-qm", "outgoing fixture")
            commit = run_git(repo, "rev-parse", "HEAD", text=True).stdout.strip()
            run_git(repo, "update-ref", "refs/remotes/origin/main", commit)
            call_log = base / "gitleaks-arguments.txt"
            # The hook run itself starts from the same scrubbed environment:
            # its git plumbing must see the fixture repository, not whatever
            # GIT_DIR/GIT_CONFIG_* the invoking shell happens to export. The
            # deliberate additions below are layered on top of the scrub.
            environment = hermetic_git_environment(repo)
            environment["PATH"] = str(binary_dir) + os.pathsep + environment["PATH"]
            # The exact GitHub URLs are rewritten to the disposable bare repo;
            # forbidding every non-file transport makes accidental network use
            # impossible if that test configuration ever regresses.
            environment["GIT_ALLOW_PROTOCOL"] = "file"
            environment["MOCK_GITLEAKS_LOG"] = str(call_log)
            ambient = base / "ambient-python"
            ambient.mkdir()
            sentinel = base / "sitecustomize-executed.txt"
            (ambient / "sitecustomize.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['INJECTION_SENTINEL']).write_text('executed')\n",
                encoding="utf-8",
            )
            environment["PYTHONPATH"] = str(ambient)
            environment["INJECTION_SENTINEL"] = str(sentinel)
            ssh_remote = "git" + "@" + "github.com:snaraj/website-infrastructure.git"
            for remote_url in (
                "https://github.com/snaraj/website-infrastructure.git",
                ssh_remote,
            ):
                for remote_sha in ("0" * 40, baseline):
                    with self.subTest(remote_url=remote_url, remote_sha=remote_sha):
                        update = (
                            "refs/heads/review {} refs/heads/review {}\n".format(
                                commit, remote_sha
                            )
                        )
                        result = subprocess.run(
                            [
                                required_tool(BASH, BASH_REQUIRED),
                                str(repo / ".githooks" / "pre-push"),
                                "origin",
                                remote_url,
                            ],
                            cwd=repo,
                            input=update,
                            text=True,
                            capture_output=True,
                            env=environment,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        arguments = call_log.read_text(encoding="utf-8")
                        self.assertIn(
                            "--log-opts=" + baseline + ".." + commit, arguments
                        )
                        self.assertIn("--redact", arguments)
                        self.assertIn("--ignore-gitleaks-allow", arguments)
                        self.assertIn("--max-archive-depth=1", arguments)
                        self.assertIn("--max-target-megabytes=2", arguments)
                        self.assertFalse(sentinel.exists())


class PublicationHistoryValidatorTests(unittest.TestCase):
    def test_gitleaks_policy_has_no_global_suppression_and_has_bare_token_rule(self):
        policy = (ROOT / "policies" / "gitleaks.toml").read_text(encoding="utf-8")
        self.assertNotIn("[allowlist]", policy)
        self.assertIn('id = "bare-cloudflare-tunnel-runtime-token"', policy)
        self.assertIn("[A-Za-z0-9+/]{77,}", policy)
        self.assertIn('id = "kubernetes-api-encryption-secretbox-key"', policy)
        self.assertIn("[A-Za-z0-9+/]{43}=", policy)

    def test_allows_one_safe_outgoing_commit_with_github_noreply_author(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            noreply = "123+synthetic" + "@" + "users.noreply.github.com"
            run_git(repository, "config", "user.email", noreply)
            (repository / "safe.txt").write_text("reviewed value\n", encoding="utf-8")
            media = (
                repository
                / "websites/naranjo.online/frontend/src/assets/images/pixel.jpg"
            )
            media.parent.mkdir(parents=True)
            media.write_bytes(bytes((0xFF, 0xD8, 0xFF, 0xD9)))
            run_git(
                repository,
                "add",
                "safe.txt",
                media.relative_to(repository).as_posix(),
            )
            run_git(repository, "commit", "-m", "safe outgoing commit")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("1 outgoing commit(s) scanned", result.stdout)

    def test_pull_request_mode_scans_a_related_divergent_base_to_head_range(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, shared = initialize_history_repository(directory)
            run_git(repository, "checkout", "-qb", "candidate", shared)
            (repository / "candidate.txt").write_text("safe candidate\n", encoding="utf-8")
            run_git(repository, "add", "candidate.txt")
            run_git(repository, "commit", "-qm", "candidate change")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            run_git(repository, "checkout", "-qb", "base", shared)
            (repository / "base.txt").write_text("safe base\n", encoding="utf-8")
            run_git(repository, "add", "base.txt")
            run_git(repository, "commit", "-qm", "base change")
            baseline = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            push_result = run_history_validator(repository, baseline, candidate)
            pull_request_result = run_history_validator(
                repository, baseline, candidate, "--pull-request"
            )

            self.assertNotEqual(push_result.returncode, 0)
            self.assertEqual(pull_request_result.returncode, 0, pull_request_result.stderr)
            self.assertIn("1 outgoing commit(s) scanned", pull_request_result.stdout)

    def test_allows_encrypted_values_in_the_exact_approved_sops_path(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            relative = Path(
                "kubernetes/platform/cloudflare-public/release/"
                "tunnel-token.sops.yaml"
            )
            path = repository / relative
            path.parent.mkdir(parents=True)
            config, secret = synthetic_sops_documents()
            path.write_text(secret, encoding="utf-8")
            (repository / ".sops.yaml").write_text(config, encoding="utf-8")
            run_git(repository, "add", relative.as_posix(), ".sops.yaml")
            run_git(repository, "commit", "-m", "encrypted synthetic fixture")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_allows_only_the_exact_inert_tunnel_token_structural_example(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            relative = Path(
                "kubernetes/platform/cloudflare-public/examples/"
                "tunnel-token.invalid-example.yaml"
            )
            path = repository / relative
            path.parent.mkdir(parents=True)
            source = ROOT / relative
            exact_bytes = source.read_bytes()
            path.write_bytes(exact_bytes)
            run_git(repository, "add", relative.as_posix())
            run_git(repository, "commit", "-m", "exact structural example")
            exact_candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            exact_result = run_history_validator(
                repository, baseline, exact_candidate
            )

            self.assertEqual(exact_result.returncode, 0, exact_result.stderr)

            path.write_bytes(exact_bytes.replace(b"INTENTIONALLY_UNUSABLE", b"MUTATED"))
            run_git(repository, "add", relative.as_posix())
            run_git(repository, "commit", "-m", "mutated structural example")
            mutated_candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            mutated_result = run_history_validator(
                repository, baseline, mutated_candidate
            )

            self.assertNotEqual(mutated_result.returncode, 0)
            self.assertIn(
                "unencrypted Kubernetes Secret manifest", mutated_result.stderr
            )
            self.assertNotIn(relative.name, mutated_result.stderr)

    def test_rejects_a_secret_added_then_deleted_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            secret = "AGE-SECRET-" + "KEY-PQ-1" + ("A" * 96)
            secret_path = repository / "transient.txt"
            secret_path.write_text(secret + "\n", encoding="utf-8")
            run_git(repository, "add", "transient.txt")
            run_git(repository, "commit", "-m", "temporary material")
            secret_path.unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove temporary material")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("age private identity", combined)
            self.assertNotIn(secret, combined)
            self.assertNotIn("transient.txt", combined)

    def test_every_finding_line_is_label_commit_and_path_digest_only(self):
        """The diagnostic shape itself, not one more not-echoed example.

        The tests around this one each prove that a particular value stayed out
        of a particular message. This one pins the grammar every finding line
        must obey — a label, a validated commit id, and a truncated digest of
        the path — and pins that the label came from the module's own table of
        published labels rather than from anything the validator read. That is
        the property which makes 'this validator cannot leak what it inspects'
        a structural fact instead of a case-by-case observation, and it is what
        a diagnostic that started interpolating matched content would break.
        """

        line_grammar = re.compile(
            r"^FAIL publication history: (?P<label>[^;]+); commit=(?P<commit>[0-9a-f]{40})"
            r"(?:; path_sha256=(?P<digest>[0-9a-f]{16}))?$"
        )
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            identity = "AGE-SECRET-" + "KEY-PQ-1" + ("A" * 96)
            relative = "notes/quarterly-review-draft.txt"
            target = repository / relative
            target.parent.mkdir(parents=True)
            target.write_text(identity + "\n", encoding="utf-8")
            run_git(repository, "add", relative)
            run_git(repository, "commit", "-m", "draft notes")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertNotIn(identity, combined)
            self.assertNotIn(relative, combined)
            self.assertNotIn("quarterly-review-draft", combined)

            reported = [line for line in result.stderr.splitlines() if line.strip()]
            self.assertNotEqual(reported, [])
            published_labels = set(HISTORY_MODULE.PROHIBITED_CONTENT_PATTERNS)
            expected_digest = hashlib.sha256(
                relative.encode("utf-8")
            ).hexdigest()[:16]
            for line in reported:
                with self.subTest(line=line):
                    match = line_grammar.fullmatch(line)
                    if match is None:
                        self.fail("finding line escaped the grammar: {!r}".format(line))
                    self.assertIn(match.group("label"), published_labels)
                    self.assertEqual(match.group("commit"), candidate)
                    self.assertEqual(match.group("digest"), expected_digest)

    def test_rejects_renamed_api_encryption_config_added_then_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            synthetic_key = base64.b64encode(bytes(range(32))).decode("ascii")
            target = repository / "notes" / "review.txt"
            target.parent.mkdir(parents=True)
            target.write_text(
                synthetic_api_encryption_configuration(synthetic_key),
                encoding="utf-8",
            )
            run_git(repository, "add", "notes/review.txt")
            run_git(repository, "commit", "-m", "temporary encryption config")
            target.unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove encryption config")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "plaintext Kubernetes API encryption configuration", combined
            )
            self.assertNotIn(synthetic_key, combined)
            self.assertNotIn("notes/review.txt", combined)

    def test_allows_api_encryption_sentinel_example_in_history(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            target = repository / "encryption-config.yaml.example"
            target.write_text(
                synthetic_api_encryption_configuration(
                    "REPLACE_BASE64_32_BYTE_KEY"
                ),
                encoding="utf-8",
            )
            run_git(repository, "add", target.name)
            run_git(repository, "commit", "-m", "safe sentinel example")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_deleted_archive_and_historical_symbolic_mode(self):
        for unsafe_kind in ("archive", "link"):
            with self.subTest(unsafe_kind=unsafe_kind), tempfile.TemporaryDirectory() as directory:
                repository, baseline = initialize_history_repository(directory)
                if unsafe_kind == "archive":
                    path = repository / "opaque.zip"
                    path.write_bytes(b"PK" + bytes((3, 4)) + b"synthetic")
                    run_git(repository, "add", "opaque.zip")
                else:
                    blob = run_git(
                        repository,
                        "hash-object",
                        "-w",
                        "--stdin",
                        input=b"synthetic-target\n",
                    ).stdout.decode("ascii").strip()
                    run_git(
                        repository,
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        "120000," + blob + ",transient-link",
                    )
                run_git(repository, "commit", "-m", "temporary unsafe object")
                if unsafe_kind == "archive":
                    (repository / "opaque.zip").unlink()
                    run_git(repository, "add", "-u")
                else:
                    run_git(repository, "update-index", "--force-remove", "transient-link")
                run_git(repository, "commit", "-m", "remove unsafe object")
                candidate = run_git(
                    repository, "rev-parse", "HEAD", text=True
                ).stdout.strip()

                result = run_history_validator(repository, baseline, candidate)

                self.assertNotEqual(result.returncode, 0)
                expected = (
                    "forbidden local-only path"
                    if unsafe_kind == "archive"
                    else "symbolic or unsupported Git mode"
                )
                self.assertIn(expected, result.stderr)
                self.assertNotIn("opaque.zip", result.stderr)
                self.assertNotIn("transient-link", result.stderr)

    def test_rejects_historical_media_outside_assets_svg_and_data_uri(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            (repository / "photo.jpg").write_bytes(bytes((0xFF, 0xD8, 0xFF, 0xD9)))
            (repository / "renamed.txt").write_text(
                "  <svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n",
                encoding="utf-8",
            )
            embedded = "data:" + "image/png;base64," + ("A" * 24)
            (repository / "embedded.md").write_text(embedded + "\n", encoding="utf-8")
            unknown_media = (
                repository / "websites/unapproved.invalid/frontend/src/assets/photo.jpg"
            )
            unknown_media.parent.mkdir(parents=True)
            unknown_media.write_bytes(bytes((0xFF, 0xD8, 0xFF, 0xD9)))
            run_git(
                repository,
                "add",
                "photo.jpg",
                "renamed.txt",
                "embedded.md",
                unknown_media.relative_to(repository).as_posix(),
            )
            run_git(repository, "commit", "-m", "temporary media")
            for name in ("photo.jpg", "renamed.txt", "embedded.md"):
                (repository / name).unlink()
            unknown_media.unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove temporary media")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("media outside approved frontend asset tree", result.stderr)
            self.assertIn("embedded media data URI", result.stderr)
            for name in ("photo.jpg", "renamed.txt", "embedded.md"):
                self.assertNotIn(name, result.stderr)
            self.assertNotIn("unapproved.invalid", result.stderr)

    def test_rejects_noncanonical_historical_kubernetes_secret_kinds(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            root = repository / "kubernetes"
            root.mkdir()
            documents = {
                "quoted.yaml": 'apiVersion: v1\n"kind": "' + "Secret" + '"\n',
                "tagged.yaml": "apiVersion: v1\nkind: !tag " + "Secret" + "\n",
                "aliased.yaml": "apiVersion: v1\nkind: *synthetic\n",
                "escaped.yaml": 'apiVersion: v1\nkind: "Secr' + "\\u0065t" + '"\n',
                "flow.yaml": "{apiVersion: v1, kind: " + "Secret" + "}\n",
            }
            for name, document in documents.items():
                (root / name).write_text(document, encoding="utf-8")
            run_git(repository, "add", "kubernetes")
            run_git(repository, "commit", "-m", "temporary noncanonical manifests")
            for name in documents:
                (root / name).unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove noncanonical manifests")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unencrypted Kubernetes Secret manifest", result.stderr)
            for name in documents:
                self.assertNotIn(name, result.stderr)

    def test_rejects_short_armored_ciphertext_with_a_harmless_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            age_armor = "-----BEGIN " + "AGE ENCRYPTED FILE-----\nshort\n"
            openssl_armor = "U2Fs" + "dGVkX1" + "synthetic\n"
            (repository / "note.txt").write_text(age_armor, encoding="utf-8")
            (repository / "other.txt").write_text(openssl_armor, encoding="utf-8")
            run_git(repository, "add", "note.txt", "other.txt")
            run_git(repository, "commit", "-m", "temporary armored data")
            (repository / "note.txt").unlink()
            (repository / "other.txt").unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove armored data")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("archive or encrypted artifact", result.stderr)
            self.assertNotIn(age_armor, result.stderr)
            self.assertNotIn(openssl_armor, result.stderr)

    def test_rejects_every_current_opaque_filename_pattern_in_deleted_history(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            names = (
                "payload.token", "payload.bin", "payload.blob", "payload.tar.part",
                "api-encryption-config.yaml", "encryption-config.yaml.local",
            )
            for name in names:
                (repository / name).write_text("synthetic\n", encoding="utf-8")
            run_git(repository, "add", *names)
            run_git(repository, "commit", "-m", "temporary opaque paths")
            for name in names:
                (repository / name).unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove opaque paths")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden local-only path", result.stderr)
            for name in names:
                self.assertNotIn(name, result.stderr)

    def test_rejects_private_commit_message_or_author_without_echoing_it(self):
        for field in ("message", "author"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                repository, baseline = initialize_history_repository(directory)
                private_address = "operator" + "@" + "private" + ".example"
                if field == "author":
                    run_git(repository, "config", "user.email", private_address)
                (repository / "safe.txt").write_text("safe\n", encoding="utf-8")
                run_git(repository, "add", "safe.txt")
                message = (
                    "contact " + private_address if field == "message" else "safe metadata"
                )
                run_git(repository, "commit", "-m", message)
                candidate = run_git(
                    repository, "rev-parse", "HEAD", text=True
                ).stdout.strip()

                result = run_history_validator(repository, baseline, candidate)

                combined = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("commit metadata non-private email address", combined)
                self.assertNotIn(private_address, combined)

    def test_rejects_blob_above_the_publication_ceiling_without_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            (repository / "oversized.txt").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            run_git(repository, "add", "oversized.txt")
            run_git(repository, "commit", "-m", "oversized object")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("blob exceeds publication size ceiling", result.stderr)
            self.assertNotIn("oversized.txt", result.stderr)

    def test_rejects_plaintext_in_the_approved_sops_path_then_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, baseline = initialize_history_repository(directory)
            relative = Path(
                "kubernetes/platform/cloudflare-public/release/"
                "tunnel-token.sops.yaml"
            )
            path = repository / relative
            path.parent.mkdir(parents=True)
            config, _valid_secret = synthetic_sops_documents()
            (repository / ".sops.yaml").write_text(config, encoding="utf-8")
            path.write_text(
                "apiVersion: v1\nkind: Secret\nmetadata:\n"
                "  name: synthetic\nstringData:\n  token: ENC[synthetic]\n"
                "sops:\n  age: []\n",
                encoding="utf-8",
            )
            run_git(repository, "add", relative.as_posix(), ".sops.yaml")
            run_git(repository, "commit", "-m", "temporary malformed ciphertext")
            path.unlink()
            run_git(repository, "add", "-u")
            run_git(repository, "commit", "-m", "remove malformed ciphertext")
            candidate = run_git(
                repository, "rev-parse", "HEAD", text=True
            ).stdout.strip()

            result = run_history_validator(repository, baseline, candidate)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid historical SOPS Secret", result.stderr)
            self.assertNotIn(relative.as_posix(), result.stderr)

    @unittest.skipUnless(GITLEAKS, "pinned Gitleaks is required for policy behavior")
    def test_gitleaks_detects_bare_standard_base64_tunnel_and_quoted_bearer(self):
        tunnel = "eyJ" + ("A" * 37) + "+/" + ("B" * 40) + "="
        bearer = "Z" * 40
        payloads = (
            tunnel,
            "ENC[AES256_GCM,data:" + tunnel + ",iv:synthetic]",
            tunnel + " # " + "gitleaks:" + "allow",
            '{"Author' + 'ization": "Bearer ' + bearer + '"}',
        )
        for payload in payloads:
            with self.subTest(payload_kind=payload[:3]), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "candidate.txt"
                target.write_text(payload + "\n", encoding="utf-8")
                result = subprocess.run(
                    [
                        required_tool(GITLEAKS, GITLEAKS_REQUIRED),
                        "dir",
                        "--no-banner",
                        "--redact",
                        "--ignore-gitleaks-allow",
                        "--config",
                        str(ROOT / "policies" / "gitleaks.toml"),
                        directory,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(payload, result.stdout + result.stderr)

    @unittest.skipUnless(GITLEAKS, "pinned Gitleaks is required for policy behavior")
    def test_gitleaks_rejects_api_encryption_key_and_allows_sentinel(self):
        synthetic_key = base64.b64encode(bytes(range(32))).decode("ascii")
        candidates = (
            ("              secret: " + synthetic_key + "\n", 1),
            ("              secret: REPLACE_BASE64_32_BYTE_KEY\n", 0),
        )
        for payload, expected in candidates:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "candidate.txt"
                target.write_text(payload, encoding="utf-8")
                result = subprocess.run(
                    [
                        required_tool(GITLEAKS, GITLEAKS_REQUIRED),
                        "dir",
                        "--no-banner",
                        "--redact",
                        "--ignore-gitleaks-allow",
                        "--config",
                        str(ROOT / "policies" / "gitleaks.toml"),
                        directory,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertNotIn(synthetic_key, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
