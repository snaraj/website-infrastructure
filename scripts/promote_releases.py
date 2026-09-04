"""Receipted release promotion: a published release opens its own reviewed
promotion pull request, and the owner's merge is the only human touch
(issue #286).

Design, in the order the ``tick`` runs it:

* **Discovery.** Promotable workloads are read from the manifests, never from
  a table in this file: every ``OCIRepository`` under ``kubernetes/`` that
  carries the ``platform.snaraj.dev/chart-release`` annotation and a cosign
  ``matchOIDCIdentity`` is a selection, and its identity tuple (chart
  repository, source repository, publisher subject) comes from that
  document. The publisher identity selects the acquisition profile, and a
  workload whose identity has no profile is refused, never guessed.
* **Ceremony.** Every judgment of the issue-195 acquisition sequence is
  code: double tag resolution with ``docker-content-digest`` agreement and
  byte identity, config and sole Helm layer fetched by their own digests and
  hash-verified, ``Chart.yaml`` and ``values.yaml`` inspected, the embedded
  workload pin resolved twice and bound to the exact index digest, exactly
  one ``linux/arm64`` child, cosign verification of the chart AT ITS DIGEST,
  SLSA v1 provenance AT THE INDEX DIGEST, the Release asset hashed and bound
  to GitHub's own digest, and the annotated tag dereferenced to the very
  commit the asset names. The pinned cosign version is required, not assumed.
* **Rewrite.** The receipt is regenerated from the record (the JSON renderer
  is byte-exact against the committed file) and every other pinned copy of a
  tag or digest is rewritten by counted substitution across the whole
  tracked tree — including split string literals in the security batteries —
  so no two surfaces can disagree. An unexpected occurrence count refuses
  the entire rewrite.
* **Publication.** The gates run, the commit is signed under the owner's
  noreply identity, the publication gate runs on that exact signed commit,
  and the branch is pushed and opened as a labelled DRAFT pull request.
* **Receipt (issue #309).** On a later tick the promotion pull request earns
  its exact-head verdict rather than asking for one: the tool proves no App
  comment already binds that head, that every path the head changes is one
  ``apply_promotion`` itself writes, and that re-running the ceremony above
  from ``main`` re-renders that surface byte for byte — then the reviewer App
  posts the receipt. Nothing is read from the pull request; a proof failure is
  REQUEST-CHANGES and an unattributable refusal is neither.

The tool runs on the owner's workstation under the owner's own keyring
credential and SSH signing key, exactly like every promotion so far: no new
principal, no credential in CI, and the identity, signature and
account-protection contracts are untouched. Standard library only. It holds
no readiness authority: under AGENTS.md the coordinator flips Ready
(``scripts/ready_check.py`` is that rule in code) and the owner alone merges.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

REPOSITORY = "snaraj/website-infrastructure"
REGISTRY_HOST = "ghcr.io"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"
HELM_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_V1 = "https://slsa.dev/provenance/v1"
IN_TOTO = "application/vnd.in-toto+json"
RECEIPT_SCHEMA = "dev.snaraj.chart-acquisition-receipt/v2"
RECEIPT_JSON = Path("docs/assurance/195-chart-acquisition-receipt.json")
RECEIPT_MD = Path("docs/assurance/195-chart-acquisition-receipt.md")
MANIFEST_ROOT = Path("kubernetes")
README = Path("README.md")
FRAGMENTS = Path("changelog.d")
VERSIONS_ENV = Path("versions.env")
ANNOTATION = "platform.snaraj.dev/chart-release"
# `promoter` stands in for the agent pair AGENTS.md withholds from this tool,
# and `security` is the tier a promotion actually earns: it advances a signed
# chart digest and the identity pins that gate it, which AGENTS.md's risk table
# names ("signing, digests, immutable artifacts"). `scripts/ready_check.py`'s
# PROMOTER_TUPLE is exactly this tuple, and its battery reads both and proves
# they agree, so widening one alone is a red test rather than a permission.
PR_LABELS = ("release", "security", "delivery-lane", "promoter")
# Since issue #309 a promotion pull request arms review ATTENTION only. Its
# receipt is EARNED, not requested: the receipt step below re-derives the whole
# promotion surface from the registry and the site's immutable Release, and the
# reviewer App posts the verdict at the exact head. The cybersecurity lane
# keeps reviewing every change to this tool's CODE — normal agent pull
# requests, where the risk actually lives — so arming that lane on the tool's
# own mechanical output spent a scarce reviewer re-reading a value a machine
# had already re-derived byte for byte.
REVIEW_LABELS = ("requires-review",)
MILESTONE = "Platform upkeep"
ASSIGNEE = "snaraj"
NOREPLY_DOMAIN = "users.noreply.github.com"
SIGNATURE = "- Promoter"
BRANCH_PREFIX = "promoter/"
GATES = (("make", "check-fast"), ("make", "check-gitleaks"), ("make", "check-kubernetes"))
# The repository's outgoing-range gate: it runs on the exact signed commit,
# after the commit and before the push, and a refusal pushes nothing.
PUBLICATION_GATE = ("make", "pre-push-security")
# Every subprocess is bounded, so a hung command cannot hold the tick's lock
# forever; the gates get the long bound.
COMMAND_TIMEOUT_SECONDS = 600
GATE_TIMEOUT_SECONDS = 3600
# Cosign is the one call that reaches a public transparency log and a registry
# in the same breath, and it is where a stall actually happened: on 2026-09-04
# one `cosign verify` held COMMAND_TIMEOUT_SECONDS in full and cost a tick
# fifteen minutes. Its own budget is therefore short and it gets exactly one
# in-tick retry, so a Sigstore or registry stall costs a couple of minutes and
# a logged retry rather than a silent ten. Two attempts, not more: a second
# stall is a condition to report, not to keep paying for.
COSIGN_TIMEOUT_SECONDS = 120
COSIGN_ATTEMPTS = 2
MAX_JSON_BYTES = 1024 * 1024
MAX_BLOB_BYTES = 64 * 1024 * 1024
# The chart layer is read as a bounded stream: an entry-count ceiling, a
# decompressed-byte ceiling and a per-file ceiling for the two files the
# ceremony inspects, so a small signed gzip cannot expand into memory.
ARCHIVE_MEMBER_CEILING = 4096
ARCHIVE_EXPANSION_CEILING = 64 * 1024 * 1024
CHART_FILE_CEILING = 1024 * 1024
TIMEOUT = 60
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRAGMENT_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
BRANCH_RE = re.compile(
    r"^promoter/([0-9a-f]{7})/([1-9][0-9]*)-"
    r"((?:[a-z0-9-]+-\d+\.\d+\.\d+)(?:_[a-z0-9-]+-\d+\.\d+\.\d+)*)$"
)
TARGET_RE = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)*)-(\d+\.\d+\.\d+)$")
CAPTURE_HEADER_RE = re.compile(
    r"^Captured (\d{4}-\d{2}-\d{2}) for (?:the )?issues? (#\d+(?:/#\d+)*)", re.MULTILINE
)
INSPECTION_RE = re.compile(
    r"^- ([a-z0-9-]+) `(Chart\.yaml|values\.yaml)`: `(sha256:[0-9a-f]{64})`$",
    re.MULTILINE,
)
README_ROW_RE = re.compile(
    r"Current selections: (.+?), captured (\d{4}-\d{2}-\d{2}) for issues? "
    r"(#\d+(?:/#\d+)*) in `docs/assurance/195-chart-acquisition-receipt\.json`"
)
LAUNCHD_LABEL = "dev.snaraj.release-promoter"
# The tick is a READ-ONLY poll until it has something to do: a status read per
# selection and one pull-request listing. Five minutes is the interval the
# owner's 2026-09-03 release-loop commission (issue #309) fixed, cutting the
# worst-case wait between a published release and its promotion pull request
# from fifteen minutes to five without touching a control: the lock, the
# per-command bounds and every ceremony judgment are unchanged. The runbook
# states the same number and `test_promotion_receipt_contract.py` pins the two
# together, so the prose and the plist cannot drift apart.
LAUNCHD_INTERVAL_SECONDS = 300

# The runbook's fenced command blocks, pinned byte for byte by the battery so
# a neutralized or smuggled invocation is a red test, never prose drift.
RUNBOOK_BLOCKS = (
    'repo="$HOME/Library/Application Support/release-promoter/website-infrastructure"\n'
    'mkdir -p "$(dirname "$repo")"\n'
    'git clone --quiet https://github.com/snaraj/website-infrastructure.git "$repo"\n',
    'python3 -I -B "$repo/scripts/promote_releases.py" tick --repo "$repo" --dry-run\n',
    'receipt_helper="$HOME/path/to/agent-reviews-token"\n'
    'python3 -I -B "$repo/scripts/promote_releases.py" launchd-plist --repo "$repo"'
    ' --log "$HOME/Library/Logs/release-promoter.log"'
    ' --token-command "$receipt_helper"'
    ' > "$HOME/Library/LaunchAgents/dev.snaraj.release-promoter.plist"\n'
    'launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.snaraj.release-promoter.plist"\n',
    'launchctl kickstart -k "gui/$(id -u)/dev.snaraj.release-promoter"\n'
    'tail -n 40 "$HOME/Library/Logs/release-promoter.log"\n',
    'launchctl bootout "gui/$(id -u)/dev.snaraj.release-promoter"\n',
    'python3 -I -B scripts/promote_releases.py status\n',
    'python3 -I -B scripts/promote_releases.py verify\n',
    'PROMOTER_RECEIPT_TOKEN_COMMAND="$receipt_helper"'
    ' python3 -I -B "$repo/scripts/promote_releases.py" receipt --repo "$repo" --dry-run\n',
)


class Refusal(Exception):
    """A fail-closed judgment. The message names the exact check that failed."""


# "no entry at all", distinguishable from a stored ``None``.
_ABSENT = object()


def _load_sibling(name, module_name):
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).resolve().parent / name
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"{name} is unloadable")
    module = importlib.util.module_from_spec(spec)
    # The module must be in ``sys.modules`` WHILE its body runs — the documented
    # importlib recipe. Anything resolving a PEP 563 string annotation looks its
    # defining module up there, so a sibling with `from __future__ import
    # annotations` and a dataclass would otherwise abort the whole tick with a
    # bare AttributeError on None. Removed again immediately, so the sibling
    # stays a private copy rather than an importable name. Absence is tracked
    # with a private sentinel, never with ``None``: a present ``None`` entry is
    # Python's import-blocking marker, a distinct state that must be RESTORED
    # rather than dropped as if the key had never been there.
    previous = sys.modules.get(module_name, _ABSENT)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is _ABSENT:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    return module


# The watchdog owns the annotation/subject grammar and the drift verdict; the
# promoter reuses them so the two can never classify one manifest differently.
ASSURANCE = _load_sibling("ci/deploy_assurance.py", "promoter_deploy_assurance")
# The Ready rule owns the reviewer App's immutable identity (login, user id,
# App id) and loads the receipt-shape validator. The promoter READS both from
# there rather than restating them: an actor tuple copied into a second file is
# a tuple that can drift, and the whole value of an App-posted receipt is that
# the actor is exactly the one the Ready evaluator will later look for. Nothing
# here can widen that rule — this module never writes to it and holds no Ready
# authority.
READY = _load_sibling("ready_check.py", "promoter_ready_check")
RECEIPTS = READY.RECEIPTS


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def utc_today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def log(message: str) -> None:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


# ---------------------------------------------------------------------------
# Call tracing (owner direction, 2026-09-04). A tick spends nearly all of its
# wall clock inside a handful of external calls, and until this existed a
# stalled one was INVISIBLE: on 2026-09-04 a `cosign verify` held the full
# 600-second command bound and the only trace was a single refusal line ten
# minutes later, after which the next tick silently retried. Every long call
# now announces itself before it starts, with its budget, and reports its
# elapsed time and — when it fails — the decision the tick took, on one line.
# ---------------------------------------------------------------------------

# What a failed call means depends on WHO is making it, not on the call: the
# same registry read refuses a cut and merely skips a receipt. The caller
# declares that once with ``failure_decision`` and every call underneath it
# reports the truth instead of a guess. A single-threaded tick, one stack.
_FAILURE_DECISION = ["refuse"]


@contextlib.contextmanager
def failure_decision(decision: str):
    """Declare what a failed call under this block costs the tick."""

    _FAILURE_DECISION.append(decision)
    try:
        yield
    finally:
        _FAILURE_DECISION.pop()


@contextlib.contextmanager
def timed_call(kind: str, target: str, budget: int, decision: str = ""):
    """One START line, one DONE line with elapsed seconds and the outcome.

    The failure line carries the decision AND the reason together, so reading
    the log never means correlating two lines to learn what a stall cost. The
    reason is redacted at the source: it can quote a registry or Release the
    promoter does not control.
    """

    log(f"START {kind} {target} budget={budget}s")
    started = time.monotonic()
    try:
        yield
    except BaseException as error:
        taken = decision or _FAILURE_DECISION[-1]
        log(
            f"DONE {kind} {target} elapsed={time.monotonic() - started:.1f}s FAILED"
            f" decision={taken} reason={redact(str(error))[:200]}"
        )
        raise
    log(f"DONE {kind} {target} elapsed={time.monotonic() - started:.1f}s OK")


# ---------------------------------------------------------------------------
# Discovery: selections come from the manifests, never from a table here.
# ---------------------------------------------------------------------------


class Selection:
    """One promotable workload as its committed manifest states it."""

    __slots__ = (
        "slug",
        "path",
        "version",
        "digest",
        "chart_repository",
        "source_repository",
        "subject",
        "domain",
    )

    def __init__(self, slug, path, version, digest, chart_repository, source_repository, subject):
        self.slug = slug
        self.path = path
        self.version = version
        self.digest = digest
        self.chart_repository = chart_repository
        self.source_repository = source_repository
        self.subject = subject
        # The human name is the source repository's own name (naranjo.online).
        self.domain = source_repository.split("/", 1)[1]


DIGEST_LINE_RE = re.compile(r"^\s*digest:\s*(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
URL_LINE_RE = re.compile(r"^\s*url:\s*oci://([^\s]+)\s*$", re.MULTILINE)
NAME_LINE_RE = re.compile(r"^\s*name:\s*([a-z0-9-]+)-chart\s*$", re.MULTILINE)


def _oci_repository_documents(text: str):
    for document in re.split(r"^---\s*$", text, flags=re.MULTILINE):
        if re.search(r"^kind:\s*OCIRepository\s*$", document, re.MULTILINE):
            yield document


def discover_selections(root: Path) -> dict:
    """Return ``{slug: Selection}`` for every annotated OCIRepository.

    The slug is the manifest's own ``<slug>-chart`` name; the annotation,
    subject, exact digest and chart URL must all be present and singular, or
    the document is refused rather than half-read. Sorted by slug so every
    downstream artifact is deterministic.
    """

    found = {}
    for path in sorted((root / MANIFEST_ROOT).rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for document in _oci_repository_documents(text):
            if ANNOTATION not in document:
                continue
            parsed = ASSURANCE.parse_site_selection(document)
            names = NAME_LINE_RE.findall(document)
            digests = DIGEST_LINE_RE.findall(document)
            urls = URL_LINE_RE.findall(document)
            relative = path.relative_to(root).as_posix()
            if parsed is None or len(names) != 1 or len(digests) != 1 or len(urls) != 1:
                raise Refusal(f"{relative}: annotated OCIRepository is not a closed selection")
            version, source_repository = parsed
            slug = names[0]
            subject = _subject_from_document(document)
            if slug in found:
                raise Refusal(f"{relative}: duplicate selection for {slug}")
            found[slug] = Selection(
                slug, relative, version, digests[0], urls[0], source_repository, subject
            )
    return dict(sorted(found.items()))


SUBJECT_LINE_RE = re.compile(r"^\s*subject:\s*(\^?\S+)\s*$", re.MULTILINE)


def _subject_from_document(document: str) -> str:
    """The exact publisher identity the cluster verifies, un-escaped.

    The manifest carries cosign's anchored regular expression
    (``^https://github\\.com/...$``); the identity cosign is asked to match
    is that string with the anchors and escapes removed. Exactly one is
    required.
    """

    subjects = SUBJECT_LINE_RE.findall(document)
    if len(subjects) != 1:
        raise Refusal("selection must carry exactly one cosign subject")
    subject = subjects[0].strip('"').strip("'")
    subject = subject[1:] if subject.startswith("^") else subject
    subject = subject[:-1] if subject.endswith("$") else subject
    return subject.replace("\\.", ".")


# ---------------------------------------------------------------------------
# Transport: anonymous OCI reads, GitHub through gh, cosign as a subprocess.
# Every class takes its I/O callable so the batteries run without a network.
# ---------------------------------------------------------------------------


def _bounded_read(response, limit: int) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise Refusal(f"response exceeds the {limit}-byte bound")
    return data


def http_fetch(url: str, headers: dict, limit: int) -> tuple:
    """One bounded anonymous GET; transport failures are Refusals, so the
    tick reports them instead of dying on a traceback."""

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = _bounded_read(response, limit)
            return body, {key.lower(): value for key, value in response.headers.items()}
    except (urllib.error.URLError, OSError) as error:
        raise Refusal(f"{url.split('?', 1)[0]}: {error}") from None


class Registry:
    """Anonymous OCI distribution reads with the pull-scope bearer token.

    Repository names arrive host-qualified from the manifests
    (``ghcr.io/snaraj/charts/<slug>``); the distribution API wants the
    path without the host, and a name on any other host is refused."""

    def __init__(self, fetch=http_fetch, host: str = REGISTRY_HOST):
        self._fetch = fetch
        self.host = host
        self._tokens = {}

    def _name(self, repository: str) -> str:
        host, _, path = repository.partition("/")
        if host != self.host or not path:
            raise Refusal(f"{repository}: not a repository on {self.host}")
        return path

    def _token(self, name: str) -> str:
        if name not in self._tokens:
            url = f"https://{self.host}/token?scope=repository:{name}:pull"
            # The traced target names the repository and the scope, never the
            # answer: the pull token itself is a credential and stays out of
            # every log line the same way the reviewer App's token does.
            with timed_call("registry-token", f"{name} scope=pull", TIMEOUT):
                body, _ = self._fetch(url, {}, MAX_JSON_BYTES)
            token = json.loads(body).get("token")
            if not isinstance(token, str) or not token:
                raise Refusal(f"{name}: registry issued no pull token")
            self._tokens[name] = token
        return self._tokens[name]

    def manifest(self, repository: str, reference: str, accept: str) -> tuple:
        """Return ``(bytes, docker-content-digest)`` for one reference."""

        name = self._name(repository)
        headers = {"Authorization": "Bearer " + self._token(name), "Accept": accept}
        url = f"https://{self.host}/v2/{name}/manifests/{reference}"
        with timed_call("registry-manifest", f"{repository}:{reference}", TIMEOUT):
            body, response_headers = self._fetch(url, headers, MAX_JSON_BYTES)
        header = response_headers.get("docker-content-digest")
        if not isinstance(header, str) or DIGEST_RE.fullmatch(header) is None:
            raise Refusal(f"{repository}:{reference}: registry answered without a content digest")
        return body, header

    def blob(self, repository: str, digest: str) -> bytes:
        name = self._name(repository)
        headers = {"Authorization": "Bearer " + self._token(name)}
        url = f"https://{self.host}/v2/{name}/blobs/{digest}"
        with timed_call("registry-blob", f"{repository}@{digest}", TIMEOUT):
            body, _ = self._fetch(url, headers, MAX_BLOB_BYTES)
        if sha256_hex(body) != digest:
            raise Refusal(f"{repository}@{digest}: blob bytes do not hash to their digest")
        return body


GIT_MAINTENANCE_PINS = (("gc.auto", "0"), ("gc.autoDetach", "false"), ("maintenance.auto", "false"))


def pinned_environment(env=None) -> dict:
    """The environment every command runs in: the caller's (or the
    process's) plus git's post-command auto maintenance pinned OFF through
    ``GIT_CONFIG_COUNT``, appended after any entries already present. After
    ``fetch`` and ``commit`` git otherwise detaches a ``maintenance run
    --auto`` child into its own session, the one known way a command the
    tick runs — directly or under ``make``/``gh`` — leaves the session the
    tick supervises."""

    merged = dict(os.environ if env is None else env)
    start = int(merged.get("GIT_CONFIG_COUNT", "0") or 0)
    for offset, (key, value) in enumerate(GIT_MAINTENANCE_PINS):
        merged[f"GIT_CONFIG_KEY_{start + offset}"] = key
        merged[f"GIT_CONFIG_VALUE_{start + offset}"] = value
    merged["GIT_CONFIG_COUNT"] = str(start + len(GIT_MAINTENANCE_PINS))
    return merged


def run_command(argv, cwd=None, input_text=None, env=None, timeout=COMMAND_TIMEOUT_SECONDS, quiet_output=False) -> str:
    """Run one command as the leader of its own session and return its
    stdout; a non-zero exit, or a hang past ``timeout`` seconds, is a
    Refusal. On completion and on timeout the whole process group is killed
    before returning, so no descendant IN THAT SESSION outlives the tick's
    lock. A descendant that starts a session of its own is outside this
    boundary: the commands the tick runs are a fixed set (git, gh, make,
    cosign and the gates), and their one known detaching path — git's auto
    maintenance — is pinned off in every command's environment. The refusal
    names the program and its subcommand only — never the full argv, which
    can carry workstation paths."""

    label = " ".join(map(str, argv[:2]))
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=None if cwd is None else str(cwd),
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=pinned_environment(env),
            text=True,
            start_new_session=True,
        )
    except OSError as error:
        # A program missing from the agent's pinned PATH, or not executable,
        # is a refusal the tick reports — never a traceback that escapes
        # every handler. The strerror carries no path; the filename would.
        raise Refusal(f"`{label}` could not be run: {error.strerror or type(error).__name__}") from None
    timed_out = False
    try:
        stdout, stderr = process.communicate(input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout, stderr = "", ""
    finally:
        try:
            _kill_process_group(process)
        finally:
            # ``wait`` alone does not own the TextIOWrapper lifetime after a
            # timeout. Close every local pipe explicitly once the whole
            # process group is dead so the long-running tick leaks no fds.
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
    if timed_out:
        raise Refusal(f"`{label}` exceeded {timeout}s and its process group was killed") from None
    if process.returncode != 0:
        if quiet_output:
            # A command whose OUTPUT is a credential: its exit status is
            # reportable, its bytes are not. Nothing from either stream reaches
            # the local log or the refusal, because a failing helper that
            # printed a token first would otherwise put it there.
            raise Refusal(f"`{label}` exited {process.returncode}; its output is deliberately not recorded")
        detail = (stderr or stdout).strip().splitlines()
        tail = " | ".join(detail[-3:]) if detail else "no output"
        # The raw tail stays in the local log; the refusal, which can travel
        # into a public comment, is redacted at the source.
        log(f"`{label}` exited {process.returncode}: {tail}")
        raise Refusal(f"`{label}` exited {process.returncode}: {redact(tail)}")
    return stdout


def _kill_process_group(process) -> None:
    """Kill everything in the command's process group — its id is the
    child's pid because it was started as a session leader — then reap the
    direct child. A descendant that detached its output but stayed in the
    session is included; the group is signalled before the child is reaped
    so its id cannot be reused in between."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


class GitHub:
    """GitHub reads and the few writes the promoter is allowed, through gh.

    ``gh`` supplies the owner's keyring credential; the promoter never reads,
    echoes or stores a token value. ``fetch`` downloads public Release
    assets anonymously.
    """

    def __init__(self, run=run_command, fetch=http_fetch):
        self._run = run
        self._fetch = fetch

    def api(self, path: str, method: str = "GET", body=None) -> dict:
        """One object-shaped call; an empty body (204) decodes to ``{}``."""

        argv = ["gh", "api", "-X", method, "-H", "Accept: application/vnd.github+json", path]
        input_text = None
        if body is not None:
            argv += ["--input", "-"]
            input_text = json.dumps(body)
        with timed_call("github-api", f"{method} {path}", COMMAND_TIMEOUT_SECONDS):
            output = self._run(argv, input_text=input_text)
        decoded = json.loads(output) if output.strip() else {}
        if not isinstance(decoded, dict):
            raise Refusal(f"{path}: expected one object, got {type(decoded).__name__}")
        return decoded

    def mutate(self, path: str, method: str, body=None) -> None:
        """One write. GitHub answers writes in whatever shape the endpoint
        has (label writes return arrays); the answer is discarded and only
        the exit status counts."""

        argv = ["gh", "api", "-X", method, "-H", "Accept: application/vnd.github+json", path]
        input_text = None
        if body is not None:
            argv += ["--input", "-"]
            input_text = json.dumps(body)
        with timed_call("github-write", f"{method} {path}", COMMAND_TIMEOUT_SECONDS):
            self._run(argv, input_text=input_text)

    def api_pages(self, path: str) -> list:
        """A list-shaped call, paginated to exhaustion."""

        argv = ["gh", "api", "--paginate", "--slurp", "-H", "Accept: application/vnd.github+json", path]
        with timed_call("github-list", path, COMMAND_TIMEOUT_SECONDS):
            output = self._run(argv)
        decoded = json.loads(output)
        merged = []
        for page in decoded:
            if not isinstance(page, list):
                raise Refusal(f"{path}: expected list pages")
            merged.extend(page)
        return merged

    def download(self, url: str) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "github.com":
            raise Refusal(f"refusing to download a Release asset from {parsed.netloc}")
        with timed_call("release-asset", parsed.path, TIMEOUT):
            body, _ = self._fetch(url, {}, MAX_JSON_BYTES)
        return body

    def command(self, argv, cwd=None) -> str:
        # The traced target is the subcommand only: a full argv can carry a
        # workstation path (run_command's own refusals redact for this reason).
        with timed_call("github-command", " ".join(argv[:2]), COMMAND_TIMEOUT_SECONDS):
            return self._run(["gh", *argv], cwd=cwd)


class Cosign:
    """The two cosign verifications, always AT A DIGEST, never at a tag."""

    def __init__(self, run=run_command, pinned_version: str = ""):
        self._run = run
        self.pinned_version = pinned_version
        self._verified_version = None

    def require_pinned_version(self) -> str:
        """The pin is checked before the first verification and cached; a
        cosign that is not the ``versions.env`` pin verifies nothing."""

        if self._verified_version is None:
            output = self._run(["cosign", "version", "--json"])
            version = json.loads(output).get("gitVersion")
            if version != self.pinned_version:
                raise Refusal(
                    f"cosign {version!r} is not the versions.env pin {self.pinned_version!r}"
                )
            self._verified_version = version
        return self._verified_version

    def _bounded(self, argv, kind: str, target: str) -> str:
        """One cosign call under a SHORT budget, with exactly one retry.

        Cosign reaches Sigstore and the registry in the same call, so a stall
        there is the one failure mode that used to cost a whole tick silently.
        Each attempt is traced and bounded; the first failure logs
        ``decision=retry`` and the second the caller's real decision, so the
        log says what a stall cost without anyone correlating lines.
        """

        failure = None
        for attempt in range(1, COSIGN_ATTEMPTS + 1):
            decision = "retry" if attempt < COSIGN_ATTEMPTS else ""
            try:
                with timed_call(kind, f"{target} attempt={attempt}/{COSIGN_ATTEMPTS}", COSIGN_TIMEOUT_SECONDS, decision):
                    return self._run(argv, timeout=COSIGN_TIMEOUT_SECONDS)
            except Refusal as error:
                failure = error
        raise failure

    def verify_chart(self, repository: str, digest: str, subject: str) -> None:
        self.require_pinned_version()
        output = self._bounded(
            [
                "cosign",
                "verify",
                "--certificate-identity",
                subject,
                "--certificate-oidc-issuer",
                ACTIONS_ISSUER,
                f"{repository}@{digest}",
            ],
            "cosign-verify-chart",
            f"{repository}@{digest}",
        )
        entries = json.loads(output)
        if not isinstance(entries, list) or not entries:
            raise Refusal(f"{repository}@{digest}: cosign returned no signature")
        for entry in entries:
            bound = entry.get("critical", {}).get("image", {}).get("docker-manifest-digest")
            if bound != digest:
                raise Refusal(f"{repository}: signature binds {bound}, not {digest}")

    def verify_provenance(self, repository: str, digest: str, subject: str) -> None:
        self.require_pinned_version()
        output = self._bounded(
            [
                "cosign",
                "verify-attestation",
                "--type",
                "slsaprovenance1",
                "--new-bundle-format",
                "--certificate-identity",
                subject,
                "--certificate-oidc-issuer",
                ACTIONS_ISSUER,
                f"{repository}@{digest}",
            ],
            "cosign-verify-provenance",
            f"{repository}@{digest}",
        )
        statements = 0
        for line in output.splitlines():
            if not line.strip():
                continue
            envelope = json.loads(line)
            if envelope.get("payloadType") != IN_TOTO:
                raise Refusal(f"{repository}: attestation payload type is not in-toto")
            statement = json.loads(base64.b64decode(envelope["payload"]))
            if statement.get("predicateType") != SLSA_V1:
                raise Refusal(f"{repository}: attestation is not SLSA v1 provenance")
            subjects = {
                "sha256:" + item.get("digest", {}).get("sha256", "")
                for item in statement.get("subject", [])
            }
            if subjects != {digest}:
                raise Refusal(f"{repository}: provenance subject is not exactly {digest}")
            statements += 1
        if statements == 0:
            raise Refusal(f"{repository}@{digest}: no SLSA v1 provenance statement")


# ---------------------------------------------------------------------------
# Ceremony: the issue-195 acquisition sequence, every judgment in code.
# ---------------------------------------------------------------------------


def resolve_twice(registry: Registry, repository: str, reference: str, accept: str) -> tuple:
    """Resolve one reference twice; both answers must agree with their bytes
    and with each other. Returns ``(digest, bytes)``."""

    answers = []
    for _ in range(2):
        body, header = registry.manifest(repository, reference, accept)
        computed = sha256_hex(body)
        if header != computed:
            raise Refusal(
                f"{repository}:{reference}: content digest {header} disagrees with the bytes ({computed})"
            )
        answers.append((computed, body))
    if answers[0] != answers[1]:
        raise Refusal(f"{repository}:{reference}: the reference moved between two resolutions")
    return answers[0]


def _yaml_scalar(text: str, key: str, indent: str = "") -> str:
    pattern = re.compile(rf"^{indent}{re.escape(key)}:\s*(.+?)\s*$", re.MULTILINE)
    values = [value.strip("'\"") for value in pattern.findall(text)]
    if len(values) != 1:
        raise Refusal(f"expected exactly one `{key}` in the chart document, found {len(values)}")
    return values[0]


def chart_identity(chart_yaml: str) -> dict:
    return {
        "appVersion": _yaml_scalar(chart_yaml, "appVersion"),
        "name": _yaml_scalar(chart_yaml, "name"),
        "version": _yaml_scalar(chart_yaml, "version"),
    }


def image_pin(values_yaml: str) -> dict:
    """The embedded workload pin: ``image.repository``, ``image.tag``,
    ``image.digest`` — each exactly once, inside the top-level image block."""

    block = re.search(r"^image:\n((?:[ \t]+.*\n|[ \t]*#.*\n)*)", values_yaml, re.MULTILINE)
    if block is None:
        raise Refusal("values.yaml carries no top-level image block")
    body = block.group(1)
    return {
        "repository": _yaml_scalar(body, "repository", indent="  "),
        "tag": _yaml_scalar(body, "tag", indent="  "),
        "digest": _yaml_scalar(body, "digest", indent="  "),
    }


class _BoundedReader:
    """Serves a decompressing stream and refuses once more than ``ceiling``
    bytes have been produced, so an archive's expansion is bounded before
    any entry is materialized."""

    def __init__(self, inner, ceiling: int):
        self._inner, self._ceiling, self._seen = inner, ceiling, 0

    def read(self, size=-1) -> bytes:
        chunk = self._inner.read(size)
        self._seen += len(chunk)
        if self._seen > self._ceiling:
            raise Refusal(f"chart layer expands past {self._ceiling} bytes")
        return chunk


def chart_members(layer: bytes, names: tuple) -> dict:
    """The exact bytes of ``names`` from the chart layer, read in ONE
    bounded streaming pass. Every entry path is normalized and must be
    unique — a second entry for a path, or a ``./``-prefixed twin, is
    refused outright rather than resolved, because Helm's choice among such
    entries need not be this tool's — every entry must be a regular file or
    a directory (a link or device anywhere in the chart is refused), and
    each wanted name must be a regular file within the per-file ceiling.
    Entries outside the archive root are refused."""

    wanted = set(names)
    found, seen, count = {}, set(), 0
    stream = _BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(layer)), ARCHIVE_EXPANSION_CEILING)
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                count += 1
                if count > ARCHIVE_MEMBER_CEILING:
                    raise Refusal(f"chart layer carries more than {ARCHIVE_MEMBER_CEILING} entries")
                normalized = posixpath.normpath(member.name)
                if normalized.startswith("/") or normalized == "." or ".." in normalized.split("/"):
                    raise Refusal("chart layer carries an entry outside the archive root")
                if normalized in seen:
                    raise Refusal(f"chart layer carries {normalized} more than once")
                seen.add(normalized)
                if not (member.isfile() or member.isdir()):
                    raise Refusal(f"chart layer member {normalized} is not a regular file")
                if normalized not in wanted:
                    continue
                if not member.isfile():
                    raise Refusal(f"chart layer member {normalized} is not a regular file")
                if member.size > CHART_FILE_CEILING:
                    raise Refusal(f"chart layer member {normalized} exceeds {CHART_FILE_CEILING} bytes")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise Refusal(f"chart layer member {normalized} is unreadable")
                # tarfile refuses a member whose data falls short of its
                # header (ReadError, caught below); the read is exactly the
                # declared, already-bounded size.
                found[normalized] = extracted.read(member.size)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as error:
        raise Refusal(f"chart layer is not a readable gzip tar: {type(error).__name__}") from None
    for name in names:
        if name not in found:
            raise Refusal(f"chart layer carries no {name}")
    return found


def profile_for(subject: str) -> str:
    """Select the acquisition profile from the publisher identity.

    A subject this file has no profile for is refused: the promoter never
    guesses how an unknown publisher should be verified.
    """

    if re.fullmatch(
        r"https://github\.com/snaraj/[^/]+/\.github/workflows/release-publisher\.yml@refs/heads/main",
        subject,
    ):
        return "release-publisher"
    raise Refusal(f"no acquisition profile for publisher identity {subject}")


def release_manifest_statements(asset: dict) -> dict:
    """Every statement a Release manifest makes about the resolved identities,
    across both publisher schemas in the fleet (``lidersea.release-manifest/v1``
    carries ``tag``/``version``/``workflow_identity`` and nested ``signature``
    blocks; the naranjo schema carries ``release``/``publisher`` blocks and
    ``signature_identity`` fields). Absent statements are omitted, never
    defaulted, so a schema that states nothing cannot pass by silence."""

    artifacts = asset.get("artifacts") or {}
    chart = artifacts.get("chart") or {}
    image = artifacts.get("image") or {}
    publisher = asset.get("publisher") or {}
    release = asset.get("release") or {}
    candidates = {
        "repository": [asset.get("repository")],
        "version": [asset.get("version"), release.get("version"), chart.get("tag")],
        "tag": [asset.get("tag"), release.get("tag"), image.get("tag")],
        "identity": [
            asset.get("workflow_identity"),
            chart.get("signature_identity"),
            image.get("signature_identity"),
            (chart.get("signature") or {}).get("certificate_identity"),
            (image.get("signature") or {}).get("certificate_identity"),
            (
                f"https://github.com/{asset.get('repository')}/{publisher.get('workflow')}@{publisher.get('ref')}"
                if publisher.get("workflow") and publisher.get("ref")
                else None
            ),
        ],
        "chart.repository": [chart.get("repository"), chart.get("registry")],
        "chart.digest": [chart.get("digest")],
        "image.repository": [image.get("repository"), image.get("registry")],
        "image.digest": [image.get("digest")],
    }
    return {key: [value for value in values if value is not None] for key, values in candidates.items()}


def bind_release_manifest(asset: dict, expected: dict, label: str) -> None:
    """Every stated value must equal the resolved one, and the load-bearing
    fields — repository, version, publisher identity, chart and image
    digests — must be stated at least once."""

    statements = release_manifest_statements(asset)
    for field, value in expected.items():
        stated = statements.get(field, [])
        for candidate in stated:
            if candidate != value:
                raise Refusal(f"{label}: release manifest {field} states {candidate!r}, not {value!r}")
        if not stated:
            raise Refusal(f"{label}: release manifest states no {field}")


def acquire_release_publisher(
    selection: Selection, version: str, registry: Registry, github: GitHub, cosign: Cosign
) -> tuple:
    """The ``release-publisher`` profile. Returns ``(record, inspection)``.

    ``record`` is one receipt-v2 record; ``inspection`` holds the exact-layer
    hashes of ``Chart.yaml`` and ``values.yaml`` the Markdown view states.
    """

    slug, chart_repo, subject = selection.slug, selection.chart_repository, selection.subject
    # The site publisher contract names the workload image after the chart.
    image_repo = f"{REGISTRY_HOST}/snaraj/{slug}"
    tag = f"v{version}"

    manifest_digest, manifest_bytes = resolve_twice(registry, chart_repo, version, OCI_MANIFEST)
    manifest = json.loads(manifest_bytes)
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType", OCI_MANIFEST) != OCI_MANIFEST:
        raise Refusal(f"{chart_repo}:{version}: not an OCI image manifest")
    config = manifest.get("config", {})
    if config.get("mediaType") != HELM_CONFIG:
        raise Refusal(f"{chart_repo}:{version}: config is not a Helm config blob")
    layers = [layer for layer in manifest.get("layers", []) if layer.get("mediaType") == HELM_LAYER]
    if len(layers) != 1 or len(manifest.get("layers", [])) != 1:
        raise Refusal(f"{chart_repo}:{version}: expected exactly one Helm chart layer")
    layer = layers[0]

    config_bytes = registry.blob(chart_repo, config["digest"])
    config_document = json.loads(config_bytes)
    expected_chart = {"appVersion": version, "name": slug, "version": version}
    if {key: config_document.get(key) for key in expected_chart} != expected_chart:
        raise Refusal(f"{chart_repo}:{version}: Helm config identity is not {expected_chart}")

    layer_bytes = registry.blob(chart_repo, layer["digest"])
    if layer.get("size") != len(layer_bytes):
        raise Refusal(f"{chart_repo}:{version}: layer size disagrees with its bytes")
    members = chart_members(layer_bytes, (f"{slug}/Chart.yaml", f"{slug}/values.yaml"))
    chart_yaml = members[f"{slug}/Chart.yaml"]
    values_yaml = members[f"{slug}/values.yaml"]
    if chart_identity(chart_yaml.decode("utf-8")) != expected_chart:
        raise Refusal(f"{chart_repo}:{version}: Chart.yaml identity is not {expected_chart}")
    pin = image_pin(values_yaml.decode("utf-8"))
    if pin["repository"] != image_repo or pin["tag"] != tag:
        raise Refusal(f"{slug}: embedded image pin {pin} is not {image_repo}:{tag}")
    if DIGEST_RE.fullmatch(pin["digest"]) is None:
        raise Refusal(f"{slug}: embedded image digest {pin['digest']!r} is malformed")

    index_digest, index_bytes = resolve_twice(registry, image_repo, tag, OCI_INDEX)
    if index_digest != pin["digest"]:
        raise Refusal(f"{image_repo}:{tag}: index {index_digest} is not the embedded pin {pin['digest']}")
    index = json.loads(index_bytes)
    if index.get("mediaType") != OCI_INDEX:
        raise Refusal(f"{image_repo}:{tag}: not an OCI image index")
    arm64 = [
        child["digest"]
        for child in index.get("manifests", [])
        if child.get("platform", {}).get("os") == "linux"
        and child.get("platform", {}).get("architecture") == "arm64"
    ]
    if len(arm64) != 1 or DIGEST_RE.fullmatch(arm64[0]) is None:
        raise Refusal(f"{image_repo}:{tag}: expected exactly one linux/arm64 child")

    cosign.verify_chart(chart_repo, manifest_digest, subject)
    cosign.verify_provenance(image_repo, index_digest, subject)

    release = github.api(f"repos/{selection.source_repository}/releases/tags/{tag}")
    if release.get("immutable") is not True or release.get("draft") or release.get("prerelease"):
        raise Refusal(f"{selection.source_repository} {tag}: Release is not an immutable final release")
    assets = [asset for asset in release.get("assets", []) if asset.get("name", "").endswith("release-manifest.json")]
    if len(assets) != 1:
        raise Refusal(f"{selection.source_repository} {tag}: expected exactly one release-manifest.json asset")
    asset_bytes = github.download(assets[0]["browser_download_url"])
    asset_digest = sha256_hex(asset_bytes)
    if assets[0].get("digest") != asset_digest:
        raise Refusal(f"{selection.source_repository} {tag}: asset bytes hash to {asset_digest}, GitHub states {assets[0].get('digest')}")
    asset = json.loads(asset_bytes)
    source_sha = asset.get("source_sha")
    bind_release_manifest(
        asset,
        {
            "repository": selection.source_repository,
            "version": version,
            "tag": tag,
            "identity": subject,
            "chart.repository": chart_repo,
            "chart.digest": manifest_digest,
            "image.repository": image_repo,
            "image.digest": index_digest,
        },
        f"{selection.source_repository} {tag}",
    )
    if not isinstance(source_sha, str) or SHA_RE.fullmatch(source_sha) is None:
        raise Refusal(f"{selection.source_repository} {tag}: release manifest source_sha is malformed")

    reference = github.api(f"repos/{selection.source_repository}/git/ref/tags/{tag}")
    if reference.get("object", {}).get("type") != "tag":
        raise Refusal(f"{selection.source_repository} {tag}: not an annotated tag")
    tag_object = github.api(f"repos/{selection.source_repository}/git/tags/{reference['object']['sha']}")
    if tag_object.get("tag") != tag or tag_object.get("object", {}).get("type") != "commit":
        raise Refusal(f"{selection.source_repository} {tag}: tag object does not name a commit")
    if tag_object["object"].get("sha") != source_sha:
        raise Refusal(
            f"{selection.source_repository} {tag}: annotated tag dereferences to {tag_object['object'].get('sha')}, the Release asset names {source_sha}"
        )
    # "Protected-main source" is a claim the receipt makes; earn it: the
    # source commit must be an ancestor of (or equal to) the site's main.
    ancestry = github.api(f"repos/{selection.source_repository}/compare/main...{source_sha}").get("status")
    if ancestry not in {"identical", "behind"}:
        raise Refusal(f"{selection.source_repository} {tag}: source {source_sha} is not reachable from protected main ({ancestry})")

    record = {
        "arm64Digest": arm64[0],
        "chart": expected_chart,
        "chartConfigDigest": config["digest"],
        "chartLayerDigest": layer["digest"],
        "chartRepository": chart_repo,
        "chartTag": version,
        "manifestDigest": manifest_digest,
        "matchingChartLayerCount": 1,
        "release": {"assetDigest": asset_digest, "sourceSha": source_sha},
        "signer": {"issuer": ACTIONS_ISSUER, "subject": subject},
        "workloadImage": f"{image_repo}:{tag}@{index_digest}",
    }
    inspection = {"Chart.yaml": sha256_hex(chart_yaml), "values.yaml": sha256_hex(values_yaml)}
    return record, inspection


PROFILES = {"release-publisher": acquire_release_publisher}


def acquire(selection: Selection, version: str, registry, github, cosign) -> tuple:
    if VERSION_RE.fullmatch(version) is None:
        raise Refusal(f"{selection.slug}: version {version!r} is not a plain semantic version")
    profile = PROFILES[profile_for(selection.subject)]
    try:
        return profile(selection, version, registry, github, cosign)
    except (KeyError, TypeError, ValueError, tarfile.TarError, OSError) as error:
        # A malformed registry, Release or cosign answer is a refusal with a
        # name, never a traceback the tick cannot report.
        raise Refusal(f"{selection.slug} {version}: malformed answer ({type(error).__name__}: {error})") from None


# ---------------------------------------------------------------------------
# Receipt: byte-exact JSON renderer and the Markdown explanatory view.
# ---------------------------------------------------------------------------


def _compact(mapping: dict) -> str:
    return "{" + ", ".join(f'"{key}": {json.dumps(mapping[key])}' for key in sorted(mapping)) + "}"


def render_receipt_json(receipt: dict) -> str:
    """Render exactly the committed layout: nested identity objects on one
    line each, records sorted by slug, fields sorted within a record."""

    lines = [
        "{",
        f'  "chartLayerMediaType": {json.dumps(receipt["chartLayerMediaType"])},',
        f'  "capturedDate": {json.dumps(receipt["capturedDate"])},',
        '  "records": {',
    ]
    slugs = sorted(receipt["records"])
    for index, slug in enumerate(slugs):
        record = receipt["records"][slug]
        lines.append(f'    "{slug}": {{')
        keys = sorted(record)
        for position, key in enumerate(keys):
            value = record[key]
            rendered = _compact(value) if isinstance(value, dict) else json.dumps(value)
            comma = "," if position < len(keys) - 1 else ""
            lines.append(f'      "{key}": {rendered}{comma}')
        lines.append("    }" + ("," if index < len(slugs) - 1 else ""))
    lines += [
        "  },",
        f'  "schema": {json.dumps(receipt["schema"])},',
        f'  "tools": {_compact(receipt["tools"])}',
        "}",
    ]
    return "\n".join(lines) + "\n"


def load_receipt(root: Path) -> dict:
    return json.loads((root / RECEIPT_JSON).read_text(encoding="utf-8"))


def parse_inspection(markdown: str) -> dict:
    """``{short-name: {"Chart.yaml": digest, "values.yaml": digest}}`` from
    the committed view; the JSON does not carry these four values."""

    found = {}
    for short, filename, digest in INSPECTION_RE.findall(markdown):
        found.setdefault(short, {})[filename] = digest
    return found


def parse_capture_header(markdown: str) -> tuple:
    match = CAPTURE_HEADER_RE.search(markdown)
    if match is None:
        raise Refusal("receipt Markdown header does not state its capture date and issue")
    return match.group(1), match.group(2)


def short_name(slug: str) -> str:
    return slug.split("-", 1)[0]


def tool_pins(root: Path) -> dict:
    text = (root / VERSIONS_ENV).read_text(encoding="utf-8")
    pins = {}
    for tool in ("cosign", "oras"):
        values = re.findall(rf"^{tool.upper()}_VERSION=v(\S+)$", text, re.MULTILINE)
        if len(values) != 1:
            raise Refusal(f"versions.env must pin exactly one {tool.upper()}_VERSION")
        pins[tool] = values[0]
    return pins


def render_receipt_markdown(receipt: dict, selections: dict, inspection: dict, context: dict) -> str:
    """The explanatory view. ``context``: ``issues`` (``#N/#M``), ``advanced``
    (slugs whose selection moved), ``previous`` = ``(date, issues)``."""

    ordered = [slug for slug in selections if slug in receipt["records"]]
    moves = []
    for slug in ordered:
        version = receipt["records"][slug]["chartTag"]
        verb = "advanced" if slug in context["advanced"] else "kept"
        joiner = "to" if verb == "advanced" else "at"
        moves.append(f"{verb} {selections[slug].domain} {joiner} `{version}`")
    previous_date, previous_issues = context["previous"]
    tools = receipt["tools"]
    header = (
        f"Captured {receipt['capturedDate']} for issues {context['issues']}, which "
        + " and ".join(moves)
        + f"; it supersedes the issues {previous_issues} capture of {previous_date}."
    )
    rows = []
    bindings = []
    subjects = []
    hashes = []
    for slug in ordered:
        record = receipt["records"][slug]
        domain = selections[slug].domain
        chart = record["chart"]
        rows.append(
            f"| {domain} — `{record['chartRepository']}` | `{record['chartTag']}` | "
            f"`{record['manifestDigest']}` / `{record['chartConfigDigest']}` / `{record['chartLayerDigest']}` | "
            f"name/version/appVersion `{chart['name']}` / `{chart['version']}` / `{chart['appVersion']}` | "
            f"`{record['workloadImage']}` | `{record['arm64Digest']}` |"
        )
        bindings.append(
            f"- {domain}: protected-main source `{record['release']['sourceSha']}`; "
            f"immutable Release asset `{record['release']['assetDigest']}`."
        )
        subjects.append(f"- `{record['signer']['subject']}`")
        short = short_name(slug)
        for filename in ("Chart.yaml", "values.yaml"):
            hashes.append(f"- {short} `{filename}`: `{inspection[short][filename]}`")
    return (
        "# Issue 195 chart acquisition receipt\n\n"
        + _wrap(header)
        + " The canonical, machine-checked record is\n"
        "`195-chart-acquisition-receipt.json`; this Markdown is its explanatory view\n"
        "and must not be used as an independent source of release pins. This receipt\n"
        "is public, credential-free evidence for the exact chart artifacts committed\n"
        "by this repository. It is acquisition evidence, not proof of Flux or live\n"
        "cluster convergence.\n\n"
        f"The acquisition was run by `scripts/promote_releases.py` with Cosign {tools['cosign']},\n"
        "the exact `versions.env` pin; registry reads were direct anonymous OCI API\n"
        "resolutions whose `docker-content-digest` answers were required to agree with\n"
        "the fetched manifest bytes' own hashes (the technique reviewed in PRs #255 and\n"
        f"#259), with ORAS {tools['oras']} remaining the pinned acquisition tool of record.\n"
        "Each human tag was resolved, the resulting repository-at-digest was\n"
        "verified against the exact publisher identity and GitHub Actions issuer, the\n"
        "Helm layer was fetched by its own digest and inspected, and both chart and\n"
        "embedded workload tags were resolved a second time. Both pairs of resolutions\n"
        "agreed. The immutable Release asset and protected-main source commit were\n"
        "also bound for each acquisition. Public SLSA v1 attestations bound the exact\n"
        "workload indexes; chart trust remains each chart's exact Cosign signature.\n\n"
        "| workload and canonical chart repository | tag | OCI manifest / config / chart-layer digests | Chart.yaml identity | embedded workload image | Linux ARM64 child |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(rows)
        + "\n\nPublisher Release bindings:\n\n"
        + "\n".join(bindings)
        + "\n\nEach `vX.Y.Z` annotated tag was dereferenced to the commit above, and that\n"
        "same commit is what the Release asset's own `source_sha` field reports — two\n"
        "independent statements of the source binding that had to agree. Each manifest\n"
        "also states the chart and image digests independently of the registry\n"
        "resolution, and both agreed.\n\n"
        "Each signed OCI manifest contained exactly one layer with\n"
        "`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector\n"
        "copies exactly that single matching layer.\n\n"
        "Cosign accepted only these certificate subjects, with issuer\n"
        f"`{ACTIONS_ISSUER}`:\n\n"
        + "\n".join(subjects)
        + "\n\nExact-layer inspection hashes provide a reproducible custody check:\n\n"
        + "\n".join(hashes)
        + "\n\nFuture updates repeat this exact sequence: resolve the reviewed tag, verify the\n"
        "exact manifest, config, sole layer and signer, inspect chart identity and\n"
        "embedded workload image, bind the protected source and immutable Release\n"
        "asset, resolve the tag again, then atomically review the audit annotation and\n"
        "digest. Tag movement, deletion, or replacement after that point cannot change\n"
        "the bytes selected by the committed digest.\n"
    )


def _wrap(text: str, width: int = 78) -> str:
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Rewrite: counted substitution across the tracked tree.
# ---------------------------------------------------------------------------

STRING_RUN_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"(?:\s*"(?:[^"\\\n]|\\.)*")*')


def rewrite_literal_runs(text: str, tokens: dict) -> str:
    """Rewrite tokens inside Python string literals, including a value split
    across adjacent literals (the batteries wrap long digests that way). A
    run of adjacent literals is joined, rewritten, and re-split at the
    original chunk lengths so the file's shape is preserved."""

    def rewrite(match):
        run = match.group(0)
        pieces = re.findall(r'"((?:[^"\\\n]|\\.)*)"', run)
        gaps = re.split(r'"(?:[^"\\\n]|\\.)*"', run)
        joined = "".join(pieces)
        rewritten = joined
        for old, new in tokens.items():
            rewritten = rewritten.replace(old, new)
        if rewritten == joined:
            return run
        chunks = []
        cursor = 0
        for piece in pieces[:-1]:
            chunks.append(rewritten[cursor : cursor + len(piece)])
            cursor += len(piece)
        chunks.append(rewritten[cursor:])
        out = gaps[0]
        for chunk, gap in zip(chunks, gaps[1:]):
            out += f'"{chunk}"{gap}'
        return out

    return STRING_RUN_RE.sub(rewrite, text)


def _tracked_text_files(root: Path, run=run_command):
    listing = run(["git", "ls-files", "-z"], cwd=root)
    for name in listing.split("\0"):
        if not name or name.startswith(FRAGMENTS.as_posix() + "/"):
            continue
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        yield name, path, text


def join_literal_runs(text: str) -> str:
    """The logical view of a Python file: adjacent string literals joined
    into one, so a value split across literals counts as one token."""

    return STRING_RUN_RE.sub(
        lambda match: '"' + "".join(re.findall(r'"((?:[^"\\\n]|\\.)*)"', match.group(0))) + '"',
        text,
    )


def version_shapes(selection: Selection, old: str, new: str) -> list:
    """The closed grammar of where a version is pinned by value, keyed by
    slug (or by the selection's own manifest) so two workloads sharing a
    version string never clobber each other. Each entry is ``(pattern,
    replacement, path-or-None, required)``: the three pin surfaces every
    workload carries (its manifest annotation, the policy maps, the contract
    tuple) must match or the grammar is stale; the release-manifest fixture
    shape is a per-workload test fixture that need not exist."""

    slug, escaped = selection.slug, re.escape(old)
    replacement = rf"\g<1>{new}\g<2>"
    return [
        (re.compile(rf'({re.escape(ANNOTATION)}: "){escaped}(")'), replacement, selection.path, True),
        (re.compile(rf'("{slug}":\s*\{{\s*"tag":\s*"){escaped}(")'), replacement, None, True),
        (re.compile(rf'("{slug}":\s*\(\s*"){escaped}(",)'), replacement, None, True),
        (
            re.compile(rf'("repository": "{re.escape(selection.chart_repository)}",\s*"version": "){escaped}(")'),
            replacement,
            None,
            False,
        ),
    ]


def rewrite_tree(root: Path, selections: dict, old_receipt: dict, new_receipt: dict, old_inspection: dict, new_inspection: dict, run=run_command) -> list:
    """Apply every value change between the two receipts to every tracked
    file. Returns the changed paths. Every old digest must vanish from the
    tree and every new one must appear exactly as often as the old did —
    counted on the logical view, so a digest split across literals cannot
    survive unseen."""

    tokens = {}
    shapes = []
    for slug, new_record in new_receipt["records"].items():
        old_record = old_receipt["records"][slug]
        if old_record == new_record:
            continue
        for key in ("manifestDigest", "chartConfigDigest", "chartLayerDigest", "arm64Digest"):
            tokens[old_record[key]] = new_record[key]
        tokens[old_record["release"]["assetDigest"]] = new_record["release"]["assetDigest"]
        tokens[old_record["release"]["sourceSha"]] = new_record["release"]["sourceSha"]
        tokens[old_record["workloadImage"]] = new_record["workloadImage"]
        short = short_name(slug)
        for filename in ("Chart.yaml", "values.yaml"):
            old_hash = old_inspection[short][filename].split(":", 1)[1]
            tokens[old_hash] = new_inspection[short][filename].split(":", 1)[1]
        if old_record["chartTag"] != new_record["chartTag"]:
            shapes += version_shapes(selections[slug], old_record["chartTag"], new_record["chartTag"])
    for old, new in tokens.items():
        if old == new:
            raise Refusal(f"token {old} is unchanged between receipts")
    changed = []
    counts = {old: 0 for old in tokens}
    shape_hits = [0] * len(shapes)
    for name, path, text in _tracked_text_files(root, run):
        if name in {RECEIPT_JSON.as_posix(), RECEIPT_MD.as_posix()}:
            continue
        logical = join_literal_runs(text) if name.endswith(".py") else text
        before = text
        for old in tokens:
            counts[old] += logical.count(old)
        if name.endswith(".py"):
            text = rewrite_literal_runs(text, tokens)
        for old, new in tokens.items():
            text = text.replace(old, new)
        for position, (pattern, replacement, only, _required) in enumerate(shapes):
            if only is None or only == name:
                text, hits = pattern.subn(replacement, text)
                shape_hits[position] += hits
        if text != before:
            after = join_literal_runs(text) if name.endswith(".py") else text
            for old, new in tokens.items():
                if old in after:
                    raise Refusal(f"{name}: {old} survives the rewrite")
                if after.count(new) != logical.count(old) + logical.count(new):
                    raise Refusal(f"{name}: {new} occurrence count changed unexpectedly")
            path.write_text(text, encoding="utf-8")
            changed.append(name)
    for old, count in counts.items():
        if count == 0:
            raise Refusal(f"{old} was pinned nowhere in the tree; the rewrite grammar is stale")
    for position, hits in enumerate(shape_hits):
        if hits == 0 and shapes[position][3]:
            raise Refusal(f"version pin shape {position + 1} matched nowhere in the tree; the rewrite grammar is stale")
    return changed


def rewrite_readme(root: Path, selections: dict, receipt: dict, issues: str) -> bool:
    text = (root / README).read_text(encoding="utf-8")
    matches = README_ROW_RE.findall(text)
    if len(matches) != 1:
        raise Refusal("README carries no single machine-maintained current-selection sentence")
    current = " and ".join(
        f"{selection.domain} `{receipt['records'][slug]['chartTag']}`"
        for slug, selection in selections.items()
    )
    replacement = (
        f"Current selections: {current}, captured {receipt['capturedDate']} for issues {issues} "
        "in `docs/assurance/195-chart-acquisition-receipt.json`"
    )
    rewritten = README_ROW_RE.sub(lambda _: replacement, text, count=1)
    (root / README).write_text(rewritten, encoding="utf-8")
    return rewritten != text


def fragment_path(issue: int, targets: dict) -> Path:
    slug = "promote-" + "-".join(f"{s}-{v.replace('.', '-')}" for s, v in sorted(targets.items()))
    if FRAGMENT_SLUG_RE.fullmatch(slug) is None:
        raise Refusal(f"fragment slug {slug!r} violates the fragment grammar")
    return FRAGMENTS / f"{issue}-{slug}.md"


def render_fragment(selections: dict, targets: dict, issues: str) -> str:
    moved = " and ".join(f"{selections[s].domain} `{v}`" for s, v in sorted(targets.items()))
    return (
        "### Changed\n\n"
        f"- Advance the exact signed chart selection to the published release — {moved} — "
        f"remediating the drift the deploy-assurance watchdog reported (issues {issues}), by the "
        "receipted ceremony in `scripts/promote_releases.py`: resolving each reviewed tag twice with "
        "identical answers, verifying each repository-at-digest against the publisher's "
        "`release-publisher.yml@refs/heads/main` keyless identity, inspecting the sole Helm chart layer "
        "and its embedded workload image, verifying the public SLSA v1 attestation at the exact workload "
        "index digest, and binding the protected-main source commit and immutable Release asset before "
        "the annotation and digest moved together.\n"
        "- Recapture `docs/assurance/195-chart-acquisition-receipt.{json,md}` for that acquisition, keeping "
        "every reviewed tag/digest pair identical across the receipt, `scripts/validate_signature_policy.py`, "
        "`policies/conftest/kubernetes.rego`, every `kubernetes/**` selection and the security batteries "
        "that pin them, so no two can disagree.\n"
    )


def apply_promotion(root: Path, selections: dict, acquired: dict, issue: int, issues: str, captured: str, run=run_command) -> list:
    """Write every surface for ``acquired`` (``{slug: (record, inspection)}``).
    Returns the changed and created paths."""

    old_receipt = load_receipt(root)
    old_markdown = (root / RECEIPT_MD).read_text(encoding="utf-8")
    old_inspection = parse_inspection(old_markdown)
    previous = parse_capture_header(old_markdown)
    new_receipt = json.loads(json.dumps(old_receipt))
    new_receipt["capturedDate"] = captured
    new_receipt["tools"] = tool_pins(root)
    new_inspection = json.loads(json.dumps(old_inspection))
    for slug, (record, inspection) in acquired.items():
        if slug not in new_receipt["records"]:
            raise Refusal(f"{slug}: the receipt contract does not yet bind this workload; extend the identity closure first")
        new_receipt["records"][slug] = record
        new_inspection[short_name(slug)] = inspection
    # Every refusal that needs no rewrite comes BEFORE the first write, so a
    # refused promotion never leaves a half-rewritten tree behind.
    targets = {slug: record["chartTag"] for slug, (record, _) in acquired.items()}
    fragment = fragment_path(issue, targets)
    if (root / fragment).exists():
        raise Refusal(f"{fragment} already exists; fragments are immutable")
    if len(README_ROW_RE.findall((root / README).read_text(encoding="utf-8"))) != 1:
        raise Refusal("README carries no single machine-maintained current-selection sentence")
    changed = rewrite_tree(root, selections, old_receipt, new_receipt, old_inspection, new_inspection, run)
    (root / RECEIPT_JSON).write_text(render_receipt_json(new_receipt), encoding="utf-8")
    context = {"issues": issues, "advanced": set(acquired), "previous": previous}
    (root / RECEIPT_MD).write_text(
        render_receipt_markdown(new_receipt, selections, new_inspection, context), encoding="utf-8"
    )
    changed += [RECEIPT_JSON.as_posix(), RECEIPT_MD.as_posix()]
    if rewrite_readme(root, selections, new_receipt, issues):
        changed.append(README.as_posix())
    (root / fragment).write_text(render_fragment(selections, targets, issues), encoding="utf-8")
    changed.append(fragment.as_posix())
    return changed


# ---------------------------------------------------------------------------
# Status and verify.
# ---------------------------------------------------------------------------


def status_exit_code(report: dict) -> int:
    """0 when every selection is current; 3 when ANY selection is not —
    behind, ahead or unpublished alike, so a wrapper cannot read a non-zero
    exit as "a newer release exists"."""

    return 3 if any(entry["verdict"] != "current" for entry in report.values()) else 0


# gh reports the request's final status as the LAST thing it says; only a
# refusal that ENDS with the Not Found marker is a 404, so a body phrase or
# proxy line quoting "(HTTP 404)" ahead of a real "(HTTP 500)" stays a 500.
NOT_FOUND_RE = re.compile(r"\(HTTP 404\)\s*$")


def latest_release(github: GitHub, repository: str) -> tuple:
    """``(version-without-v, tag)`` of the latest published Release, or
    ``(None, None)`` when the repository publishes nothing."""

    try:
        release = github.api(f"repos/{repository}/releases/latest")
    except Refusal as error:
        # Only a refusal that ENDS with gh's Not Found marker means "publishes
        # nothing"; any other refusal (a transport failure that happens to
        # mention 4040, a 403, a 5xx, a 404 quoted ahead of the final status)
        # propagates with its real classification.
        if NOT_FOUND_RE.search(str(error)):
            return None, None
        raise
    tag = release.get("tag_name", "")
    if not tag.startswith("v") or VERSION_RE.fullmatch(tag[1:]) is None:
        raise Refusal(f"{repository}: latest release tag {tag!r} is not a plain vX.Y.Z tag")
    return tag[1:], tag


def status(root: Path, github: GitHub) -> dict:
    """``{slug: {"committed", "latest", "verdict"}}`` for every selection."""

    report = {}
    for slug, selection in discover_selections(root).items():
        latest, _ = latest_release(github, selection.source_repository)
        if latest is None:
            verdict = "unpublished"
        else:
            verdict = ASSURANCE.drift_verdict(selection.version, latest)
        report[slug] = {"committed": selection.version, "latest": latest, "verdict": verdict}
    return report


def verify(root: Path, registry: Registry, github: GitHub, cosign: Cosign) -> list:
    """Re-derive the committed receipt from the registry; return the list of
    disagreements (empty means the committed evidence reproduces)."""

    cosign.require_pinned_version()
    receipt = load_receipt(root)
    inspection = parse_inspection((root / RECEIPT_MD).read_text(encoding="utf-8"))
    problems = []
    for slug, selection in discover_selections(root).items():
        record, hashes = acquire(selection, selection.version, registry, github, cosign)
        committed = receipt["records"].get(slug)
        if committed != record:
            problems.append(f"{slug}: committed record differs from a fresh acquisition")
        if selection.digest != record["manifestDigest"]:
            problems.append(f"{slug}: {selection.path} pins {selection.digest}, the registry serves {record['manifestDigest']}")
        if inspection.get(short_name(slug)) != hashes:
            problems.append(f"{slug}: inspection hashes differ from the committed view")
    return problems


# ---------------------------------------------------------------------------
# Pull requests: the tick's planning, network-free.
# ---------------------------------------------------------------------------


def parse_branch(branch: str) -> tuple | None:
    """``(base, issue, {slug: version})`` from a promoter branch, or ``None``."""

    match = BRANCH_RE.match(branch)
    if match is None:
        return None
    targets = {}
    for part in match.group(3).split("_"):
        target = TARGET_RE.match(part)
        if target is None:
            return None
        targets[target.group(1)] = target.group(2)
    return match.group(1), int(match.group(2)), targets


def branch_name(base: str, issue: int, targets: dict) -> str:
    """``promoter/<base7>/<issue>-<slug>-<version>[_<slug>-<version>]``: the
    base segment keeps a re-cut from colliding with a superseded branch."""

    return BRANCH_PREFIX + f"{base[:7]}/{issue}-" + "_".join(f"{s}-{v}" for s, v in sorted(targets.items()))


def plan(report: dict, open_prs: list) -> dict:
    """Decide the tick's actions from the status report and the open
    promoter pull requests (``{"number", "branch", "behind_by"}``).

    Returns ``{"targets": {slug: version}, "keep": [numbers],
    "supersede": [numbers]}``. Any selection the watchdog would call
    unpublished or ahead is refused: the promoter only ever moves a
    selection FORWARD to a published release.
    """

    targets = {}
    for slug, entry in report.items():
        if entry["verdict"] in {"unpublished", "ahead"}:
            raise Refusal(f"{slug}: selection is {entry['verdict']}; the watchdog owns this condition")
        if entry["verdict"] == "behind":
            targets[slug] = entry["latest"]
    keep, supersede = [], []
    for pr in open_prs:
        parsed = parse_branch(pr["branch"])
        if parsed is None:
            continue
        _, _, pr_targets = parsed
        if pr_targets == targets and not pr["behind_by"] and not keep:
            keep.append(pr["number"])
        else:
            supersede.append(pr["number"])
    return {"targets": targets, "keep": keep, "supersede": supersede}


# ---------------------------------------------------------------------------
# The tick: git, gates, signing, push, Draft pull request.
# ---------------------------------------------------------------------------


class Workspace:
    """The promoter's own clone: fetched, reset and branched every tick."""

    def __init__(self, root: Path, run=run_command):
        self.root = root
        self._run = run

    def git(self, *argv, env=None) -> str:
        return self._run(["git", *argv], cwd=self.root, env=env)

    def refresh(self) -> str:
        self.git("fetch", "--quiet", "origin", "main")
        status_lines = self.git("status", "--porcelain").strip()
        if status_lines:
            raise Refusal("promoter clone is dirty; refusing to reset another writer's work")
        self.git("checkout", "--quiet", "--detach", "origin/main")
        return self.git("rev-parse", "HEAD").strip()

    def restore(self, base: str) -> None:
        """Return the promoter's own clone to the fetched base with no
        working-tree residue — after a pushed cut, a refusal, or a dry run."""

        self.git("checkout", "--quiet", "--detach", base)
        self.git("reset", "--quiet", "--hard", base)
        self.git("clean", "--quiet", "-fd")

    def identity(self, github: GitHub) -> dict:
        """The owner's noreply identity, from the authenticated user — never
        from whoever authored the tip of main (a squash-merged Dependabot
        pull request puts its bot there) — reconciled with published history."""

        user = github.api("user")
        login, uid = user.get("login"), user.get("id")
        if login != ASSIGNEE or not isinstance(uid, int):
            raise Refusal("gh is not authenticated as the repository owner")
        email = f"{uid}+{login}@{NOREPLY_DOMAIN}"
        name = self.git("log", "-1", "--fixed-strings", f"--author=<{email}>", "--format=%an", "origin/main").strip()
        if not name:
            raise Refusal("the owner's noreply identity has no published commit on origin/main")
        return {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
        }

    def signing_key(self, github: GitHub) -> str:
        login = github.api("user").get("login")
        registered = {
            " ".join(key["key"].split()[:2])
            for key in github.api_pages(f"users/{login}/ssh_signing_keys")
        }
        loaded = {" ".join(line.split()[:2]) for line in self._run(["ssh-add", "-L"]).splitlines() if line.strip()}
        matched = sorted(registered & loaded)
        if len(matched) != 1:
            raise Refusal(f"expected exactly one registered signing key in the agent, found {len(matched)}")
        return matched[0]

    def numstat(self, base: str) -> tuple:
        """``(files, added, deleted)`` for the rewritten tree against ``base``.

        All three come from the SAME numstat rows, deliberately: the file
        count is ``len(rows)``, never the length of ``apply_promotion``'s
        returned path list. Those two can differ — a gate that rewrites a
        tracked file (a formatter, a regenerated badge) changes what the
        commit records without changing what the rewrite reported — and the
        body must state what the commit records, because that is what the
        command it names reproduces. Measured from the index after ``add -A``,
        which carries exactly what the commit then records, so a reviewer
        reproduces these numbers with ``git diff --numstat <base>..HEAD`` on
        the published head. A row that is not two integers and a path — a
        binary one, which git renders ``-`` — refuses: an accounting it cannot
        measure the tool must not state.
        """

        self.git("add", "-A")
        files = added = deleted = 0
        for line in self.git("diff", "--numstat", "--cached", base).splitlines():
            fields = line.split("\t")
            if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
                raise Refusal("a numstat row is not measurable; refusing to state an accounting this cut cannot prove")
            files += 1
            added += int(fields[0])
            deleted += int(fields[1])
        return files, added, deleted

    def commit_signed(self, message: str, identity: dict, key: str) -> str:
        env = dict(os.environ)
        env.update(identity)
        self.git("add", "-A")
        self._run(
            ["git", "-c", "gpg.format=ssh", "-c", f"user.signingkey=key::{key}", "commit", "--quiet", "-S", "-F", "-"],
            cwd=self.root,
            input_text=message,
            env=env,
        )
        return self.git("rev-parse", "HEAD").strip()


def pr_title(selections: dict, targets: dict) -> str:
    moved = ", ".join(f"{selections[s].domain} {v}" for s, v in sorted(targets.items()))
    return f"Promote {moved} to the published release by receipted ceremony"


ACCOUNTING_PREFIX = "Accounting (measured, "


def accounting_line(base: str, files: int, added: int, deleted: int) -> str:
    """The actuals AGENTS.md requires of a pull-request body, in the shape the
    agent lanes already write by hand, naming the command that reproduces it so
    a reviewer re-measures rather than trusting the number."""

    return (
        f"{ACCOUNTING_PREFIX}`git diff --numstat {base[:7]}..HEAD`): "
        f"{files} files, +{added} / -{deleted}, net {added - deleted:+d}."
    )


def pr_body(selections: dict, acquired: dict, issues: list, head_base: str, accounting: str) -> str:
    """One line per moved workload; the regenerated receipt is the evidence.
    ``accounting`` is measured by the workspace and passed in, so one string
    reaches the commit message and the body and the two cannot disagree."""

    lines = [
        "## Promotion",
        "",
        f"Opened by `scripts/promote_releases.py` (issue #286) from protected `main` at `{head_base}`.",
        "",
    ]
    for slug, (record, _) in sorted(acquired.items()):
        lines.append(f"- {selections[slug].domain}: `{selections[slug].version}` to `{record['chartTag']}`, workload index `{record['workloadImage'].split('@', 1)[1]}`")
    lines += ["", "Evidence: the regenerated `docs/assurance/195-chart-acquisition-receipt.*` files in this pull request.", ""]
    lines += [accounting, ""]
    lines += [f"Closes #{number}" for number in issues]
    lines += ["", SIGNATURE, ""]
    body = "\n".join(lines)
    # EXACTLY one accounting line. A body stating two sets of numbers states
    # neither: a reader cannot tell which the commit records, and the whole
    # point of the line is that one command reproduces it. Enforced here
    # rather than trusted, because the string is composed by the caller.
    if body.count(ACCOUNTING_PREFIX) != 1:
        raise Refusal(f"a promotion body states its accounting exactly once, not {body.count(ACCOUNTING_PREFIX)} times")
    return body


def owned_pull_request(pr: dict) -> dict | None:
    """The identity tuple every promoter pull request must satisfy before any
    read-derived decision or write: opened by the owner's credential, from a
    promoter branch in THIS repository, against ``main`` of this repository,
    Draft state known. Every part is immutable or owner-only. Anything else —
    a fork with a ``promoter/`` head above all — is never planned or
    superseded by the owner's unattended process."""

    head, base = pr.get("head") or {}, pr.get("base") or {}
    branch = head.get("ref") or ""
    if (
        (head.get("repo") or {}).get("full_name") != REPOSITORY
        or (base.get("repo") or {}).get("full_name") != REPOSITORY
        or base.get("ref") != "main"
        or (pr.get("user") or {}).get("login") != ASSIGNEE
        or parse_branch(branch) is None
        or SHA_RE.fullmatch(head.get("sha") or "") is None
        or not isinstance(pr.get("draft"), bool)
        or not isinstance(pr.get("number"), int)
    ):
        return None
    return {"number": pr["number"], "branch": branch, "head": head["sha"], "draft": pr["draft"]}


def open_promoter_prs(github: GitHub) -> list:
    found = []
    for pr in github.api_pages(f"repos/{REPOSITORY}/pulls?state=open&per_page=100"):
        branch = (pr.get("head") or {}).get("ref") or ""
        if not branch.startswith(BRANCH_PREFIX):
            continue
        owned = owned_pull_request(pr)
        if owned is None:
            log(f"PR #{pr.get('number')} has a promoter head but is not an owned promoter pull request; ignored")
            continue
        compare = github.api(f"repos/{REPOSITORY}/compare/main...{owned['head']}")
        behind_by = compare.get("behind_by")
        if not isinstance(behind_by, int):
            # Unknown freshness is neither current nor behind: the planner
            # keeps the pull request, making no cut and no supersede.
            log(f"PR #{owned['number']}: base freshness is unknown; kept, not judged current")
            behind_by = None
        owned["behind_by"] = behind_by
        found.append(owned)
    return found


def drift_issues(github: GitHub, targets: dict) -> list:
    issues = github.api_pages(f"repos/{REPOSITORY}/issues?state=open&labels=delivery-lane&per_page=100")
    wanted = {ASSURANCE.condition_title(f"site-drift/{slug}") for slug in targets}
    return sorted(issue["number"] for issue in issues if "pull_request" not in issue and issue["title"] in wanted)


def supersede(github: GitHub, number: int, reason: str, dry_run: bool) -> None:
    if dry_run:
        log(f"PR #{number} WOULD be closed as superseded: {reason}")
        return
    github.mutate(
        f"repos/{REPOSITORY}/issues/{number}/comments",
        "POST",
        body={"body": f"Superseded by the promoter: {reason}. The branch is left for the owner.\n\n{SIGNATURE}"},
    )
    github.mutate(f"repos/{REPOSITORY}/pulls/{number}", "PATCH", body={"state": "closed"})
    log(f"PR #{number} closed as superseded: {reason}")


def cut_promotion(workspace: Workspace, github: GitHub, registry: Registry, cosign: Cosign, selections: dict, targets: dict, dry_run: bool) -> int:
    base = workspace.git("rev-parse", "origin/main").strip()
    issues = drift_issues(github, targets)
    if not issues:
        raise Refusal("no open deploy-assurance drift issue names these workloads; wait for the watchdog's tick")
    issue_refs = "/".join(f"#{n}" for n in issues)
    cosign.require_pinned_version()
    acquired = {slug: acquire(selections[slug], version, registry, github, cosign) for slug, version in sorted(targets.items())}
    branch = branch_name(base, issues[0], targets)
    # The cut is made on the detached base and pushed to the remote branch
    # name, so neither a dry run nor a live tick leaves a local ref behind.
    changed = apply_promotion(workspace.root, selections, acquired, issues[0], issue_refs, utc_today(), workspace._run)
    log(f"rewrote {len(changed)} paths for {branch}: " + ", ".join(changed))
    for gate in GATES:
        try:
            with timed_call("gate", " ".join(gate), GATE_TIMEOUT_SECONDS):
                workspace._run(list(gate), cwd=workspace.root, timeout=GATE_TIMEOUT_SECONDS)
        except Refusal as error:
            # The output stays in the local log: a gate's findings (gitleaks
            # above all) are never forwarded into a public issue comment.
            log(f"gate `{' '.join(gate)}` FAILED: {error}")
            raise Refusal(f"gate `{' '.join(gate)}` failed; the promoter log carries its output") from None
        log(f"gate `{' '.join(gate)}` OK")
    title = pr_title(selections, targets)
    # Measured after the rewrite and before the commit, so one accounting
    # string reaches the commit message and the pull-request body alike.
    body = pr_body(selections, acquired, issues, base, accounting_line(base, *workspace.numstat(base)))
    if dry_run:
        log(f"WOULD commit, push and open Draft PR `{title}` from {branch} (dry run)")
        return 0
    head = workspace.commit_signed(f"{title}\n\n{body}", workspace.identity(github), workspace.signing_key(github))
    try:
        with timed_call("gate", " ".join(PUBLICATION_GATE), GATE_TIMEOUT_SECONDS):
            workspace._run(list(PUBLICATION_GATE), cwd=workspace.root, timeout=GATE_TIMEOUT_SECONDS)
    except Refusal as error:
        log(f"gate `{' '.join(PUBLICATION_GATE)}` FAILED on the signed commit {head}: {error}")
        raise Refusal(f"gate `{' '.join(PUBLICATION_GATE)}` refused the outgoing commit; nothing was pushed") from None
    log(f"gate `{' '.join(PUBLICATION_GATE)}` OK on the outgoing commit {head}")
    with timed_call("git-push", f"origin {branch}", COMMAND_TIMEOUT_SECONDS):
        workspace.git("push", "--quiet", "origin", f"HEAD:refs/heads/{branch}")
    body_path = workspace.root / ".git" / "promoter-pr-body.md"
    body_path.write_text(body, encoding="utf-8")
    argv = ["pr", "create", "--repo", REPOSITORY, "--draft", "--base", "main", "--head", branch, "--title", title, "--body-file", str(body_path), "--milestone", MILESTONE, "--assignee", ASSIGNEE]
    for label in PR_LABELS:
        argv += ["--label", label]
    url = github.command(argv).strip()
    body_path.unlink()
    number = int(url.rstrip("/").rsplit("/", 1)[1])
    github.mutate(f"repos/{REPOSITORY}/issues/{number}/labels", "POST", body={"labels": list(REVIEW_LABELS)})
    log(f"opened Draft PR #{number} at {head} and armed both review lanes")
    return number


def redact(text: str) -> str:
    """What a public failure comment may carry: one line, no Markdown
    fences, and no private host detail — every path-shaped token that is not
    a scheme URL, every dotted address, this workstation's host name and the
    login name are replaced. The raw text stays in the local log."""

    flat = re.sub(r"[`\r\n]+", " ", text)
    flat = re.sub(r"(?<!\S)(?!\w+://)\S*/\S*", "<path>", flat)
    flat = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<addr>", flat)
    for private in (socket.gethostname(), socket.gethostname().split(".")[0], os.environ.get("USER"), os.environ.get("LOGNAME")):
        if private and len(private) > 2:
            flat = flat.replace(private, "<host>")
    return flat


def report_failure(github: GitHub, targets: dict, step: str, error: str, dry_run: bool) -> None:
    """One idempotent comment per (targets, step) on the drift issue. Its
    one call site is a refused CUT — the failure whose silence would
    otherwise hide behind the watchdog's open drift issue. Every other
    refusal in a tick (a dirty clone, a status or planning refusal) stays in
    the local log and the tick's exit status."""

    marker = "promoter-failure " + " ".join(f"{s}={v}" for s, v in sorted(targets.items())) + f" step={step}"
    try:
        issues = drift_issues(github, targets)
    except Refusal:
        issues = []
    if not issues or dry_run:
        return
    number = issues[0]
    # Only the promoter's own earlier report counts as "already reported":
    # the owner's authenticated identity (login and immutable id) and the
    # exact marker as the first line. A marker pasted by anyone else, or
    # anywhere else in a body, never suppresses the alert.
    owner = github.api("user")
    if owner.get("login") != ASSIGNEE or not isinstance(owner.get("id"), int):
        raise Refusal("gh is not authenticated as the repository owner")
    fence = f"`{marker}`\n"
    existing = github.api_pages(f"repos/{REPOSITORY}/issues/{number}/comments?per_page=100")
    if any(
        (c.get("user") or {}).get("login") == owner["login"]
        and (c.get("user") or {}).get("id") == owner["id"]
        and (c.get("body") or "").startswith(fence)
        for c in existing
    ):
        return
    # The reason is fenced, single-line, bounded and redacted: it can carry
    # strings an untrusted Release manifest chose, and a public comment must
    # never render them as Markdown or mentions, nor disclose this host.
    detail = redact(error)[:400]
    github.mutate(
        f"repos/{REPOSITORY}/issues/{number}/comments",
        "POST",
        body={"body": f"`{marker}`\n\nThe promoter could not open a promotion at step `{step}`:\n\n```\n{detail}\n```\n\n{SIGNATURE}"},
    )


# ---------------------------------------------------------------------------
# Proof-based receipts for promotion pull requests (issue #309).
#
# A promotion pull request's verdict is EARNED by re-derivation, never by
# reading the pull request. Three proofs, in the order the step runs them:
#
#   0. Novelty. No comment by the reviewer App already binds this head, so a
#      verdict is posted at most once per head.
#   1. Confinement. Every path `main...HEAD` changes is a path the promoter's
#      own ``apply_promotion`` writes. The permitted set is not a list kept in
#      this file — it is the return value of that very function, re-run.
#   2. Re-derivation. From `main`, the issue-195 acquisition ceremony runs
#      again against the registry, the site's immutable GitHub Release and its
#      protected `main`, the whole promotion surface is re-rendered from the
#      resulting record, and every blob is compared to the head's by object id.
#      A single mutated byte anywhere in that surface is a different object id.
#
# Failing 1 or 2 is a definitive REQUEST-CHANGES: those comparisons are this
# tool's own arithmetic over bytes it produced. A refusal from the network, the
# registry, cosign or the ceremony is NOT: the promoter cannot attribute it to
# the pull request, so it logs and skips the tick rather than publishing a
# verdict it cannot stand behind. Nothing here flips Ready or merges.
# ---------------------------------------------------------------------------

# The machine-local helper that mints the reviewer App's repository-scoped
# token is named by ENVIRONMENT, never by a committed path: the tool must carry
# no workstation path (safety invariant 12), and an unset variable means the
# receipt step reports itself unconfigured and does nothing at all.
RECEIPT_TOKEN_COMMAND_ENV = "PROMOTER_RECEIPT_TOKEN_COMMAND"
RECEIPT_SIGNATURE = "- Promoter (adversarial reviewer)"
RECEIPT_VALIDATOR = Path("scripts/validate_review_receipt.py")
# A promotion surface is a handful of paths; a diff claiming hundreds is a
# report to bound rather than to render in full.
RECEIPT_PATH_CEILING = 20
CAPTURE_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def receipt_actor() -> tuple:
    """The reviewer App's immutable identity, read from the Ready rule."""

    return (READY.REVIEWS_APP, READY.REVIEWS_APP_USER_ID, "Bot", READY.REVIEWS_APP_ID)


def app_receipt_heads(github: GitHub, number: int) -> set:
    """Every head an App-posted comment on this pull request already binds.

    Only the App's own comments count, matched on the same four-part actor the
    Ready evaluator uses; a `HEAD:` line pasted by anybody else is text.
    """

    heads = set()
    for comment in github.api_pages(f"repos/{REPOSITORY}/issues/{number}/comments?per_page=100"):
        user = comment.get("user") or {}
        actor = (
            user.get("login"),
            user.get("id"),
            user.get("type"),
            (comment.get("performed_via_github_app") or {}).get("id"),
        )
        if actor != receipt_actor():
            continue
        for line in (comment.get("body") or "").replace("\r\n", "\n").splitlines():
            if line.startswith("HEAD: ") and SHA_RE.fullmatch(line[6:].strip()):
                heads.add(line[6:].strip())
    return heads


@contextlib.contextmanager
def scratch_worktree(workspace: Workspace, commit: str):
    """A disposable detached worktree of the promoter's OWN clone at ``commit``.

    It lives outside the repository so no scratch path can ever be staged, and
    it is removed on every exit path — the receipt states that removal, so the
    statement has to be true.
    """

    holder = Path(tempfile.mkdtemp(prefix="promoter-proof-"))
    tree = holder / "tree"
    workspace.git("worktree", "add", "--quiet", "--detach", str(tree), commit)
    try:
        yield tree
    finally:
        try:
            workspace.git("worktree", "remove", "--force", str(tree))
        except Refusal:
            log("scratch worktree could not be removed by git; pruning")
        shutil.rmtree(holder, ignore_errors=True)
        workspace.git("worktree", "prune")


def head_blob(workspace: Workspace, commit: str, name: str):
    """The object id of ``name`` at ``commit``, or ``None`` when it is absent."""

    try:
        return workspace.git("rev-parse", f"{commit}:{name}").strip()
    except Refusal:
        return None


def rendered_blob(workspace: Workspace, path: Path) -> str:
    """The object id of a re-rendered file's exact bytes.

    ``--no-filters`` is what makes this a BYTE comparison: it hashes the file
    as it sits, with no attribute-driven line-ending or clean filter in the
    way, so equal ids mean equal bytes and nothing weaker.
    """

    return workspace.git("hash-object", "--no-filters", "--", str(path)).strip()


def safe_path(name: str) -> str:
    """One repository path, safe to render inside a public comment.

    Path names on a head are attacker-chooseable text. Everything outside the
    ordinary path alphabet becomes ``?`` and the result is bounded, so a
    crafted name cannot smuggle Markdown, a mention or a line break into a
    receipt.
    """

    cleaned = re.sub(r"[^A-Za-z0-9._/+-]", "?", name)
    return cleaned[:120] + ("…" if len(cleaned) > 120 else "")


def path_list(names) -> str:
    """A bounded, rendered list of repository paths."""

    shown = [f"`{safe_path(name)}`" for name in sorted(names)[:RECEIPT_PATH_CEILING]]
    if len(names) > RECEIPT_PATH_CEILING:
        shown.append(f"and {len(names) - RECEIPT_PATH_CEILING} more")
    return ", ".join(shown) if shown else "none"


def captured_date(workspace: Workspace, head: str) -> str:
    """The capture date the head's receipt states, bound to its own commit.

    This is the ONE value the proof takes from the head, because
    ``apply_promotion`` stamps the day the cut ran and cannot recover it from
    the registry. It is bound anyway: it must be a plain ISO date within a day
    of the head commit's own author timestamp — and that commit is signed — so
    the only thing it can be is the date the promoter actually cut, give or
    take a midnight boundary. Anything else is a mutation.
    """

    try:
        document = json.loads(workspace.git("show", f"{head}:{RECEIPT_JSON.as_posix()}"))
        stamp = int(workspace.git("show", "-s", "--format=%at", head).strip())
    except (ValueError, TypeError) as error:
        # The head's receipt file is untrusted bytes: a malformed one is a
        # named refusal, never a traceback that escapes every handler above.
        raise Refusal(f"the receipt at {head[:7]} is unreadable ({type(error).__name__})") from None
    stated = document.get("capturedDate") if isinstance(document, dict) else None
    if not isinstance(stated, str) or CAPTURE_DATE_RE.fullmatch(stated) is None:
        raise Refusal(f"the receipt at {head[:7]} states no plain ISO capture date")
    day = dt.datetime.fromtimestamp(stamp, dt.timezone.utc).date()
    allowed = {(day + dt.timedelta(days=offset)).isoformat() for offset in (-1, 0, 1)}
    if stated not in allowed:
        raise Refusal(
            f"capture date {stated} is not the head commit's own date {day.isoformat()}"
        )
    return stated


def workload_statement(selection: Selection, record: dict) -> str:
    """One workload's re-derived figures, exactly as the ceremony proved them."""

    image, index = record["workloadImage"].split("@", 1)
    tag = f"v{record['chartTag']}"
    return (
        f"   - {selection.domain} `{record['chartTag']}`: chart"
        f" `{record['chartRepository']}` manifest `{record['manifestDigest']}`"
        f" (config `{record['chartConfigDigest']}`, sole Helm layer"
        f" `{record['chartLayerDigest']}`), workload `{image}` index `{index}`"
        f" with one linux/arm64 child `{record['arm64Digest']}`, both"
        f" cosign-verified AT THOSE DIGESTS against"
        f" `{record['signer']['subject']}`; the immutable Release"
        f" https://github.com/{selection.source_repository}/releases/tag/{tag}"
        f" states the same pair, its `release-manifest.json` bytes hash to"
        f" `{record['release']['assetDigest']}`, and its annotated tag"
        f" dereferences to `{record['release']['sourceSha']}`, reachable from"
        f" that site's protected `main`."
    )


def approve_receipt(head: str, base: str, surface: list, statements: list, captured: str) -> str:
    """The APPROVE receipt, in the contract's shape (AGENTS.md, Verdict format)."""

    return "\n".join(
        [
            f"HEAD: {head}",
            "VERDICT: APPROVE",
            "",
            "Proof-based receipt for a promotion pull request, composed and posted from"
            " the promoter's own tick (issue #309). No figure below was read from this"
            f" pull request: each was re-derived from `main` at `{base[:7]}`, the OCI"
            " registry and the site's immutable GitHub Release.",
            "",
            f"1. Confinement. This head changes {len(surface)} path(s), every one of them"
            " written by the promoter's own `apply_promotion` when the cut was"
            f" re-derived: {path_list(surface)}. Nothing else is touched.",
            "2. Re-derivation. The issue-195 acquisition ceremony ran again:",
        ]
        + statements
        + [
            "   Re-rendering every promotion surface from those records reproduces this"
            " head byte for byte — each blob compared by object id. The capture date"
            f" {captured} is the one value taken from the head and is bound to the head"
            " commit's own signed timestamp.",
            f"3. Novelty. No `{READY.REVIEWS_APP}` comment on this pull request bound"
            " this head before this one.",
            "",
            "Mutation and claim audit: the re-derivation IS both. Every claim the body"
            " and commit make about a version, digest or source is a value recomputed"
            " above rather than read from the diff, so an overstated claim is a byte"
            " mismatch; and one mutated byte anywhere in the surface — a digest, a"
            " receipt field, the changelog fragment, the README sentence — changes an"
            " object id and turns this verdict into REQUEST-CHANGES. Findings: none.",
            "No finding — checked the changed-path set, every re-rendered byte, the"
            " keyless signer identity, the immutable Release binding, the"
            " manifest-digest agreement and the tag-to-protected-main ancestry.",
            "",
            "Gates and flakes: this head's tree is byte-identical to one the promoter's"
            " own cut produces, and that cut runs `make check-fast`, `make"
            " check-gitleaks` and `make check-kubernetes` before committing and `make"
            " pre-push-security` on the exact signed commit before pushing; GitHub's"
            " required checks at this head are the authority for the rest and are not"
            " restated here. The re-derivation is deterministic: the same bytes, or a"
            " refusal.",
            "Scratch: the detached read-only worktree this proof used was removed.",
            "",
            "Review evidence only. NO TOOL FLIPS READY, promoter included: the"
            " coordinator flips and the owner alone merges.",
            "",
            RECEIPT_SIGNATURE,
            "",
        ]
    )


def request_changes_receipt(head: str, base: str, proof: str, detail: str) -> str:
    """The REQUEST-CHANGES receipt: which proof failed, and on what."""

    return "\n".join(
        [
            f"HEAD: {head}",
            "VERDICT: REQUEST-CHANGES",
            "",
            "Proof-based receipt for a promotion pull request, composed and posted from"
            " the promoter's own tick (issue #309). The promotion surface at this head"
            f" does not re-derive from `main` at `{base[:7]}`, the OCI registry and the"
            " site's immutable GitHub Release.",
            "",
            f"1. {proof} failed: {detail}",
            "",
            "Mutation and claim audit: the re-derivation IS both — the only claim a"
            " promotion pull request makes is the surface it writes, and the difference"
            " named above is that claim against what the registry and the immutable"
            " Release actually produce. Every other statement is withheld, because a"
            " head that does not re-derive has no verified figures to report.",
            "Scratch: no workspace from this proof remains.",
            "",
            "A promotion pull request is never repaired in place: the fix lands in the"
            " promoter's own code through a normal pull request, and this one is"
            " superseded and re-cut. Review evidence only — the owner alone merges.",
            "",
            RECEIPT_SIGNATURE,
            "",
        ]
    )


def proof_log(name: str, number: int, head: str, outcome: str, started: float) -> None:
    """One line per proof: which, on what, how it ended, and what it cost."""

    log(f"PROOF {name} pull-request={number} head={head[:7]} {outcome} elapsed={time.monotonic() - started:.1f}s")


def prove_promotion(workspace: Workspace, github: GitHub, registry: Registry, cosign: Cosign, pr: dict):
    """Judge one open promoter pull request. Returns ``(verdict, body)`` or
    ``None`` when this tick has nothing to say about it."""

    number, head, branch = pr["number"], pr["head"], pr["branch"]
    label = f"PR #{number}"
    started = time.monotonic()
    parsed = parse_branch(branch)
    if parsed is None:
        proof_log("subject", number, head, "skipped: branch is outside the promoter grammar", started)
        return None
    base7, issue, targets = parsed
    if pr.get("behind_by") is None:
        proof_log("subject", number, head, "skipped: base freshness is unknown", started)
        return None
    if pr["behind_by"]:
        proof_log("subject", number, head, f"skipped: {pr['behind_by']} commit(s) behind main", started)
        return None

    # Every read from here to the verdict is one the tick can afford to lose:
    # a failure means this head is judged again in five minutes, and the log
    # says so on the failing line itself.
    with failure_decision("skip-this-tick"):
        novelty = time.monotonic()
        if head in app_receipt_heads(github, number):
            proof_log("novelty", number, head, "skipped: a receipt already binds this head", novelty)
            return None
        proof_log("novelty", number, head, "held: no App receipt binds this head", novelty)

        base = workspace.git("rev-parse", "origin/main").strip()
        if not base.startswith(base7):
            proof_log("subject", number, head, f"skipped: cut from {base7}, main is now {base[:7]}", started)
            return None
        # Bind the head through the BRANCH REF rather than by fetching a bare
        # object: the ref is what the owner's credential pushed, and a head
        # GitHub reports that the ref does not carry is a moving target.
        with timed_call("git-fetch", f"origin {branch}", COMMAND_TIMEOUT_SECONDS):
            workspace.git("fetch", "--quiet", "origin", f"refs/heads/{branch}")
        if workspace.git("rev-parse", "FETCH_HEAD").strip() != head:
            proof_log("subject", number, head, "skipped: the branch does not point at the head GitHub reports", started)
            return None

        changed = [name for name in workspace.git("diff", "--name-only", "-z", base, head).split("\0") if name]
        derivation = time.monotonic()
        try:
            captured = captured_date(workspace, head)
        except Refusal as error:
            proof_log("re-derivation", number, head, f"failed: {error}", derivation)
            return "REQUEST-CHANGES", request_changes_receipt(head, base, "Re-derivation", str(error))

        try:
            cosign.require_pinned_version()
            with scratch_worktree(workspace, base) as tree:
                selections = discover_selections(tree)
                unknown = sorted(set(targets) - set(selections))
                if unknown:
                    proof_log("subject", number, head, f"skipped: main has no selection for {', '.join(unknown)}", started)
                    return None
                acquired = {
                    slug: acquire(selections[slug], version, registry, github, cosign)
                    for slug, version in sorted(targets.items())
                }
                issues = drift_issues(github, targets)
                if not issues or issues[0] != issue:
                    proof_log("subject", number, head, "skipped: the drift issues these targets name have moved", started)
                    return None
                surface = apply_promotion(
                    tree,
                    selections,
                    acquired,
                    issue,
                    "/".join(f"#{n}" for n in issues),
                    captured,
                    workspace._run,
                )
                surface = sorted(set(surface))
                confinement = time.monotonic()
                outside = sorted(set(changed) - set(surface))
                if outside:
                    proof_log("confinement", number, head, f"failed: {len(outside)} path(s) outside the promotion surface", confinement)
                    return "REQUEST-CHANGES", request_changes_receipt(
                        head, base, "Confinement",
                        f"{len(outside)} changed path(s) are outside the promotion surface"
                        f" this cut writes: {path_list(outside)}",
                    )
                proof_log("confinement", number, head, f"held: {len(changed)} changed path(s), all in the surface", confinement)
                differing = [
                    name for name in surface
                    if head_blob(workspace, head, name) != rendered_blob(workspace, tree / name)
                ]
                statements = [workload_statement(selections[slug], record) for slug, (record, _) in sorted(acquired.items())]
        except Refusal as error:
            # A registry, Release, cosign or ceremony refusal is not this pull
            # request's fault as far as this tool can prove, so it never becomes
            # a verdict: the tick logs it and tries again on the next tick.
            proof_log("re-derivation", number, head, f"skipped: could not complete ({error})", derivation)
            return None

    if differing:
        proof_log("re-derivation", number, head, f"failed: {len(differing)} path(s) do not reproduce", derivation)
        return "REQUEST-CHANGES", request_changes_receipt(
            head, base, "Re-derivation",
            f"{len(differing)} promotion-surface path(s) do not reproduce from the"
            f" registry and the immutable Release: {path_list(differing)}",
        )
    proof_log("re-derivation", number, head, f"held: {len(surface)} path(s) reproduce byte for byte", derivation)
    log(f"{label}: all three proofs hold at {head[:7]}")
    return "APPROVE", approve_receipt(head, base, surface, statements, captured)


def post_receipt(workspace: Workspace, github: GitHub, run, helper: str, number: int, head: str, body: str, dry_run: bool) -> bool:
    """Validate one composed receipt and post it AS THE REVIEWER APP.

    The token never enters an argument list, a log line or a file: it is minted
    by the machine-local helper, held in one local name, and handed to exactly
    one ``gh`` subprocess through its environment.
    """

    path = workspace.root / ".git" / "promoter-receipt.md"
    path.write_text(body, encoding="utf-8")
    try:
        run([
            sys.executable, "-I", "-B", str(workspace.root / RECEIPT_VALIDATOR),
            "--head", head, "--resource-kind", "pull-request", str(path),
        ])
        # The head is re-read from GitHub as late as possible: a receipt names
        # one head, so a head that moved between the proof and the post would
        # bind a verdict to bytes nobody proved.
        live = owned_pull_request(github.api(f"repos/{REPOSITORY}/pulls/{number}"))
        if live is None or live["head"] != head:
            log(f"PR #{number}: the head moved between proof and post; nothing was posted")
            return False
        if dry_run:
            log(f"PR #{number}: WOULD post a validated receipt at {head[:7]} as the review App (dry run)")
            return False
        with timed_call("receipt-token", f"repository={REPOSITORY}", COMMAND_TIMEOUT_SECONDS):
            # ``quiet_output`` is load-bearing, not tidiness: this command's
            # STDOUT IS THE CREDENTIAL, and the ordinary failure path quotes a
            # failed command's output into the local log.
            token = run([helper, REPOSITORY], quiet_output=True).strip()
        if not token or "\n" in token:
            raise Refusal("the receipt token helper produced no single-line token")
        environment = dict(os.environ)
        environment.pop("GITHUB_TOKEN", None)
        environment["GH_TOKEN"] = token
        with timed_call("receipt-post", f"pull-request={number} head={head[:7]}", COMMAND_TIMEOUT_SECONDS):
            run(
                ["gh", "pr", "comment", str(number), "--repo", REPOSITORY, "--body-file", str(path)],
                cwd=workspace.root,
                env=environment,
            )
    finally:
        path.unlink(missing_ok=True)
    # Trust the forge, not the exit status: the comment counts only if the
    # App's own identity is what carries it at this exact head.
    if head not in app_receipt_heads(github, number):
        raise Refusal(f"PR #{number}: no App-posted comment binds {head[:7]} after posting")
    log(f"PR #{number}: the review App posted a receipt at {head[:7]}")
    return True


def post_receipts(workspace: Workspace, github: GitHub, registry: Registry, cosign: Cosign, prs: list, dry_run: bool, run=run_command, outcomes=None) -> None:
    """The tick's receipt step over the promotion pull requests it keeps.

    ``outcomes`` collects one word per pull request for the tick's summary
    line, so a reader learns from one line whether a receipt was posted,
    withheld, or never attempted.
    """

    record = {} if outcomes is None else outcomes
    helper = (os.environ.get(RECEIPT_TOKEN_COMMAND_ENV) or "").strip()
    if not helper:
        if prs:
            log(f"receipt posting not configured ({RECEIPT_TOKEN_COMMAND_ENV} is unset); no receipt was composed")
            record["receipt"] = "unconfigured"
        return
    for pr in prs:
        # Nothing in this loop is worth stopping a tick for: a failed proof, a
        # failed validation and a failed post all mean the same thing — this
        # head is judged again on the next tick — and every call underneath
        # says so on its own failing line.
        try:
            with failure_decision("skip-this-tick"):
                judged = prove_promotion(workspace, github, registry, cosign, pr)
                if judged is None:
                    record[f"receipt-{pr['number']}"] = "skipped"
                    continue
                verdict, body = judged
                log(f"PR #{pr['number']}: proof verdict {verdict} at {pr['head'][:7]}")
                if not post_receipt(workspace, github, run, helper, pr["number"], pr["head"], body, dry_run):
                    record[f"receipt-{pr['number']}"] = "not-posted"
                    continue
                record[f"receipt-{pr['number']}"] = f"posted:{verdict}"
                if verdict == "APPROVE":
                    # Only an APPROVE retires the review-attention label. A
                    # REQUEST-CHANGES leaves it armed on purpose: the pull
                    # request still needs a human to look, and the promoter
                    # will supersede and re-cut it rather than repair it.
                    labels = [(label or {}).get("name") for label in (github.api(f"repos/{REPOSITORY}/pulls/{pr['number']}").get("labels") or [])]
                    if READY.REVIEW_ATTENTION_LABEL in labels:
                        github.mutate(
                            f"repos/{REPOSITORY}/issues/{pr['number']}/labels/{READY.REVIEW_ATTENTION_LABEL}",
                            "DELETE",
                        )
                        log(f"PR #{pr['number']}: {READY.REVIEW_ATTENTION_LABEL} removed with the verdict")
        except Refusal as error:
            log(f"PR #{pr['number']}: receipt step refused ({error})")
            record[f"receipt-{pr['number']}"] = "refused"


def acquire_lock(path: Path):
    """Hold an OS-level exclusive lock on ``path`` for the tick's lifetime,
    or return ``None`` while another live process holds it. The kernel
    releases the lock when its holder exits, however it exits, so nothing
    is ever reaped by age: a hung tick keeps its lock until it dies, and
    every subprocess it runs is bounded so that death is guaranteed."""

    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()} {int(time.time())}\n".encode())
    return fd


def release_lock(fd) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def tick(repo: Path, dry_run: bool, registry=None, github=None, cosign=None, run=run_command) -> int:
    github = github or GitHub(run=run)
    registry = registry or Registry()
    lock = acquire_lock(repo / ".git" / "promoter.lock")
    if lock is None:
        log("another tick holds the lock; skipping")
        return 0
    # One line at the end says what this tick did to every workload and every
    # pull request it touched, and what the whole thing cost. It is emitted on
    # EVERY exit path: a tick that ends in a refusal is exactly the tick whose
    # summary a reader needs.
    started, outcomes = time.monotonic(), {}
    try:
        workspace = Workspace(repo, run)
        base = workspace.refresh()
        cosign = cosign or Cosign(run=run, pinned_version="v" + tool_pins(repo)["cosign"])
        selections = discover_selections(repo)
        report = status(repo, github)
        for slug, entry in report.items():
            log(f"{slug}: committed {entry['committed']} vs latest {entry['latest']} -> {entry['verdict']}")
            outcomes[slug] = entry["verdict"]
        open_prs = open_promoter_prs(github)
        decision = plan(report, open_prs)
        # The receipt step runs on the pull requests the planner KEEPS — never
        # on one it is about to supersede — and never stops the tick: a promotion
        # that is due must still be cut when a receipt cannot be earned.
        try:
            keep = set(decision["keep"])
            post_receipts(workspace, github, registry, cosign, [pr for pr in open_prs if pr["number"] in keep], dry_run, run, outcomes)
        except Refusal as error:
            log(f"receipt step refused: {error}")
            outcomes["receipt"] = "refused"
        for number in decision["supersede"]:
            supersede(github, number, "base moved or the target release changed; a fresh cut follows", dry_run)
            outcomes[f"pull-request-{number}"] = "superseded"
        if decision["targets"] and not decision["keep"]:
            try:
                with failure_decision("refuse"):
                    number = cut_promotion(workspace, github, registry, cosign, selections, decision["targets"], dry_run)
                outcomes["cut"] = str(number) if number else "dry-run"
            except Refusal as error:
                log(f"promotion refused: {error}")
                report_failure(github, decision["targets"], "cut", str(error), dry_run)
                outcomes["cut"] = "refused"
                return 1
            finally:
                workspace.restore(base)
        elif not decision["targets"]:
            log("every selection is current; nothing to promote")
        return 0
    finally:
        log(
            f"SUMMARY tick elapsed={time.monotonic() - started:.1f}s dry-run={dry_run} "
            + (" ".join(f"{key}={value}" for key, value in sorted(outcomes.items())) or "nothing-to-report")
        )
        release_lock(lock)


def receipt_pass(repo: Path, dry_run: bool, registry=None, github=None, cosign=None, run=run_command) -> int:
    """The receipt step on its own, for a manual run.

    It reads exactly what the tick reads and judges exactly the pull requests
    the tick would judge, under the same lock — so a manual run can never race
    a scheduled one, and can never post a receipt the tick would not.
    """

    github = github or GitHub(run=run)
    registry = registry or Registry()
    lock = acquire_lock(repo / ".git" / "promoter.lock")
    if lock is None:
        log("another tick holds the lock; skipping")
        return 0
    started, outcomes = time.monotonic(), {}
    try:
        workspace = Workspace(repo, run)
        workspace.refresh()
        cosign = cosign or Cosign(run=run, pinned_version="v" + tool_pins(repo)["cosign"])
        open_prs = open_promoter_prs(github)
        decision = plan(status(repo, github), open_prs)
        keep = set(decision["keep"])
        post_receipts(workspace, github, registry, cosign, [pr for pr in open_prs if pr["number"] in keep], dry_run, run, outcomes)
        return 0
    finally:
        log(
            f"SUMMARY receipt elapsed={time.monotonic() - started:.1f}s dry-run={dry_run} "
            + (" ".join(f"{key}={value}" for key, value in sorted(outcomes.items())) or "nothing-to-report")
        )
        release_lock(lock)


# ---------------------------------------------------------------------------
# launchd
# ---------------------------------------------------------------------------


def launchd_plist(repo: str, log_path: str, token_command: str = "") -> str:
    """The user agent that runs ``tick`` on ``LAUNCHD_INTERVAL_SECONDS``.
    Paths are the installer's arguments, never committed values; the reviewer
    App token helper is named the same way and reaches the tick as one
    environment variable, so no machine path is ever committed."""

    def escape(value: str) -> str:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    script = f"{repo}/scripts/promote_releases.py"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n<dict>\n'
        f"  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n"
        "  <key>ProgramArguments</key>\n  <array>\n"
        "    <string>/usr/bin/env</string><string>python3</string><string>-I</string><string>-B</string>\n"
        f"    <string>{escape(script)}</string><string>tick</string><string>--repo</string><string>{escape(repo)}</string>\n"
        "  </array>\n"
        f"  <key>StartInterval</key><integer>{LAUNCHD_INTERVAL_SECONDS}</integer>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "  <key>EnvironmentVariables</key>\n  <dict>\n"
        "    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>\n"
        # The reviewer App token helper reaches the tick by NAME only, and only
        # when the installer supplies one: an agent installed without it runs
        # every proof and posts nothing. The path is the installer's argument,
        # exactly like the clone and the log, so none is ever committed.
        + (
            f"    <key>{RECEIPT_TOKEN_COMMAND_ENV}</key><string>{escape(token_command)}</string>\n"
            if token_command
            else ""
        )
        + "  </dict>\n"
        f"  <key>StandardOutPath</key><string>{escape(log_path)}</string>\n"
        f"  <key>StandardErrorPath</key><string>{escape(log_path)}</string>\n"
        "</dict>\n</plist>\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("status", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--repo", type=Path, default=Path.cwd())
    for name in ("tick", "receipt"):
        p = sub.add_parser(name)
        p.add_argument("--repo", type=Path, required=True)
        p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("launchd-plist")
    p.add_argument("--repo", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--token-command", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "status":
            report = status(args.repo.resolve(), GitHub())
            for slug, entry in report.items():
                print(f"{slug}: committed {entry['committed']} vs latest {entry['latest']} -> {entry['verdict']}")
            return status_exit_code(report)
        if args.mode == "verify":
            root = args.repo.resolve()
            cosign = Cosign(pinned_version="v" + tool_pins(root)["cosign"])
            problems = verify(root, Registry(), GitHub(), cosign)
            for problem in problems:
                print("DENY: " + problem)
            if not problems:
                print("OK: the committed receipt reproduces from the registry")
            return 1 if problems else 0
        if args.mode == "tick":
            return tick(args.repo.resolve(), args.dry_run)
        if args.mode == "receipt":
            return receipt_pass(args.repo.resolve(), args.dry_run)
        if args.mode == "launchd-plist":
            sys.stdout.write(launchd_plist(args.repo, args.log, args.token_command))
            return 0
    except Refusal as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
