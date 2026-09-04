"""Shared subject-loading helpers for the security batteries.

Every battery in this package exercises a file under ``scripts/`` — a
command-line validator, not a member of an importable package — so each
test module loads its subject straight from the file path. Before this
module existed that importlib stanza was pasted across the package, and
only a minority of the copies guarded against ``spec_from_file_location``
returning ``None`` (or a spec without a loader), so a missing or
unreadable script surfaced as a bare ``AttributeError`` on ``NoneType``
far from the real cause. ``load_script`` keeps the sequence and the
fail-closed guard in exactly one place.

``run_script`` is the one subprocess shape shared by the CLI batteries
that execute their validator the way an operator would (``python -B
script args`` with captured text output). Batteries whose execution
contract genuinely differs — isolated ``-I`` interpreter mode, byte-mode
stdin capture, ``check=True`` Git plumbing — keep their own helpers on
purpose and are not routed through here.

``hermetic_git_environment`` is the one environment shape shared by the
batteries that build synthetic Git history: it makes fixture ``git``
invocations immune to identity and repository-redirection variables
exported by the invoking shell, which would otherwise silently rewrite
what a fixture constructs (see the function docstring for the observed
failure).

This module is support code, not a test module: unittest discovery only
collects ``test_*.py``, and the coverage gate's source scope is the
``scripts/`` tree alone (``[run] source`` in ``scripts/ci/coveragerc``),
so nothing in this file enters any coverage denominator.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

# The two constants every pasted loader stanza re-derived for itself:
# tests/security/support.py -> tests/security -> tests -> repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
# "no entry at all", distinguishable from a stored ``None``.
_ABSENT = object()


def load_script(name: str, *, module_name: str | None = None) -> ModuleType:
    """Execute ``scripts/<name>`` and return the resulting module object.

    ``name`` is the path relative to ``scripts/`` (for example
    ``"validate_repository.py"`` or ``"ci/coverage_gate.py"``). The module
    is created under the file's stem unless ``module_name`` says
    otherwise; batteries that load the same script more than once in a
    single test process pass distinct names so the copies stay visibly
    independent.

    Raises ``AssertionError`` with the offending path when importlib
    yields no spec or a spec without a loader (missing file, unreadable
    checkout), so a broken tree fails with the cause instead of an
    ``AttributeError`` symptom. The guard is a raise statement, not an
    ``assert``, so it survives ``python -O``.
    """

    path = SCRIPTS_DIR / name
    spec = importlib.util.spec_from_file_location(
        module_name or Path(name).stem, path
    )
    if spec is None or spec.loader is None:
        raise AssertionError(
            "cannot load the script under test: importlib returned no "
            "usable spec/loader for {}".format(path)
        )
    module = importlib.util.module_from_spec(spec)
    # The module must be visible in ``sys.modules`` WHILE its body runs, which
    # is the documented importlib recipe and not optional: anything resolving a
    # PEP 563 string annotation looks its defining module up there, so a script
    # with `from __future__ import annotations` and a ``@dataclasses.dataclass``
    # fails at class-creation time with a bare ``AttributeError`` on ``None``.
    # It is removed again immediately, so the "copies stay visibly independent"
    # property above is unchanged: nothing observes the name after this returns.
    # Absence is tracked with a private sentinel, never with ``None``: a present
    # ``None`` entry is Python's import-blocking marker, a distinct state that
    # must be RESTORED rather than dropped as if the key had never been there.
    previous = sys.modules.get(spec.name, _ABSENT)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is _ABSENT:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


def required_tool(resolved: str | None, description: str) -> str:
    """Return a ``shutil.which`` result as a definite path, or fail loudly.

    The hermetic batteries locate host executables with ``shutil.which`` at
    module scope and gate their classes with ``unittest.skipUnless`` so a
    host genuinely missing the tool skips with an explanation. That leaves
    the module constant ``str | None``, and a ``None`` that slipped past a
    lost or bypassed skip guard would otherwise ride silently into a
    subprocess argv. This helper is the fail-closed floor under the skips:
    call it where the argv is built, and a missing executable becomes an
    immediate ``AssertionError`` naming the tool instead of a confusing
    ``subprocess`` type error. A raise statement, not an ``assert``, so it
    survives ``python -O`` (same discipline as ``load_script``).
    """

    if resolved is None:
        raise AssertionError(description)
    return resolved


_GREP_PATTERN_TOKEN = re.compile(
    r"""
    (?P<command>\bgrep\b(?:\s+-{1,2}[A-Za-z-]+)*)   # grep and its option words
    \s+
    (?P<token>
        '[^']*'                                     # 'single quoted'
      | \$'(?:\\.|[^'\\])*'                         # $'ansi-c quoted'
      | "(?:\\.|[^"\\])*"                           # "double quoted"
    )
    """,
    re.VERBOSE,
)
# The three ways a script can spell a literal dot inside a probe pattern. The
# reviewed spelling is the POSIX bracket class, because it needs no escaping in
# any quoting context; `\.` is what an evasive rewrite reaches for.
_ESCAPED_DOT = re.compile(r"\\\.")
# A `$` inside a double-quoted word introduces an expansion only when a name,
# a brace, or a parenthesis follows it. A trailing `$` is the ERE end anchor —
# which every probe pattern here ends with, so treating a bare `$` as an
# expansion would refuse to canonicalise exactly the tokens that matter.
_SHELL_EXPANSION = re.compile(r"(?<!\\)[$](?=[A-Za-z_{(])|(?<!\\)`")


def canonicalize_probe_spellings(text: str) -> str:
    """Rewrite grep pattern literals into this repository's reviewed spelling.

    The CRI batteries read probe patterns out of the bootstrap scripts with
    regexes keyed on ONE spelling: single-quoted, dots written ``[.]``. That
    made every one of them, and both stale-row tripwires, blind to a
    functionally equivalent probe written ``"^io\\.containerd\\.grpc\\.v1..."``
    — a double-quoted, backslash-escaped rewrite passes all five checks while
    changing what the host actually verifies (issue #51). The dangerous
    direction is the stale 1.x row returning under a spelling the tripwire
    cannot see.

    Normalising the SOURCE, rather than teaching five patterns four spellings,
    keeps one canonical form and leaves every existing check working on it.
    Two rewrites, both confined to a grep invocation's pattern token:

    * a double-quoted or ``$'...'`` token with no shell expansion in it becomes
      a single-quoted token, with the quoting-level backslashes resolved;
    * ``\\.`` becomes ``[.]``.

    A token carrying a ``$`` expansion or a backtick is left EXACTLY as it
    stands: its value is not knowable from the text, and silently rewriting it
    would invent a pattern nobody wrote. Several legitimate probes interpolate
    a version or an address that way, so this is the common case rather than an
    edge one — callers that need to know a pattern was unresolvable ask for it
    rather than reading a guess.

    Canonicalising is IDENTIFICATION, not emulation: ``.`` and ``[.]`` are not
    the same ERE, and this function does not claim they are. It claims that a
    probe written either way is the same probe for the purpose of asking which
    plugin rows the bootstrap verifies.
    """

    def canonical_command(command):
        """``grep -Eq`` for every spelling of "extended regexp, quiet".

        ``-Eq``, ``-qE``, ``-E -q`` and ``--extended-regexp --quiet`` are the
        same invocation, and two of the three extraction regexes key on the
        literal ``grep -Eq ``. Any OTHER flag set is left alone — ``-Fq`` is a
        fixed-string search, not an ERE, and rewriting it would assert
        something the script does not do.
        """

        flags = set()
        for word in command.split()[1:]:
            if word.startswith("--"):
                flags.add({"extended-regexp": "E", "quiet": "q"}.get(word[2:], word))
            else:
                flags.update(word[1:])
        return "grep -Eq" if flags == {"E", "q"} else command

    def rewrite(match):
        command = canonical_command(match.group("command"))
        if command != "grep -Eq":
            # Out of scope by construction. This helper exists for PROBE
            # patterns — the quiet extended-regexp assertions the bootstrap
            # scripts gate on — and the batteries' own extractors key on that
            # exact invocation. A counting, inverting or fixed-string grep is
            # a different question and is left byte-identical.
            return match.group(0)
        token = match.group("token")
        if token.startswith("'"):
            body = token[1:-1]
        elif token.startswith("$'"):
            # Inside `$'...'` a dollar sign is literal; only backslash escapes
            # are resolved by the shell.
            body = re.sub(r"\\(.)", _ansi_c_escape, token[2:-1])
        else:
            if _SHELL_EXPANSION.search(token[1:-1]):
                return match.group(0)
            body = re.sub(r'\\(["\\])', r"\1", token[1:-1])
        if "'" in body:
            # A literal single quote cannot be carried inside a single-quoted
            # token; leave the invocation exactly as written.
            return match.group(0)
        return "{} '{}'".format(command, _ESCAPED_DOT.sub("[.]", body))

    return _GREP_PATTERN_TOKEN.sub(rewrite, text)


def _ansi_c_escape(match: "re.Match[str]") -> str:
    """Resolve the ``$'...'`` escapes a probe pattern could plausibly use."""

    return {"n": "\n", "t": "\t", "\\": "\\", "'": "'"}.get(
        match.group(1), "\\" + match.group(1)
    )


def run_script(script: Path, *argv: object) -> subprocess.CompletedProcess:
    """Run one ``scripts/`` CLI exactly as the common battery pattern does.

    Mirrors the byte-similar helper the CLI batteries each carried:
    current interpreter, ``-B`` (no bytecode in the checkout), string
    arguments, captured text stdout/stderr, and no ``check=`` so the
    battery asserts on the returncode itself.
    """

    return subprocess.run(
        [sys.executable, "-B", str(script), *(str(item) for item in argv)],
        capture_output=True,
        text=True,
    )


def hermetic_git_environment(
    repository: Path | str | None = None,
    identity: tuple[str | None, str | None] | None = None,
) -> dict[str, str]:
    """Return the environment every history-building fixture git call uses.

    Ambient ``GIT_AUTHOR_*``/``GIT_COMMITTER_*`` variables override the
    ``user.name``/``user.email`` a fixture sets through ``git config`` or
    ``git -c``, and ``GIT_DIR``/``GIT_WORK_TREE``/``GIT_INDEX_FILE``/
    ``GIT_CONFIG_*`` redirect which repository, index, or configuration a
    command even sees. A shell that exports an identity — observed with
    the repository's own publication noreply address — therefore silently
    rewrote what the fixtures built: the metadata-privacy battery's
    private-author fixture committed with the exported clean identity and
    the battery failed with no repository change at all. Passing this
    environment to every fixture git invocation removes the whole ambient
    ``GIT_``-prefixed surface and then re-pins the author and committer
    explicitly, so nothing exported by the invoking shell can alter what a
    fixture constructs.

    ``identity`` is an explicit ``(name, email)`` pin. When only
    ``repository`` is given, the pin is read from that repository's own
    local ``git config`` — the identity the fixture itself declared, so
    fixtures that reconfigure ``user.email`` mid-test keep working
    unmodified. With neither, the environment is merely scrubbed, which is
    the right shape for commands that must observe already-built history
    without inventing an identity of their own.
    """

    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }
    if identity is None and repository is not None:
        configured = []
        for key in ("user.name", "user.email"):
            lookup = subprocess.run(
                ["git", "config", "--local", key],
                cwd=str(repository),
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )
            configured.append(
                lookup.stdout.strip() if lookup.returncode == 0 else None
            )
        identity = (configured[0], configured[1])
    if identity is not None:
        pinned_name, pinned_email = identity
        if pinned_name:
            environment["GIT_AUTHOR_NAME"] = pinned_name
            environment["GIT_COMMITTER_NAME"] = pinned_name
        if pinned_email:
            environment["GIT_AUTHOR_EMAIL"] = pinned_email
            environment["GIT_COMMITTER_EMAIL"] = pinned_email
    return environment
