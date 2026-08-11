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
import subprocess
import sys
from pathlib import Path
from types import ModuleType

# The two constants every pasted loader stanza re-derived for itself:
# tests/security/support.py -> tests/security -> tests -> repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"


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
    spec.loader.exec_module(module)
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
