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

This module is support code, not a test module: unittest discovery only
collects ``test_*.py``, and the coverage gate's source scope is the
``scripts/`` tree alone (``[run] source`` in ``scripts/ci/coveragerc``),
so nothing in this file enters any coverage denominator.
"""

from __future__ import annotations

import importlib.util
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
