# Local development on macOS

The validation suite is authoritative on Linux (CI runs ubuntu-24.04).
macOS workstations previously showed 103 spurious failures on a pristine
`main` for two environmental reasons, both addressed:

1. **Symlinked temp root.** macOS puts `TMPDIR` under `/var`, a symlink to
   `/private/var`; the suite's own link-traversal and canonical-path guards
   then reject every temp fixture. `make check-fast` now realpaths
   `TMPDIR` before running anything, which is a no-op on Linux.
2. **Linux-only security semantics.** Thirteen tests exercise procfs mount
   fingerprinting, symlink-race, and FIFO-substitution defenses that only
   exist on Linux. They now carry
   `skipUnless(sys.platform.startswith("linux"), ...)` guards — mirroring
   the suite's existing POSIX guards — and still run unchanged in CI.

`make check-fast` also exports `PYTHONDONTWRITEBYTECODE=1` so a plain
check run can no longer leave `scripts/__pycache__` behind, which the
stricter `make pre-push-security` correctly rejects as ambient bytecode.

Remaining expectations on macOS:

- Any Python ≥3.12 works; no third-party packages are required. If you use
  a venv, pass it explicitly: `make check-fast PYTHON=/path/to/python`.
- `make pre-push-security` requires the exact gitleaks version pinned in
  `versions.env` (`brew install gitleaks`, then verify `gitleaks version`).
- Full parity when in doubt runs the suite in a disposable Linux
  container:
  `docker run --rm -v "$PWD":/repo -w /repo ubuntu:24.04 sh -c 'apt-get update -q && apt-get install -qy python3 git && git config --global safe.directory /repo && python3 -B -m unittest discover -s tests -p "test_*.py"'`
- One-time hook wiring (optional but recommended):
  `git config core.hooksPath .githooks`.
