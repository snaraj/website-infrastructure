"""Detect security-toggle idioms anywhere in the tracked tree (Coinkite law).

No flag, environment variable, or configuration switch may disable a
security behavior. This validator sweeps every tracked text file for a
closed set of dangerous toggle idioms — skip/disable/bypass identifiers
aimed at verification, signing, policy, scanning, gates, or checks, and
insecure/no-verify CLI flags. Occurrences are legal only through the exact
allowlist below, where every entry carries its justification and must still
match (a stale allowlist entry is itself an error, so retired exemptions
cannot linger). Everything else fails closed.

The patterns are assembled from fragments so this file does not flag
itself; its unit tests build hostile fixtures the same way.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Fragments concatenated at import time keep the literal idioms out of this
# file's bytes at rest while scanning for them everywhere else.
_SKIP = "SK" + "IP"
_DISABLE = "DIS" + "ABLE"
_BYPASS = "BY" + "PASS"
_NO_VERIFY = "--no-" + "verify"
_INSECURE = "--in" + "secure"
_SKIP_FLAG = "--sk" + "ip-"
_UNSIGNED = "ALLOW_" + "UNSIGNED"
_VERIFY_FALSE = "verify" + "=false"

TOGGLE_PATTERNS = (
    (
        "security-toggle identifier",
        re.compile(
            r"\b(?:" + _SKIP + "|" + _DISABLE + "|" + _BYPASS + r")_[A-Z_]*"
            r"(?:VERIF|SIGN|POLIC|SCAN|GATE|CHECK|SECUR|ADMISSION|ENFORCE)[A-Z_]*\b"
        ),
    ),
    ("unsigned-artifact toggle", re.compile(r"\b" + _UNSIGNED + r"\b")),
    ("no-verify flag", re.compile(re.escape(_NO_VERIFY) + r"\b")),
    ("insecure flag", re.compile(re.escape(_INSECURE) + r"\b")),
    ("skip flag", re.compile(re.escape(_SKIP_FLAG) + r"[a-z-]+")),
    ("verification disabled", re.compile(r"\b" + _VERIFY_FALSE + r"\b")),
)

# (path, exact fragment, justification). Fragments are matched per line;
# a line containing the fragment is exempt for that file only.
ALLOWLIST = (
    (
        ".github/workflows/pull-request.yml",
        "--skip-dirs ./tests/kubernetes/fixtures/deny",
        "trivy must not scan deliberate DENY fixtures as findings",
    ),
    (
        ".github/workflows/scheduled-security.yml",
        "--skip-dirs ./tests/kubernetes/fixtures/deny",
        "same deny-fixture exemption on the scheduled scan",
    ),
    (
        "bootstrap/pi/init-control-plane.sh",
        "--skip-token-print",
        "security-POSITIVE: keeps the bootstrap token out of logs",
    ),
    (
        "tests/security/test_init_control_plane_tokens.py",
        "--skip-token-print",
        "pins the security-positive kubeadm invocation above",
    ),
    (
        "tests/security/test_protected_runtime_contract_integration.py",
        "--skip-token-print",
        "pins the same invocation in the integration contract",
    ),
    (
        "tests/security/test_trivy_scan_contract.py",
        "--skip-dirs ./tests/kubernetes/fixtures/deny",
        "pins the deny-fixture exemption as the ONLY allowed skip",
    ),
    (
        "tests/security/test_trivy_scan_contract.py",
        '"--skip-files"',
        "assertNotIn: the test FORBIDS this flag from appearing",
    ),
    (
        "docs/runbooks/github-controls.md",
        "Never use `--no-verify`",
        "prose stating the law itself",
    ),
    (
        "docs/assurance/phase-c-kubernetes-adversarial.md",
        "`--skip-token-print` pinned by two suites",
        "audit prose describing the allowlisted security-positive flag",
    ),
)

# Whole-file exemptions for the detector itself and its test: the marker
# proves file identity (a replaced file without the marker is flagged).
SELF_EXEMPT = {
    "scripts/validate_no_security_toggles.py": "assembled from fragments",
    "tests/security/test_no_security_toggles.py": "runtime-assembled",
}


def tracked_files():
    listing = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [name for name in listing.stdout.decode("utf-8").split("\0") if name]


def toggle_errors(root):
    errors = []
    used_entries = set()
    allow_by_path = {}
    for path, fragment, _justification in ALLOWLIST:
        allow_by_path.setdefault(path, []).append(fragment)
    for name in tracked_files():
        path = Path(root) / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if name in SELF_EXEMPT:
            if SELF_EXEMPT[name] not in text:
                errors.append(f"{name}: self-exempt marker is missing")
            continue
        exempt_fragments = allow_by_path.get(name, [])
        for line_number, line in enumerate(text.splitlines(), 1):
            exempted = False
            for fragment in exempt_fragments:
                if fragment in line:
                    used_entries.add((name, fragment))
                    exempted = True
            if exempted:
                continue
            for label, pattern in TOGGLE_PATTERNS:
                if pattern.search(line):
                    errors.append(f"{name}:{line_number}: {label}")
    for path, fragment, _justification in ALLOWLIST:
        if (path, fragment) not in used_entries:
            errors.append(
                f"allowlist entry no longer matches anything: {path} :: {fragment}"
            )
    return errors


def main(argv):
    root = argv[1] if len(argv) > 1 else str(REPO_ROOT)
    errors = toggle_errors(root)
    for error in errors:
        print(f"no-security-toggles: {error}", file=sys.stderr)
    if errors:
        return 1
    print("no-security-toggles: PASS no toggle idiom outside the justified allowlist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
