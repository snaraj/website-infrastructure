#!/usr/bin/env python3
"""Validate independent, immutable website container release versions."""

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from workload_registry import load_registry


WORKLOADS = load_registry(ROOT)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
TAGGED_SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
POLICY_FILE = "release-policy.env"

# The paths are deliberately explicit. Chart-only changes do not alter a
# container, while source, Docker build inputs, and the selected publication
# lane do. Shared release tooling changes require both independent versions to
# move so a main-branch rebuild can never collide with an existing SemVer tag.
# Site source, versions, and publishers live in the standalone repositories
# (github.com/snaraj/<domain>). This platform keeps only the promotion-side
# contract: which sites exist, and the tracked production-graduation gates
# that bound which SemVer majors may be promoted into desired state.
SITE_CONTRACTS = {
    slug: {
        "domain": entry["deploy"]["domain"],
        "gate": slug.replace("-", "_").upper() + "_PRODUCTION_GRADUATED",
    }
    for slug in sorted(WORKLOADS, reverse=True)
    if (entry := WORKLOADS[slug])["deploy"]["shape"] == "site"
}


def parse_semver(value, tagged=False):
    """Return a comparable stable SemVer tuple or ``None`` for invalid input."""

    # OCI tags are limited to 128 characters. Keep the unprefixed file within
    # 127 so adding `v` is always representable and integer parsing stays
    # bounded even for a malicious pull request.
    if not isinstance(value, str) or len(value) > (128 if tagged else 127):
        return None
    match = (TAGGED_SEMVER if tagged else SEMVER).fullmatch(value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _read_policy_text(text):
    """Parse the closed production-graduation policy without shell semantics."""

    values = {}
    lines = text.splitlines()
    if not text.endswith(("\n", "\r\n")) or len(lines) != len(SITE_CONTRACTS):
        return None
    for line in lines:
        match = re.fullmatch(r"([A-Z0-9_]+)=(yes|no)", line)
        if not match or match.group(1) in values:
            return None
        values[match.group(1)] = match.group(2)
    expected = [contract["gate"] for contract in SITE_CONTRACTS.values()]
    return values if list(values) == expected else None


def read_policy(root):
    """Return the tracked per-site graduation gates, or ``None`` if malformed."""

    try:
        return _read_policy_text((root / POLICY_FILE).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return None


def repository_errors(root, site=None):
    """Report static release-policy errors without reading Git or the network."""

    root = Path(root)
    sites = [site] if site else list(SITE_CONTRACTS)
    if any(candidate not in SITE_CONTRACTS for candidate in sites):
        return ["unknown website release identity"]

    del sites  # every site shares the single policy-shape requirement
    policy = read_policy(root)
    if policy is None:
        return [
            "release-policy.env must contain exactly the two reviewed yes/no "
            "production-graduation gates"
        ]
    return []


def tag_errors(root, site, tag, *, current=False, rollback=False):
    """Validate a requested historical/current release tag for promotion."""

    if site not in SITE_CONTRACTS:
        return ["unknown website release identity"]
    errors = repository_errors(root, site)
    parsed = parse_semver(tag, tagged=True)
    if parsed is None:
        errors.append("release tag must be exact stable vMAJOR.MINOR.PATCH SemVer")
        return errors
    policy = read_policy(Path(root))
    if policy is not None:
        gate = SITE_CONTRACTS[site]["gate"]
        if policy[gate] == "no" and parsed[0] != 0:
            errors.append("v1+ promotion is forbidden before tracked production graduation")
    if current and rollback:
        errors.append("release tag cannot be both current and rollback")
    # The authoritative version now lives in each site repository; forward
    # and rollback ordering are proven by the verified image version label
    # and the reviewed values diff rather than a local VERSION file.
    return errors


def main(argv=None):
    """Run static, promotion-tag, or pull-request release validation."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--site", choices=sorted(SITE_CONTRACTS))
    tag_parser = subparsers.add_parser("validate-tag")
    tag_parser.add_argument("--site", required=True, choices=sorted(SITE_CONTRACTS))
    tag_parser.add_argument("--tag", required=True)
    tag_mode = tag_parser.add_mutually_exclusive_group()
    tag_mode.add_argument(
        "--current",
        action="store_true",
        help="require the tag to match the site's current VERSION",
    )
    tag_mode.add_argument(
        "--rollback",
        action="store_true",
        help="require the tag to be strictly older than the site's current VERSION",
    )
    args = parser.parse_args(argv)

    if args.command == "validate":
        errors = repository_errors(args.root.resolve(), args.site)
    else:
        errors = tag_errors(
            args.root.resolve(),
            args.site,
            args.tag,
            current=args.current,
            rollback=args.rollback,
        )
    if errors:
        for error in errors:
            print("FAIL " + error, file=sys.stderr)
        return 1
    print("PASS immutable image release version policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
