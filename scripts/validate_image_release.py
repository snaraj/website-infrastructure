#!/usr/bin/env python3
"""Validate independent, immutable website container release versions."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
TAGGED_SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
POLICY_FILE = "release-policy.env"

# The paths are deliberately explicit. Chart-only changes do not alter a
# container, while source, Docker build inputs, and the selected publication
# lane do. Shared release tooling changes require both independent versions to
# move so a main-branch rebuild can never collide with an existing SemVer tag.
SITE_CONTRACTS = {
    "naranjo-online": {
        "domain": "naranjo.online",
        "gate": "NARANJO_ONLINE_PRODUCTION_GRADUATED",
        "workflow": ".github/workflows/publish-naranjo-online-image.yml",
    },
    "lidersea-com": {
        "domain": "lidersea.com",
        "gate": "LIDERSEA_COM_PRODUCTION_GRADUATED",
        "workflow": ".github/workflows/publish-lidersea-com-image.yml",
    },
}
SHARED_RELEASE_INPUTS = {
    "scripts/ci/install-tools.sh",
    "scripts/ci/publish-oci-artifact.sh",
    "scripts/ci/publish-stable-oci-tag.sh",
    "scripts/ci/verify-existing-oci-release.sh",
    "scripts/ci/verify-oci-artifact.sh",
    "scripts/validate_image_release.py",
    "versions.env",
}
SITE_BUILD_FILES = {".dockerignore", "Dockerfile", "go.mod", "go.sum"}
SITE_BUILD_DIRECTORIES = {"cmd", "frontend", "internal"}


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


def _read_exact_single_line(path):
    """Read one newline-terminated UTF-8 line without normalizing its value."""

    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if text.endswith("\r\n"):
        value = text[:-2]
        terminator = "\r\n"
    elif text.endswith("\n"):
        value = text[:-1]
        terminator = "\n"
    else:
        return None
    if not value or "\n" in value or "\r" in value:
        return None
    if text != value + terminator:
        return None
    return value


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


def version_path(root, site):
    """Return the one authoritative container VERSION path for a site."""

    return root / "websites" / SITE_CONTRACTS[site]["domain"] / "VERSION"


def read_version(root, site):
    """Return one canonical stable SemVer value, or ``None`` when invalid."""

    value = _read_exact_single_line(version_path(root, site))
    return value if value is not None and parse_semver(value) is not None else None


def repository_errors(root, site=None):
    """Report static release-policy errors without reading Git or the network."""

    root = Path(root)
    sites = [site] if site else list(SITE_CONTRACTS)
    if any(candidate not in SITE_CONTRACTS for candidate in sites):
        return ["unknown website release identity"]

    errors = []
    policy = read_policy(root)
    if policy is None:
        return [
            "release-policy.env must contain exactly the two reviewed yes/no "
            "production-graduation gates"
        ]

    for candidate in sites:
        version = read_version(root, candidate)
        relative_version = version_path(root, candidate).relative_to(root).as_posix()
        if version is None:
            errors.append(
                "{} must contain one newline-terminated stable SemVer without "
                "a v prefix, prerelease, build metadata, whitespace, or leading zeros".format(
                    relative_version
                )
            )
            continue
        major = parse_semver(version)[0]
        graduated = policy[SITE_CONTRACTS[candidate]["gate"]] == "yes"
        if not graduated and major != 0:
            errors.append(
                "{} must remain v0.x.x until its tracked production gate is yes".format(
                    candidate
                )
            )
        if graduated and major == 0:
            errors.append(
                "{} production graduation must atomically move VERSION to v1.0.0 or later".format(
                    candidate
                )
            )
    return errors


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
    if current or rollback:
        current_version = read_version(Path(root), site)
        current_parsed = parse_semver(current_version) if current_version else None
        if current and current_version is not None and tag != "v" + current_version:
            errors.append(
                "current promotion tag must exactly match the site's tracked VERSION"
            )
        if rollback and current_parsed is not None and parsed >= current_parsed:
            errors.append(
                "rollback tag must be strictly older than the site's tracked VERSION"
            )
    return errors


def is_release_input(site, path):
    """Return whether a changed repository path can affect a site's release."""

    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    contract = SITE_CONTRACTS[site]
    if normalized == contract["workflow"] or normalized in SHARED_RELEASE_INPUTS:
        return True
    prefix = "websites/{}/".format(contract["domain"])
    if not normalized.startswith(prefix):
        return False
    relative = normalized[len(prefix):]
    first = relative.split("/", 1)[0]
    return relative in SITE_BUILD_FILES or first in SITE_BUILD_DIRECTORIES


def changed_release_errors(root, changed_paths, base_versions, base_policy):
    """Require a strictly increasing independent version for changed inputs."""

    root = Path(root)
    errors = repository_errors(root)
    if errors:
        return errors
    current_policy = read_policy(root)
    normalized_paths = {path.replace("\\", "/").lstrip("/") for path in changed_paths}
    for site, contract in SITE_CONTRACTS.items():
        gate = contract["gate"]
        release_changed = any(is_release_input(site, path) for path in changed_paths)
        release_changed = release_changed or base_policy is None
        if base_policy is not None:
            release_changed = release_changed or base_policy.get(gate) != current_policy[gate]
        version_file = "websites/{}/VERSION".format(contract["domain"])
        version_changed = version_file in normalized_paths or "./" + version_file in normalized_paths
        if not release_changed and not version_changed:
            continue

        previous = base_versions.get(site)
        current = read_version(root, site)
        if previous is None:
            continue
        previous_tuple = parse_semver(previous)
        if previous_tuple is None or parse_semver(current) <= previous_tuple:
            errors.append(
                "{} release inputs changed without a strictly increasing VERSION "
                "(base {}, current {})".format(site, previous, current)
            )
    return errors


def _git(root, *arguments, allow_missing=False):
    """Run one read-only Git query and return text or ``None`` when allowed."""

    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if result.returncode == 0:
        return result.stdout
    if allow_missing:
        return None
    raise RuntimeError(result.stderr.strip() or "Git query failed")


def _git_bytes(root, *arguments):
    """Run one read-only Git query without pathname decoding or quoting."""

    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        return result.stdout
    message = result.stderr.decode("utf-8", errors="replace").strip()
    raise RuntimeError(message or "Git query failed")


def _nul_paths(value):
    """Decode one complete NUL-delimited Git pathname stream losslessly."""

    if not isinstance(value, bytes) or (value and not value.endswith(b"\0")):
        raise ValueError("malformed NUL-delimited Git pathname output")
    if not value:
        return []
    records = value[:-1].split(b"\0")
    if any(not record for record in records):
        raise ValueError("malformed NUL-delimited Git pathname output")
    return [record.decode("utf-8", errors="surrogateescape") for record in records]


def git_changed_errors(root, base):
    """Compare a pull request to its trusted base commit without credentials."""

    root = Path(root).resolve()
    if not FULL_GIT_SHA.fullmatch(base):
        return ["pull-request base must be one full lowercase Git commit SHA"]
    try:
        _git(root, "cat-file", "-e", "{}^{{commit}}".format(base))
        changed_bytes = _git_bytes(
            # Disabling rename detection deliberately exposes both the deleted
            # build input and its new path. Otherwise moving a source file out
            # of a site's release tree could look like an unrelated addition
            # and evade the required version bump. NUL delimiters also disable
            # Git pathname quoting and preserve embedded control characters.
            root, "diff", "--name-only", "-z", "--no-renames",
            "--diff-filter=ACDMRTUXB",
            "{}...HEAD".format(base), "--"
        )
        changed_paths = _nul_paths(changed_bytes)
    except (OSError, RuntimeError, ValueError) as error:
        return ["cannot compare release versions with base commit: {}".format(error)]

    base_versions = {}
    for site, contract in SITE_CONTRACTS.items():
        path = "websites/{}/VERSION".format(contract["domain"])
        value = _git(root, "show", "{}:{}".format(base, path), allow_missing=True)
        if value is None:
            base_versions[site] = None
        else:
            base_versions[site] = value.rstrip("\r\n")
    policy_text = _git(root, "show", "{}:{}".format(base, POLICY_FILE), allow_missing=True)
    base_policy = _read_policy_text(policy_text) if policy_text is not None else None
    return changed_release_errors(root, changed_paths, base_versions, base_policy)


def main(argv=None):
    """Run static, promotion-tag, or pull-request release validation."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--site", choices=sorted(SITE_CONTRACTS))
    changed_parser = subparsers.add_parser("changed")
    changed_parser.add_argument("--base", required=True)
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
    elif args.command == "changed":
        errors = git_changed_errors(args.root.resolve(), args.base)
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
