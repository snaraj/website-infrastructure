#!/usr/bin/env python3
"""Remove one failed promotion transaction without traversing a symlink root."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
from pathlib import Path


SITE_RE = re.compile(r"(?:naranjo-online|lidersea-com)\Z")


class CleanupError(ValueError):
    """The requested cleanup path is not one owned review transaction."""


def remove_transaction(artifact_root: Path, transaction_root: Path, site: str) -> None:
    if not SITE_RE.fullmatch(site):
        raise CleanupError("cleanup site escaped its closed allowlist")
    artifact = Path(os.path.abspath(os.fspath(artifact_root)))
    transaction = Path(os.path.abspath(os.fspath(transaction_root)))
    expected_name = re.compile(r"promotion\.{}\.[A-Za-z0-9]+\Z".format(re.escape(site)))
    try:
        artifact_metadata = artifact.lstat()
        transaction_metadata = transaction.lstat()
        if (
            not stat.S_ISDIR(artifact_metadata.st_mode)
            or not stat.S_ISDIR(transaction_metadata.st_mode)
            or artifact.resolve(strict=True) != artifact
            or transaction.resolve(strict=True) != transaction
            or transaction.parent != artifact
            or not expected_name.fullmatch(transaction.name)
        ):
            raise CleanupError("cleanup target is not one real owned transaction")
        shutil.rmtree(transaction)
        if os.path.lexists(transaction):
            raise CleanupError("cleanup target still exists")
        if artifact.resolve(strict=True) != artifact:
            raise CleanupError("artifact root changed during cleanup")
    except CleanupError:
        raise
    except (OSError, RuntimeError) as error:
        raise CleanupError("review transaction could not be removed safely") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--transaction-root", type=Path, required=True)
    parser.add_argument("--site", required=True)
    args = parser.parse_args(argv)
    try:
        remove_transaction(args.artifact_root, args.transaction_root, args.site)
    except CleanupError:
        print("ERROR failed review transaction could not be removed safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
