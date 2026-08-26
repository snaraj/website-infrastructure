"""Custodied dispatch for the one authenticated v0.1.30 recovery incident."""

from __future__ import annotations


SCHEMA = "flux-rbac-v030-recovery-dispatch-v1"


def run(transaction: object, custody: object) -> None:
    """Enter only the recovery implementation bound into transaction.py."""

    if getattr(transaction, "RECOVERY_SCHEMA", None) != SCHEMA:
        raise transaction.TransactionError("RECOVERY_DISPATCH_IDENTITY_INVALID")
    transaction.recover_v030(custody)
