"""Hermetic mock clients for the release-sync contract batteries.

WHAT THIS IS
------------

Three small, dependency-free models used by ``tests/security`` to exercise the
digest-selected release flow of ADR 0016 without touching anything live:

* :mod:`tests.security.testsupport.oci_registry` — a real HTTP server on loopback that
  speaks the slice of the OCI Distribution API this platform depends on
  (manifest resolution by exact digest and cosign signature presence
  with its certificate identity), plus a ``urllib`` client that speaks to it.
* :mod:`tests.security.testsupport.kubernetes_api` — a typed in-memory Kubernetes API
  with the three object kinds this flow touches (``OCIRepository``,
  ``HelmRelease``, ``Deployment``), modelling apply/patch, generation bumps on
  spec change, and status subresource transitions.
* :mod:`tests.security.testsupport.flux_sync` — the release-sync state machine itself,
  written against those two clients: pinned digest → exact fetch →
  signature-verification decision → digest-bound upgrade → rollout health →
  rollback.

WHAT THIS IS NOT
----------------

**These are models, not Flux.** No source-controller, helm-controller, cosign,
Helm, or Kubernetes API server executes here, and no chart signature is
cryptographically verified by anything. A battery built on this module proves
two things and claims nothing more:

1. the *contract* — the sequence of decisions and denials the platform expects
   from a digest-selected, signature-verified release flow — is internally coherent
   and fails closed on every hostile input the batteries enumerate; and
2. the *committed manifests* express exactly that contract, because the
   batteries build their fixtures from the same reviewed field values the
   manifests carry and re-derive them through the repository's own validators.

Proving that a running Flux controller behaves this way is a separate, live
event that this repository deliberately cannot perform. Where a test's name or
docstring could be read as claiming live behavior, it says so explicitly
instead.

This package is support code, not a test module: ``unittest`` discovery only
collects ``test_*.py``, and the coverage gate's source scope is ``scripts/``
alone (``[run] source`` in ``scripts/ci/coveragerc``), so nothing here enters
any coverage denominator.
"""
