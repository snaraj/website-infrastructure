### Changed

- Advance naranjo.online's exact signed chart selection to its published
  release `0.1.67` (carrying the site's merged gesture train — naranjo.online
  PR #273: pull-to-refresh, gallery swipe and captions, projects stats, the
  Media surface, and the coverage heatmap — to the domain) by re-resolving
  the reviewed tag, verifying the repository-at-digest against the site's
  `release-publisher.yml@refs/heads/main` keyless identity, inspecting the
  sole Helm chart layer and its embedded workload image, and binding the
  protected-main source commit and immutable Release asset before the
  annotation and digest moved together. lidersea.com stays at its receipted
  `0.1.40` selection; `scripts/promote-image.sh` stays retired fail-closed
  and no HelmRelease override is reintroduced.
- Recapture `docs/assurance/195-chart-acquisition-receipt.{json,md}` for
  that acquisition, keeping every reviewed tag/digest pair identical across
  the receipt, `scripts/validate_signature_policy.py`,
  `policies/conftest/kubernetes.rego`, and
  `kubernetes/websites/naranjo-online/source.yaml`, so no two can disagree.
