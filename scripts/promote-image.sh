#!/usr/bin/env bash

# Retired by ADR 0016's 2026-08-24 amendment. Site workload identity now comes
# only from a signature-verified chart selected by an exact OCI manifest
# digest. Reintroducing a HelmRelease image override would create a second,
# conflicting release authority.
printf '%s\n' \
  'promote-image: RETIRED; review an exact chart-release annotation and OCI manifest digest pair in source.yaml' \
  >&2
exit 1
