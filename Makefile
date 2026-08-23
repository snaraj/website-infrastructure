# Keep local validation close to pull-request CI. Tool versions come from
# versions.env; this file orchestrates checks but never installs or authenticates.
SHELL := /usr/bin/env bash
PYTHON ?= python3
.DEFAULT_GOAL := help

.PHONY: help check check-fast release-check pre-push-security check-layout check-privacy check-secrets check-gitleaks check-workflows check-kubernetes check-cloudflare check-shell check-tofu check-determinism check-ingress-guard flux-rbac-kind-acceptance coverage coverage-refresh

help:
	@printf '%s\n' \
	  'check            Run the credential-free worktree/render validation suite' \
	  'check-fast       Run repository checks requiring only Python and Git' \
	  'release-check    Reject every deployment sentinel/suspension' \
	  'pre-push-security Rehearse the origin/main..HEAD publication gate' \
	  'check-layout     Reject local-only or forbidden repository layout content' \
	  'check-privacy    Reject private workstation, identity, and host context' \
	  'check-secrets    Reject committed secret material and plaintext config' \
	  'check-gitleaks   Scan the working tree with the pinned gitleaks policy' \
	  'check-shell      Shellcheck every tracked shell entry point' \
	  'check-workflows  Actionlint the GitHub Actions workflows' \
	  'check-kubernetes Render/schema/policy-test Kubernetes desired state' \
	  'check-cloudflare Validate OpenTofu formatting and plan fixtures' \
	  'check-tofu       Alias for check-cloudflare' \
	  'check-determinism Prove two renders of the selected mode are identical' \
	  'check-ingress-guard Verify the SSH-only admin-ingress guard artifacts' \
	  'flux-rbac-kind-acceptance Run full Flux RBAC/Kustomize/Helm acceptance in a new isolated owned kind cluster' \
	  'coverage         Measure suite coverage and enforce floor/drift/badge' \
	  'coverage-refresh Re-measure and rewrite the committed coverage ledger/badge'

check: check-fast check-gitleaks check-shell check-workflows check-kubernetes check-cloudflare check-ingress-guard

# Bytecode caches from a plain run would poison the later pre-push gate's
# ambient-artifact check; a macOS TMPDIR under the /var symlink trips the
# suite's own link-traversal guards, so both are normalized here.
check-fast: export PYTHONDONTWRITEBYTECODE = 1
check-fast:
	@TMPDIR="$$(realpath "$${TMPDIR:-/tmp}")" $(PYTHON) scripts/validate_repository.py all
	@TMPDIR="$$(realpath "$${TMPDIR:-/tmp}")" $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

release-check:
	@$(PYTHON) scripts/validate_repository.py release

pre-push-security:
	@./scripts/pre-push-security.sh "$$(git rev-parse --verify refs/remotes/origin/main^{commit})" "$$(git rev-parse --verify HEAD^{commit})"

check-layout:
	@$(PYTHON) scripts/validate_repository.py layout

check-privacy:
	@$(PYTHON) scripts/validate_repository.py privacy

check-secrets:
	@$(PYTHON) scripts/validate_repository.py secrets

check-gitleaks:
	@gitleaks dir --no-banner --redact --config policies/gitleaks.toml .

check-shell:
	@find bootstrap scripts -type f -name '*.sh' -print0 | xargs -0 shellcheck

check-workflows:
	@actionlint

check-kubernetes:
	@set -euo pipefail; \
	  release_mode="$$(python3 -B scripts/validate_release_transition.py select-mode)"; \
	  case "$${release_mode}" in scaffold|transition|release) ;; \
	    *) printf '%s\n' 'Unsafe release transition mode.' >&2; exit 1 ;; \
	  esac; \
	  ./scripts/render-kubernetes.sh "--$${release_mode}"
	@./scripts/validate-security.sh

check-cloudflare:
	@./scripts/validate-cloudflare-iac.sh

check-determinism:
	@./scripts/ci/verify-render-determinism.sh

check-ingress-guard:
	@$(PYTHON) scripts/validate_ingress_guard.py repo
	@$(PYTHON) scripts/validate_admin_ingress_contract.py EXAMPLE bootstrap/pi/ingress-guard/admin-ingress.env.example

# Under the owner-controlled local entrypoint assumption, the explicit SHA,
# external receipt, raw comparison, and no-replace committed harness execution
# detect accidental checkout drift. This target is defence in depth, not an
# external stage-zero provenance or promotion authority.
unexport EXPECTED_COMMIT FLUX_RBAC_KIND_RECEIPT PYTHON
flux-rbac-kind-acceptance: export FLUX_RBAC_EXPECTED_COMMIT := $(value EXPECTED_COMMIT)
flux-rbac-kind-acceptance: export FLUX_RBAC_RECEIPT_PATH := $(value FLUX_RBAC_KIND_RECEIPT)
flux-rbac-kind-acceptance: export FLUX_RBAC_PYTHON := $(value PYTHON)
flux-rbac-kind-acceptance:
	@set -euo pipefail; \
	  test -n "$${FLUX_RBAC_EXPECTED_COMMIT}" || { printf '%s\n' 'EXPECTED_COMMIT is required' >&2; exit 2; }; \
	  test -n "$${FLUX_RBAC_RECEIPT_PATH}" || { printf '%s\n' 'FLUX_RBAC_KIND_RECEIPT is required' >&2; exit 2; }; \
	  [[ "$${FLUX_RBAC_EXPECTED_COMMIT}" =~ ^[0-9a-f]{40}$$ ]] || { printf '%s\n' 'EXPECTED_COMMIT must be a full lowercase SHA-1' >&2; exit 2; }; \
	  umask 077; \
	  repo_root="$$(pwd -P)"; \
	  tmp_parent="$$(realpath "$${TMPDIR:-/tmp}")"; \
	  case "$${tmp_parent}/" in "$${repo_root}/"*) printf '%s\n' 'TMPDIR must be outside the checkout' >&2; exit 2 ;; esac; \
	  launch_root="$$(mktemp -d "$${tmp_parent}/flux-rbac-kind-launch.XXXXXX")"; \
	  cleanup() { case "$${launch_root}" in "$${tmp_parent}"/flux-rbac-kind-launch.*) rm -rf -- "$${launch_root}" ;; *) return 1 ;; esac; }; \
	  trap cleanup EXIT; \
	  trap 'exit 129' HUP; \
	  trap 'exit 130' INT; \
	  trap 'exit 143' TERM; \
	  chmod 700 "$${launch_root}"; \
	  harness="$${launch_root}/flux_rbac_kind_acceptance.py"; \
	  trusted_git() { env -i PATH="$${PATH}" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 git --no-replace-objects -c credential.helper= -c core.askPass= -c core.fsmonitor=false -c core.untrackedCache=false "$$@"; }; \
	  test ! -e "$$(trusted_git rev-parse --path-format=absolute --git-path info/grafts)" || { printf '%s\n' 'Git grafts are forbidden' >&2; exit 2; }; \
	  test ! -e "$$(trusted_git rev-parse --path-format=absolute --git-path objects/info/alternates)" || { printf '%s\n' 'Git alternates are forbidden' >&2; exit 2; }; \
	  test ! -e "$$(trusted_git rev-parse --path-format=absolute --git-path objects/info/http-alternates)" || { printf '%s\n' 'Git HTTP alternates are forbidden' >&2; exit 2; }; \
	  test -z "$$(trusted_git for-each-ref --format='%(refname)' refs/replace)" || { printf '%s\n' 'Git replacement refs are forbidden' >&2; exit 2; }; \
	  trusted_git fsck --strict --full --no-reflogs >/dev/null 2>&1 || { printf '%s\n' 'Git object integrity check failed' >&2; exit 2; }; \
	  trusted_git cat-file blob "$${FLUX_RBAC_EXPECTED_COMMIT}:scripts/flux_rbac_kind_acceptance.py" > "$${harness}"; \
	  chmod 600 "$${harness}"; \
	  cmp -s -- scripts/flux_rbac_kind_acceptance.py "$${harness}" || { printf '%s\n' 'Worktree harness bytes differ from EXPECTED_COMMIT' >&2; exit 2; }; \
	  harness_blob="$$(trusted_git rev-parse "$${FLUX_RBAC_EXPECTED_COMMIT}:scripts/flux_rbac_kind_acceptance.py")"; \
	  test "$$(trusted_git hash-object --no-filters "$${harness}")" = "$${harness_blob}" || { printf '%s\n' 'Committed harness extraction failed validation' >&2; exit 2; }; \
	  handoff="$${launch_root}/handoff"; \
	  printf '1\n%s\n%s\n' "$${FLUX_RBAC_EXPECTED_COMMIT}" "$${harness_blob}" > "$${handoff}"; \
	  chmod 600 "$${handoff}"; \
	  FLUX_RBAC_ACCEPTANCE_REPOSITORY_ROOT="$${repo_root}" \
	  FLUX_RBAC_ACCEPTANCE_LAUNCH_ROOT="$${launch_root}" \
	  FLUX_RBAC_ACCEPTANCE_HANDOFF="$${handoff}" \
	  "$${FLUX_RBAC_PYTHON}" -I -B -S "$${harness}" \
	    --expected-commit "$${FLUX_RBAC_EXPECTED_COMMIT}" \
	    --receipt "$${FLUX_RBAC_RECEIPT_PATH}"

check-tofu: check-cloudflare

# Coverage measurement writes its data outside the checkout (measurement
# artifacts in the tree would trip the ambient-artifact checks) and needs the
# one hash-pinned wheel installed first:
#   pip install --require-hashes -r scripts/ci/requirements-coverage.txt
# 'coverage' enforces the committed contract; 'coverage-refresh' re-measures
# and rewrites docs/badges/ for committing after test changes.
coverage: COVERAGE_GATE_MODE = gate
coverage-refresh: COVERAGE_GATE_MODE = refresh
coverage coverage-refresh: export PYTHONDONTWRITEBYTECODE = 1
coverage coverage-refresh:
	@set -euo pipefail; \
	  tmp_root="$$(realpath "$${TMPDIR:-/tmp}")"; \
	  data_dir="$$(mktemp -d "$${tmp_root}/website-infrastructure-coverage.XXXXXX")"; \
	  trap 'rm -rf -- "$$data_dir"' EXIT; \
	  export COVERAGE_FILE="$$data_dir/data"; \
	  export COVERAGE_RCFILE="$$PWD/scripts/ci/coveragerc"; \
	  export COVERAGE_SOURCE_ROOT="$$PWD/scripts"; \
	  TMPDIR="$$tmp_root" $(PYTHON) -B -m coverage run -m unittest discover -s tests -p 'test_*.py'; \
	  $(PYTHON) -B -m coverage combine >/dev/null; \
	  $(PYTHON) -B scripts/ci/coverage_gate.py $(COVERAGE_GATE_MODE) --data-file "$$data_dir/data"
