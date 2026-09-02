# Keep local validation close to pull-request CI. Tool versions come from
# versions.env; this file orchestrates checks but never installs or authenticates.
SHELL := /usr/bin/env bash
PYTHON ?= python3
.DEFAULT_GOAL := help

.PHONY: help check check-fast release-check pre-push-security check-gitleaks check-workflows check-kubernetes check-cloudflare check-shell check-determinism check-ingress-guard coverage coverage-refresh

help:
	@printf '%s\n' \
	  'check            Run the credential-free worktree/render validation suite' \
	  'check-fast       Run repository checks requiring only Python and Git' \
	  'release-check    Reject every deployment sentinel/suspension' \
	  'pre-push-security Rehearse the origin/main..HEAD publication gate' \
	  'check-gitleaks   Scan the working tree with the pinned gitleaks policy' \
	  'check-shell      Shellcheck every tracked shell entry point' \
	  'check-workflows  Actionlint the GitHub Actions workflows' \
	  'check-kubernetes Render/schema/policy-test Kubernetes desired state' \
	  'check-cloudflare Validate OpenTofu formatting and plan fixtures' \
	  'check-determinism Prove two renders of the selected mode are identical' \
	  'check-ingress-guard Verify the SSH-only admin-ingress guard artifacts' \
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
