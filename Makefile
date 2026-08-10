# Keep local validation close to pull-request CI. Tool versions come from
# versions.env; this file orchestrates checks but never installs or authenticates.
SHELL := /usr/bin/env bash
PYTHON ?= python3
.DEFAULT_GOAL := help

.PHONY: help check check-fast release-check pre-push-security check-layout check-privacy check-secrets check-gitleaks check-workflows check-kubernetes check-cloudflare check-shell check-tofu

help:
	@printf '%s\n' \
	  'check            Run the credential-free worktree/render validation suite' \
	  'check-fast       Run repository checks requiring only Python and Git' \
	  'release-check    Reject every deployment sentinel/suspension' \
	  'pre-push-security Rehearse the origin/main..HEAD publication gate' \
	  'check-privacy    Reject private workstation, identity, and host context' \
	  'check-kubernetes Render/schema/policy-test Kubernetes desired state' \
	  'check-cloudflare Validate OpenTofu formatting and plan fixtures' \
	  'check-determinism Prove two scaffold renders are byte-identical'

check: check-fast check-gitleaks check-shell check-workflows check-kubernetes check-cloudflare

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
	@./scripts/render-kubernetes.sh
	@./scripts/validate-security.sh

check-cloudflare:
	@./scripts/validate-cloudflare-iac.sh

check-determinism:
	@./scripts/ci/verify-render-determinism.sh

check-tofu: check-cloudflare

