# Keep local validation close to pull-request CI. Tool versions come from
# versions.env; this file orchestrates checks but never installs or authenticates.
SHELL := /usr/bin/env bash
PYTHON ?= python3
.DEFAULT_GOAL := help

.PHONY: help check check-fast release-check check-layout check-privacy check-secrets check-gitleaks check-workflows check-container check-kubernetes check-cloudflare check-shell check-tofu website-test kind-check

help:
	@printf '%s\n' \
	  'check            Run every credential-free validation gate' \
	  'check-fast       Run repository checks requiring only Python and Git' \
	  'release-check    Reject every deployment sentinel/suspension' \
	  'check-privacy    Reject private workstation, identity, and host context' \
	  'check-kubernetes Render/schema/policy-test Kubernetes desired state' \
	  'check-cloudflare Validate OpenTofu formatting and plan fixtures' \
	  'kind-check       Check pinned prerequisites for the disposable local Kind harness' \
	  'website-test     Check Svelte/Go code, artifacts, and served-site contracts'

check: check-fast check-gitleaks check-shell check-workflows check-container check-kubernetes check-cloudflare website-test

check-fast:
	@$(PYTHON) scripts/validate_repository.py all
	@$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

release-check:
	@$(PYTHON) scripts/validate_repository.py release

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

check-container:
	@hadolint websites/naranjo.online/Dockerfile websites/lidersea.com/Dockerfile

check-kubernetes:
	@./scripts/render-kubernetes.sh
	@./scripts/validate-security.sh

check-cloudflare:
	@tofu -chdir=infrastructure/cloudflare fmt -check -recursive
	@tofu -chdir=infrastructure/cloudflare init -backend=false
	@tofu -chdir=infrastructure/cloudflare validate
	@./scripts/test-cloudflare-policy.sh

check-tofu: check-cloudflare

website-test:
	@test -f websites/naranjo.online/frontend/package-lock.json
	@cd websites/naranjo.online/frontend && npm ci --ignore-scripts --no-audit --no-fund && npm run check && npm test && npm run build
	@$(PYTHON) scripts/validate_frontend_dist.py --site naranjo.online
	@test -f websites/lidersea.com/frontend/package-lock.json
	@cd websites/lidersea.com/frontend && npm ci --ignore-scripts --no-audit --no-fund && npm run check && npm test && npm run build
	@$(PYTHON) scripts/validate_frontend_dist.py --site lidersea.com
	@$(PYTHON) scripts/validate_repository.py media
	@test -z "$$(gofmt -l websites/naranjo.online)"
	@cd websites/naranjo.online && GOTOOLCHAIN=local go vet ./...
	@cd websites/naranjo.online && GOTOOLCHAIN=local go test ./...
	@test -z "$$(gofmt -l websites/lidersea.com)"
	@cd websites/lidersea.com && GOTOOLCHAIN=local go vet ./...
	@cd websites/lidersea.com && GOTOOLCHAIN=local go test ./...

kind-check:
	@./scripts/test-kind.sh --check
