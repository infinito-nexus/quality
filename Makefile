SHELL := /bin/bash
INSPECT_COMPOSE := docker compose -f service/compose.yml
WEB_SECRET := build/web-secret
VERIFY_APPS := web-app-keycloak,web-app-cst-quality-check
VERIFY_DISABLE :=
VERIFY_VARIANT := 0
SERVICE_VENV := .venv/service

.PHONY: test-unit test-integration test-service test-egress up down verify-test verify-compose

test-unit:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/unit

test-integration:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/integration

$(SERVICE_VENV)/bin/pytest: service/web/requirements.txt
	python3 -m venv $(SERVICE_VENV)
	$(SERVICE_VENV)/bin/pip install --quiet -r service/web/requirements.txt pytest==9.2.0
	touch $@

test-service: $(SERVICE_VENV)/bin/pytest
	PYTHONDONTWRITEBYTECODE=1 $(SERVICE_VENV)/bin/python -m pytest tests/service

# Fails without the running stack of `make up`: the tests join its images and fetch network
test-egress:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/egress

$(WEB_SECRET):
	@mkdir -p $(dir $@)
	@head -c 48 /dev/urandom | base64 > $@
	@chmod 0644 $@

up: $(WEB_SECRET)
	$(INSPECT_COMPOSE) --profile image build
	$(INSPECT_COMPOSE) up -d --wait
	@echo "Inspection mode: http://localhost:18098/"

down:
	$(INSPECT_COMPOSE) --profile image down -v

# Param: INFINITO_CORE_DIR (required) - core checkout with custom-role support (make roles-pull)
verify-test:
	@test -n "$(INFINITO_CORE_DIR)" || { echo "INFINITO_CORE_DIR is required" >&2; exit 2; }
	set -o pipefail; bash service/verify/core.sh test 2>&1 | tee /tmp/quality-check-verify-test.log

# Param: INFINITO_CORE_DIR (required) - core checkout with custom-role support (make roles-pull)
# Param: VERIFY_APPS - roles the deploy runs; Keycloak by default, because the role brings its own OIDC client
# Param: VERIFY_DISABLE - core services the deploy disables, empty by default so every dependent role deploys
# Param: VERIFY_VARIANT - variant round the deploy pins; 1 turns anonymous submissions off
verify-compose: verify-test
	set -o pipefail; VERIFY_APPS='$(VERIFY_APPS)' VERIFY_DISABLE='$(VERIFY_DISABLE)' VERIFY_VARIANT='$(VERIFY_VARIANT)' \
		bash service/verify/core.sh deploy 2>&1 | tee /tmp/quality-check-verify-compose.log
