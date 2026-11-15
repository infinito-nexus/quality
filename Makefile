SHELL := /bin/bash
INSPECT_COMPOSE := docker compose -f service/compose.yml
WEB_SECRET := build/web-secret
DEV_CONFIG := build/dev-config.json
QUALITY_DEV_DB := $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/quality-check/dev-db
QUALITY_DEV_PORT := 18098
export QUALITY_DEV_PORT
export QUALITY_DEV_DB_DIR = $(abspath $(QUALITY_DEV_DB))
VERIFY_APPS := web-app-keycloak,web-app-cst-quality-check
VERIFY_DISABLE :=
VERIFY_VARIANT := 0
SERVICE_VENV := .venv/service
TEST_WORKERS := 4
FLAKE_RESULT := build/flake/result

.PHONY: test-unit test-integration test-bench test-service test-egress test-distribution test-e2e flake up down verify-test verify-compose

test-unit:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/unit tests/workflows

# Param: TEST_WORKERS - pytest-xdist workers; with each tool's parallel work capped at TOOL_THREADS of tests/integration/support.py, the run stays near this many cores on a shared host
test-integration:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/integration -n $(TEST_WORKERS) --dist worksteal

# Param: QUALITY_CORE_DIR (required) - core checkout the benchmarks read, never change
# Param: QUALITY_DB_DIR (required) - fresh bundle of `quality db update` for the deep tier
# Param: QUALITY_DEFAULTS_SCRIPT (required) - defaults.py of the kvb-code-clean skill, the reference of the recall bound
test-bench:
	@test -n "$(QUALITY_CORE_DIR)" || { echo "QUALITY_CORE_DIR is required" >&2; exit 2; }
	@test -n "$(QUALITY_DB_DIR)" || { echo "QUALITY_DB_DIR is required" >&2; exit 2; }
	@test -n "$(QUALITY_DEFAULTS_SCRIPT)" || { echo "QUALITY_DEFAULTS_SCRIPT is required" >&2; exit 2; }
	QUALITY_CORE_DIR='$(QUALITY_CORE_DIR)' QUALITY_DB_DIR='$(QUALITY_DB_DIR)' QUALITY_DEFAULTS_SCRIPT='$(QUALITY_DEFAULTS_SCRIPT)' \
		PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/bench tests/distribution/test_distribution.py::test_version_stays_within_its_budget -rs --durations=0

$(SERVICE_VENV)/bin/pytest: service/web/requirements.txt tests/service/requirements.txt
	python3 -m venv $(SERVICE_VENV)
	$(SERVICE_VENV)/bin/pip install --quiet -r service/web/requirements.txt -r tests/service/requirements.txt
	touch $@

test-service: $(SERVICE_VENV)/bin/pytest
	PATH="$(abspath $(SERVICE_VENV))/bin:$$PATH" PYTHONDONTWRITEBYTECODE=1 $(SERVICE_VENV)/bin/python -m pytest tests/service

flake:
	nix --extra-experimental-features "nix-command flakes" build path:.#default path:.#image --out-link $(FLAKE_RESULT)

test-distribution: flake
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/distribution

# Param: QUALITY_E2E_SKILLS (required) - path or URL of the skills repository the test clones
# Param: QUALITY_E2E_PACKAGE_MANAGER (required) - path or URL of the package-manager repository the test clones
# Param: QUALITY_E2E_RUNTIME (required) - docker runtime the image runs under, core's SANDBOX_RUNTIME (runsc) on a sandbox host
test-e2e:
	@test -n "$(QUALITY_E2E_RUNTIME)" || { echo "QUALITY_E2E_RUNTIME is required: the docker runtime test-e2e runs the image under" >&2; exit 2; }
	$(MAKE) --no-print-directory flake
	QUALITY_E2E_BINARY=$(abspath $(FLAKE_RESULT))/bin/quality QUALITY_E2E_IMAGE=$(abspath $(FLAKE_RESULT))-1 \
		PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/e2e/test_host_vs_image.py

# Fails without the running stack of `make up`: the tests join its images and fetch network
# Param: INFINITO_CORE_DIR (required) - core checkout whose container wrapper test_stage_flags runs the step flags through
# Param: EGRESS_RUNTIMES (required) - space-separated container runtimes, e.g. "runc sysbox-runc"; every launcher and test-proxy test runs once under each, and docker info must offer all of them
test-egress:
	@test -n "$(INFINITO_CORE_DIR)" || { echo "INFINITO_CORE_DIR is required" >&2; exit 2; }
	@test -n "$(EGRESS_RUNTIMES)" || { echo "EGRESS_RUNTIMES is required" >&2; exit 2; }
	EGRESS_RUNTIMES='$(EGRESS_RUNTIMES)' PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/egress -rs

$(WEB_SECRET):
	@mkdir -p $(dir $@)
	@head -c 48 /dev/urandom | base64 > $@
	@chmod 0644 $@

# Param: QUALITY_DEV_DB - directory whose bundle/ every scan step of the stack mounts read-only at /db and whose manifest the launcher reads for the report header; the stack never updates it. Under the XDG cache by default, so one `quality db update --db <it>/bundle` serves every later stack
# Param: QUALITY_DEV_PORT - port on 127.0.0.1 the stack serves on; 18098 is the port this repository's docs name, and a host where another stack holds it passes a free one
up: $(WEB_SECRET)
	@test -f $(QUALITY_DEV_DB)/bundle/manifest.json || { echo "no vulnerability database at $(QUALITY_DEV_DB)/bundle: run quality db update --db $(QUALITY_DEV_DB)/bundle" >&2; exit 2; }
	python3 -c 'import json, sys; config = json.load(open(sys.argv[1])); config["database"]["dir"] = sys.argv[2]; config["public_url"] = sys.argv[3]; print(json.dumps(config))' service/dev/config.json $(QUALITY_DEV_DB_DIR) http://localhost:$(QUALITY_DEV_PORT) > $(DEV_CONFIG)
	$(INSPECT_COMPOSE) --profile image build
	$(INSPECT_COMPOSE) up -d --wait
	@echo "Inspection mode: http://localhost:$(QUALITY_DEV_PORT)/"

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
