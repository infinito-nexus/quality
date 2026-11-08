#!/usr/bin/env bash
# Param $1: test runs core's full test suite with the role pulled in, deploy runs compose-deploy (required)
# Param INFINITO_CORE_DIR: core checkout with custom-role support, make roles-pull (required)
# Param VERIFY_APPS: comma-separated roles the deploy runs, this role and the roles it needs (required for deploy)
# Param VERIFY_DISABLE: comma-separated core services the deploy disables, may be empty (required for deploy)
# Param VERIFY_VARIANT: variant round the deploy pins (required for deploy)
set -euo pipefail

action="${1:?usage: core.sh test|deploy}"
: "${INFINITO_CORE_DIR:?INFINITO_CORE_DIR must point at a core checkout with make roles-pull}"
case "${action}" in
test) ;;
deploy)
  : "${VERIFY_APPS:?VERIFY_APPS must list the roles to deploy}"
  : "${VERIFY_DISABLE?VERIFY_DISABLE must be set, empty disables nothing}"
  : "${VERIFY_VARIANT:?VERIFY_VARIANT must name the variant round}"
  ;;
*)
  echo "usage: core.sh test|deploy" >&2
  exit 2
  ;;
esac

role="web-app-cst-quality-check"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
core="$(cd "${INFINITO_CORE_DIR}" && pwd)"
declaration="$(mktemp -d)"
trap 'make -C "${core}" roles-clean; rm -rf "${declaration}"' EXIT

mkdir "${declaration}/group_vars"
printf 'all:\n  hosts:\n    localhost:\n' >"${declaration}/inventory.yml"
printf 'applications:\n  %s:\n    custom: true\n    source:\n      url: %s\n      path: ansible/roles/%s\n' \
  "${role}" "${repo}" "${role}" >"${declaration}/group_vars/all.yml"

export INFINITO_EXTRA_MOUNTS="${repo}"
make -C "${core}" roles-pull inventory="${declaration}/inventory.yml"

if [ "${action}" = test ]; then
  make -C "${core}" compose-up
  cores="$(lscpu --parse=Core | grep -v '^#' | sort -u | wc -l)"
  # Exception: core's `make test` runs four suites at once, each with pytest -n auto sized by the container's CPUs (4 x 20 workers on this host);
  # pinning the container to one CPU per physical core and running the suites one after another keeps threads at the core count (operator 2026-11-07)
  docker update --cpuset-cpus "0-$((cores - 1))" "$(cd "${core}" && docker compose ps -q infinito)"
  make -k -C "${core}" test-external test-integration test-lint test-unit
  exit
fi

extra="$(python3 -I "${repo}/service/verify/extra_vars.py" "${role}" "${repo}")"
INFINITO_INVENTORY_EXTRA_VARS="${extra}" \
  make -C "${core}" compose-deploy mode=initialize apps="${VERIFY_APPS}" disable="${VERIFY_DISABLE}" variant="${VERIFY_VARIANT}"
