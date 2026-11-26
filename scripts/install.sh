#!/usr/bin/env bash
# Param $1: the step, skills or python (required)
# Param HOME: absolute home every path below lies in (required)
# Outputs:
#   skills: mirrors every skills/kvb-quality-*/ folder of this checkout into ~/.claude/skills,
#   ~/.agents/skills and, only when ~/.codex exists, ~/.codex/skills; an installed folder equal
#   to its source stays untouched, and an installed kvb-quality-* folder without a source is removed
#   python: installs this checkout with pip install --no-deps into ~/.local/share/kvb-quality/venv
#   and writes ~/.local/bin/kvb-quality-python, which execs that venv's interpreter
# Exit codes:
#   0  installed
#   2  usage error, or no skills/kvb-quality-*/ folder to install
#   other  the code of the copy, venv or pip command that failed
set -euo pipefail

fail() {
  echo "install.sh: $*" >&2
  exit 2
}

[[ $# -eq 1 ]] || fail "expected 1 argument, the step skills or python, got $#"
[[ "${HOME:-}" == /* ]] || fail "HOME must be an absolute path, got '${HOME:-}'"

repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
prefix="kvb-quality-"
venv="${HOME}/.local/share/kvb-quality/venv"
launcher="${HOME}/.local/bin/kvb-quality-python"
staging=""
trap 'if [[ -n "${staging}" ]]; then rm -rf -- "${staging}"; fi' EXIT
shopt -s nullglob

# Param $1: directory to list, its bytecode caches left out
listing() {
  (cd -- "$1" && find . \( -name __pycache__ -o -name '*.py[co]' \) -prune -o -printf '%P\t%y\t%m\n' | LC_ALL=C sort)
}

# Param $1: source folder of a skill
# Param $2: installed folder of that skill, which may be missing
same() {
  [[ -d "$2" && ! -L "$2" ]] || return 1
  diff -r --no-dereference -q -x __pycache__ -x '*.py[co]' -- "$1" "$2" >/dev/null 2>&1 || return 1
  [[ "$(listing "$1")" == "$(listing "$2")" ]]
}

# Param $1: install root such as ~/.claude/skills
mirror() {
  local target="$1" installed source name
  mkdir -p -- "${target}"
  for installed in "${target}/${prefix}"*; do
    name="${installed##*/}"
    if [[ ! -d "${repo}/skills/${name}" ]]; then
      rm -rf -- "${installed}"
      echo "install.sh: removed ${installed}"
    fi
  done
  for source in "${repo}/skills/${prefix}"*/; do
    source="${source%/}"
    name="${source##*/}"
    if same "${source}" "${target}/${name}"; then
      continue
    fi
    staging="$(mktemp -d "${target}/.${name}.XXXXXXXX")"
    cp -a -- "${source}/." "${staging}/"
    find "${staging}" \( -name __pycache__ -o -name '*.py[co]' \) -prune -exec rm -rf -- {} +
    chmod --reference="${source}" -- "${staging}"
    rm -rf -- "${target:?}/${name}"
    mv -T -- "${staging}" "${target}/${name}"
    staging=""
    echo "install.sh: installed ${target}/${name}"
  done
}

install_skills() {
  local sources=("${repo}/skills/${prefix}"*/)
  ((${#sources[@]} > 0)) || fail "no skills/${prefix}*/ folder in ${repo}"
  mirror "${HOME}/.claude/skills"
  mirror "${HOME}/.agents/skills"
  if [[ -d "${HOME}/.codex" ]]; then
    mirror "${HOME}/.codex/skills"
  fi
}

install_python() {
  local content
  [[ "${venv}" != *\'* ]] || fail "HOME must not hold a single quote, got '${HOME}'"
  if ! "${venv}/bin/python" -c '' 2>/dev/null; then
    python3 -m venv --clear "${venv}"
  fi
  "${venv}/bin/python" -m pip install --no-deps --no-input --disable-pip-version-check "${repo}"
  content="#!/bin/sh
exec '${venv}/bin/python' \"\$@\""
  mkdir -p -- "${launcher%/*}"
  if [[ -L "${launcher}" || ! -f "${launcher}" || "$(<"${launcher}")" != "${content}" ]]; then
    staging="$(mktemp "${launcher}.XXXXXXXX")"
    printf '%s\n' "${content}" >"${staging}"
    chmod 0755 -- "${staging}"
    mv -fT -- "${staging}" "${launcher}"
    staging=""
    echo "install.sh: wrote ${launcher}"
  fi
}

case "$1" in
  skills) install_skills ;;
  python) install_python ;;
  *) fail "unknown step '$1', expected skills or python" ;;
esac
