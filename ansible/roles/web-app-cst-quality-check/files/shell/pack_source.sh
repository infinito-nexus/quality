#!/usr/bin/env bash
# Param url: git URL or local checkout the role came from (required)
# Param version: tag or commit to archive; empty archives the local checkout as it is (required)
# Param archive: .tar.gz file to write (required)
set -euo pipefail

url="$1"
version="$2"
archive="$3"

if [[ -z "${version}" ]]; then
  tar -C "${url}" --exclude=./.git --exclude=./.worktrees --exclude=./build --exclude=./.venv \
    --exclude=./.claude --exclude=./.mcp.json -czf "${archive}" .
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
export GIT_TERMINAL_PROMPT=0
git init --quiet --bare "${work}"
git --git-dir="${work}" fetch --quiet --depth 1 --no-tags -- "${url}" "${version}"
git --git-dir="${work}" archive --format=tar.gz --output="${archive}" FETCH_HEAD
