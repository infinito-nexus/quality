#!/usr/bin/env bash
# Param $1: core checkout whose last non-merge commits are replayed; it is only read (required)
# Param $2: quality binary to time (required)
# Param BENCH_COMMITS: commits to replay; 43 when unset, the sample size of the Speed criterion in requirement 001
# Param BENCH_LIMIT_MS: milliseconds the p90 must stay under; 1000 when unset, the 1 s bound of that criterion
# Outputs:
#   per commit its id, the seconds of quality check --staged and that run's exit code,
#   then the p90 line ending in pass or fail
# Exit codes:
#   0  p90 under the limit
#   1  p90 at or over the limit
#   2  usage error, too few commits, or a quality run exiting neither 0 nor 1
set -euo pipefail

fail() {
  echo "bench.sh: $*" >&2
  exit 2
}

seconds() {
  printf '%d.%03d' "$(($1 / 1000000))" "$(($1 / 1000 % 1000))"
}

[[ $# -ge 1 ]] || fail "missing argument 1: the core checkout"
[[ $# -ge 2 ]] || fail "missing argument 2: the quality binary"
[[ $# -eq 2 ]] || fail "expected 2 arguments, got $#"
[[ -f "${2}" && -x "${2}" ]] || fail "argument 2: no executable file at ${2}"
[[ -n "${EPOCHREALTIME:-}" ]] || fail "needs bash 5 or later for EPOCHREALTIME"

commits=43
limit_ms=1000
if [[ -n "${BENCH_COMMITS:-}" ]]; then
  commits="${BENCH_COMMITS}"
fi
if [[ -n "${BENCH_LIMIT_MS:-}" ]]; then
  limit_ms="${BENCH_LIMIT_MS}"
fi
[[ "${commits}" =~ ^[1-9][0-9]*$ ]] || fail "BENCH_COMMITS must be a positive integer, got ${commits}"
[[ "${limit_ms}" =~ ^[1-9][0-9]*$ ]] || fail "BENCH_LIMIT_MS must be a positive integer, got ${limit_ms}"

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null

quality="$(realpath -- "${2}")"
core="$(git -C "${1}" rev-parse --show-toplevel)" || fail "argument 1: no git checkout at ${1}"
common="$(git -C "${core}" rev-parse --path-format=absolute --git-common-dir)"
listed="$(git -C "${core}" rev-list --no-merges --min-parents=1 --max-count="${commits}" HEAD)" ||
  fail "argument 1: no history at ${core}"
mapfile -t shas <<<"${listed}"
if [[ -z "${listed}" || "${#shas[@]}" -lt "${commits}" ]]; then
  fail "argument 1: ${core} has fewer than ${commits} non-merge commits with a parent"
fi

scratch="$(mktemp -d -t quality-bench.XXXXXXXX)"
trap 'rm -rf -- "${scratch}"' EXIT
trap 'exit 130' HUP INT TERM
git clone --quiet --shared --no-checkout -- "${common}" "${scratch}/repo"
cd "${scratch}/repo"

durations=()
for sha in "${shas[@]}"; do
  git checkout --quiet --force --detach "${sha}^"
  git read-tree -m -u "${sha}^" "${sha}"
  status=0
  start="${EPOCHREALTIME/[.,]/}"
  "${quality}" check --staged >"${scratch}/output" 2>&1 || status=$?
  end="${EPOCHREALTIME/[.,]/}"
  if ((status > 1)); then
    cat -- "${scratch}/output" >&2
    fail "quality exited ${status} on ${sha}"
  fi
  durations+=("$((end - start))")
  printf '%s %ss exit %d\n' "${sha}" "$(seconds "$((end - start))")" "${status}"
done

mapfile -t sorted < <(printf '%s\n' "${durations[@]}" | sort -n)
p90="${sorted[(9 * commits + 9) / 10 - 1]}"
limit=$((limit_ms * 1000))
if ((p90 < limit)); then verdict=pass; else verdict=fail; fi
printf 'p90 %ss over %d commits, limit %ss: %s\n' "$(seconds "${p90}")" "${commits}" "$(seconds "${limit}")" "${verdict}"
[[ "${verdict}" == pass ]] || exit 1
