#!/usr/bin/env bash
# Retry a command with linear backoff. Used by the publish workflows to absorb
# transient registry/network failures (npm/nuget/maven/crates pushes, GitHub
# release upload/download). Mirrors the inline retry loops already used in
# publish-pypi.yml (twine) and publish-maven.yml (keyserver verify).
#
# Usage:
#   scripts/retry.sh <max_attempts> <base_delay_secs> -- <command> [args...]
#
# Backoff is linear: the delay before attempt N is (base_delay_secs * (N-1)).
#
# Optional env:
#   RETRY_SUCCESS_REGEX - extended regex (grep -E, case-insensitive). If the
#       command exits non-zero but its combined stdout+stderr matches this
#       regex, the failure is treated as success. Use for idempotent
#       re-publishes, e.g. "already (been )?(pushed|exists)|already uploaded".
set -uo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: retry.sh <max_attempts> <base_delay_secs> -- <command...>" >&2
  exit 2
fi

max_attempts="$1"
shift
base_delay="$1"
shift
if [ "$1" != "--" ]; then
  echo "retry.sh: expected '--' separator before the command" >&2
  exit 2
fi
shift

attempt=1
while :; do
  echo "retry.sh: attempt ${attempt}/${max_attempts}: $*"
  out_file="$(mktemp)"
  # tee so output still streams to the job log; PIPESTATUS captures the
  # command's exit code (not tee's).
  "$@" 2>&1 | tee "$out_file"
  rc=${PIPESTATUS[0]}

  if [ "$rc" -eq 0 ]; then
    rm -f "$out_file"
    exit 0
  fi

  if [ -n "${RETRY_SUCCESS_REGEX:-}" ] && grep -qiE "$RETRY_SUCCESS_REGEX" "$out_file"; then
    echo "retry.sh: command exited ${rc} but output matched RETRY_SUCCESS_REGEX; treating as success." >&2
    rm -f "$out_file"
    exit 0
  fi
  rm -f "$out_file"

  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "::error::retry.sh: command failed after ${max_attempts} attempts (rc=${rc}): $*" >&2
    exit "$rc"
  fi

  delay=$(( base_delay * attempt ))
  echo "retry.sh: command exited ${rc}; retrying in ${delay}s..." >&2
  sleep "$delay"
  attempt=$(( attempt + 1 ))
done
