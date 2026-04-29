#!/usr/bin/env bash
# Retry-wrapper for `vcpkg install` on Windows CI runners.
#
# vcpkg builds packages from source the first time they're requested,
# pulling build prerequisites (notably Strawberry Perl for openssl)
# from GitHub's CDN. Those downloads occasionally 502 — which
# kills the entire CI job because vcpkg's internal retry budget
# (3 attempts, ~3s apart) isn't enough for the typical CDN blip.
#
# This wrapper adds exponential-backoff retries on top of vcpkg's own
# retry logic, turning a transient flake into a delayed-but-successful
# build instead of a failed CI run.
#
# Single source of truth: every Windows workflow that does
# `vcpkg install` should call this script. Don't inline the retry
# loop — keeping it here means `MAX_ATTEMPTS` and the backoff schedule
# stay consistent across workflows.
#
# Usage:
#   bash "$GITHUB_WORKSPACE/scripts/vcpkg-install-with-retry.sh" openssl:x64-windows-static-md
set -euo pipefail

PORT="${1:?usage: vcpkg-install-with-retry.sh <port>}"
MAX_ATTEMPTS="${VCPKG_INSTALL_MAX_ATTEMPTS:-5}"

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  if vcpkg install "$PORT"; then
    exit 0
  fi

  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    echo "::error::vcpkg install $PORT failed after $MAX_ATTEMPTS attempts" >&2
    exit 1
  fi

  # Linear backoff: 10s, 20s, 30s, 40s. Total ceiling is 100s wait
  # spread across the 4 retry gaps, well under any reasonable CI
  # timeout.
  delay=$((10 * attempt))
  echo "::warning::vcpkg install $PORT attempt ${attempt}/${MAX_ATTEMPTS} failed; retrying in ${delay}s" >&2
  sleep "$delay"
done
