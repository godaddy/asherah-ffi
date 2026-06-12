#!/usr/bin/env bash
set -euo pipefail

attempts="${COMPOSER_RETRY_ATTEMPTS:-3}"
delay_seconds="${COMPOSER_RETRY_DELAY_SECONDS:-10}"
attempt=1

if command -v git >/dev/null 2>&1; then
    for dir in "$PWD" "${GITHUB_WORKSPACE:-}" /work; do
        if [ -n "$dir" ] && [ -d "$dir" ]; then
            git config --global --add safe.directory "$dir" 2>/dev/null || true
        fi
    done
fi

while true; do
    if composer "$@"; then
        exit 0
    else
        status=$?
    fi
    if [ "$attempt" -ge "$attempts" ]; then
        exit "$status"
    fi
    echo "composer command failed with status $status; retrying ($attempt/$attempts)..." >&2
    sleep "$delay_seconds"
    attempt=$((attempt + 1))
done
