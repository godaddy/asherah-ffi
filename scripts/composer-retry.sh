#!/usr/bin/env bash
set -euo pipefail

attempts="${COMPOSER_RETRY_ATTEMPTS:-3}"
delay_seconds="${COMPOSER_RETRY_DELAY_SECONDS:-10}"
attempt=1

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
