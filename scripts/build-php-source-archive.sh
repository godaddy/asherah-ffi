#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/tmp/asherah-php-dist}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

composer install --prefer-dist --no-progress
composer validate --strict
composer archive --format=zip --dir="$OUT_DIR" >/dev/null

ARCHIVE="$(find "$OUT_DIR" -maxdepth 1 -type f -name '*.zip' | head -n 1)"
if [ -z "$ARCHIVE" ]; then
    echo "ERROR: composer archive did not produce a zip" >&2
    exit 1
fi

unzip -l "$ARCHIVE" | tee "$OUT_DIR/archive.txt"
! grep -E " vendor/| native/| composer.lock" "$OUT_DIR/archive.txt"
grep -q "src/Asherah.php" "$OUT_DIR/archive.txt"

printf '%s\n' "$ARCHIVE"
