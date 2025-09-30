#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE_TAG="asherah-tests:latest"

docker build -f "$ROOT_DIR/docker/tests.Dockerfile" -t "$IMAGE_TAG" "$ROOT_DIR"

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -w /workspace \
  "$IMAGE_TAG" \
  /workspace/scripts/run-tests.sh
