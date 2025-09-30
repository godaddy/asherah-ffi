#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE_TAG="asherah-tests:latest"

if [ -n "${DOCKER_PLATFORM:-}" ]; then
  docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --file "$ROOT_DIR/docker/tests.Dockerfile" \
    --tag "$IMAGE_TAG" \
    --load \
    "$ROOT_DIR"

  docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$IMAGE_TAG" \
    /workspace/scripts/run-tests.sh
else
  docker build -f "$ROOT_DIR/docker/tests.Dockerfile" -t "$IMAGE_TAG" "$ROOT_DIR"

  docker run --rm \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$IMAGE_TAG" \
    /workspace/scripts/run-tests.sh
fi
