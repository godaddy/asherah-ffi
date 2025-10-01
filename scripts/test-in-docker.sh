#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE_TAG="asherah-tests:latest"
CACHE_DIR="$ROOT_DIR/.cache"

mkdir -p \
  "$CACHE_DIR/cargo" \
  "$CACHE_DIR/pip" \
  "$CACHE_DIR/npm" \
  "$CACHE_DIR/maven" \
  "$CACHE_DIR/dotnet"

COMMON_MOUNTS=(
  -v "$ROOT_DIR:/workspace"
  -w /workspace
  -v "$CACHE_DIR/cargo:/root/.cargo"
  -v "$CACHE_DIR/pip:/root/.cache/pip"
  -v "$CACHE_DIR/npm:/root/.npm"
  -v "$CACHE_DIR/maven:/root/.m2"
  -v "$CACHE_DIR/dotnet:/root/.nuget/packages"
)

RUN_SCRIPT="/workspace/scripts/run-tests.sh"
if [ -n "${BINDING_TESTS_ONLY:-}" ]; then
  RUN_SCRIPT="/workspace/scripts/run-binding-tests.sh"
fi

RUN_ENVS=()
if [ -n "${BINDING_ARTIFACTS_DIR:-}" ]; then
  BINDING_PATH="$BINDING_ARTIFACTS_DIR"
  if [[ "$BINDING_PATH" == "$ROOT_DIR"* ]]; then
    BINDING_PATH="/workspace${BINDING_PATH#"$ROOT_DIR"}"
  fi
  RUN_ENVS+=(-e "BINDING_ARTIFACTS_DIR=$BINDING_PATH")
fi

if [ -n "${BINDING_TESTS_ONLY:-}" ]; then
  RUN_ENVS+=(-e "BINDING_TESTS_ONLY=$BINDING_TESTS_ONLY")
fi

if [ -n "${DOCKER_PLATFORM:-}" ]; then
  docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --file "$ROOT_DIR/docker/tests.Dockerfile" \
    --tag "$IMAGE_TAG" \
    --load \
    "$ROOT_DIR"

  docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    "${COMMON_MOUNTS[@]}" \
    "${RUN_ENVS[@]}" \
    "$IMAGE_TAG" \
    "$RUN_SCRIPT"
else
  docker build -f "$ROOT_DIR/docker/tests.Dockerfile" -t "$IMAGE_TAG" "$ROOT_DIR"

  docker run --rm \
    "${COMMON_MOUNTS[@]}" \
    "${RUN_ENVS[@]}" \
    "$IMAGE_TAG" \
    "$RUN_SCRIPT"
fi
