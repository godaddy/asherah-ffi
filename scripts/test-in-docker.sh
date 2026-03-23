#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE_TAG="${TESTS_IMAGE_TAG:-asherah-tests:latest}"
USE_PREBUILT_IMAGE="${USE_PREBUILT_TEST_IMAGE:-0}"
CACHE_DIR="$ROOT_DIR/.cache"

mkdir -p \
  "$CACHE_DIR/cargo" \
  "$CACHE_DIR/pip" \
  "$CACHE_DIR/npm" \
  "$CACHE_DIR/maven" \
  "$CACHE_DIR/dotnet" \
  "$CACHE_DIR/bun"

COMMON_MOUNTS=(
  -v "$ROOT_DIR:/workspace"
  -w /workspace
  -v "$CACHE_DIR/cargo:/root/.cargo"
  -v "$CACHE_DIR/pip:/root/.cache/pip"
  -v "$CACHE_DIR/npm:/root/.npm"
  -v "$CACHE_DIR/maven:/root/.m2"
  -v "$CACHE_DIR/dotnet:/root/.nuget/packages"
  -v "$CACHE_DIR/bun:/root/.bun"
)

# Build the test.sh command line from environment variables
TEST_CMD="/workspace/scripts/test.sh --bindings"

if [ -n "${BINDING_TESTS_BINDING:-}" ]; then
  TEST_CMD="$TEST_CMD --binding=$BINDING_TESTS_BINDING"
fi

# Determine platform from DOCKER_PLATFORM (e.g., linux/arm64 → arm64)
PLATFORM_FLAG=""
if [ -n "${DOCKER_PLATFORM:-}" ]; then
  case "$DOCKER_PLATFORM" in
    */arm64|*/aarch64)  PLATFORM_FLAG="--platform=arm64" ;;
    */amd64|*/x86_64)   PLATFORM_FLAG="--platform=x64" ;;
  esac
fi
if [ -n "$PLATFORM_FLAG" ]; then
  TEST_CMD="$TEST_CMD $PLATFORM_FLAG"
fi

RUN_ENVS=()
if [ -n "${BINDING_ARTIFACTS_DIR:-}" ]; then
  BINDING_PATH="$BINDING_ARTIFACTS_DIR"
  if [[ "$BINDING_PATH" == "$ROOT_DIR"* ]]; then
    BINDING_PATH="/workspace${BINDING_PATH#"$ROOT_DIR"}"
  fi
  RUN_ENVS+=(-e "BINDING_ARTIFACTS_DIR=$BINDING_PATH")
fi

run_in_docker() {
  local platform_args=()
  if [ -n "${DOCKER_PLATFORM:-}" ]; then
    platform_args=(--platform "$DOCKER_PLATFORM")
  fi

  docker run --rm \
    --entrypoint "" \
    "${platform_args[@]}" \
    "${COMMON_MOUNTS[@]}" \
    "${RUN_ENVS[@]}" \
    "$IMAGE_TAG" \
    bash -c "$TEST_CMD"
}

if [ -n "${DOCKER_PLATFORM:-}" ] && [ "$USE_PREBUILT_IMAGE" != "1" ]; then
  docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --file "$ROOT_DIR/docker/tests.Dockerfile" \
    --tag "$IMAGE_TAG" \
    --load \
    "$ROOT_DIR"
elif [ "$USE_PREBUILT_IMAGE" != "1" ]; then
  docker build -f "$ROOT_DIR/docker/tests.Dockerfile" -t "$IMAGE_TAG" "$ROOT_DIR"
fi

run_in_docker
