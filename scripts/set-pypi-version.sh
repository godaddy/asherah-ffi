#!/bin/bash
# Set version in asherah-py/pyproject.toml and Cargo.toml for PyPI publishing.
# Used by both build-wheels and build-sdist jobs in publish-pypi.yml.
#
# Required env vars: PYPI_VERSION, PYPI_STABLE, PYPI_BETA
set -euo pipefail

: "${PYPI_VERSION:?PYPI_VERSION must be set}"
: "${PYPI_STABLE:?PYPI_STABLE must be set}"

echo "Publishing version: ${PYPI_VERSION}"
sed -i.bak 's/^version = ".*"/version = "'"${PYPI_VERSION}"'"/' asherah-py/pyproject.toml
rm -f asherah-py/pyproject.toml.bak

if [ "$PYPI_STABLE" = "true" ]; then
  sed -i.bak 's/^version = ".*"/version = "'"${PYPI_VERSION}"'"/' asherah-py/Cargo.toml
else
  : "${PYPI_BETA:?PYPI_BETA must be set for non-stable builds}"
  sed -i.bak 's/^version = ".*"/version = "0.5.0-beta.'"${PYPI_BETA}"'"/' asherah-py/Cargo.toml
fi
rm -f asherah-py/Cargo.toml.bak
