#!/usr/bin/env bash
# Frees ~15 GB on a hosted ubuntu-latest runner by removing toolchains
# this repository's heavy cargo jobs (lint, rust-tests, integration-tests,
# interop-tests) don't use. Their target/ + sccache + vendored
# OpenSSL/aws-lc-sys outputs would otherwise crowd the 14 GB free space
# on a stock runner.
#
# Conservative on purpose: only removes large preinstalled SDKs that none
# of the cargo-only jobs need. Leaves /usr/share/dotnet, /opt/hostedtoolcache,
# and language runtimes intact so this script is safe to drop into any job.
#
# Failure to delete any individual path is non-fatal.
set -uo pipefail

before=$(df --output=avail -B1G / | tail -1 | tr -d ' ')

# Largest items that no cargo-only job needs.
sudo rm -rf /usr/local/lib/android      || true   # ~12 GB Android SDK + NDK
sudo rm -rf /opt/ghc                    || true   # ~5 GB Haskell GHC
sudo rm -rf /usr/local/share/boost      || true   # Boost C++ headers/libs
sudo rm -rf /usr/share/swift            || true   # Swift toolchain
sudo rm -rf /opt/google                 || true   # Chrome
sudo rm -rf /opt/microsoft              || true   # Edge, msodbc

sudo apt-get autoremove -y >/dev/null 2>&1 || true
sudo apt-get clean         >/dev/null 2>&1 || true

after=$(df --output=avail -B1G / | tail -1 | tr -d ' ')
echo "Freed disk: ${before} GB → ${after} GB available on /"
