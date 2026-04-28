# Publishing Guide

All publish workflows are triggered automatically on GitHub Release creation, or can be run manually via Actions → workflow_dispatch.

## Native Libraries (release-cobhan)

Builds `asherah-ffi` and `asherah-java` shared libraries for Linux, macOS, and Windows (x64 + arm64). Uploads artifacts to the GitHub Release. Downstream workflows (RubyGems, NuGet, Maven) trigger automatically when this completes.

## Node.js (publish-npm)

### Prerequisites

- `NPM_TOKEN` secret in repository settings
- `NPM_VERSION` or `NPM_BETA_VERSION` repository variable

### Manual trigger

Actions → "Publish to npm" → Run workflow. Optional: enter tag, enable dry run.

Builds native bindings for 8 platform targets via napi-rs and publishes platform-specific + main packages to npm.

## Python (publish-pypi)

### Prerequisites

- `PYPI_TOKEN` secret in repository settings
- `PYPI_VERSION` or `PYPI_BETA_VERSION` repository variable

### Manual trigger

Actions → "Publish to PyPI" → Run workflow. Optional: enter tag, enable dry run.

Builds wheels for 7 targets (manylinux, musllinux, macOS universal2, Windows) via maturin and publishes to PyPI.

## .NET (publish-nuget)

### Prerequisites

- Repository secret `NUGET_TOKEN` (NuGet.org API key with push scope for the packages)

### Trigger

Automatic via `workflow_run` after "Release Asherah Native Library" completes. Downloads pre-built native libraries from the release and packs a NuGet package with all platform runtimes.

## Java (publish-maven)

### Prerequisites

- Uses `GITHUB_TOKEN` (automatic) for GitHub Packages

### Trigger

Automatic via `workflow_run` after "Release Asherah Native Library" completes. Downloads pre-built JNI libraries from the release and builds a JAR with native libraries bundled.

## Ruby (publish-rubygems)

### Prerequisites

- `RUBYGEMS_API_KEY` secret in repository settings

### Trigger

Automatic via `workflow_run` after "Release Asherah Native Library" completes. Downloads pre-built native libraries from the release and builds platform-specific gems for Linux and macOS.