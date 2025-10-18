# Publishing Guide

## Node.js Package (asherah-node)

### Prerequisites
- Add `NPM_TOKEN` secret to repository settings (Settings → Secrets → Actions)
- Obtain token from https://www.npmjs.com/settings/[username]/tokens

### Publishing Process

**Note:** The GitHub Actions publish workflow is currently blocked due to org billing issues. Use the local build method instead.

#### Local Build (Current Method)
```bash
# Build for your current platform
./scripts/build-npm-package.sh

# Test the package
cd asherah-node
node test/roundtrip.js

# Publish (requires npm login first)
npm publish --access public
```

**Supported platforms for local builds:**
- macOS ARM64 (Apple Silicon)
- macOS x64 (Intel)
- Linux x64 (glibc)
- Linux ARM64 (via cross-compilation with aarch64-linux-gnu tools)

**Note:** The current napi-rs configuration builds a single universal package (`npm = { default = true }`), not platform-specific packages. The output `index.node` contains the native binary for the current platform.

#### GitHub Actions (When Billing Resolved)
1. Go to Actions → "Publish to npm"
2. Click "Run workflow"
3. Optional: Enter specific tag (e.g., v4.0.0)
4. Optional: Enable "Dry run" to test without publishing
5. Click "Run workflow"

The workflow builds for all platforms and creates platform-specific npm packages.

## Python Package (asherah-python)

Coming soon

## .NET Package (Asherah.NET)

Coming soon

## Java Package (asherah-java)

Coming soon
