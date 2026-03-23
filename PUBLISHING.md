# Publishing Guide

## Node.js Package (asherah-node)

### Prerequisites
- Add `NPM_TOKEN` secret to repository settings (Settings → Secrets → Actions)
- Obtain token from https://www.npmjs.com/settings/[username]/tokens

### Publishing Process

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
