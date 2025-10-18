# Publishing Guide

## Node.js Package (asherah-node)

### Prerequisites
- Add `NPM_TOKEN` secret to repository settings (Settings → Secrets → Actions)
- Obtain token from https://www.npmjs.com/settings/[username]/tokens

### Publishing Process

#### Automatic (on release)
1. Create a git tag: `git tag v4.0.0`
2. Push tag: `git push origin v4.0.0`
3. Create GitHub release from tag
4. Workflow automatically builds for all platforms and publishes to npm

#### Manual
1. Go to Actions → "Publish to npm"
2. Click "Run workflow"
3. Optional: Enter specific tag (e.g., v4.0.0)
4. Optional: Enable "Dry run" to test without publishing
5. Click "Run workflow"

### Supported Platforms
- Linux x64 (glibc)
- Linux ARM64 (glibc)
- macOS x64 (Intel)
- macOS ARM64 (Apple Silicon)
- Windows x64 (MSVC)

### Dry Run Testing
To verify builds without publishing:
```bash
gh workflow run publish-npm.yml -f dry_run=true
```

This creates platform bindings and packages them but skips `npm publish`.

## Python Package (asherah-python)

Coming soon

## .NET Package (Asherah.NET)

Coming soon

## Java Package (asherah-java)

Coming soon
