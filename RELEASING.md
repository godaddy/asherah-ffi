# Releasing

Releases are fully automated. Creating a GitHub Release triggers all build and
publish workflows.

## How to Release

1. Ensure all PRs are merged and CI passes on `main`.
2. Create a [GitHub Release](https://github.com/godaddy/asherah-ffi/releases/new):
   - Tag: `v0.6.86` (increment from latest release)
   - Target: `main`
   - Title: same as tag
   - Click "Publish release"

Or via CLI:
```bash
gh release create v0.6.86 --target main --generate-notes
```

## What Happens Automatically

Creating a release triggers two waves of workflows:

### Wave 1 (triggered by `release: published`)

Each workflow waits up to 20 minutes for CI (`lint`, `rust-tests`,
`integration-tests`) to pass before building.

| Workflow | Publishes to |
|----------|-------------|
| `release-cobhan` | Native libraries uploaded to the GitHub Release |
| `publish-npm` | [npmjs.com](https://www.npmjs.com/package/asherah) |
| `publish-pypi` | [pypi.org](https://pypi.org/project/asherah) |
| `publish-server` | [GHCR](https://github.com/godaddy/asherah-ffi/pkgs/container/asherah-server) |

### Wave 2 (triggered by `release-cobhan` completion)

These download pre-built native libraries from the release, package them, and
publish:

| Workflow | Publishes to |
|----------|-------------|
| `publish-nuget` | [nuget.org](https://www.nuget.org/packages/GoDaddy.Asherah.Encryption) (`NUGET_TOKEN` secret) |
| `publish-maven` | [GitHub Packages (Maven)](https://github.com/godaddy/asherah-ffi/packages) |
| `publish-rubygems` | [GitHub Packages (RubyGems)](https://github.com/godaddy/asherah-ffi/packages) |

## Version Numbers

Versions are managed by repository variables, not by in-repo manifest files.
The publish workflows read these variables and auto-increment the patch version
after each successful publish.

| Package | Version source | Variable |
|---------|---------------|----------|
| npm | Repo variable | `NPM_VERSION` |
| PyPI | Repo variable | `PYPI_VERSION` |
| NuGet | Repo variable | `NUGET_VERSION` |
| RubyGems | Repo variable | `RUBYGEMS_VERSION` |
| Maven | Release tag (`v0.6.86` → `0.6.86`) | n/a |
| Server | Release tag | n/a |
| Cobhan | Release tag | n/a |

In-repo versions (`Cargo.toml`, `pom.xml`, `package.json`, etc.) are
placeholders used only for local development builds.

## Verifying a Release

Check that all 7 publish workflows succeeded:

```bash
gh run list --limit 10 --json name,status,conclusion,headBranch \
  --jq '.[] | select(.headBranch | startswith("v")) | "\(.name)\t\(.conclusion)"'
```

## Re-running Failed Jobs

Wave 1 workflows can be re-run from the Actions tab or via CLI:
```bash
gh run rerun <run-id> --failed
```

Wave 2 workflows (NuGet, Maven, RubyGems) can be triggered manually:
```bash
gh workflow run publish-nuget.yml -f version=0.50.10
gh workflow run publish-maven.yml -f version=0.6.86
gh workflow run publish-rubygems.yml -f version=0.9.55
```
