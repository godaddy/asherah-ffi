# End-to-End Tests

Smoke tests that verify published packages work correctly when installed from
their respective registries (npm, PyPI).

## Structure

- `npm/` — Installs `asherah` from npm and runs encrypt/decrypt roundtrips
- `pypi/` — Installs `asherah` from PyPI and runs encrypt/decrypt roundtrips

## Running

```bash
# Via the test runner
scripts/test.sh --e2e

# Manually
cd e2e/npm && npm install && node test.js
cd e2e/pypi && pip install asherah && python test_asherah.py
```

These tests require the packages to be published first. They are not part of
the normal CI test suite.
