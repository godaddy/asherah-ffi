# asherah-py

`asherah-py` provides Python bindings for the Asherah AppEncryption runtime via
`pyo3`. The crate builds a Python extension module that is distributed with
`maturin` alongside the Python package in this repository.

## Highlights

- Mirrors the Go and Node APIs for session lifecycle, caching, and encryption.
- Uses `asherah-config` for consistent structured configuration parsing.
- Ships abi3 wheels targeting Python 3.8+.

## Building

Install `maturin` and run `maturin develop` or use the provided `Makefile` in
`asherah-py/` to produce distributable wheels.

## License

Licensed under the Apache License, Version 2.0.
