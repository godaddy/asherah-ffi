# Contributing

Thank you for your interest in improving the Asherah ecosystem. This repository
contains the Rust core, native FFI wrapper, and language bindings used across
multiple runtimes. The following guidelines keep contributions consistent and
easy to review.

## Getting Started

- Install the Rust toolchain (Rust 1.75+ recommended) and enable the `rustfmt`
  and `clippy` components.
- Install language toolchains required for the bindings you plan to touch:
  Node 18+, Python 3.9+, Go 1.21+, Ruby 3.1+, .NET 8, and Java 17.
- Ensure Docker is available if you plan to use the full matrix test harness
  located in `scripts/test-in-docker.sh`.

## Development Workflow

1. Create a feature branch from `main`.
2. Make focused commits with clear messages describing the change and why it is
   needed.
3. Keep changes minimal—avoid sweeping refactors unless they are required to
   fix a bug or implement a feature.

## Formatting & Linting

- Run `cargo fmt` and `cargo clippy --all-targets --all-features` inside the
  `asherah/` crate when modifying Rust sources.
- Use the repository `.editorconfig` settings to align editors across the
  different languages.
- Apply language-specific formatters where available (`go fmt`, `npm run lint`,
  `black`, `rubocop`, etc.) when updating those bindings.

## Testing

Run the tests that correspond to the areas you changed before opening a pull
request.

- Core crates: `cargo test` (workspace root) and `cd asherah && cargo test`.
- Feature adapters: enable the relevant feature flag, e.g.
  `cargo test --features sqlite`.
- Language bindings: follow the commands in `README.md` (e.g. `npm test`,
  `python -m pytest`, `dotnet test`).
- Full matrix: `./scripts/test-in-docker.sh` for an end-to-end validation.

Please include notes about which test suites you exercised in your pull
request description.

## Pull Request Checklist

- [ ] All code compiles and tests pass for the components you touched.
- [ ] Formatting and linting tools have been executed.
- [ ] Documentation is updated when behavior or configuration changes.
- [ ] Sensitive data is not logged or committed.

We appreciate your contributions! If you are unsure about an approach, feel
free to open a draft pull request or start a discussion in issues before
investing significant effort.
