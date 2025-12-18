# C# FFI/Cobhan Acceptance Evidence

## SQL Server integration (plaintext test workaround)
- Rust metastore (feature-gated):
  - `MSSQL_URL='Server=127.0.0.1,1433;User ID=sa;Password=YourStrong!Passw0rd;Database=master;Encrypt=DANGER_PLAINTEXT;TrustServerCertificate=true' \
     cargo test -p asherah --features mssql --test metastore_mssql`
- C# FFI tests (shared SQL Server integration test runs via `MSSQL_URL`):
  - `MSSQL_URL='Server=127.0.0.1,1433;User ID=sa;Password=YourStrong!Passw0rd;Database=master;Encrypt=DANGER_PLAINTEXT;TrustServerCertificate=true' \
     dotnet test asherah-dotnet-ffi/tests/AsherahDotNetFfi.Tests/AsherahDotNetFfi.Tests.csproj --nologo`
- C# Cobhan tests (shared SQL Server integration test runs via `MSSQL_URL`):
  - `MSSQL_URL='Server=127.0.0.1,1433;User ID=sa;Password=YourStrong!Passw0rd;Database=master;Encrypt=DANGER_PLAINTEXT;TrustServerCertificate=true' \
     dotnet test asherah-dotnet-cobhan/tests/AsherahDotNetCobhan.Tests/AsherahDotNetCobhan.Tests.csproj --nologo`

## Cross-language DRR JSON compatibility
- `python3 -m pytest interop/tests`

## Full binding regression (no MSSQL)
- `DOTNET_ROOT=/opt/homebrew/opt/dotnet@8/libexec PATH=/opt/homebrew/opt/dotnet@8/bin:$PATH ./scripts/run-tests.sh`
  - Note: dotnet 10 is present on this host; setting `DOTNET_ROOT`/`PATH` to the Homebrew `dotnet@8` install ensures the net8.0 tests locate the correct runtime.

## API/ABI inventory
- `docs/csharp-api-abi/upstream-app-crypto.txt`
- `docs/csharp-api-abi/dotnet-ffi.txt`
- `docs/csharp-api-abi/api-diff.txt` (no differences)

## Results
- SQL Server integration tests: pass with `Encrypt=DANGER_PLAINTEXT` local-only connection string.
- Cross-language DRR JSON tests: pass.
- Full binding regression script: pass.
