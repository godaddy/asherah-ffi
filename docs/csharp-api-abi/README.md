# C# Public API/ABI Inventory (AppEncryption + Crypto)

This directory captures the public API/ABI surface comparison between:
- Upstream GoDaddy Asherah C# (`csharp/AppEncryption` and `csharp/Crypto`).
- The FFI-based `GoDaddy.Asherah.AppEncryption` assembly produced in this repo.

## Inputs
- Upstream build (net8.0) published to `/tmp/publish-upstream-appencryption`.
- Local FFI build (net8.0) published to `/tmp/publish-ffi`.

## Outputs
- `docs/csharp-api-abi/upstream-app-crypto.txt`: flattened public API for upstream AppEncryption + Crypto.
- `docs/csharp-api-abi/dotnet-ffi.txt`: flattened public API for the FFI assembly (Cobhan uses the same source set).
- `docs/csharp-api-abi/api-diff.txt`: empty diff (no differences).

## Notes
- The upstream AppEncryption build required a temporary SecureMemory package reference during the analysis.
- SecureMemory APIs remain provided by the `GoDaddy.Asherah.SecureMemory` NuGet dependency (v0.5.0).
