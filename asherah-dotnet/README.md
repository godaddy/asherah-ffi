# Asherah .NET

.NET bindings for the Asherah envelope encryption and key rotation library.

Published to GitHub Packages (NuGet) with prebuilt native libraries for
Linux (x64/arm64), macOS (x64/arm64), and Windows (x64/arm64).

## Features

- Envelope encryption with automatic key rotation
- Drop-in compatible API with the original GoDaddy Asherah .NET SDK
- `SessionFactory` builder pattern with `WithInMemoryMetastore()`, `WithStaticKeyManagementService()`, etc.
- `Session<TP, TD>` generics for typed encrypt/decrypt
- Async encrypt/decrypt support
- Targets .NET 8.0 and .NET 10.0

## Quick Start

```csharp
using GoDaddy.Asherah.AppEncryption;

var factory = SessionFactory.NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithNeverExpiredCryptoPolicy()
    .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
    .Build();

using var session = factory.GetSessionBytes("partition");
byte[] encrypted = session.Encrypt(Encoding.UTF8.GetBytes("hello"));
byte[] decrypted = session.Decrypt(encrypted);
```

## Building

```bash
dotnet build asherah-dotnet/AsherahDotNet/
dotnet test asherah-dotnet/tests/AsherahDotNet.Tests/
```
