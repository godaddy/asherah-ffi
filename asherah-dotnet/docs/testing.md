# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode specifically for
tests.

## In-memory + static-KMS test fixture

The simplest fixture for unit tests of code that wraps Asherah:

```csharp
using GoDaddy.Asherah.Encryption;

public class AsherahTestFixture : IDisposable
{
    public AsherahFactory Factory { get; }

    public AsherahTestFixture()
    {
        // Static KMS uses a hardcoded 32-byte master key from the env var.
        // Generate per-fixture if you want isolation between fixtures.
        Environment.SetEnvironmentVariable(
            "STATIC_MASTER_KEY_HEX", new string('2', 64));

        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore(MetastoreKind.Memory)  // no DB, no AWS
            .WithKms(KmsKind.Static)
            .Build();

        Factory = AsherahFactory.FromConfig(config);
    }

    public void Dispose() => Factory.Dispose();
}
```

Use as an `IClassFixture` to share one factory across tests in a class:

```csharp
public class CardRepositoryTests(AsherahTestFixture fx) : IClassFixture<AsherahTestFixture>
{
    [Fact]
    public void RoundTrips()
    {
        using var session = fx.Factory.GetSession("tenant-A");
        var ct = session.EncryptString("4242 4242 4242 4242");
        Assert.Equal("4242 4242 4242 4242", session.DecryptString(ct));
    }
}
```

Tests that exercise hooks should run serially — hooks are
process-global and parallel test harnesses race. xUnit:
`[Collection("AsherahHooks")]` on every hook test class.

## Mocking `IAsherahApi`

If your code injects `IAsherahApi` (the DI-friendly mirror of the
single-shot static API), mock it directly with NSubstitute / Moq /
your mock framework of choice:

```csharp
[Fact]
public void Repository_PassesPartitionId()
{
    var asherah = Substitute.For<IAsherahApi>();
    asherah.EncryptString("user-42", "secret").Returns("ct-token");

    var repo = new Repository(asherah);
    var result = repo.Protect("user-42", "secret");

    Assert.Equal("ct-token", result);
    asherah.Received(1).EncryptString("user-42", "secret");
}
```

`AsherahFactory` and `AsherahSession` are sealed concrete types — they
don't have parallel interfaces for direct mocking. For factory/session
code, prefer the in-memory fixture above (it's faster than mocking
through a fake factory anyway).

## Asserting envelope shape

`session.EncryptString(...)` returns a `DataRowRecord` JSON envelope.
For tests that need to assert on the wire shape (e.g. interop with a
non-.NET service), parse it directly:

```csharp
[Fact]
public void Envelope_HasExpectedShape()
{
    using var session = fx.Factory.GetSession("partition-1");
    var json = session.EncryptString("hello");

    using var doc = JsonDocument.Parse(json);
    var root = doc.RootElement;
    Assert.True(root.TryGetProperty("Key", out _));
    Assert.True(root.TryGetProperty("Data", out _));
    Assert.True(root.GetProperty("Key").TryGetProperty("ParentKeyMeta", out _));
}
```

The wire format is documented in
[`docs/input-contract.md`](../../docs/input-contract.md) and is
byte-for-byte compatible with canonical Asherah implementations.

## Testing empty-input handling

The `Decrypt*` overloads reject empty input at the C# boundary with
`AsherahException("decrypt: ciphertext is empty (expected a
DataRowRecord JSON envelope)")`. Tests that verify your wrapper
handles this gracefully:

```csharp
[Fact]
public void EmptyCiphertext_SurfacesAsherahException()
{
    using var session = fx.Factory.GetSession("p");
    var ex = Assert.Throws<AsherahException>(
        () => session.DecryptString(string.Empty));
    Assert.Contains("ciphertext is empty", ex.Message,
        StringComparison.OrdinalIgnoreCase);
}
```

## Testing with the SQL metastore

For integration tests against MySQL or Postgres, point at a
container-managed test database. Asherah's RDBMS metastore creates the
schema automatically on first use, so no migration is required.

```csharp
public class SqlMetastoreFixture : IAsyncLifetime
{
    private readonly MySqlContainer _container = new MySqlBuilder()
        .WithImage("mysql:8.0")
        .Build();

    public AsherahFactory Factory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        Environment.SetEnvironmentVariable(
            "STATIC_MASTER_KEY_HEX", new string('2', 64));

        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore(MetastoreKind.Rdbms)
            .WithConnectionString(_container.GetConnectionString())
            .WithKms(KmsKind.Static)
            .Build();

        Factory = AsherahFactory.FromConfig(config);
    }

    public async Task DisposeAsync()
    {
        Factory.Dispose();
        await _container.DisposeAsync();
    }
}
```

Uses [Testcontainers for .NET](https://dotnet.testcontainers.org/);
swap `MySqlBuilder` for `PostgreSqlBuilder` for Postgres integration
tests.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** A fresh nonce means
  the ciphertext is non-deterministic — `EncryptString("x")` produces
  a different envelope on every call. Don't write tests that compare
  ciphertext bytes; round-trip through `DecryptString` and compare
  plaintexts instead.
- **Session caching.** `factory.GetSession("p")` returns a cached
  session by default. Tests that assert per-call behaviour (e.g. a
  metastore call count) should disable caching with
  `WithEnableSessionCaching(false)`.
- **Hooks are process-global.** A test that registers a log hook will
  see records from other tests in the same process if they aren't
  serialized. Use `[Collection("AsherahHooks")]` and clear hooks in
  test teardown.

## Native library resolution in tests

The NuGet package ships native binaries under `runtimes/<rid>/native/`.
Tests run from `bin/Debug/<tfm>/` and the .NET runtime resolves the
binary automatically. If a test fails with "unable to load
asherah_ffi", set `ASHERAH_DOTNET_NATIVE` to an explicit directory:

```bash
export ASHERAH_DOTNET_NATIVE="$(pwd)/target/debug"
dotnet test
```

Locally during repository development, point this at your `cargo
build` output. In CI, ensure the publish step copies the native
binaries before `dotnet test` runs.
