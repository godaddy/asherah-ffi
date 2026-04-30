using GoDaddy.Asherah;
using System.IO;
using System.Threading.Tasks;
using GoDaddy.Asherah.Encryption;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Empty-input pre-FFI validation on Decrypt*. Empty ciphertext cannot be
/// a valid DataRowRecord envelope (a real envelope is ~241+ bytes of
/// JSON), so we reject it at the C# boundary with a clear, actionable
/// error message instead of forwarding the Rust serde diagnostic
/// ("expected value at line 1 column 1") which doesn't tell the caller
/// what went wrong or how to fix it.
///
/// Null partition / null ciphertext continue to throw
/// <see cref="ArgumentNullException"/> per the established
/// <c>ArgumentNullException.ThrowIfNull</c> guards.
/// </summary>
public class DecryptEmptyInputTests : IDisposable
{
    static DecryptEmptyInputTests()
    {
        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
                ?? new string('2', 64));
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            var root = LocateRepoRoot();
            Environment.SetEnvironmentVariable(
                "ASHERAH_DOTNET_NATIVE", Path.Combine(root, "target", "debug"));
        }
    }

    private readonly AsherahFactory _factory;
    private readonly AsherahSession _session;

    public DecryptEmptyInputTests()
    {
        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("decrypt-empty-test-svc")
            .WithProductId("decrypt-empty-test-prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.Static)
            .Build();
        _factory = AsherahFactory.FromConfig(config);
        _session = _factory.GetSession("decrypt-empty-test-partition");
    }

    public void Dispose()
    {
        _session.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public void DecryptBytes_EmptyArray_ThrowsAsherahExceptionWithClearMessage()
    {
        var ex = Assert.Throws<AsherahException>(
            () => _session.DecryptBytes(Array.Empty<byte>()));
        // Caller reads the message; it must clearly say what's wrong.
        Assert.Contains("ciphertext is empty", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DataRowRecord", ex.Message);
        // Must NOT be the forwarded serde error.
        Assert.DoesNotContain("expected value at line 1 column 1", ex.Message);
    }

    [Fact]
    public void DecryptBytes_NullArray_ThrowsArgumentNullException()
    {
        // Null is a programming error per the input contract — distinct from
        // empty (which is a runtime data error). Different exception type
        // signals the difference.
        Assert.Throws<ArgumentNullException>(() => _session.DecryptBytes(null!));
    }

    [Fact]
    public void DecryptString_EmptyString_ThrowsAsherahExceptionWithClearMessage()
    {
        var ex = Assert.Throws<AsherahException>(
            () => _session.DecryptString(string.Empty));
        Assert.Contains("ciphertext is empty", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expected value at line 1 column 1", ex.Message);
    }

    [Fact]
    public void DecryptString_NullString_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _session.DecryptString(null!));
    }

    [Fact]
    public async Task DecryptBytesAsync_EmptyArray_FaultsTaskWithAsherahException()
    {
        // Async path surfaces the empty-input error as a faulted Task,
        // matching how the C ABI surfaces native errors via the async
        // callback. Null still throws synchronously — that's the
        // established C# convention.
        var ex = await Assert.ThrowsAsync<AsherahException>(
            () => _session.DecryptBytesAsync(Array.Empty<byte>()));
        Assert.Contains("ciphertext is empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecryptBytesAsync_NullArray_ThrowsArgumentNullExceptionSync()
    {
        // Async overload, but null input throws synchronously (not via Task)
        // for parity with ArgumentNullException.ThrowIfNull elsewhere.
        // Statement-lambda discards the Task<byte[]> return so xUnit
        // dispatches to the synchronous Assert.Throws overload.
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = _session.DecryptBytesAsync(null!);
        });
    }

    [Fact]
    public async Task DecryptStringAsync_EmptyString_ThrowsAsherahException()
    {
        var ex = await Assert.ThrowsAsync<AsherahException>(
            () => _session.DecryptStringAsync(string.Empty));
        Assert.Contains("ciphertext is empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DecryptStringAsync_NullString_FaultsTaskWithArgumentNullException()
    {
        // DecryptStringAsync is async-marked, so the null guard runs as
        // part of the state-machine prelude and surfaces as a faulted Task.
        // Spec-compliant per docs/input-contract.md: "null → ArgumentNullException
        // (sync) / rejected Task (async)" — either is acceptable.
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _session.DecryptStringAsync(null!));
    }

    [Fact]
    public void RoundTrip_NotAffectedByGuards()
    {
        // Sanity: real envelopes still decrypt. The empty-input guard must
        // not regress the happy path.
        var ciphertext = _session.EncryptString("decrypt-empty-test payload");
        Assert.Equal("decrypt-empty-test payload", _session.DecryptString(ciphertext));
    }

    private static string LocateRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            if (File.Exists(Path.Combine(dir, "Cargo.toml"))) return dir;
            dir = Path.GetDirectoryName(dir);
        }
        throw new InvalidOperationException("Could not locate repo root from " + AppContext.BaseDirectory);
    }
}
