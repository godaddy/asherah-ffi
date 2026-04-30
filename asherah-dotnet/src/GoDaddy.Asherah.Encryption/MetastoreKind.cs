using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed metastore selector for
/// <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithMetastore(MetastoreKind)"/>.
///
/// Each value maps 1:1 to a wire string accepted by the native Rust core.
/// </summary>
public enum MetastoreKind
{
    /// <summary>In-process volatile metastore. Wire value: <c>"memory"</c>. Testing only — keys do not survive process restart.</summary>
    Memory,
    /// <summary>SQL metastore (MySQL or PostgreSQL via <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithConnectionString(System.String)"/>). Wire value: <c>"rdbms"</c>.</summary>
    Rdbms,
    /// <summary>AWS DynamoDB metastore. Wire value: <c>"dynamodb"</c>.</summary>
    DynamoDb,
    /// <summary>Embedded SQLite metastore. Wire value: <c>"sqlite"</c>.</summary>
    Sqlite,
}

internal static class MetastoreKindExtensions
{
    internal static string ToWireString(this MetastoreKind kind) => kind switch
    {
        MetastoreKind.Memory => "memory",
        MetastoreKind.Rdbms => "rdbms",
        MetastoreKind.DynamoDb => "dynamodb",
        MetastoreKind.Sqlite => "sqlite",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown MetastoreKind"),
    };
}
