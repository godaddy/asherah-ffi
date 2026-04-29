using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed metastore selector for
/// <see cref="AsherahConfig.Builder.WithMetastore(MetastoreKind)"/>.
///
/// Each value maps 1:1 to a wire string accepted by the native Rust core.
/// Use this enum overload in new code; the
/// <see cref="AsherahConfig.Builder.WithMetastore(string)"/> string overload
/// is retained for source-level compatibility.
/// </summary>
public enum MetastoreKind
{
    /// <summary>In-process volatile metastore. Wire value: <c>"memory"</c>. Testing only — keys do not survive process restart.</summary>
    Memory,
    /// <summary>SQL metastore (MySQL or PostgreSQL via <see cref="AsherahConfig.Builder.WithSqlMetastoreDbType(string?)"/>). Wire value: <c>"rdbms"</c>.</summary>
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
