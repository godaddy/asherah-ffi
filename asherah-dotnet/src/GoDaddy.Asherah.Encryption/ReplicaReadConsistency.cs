using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed Aurora MySQL read-replica consistency selector for
/// <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithReplicaReadConsistency(System.Nullable{ReplicaReadConsistency})"/>.
///
/// Applies only when the metastore is <see cref="MetastoreKind.Rdbms"/> and
/// the connection points at an Aurora MySQL cluster with read replicas.
/// Each value maps 1:1 to the wire string accepted by the Rust MySQL pool.
/// </summary>
public enum ReplicaReadConsistency
{
    /// <summary>Read from the nearest replica without consistency guarantees. Wire value: <c>"eventual"</c>.</summary>
    Eventual,
    /// <summary>Aurora session-level read consistency: replicas wait for the writer's recent commits. Wire value: <c>"global"</c>.</summary>
    Global,
    /// <summary>Aurora session-level read consistency for the current session. Wire value: <c>"session"</c>.</summary>
    Session,
}

internal static class ReplicaReadConsistencyExtensions
{
    internal static string ToWireString(this ReplicaReadConsistency value) => value switch
    {
        ReplicaReadConsistency.Eventual => "eventual",
        ReplicaReadConsistency.Global => "global",
        ReplicaReadConsistency.Session => "session",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown ReplicaReadConsistency"),
    };
}
