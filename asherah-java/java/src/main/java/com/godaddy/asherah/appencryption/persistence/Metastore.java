package com.godaddy.asherah.appencryption.persistence;

import java.time.Instant;
import java.util.Optional;

/**
 * Interface for key metastore implementations.
 * Compatible with the canonical godaddy/asherah Metastore interface.
 * In the FFI binding, actual metastore operations are handled by the native Rust layer.
 *
 * @param <V> the value type stored in the metastore
 */
public interface Metastore<V> {

    Optional<V> load(String keyId, Instant created);

    Optional<V> loadLatest(String keyId);

    boolean store(String keyId, Instant created, V value);

    default String getKeySuffix() {
        return "";
    }
}
