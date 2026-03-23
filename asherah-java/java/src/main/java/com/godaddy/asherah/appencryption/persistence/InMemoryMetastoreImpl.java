package com.godaddy.asherah.appencryption.persistence;

import com.godaddy.asherah.jni.AsherahConfig;
import org.json.JSONObject;

import java.time.Instant;
import java.util.Optional;

/**
 * In-memory metastore marker. Actual storage is handled by the native Rust layer.
 * Exists for API compatibility with the canonical godaddy/asherah SDK.
 */
public class InMemoryMetastoreImpl<T> implements Metastore<T> {

    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.metastore("memory");
    }

    @Override
    public Optional<T> load(final String keyId, final Instant created) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public Optional<T> loadLatest(final String keyId) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public boolean store(final String keyId, final Instant created, final T value) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }
}
