package com.godaddy.asherah.appencryption.persistence;

import java.util.Optional;
import java.util.UUID;

/**
 * Abstract persistence layer for storing and loading encrypted data row records.
 * Compatible with the canonical godaddy/asherah Persistence interface.
 *
 * @param <T> the type of data being persisted
 */
public abstract class Persistence<T> {

    public abstract Optional<T> load(String key);

    public abstract void store(String key, T value);

    public String store(final T value) {
        final String key = generateKey(value);
        store(key, value);
        return key;
    }

    @SuppressWarnings("unused") // value available for subclass overrides to generate content-based keys
    public String generateKey(final T value) {
        return UUID.randomUUID().toString();
    }
}
