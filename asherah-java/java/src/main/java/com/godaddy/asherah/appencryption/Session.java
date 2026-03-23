package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.appencryption.persistence.Persistence;

import java.util.Optional;
import java.util.UUID;

/**
 * A session for encrypting and decrypting data for a specific partition.
 * Compatible with the canonical godaddy/asherah Session interface.
 *
 * @param <P> the payload type (JSONObject or byte[])
 * @param <D> the data row record type (byte[] or JSONObject)
 */
public interface Session<P, D> extends AutoCloseable {

    P decrypt(D dataRowRecord);

    D encrypt(P payload);

    @Override
    void close();

    default Optional<P> load(final String persistenceKey, final Persistence<D> dataPersistence) {
        final Optional<D> dataRowRecord = dataPersistence.load(persistenceKey);
        return dataRowRecord.map(this::decrypt);
    }

    default String store(final P payload, final Persistence<D> dataPersistence) {
        final D dataRowRecord = encrypt(payload);
        final String key = dataPersistence.generateKey(dataRowRecord);
        dataPersistence.store(key, dataRowRecord);
        return key;
    }

    default void store(final String key, final P payload, final Persistence<D> dataPersistence) {
        final D dataRowRecord = encrypt(payload);
        dataPersistence.store(key, dataRowRecord);
    }
}
