package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.appencryption.kms.AwsKeyManagementServiceImpl;
import com.godaddy.asherah.appencryption.kms.KeyManagementService;
import com.godaddy.asherah.appencryption.kms.StaticKeyManagementServiceImpl;
import com.godaddy.asherah.appencryption.persistence.DynamoDbMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.InMemoryMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.JdbcMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.Metastore;
import com.godaddy.asherah.crypto.CryptoPolicy;
import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;
import com.godaddy.asherah.jni.AsherahFactory;
import org.json.JSONObject;

/**
 * Factory for creating encryption sessions. Provides a builder API compatible
 * with the canonical godaddy/asherah SessionFactory.
 *
 * <pre>
 * SessionFactory factory = SessionFactory.newBuilder("productId", "serviceId")
 *     .withInMemoryMetastore()
 *     .withNeverExpiredCryptoPolicy()
 *     .withStaticKeyManagementService("masterKey")
 *     .build();
 *
 * try (Session&lt;JSONObject, byte[]&gt; session = factory.getSessionJson("partition")) {
 *     byte[] encrypted = session.encrypt(payload);
 *     JSONObject decrypted = session.decrypt(encrypted);
 * }
 * factory.close();
 * </pre>
 */
public class SessionFactory implements AutoCloseable {

    private final AsherahFactory nativeFactory;

    private SessionFactory(final AsherahFactory nativeFactory) {
        this.nativeFactory = nativeFactory;
    }

    public Session<JSONObject, byte[]> getSessionJson(final String partitionId) {
        return new SessionJsonImpl<>(nativeFactory.getSession(partitionId), false);
    }

    public Session<byte[], byte[]> getSessionBytes(final String partitionId) {
        return new SessionBytesImpl<>(nativeFactory.getSession(partitionId), false);
    }

    public Session<JSONObject, JSONObject> getSessionJsonAsJson(final String partitionId) {
        return new SessionJsonImpl<>(nativeFactory.getSession(partitionId), true);
    }

    public Session<byte[], JSONObject> getSessionBytesAsJson(final String partitionId) {
        return new SessionBytesImpl<>(nativeFactory.getSession(partitionId), true);
    }

    @Override
    public void close() {
        nativeFactory.close();
    }

    public static MetastoreStep newBuilder(final String productId, final String serviceId) {
        return new Builder(productId, serviceId);
    }

    // --- Builder step interfaces (matching canonical API) ---

    public interface MetastoreStep {
        CryptoPolicyStep withInMemoryMetastore();
        CryptoPolicyStep withMetastore(Metastore<JSONObject> metastore);
    }

    public interface CryptoPolicyStep {
        KeyManagementServiceStep withNeverExpiredCryptoPolicy();
        KeyManagementServiceStep withCryptoPolicy(CryptoPolicy cryptoPolicy);
    }

    public interface KeyManagementServiceStep {
        BuildStep withStaticKeyManagementService(String staticMasterKey);
        BuildStep withKeyManagementService(KeyManagementService kms);
    }

    public interface BuildStep {
        BuildStep withMetricsEnabled();
        SessionFactory build();
    }

    // --- Builder implementation ---

    private static final class Builder
            implements MetastoreStep, CryptoPolicyStep, KeyManagementServiceStep, BuildStep {

        private final String productId;
        private final String serviceId;
        private Object metastore;
        private CryptoPolicy cryptoPolicy;
        private KeyManagementService kms;

        Builder(final String productId, final String serviceId) {
            this.productId = productId;
            this.serviceId = serviceId;
        }

        @Override
        public CryptoPolicyStep withInMemoryMetastore() {
            this.metastore = new InMemoryMetastoreImpl<>();
            return this;
        }

        @Override
        public CryptoPolicyStep withMetastore(final Metastore<JSONObject> metastore) {
            if (metastore instanceof InMemoryMetastoreImpl
                    || metastore instanceof JdbcMetastoreImpl
                    || metastore instanceof DynamoDbMetastoreImpl) {
                this.metastore = metastore;
            } else {
                throw new UnsupportedOperationException(
                        "Custom Metastore implementations are not supported by the FFI binding. "
                                + "Use InMemoryMetastoreImpl, JdbcMetastoreImpl, or DynamoDbMetastoreImpl.");
            }
            return this;
        }

        @Override
        public KeyManagementServiceStep withNeverExpiredCryptoPolicy() {
            this.cryptoPolicy = new com.godaddy.asherah.crypto.NeverExpiredCryptoPolicy();
            return this;
        }

        @Override
        public KeyManagementServiceStep withCryptoPolicy(final CryptoPolicy cryptoPolicy) {
            this.cryptoPolicy = cryptoPolicy;
            return this;
        }

        @Override
        public BuildStep withStaticKeyManagementService(final String staticMasterKey) {
            this.kms = new StaticKeyManagementServiceImpl(staticMasterKey);
            return this;
        }

        @Override
        public BuildStep withKeyManagementService(final KeyManagementService kms) {
            this.kms = kms;
            return this;
        }

        @Override
        public BuildStep withMetricsEnabled() {
            // Metrics are handled by the native Rust layer's observability.
            return this;
        }

        @Override
        public SessionFactory build() {
            final AsherahConfig.Builder cb = AsherahConfig.builder()
                    .productId(productId)
                    .serviceName(serviceId);

            // Apply metastore config
            if (metastore instanceof InMemoryMetastoreImpl) {
                ((InMemoryMetastoreImpl<?>) metastore).applyConfig(cb);
            } else if (metastore instanceof JdbcMetastoreImpl) {
                ((JdbcMetastoreImpl) metastore).applyConfig(cb);
            } else if (metastore instanceof DynamoDbMetastoreImpl) {
                ((DynamoDbMetastoreImpl) metastore).applyConfig(cb);
            }

            // Apply crypto policy config
            if (cryptoPolicy != null) {
                cryptoPolicy.applyConfig(cb);
            }

            // Apply KMS config
            if (kms != null) {
                kms.applyConfig(cb);
            }

            final AsherahConfig config = cb.build();
            final AsherahFactory nativeFactory = Asherah.factoryFromConfig(config);
            return new SessionFactory(nativeFactory);
        }
    }
}
