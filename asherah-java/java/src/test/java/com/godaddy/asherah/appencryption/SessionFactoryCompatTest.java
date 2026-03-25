package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.appencryption.kms.AwsKeyManagementServiceImpl;
import com.godaddy.asherah.appencryption.kms.KeyManagementService;
import com.godaddy.asherah.appencryption.kms.StaticKeyManagementServiceImpl;
import com.godaddy.asherah.appencryption.persistence.DynamoDbMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.InMemoryMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.JdbcMetastoreImpl;
import com.godaddy.asherah.appencryption.persistence.Metastore;
import com.godaddy.asherah.appencryption.persistence.Persistence;
import com.godaddy.asherah.crypto.BasicExpiringCryptoPolicy;
import com.godaddy.asherah.crypto.CryptoPolicy;
import com.godaddy.asherah.crypto.NeverExpiredCryptoPolicy;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that the canonical SessionFactory builder API works as a drop-in replacement.
 */
class SessionFactoryCompatTest {

    private SessionFactory factory;

    @AfterEach
    void tearDown() {
        if (factory != null) {
            factory.close();
            factory = null;
        }
    }

    @Test
    void canonicalBuilderPatternRoundTrip() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<JSONObject, byte[]> session = factory.getSessionJson("test-partition")) {
            JSONObject payload = new JSONObject();
            payload.put("message", "hello from canonical API");

            byte[] encrypted = session.encrypt(payload);
            assertNotNull(encrypted);
            assertTrue(encrypted.length > 0);

            JSONObject decrypted = session.decrypt(encrypted);
            assertEquals("hello from canonical API", decrypted.getString("message"));
        }
    }

    @Test
    void sessionBytesRoundTrip() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<byte[], byte[]> session = factory.getSessionBytes("test-partition")) {
            byte[] payload = "binary payload test".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = session.encrypt(payload);
            assertNotNull(encrypted);

            byte[] decrypted = session.decrypt(encrypted);
            assertArrayEquals(payload, decrypted);
        }
    }

    @Test
    void sessionJsonAsJsonRoundTrip() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<JSONObject, JSONObject> session = factory.getSessionJsonAsJson("test-partition")) {
            JSONObject payload = new JSONObject();
            payload.put("key", "value");

            JSONObject encrypted = session.encrypt(payload);
            assertNotNull(encrypted);
            assertTrue(encrypted.has("Key")); // DRR has Key field

            JSONObject decrypted = session.decrypt(encrypted);
            assertEquals("value", decrypted.getString("key"));
        }
    }

    @Test
    void sessionBytesAsJsonRoundTrip() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<byte[], JSONObject> session = factory.getSessionBytesAsJson("test-partition")) {
            byte[] payload = "bytes as json test".getBytes(StandardCharsets.UTF_8);
            JSONObject encrypted = session.encrypt(payload);
            assertNotNull(encrypted);

            byte[] decrypted = session.decrypt(encrypted);
            assertArrayEquals(payload, decrypted);
        }
    }

    @Test
    void basicExpiringCryptoPolicy() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withCryptoPolicy(
                        BasicExpiringCryptoPolicy.newBuilder()
                                .withKeyExpirationDays(90)
                                .withRevokeCheckMinutes(60)
                                .withCanCacheSessions(true)
                                .withSessionCacheMaxSize(500)
                                .withSessionCacheExpireMinutes(30)
                                .build())
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<byte[], byte[]> session = factory.getSessionBytes("policy-test")) {
            byte[] payload = "policy test".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = session.encrypt(payload);
            byte[] decrypted = session.decrypt(encrypted);
            assertArrayEquals(payload, decrypted);
        }
    }

    @Test
    void metricsEnabledIsAccepted() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .withMetricsEnabled()
                .build();

        // Just verify it builds without error
        assertNotNull(factory);
    }

    @Test
    void withMetastoreAcceptsBuiltInImpl() {
        InMemoryMetastoreImpl<JSONObject> metastore = new InMemoryMetastoreImpl<>();
        factory = SessionFactory.newBuilder("product", "service")
                .withMetastore(metastore)
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<byte[], byte[]> session = factory.getSessionBytes("metastore-test")) {
            byte[] ct = session.encrypt("test".getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("test".getBytes(StandardCharsets.UTF_8), session.decrypt(ct));
        }
    }

    @Test
    void withKeyManagementServiceAcceptsStaticKms() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withKeyManagementService(new StaticKeyManagementServiceImpl("thisIsAStaticMasterKeyForTesting"))
                .build();

        try (Session<byte[], byte[]> session = factory.getSessionBytes("kms-test")) {
            byte[] ct = session.encrypt("kms test".getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("kms test".getBytes(StandardCharsets.UTF_8), session.decrypt(ct));
        }
    }

    @Test
    void customMetastoreThrowsUnsupported() {
        assertThrows(UnsupportedOperationException.class, () -> {
            SessionFactory.newBuilder("product", "service")
                    .withMetastore(new Metastore<JSONObject>() {
                        @Override public Optional<JSONObject> load(String k, java.time.Instant c) { return Optional.empty(); }
                        @Override public Optional<JSONObject> loadLatest(String k) { return Optional.empty(); }
                        @Override public boolean store(String k, java.time.Instant c, JSONObject v) { return false; }
                    });
        });
    }

    @Test
    void persistenceLoadStore() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        // Simple in-memory persistence store
        Map<String, byte[]> storage = new ConcurrentHashMap<>();
        Persistence<byte[]> persistence = new Persistence<byte[]>() {
            @Override public Optional<byte[]> load(String key) {
                return Optional.ofNullable(storage.get(key));
            }
            @Override public void store(String key, byte[] value) {
                storage.put(key, value);
            }
        };

        try (Session<byte[], byte[]> session = factory.getSessionBytes("persist-test")) {
            byte[] payload = "persist me".getBytes(StandardCharsets.UTF_8);

            // store encrypts and persists, returns the key
            String key = session.store(payload, persistence);
            assertNotNull(key);
            assertTrue(storage.containsKey(key));

            // load retrieves and decrypts
            Optional<byte[]> loaded = session.load(key, persistence);
            assertTrue(loaded.isPresent());
            assertArrayEquals(payload, loaded.get());
        }
    }

    @Test
    void dynamoDbMetastoreBuilder() {
        DynamoDbMetastoreImpl metastore = DynamoDbMetastoreImpl.newBuilder("us-east-1")
                .withTableName("CustomTable")
                .withEndPointConfiguration("http://localhost:4566", "us-west-2")
                .withKeySuffix()
                .build();

        assertEquals("_us-east-1", metastore.getKeySuffix());
    }

    @Test
    void jdbcMetastoreBuilder() {
        JdbcMetastoreImpl metastore = JdbcMetastoreImpl.newBuilder("mysql://localhost:3306/test")
                .build();
        assertNotNull(metastore);
    }

    @Test
    void awsKmsBuilder() {
        Map<String, String> regionMap = new HashMap<>();
        regionMap.put("us-east-1", "arn:aws:kms:us-east-1:123456:key/abc");
        AwsKeyManagementServiceImpl kms = AwsKeyManagementServiceImpl
                .newBuilder(regionMap, "us-east-1")
                .build();
        assertNotNull(kms);
    }

    @Test
    void neverExpiredCryptoPolicyValues() {
        NeverExpiredCryptoPolicy p = new NeverExpiredCryptoPolicy();
        assertFalse(p.isKeyExpired(java.time.Instant.EPOCH));
        assertTrue(p.canCacheSystemKeys());
        assertTrue(p.canCacheIntermediateKeys());
        assertFalse(p.canCacheSessions());
        assertTrue(p.isInlineKeyRotation());
        assertFalse(p.isQueuedKeyRotation());
    }

    @Test
    void basicExpiringCryptoPolicyFullBuilder() {
        BasicExpiringCryptoPolicy p = BasicExpiringCryptoPolicy.newBuilder()
                .withKeyExpirationDays(30)
                .withRevokeCheckMinutes(10)
                .withRotationStrategy(CryptoPolicy.KeyRotationStrategy.QUEUED)
                .withCanCacheSystemKeys(false)
                .withCanCacheIntermediateKeys(false)
                .withCanCacheSessions(true)
                .withSessionCacheMaxSize(100)
                .withSessionCacheExpireMinutes(5)
                .withNotifyExpiredSystemKeyOnRead(true)
                .withNotifyExpiredIntermediateKeyOnRead(true)
                .build();

        assertFalse(p.canCacheSystemKeys());
        assertFalse(p.canCacheIntermediateKeys());
        assertTrue(p.canCacheSessions());
        assertEquals(100, p.getSessionCacheMaxSize());
        assertEquals(5 * 60 * 1000, p.getSessionCacheExpireMillis());
        assertTrue(p.notifyExpiredSystemKeyOnRead());
        assertTrue(p.notifyExpiredIntermediateKeyOnRead());
        assertTrue(p.isQueuedKeyRotation());
    }

    @Test
    void multipleSessionsSameFactory() {
        factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withNeverExpiredCryptoPolicy()
                .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
                .build();

        try (Session<byte[], byte[]> session1 = factory.getSessionBytes("partition-1");
             Session<byte[], byte[]> session2 = factory.getSessionBytes("partition-2")) {

            byte[] ct1 = session1.encrypt("data1".getBytes(StandardCharsets.UTF_8));
            byte[] ct2 = session2.encrypt("data2".getBytes(StandardCharsets.UTF_8));

            byte[] pt1 = session1.decrypt(ct1);
            byte[] pt2 = session2.decrypt(ct2);

            assertArrayEquals("data1".getBytes(StandardCharsets.UTF_8), pt1);
            assertArrayEquals("data2".getBytes(StandardCharsets.UTF_8), pt2);
        }
    }
}
