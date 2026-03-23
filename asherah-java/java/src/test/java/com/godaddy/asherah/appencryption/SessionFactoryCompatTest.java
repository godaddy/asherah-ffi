package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.crypto.BasicExpiringCryptoPolicy;
import com.godaddy.asherah.crypto.CryptoPolicy;
import com.godaddy.asherah.crypto.NeverExpiredCryptoPolicy;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

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
