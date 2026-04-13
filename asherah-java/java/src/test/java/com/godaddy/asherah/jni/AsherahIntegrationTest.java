package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AsherahIntegrationTest {

  @BeforeAll
  static void configureLibraryPath() {
    if (System.getProperty("asherah.java.nativeLibraryPath") == null) {
      final Path defaultDir = Paths.get("..", "..", "target", "debug").toAbsolutePath().normalize();
      System.setProperty("asherah.java.nativeLibraryPath", defaultDir.toString());
    }
    System.setProperty("SERVICE_NAME", "svc");
    System.setProperty("PRODUCT_ID", "prod");
    System.setProperty("STATIC_MASTER_KEY_HEX", repeat("22", 32));
    System.setProperty("KMS", "static");
  }

  @Test
  void encryptDecryptRoundTrip() {
    try (AsherahFactory factory = Asherah.factoryFromEnv();
        AsherahSession session = factory.getSession("java-integration")) {
      byte[] plaintext = "hello-java-asherah".getBytes(StandardCharsets.UTF_8);
      String json = session.encryptToJson(plaintext);
      byte[] decrypted = session.decryptFromJson(json);
      assertArrayEquals(plaintext, decrypted);
    }
  }

  @Test
  void moduleLevelSetupRoundTrip() {
    final AsherahConfig config =
        AsherahConfig.builder()
            .serviceName("svc")
            .productId("prod")
            .metastore("memory")
            .kms("static")
            .enableSessionCaching(Boolean.TRUE)
            .verbose(Boolean.FALSE)
            .build();

    Asherah.setup(config);
    try {
      byte[] plaintext = "module-level".getBytes(StandardCharsets.UTF_8);
      String ciphertext = Asherah.encryptString("java-module", "module-level");
      byte[] decrypted = Asherah.decrypt("java-module", ciphertext.getBytes(StandardCharsets.UTF_8));
      assertArrayEquals(plaintext, decrypted);
    } finally {
      Asherah.shutdown();
    }
  }

  // --- FFI Boundary Tests ---

  private void withSetup(Runnable body) {
    final AsherahConfig config =
        AsherahConfig.builder()
            .serviceName("ffi-test")
            .productId("prod")
            .metastore("memory")
            .kms("static")
            .enableSessionCaching(Boolean.FALSE)
            .build();
    Asherah.setup(config);
    try {
      body.run();
    } finally {
      Asherah.shutdown();
    }
  }

  @Test
  void unicodeCjkRoundTrip() {
    withSetup(() -> {
      String text = "你好世界こんにちは세계";
      String ct = Asherah.encryptString("java-unicode", text);
      byte[] decrypted = Asherah.decrypt("java-unicode", ct.getBytes(StandardCharsets.UTF_8));
      assertEquals(text, new String(decrypted, StandardCharsets.UTF_8));
    });
  }

  @Test
  void unicodeEmojiRoundTrip() {
    withSetup(() -> {
      String text = "🦀🔐🎉💾🌍";
      String ct = Asherah.encryptString("java-unicode", text);
      byte[] decrypted = Asherah.decrypt("java-unicode", ct.getBytes(StandardCharsets.UTF_8));
      assertEquals(text, new String(decrypted, StandardCharsets.UTF_8));
    });
  }

  @Test
  void unicodeMixedScriptsRoundTrip() {
    withSetup(() -> {
      String text = "Hello 世界 مرحبا Привет 🌍";
      String ct = Asherah.encryptString("java-unicode", text);
      byte[] decrypted = Asherah.decrypt("java-unicode", ct.getBytes(StandardCharsets.UTF_8));
      assertEquals(text, new String(decrypted, StandardCharsets.UTF_8));
    });
  }

  @Test
  void unicodeCombiningCharactersRoundTrip() {
    withSetup(() -> {
      String text = "e\u0301 n\u0303 a\u0308";
      String ct = Asherah.encryptString("java-unicode", text);
      byte[] decrypted = Asherah.decrypt("java-unicode", ct.getBytes(StandardCharsets.UTF_8));
      assertEquals(text, new String(decrypted, StandardCharsets.UTF_8));
    });
  }

  @Test
  void unicodeZwjSequenceRoundTrip() {
    withSetup(() -> {
      String text = "\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67\u200D\uD83D\uDC66";
      String ct = Asherah.encryptString("java-unicode", text);
      byte[] decrypted = Asherah.decrypt("java-unicode", ct.getBytes(StandardCharsets.UTF_8));
      assertEquals(text, new String(decrypted, StandardCharsets.UTF_8));
    });
  }

  @Test
  void binaryAllByteValuesRoundTrip() {
    try (AsherahFactory factory = Asherah.factoryFromEnv();
        AsherahSession session = factory.getSession("java-binary")) {
      byte[] payload = new byte[256];
      for (int i = 0; i < 256; i++) payload[i] = (byte) i;
      String json = session.encryptToJson(payload);
      byte[] decrypted = session.decryptFromJson(json);
      assertArrayEquals(payload, decrypted);
    }
  }

  @Test
  void emptyPayloadRoundTrip() {
    try (AsherahFactory factory = Asherah.factoryFromEnv();
        AsherahSession session = factory.getSession("java-empty")) {
      byte[] payload = new byte[0];
      String json = session.encryptToJson(payload);
      byte[] decrypted = session.decryptFromJson(json);
      assertArrayEquals(payload, decrypted);
    }
  }

  @Test
  void largePayload1MbRoundTrip() {
    try (AsherahFactory factory = Asherah.factoryFromEnv();
        AsherahSession session = factory.getSession("java-large")) {
      byte[] payload = new byte[1024 * 1024];
      for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i % 256);
      String json = session.encryptToJson(payload);
      byte[] decrypted = session.decryptFromJson(json);
      assertEquals(payload.length, decrypted.length);
      assertArrayEquals(payload, decrypted);
    }
  }

  @Test
  void decryptInvalidJsonThrows() {
    withSetup(() -> {
      assertThrows(Exception.class, () ->
          Asherah.decrypt("java-error", "not valid json".getBytes(StandardCharsets.UTF_8)));
    });
  }

  @Test
  void decryptWrongPartitionThrows() {
    withSetup(() -> {
      String ct = Asherah.encryptString("partition-a", "secret");
      assertThrows(Exception.class, () ->
          Asherah.decrypt("partition-b", ct.getBytes(StandardCharsets.UTF_8)));
    });
  }

  // --- Factory / Session API Tests ---

  private AsherahConfig factoryConfig() {
    return AsherahConfig.builder()
        .serviceName("factory-test")
        .productId("prod")
        .metastore("memory")
        .kms("static")
        .enableSessionCaching(Boolean.FALSE)
        .build();
  }

  @Test
  void factorySessionRoundTrip() {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession session = factory.getSession("factory-bytes")) {
      byte[] plaintext = "factory-session-bytes".getBytes(StandardCharsets.UTF_8);
      String json = session.encryptToJson(plaintext);
      byte[] decrypted = session.decryptFromJson(json);
      assertArrayEquals(plaintext, decrypted);
    }
  }

  @Test
  void factorySessionStringApi() {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession session = factory.getSession("factory-string")) {
      String plaintext = "factory-session-string-api";
      String json = session.encryptString(plaintext);
      String decrypted = session.decryptString(json);
      assertEquals(plaintext, decrypted);
    }
  }

  @Test
  void factoryMultipleSessionsIsolation() {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession sessionA = factory.getSession("isolation-a");
        AsherahSession sessionB = factory.getSession("isolation-b")) {
      String json = sessionA.encryptString("secret-a");
      // session B with a different partition should fail to decrypt
      assertThrows(Exception.class, () -> sessionB.decryptString(json));
    }
  }

  @Test
  void concurrentEncryptDecrypt() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig())) {
      ExecutorService executor = Executors.newFixedThreadPool(10);
      List<Future<Void>> futures = new ArrayList<>();
      for (int t = 0; t < 10; t++) {
        final int threadId = t;
        futures.add(executor.submit(() -> {
          String partition = "concurrent-" + threadId;
          try (AsherahSession session = factory.getSession(partition)) {
            for (int i = 0; i < 50; i++) {
              byte[] plaintext = ("thread-" + threadId + "-iter-" + i)
                  .getBytes(StandardCharsets.UTF_8);
              String json = session.encryptToJson(plaintext);
              byte[] decrypted = session.decryptFromJson(json);
              assertArrayEquals(plaintext, decrypted);
            }
          }
          return null;
        }));
      }
      executor.shutdown();
      for (Future<Void> f : futures) {
        f.get();
      }
    }
  }

  // --- Async API Tests ---

  @Test
  void asyncEncryptDecryptRoundTrip() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession session = factory.getSession("async-roundtrip")) {
      byte[] plaintext = "async-roundtrip".getBytes(StandardCharsets.UTF_8);
      byte[] ciphertext = session.encryptBytesAsync(plaintext).get();
      byte[] decrypted = session.decryptBytesAsync(ciphertext).get();
      assertArrayEquals(plaintext, decrypted);
    }
  }

  @Test
  void asyncEmptyPayload() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession session = factory.getSession("async-empty")) {
      byte[] ciphertext = session.encryptBytesAsync(new byte[0]).get();
      byte[] decrypted = session.decryptBytesAsync(ciphertext).get();
      assertArrayEquals(new byte[0], decrypted);
    }
  }

  @Test
  void asyncConcurrent() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig())) {
      List<java.util.concurrent.CompletableFuture<Void>> futures = new ArrayList<>();
      List<AsherahSession> sessions = new ArrayList<>();
      for (int t = 0; t < 10; t++) {
        final int threadId = t;
        AsherahSession session = factory.getSession("async-concurrent-" + threadId);
        sessions.add(session);
        byte[] plaintext = ("async-data-" + threadId).getBytes(StandardCharsets.UTF_8);
        futures.add(
            session.encryptBytesAsync(plaintext)
                .thenCompose(ct -> session.decryptBytesAsync(ct))
                .thenAccept(recovered -> assertArrayEquals(plaintext, recovered)));
      }
      java.util.concurrent.CompletableFuture.allOf(
          futures.toArray(new java.util.concurrent.CompletableFuture[0])).get();
      for (AsherahSession s : sessions) {
        s.close();
      }
    }
  }

  @Test
  void asyncStringRoundTrip() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig());
        AsherahSession session = factory.getSession("async-string")) {
      String plaintext = "async string test 🦀";
      String ciphertext = session.encryptStringAsync(plaintext).get();
      String decrypted = session.decryptStringAsync(ciphertext).get();
      assertEquals(plaintext, decrypted);
    }
  }

  // Regression: closing a session while async futures are in flight must not
  // crash — the Arc-wrapped native session keeps it alive until all tasks complete.
  @Test
  void asyncCloseWhileInflight() throws Exception {
    try (AsherahFactory factory = Asherah.factoryFromConfig(factoryConfig())) {
      AsherahSession session = factory.getSession("async-close-test");
      List<CompletableFuture<byte[]>> futures = new ArrayList<>();
      for (int i = 0; i < 5; i++) {
        futures.add(session.encryptBytesAsync(
            ("async-close-" + i).getBytes(StandardCharsets.UTF_8)));
      }
      // Close while async ops may be in flight
      session.close();
      // All futures must complete without exception
      for (CompletableFuture<byte[]> f : futures) {
        assertNotNull(f.get());
      }
    }
  }

  // Regression: the static facade must allow concurrent encrypt/decrypt
  // across partitions (ReadWriteLock, not synchronized).
  @Test
  void concurrentStaticFacade() throws Exception {
    final AsherahConfig config =
        AsherahConfig.builder()
            .serviceName("concurrent-facade")
            .productId("prod")
            .metastore("memory")
            .kms("static")
            .enableSessionCaching(Boolean.FALSE)
            .build();
    Asherah.setup(config);
    try {
      ExecutorService executor = Executors.newFixedThreadPool(10);
      List<Future<Void>> futures = new ArrayList<>();
      for (int t = 0; t < 10; t++) {
        final int threadId = t;
        futures.add(executor.submit(() -> {
          for (int i = 0; i < 50; i++) {
            String data = "thread-" + threadId + "-iter-" + i;
            String ct = Asherah.encryptString("facade-" + threadId, data);
            byte[] pt = Asherah.decrypt("facade-" + threadId,
                ct.getBytes(StandardCharsets.UTF_8));
            assertArrayEquals(data.getBytes(StandardCharsets.UTF_8), pt);
          }
          return null;
        }));
      }
      executor.shutdown();
      for (Future<Void> f : futures) {
        f.get();
      }
    } finally {
      Asherah.shutdown();
    }
  }

  private static String repeat(String value, int count) {
    StringBuilder builder = new StringBuilder(value.length() * count);
    for (int i = 0; i < count; i++) {
      builder.append(value);
    }
    return builder.toString();
  }
}
