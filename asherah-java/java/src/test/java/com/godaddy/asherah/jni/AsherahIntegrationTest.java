package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AsherahIntegrationTest {

  @BeforeAll
  static void configureLibraryPath() {
    if (System.getProperty("asherah.java.nativeLibraryPath") == null) {
      final Path defaultDir = Paths.get("..", "target", "debug").toAbsolutePath().normalize();
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

  private static String repeat(String value, int count) {
    StringBuilder builder = new StringBuilder(value.length() * count);
    for (int i = 0; i < count; i++) {
      builder.append(value);
    }
    return builder.toString();
  }
}
