package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

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

  private static String repeat(String value, int count) {
    StringBuilder builder = new StringBuilder(value.length() * count);
    for (int i = 0; i < count; i++) {
      builder.append(value);
    }
    return builder.toString();
  }
}
