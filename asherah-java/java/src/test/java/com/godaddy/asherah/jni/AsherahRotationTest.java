package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Rotation, revocation, and sync↔async interop tests for the
 * asherah-java JNI binding.
 *
 * <p>The Rust core has comprehensive rotation/revocation coverage;
 * the Java binding had zero such tests prior to this file. Mirrors
 * the asherah-node and asherah-py rotation suites.
 *
 * <p>Hermetic: {@code Metastore: 'memory'} + {@code KMS:
 * 'test-debug-static'} produces a hermetic factory with no Docker or
 * network dependency.
 */
class AsherahRotationTest {

  @BeforeAll
  static void configureLibraryPath() {
    if (System.getProperty("asherah.java.nativeLibraryPath") == null) {
      final Path defaultDir = Paths.get("..", "..", "target", "debug").toAbsolutePath().normalize();
      System.setProperty("asherah.java.nativeLibraryPath", defaultDir.toString());
    }
  }

  private static AsherahConfig shortExpiryConfig(String suffix) {
    return AsherahConfig.builder()
        .serviceName("rot-" + suffix + "-svc")
        .productId("rot-" + suffix + "-prod")
        .metastore("memory")
        .kms("test-debug-static")
        .expireAfter(1L)
        .checkInterval(1L)
        .enableSessionCaching(Boolean.FALSE)
        .build();
  }

  /** Pull {@code Key.ParentKeyMeta.Created} out of a DRR JSON string. */
  private static long ikCreated(String drrJson) {
    // Cheap JSON extract — the core uses Pascal-cased fields, and we
    // only need a single integer. Avoids pulling in a JSON library.
    int parentIdx = drrJson.indexOf("\"ParentKeyMeta\"");
    assertTrue(parentIdx >= 0, "DRR missing ParentKeyMeta: " + drrJson);
    int createdIdx = drrJson.indexOf("\"Created\"", parentIdx);
    assertTrue(createdIdx >= 0, "ParentKeyMeta missing Created: " + drrJson);
    int colon = drrJson.indexOf(':', createdIdx);
    // The Created value is an integer; scan past whitespace, then take
    // digits (and an optional leading '-') until a non-digit. Avoids
    // brittleness around trailing `,` vs `}` vs nested braces.
    int i = colon + 1;
    while (i < drrJson.length() && Character.isWhitespace(drrJson.charAt(i))) {
      i++;
    }
    int start = i;
    if (i < drrJson.length() && drrJson.charAt(i) == '-') {
      i++;
    }
    while (i < drrJson.length() && Character.isDigit(drrJson.charAt(i))) {
      i++;
    }
    return Long.parseLong(drrJson.substring(start, i));
  }

  // ──────────── Sync rotation ────────────

  @Test
  void syncRotationAcrossExpiry() throws InterruptedException {
    Asherah.setup(shortExpiryConfig("sync"));
    try {
      String drr1 = Asherah.encryptString("p1", "before");
      long ik1 = ikCreated(drr1);

      Thread.sleep(3000);

      String drr2 = Asherah.encryptString("p1", "after");
      long ik2 = ikCreated(drr2);

      assertTrue(
          ik2 > ik1,
          "expected IK rotation across expiry: ik2=" + ik2 + " should be > ik1=" + ik1);
      assertArrayEquals(
          "before".getBytes(StandardCharsets.UTF_8),
          Asherah.decrypt("p1", drr1.getBytes(StandardCharsets.UTF_8)));
      assertArrayEquals(
          "after".getBytes(StandardCharsets.UTF_8),
          Asherah.decrypt("p1", drr2.getBytes(StandardCharsets.UTF_8)));
    } finally {
      Asherah.shutdown();
    }
  }

  // ──────────── Async rotation ────────────

  @Test
  void asyncRotationAcrossExpiry() throws Exception {
    Asherah.setup(shortExpiryConfig("async"));
    try {
      byte[] plaintext1 = "before-async".getBytes(StandardCharsets.UTF_8);
      byte[] drr1 = Asherah.encryptAsync("p1", plaintext1).get();
      long ik1 = ikCreated(new String(drr1, StandardCharsets.UTF_8));

      Thread.sleep(3000);

      byte[] plaintext2 = "after-async".getBytes(StandardCharsets.UTF_8);
      byte[] drr2 = Asherah.encryptAsync("p1", plaintext2).get();
      long ik2 = ikCreated(new String(drr2, StandardCharsets.UTF_8));

      assertTrue(
          ik2 > ik1,
          "async path must rotate IK across expiry: ik2=" + ik2 + " should be > ik1=" + ik1);
      assertArrayEquals(plaintext1, Asherah.decryptAsync("p1", drr1).get());
      assertArrayEquals(plaintext2, Asherah.decryptAsync("p1", drr2).get());
    } finally {
      Asherah.shutdown();
    }
  }

  // ──────────── Sync↔async interop after rotation ────────────

  @Test
  void syncAsyncInteropAfterRotation() throws Exception {
    Asherah.setup(shortExpiryConfig("interop"));
    try {
      String drrSyncPre = Asherah.encryptString("p1", "sync-pre");
      byte[] drrAsyncPre =
          Asherah.encryptAsync("p1", "async-pre".getBytes(StandardCharsets.UTF_8)).get();

      Thread.sleep(3000);

      String drrSyncPost = Asherah.encryptString("p1", "sync-post");
      byte[] drrAsyncPost =
          Asherah.encryptAsync("p1", "async-post".getBytes(StandardCharsets.UTF_8)).get();

      // Confirm rotation actually happened — at least one post-DRR has
      // a strictly newer IK than both pre-DRRs.
      long preMax =
          Math.max(ikCreated(drrSyncPre), ikCreated(new String(drrAsyncPre, StandardCharsets.UTF_8)));
      long postMin =
          Math.min(
              ikCreated(drrSyncPost),
              ikCreated(new String(drrAsyncPost, StandardCharsets.UTF_8)));
      assertTrue(
          postMin > preMax,
          "interop path must rotate: postMin=" + postMin + " should be > preMax=" + preMax);

      // 8 round-trips: every encrypt × every decrypt path.
      assertArrayEquals(
          "sync-pre".getBytes(StandardCharsets.UTF_8),
          Asherah.decrypt("p1", drrSyncPre.getBytes(StandardCharsets.UTF_8)));
      assertArrayEquals(
          "sync-pre".getBytes(StandardCharsets.UTF_8),
          Asherah.decryptAsync("p1", drrSyncPre.getBytes(StandardCharsets.UTF_8)).get());
      assertArrayEquals(
          "async-pre".getBytes(StandardCharsets.UTF_8), Asherah.decrypt("p1", drrAsyncPre));
      assertArrayEquals(
          "async-pre".getBytes(StandardCharsets.UTF_8),
          Asherah.decryptAsync("p1", drrAsyncPre).get());
      assertArrayEquals(
          "sync-post".getBytes(StandardCharsets.UTF_8),
          Asherah.decrypt("p1", drrSyncPost.getBytes(StandardCharsets.UTF_8)));
      assertArrayEquals(
          "sync-post".getBytes(StandardCharsets.UTF_8),
          Asherah.decryptAsync("p1", drrSyncPost.getBytes(StandardCharsets.UTF_8)).get());
      assertArrayEquals(
          "async-post".getBytes(StandardCharsets.UTF_8), Asherah.decrypt("p1", drrAsyncPost));
      assertArrayEquals(
          "async-post".getBytes(StandardCharsets.UTF_8),
          Asherah.decryptAsync("p1", drrAsyncPost).get());
    } finally {
      Asherah.shutdown();
    }
  }

  // ──────────── Multiple rotation cycles ────────────

  @Test
  void multipleRotationCycles() throws Exception {
    Asherah.setup(shortExpiryConfig("multi"));
    try {
      List<byte[]> drrs = new ArrayList<>();
      List<byte[]> payloads = new ArrayList<>();
      List<Long> iks = new ArrayList<>();
      for (int i = 0; i < 3; i++) {
        byte[] payload = ("cycle-" + i).getBytes(StandardCharsets.UTF_8);
        byte[] drr = Asherah.encryptAsync("p1", payload).get();
        drrs.add(drr);
        payloads.add(payload);
        iks.add(ikCreated(new String(drr, StandardCharsets.UTF_8)));
        Thread.sleep(3000);
      }

      // Each cycle's IK must be strictly newer than the previous.
      for (int i = 1; i < iks.size(); i++) {
        assertTrue(
            iks.get(i) > iks.get(i - 1),
            "cycle " + i + ": ik=" + iks.get(i) + " should be > prev ik=" + iks.get(i - 1));
      }

      // Every historical DRR still decrypts.
      for (int i = 0; i < drrs.size(); i++) {
        assertArrayEquals(payloads.get(i), Asherah.decryptAsync("p1", drrs.get(i)).get());
      }
    } finally {
      Asherah.shutdown();
    }
  }
}
