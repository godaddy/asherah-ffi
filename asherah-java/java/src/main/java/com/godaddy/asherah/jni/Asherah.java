package com.godaddy.asherah.jni;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public final class Asherah {
  private static final Object LOCK = new Object();
  private static AsherahFactory sharedFactory;
  private static final Map<String, AsherahSession> SESSION_CACHE = new HashMap<>();
  private static boolean sessionCachingEnabled = true;

  private Asherah() {}

  public static AsherahFactory factoryFromEnv() {
    final long handle = AsherahNative.factoryFromEnv();
    if (handle == 0) {
      throw new IllegalStateException("Native factory handle is null");
    }
    return new AsherahFactory(handle);
  }

  public static AsherahFactory factoryFromConfig(final AsherahConfig config) {
    Objects.requireNonNull(config, "config");
    final long handle = AsherahNative.factoryFromJson(config.toJson());
    if (handle == 0) {
      throw new IllegalStateException("Native factory handle is null");
    }
    return new AsherahFactory(handle);
  }

  public static void setup(final AsherahConfig config) {
    final AsherahFactory factory = factoryFromConfig(config);
    synchronized (LOCK) {
      if (sharedFactory != null) {
        factory.close();
        throw new IllegalStateException("Asherah is already configured; call shutdown() first");
      }
      sharedFactory = factory;
      SESSION_CACHE.clear();
      sessionCachingEnabled = config.isSessionCachingEnabled();
    }
  }

  public static CompletableFuture<Void> setupAsync(final AsherahConfig config) {
    return CompletableFuture.runAsync(() -> setup(config));
  }

  public static void shutdown() {
    synchronized (LOCK) {
      if (sharedFactory == null) {
        return;
      }
      for (AsherahSession session : SESSION_CACHE.values()) {
        try {
          session.close();
        } catch (RuntimeException ignored) {
        }
      }
      SESSION_CACHE.clear();
      sharedFactory.close();
      sharedFactory = null;
    }
  }

  public static CompletableFuture<Void> shutdownAsync() {
    return CompletableFuture.runAsync(Asherah::shutdown);
  }

  public static boolean getSetupStatus() {
    synchronized (LOCK) {
      return sharedFactory != null;
    }
  }

  public static void setEnv(final Map<String, String> env) {
    final Map<String, String> copy = new HashMap<>();
    for (Map.Entry<String, String> entry : env.entrySet()) {
      copy.put(entry.getKey(), entry.getValue());
    }
    AsherahNative.setEnv(JsonUtil.toJson(copy));
  }

  public static void setEnvJson(final String envJson) {
    AsherahNative.setEnv(envJson);
  }

  public static byte[] encrypt(final String partitionId, final byte[] plaintext) {
    Objects.requireNonNull(partitionId, "partitionId");
    Objects.requireNonNull(plaintext, "plaintext");
    synchronized (LOCK) {
      final AsherahSession session = acquireSession(partitionId);
      try {
        return session.encryptBytes(plaintext);
      } finally {
        releaseSession(partitionId, session);
      }
    }
  }

  public static String encryptString(final String partitionId, final String plaintext) {
    final byte[] cipher = encrypt(partitionId, plaintext.getBytes(StandardCharsets.UTF_8));
    return new String(cipher, StandardCharsets.UTF_8);
  }

  public static CompletableFuture<byte[]> encryptAsync(
      final String partitionId, final byte[] plaintext) {
    return CompletableFuture.supplyAsync(() -> encrypt(partitionId, plaintext));
  }

  public static CompletableFuture<String> encryptStringAsync(
      final String partitionId, final String plaintext) {
    return CompletableFuture.supplyAsync(() -> encryptString(partitionId, plaintext));
  }

  public static byte[] decrypt(final String partitionId, final byte[] dataRowRecordJson) {
    Objects.requireNonNull(partitionId, "partitionId");
    Objects.requireNonNull(dataRowRecordJson, "dataRowRecordJson");
    synchronized (LOCK) {
      final AsherahSession session = acquireSession(partitionId);
      try {
        return session.decryptBytes(dataRowRecordJson);
      } finally {
        releaseSession(partitionId, session);
      }
    }
  }

  public static byte[] decryptJson(final String partitionId, final String dataRowRecordJson) {
    return decrypt(partitionId, dataRowRecordJson.getBytes(StandardCharsets.UTF_8));
  }

  public static String decryptString(final String partitionId, final String dataRowRecordJson) {
    final byte[] plaintext = decryptJson(partitionId, dataRowRecordJson);
    return new String(plaintext, StandardCharsets.UTF_8);
  }

  public static CompletableFuture<byte[]> decryptAsync(
      final String partitionId, final byte[] dataRowRecordJson) {
    return CompletableFuture.supplyAsync(() -> decrypt(partitionId, dataRowRecordJson));
  }

  public static CompletableFuture<String> decryptStringAsync(
      final String partitionId, final String dataRowRecordJson) {
    return CompletableFuture.supplyAsync(() -> decryptString(partitionId, dataRowRecordJson));
  }

  private static AsherahSession acquireSession(final String partitionId) {
    ensureConfigured();
    if (sessionCachingEnabled) {
      return SESSION_CACHE.computeIfAbsent(partitionId, key -> sharedFactory.getSession(key));
    }
    return sharedFactory.getSession(partitionId);
  }

  private static void releaseSession(final String partitionId, final AsherahSession session) {
    if (!sessionCachingEnabled) {
      session.close();
    } else if (!SESSION_CACHE.containsKey(partitionId)) {
      session.close();
    }
  }

  private static void ensureConfigured() {
    if (sharedFactory == null) {
      throw new IllegalStateException("Asherah not configured; call setup() first");
    }
  }
}
