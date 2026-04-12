package com.godaddy.asherah.jni;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class Asherah {
  private static final ReentrantReadWriteLock LOCK = new ReentrantReadWriteLock();
  private static volatile AsherahFactory sharedFactory;
  private static final ConcurrentHashMap<String, AsherahSession> SESSION_CACHE = new ConcurrentHashMap<>();
  private static volatile boolean sessionCachingEnabled = true;

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
    LOCK.writeLock().lock();
    try {
      if (sharedFactory != null) {
        factory.close();
        throw new IllegalStateException("Asherah is already configured; call shutdown() first");
      }
      sharedFactory = factory;
      SESSION_CACHE.clear();
      sessionCachingEnabled = config.isSessionCachingEnabled();
    } finally {
      LOCK.writeLock().unlock();
    }
  }

  public static CompletableFuture<Void> setupAsync(final AsherahConfig config) {
    return CompletableFuture.runAsync(() -> setup(config));
  }

  public static void shutdown() {
    LOCK.writeLock().lock();
    try {
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
    } finally {
      LOCK.writeLock().unlock();
    }
  }

  public static CompletableFuture<Void> shutdownAsync() {
    return CompletableFuture.runAsync(Asherah::shutdown);
  }

  public static boolean getSetupStatus() {
    return sharedFactory != null;
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
    LOCK.readLock().lock();
    try {
      final AsherahSession session = acquireSession(partitionId);
      try {
        return session.encryptBytes(plaintext);
      } finally {
        releaseSession(partitionId, session);
      }
    } finally {
      LOCK.readLock().unlock();
    }
  }

  public static String encryptString(final String partitionId, final String plaintext) {
    final byte[] cipher = encrypt(partitionId, plaintext.getBytes(StandardCharsets.UTF_8));
    return new String(cipher, StandardCharsets.UTF_8);
  }

  public static CompletableFuture<byte[]> encryptAsync(
      final String partitionId, final byte[] plaintext) {
    Objects.requireNonNull(partitionId, "partitionId");
    Objects.requireNonNull(plaintext, "plaintext");
    LOCK.readLock().lock();
    final AsherahSession session;
    try {
      session = acquireSession(partitionId);
    } catch (Throwable t) {
      LOCK.readLock().unlock();
      throw t;
    }
    LOCK.readLock().unlock();
    return session.encryptBytesAsync(plaintext)
        .whenComplete((r, e) -> releaseSession(partitionId, session));
  }

  public static CompletableFuture<String> encryptStringAsync(
      final String partitionId, final String plaintext) {
    return encryptAsync(partitionId, plaintext.getBytes(StandardCharsets.UTF_8))
        .thenApply(bytes -> new String(bytes, StandardCharsets.UTF_8));
  }

  public static byte[] decrypt(final String partitionId, final byte[] dataRowRecordJson) {
    Objects.requireNonNull(partitionId, "partitionId");
    Objects.requireNonNull(dataRowRecordJson, "dataRowRecordJson");
    LOCK.readLock().lock();
    try {
      final AsherahSession session = acquireSession(partitionId);
      try {
        return session.decryptBytes(dataRowRecordJson);
      } finally {
        releaseSession(partitionId, session);
      }
    } finally {
      LOCK.readLock().unlock();
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
    Objects.requireNonNull(partitionId, "partitionId");
    Objects.requireNonNull(dataRowRecordJson, "dataRowRecordJson");
    LOCK.readLock().lock();
    final AsherahSession session;
    try {
      session = acquireSession(partitionId);
    } catch (Throwable t) {
      LOCK.readLock().unlock();
      throw t;
    }
    LOCK.readLock().unlock();
    return session.decryptBytesAsync(dataRowRecordJson)
        .whenComplete((r, e) -> releaseSession(partitionId, session));
  }

  public static CompletableFuture<String> decryptStringAsync(
      final String partitionId, final String dataRowRecordJson) {
    return decryptAsync(partitionId, dataRowRecordJson.getBytes(StandardCharsets.UTF_8))
        .thenApply(bytes -> new String(bytes, StandardCharsets.UTF_8));
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
    }
  }

  private static void ensureConfigured() {
    if (sharedFactory == null) {
      throw new IllegalStateException("Asherah not configured; call setup() first");
    }
  }
}
