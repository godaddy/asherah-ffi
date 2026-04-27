package com.godaddy.asherah.jni;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.slf4j.Logger;

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

  /**
   * Install a log hook. Replaces any previously installed hook. The callback
   * may fire from any thread; implementations must be thread-safe. Pass
   * {@code null} to clear (equivalent to {@link #clearLogHook()}).
   */
  public static void setLogHook(final AsherahLogHook callback) {
    AsherahNative.setLogHook(callback);
  }

  /**
   * Install an SLF4J {@link Logger} as the destination for Asherah log
   * records. Records are forwarded with their native severity (Asherah's
   * Rust source emits TRACE/DEBUG/INFO/WARN/ERROR; SLF4J takes those
   * directly). The logger's own enablement check ({@code logger.isXxxEnabled()})
   * is honoured before the message is materialised on the consumer side.
   *
   * <p>Typical use in a Spring/Micronaut/Quarkus app:
   * <pre>
   *   Logger asherahLogger = LoggerFactory.getLogger("asherah");
   *   Asherah.setLogHook(asherahLogger);
   * </pre>
   */
  public static void setLogHook(final Logger logger) {
    Objects.requireNonNull(logger, "logger");
    AsherahNative.setLogHook(adaptLogger(logger));
  }

  /** Remove the currently installed log hook, if any. */
  public static void clearLogHook() {
    AsherahNative.clearLogHook();
  }

  /**
   * Install a metrics hook. Replaces any previously installed hook. Installing
   * a hook implicitly enables the global metrics gate; clearing it disables
   * the gate. Pass {@code null} to clear (equivalent to
   * {@link #clearMetricsHook()}).
   *
   * <p>To forward to a Micrometer {@code MeterRegistry} (Spring Boot,
   * Micronaut, Quarkus, OpenTelemetry, Prometheus, Datadog, CloudWatch), use
   * {@code AsherahMicrometer.metricsHook(registry)} as the callback. That
   * helper class lives in a separate compilation unit so users without
   * micrometer-core on their classpath are not affected.
   */
  public static void setMetricsHook(final AsherahMetricsHook callback) {
    AsherahNative.setMetricsHook(callback);
  }

  /** Remove the currently installed metrics hook, if any. */
  public static void clearMetricsHook() {
    AsherahNative.clearMetricsHook();
  }

  // ── SLF4J bridge ─────────────────────────────────────────────────────

  static AsherahLogHook adaptLogger(final Logger logger) {
    return event -> {
      switch (event.getLevel()) {
        case TRACE:
          if (logger.isTraceEnabled()) {
            logger.trace("{}: {}", event.getTarget(), event.getMessage());
          }
          break;
        case DEBUG:
          if (logger.isDebugEnabled()) {
            logger.debug("{}: {}", event.getTarget(), event.getMessage());
          }
          break;
        case INFO:
          if (logger.isInfoEnabled()) {
            logger.info("{}: {}", event.getTarget(), event.getMessage());
          }
          break;
        case WARN:
          if (logger.isWarnEnabled()) {
            logger.warn("{}: {}", event.getTarget(), event.getMessage());
          }
          break;
        case ERROR:
        default:
          if (logger.isErrorEnabled()) {
            logger.error("{}: {}", event.getTarget(), event.getMessage());
          }
          break;
      }
    };
  }
}
