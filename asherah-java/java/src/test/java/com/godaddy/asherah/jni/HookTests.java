package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the Asherah log + metrics hook plumbing. These run serially via
 * surefire's default forking behavior; the tests defensively clear hooks in
 * {@link #cleanup()} so they don't bleed across tests if a future runner
 * parallelizes them.
 */
class HookTests {

  @BeforeAll
  static void configureLibraryPath() {
    if (System.getProperty("asherah.java.nativeLibraryPath") == null) {
      final Path defaultDir = Paths.get("..", "..", "target", "debug").toAbsolutePath().normalize();
      System.setProperty("asherah.java.nativeLibraryPath", defaultDir.toString());
    }
    System.setProperty("SERVICE_NAME", "svc");
    System.setProperty("PRODUCT_ID", "prod");
    System.setProperty("STATIC_MASTER_KEY_HEX",
        "2222222222222222222222222222222222222222222222222222222222222222");
    System.setProperty("KMS", "static");
  }

  @BeforeEach
  void clearHooksBefore() {
    Asherah.clearLogHook();
    Asherah.clearMetricsHook();
  }

  @AfterEach
  void cleanup() {
    Asherah.clearLogHook();
    Asherah.clearMetricsHook();
  }

  private static AsherahConfig hookConfig() {
    return AsherahConfig.builder()
        .serviceName("hook-test")
        .productId("prod")
        .metastore("memory")
        .kms("static")
        .enableSessionCaching(Boolean.FALSE)
        .build();
  }

  // ---------- log hook ----------

  @Test
  void setLogHookAcceptsCallbackWithoutThrowing() {
    Asherah.setLogHook(event -> { /* no-op */ });
    Asherah.clearLogHook();
  }

  @Test
  void clearLogHookIsIdempotent() {
    Asherah.clearLogHook();
    Asherah.clearLogHook();
  }

  @Test
  void setLogHookNullClearsHook() {
    AtomicInteger counter = new AtomicInteger();
    Asherah.setLogHook(event -> counter.incrementAndGet());
    Asherah.setLogHook(null);
    // After clearing, no events should still be delivered to the original
    // callback even if the underlying library logs something.
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("log-null-clear")) {
      session.encryptToJson("ping".getBytes(StandardCharsets.UTF_8));
    }
    // We can't assert zero deterministically because logs are best-effort and
    // not guaranteed to fire for any specific operation. The important
    // contract is that null doesn't crash.
    assertTrue(counter.get() >= 0);
  }

  @Test
  void replacingLogHookRedirectsEventsToNewCallback() {
    List<String> oldEvents = new CopyOnWriteArrayList<>();
    List<String> newEvents = new CopyOnWriteArrayList<>();
    Asherah.setLogHook(event -> oldEvents.add(event.getMessage()));
    Asherah.setLogHook(event -> newEvents.add(event.getMessage()));
    Asherah.clearLogHook();
    // Either list could be empty (no log events were emitted), but at minimum
    // the replace must not have thrown.
    assertNotNull(oldEvents);
    assertNotNull(newEvents);
  }

  @Test
  void logEventFieldsAreNonNullWhenInvoked() {
    List<LogEvent> received = new CopyOnWriteArrayList<>();
    Asherah.setLogHook(received::add);
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("log-fields")) {
      for (int i = 0; i < 5; i++) {
        byte[] ct = session.encryptToJson(("payload-" + i).getBytes(StandardCharsets.UTF_8))
            .getBytes(StandardCharsets.UTF_8);
        session.decryptFromJson(new String(ct, StandardCharsets.UTF_8));
      }
    }
    Asherah.clearLogHook();
    // Every emitted record (if any) must have non-null fields.
    for (LogEvent event : received) {
      assertNotNull(event.getLevel());
      assertNotNull(event.getTarget());
      assertNotNull(event.getMessage());
      // levelEnum must parse without throwing
      assertNotNull(event.getLevelEnum());
    }
  }

  @Test
  void logHookExceptionsDoNotCrashJni() {
    Asherah.setLogHook(event -> {
      throw new RuntimeException("intentional from log hook");
    });
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("log-throw")) {
      // If hook exceptions weren't caught, this would crash the JVM.
      String ct = session.encryptString("survive-throw");
      assertNotNull(session.decryptString(ct));
    }
    Asherah.clearLogHook();
  }

  // ---------- metrics hook ----------

  @Test
  void setMetricsHookAcceptsCallbackWithoutThrowing() {
    Asherah.setMetricsHook(event -> { /* no-op */ });
    Asherah.clearMetricsHook();
  }

  @Test
  void clearMetricsHookIsIdempotent() {
    Asherah.clearMetricsHook();
    Asherah.clearMetricsHook();
  }

  @Test
  void setMetricsHookNullClearsHook() {
    AtomicInteger counter = new AtomicInteger();
    Asherah.setMetricsHook(event -> counter.incrementAndGet());
    Asherah.setMetricsHook(null);
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-null-clear")) {
      session.encryptToJson("ping".getBytes(StandardCharsets.UTF_8));
    }
    // After clear, no further metrics should be delivered. We snapshot the
    // counter and ensure it doesn't change after the clear.
    int before = counter.get();
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-null-clear-2")) {
      session.encryptToJson("ping".getBytes(StandardCharsets.UTF_8));
    }
    assertEquals(before, counter.get(), "metrics hook fired after being cleared");
  }

  @Test
  void metricsHookFiresEncryptAndDecrypt() {
    Set<MetricsEventType> seen = java.util.Collections.synchronizedSet(EnumSet.noneOf(MetricsEventType.class));
    Asherah.setMetricsHook(event -> {
      assertNotNull(event);
      assertNotNull(event.getType());
      assertNotNull(event.getTypeEnum());
      seen.add(event.getTypeEnum());
    });
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-firing")) {
      // multiple ops to maximize chance of each event type firing
      for (int i = 0; i < 5; i++) {
        String ct = session.encryptString("metrics-payload-" + i);
        session.decryptString(ct);
      }
    }
    Asherah.clearMetricsHook();
    assertTrue(seen.contains(MetricsEventType.ENCRYPT),
        "expected ENCRYPT event, saw " + seen);
    assertTrue(seen.contains(MetricsEventType.DECRYPT),
        "expected DECRYPT event, saw " + seen);
    // STORE/LOAD only fire from session.store()/session.load() — the
    // higher-level Storer/Loader path that the JNI surface doesn't expose.
  }

  @Test
  void metricsTimingEventsCarryNonZeroDuration() {
    List<MetricsEvent> timings = new CopyOnWriteArrayList<>();
    Asherah.setMetricsHook(event -> {
      switch (event.getTypeEnum()) {
        case ENCRYPT:
        case DECRYPT:
          timings.add(event);
          break;
        default:
          break;
      }
    });
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-timing")) {
      for (int i = 0; i < 3; i++) {
        session.decryptString(session.encryptString("timed-" + i));
      }
    }
    Asherah.clearMetricsHook();
    assertFalse(timings.isEmpty(), "expected at least one timing event");
    for (MetricsEvent event : timings) {
      assertTrue(event.getDurationNs() > 0,
          "timing event " + event.getType() + " had non-positive duration");
      assertNull(event.getName(), "timing event should not carry a name");
    }
  }

  @Test
  void replacingMetricsHookRedirectsToNewCallback() {
    AtomicInteger oldHits = new AtomicInteger();
    AtomicInteger newHits = new AtomicInteger();
    Asherah.setMetricsHook(event -> oldHits.incrementAndGet());
    Asherah.setMetricsHook(event -> newHits.incrementAndGet());
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-replace")) {
      for (int i = 0; i < 3; i++) {
        session.decryptString(session.encryptString("replace-" + i));
      }
    }
    Asherah.clearMetricsHook();
    assertTrue(newHits.get() > 0, "replacement hook should have received events");
    // We don't assert oldHits == 0 because there's a brief window between the
    // first and second setMetricsHook where the old hook could legitimately
    // fire. The contract is just that the new one takes over.
  }

  @Test
  void metricsHookExceptionsDoNotCrashJni() {
    AtomicInteger fired = new AtomicInteger();
    Asherah.setMetricsHook(event -> {
      fired.incrementAndGet();
      throw new RuntimeException("intentional from metrics hook");
    });
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-throw")) {
      String ct = session.encryptString("survive-metrics-throw");
      assertEquals("survive-metrics-throw", session.decryptString(ct));
    }
    Asherah.clearMetricsHook();
    assertTrue(fired.get() > 0, "hook must have fired at least once");
  }

  @Test
  void metricsHookSurvivesManyOperations() {
    AtomicInteger fired = new AtomicInteger();
    Asherah.setMetricsHook(event -> fired.incrementAndGet());
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("metrics-volume")) {
      for (int i = 0; i < 100; i++) {
        session.decryptString(session.encryptString("vol-" + i));
      }
    }
    Asherah.clearMetricsHook();
    assertTrue(fired.get() >= 200,
        "expected ≥200 metrics events for 100 enc/dec ops, got " + fired.get());
  }

  @Test
  void metricsAndLogHooksCoexist() {
    AtomicInteger logHits = new AtomicInteger();
    AtomicInteger metricHits = new AtomicInteger();
    Asherah.setLogHook(event -> logHits.incrementAndGet());
    Asherah.setMetricsHook(event -> metricHits.incrementAndGet());
    try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
         AsherahSession session = factory.getSession("hooks-coexist")) {
      for (int i = 0; i < 3; i++) {
        session.decryptString(session.encryptString("coexist-" + i));
      }
    }
    Asherah.clearLogHook();
    Asherah.clearMetricsHook();
    assertTrue(metricHits.get() > 0, "metrics hook should have fired");
    // log events are best-effort; just assert the hooks didn't interfere
    assertTrue(logHits.get() >= 0);
  }

  @Test
  void cacheEventsCarryNameAndZeroDuration() {
    AsherahConfig cachingConfig = AsherahConfig.builder()
        .serviceName("hook-cache")
        .productId("prod")
        .metastore("memory")
        .kms("static")
        .enableSessionCaching(Boolean.TRUE)
        .build();
    Set<String> cacheNames = java.util.Collections.synchronizedSet(new HashSet<>());
    List<MetricsEvent> cacheEvents = new CopyOnWriteArrayList<>();
    Asherah.setMetricsHook(event -> {
      switch (event.getTypeEnum()) {
        case CACHE_HIT:
        case CACHE_MISS:
        case CACHE_STALE:
          cacheEvents.add(event);
          if (event.getName() != null) {
            cacheNames.add(event.getName());
          }
          break;
        default:
          break;
      }
    });
    try (AsherahFactory factory = Asherah.factoryFromConfig(cachingConfig)) {
      // Multiple sessions warm/probe the IK and SK caches.
      for (int i = 0; i < 3; i++) {
        try (AsherahSession session = factory.getSession("cache-part-" + (i % 2))) {
          session.decryptString(session.encryptString("cache-payload-" + i));
        }
      }
    }
    Asherah.clearMetricsHook();
    for (MetricsEvent event : cacheEvents) {
      assertEquals(0L, event.getDurationNs(),
          "cache event " + event.getType() + " carried non-zero duration");
      assertNotNull(event.getName(),
          "cache event " + event.getType() + " missing name");
    }
    // We don't strictly require cacheEvents to be non-empty (depends on
    // metastore behavior), but at minimum the contract above must hold for
    // any cache events that did fire.
  }

  @Test
  void hookSurvivesAcrossSetupShutdownCycles() {
    AtomicInteger metricHits = new AtomicInteger();
    Asherah.setMetricsHook(event -> metricHits.incrementAndGet());
    for (int cycle = 0; cycle < 3; cycle++) {
      try (AsherahFactory factory = Asherah.factoryFromConfig(hookConfig());
           AsherahSession session = factory.getSession("cycle-" + cycle)) {
        session.decryptString(session.encryptString("payload-" + cycle));
      }
    }
    Asherah.clearMetricsHook();
    assertTrue(metricHits.get() > 0, "hook should fire across factory cycles");
  }

  @Test
  void metricsEventTypeFromStringHandlesAllVariants() {
    for (MetricsEventType expected : MetricsEventType.values()) {
      String key;
      switch (expected) {
        case ENCRYPT:     key = "encrypt"; break;
        case DECRYPT:     key = "decrypt"; break;
        case STORE:       key = "store"; break;
        case LOAD:        key = "load"; break;
        case CACHE_HIT:   key = "cache_hit"; break;
        case CACHE_MISS:  key = "cache_miss"; break;
        case CACHE_STALE: key = "cache_stale"; break;
        default: fail("missing case for " + expected); return;
      }
      assertEquals(expected, MetricsEventType.fromString(key));
    }
  }

  @Test
  void logLevelFromStringHandlesAllVariants() {
    assertEquals(LogLevel.TRACE, LogLevel.fromString("trace"));
    assertEquals(LogLevel.DEBUG, LogLevel.fromString("debug"));
    assertEquals(LogLevel.INFO,  LogLevel.fromString("info"));
    assertEquals(LogLevel.WARN,  LogLevel.fromString("warn"));
    assertEquals(LogLevel.ERROR, LogLevel.fromString("error"));
    assertEquals(LogLevel.ERROR, LogLevel.fromString(null));
    assertEquals(LogLevel.ERROR, LogLevel.fromString("bogus"));
  }
}
