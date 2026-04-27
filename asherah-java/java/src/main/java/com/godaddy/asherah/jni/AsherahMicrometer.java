package com.godaddy.asherah.jni;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Bridges Asherah {@link MetricsEvent} records to a Micrometer
 * {@link MeterRegistry}. The bridge creates standard instruments on the
 * supplied registry and forwards each event to the appropriate one:
 *
 * <ul>
 *   <li>{@code asherah.encrypt.duration} (Timer) — {@code PublicSession.encrypt()}</li>
 *   <li>{@code asherah.decrypt.duration} (Timer) — {@code PublicSession.decrypt()}</li>
 *   <li>{@code asherah.store.duration}   (Timer) — metastore store</li>
 *   <li>{@code asherah.load.duration}    (Timer) — metastore load</li>
 *   <li>{@code asherah.cache.hits}       (Counter, tag {@code cache=name})</li>
 *   <li>{@code asherah.cache.misses}     (Counter, tag {@code cache=name})</li>
 *   <li>{@code asherah.cache.stale}      (Counter, tag {@code cache=name})</li>
 * </ul>
 *
 * <p>OpenTelemetry, Prometheus, Datadog, and CloudWatch registries all consume
 * from a {@code MeterRegistry} unchanged. Typical use:
 *
 * <pre>
 *   MeterRegistry registry = ...; // Spring/Micronaut/Quarkus injected
 *   Asherah.setMetricsHook(AsherahMicrometer.metricsHook(registry));
 * </pre>
 *
 * <p>This class is loaded only when the caller references it; callers who do
 * not use Micrometer can omit {@code micrometer-core} from their classpath.
 */
public final class AsherahMicrometer {
    private AsherahMicrometer() {}

    /**
     * Build an {@link AsherahMetricsHook} that forwards events to the supplied
     * registry. Pass the result to {@link Asherah#setMetricsHook(AsherahMetricsHook)}.
     */
    public static AsherahMetricsHook metricsHook(final MeterRegistry registry) {
        Objects.requireNonNull(registry, "registry");
        final Timer encryptTimer = Timer.builder("asherah.encrypt.duration")
                .description("Time spent in PublicSession.encrypt()")
                .register(registry);
        final Timer decryptTimer = Timer.builder("asherah.decrypt.duration")
                .description("Time spent in PublicSession.decrypt()")
                .register(registry);
        final Timer storeTimer = Timer.builder("asherah.store.duration")
                .description("Time spent storing an envelope key in the metastore")
                .register(registry);
        final Timer loadTimer = Timer.builder("asherah.load.duration")
                .description("Time spent loading an envelope key from the metastore")
                .register(registry);
        return event -> {
            switch (event.getTypeEnum()) {
                case ENCRYPT:
                    encryptTimer.record(event.getDurationNs(), TimeUnit.NANOSECONDS);
                    break;
                case DECRYPT:
                    decryptTimer.record(event.getDurationNs(), TimeUnit.NANOSECONDS);
                    break;
                case STORE:
                    storeTimer.record(event.getDurationNs(), TimeUnit.NANOSECONDS);
                    break;
                case LOAD:
                    loadTimer.record(event.getDurationNs(), TimeUnit.NANOSECONDS);
                    break;
                case CACHE_HIT:
                    Counter.builder("asherah.cache.hits")
                            .tags(Tags.of("cache", nullSafe(event.getName())))
                            .register(registry)
                            .increment();
                    break;
                case CACHE_MISS:
                    Counter.builder("asherah.cache.misses")
                            .tags(Tags.of("cache", nullSafe(event.getName())))
                            .register(registry)
                            .increment();
                    break;
                case CACHE_STALE:
                    Counter.builder("asherah.cache.stale")
                            .tags(Tags.of("cache", nullSafe(event.getName())))
                            .register(registry)
                            .increment();
                    break;
                default:
                    break;
            }
        };
    }

    private static String nullSafe(final String s) {
        return s == null ? "" : s;
    }
}
