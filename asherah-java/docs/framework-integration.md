# Framework integration

How to wire Asherah into common Java frameworks. Pattern is
consistent across them: **build a `AsherahFactory` at startup
(typically as a singleton/Bean), use try-with-resources for sessions,
close the factory on graceful shutdown.**

## Spring Boot

`AsherahFactory` as a `@Bean`, scoped singleton:

```java
import com.godaddy.asherah.jni.*;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.event.EventListener;

@Configuration
public class AsherahConfiguration {

    @Bean
    public AsherahConfig asherahConfig(@Value("${asherah.serviceName}") String svc,
                                        @Value("${asherah.productId}") String prod,
                                        @Value("${asherah.dynamoDbTable}") String table,
                                        @Value("${asherah.region}") String region,
                                        @Value("#{${asherah.regionMap}}") Map<String, String> regionMap) {
        return AsherahConfig.builder()
            .serviceName(svc)
            .productId(prod)
            .metastore("dynamodb")
            .dynamoDbTableName(table)
            .dynamoDbRegion(region)
            .kms("aws")
            .regionMap(regionMap)
            .preferredRegion(region)
            .enableSessionCaching(Boolean.TRUE)
            .build();
    }

    @Bean(destroyMethod = "close")
    public AsherahFactory asherahFactory(AsherahConfig cfg) {
        return Asherah.factoryFromConfig(cfg);
    }

    @EventListener(ApplicationStartedEvent.class)
    public void wireHooks() {
        var log = org.slf4j.LoggerFactory.getLogger("asherah");
        Asherah.setLogHook(evt ->
            log.atLevel(evt.getLevel())
               .addKeyValue("target", evt.getTarget())
               .log(evt.getMessage())
        );
    }
}
```

Inject `AsherahFactory` into your services:

```java
@Service
public class EnvelopeService {
    private final AsherahFactory factory;

    public EnvelopeService(AsherahFactory factory) {
        this.factory = factory;
    }

    public String protect(String partitionId, String plaintext) {
        try (AsherahSession session = factory.getSession(partitionId)) {
            return session.encryptString(plaintext);
        }
    }

    public String unprotect(String partitionId, String ciphertext) {
        try (AsherahSession session = factory.getSession(partitionId)) {
            return session.decryptString(ciphertext);
        }
    }
}
```

The `destroyMethod = "close"` on the `@Bean` ensures Spring closes the
factory on application shutdown.

### Spring WebFlux (reactive)

```java
@Service
public class ReactiveEnvelopeService {
    private final AsherahFactory factory;

    public ReactiveEnvelopeService(AsherahFactory factory) {
        this.factory = factory;
    }

    public Mono<String> protect(String partitionId, String plaintext) {
        return Mono.using(
            () -> factory.getSession(partitionId),
            session -> Mono.fromFuture(session.encryptStringAsync(plaintext)),
            AsherahSession::close
        );
    }
}
```

`Mono.using` ensures session.close() runs after the future completes
or errors. The `*Async` methods return `CompletableFuture` which
`Mono.fromFuture` wraps non-blockingly.

## Micronaut

```java
import jakarta.inject.Singleton;
import jakarta.annotation.PreDestroy;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.runtime.event.annotation.EventListener;

@Factory
public class AsherahFactoryConfiguration {

    @Singleton
    AsherahConfig asherahConfig() {
        // ... build config from @Value or @ConfigurationProperties
    }

    @Singleton
    AsherahFactory asherahFactory(AsherahConfig cfg) {
        return Asherah.factoryFromConfig(cfg);
    }
}

@Singleton
public class AsherahLifecycle {
    private final AsherahFactory factory;

    public AsherahLifecycle(AsherahFactory factory) {
        this.factory = factory;
    }

    @EventListener
    public void onStartup(StartupEvent event) {
        var log = org.slf4j.LoggerFactory.getLogger("asherah");
        Asherah.setLogHook(evt -> log.atLevel(evt.getLevel())
                                      .log(evt.getMessage()));
    }

    @PreDestroy
    public void shutdown() {
        factory.close();
        Asherah.clearLogHook();
    }
}
```

## Quarkus

Quarkus's CDI works similarly. Mark the producer `@ApplicationScoped`
and use `@PreDestroy` for cleanup:

```java
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.annotation.PreDestroy;

@ApplicationScoped
public class AsherahProducer {
    private AsherahFactory factory;

    @Produces
    @ApplicationScoped
    AsherahFactory factory() {
        AsherahConfig cfg = AsherahConfig.builder()
            .serviceName(System.getenv("SERVICE_NAME"))
            .productId(System.getenv("PRODUCT_ID"))
            // ...
            .build();
        factory = Asherah.factoryFromConfig(cfg);
        return factory;
    }

    @PreDestroy
    void shutdown() {
        if (factory != null) factory.close();
    }
}
```

## Vert.x

Vert.x verticles can hold the factory as a verticle field, deploy
once at app startup:

```java
public class EnvelopeVerticle extends AbstractVerticle {
    private AsherahFactory factory;

    @Override
    public void start(Promise<Void> startPromise) {
        factory = Asherah.factoryFromConfig(buildConfig());

        var router = Router.router(vertx);
        router.post("/protect").handler(BodyHandler.create()).handler(ctx -> {
            String tenantId = ctx.request().getHeader("X-Tenant-Id");
            String plaintext = ctx.body().asString();

            // Run encrypt off the event loop — Asherah's *Async runs on
            // its own tokio runtime, but the result completion happens
            // on a JVM thread; vertx.executeBlocking keeps everything
            // on a worker pool clean.
            vertx.executeBlocking(() -> {
                try (AsherahSession session = factory.getSession(tenantId)) {
                    return session.encryptString(plaintext);
                }
            }, false).onSuccess(ct -> ctx.json(Map.of("token", ct)))
                     .onFailure(ctx::fail);
        });

        vertx.createHttpServer().requestHandler(router).listen(8080)
             .onSuccess(s -> startPromise.complete())
             .onFailure(startPromise::fail);
    }

    @Override
    public void stop() {
        if (factory != null) factory.close();
    }
}
```

## Servlet / Jakarta EE

```java
@WebListener
public class AsherahLifecycleListener implements ServletContextListener {
    private static AsherahFactory factory;

    public static AsherahFactory factory() { return factory; }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        AsherahConfig cfg = AsherahConfig.builder()
            // ... build from JNDI / system properties
            .build();
        factory = Asherah.factoryFromConfig(cfg);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        if (factory != null) factory.close();
    }
}

@WebServlet("/protect")
public class ProtectServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String tenantId = req.getHeader("X-Tenant-Id");
        String plaintext = req.getReader().lines().collect(Collectors.joining());
        try (AsherahSession session = AsherahLifecycleListener.factory().getSession(tenantId)) {
            resp.setContentType("application/json");
            resp.getWriter().write("{\"token\":\"" + session.encryptString(plaintext) + "\"}");
        }
    }
}
```

## SLF4J integration

`event.getLevel()` returns `org.slf4j.event.Level` directly — pass it
through:

```java
Logger log = LoggerFactory.getLogger("asherah");

Asherah.setLogHook(evt -> log.atLevel(evt.getLevel())
                              .addKeyValue("target", evt.getTarget())
                              .log(evt.getMessage()));
```

This is cleanest with SLF4J 2.0+'s fluent API. For 1.x:

```java
Asherah.setLogHook(evt -> {
    switch (evt.getLevel()) {
        case ERROR: log.error("{}: {}", evt.getTarget(), evt.getMessage()); break;
        case WARN:  log.warn("{}: {}", evt.getTarget(), evt.getMessage()); break;
        case INFO:  log.info("{}: {}", evt.getTarget(), evt.getMessage()); break;
        case DEBUG: log.debug("{}: {}", evt.getTarget(), evt.getMessage()); break;
        case TRACE: log.trace("{}: {}", evt.getTarget(), evt.getMessage()); break;
    }
});
```

## Micrometer / OpenTelemetry metrics

```java
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

public class AsherahMicrometerBridge {
    public static void wire(MeterRegistry registry) {
        Timer encrypt = Timer.builder("asherah.encrypt.duration").register(registry);
        Timer decrypt = Timer.builder("asherah.decrypt.duration").register(registry);
        // ... store/load similarly

        Asherah.setMetricsHook(evt -> {
            switch (evt.getType()) {
                case ENCRYPT: encrypt.record(evt.getDurationNs(), TimeUnit.NANOSECONDS); break;
                case DECRYPT: decrypt.record(evt.getDurationNs(), TimeUnit.NANOSECONDS); break;
                case CACHE_HIT:
                    registry.counter("asherah.cache.hits", "cache", evt.getName()).increment();
                    break;
                // CACHE_MISS / CACHE_STALE / STORE / LOAD similarly
            }
        });
    }
}
```

For OpenTelemetry's metrics SDK the integration is the same shape —
create instruments at startup, dispatch on `evt.getType()`.
