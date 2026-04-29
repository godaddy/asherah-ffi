# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode.

## In-memory + static-KMS JUnit 5 fixture

```java
import com.godaddy.asherah.jni.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.*;

public class AsherahTestFactoryExtension
        implements BeforeAllCallback, AfterAllCallback, ParameterResolver {

    private static final ExtensionContext.Namespace NS =
        ExtensionContext.Namespace.create(AsherahTestFactoryExtension.class);

    @Override
    public void beforeAll(ExtensionContext context) {
        System.setProperty("STATIC_MASTER_KEY_HEX", "22".repeat(32));
        AsherahConfig cfg = AsherahConfig.builder()
            .serviceName("test-svc")
            .productId("test-prod")
            .metastore("memory")
            .kms("static")
            .build();
        AsherahFactory factory = Asherah.factoryFromConfig(cfg);
        context.getStore(NS).put("factory", factory);
    }

    @Override
    public void afterAll(ExtensionContext context) {
        AsherahFactory f = context.getStore(NS).get("factory", AsherahFactory.class);
        if (f != null) f.close();
    }

    @Override
    public boolean supportsParameter(ParameterContext pc, ExtensionContext ec) {
        return pc.getParameter().getType() == AsherahFactory.class;
    }

    @Override
    public Object resolveParameter(ParameterContext pc, ExtensionContext ec) {
        return ec.getStore(NS).get("factory", AsherahFactory.class);
    }
}
```

Use as an extension that auto-injects `AsherahFactory` into test
methods:

```java
@ExtendWith(AsherahTestFactoryExtension.class)
class CardRepositoryTest {

    @Test
    void roundTrips(AsherahFactory factory) {
        try (AsherahSession session = factory.getSession("tenant-A")) {
            String ct = session.encryptString("4242 4242 4242 4242");
            Assertions.assertEquals("4242 4242 4242 4242", session.decryptString(ct));
        }
    }
}
```

## Spring Boot tests

```java
@SpringBootTest
@TestPropertySource(properties = {
    "asherah.serviceName=test-svc",
    "asherah.productId=test-prod",
    "asherah.metastore=memory",
    "asherah.kms=static"
})
class EnvelopeServiceIntegrationTest {

    @Autowired AsherahFactory factory;
    @Autowired EnvelopeService service;

    @Test
    void protectUnprotectRoundTrip() {
        String ct = service.protect("tenant-A", "secret");
        Assertions.assertEquals("secret", service.unprotect("tenant-A", ct));
    }
}
```

The Spring test context handles factory lifecycle for you (auto-close
on context teardown thanks to `destroyMethod = "close"` on the
`@Bean`).

For static-master-key isolation between test classes, set
`STATIC_MASTER_KEY_HEX` in the test's `@TestPropertySource` or via
`@DynamicPropertySource`:

```java
@DynamicPropertySource
static void configureAsherah(DynamicPropertyRegistry registry) {
    registry.add("STATIC_MASTER_KEY_HEX", () -> "22".repeat(32));
}
```

## Mockito for unit tests of consumers

The cleanest pattern: build a thin wrapper around `AsherahFactory` in
your application code, mock the wrapper in unit tests:

```java
public interface Protector {
    String protect(String partitionId, String plaintext);
    String unprotect(String partitionId, String ciphertext);
}

@Component
public class AsherahProtector implements Protector {
    private final AsherahFactory factory;
    public AsherahProtector(AsherahFactory factory) { this.factory = factory; }

    @Override
    public String protect(String partitionId, String plaintext) {
        try (AsherahSession session = factory.getSession(partitionId)) {
            return session.encryptString(plaintext);
        }
    }

    @Override
    public String unprotect(String partitionId, String ciphertext) {
        try (AsherahSession session = factory.getSession(partitionId)) {
            return session.decryptString(ciphertext);
        }
    }
}
```

```java
@ExtendWith(MockitoExtension.class)
class OrderServiceTest {
    @Mock Protector protector;
    @InjectMocks OrderService orders;

    @Test
    void createCallsProtect() {
        when(protector.protect("merchant-7", "card data")).thenReturn("ct-token");

        orders.create("merchant-7", "card data");

        verify(protector).protect("merchant-7", "card data");
    }
}
```

The integration test of `AsherahProtector` itself uses the real
`AsherahTestFactoryExtension` factory; unit tests of consumers mock
`Protector` directly.

`AsherahFactory` and `AsherahSession` are concrete final classes — Mockito
can mock them with the inline mock-maker, but it's slower and brittle. Prefer
the wrapper-interface approach.

## Asserting envelope shape

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Test
void envelopeShape(AsherahFactory factory) throws Exception {
    try (AsherahSession session = factory.getSession("partition-1")) {
        String json = session.encryptString("hello");
        JsonNode env = new ObjectMapper().readTree(json);
        Assertions.assertTrue(env.has("Key"));
        Assertions.assertTrue(env.has("Data"));
        Assertions.assertTrue(env.path("Key").has("ParentKeyMeta"));
    }
}
```

## Async test patterns

```java
@Test
void asyncRoundTrip(AsherahFactory factory) throws Exception {
    try (AsherahSession session = factory.getSession("p")) {
        String ct = session.encryptStringAsync("hello").get(5, TimeUnit.SECONDS);
        Assertions.assertEquals("hello", session.decryptStringAsync(ct).get(5, TimeUnit.SECONDS));
    }
}
```

For reactive (WebFlux) tests:

```java
@Test
void reactiveRoundTrip() {
    StepVerifier.create(reactiveService.protect("p", "hello"))
        .assertNext(ct -> { /* assert non-empty, JSON shape, etc. */ })
        .verifyComplete();
}
```

## Hook tests run serially

Hooks are process-global. Tests exercising them must run serially —
parallel test runners race on hook state.

```java
@Execution(ExecutionMode.SAME_THREAD)
class HookTest {
    @Test
    void logHookFires(AsherahFactory factory) {
        var events = new java.util.concurrent.CopyOnWriteArrayList<LogEvent>();
        Asherah.setLogHook(events::add);
        try (AsherahSession session = factory.getSession("p")) {
            session.encryptString("hello");
        }
        // ...assert events
        Asherah.clearLogHook();
    }
}
```

Or set JUnit's parallel mode to opt-out at the class level.

## Testing with the SQL metastore (Testcontainers)

```java
@Testcontainers
class SqlMetastoreIntegrationTest {

    @Container
    MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0").withDatabaseName("asherah");

    AsherahFactory factory;

    @BeforeEach
    void setUp() {
        System.setProperty("STATIC_MASTER_KEY_HEX", "22".repeat(32));
        factory = Asherah.factoryFromConfig(AsherahConfig.builder()
            .serviceName("test-svc")
            .productId("test-prod")
            .metastore("rdbms")
            .connectionString(mysql.getJdbcUrl().replace("jdbc:", ""))
            .sqlMetastoreDbType("mysql")
            .kms("static")
            .build());
    }

    @AfterEach
    void tearDown() { factory.close(); }

    @Test
    void roundTripAgainstMysql() {
        try (AsherahSession session = factory.getSession("p")) {
            String ct = session.encryptString("hello");
            Assertions.assertEquals("hello", session.decryptString(ct));
        }
    }
}
```

Asherah's RDBMS metastore creates the schema on first use; no
Flyway/Liquibase migration step required.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** Ciphertext is
  non-deterministic — `encryptString("x")` produces a different
  envelope on every call. Don't compare ciphertext bytes; round-trip
  through `decryptString` and compare plaintexts.
- **Session caching.** `factory.getSession("p")` returns a cached
  session by default. Tests asserting per-call behaviour should set
  `enableSessionCaching(Boolean.FALSE)`.
- **Hooks are process-global.** Use `@Execution(ExecutionMode.SAME_THREAD)`
  for hook-touching tests and clear hooks in `@AfterEach`.

## Native library resolution in tests

The published JAR bundles native binaries. If tests fail with
`UnsatisfiedLinkError`:

- Check the OS/arch matches a bundled binary
  (`linux-x64`/`linux-arm64`/`linux-musl-x64`/`linux-musl-arm64`/
  `osx-x64`/`osx-arm64`/`win-x64`/`win-arm64`).
- For repo development with `cargo build`, set
  `ASHERAH_JAVA_NATIVE` to the directory containing your local
  `libasherah_jni.{dylib,so}`.
- Alpine/musl: ensure `libgcc` and `libstdc++` are installed
  (`apk add libgcc libstdc++`).
