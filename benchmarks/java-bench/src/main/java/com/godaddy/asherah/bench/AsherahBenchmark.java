package com.godaddy.asherah.bench;

import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 3)
@Fork(1)
public class AsherahBenchmark {

    @Param({"64", "1024", "8192"})
    int payloadSize;

    private byte[] payload;
    private byte[] ciphertext;
    private String[] partitionPool;
    private byte[][] ciphertextPool;
    private int encryptPoolIndex;
    private int decryptPoolIndex;
    private String benchmarkMode;

    private static String resolveMode() {
        String mode = System.getProperty("bench.mode");
        if (mode == null || mode.isBlank()) {
            mode = System.getenv("BENCH_MODE");
        }
        if (mode == null || mode.isBlank()) {
            mode = "memory";
        }
        mode = mode.trim().toLowerCase();
        if (!mode.equals("memory") && !mode.equals("hot") && !mode.equals("warm") && !mode.equals("cold")) {
            throw new IllegalArgumentException("invalid benchmark mode '" + mode + "' (expected memory/hot/warm/cold)");
        }
        return mode;
    }

    private static String resolveMysqlUrl() {
        String url = System.getProperty("bench.mysql.url");
        if (url == null || url.isBlank()) {
            url = System.getenv("BENCH_MYSQL_URL");
        }
        if (url == null || url.isBlank()) {
            url = System.getenv("MYSQL_URL");
        }
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("non-memory modes require -Dbench.mysql.url or BENCH_MYSQL_URL/MYSQL_URL");
        }
        return url;
    }

    private static int readIntWithFallback(String propKey, String envKey, int defaultValue) {
        String value = System.getProperty(propKey);
        if (value == null || value.isBlank()) {
            value = System.getenv(envKey);
        }
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1) {
                throw new IllegalArgumentException(propKey + " must be >= 1");
            }
            return parsed;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid integer for " + propKey + "/" + envKey + ": " + value, ex);
        }
    }

    @Setup(Level.Trial)
    public void setup() {
        System.setProperty("asherah.java.nativeLibraryPath",
            System.getProperty("native.lib.path", "target/release"));

        benchmarkMode = resolveMode();
        boolean enableSessionCaching = !benchmarkMode.equals("cold");
        AsherahConfig.Builder cfgBuilder = AsherahConfig.builder()
            .serviceName("bench-svc")
            .productId("bench-prod")
            .kms("static")
            .enableSessionCaching(enableSessionCaching);

        if (benchmarkMode.equals("hot")) {
            cfgBuilder.metastore("rdbms").connectionString(resolveMysqlUrl());
            System.out.println("mode: hot (MySQL hot-cache)");
        } else if (benchmarkMode.equals("warm")) {
            cfgBuilder
                .metastore("rdbms")
                .connectionString(resolveMysqlUrl())
                .sessionCacheMaxSize(readIntWithFallback("bench.warm.session.cache.max", "BENCH_WARM_SESSION_CACHE_MAX", 4096));
            System.out.println("mode: warm (MySQL, SK cached + IK miss)");
        } else if (benchmarkMode.equals("cold")) {
            cfgBuilder.metastore("rdbms").connectionString(resolveMysqlUrl());
            System.out.println("mode: cold (MySQL, SK-only cache)");
        } else {
            cfgBuilder.metastore("memory");
            System.out.println("mode: memory (in-memory hot-cache)");
        }
        AsherahConfig config = cfgBuilder.build();

        System.setProperty("STATIC_MASTER_KEY_HEX",
            "2222222222222222222222222222222222222222222222222222222222222222");
        System.setProperty("SERVICE_NAME", "bench-svc");
        System.setProperty("PRODUCT_ID", "bench-prod");
        System.setProperty("KMS", "static");

        Asherah.setup(config);

        payload = new byte[payloadSize];
        new Random(12345).nextBytes(payload);

        if (!benchmarkMode.equals("cold")) {
            ciphertext = Asherah.encrypt("bench-partition", payload);
            byte[] decrypted = Asherah.decrypt("bench-partition", ciphertext);
            if (!Arrays.equals(payload, decrypted)) {
                throw new RuntimeException("Round-trip verification failed for " + payloadSize + "B");
            }
            partitionPool = null;
            ciphertextPool = null;
            return;
        }

        int poolSize = readIntWithFallback("bench.partition.pool", "BENCH_PARTITION_POOL", 2048);
        partitionPool = new String[poolSize];
        ciphertextPool = new byte[poolSize][];
        for (int i = 0; i < poolSize; i++) {
            String partition = "bench-" + benchmarkMode + "-" + payloadSize + "-" + i;
            partitionPool[i] = partition;
            ciphertextPool[i] = Asherah.encrypt(partition, payload);
        }
        byte[] decrypted = Asherah.decrypt(partitionPool[0], ciphertextPool[0]);
        if (!Arrays.equals(payload, decrypted)) {
            throw new RuntimeException("Round-trip verification failed for " + payloadSize + "B");
        }
        encryptPoolIndex = 0;
        decryptPoolIndex = 0;
    }

    @TearDown(Level.Trial)
    public void teardown() {
        Asherah.shutdown();
    }

    @Benchmark
    public byte[] encrypt() {
        if (benchmarkMode.equals("cold")) {
            int idx = encryptPoolIndex;
            encryptPoolIndex = (encryptPoolIndex + 1) % partitionPool.length;
            return Asherah.encrypt(partitionPool[idx], payload);
        }
        return Asherah.encrypt("bench-partition", payload);
    }

    @Benchmark
    public byte[] decrypt() {
        if (benchmarkMode.equals("cold")) {
            int idx = decryptPoolIndex;
            decryptPoolIndex = (decryptPoolIndex + 1) % partitionPool.length;
            return Asherah.decrypt(partitionPool[idx], ciphertextPool[idx]);
        }
        return Asherah.decrypt("bench-partition", ciphertext);
    }

    public static void main(String[] args) throws Exception {
        boolean useMemory = false;
        boolean useHot = false;
        boolean useWarm = false;
        boolean useCold = false;
        String mysqlUrl = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--memory")) {
                useMemory = true;
            } else if (arg.equals("--hot")) {
                useHot = true;
            } else if (arg.equals("--warm")) {
                useWarm = true;
            } else if (arg.equals("--cold")) {
                useCold = true;
            } else if (arg.equals("--mysql-url")) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("--mysql-url requires a value");
                }
                mysqlUrl = args[++i];
            } else if (arg.startsWith("--mysql-url=")) {
                mysqlUrl = arg.substring("--mysql-url=".length());
            }
        }
        int selectedModes = (useMemory ? 1 : 0) + (useHot ? 1 : 0) + (useWarm ? 1 : 0) + (useCold ? 1 : 0);
        if (selectedModes > 1) {
            throw new IllegalArgumentException("only one of --memory, --hot, --warm, or --cold may be set");
        }
        if (useHot) {
            System.setProperty("bench.mode", "hot");
        } else if (useWarm) {
            System.setProperty("bench.mode", "warm");
        } else if (useCold) {
            System.setProperty("bench.mode", "cold");
        } else if (useMemory) {
            System.setProperty("bench.mode", "memory");
        }
        if (mysqlUrl != null && !mysqlUrl.isBlank()) {
            System.setProperty("bench.mysql.url", mysqlUrl);
        }

        Options opt = new OptionsBuilder()
            .include(AsherahBenchmark.class.getSimpleName())
            .jvmArgsAppend(
                "-Dbench.mode=" + System.getProperty("bench.mode", resolveMode()),
                "-Dbench.mysql.url=" + System.getProperty("bench.mysql.url", ""),
                "-Dbench.partition.pool=" + System.getProperty(
                    "bench.partition.pool",
                    System.getenv().getOrDefault("BENCH_PARTITION_POOL", "2048")
                ),
                "-Dbench.warm.session.cache.max=" + System.getProperty(
                    "bench.warm.session.cache.max",
                    System.getenv().getOrDefault("BENCH_WARM_SESSION_CACHE_MAX", "4096")
                )
            )
            .build();
        new Runner(opt).run();
    }
}
