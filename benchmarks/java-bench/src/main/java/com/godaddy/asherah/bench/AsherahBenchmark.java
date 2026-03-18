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
import java.util.concurrent.atomic.AtomicInteger;

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
    private boolean cold;
    private byte[] coldCt0;
    private byte[] coldCt1;
    private final AtomicInteger encCtr = new AtomicInteger(0);
    private final AtomicInteger decCtr = new AtomicInteger(0);

    @Setup(Level.Trial)
    public void setup() {
        System.setProperty("asherah.java.nativeLibraryPath",
            System.getProperty("native.lib.path", "target/release"));

        cold = "1".equals(System.getenv("BENCH_COLD"));

        String metastore = System.getenv("BENCH_METASTORE") != null
            ? System.getenv("BENCH_METASTORE") : "memory";
        AsherahConfig.Builder configBuilder = AsherahConfig.builder()
            .serviceName("bench-svc")
            .productId("bench-prod")
            .metastore(metastore)
            .kms("static")
            .enableSessionCaching(true);
        if (System.getenv("BENCH_CONNECTION_STRING") != null) {
            configBuilder.connectionString(System.getenv("BENCH_CONNECTION_STRING"));
        }
        if (System.getenv("BENCH_CHECK_INTERVAL") != null) {
            configBuilder.checkInterval(Long.parseLong(System.getenv("BENCH_CHECK_INTERVAL")));
        }
        AsherahConfig config = configBuilder.build();

        String masterKeyHex = System.getenv("STATIC_MASTER_KEY_HEX") != null
            ? System.getenv("STATIC_MASTER_KEY_HEX")
            : "746869734973415374617469634d61737465724b6579466f7254657374696e67";
        System.setProperty("STATIC_MASTER_KEY_HEX", masterKeyHex);
        System.setProperty("SERVICE_NAME", "bench-svc");
        System.setProperty("PRODUCT_ID", "bench-prod");
        System.setProperty("KMS", "static");

        Asherah.setup(config);

        payload = new byte[payloadSize];
        new Random(12345).nextBytes(payload);

        if (cold) {
            coldCt0 = Asherah.encrypt("cold-0", payload);
            coldCt1 = Asherah.encrypt("cold-1", payload);
            Asherah.decrypt("cold-0", coldCt0); // warm SK cache
        } else {
            ciphertext = Asherah.encrypt("bench-partition", payload);
            byte[] decrypted = Asherah.decrypt("bench-partition", ciphertext);
            if (!Arrays.equals(payload, decrypted)) {
                throw new RuntimeException("Round-trip verification failed for " + payloadSize + "B");
            }
        }
    }

    @TearDown(Level.Trial)
    public void teardown() {
        Asherah.shutdown();
    }

    @Benchmark
    public byte[] encrypt() {
        if (cold) {
            int i = encCtr.incrementAndGet();
            return Asherah.encrypt("cold-enc-" + i, payload);
        }
        return Asherah.encrypt("bench-partition", payload);
    }

    @Benchmark
    public byte[] decrypt() {
        if (cold) {
            int i = decCtr.incrementAndGet() % 2;
            return Asherah.decrypt("cold-" + i, i == 0 ? coldCt0 : coldCt1);
        }
        return Asherah.decrypt("bench-partition", ciphertext);
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
            .include(AsherahBenchmark.class.getSimpleName())
            .build();
        new Runner(opt).run();
    }
}
