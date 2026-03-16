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

    @Setup(Level.Trial)
    public void setup() {
        System.setProperty("asherah.java.nativeLibraryPath",
            System.getProperty("native.lib.path", "target/release"));

        AsherahConfig config = AsherahConfig.builder()
            .serviceName("bench-svc")
            .productId("bench-prod")
            .metastore("memory")
            .kms("static")
            .enableSessionCaching(true)
            .build();

        System.setProperty("STATIC_MASTER_KEY_HEX",
            "2222222222222222222222222222222222222222222222222222222222222222");
        System.setProperty("SERVICE_NAME", "bench-svc");
        System.setProperty("PRODUCT_ID", "bench-prod");
        System.setProperty("KMS", "static");

        Asherah.setup(config);

        payload = new byte[payloadSize];
        new Random(12345).nextBytes(payload);
        ciphertext = Asherah.encrypt("bench-partition", payload);

        // Verify round-trip correctness
        byte[] decrypted = Asherah.decrypt("bench-partition", ciphertext);
        if (!Arrays.equals(payload, decrypted)) {
            throw new RuntimeException("Round-trip verification failed for " + payloadSize + "B");
        }
    }

    @TearDown(Level.Trial)
    public void teardown() {
        Asherah.shutdown();
    }

    @Benchmark
    public byte[] encrypt() {
        return Asherah.encrypt("bench-partition", payload);
    }

    @Benchmark
    public byte[] decrypt() {
        return Asherah.decrypt("bench-partition", ciphertext);
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
            .include(AsherahBenchmark.class.getSimpleName())
            .build();
        new Runner(opt).run();
    }
}
