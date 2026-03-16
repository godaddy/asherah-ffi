package com.godaddy.asherah.bench;

import com.godaddy.asherah.appencryption.Session;
import com.godaddy.asherah.appencryption.SessionFactory;
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
public class CanonicalBenchmark {

    @Param({"64", "1024", "8192"})
    int payloadSize;

    private SessionFactory factory;
    private Session<byte[], byte[]> session;
    private byte[] payload;
    private byte[] ciphertext;

    @Setup(Level.Trial)
    public void setup() {
        factory = SessionFactory
            .newBuilder("bench-prod", "bench-svc")
            .withInMemoryMetastore()
            .withNeverExpiredCryptoPolicy()
            .withStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .build();

        session = factory.getSessionBytes("bench-partition");

        payload = new byte[payloadSize];
        new Random(12345).nextBytes(payload);
        ciphertext = session.encrypt(payload);

        // Verify round-trip correctness
        byte[] decrypted = session.decrypt(ciphertext);
        if (!Arrays.equals(payload, decrypted)) {
            throw new RuntimeException("Round-trip verification failed for " + payloadSize + "B");
        }
    }

    @TearDown(Level.Trial)
    public void teardown() {
        if (session != null) session.close();
        if (factory != null) factory.close();
    }

    @Benchmark
    public byte[] encrypt() {
        return session.encrypt(payload);
    }

    @Benchmark
    public byte[] decrypt() {
        return session.decrypt(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
            .include(CanonicalBenchmark.class.getSimpleName())
            .build();
        new Runner(opt).run();
    }
}
