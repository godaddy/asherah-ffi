import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;
import com.godaddy.asherah.jni.AsherahFactory;
import com.godaddy.asherah.jni.AsherahSession;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

public class Sample {
    public static void main(String[] args) throws Exception {
        // Memory metastore + static KMS — testing only.
        // See production config at the bottom of this file.
        AsherahConfig config = AsherahConfig.builder()
                .serviceName("sample-service")
                .productId("sample-product")
                .metastore("memory")
                .kms("static")             // testing only — use "aws" in production
                .enableSessionCaching(Boolean.TRUE)
                .build();

        // -- 1. Static API: setup / encryptString / decryptString / shutdown --
        Asherah.setup(config);
        try {
            String ciphertext = Asherah.encryptString("sample-partition", "Hello, static API!");
            System.out.println("Static encrypt OK: " + ciphertext.substring(0, 60) + "...");

            String recovered = Asherah.decryptString("sample-partition", ciphertext);
            System.out.println("Static decrypt OK: " + recovered);
        } finally {
            Asherah.shutdown();
        }

        // -- 2. Factory/Session API: factoryFromConfig / getSession / encryptBytes / decryptBytes --
        try (AsherahFactory factory = Asherah.factoryFromConfig(config)) {
            try (AsherahSession session = factory.getSession("sample-partition")) {
                byte[] plaintext = "Hello, session API!".getBytes(StandardCharsets.UTF_8);
                byte[] encrypted = session.encryptBytes(plaintext);
                System.out.println("Session encrypt OK: " + encrypted.length + " bytes");

                byte[] decrypted = session.decryptBytes(encrypted);
                System.out.println("Session decrypt OK: " + new String(decrypted, StandardCharsets.UTF_8));
            }
        }

        // -- 3. Async API: encryptStringAsync / decryptStringAsync --
        Asherah.setup(config);
        try {
            CompletableFuture<String> encFuture = Asherah.encryptStringAsync("sample-partition", "Hello, async!");
            String asyncCipher = encFuture.get();
            System.out.println("Async encrypt OK: " + asyncCipher.substring(0, 60) + "...");

            CompletableFuture<String> decFuture = Asherah.decryptStringAsync("sample-partition", asyncCipher);
            String asyncPlain = decFuture.get();
            System.out.println("Async decrypt OK: " + asyncPlain);
        } finally {
            Asherah.shutdown();
        }
    }

    // -- 4. Production config (commented out) --
    // AsherahConfig prodConfig = AsherahConfig.builder()
    //         .serviceName("my-service")
    //         .productId("my-product")
    //         .metastore("dynamodb")              // or "mysql", "postgres"
    //         .kms("aws")
    //         .regionMap(Map.of("us-west-2", "arn:aws:kms:us-west-2:..."))
    //         .preferredRegion("us-west-2")
    //         .enableRegionSuffix(Boolean.TRUE)
    //         .enableSessionCaching(Boolean.TRUE)
    //         .build();
}
