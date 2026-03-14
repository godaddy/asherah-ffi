import com.godaddy.asherah.jni.Asherah;
import com.godaddy.asherah.jni.AsherahConfig;

public class Sample {
    public static void main(String[] args) {
        AsherahConfig config = AsherahConfig.builder()
                .serviceName("sample-service")
                .productId("sample-product")
                .metastore("memory")
                .kms("static")
                .enableSessionCaching(Boolean.TRUE)
                .build();

        Asherah.setup(config);
        try {
            // Encrypt
            String ciphertext = Asherah.encryptString("sample-partition", "Hello from Java!");
            System.out.println("Encrypted: " + ciphertext.substring(0, Math.min(80, ciphertext.length())) + "...");

            // Decrypt
            String recovered = Asherah.decryptString("sample-partition", ciphertext);
            System.out.println("Decrypted: " + recovered);
        } finally {
            Asherah.shutdown();
        }
    }
}
