// Probe canonical com.godaddy.asherah:appencryption to discover its actual
// behavior on null/empty inputs. Prints one line per probe in the form
// "<name>: <result>" so the Python interop test can assert on exact strings.
package probe;

import com.godaddy.asherah.appencryption.Session;
import com.godaddy.asherah.appencryption.SessionFactory;
import com.godaddy.asherah.appencryption.kms.StaticKeyManagementServiceImpl;
import com.godaddy.asherah.appencryption.persistence.InMemoryMetastoreImpl;
import com.godaddy.asherah.crypto.BasicExpiringCryptoPolicy;

public class Probe {
    public static void main(String[] args) {
        BasicExpiringCryptoPolicy policy = BasicExpiringCryptoPolicy.newBuilder()
            .withKeyExpirationDays(90)
            .withRevokeCheckMinutes(60)
            .build();

        // canonical static KMS expects a 32-byte UTF-8 string for AES-256
        StaticKeyManagementServiceImpl kms =
            new StaticKeyManagementServiceImpl("01234567890123456789012345678901");

        try (SessionFactory factory = SessionFactory.newBuilder("product", "service")
                .withInMemoryMetastore()
                .withCryptoPolicy(policy)
                .withKeyManagementService(kms)
                .build()) {

            // Warm-up: do a non-empty encrypt so the IK exists in the metastore.
            try (Session<byte[], byte[]> warm = factory.getSessionBytes("p1")) {
                warm.encrypt("warmup".getBytes());
            }

            probe("getSessionBytes_null_partition", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes(null)) {
                    return "accepted";
                }
            });

            probe("encrypt_with_null_partition_session", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes(null)) {
                    byte[] ct = s.encrypt("payload".getBytes());
                    return "accepted: drr=" + new String(ct);
                }
            });

            probe("getSessionBytes_empty_partition", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("")) {
                    return "accepted";
                }
            });

            probe("encrypt_with_empty_partition_session", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("")) {
                    byte[] ct = s.encrypt("payload".getBytes());
                    return "accepted: drr=" + new String(ct);
                }
            });

            probe("encrypt_null_bytes", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("p1")) {
                    byte[] ct = s.encrypt(null);
                    return "accepted: ct_len=" + (ct == null ? -1 : ct.length);
                }
            });

            probe("encrypt_empty_bytes", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("p1")) {
                    byte[] ct = s.encrypt(new byte[0]);
                    return "accepted: ct_len=" + ct.length;
                }
            });

            probe("roundtrip_empty_bytes", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("p1")) {
                    byte[] ct = s.encrypt(new byte[0]);
                    byte[] pt = s.decrypt(ct);
                    int ptLen = (pt == null ? -1 : pt.length);
                    return "recovered_len=" + ptLen + " null=" + (pt == null);
                }
            });

            probe("decrypt_null", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("p1")) {
                    byte[] pt = s.decrypt(null);
                    return "accepted: pt_len=" + (pt == null ? -1 : pt.length);
                }
            });

            probe("decrypt_empty_bytes", () -> {
                try (Session<byte[], byte[]> s = factory.getSessionBytes("p1")) {
                    byte[] pt = s.decrypt(new byte[0]);
                    return "accepted: pt_len=" + pt.length;
                }
            });
        }
    }

    interface Action { String run() throws Exception; }

    static void probe(String name, Action a) {
        try {
            String result = a.run();
            System.out.println(name + ": " + result);
        } catch (Throwable t) {
            Throwable inner = t.getCause();
            String innerStr = inner == null ? "" :
                " inner=" + inner.getClass().getSimpleName() + ": " + firstLine(String.valueOf(inner.getMessage()));
            System.out.println(name + ": ERROR: " + t.getClass().getSimpleName() + ": "
                + firstLine(String.valueOf(t.getMessage())) + innerStr);
        }
    }

    static String firstLine(String s) {
        if (s == null) return "null";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
