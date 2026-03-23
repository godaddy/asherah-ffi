package com.godaddy.asherah.appencryption.kms;

import com.godaddy.asherah.jni.AsherahConfig;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Static key management service. Maps to kms="static" in the native config.
 * Compatible with the canonical godaddy/asherah StaticKeyManagementServiceImpl.
 */
public class StaticKeyManagementServiceImpl implements KeyManagementService {

    private final String masterKeyHex;

    public StaticKeyManagementServiceImpl(final String key) {
        Objects.requireNonNull(key, "key");
        // The canonical SDK accepts the raw key string.
        // Convert to hex for the native layer's STATIC_MASTER_KEY_HEX env var.
        final StringBuilder hex = new StringBuilder();
        for (byte b : key.getBytes(StandardCharsets.UTF_8)) {
            hex.append(String.format("%02x", b));
        }
        this.masterKeyHex = hex.toString();
    }

    @Override
    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.kms("static");
        // Set the hex-encoded master key via system property for the native layer
        System.setProperty("STATIC_MASTER_KEY_HEX", masterKeyHex);
    }

    public String getMasterKeyHex() {
        return masterKeyHex;
    }
}
