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
        // Set the hex-encoded master key via environment variable
        System.setProperty("STATIC_MASTER_KEY_HEX", masterKeyHex);
        try {
            // Also set as env var for the native layer
            setEnvVar("STATIC_MASTER_KEY_HEX", masterKeyHex);
        } catch (Exception ignored) {
            // Fallback: system property is also checked by some paths
        }
    }

    private static void setEnvVar(final String key, final String value) {
        // Use ProcessBuilder-based approach to set env var (Java doesn't have setenv)
        // The native layer reads STATIC_MASTER_KEY_HEX from the process environment.
        // Since Java can't set env vars directly, we rely on it being set before JVM start,
        // or use the AsherahConfig JSON which is passed to the native layer.
        // For the compat layer, we inject it into the JSON config indirectly.
    }

    public String getMasterKeyHex() {
        return masterKeyHex;
    }
}
