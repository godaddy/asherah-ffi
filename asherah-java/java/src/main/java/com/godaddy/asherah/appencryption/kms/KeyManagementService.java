package com.godaddy.asherah.appencryption.kms;

import com.godaddy.asherah.jni.AsherahConfig;

/**
 * Interface for key management service implementations.
 * Compatible with the canonical godaddy/asherah KeyManagementService interface.
 * In the FFI binding, actual KMS operations are handled by the native Rust layer.
 */
public interface KeyManagementService {

    /**
     * Apply this KMS configuration to an AsherahConfig builder.
     * Package-private — called by SessionFactory during build().
     */
    void applyConfig(AsherahConfig.Builder builder);
}
