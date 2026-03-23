package com.godaddy.asherah.crypto;

import com.godaddy.asherah.jni.AsherahConfig;

/**
 * Abstract crypto policy. Compatible with the canonical godaddy/asherah CryptoPolicy.
 * In the FFI binding, policy settings are mapped to AsherahConfig fields.
 */
public abstract class CryptoPolicy {

    public enum KeyRotationStrategy {
        INLINE,
        QUEUED
    }

    public abstract boolean isKeyExpired(java.time.Instant keyCreationDate);
    public abstract long getRevokeCheckPeriodMillis();
    public abstract boolean canCacheSystemKeys();
    public abstract boolean canCacheIntermediateKeys();
    public abstract boolean canCacheSessions();
    public abstract long getSessionCacheMaxSize();
    public abstract long getSessionCacheExpireMillis();
    public abstract boolean notifyExpiredIntermediateKeyOnRead();
    public abstract boolean notifyExpiredSystemKeyOnRead();
    public abstract KeyRotationStrategy keyRotationStrategy();

    public boolean isInlineKeyRotation() {
        return keyRotationStrategy() == KeyRotationStrategy.INLINE;
    }

    public boolean isQueuedKeyRotation() {
        return keyRotationStrategy() == KeyRotationStrategy.QUEUED;
    }

    /**
     * Apply this policy's settings to an AsherahConfig builder.
     * Package-private — called by SessionFactory during build().
     */
    public void applyConfig(final AsherahConfig.Builder builder) {
        if (canCacheSessions()) {
            builder.enableSessionCaching(true);
            builder.sessionCacheMaxSize((int) getSessionCacheMaxSize());
            builder.sessionCacheDuration(getSessionCacheExpireMillis() / 1000);
        } else {
            builder.enableSessionCaching(false);
        }
    }
}
