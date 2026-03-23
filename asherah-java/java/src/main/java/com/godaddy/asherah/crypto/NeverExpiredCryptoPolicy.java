package com.godaddy.asherah.crypto;

import java.time.Instant;

/**
 * Crypto policy where keys never expire. Maps to default native config (no expiry settings).
 * Compatible with the canonical godaddy/asherah NeverExpiredCryptoPolicy.
 */
public class NeverExpiredCryptoPolicy extends CryptoPolicy {

    @Override
    public boolean isKeyExpired(final Instant keyCreationDate) {
        return false;
    }

    @Override
    public long getRevokeCheckPeriodMillis() {
        return Long.MAX_VALUE;
    }

    @Override
    public boolean canCacheSystemKeys() {
        return true;
    }

    @Override
    public boolean canCacheIntermediateKeys() {
        return true;
    }

    @Override
    public boolean canCacheSessions() {
        return false;
    }

    @Override
    public long getSessionCacheMaxSize() {
        return Long.MAX_VALUE;
    }

    @Override
    public long getSessionCacheExpireMillis() {
        return Long.MAX_VALUE;
    }

    @Override
    public boolean notifyExpiredIntermediateKeyOnRead() {
        return false;
    }

    @Override
    public boolean notifyExpiredSystemKeyOnRead() {
        return false;
    }

    @Override
    public KeyRotationStrategy keyRotationStrategy() {
        return KeyRotationStrategy.INLINE;
    }
}
