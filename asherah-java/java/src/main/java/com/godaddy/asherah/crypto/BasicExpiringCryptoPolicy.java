package com.godaddy.asherah.crypto;

import com.godaddy.asherah.jni.AsherahConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Configurable expiring crypto policy. Maps expiry/cache settings to native config.
 * Compatible with the canonical godaddy/asherah BasicExpiringCryptoPolicy.
 */
public class BasicExpiringCryptoPolicy extends CryptoPolicy {

    private final long keyExpirationMillis;
    private final long revokeCheckPeriodMillis;
    private final KeyRotationStrategy rotationStrategy;
    private final boolean cacheSystemKeys;
    private final boolean cacheIntermediateKeys;
    private final boolean cacheSessions;
    private final long sessionCacheMaxSize;
    private final long sessionCacheExpireMillis;
    private final boolean notifyExpiredSystemKeyOnRead;
    private final boolean notifyExpiredIntermediateKeyOnRead;

    private BasicExpiringCryptoPolicy(final Builder builder) {
        this.keyExpirationMillis = builder.keyExpirationDays * 24L * 60 * 60 * 1000;
        this.revokeCheckPeriodMillis = builder.revokeCheckMinutes * 60L * 1000;
        this.rotationStrategy = builder.rotationStrategy;
        this.cacheSystemKeys = builder.cacheSystemKeys;
        this.cacheIntermediateKeys = builder.cacheIntermediateKeys;
        this.cacheSessions = builder.cacheSessions;
        this.sessionCacheMaxSize = builder.sessionCacheMaxSize;
        this.sessionCacheExpireMillis = builder.sessionCacheExpireMinutes * 60L * 1000;
        this.notifyExpiredSystemKeyOnRead = builder.notifyExpiredSystemKeyOnRead;
        this.notifyExpiredIntermediateKeyOnRead = builder.notifyExpiredIntermediateKeyOnRead;
    }

    @Override
    public void applyConfig(final AsherahConfig.Builder builder) {
        super.applyConfig(builder);
        builder.expireAfter(keyExpirationMillis / 1000);
        builder.checkInterval(revokeCheckPeriodMillis / 1000);
    }

    @Override
    public boolean isKeyExpired(final Instant keyCreationDate) {
        return keyCreationDate.plus(keyExpirationMillis, ChronoUnit.MILLIS).isBefore(Instant.now());
    }

    @Override
    public long getRevokeCheckPeriodMillis() {
        return revokeCheckPeriodMillis;
    }

    @Override
    public boolean canCacheSystemKeys() {
        return cacheSystemKeys;
    }

    @Override
    public boolean canCacheIntermediateKeys() {
        return cacheIntermediateKeys;
    }

    @Override
    public boolean canCacheSessions() {
        return cacheSessions;
    }

    @Override
    public long getSessionCacheMaxSize() {
        return sessionCacheMaxSize;
    }

    @Override
    public long getSessionCacheExpireMillis() {
        return sessionCacheExpireMillis;
    }

    @Override
    public boolean notifyExpiredIntermediateKeyOnRead() {
        return notifyExpiredIntermediateKeyOnRead;
    }

    @Override
    public boolean notifyExpiredSystemKeyOnRead() {
        return notifyExpiredSystemKeyOnRead;
    }

    @Override
    public KeyRotationStrategy keyRotationStrategy() {
        return rotationStrategy;
    }

    public static KeyExpirationDaysStep newBuilder() {
        return new Builder();
    }

    public interface KeyExpirationDaysStep {
        RevokeCheckMinutesStep withKeyExpirationDays(int days);
    }

    public interface RevokeCheckMinutesStep {
        BuildStep withRevokeCheckMinutes(int minutes);
    }

    public interface BuildStep {
        BuildStep withRotationStrategy(KeyRotationStrategy rotationStrategy);
        BuildStep withCanCacheSystemKeys(boolean cacheSystemKeys);
        BuildStep withCanCacheIntermediateKeys(boolean cacheIntermediateKeys);
        BuildStep withCanCacheSessions(boolean cacheSessions);
        BuildStep withSessionCacheMaxSize(long sessionCacheMaxSize);
        BuildStep withSessionCacheExpireMinutes(int sessionCacheExpireMinutes);
        BuildStep withNotifyExpiredSystemKeyOnRead(boolean notify);
        BuildStep withNotifyExpiredIntermediateKeyOnRead(boolean notify);
        BasicExpiringCryptoPolicy build();
    }

    public static final class Builder implements KeyExpirationDaysStep, RevokeCheckMinutesStep, BuildStep {
        private int keyExpirationDays;
        private int revokeCheckMinutes;
        private KeyRotationStrategy rotationStrategy = KeyRotationStrategy.INLINE;
        private boolean cacheSystemKeys = true;
        private boolean cacheIntermediateKeys = true;
        private boolean cacheSessions = false;
        private long sessionCacheMaxSize = 1000;
        private int sessionCacheExpireMinutes = 120;
        private boolean notifyExpiredSystemKeyOnRead = false;
        private boolean notifyExpiredIntermediateKeyOnRead = false;

        private Builder() {}

        @Override
        public RevokeCheckMinutesStep withKeyExpirationDays(final int days) {
            this.keyExpirationDays = days;
            return this;
        }

        @Override
        public BuildStep withRevokeCheckMinutes(final int minutes) {
            this.revokeCheckMinutes = minutes;
            return this;
        }

        @Override
        public BuildStep withRotationStrategy(final KeyRotationStrategy rotationStrategy) {
            this.rotationStrategy = rotationStrategy;
            return this;
        }

        @Override
        public BuildStep withCanCacheSystemKeys(final boolean cacheSystemKeys) {
            this.cacheSystemKeys = cacheSystemKeys;
            return this;
        }

        @Override
        public BuildStep withCanCacheIntermediateKeys(final boolean cacheIntermediateKeys) {
            this.cacheIntermediateKeys = cacheIntermediateKeys;
            return this;
        }

        @Override
        public BuildStep withCanCacheSessions(final boolean cacheSessions) {
            this.cacheSessions = cacheSessions;
            return this;
        }

        @Override
        public BuildStep withSessionCacheMaxSize(final long sessionCacheMaxSize) {
            this.sessionCacheMaxSize = sessionCacheMaxSize;
            return this;
        }

        @Override
        public BuildStep withSessionCacheExpireMinutes(final int sessionCacheExpireMinutes) {
            this.sessionCacheExpireMinutes = sessionCacheExpireMinutes;
            return this;
        }

        @Override
        public BuildStep withNotifyExpiredSystemKeyOnRead(final boolean notify) {
            this.notifyExpiredSystemKeyOnRead = notify;
            return this;
        }

        @Override
        public BuildStep withNotifyExpiredIntermediateKeyOnRead(final boolean notify) {
            this.notifyExpiredIntermediateKeyOnRead = notify;
            return this;
        }

        @Override
        public BasicExpiringCryptoPolicy build() {
            return new BasicExpiringCryptoPolicy(this);
        }
    }
}
