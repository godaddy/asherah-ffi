package com.godaddy.asherah.appencryption.kms;

import com.godaddy.asherah.jni.AsherahConfig;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * AWS KMS adapter. Maps to kms="aws" in the native config.
 * Compatible with the canonical godaddy/asherah AwsKeyManagementServiceImpl.
 */
public class AwsKeyManagementServiceImpl implements KeyManagementService {

    private final Map<String, String> regionToArnMap;
    private final String preferredRegion;

    private AwsKeyManagementServiceImpl(final Builder builder) {
        this.regionToArnMap = new LinkedHashMap<>(builder.regionToArnMap);
        this.preferredRegion = builder.preferredRegion;
    }

    @Override
    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.kms("aws");
        builder.regionMap(regionToArnMap);
        builder.preferredRegion(preferredRegion);
    }

    public static Builder newBuilder(final Map<String, String> regionToArnMap, final String preferredRegion) {
        return new Builder(regionToArnMap, preferredRegion);
    }

    public static final class Builder {
        private final Map<String, String> regionToArnMap;
        private final String preferredRegion;

        private Builder(final Map<String, String> regionToArnMap, final String preferredRegion) {
            Objects.requireNonNull(regionToArnMap, "regionToArnMap");
            Objects.requireNonNull(preferredRegion, "preferredRegion");
            this.regionToArnMap = new LinkedHashMap<>(regionToArnMap);
            this.preferredRegion = preferredRegion;
        }

        public AwsKeyManagementServiceImpl build() {
            return new AwsKeyManagementServiceImpl(this);
        }
    }
}
