package com.godaddy.asherah.appencryption.persistence;

import com.godaddy.asherah.jni.AsherahConfig;
import org.json.JSONObject;

import java.time.Instant;
import java.util.Optional;

/**
 * DynamoDB metastore adapter. Maps to metastore="dynamodb" in the native config.
 * Compatible with the canonical godaddy/asherah DynamoDbMetastoreImpl.
 */
public class DynamoDbMetastoreImpl implements Metastore<JSONObject> {

    static final String DEFAULT_TABLE_NAME = "EncryptionKey";

    private final String region;
    private final String tableName;
    private final String endPoint;
    private final String signingRegion;
    private final boolean keySuffix;

    private DynamoDbMetastoreImpl(final Builder builder) {
        this.region = builder.region;
        this.tableName = builder.tableName;
        this.endPoint = builder.endPoint;
        this.signingRegion = builder.signingRegion;
        this.keySuffix = builder.keySuffix;
    }

    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.metastore("dynamodb");
        if (region != null) {
            builder.dynamoDbRegion(region);
        }
        if (signingRegion != null) {
            builder.dynamoDbSigningRegion(signingRegion);
        }
        if (tableName != null && !DEFAULT_TABLE_NAME.equals(tableName)) {
            builder.dynamoDbTableName(tableName);
        }
        if (endPoint != null) {
            builder.dynamoDbEndpoint(endPoint);
        }
        if (keySuffix) {
            builder.enableRegionSuffix(true);
        }
    }

    @Override
    public String getKeySuffix() {
        return keySuffix ? "_" + region : "";
    }

    public static Builder newBuilder(final String region) {
        return new Builder(region);
    }

    @Override
    public Optional<JSONObject> load(final String keyId, final Instant created) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public Optional<JSONObject> loadLatest(final String keyId) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public boolean store(final String keyId, final Instant created, final JSONObject value) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    public interface BuildStep {
        BuildStep withTableName(String tableName);
        BuildStep withEndPointConfiguration(String endPoint, String signingRegion);
        BuildStep withKeySuffix();
        DynamoDbMetastoreImpl build();
    }

    public static final class Builder implements BuildStep {
        private final String region;
        private String tableName = DEFAULT_TABLE_NAME;
        private String endPoint;
        private String signingRegion;
        private boolean keySuffix;

        private Builder(final String region) {
            this.region = region;
        }

        @Override
        public BuildStep withTableName(final String tableName) {
            this.tableName = tableName;
            return this;
        }

        @Override
        public BuildStep withEndPointConfiguration(final String endPoint, final String signingRegion) {
            this.endPoint = endPoint;
            this.signingRegion = signingRegion;
            return this;
        }

        @Override
        public BuildStep withKeySuffix() {
            this.keySuffix = true;
            return this;
        }

        @Override
        public DynamoDbMetastoreImpl build() {
            return new DynamoDbMetastoreImpl(this);
        }
    }
}
