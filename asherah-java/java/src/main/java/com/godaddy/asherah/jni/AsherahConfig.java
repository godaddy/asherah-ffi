package com.godaddy.asherah.jni;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class AsherahConfig {
  private final String serviceName;
  private final String productId;
  private final Long expireAfter;
  private final Long checkInterval;
  private final String metastore;
  private final String connectionString;
  private final String replicaReadConsistency;
  private final String dynamoDbEndpoint;
  private final String dynamoDbRegion;
  private final String dynamoDbTableName;
  private final Integer sessionCacheMaxSize;
  private final Long sessionCacheDuration;
  private final String kms;
  private final Map<String, String> regionMap;
  private final String preferredRegion;
  private final Boolean enableRegionSuffix;
  private final Boolean enableSessionCaching;
  private final Boolean verbose;

  private AsherahConfig(final Builder builder) {
    this.serviceName = builder.serviceName;
    this.productId = builder.productId;
    this.expireAfter = builder.expireAfter;
    this.checkInterval = builder.checkInterval;
    this.metastore = builder.metastore;
    this.connectionString = builder.connectionString;
    this.replicaReadConsistency = builder.replicaReadConsistency;
    this.dynamoDbEndpoint = builder.dynamoDbEndpoint;
    this.dynamoDbRegion = builder.dynamoDbRegion;
    this.dynamoDbTableName = builder.dynamoDbTableName;
    this.sessionCacheMaxSize = builder.sessionCacheMaxSize;
    this.sessionCacheDuration = builder.sessionCacheDuration;
    this.kms = builder.kms;
    this.regionMap = builder.regionMap;
    this.preferredRegion = builder.preferredRegion;
    this.enableRegionSuffix = builder.enableRegionSuffix;
    this.enableSessionCaching = builder.enableSessionCaching;
    this.verbose = builder.verbose;
  }

  public String toJson() {
    final Map<String, Object> json = new LinkedHashMap<>();
    json.put("ServiceName", serviceName);
    json.put("ProductID", productId);
    json.put("ExpireAfter", expireAfter);
    json.put("CheckInterval", checkInterval);
    json.put("Metastore", metastore);
    json.put("ConnectionString", connectionString);
    json.put("ReplicaReadConsistency", replicaReadConsistency);
    json.put("DynamoDBEndpoint", dynamoDbEndpoint);
    json.put("DynamoDBRegion", dynamoDbRegion);
    json.put("DynamoDBTableName", dynamoDbTableName);
    json.put("SessionCacheMaxSize", sessionCacheMaxSize);
    json.put("SessionCacheDuration", sessionCacheDuration);
    json.put("KMS", kms);
    json.put("RegionMap", regionMap == null ? null : new LinkedHashMap<>(regionMap));
    json.put("PreferredRegion", preferredRegion);
    json.put("EnableRegionSuffix", enableRegionSuffix);
    json.put("EnableSessionCaching", enableSessionCaching);
    json.put("Verbose", verbose);
    return JsonUtil.toJson(json);
  }

  boolean isSessionCachingEnabled() {
    return enableSessionCaching == null || enableSessionCaching;
  }

  boolean isVerbose() {
    return Boolean.TRUE.equals(verbose);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private String serviceName;
    private String productId;
    private Long expireAfter;
    private Long checkInterval;
    private String metastore;
    private String connectionString;
    private String replicaReadConsistency;
    private String dynamoDbEndpoint;
    private String dynamoDbRegion;
    private String dynamoDbTableName;
    private Integer sessionCacheMaxSize;
    private Long sessionCacheDuration;
    private String kms = "static";
    private Map<String, String> regionMap;
    private String preferredRegion;
    private Boolean enableRegionSuffix;
    private Boolean enableSessionCaching = Boolean.TRUE;
    private Boolean verbose = Boolean.FALSE;

    private Builder() {}

    public Builder serviceName(final String value) {
      this.serviceName = value;
      return this;
    }

    public Builder productId(final String value) {
      this.productId = value;
      return this;
    }

    public Builder expireAfter(final Long seconds) {
      this.expireAfter = seconds;
      return this;
    }

    public Builder checkInterval(final Long seconds) {
      this.checkInterval = seconds;
      return this;
    }

    public Builder metastore(final String value) {
      this.metastore = value;
      return this;
    }

    public Builder connectionString(final String value) {
      this.connectionString = value;
      return this;
    }

    public Builder replicaReadConsistency(final String value) {
      this.replicaReadConsistency = value;
      return this;
    }

    public Builder dynamoDbEndpoint(final String value) {
      this.dynamoDbEndpoint = value;
      return this;
    }

    public Builder dynamoDbRegion(final String value) {
      this.dynamoDbRegion = value;
      return this;
    }

    public Builder dynamoDbTableName(final String value) {
      this.dynamoDbTableName = value;
      return this;
    }

    public Builder sessionCacheMaxSize(final Integer value) {
      this.sessionCacheMaxSize = value;
      return this;
    }

    public Builder sessionCacheDuration(final Long value) {
      this.sessionCacheDuration = value;
      return this;
    }

    public Builder kms(final String value) {
      this.kms = value;
      return this;
    }

    public Builder regionMap(final Map<String, String> value) {
      this.regionMap = value == null ? null : new LinkedHashMap<>(value);
      return this;
    }

    public Builder preferredRegion(final String value) {
      this.preferredRegion = value;
      return this;
    }

    public Builder enableRegionSuffix(final Boolean value) {
      this.enableRegionSuffix = value;
      return this;
    }

    public Builder enableSessionCaching(final Boolean value) {
      this.enableSessionCaching = value;
      return this;
    }

    public Builder verbose(final Boolean value) {
      this.verbose = value;
      return this;
    }

    public AsherahConfig build() {
      Objects.requireNonNull(serviceName, "serviceName is required");
      Objects.requireNonNull(productId, "productId is required");
      Objects.requireNonNull(metastore, "metastore is required");
      return new AsherahConfig(this);
    }
  }
}
