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
  private final String dynamoDbSigningRegion;
  private final String dynamoDbTableName;
  private final Integer sessionCacheMaxSize;
  private final Long sessionCacheDuration;
  private final String kms;
  private final String staticMasterKeyHex;
  private final Map<String, String> regionMap;
  private final String preferredRegion;
  private final String awsProfileName;
  private final Boolean enableRegionSuffix;
  private final Boolean enableSessionCaching;
  private final Boolean verbose;
  private final Integer poolMaxOpen;
  private final Integer poolMaxIdle;
  private final Long poolMaxLifetime;
  private final Long poolMaxIdleTime;
  private final String kmsKeyId;
  private final String secretsManagerSecretId;
  private final String vaultAddr;
  private final String vaultToken;
  private final String vaultAuthMethod;
  private final String vaultAuthRole;
  private final String vaultAuthMount;
  private final String vaultApproleRoleId;
  private final String vaultApproleSecretId;
  private final String vaultClientCert;
  private final String vaultClientKey;
  private final String vaultK8sTokenPath;
  private final String vaultTransitKey;
  private final String vaultTransitMount;

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
    this.dynamoDbSigningRegion = builder.dynamoDbSigningRegion;
    this.dynamoDbTableName = builder.dynamoDbTableName;
    this.sessionCacheMaxSize = builder.sessionCacheMaxSize;
    this.sessionCacheDuration = builder.sessionCacheDuration;
    this.kms = builder.kms;
    this.staticMasterKeyHex = builder.staticMasterKeyHex;
    this.regionMap = builder.regionMap;
    this.preferredRegion = builder.preferredRegion;
    this.awsProfileName = builder.awsProfileName;
    this.enableRegionSuffix = builder.enableRegionSuffix;
    this.enableSessionCaching = builder.enableSessionCaching;
    this.verbose = builder.verbose;
    this.poolMaxOpen = builder.poolMaxOpen;
    this.poolMaxIdle = builder.poolMaxIdle;
    this.poolMaxLifetime = builder.poolMaxLifetime;
    this.poolMaxIdleTime = builder.poolMaxIdleTime;
    this.kmsKeyId = builder.kmsKeyId;
    this.secretsManagerSecretId = builder.secretsManagerSecretId;
    this.vaultAddr = builder.vaultAddr;
    this.vaultToken = builder.vaultToken;
    this.vaultAuthMethod = builder.vaultAuthMethod;
    this.vaultAuthRole = builder.vaultAuthRole;
    this.vaultAuthMount = builder.vaultAuthMount;
    this.vaultApproleRoleId = builder.vaultApproleRoleId;
    this.vaultApproleSecretId = builder.vaultApproleSecretId;
    this.vaultClientCert = builder.vaultClientCert;
    this.vaultClientKey = builder.vaultClientKey;
    this.vaultK8sTokenPath = builder.vaultK8sTokenPath;
    this.vaultTransitKey = builder.vaultTransitKey;
    this.vaultTransitMount = builder.vaultTransitMount;
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
    json.put("DynamoDBSigningRegion", dynamoDbSigningRegion);
    json.put("DynamoDBTableName", dynamoDbTableName);
    json.put("SessionCacheMaxSize", sessionCacheMaxSize);
    json.put("SessionCacheDuration", sessionCacheDuration);
    json.put("KMS", kms);
    json.put("StaticMasterKeyHex", staticMasterKeyHex);
    json.put("RegionMap", regionMap == null ? null : new LinkedHashMap<>(regionMap));
    json.put("PreferredRegion", preferredRegion);
    json.put("AwsProfileName", awsProfileName);
    json.put("EnableRegionSuffix", enableRegionSuffix);
    json.put("EnableSessionCaching", enableSessionCaching);
    json.put("Verbose", verbose);
    json.put("PoolMaxOpen", poolMaxOpen);
    json.put("PoolMaxIdle", poolMaxIdle);
    json.put("PoolMaxLifetime", poolMaxLifetime);
    json.put("PoolMaxIdleTime", poolMaxIdleTime);
    json.put("KmsKeyId", kmsKeyId);
    json.put("SecretsManagerSecretId", secretsManagerSecretId);
    json.put("VaultAddr", vaultAddr);
    json.put("VaultToken", vaultToken);
    json.put("VaultAuthMethod", vaultAuthMethod);
    json.put("VaultAuthRole", vaultAuthRole);
    json.put("VaultAuthMount", vaultAuthMount);
    json.put("VaultApproleRoleId", vaultApproleRoleId);
    json.put("VaultApproleSecretId", vaultApproleSecretId);
    json.put("VaultClientCert", vaultClientCert);
    json.put("VaultClientKey", vaultClientKey);
    json.put("VaultK8sTokenPath", vaultK8sTokenPath);
    json.put("VaultTransitKey", vaultTransitKey);
    json.put("VaultTransitMount", vaultTransitMount);
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
    private String dynamoDbSigningRegion;
    private String dynamoDbTableName;
    private Integer sessionCacheMaxSize;
    private Long sessionCacheDuration;
    private String kms = "static";
    private String staticMasterKeyHex;
    private Map<String, String> regionMap;
    private String preferredRegion;
    private String awsProfileName;
    private Boolean enableRegionSuffix;
    private Boolean enableSessionCaching = Boolean.TRUE;
    private Boolean verbose = Boolean.FALSE;
    private Integer poolMaxOpen;
    private Integer poolMaxIdle;
    private Long poolMaxLifetime;
    private Long poolMaxIdleTime;
    private String kmsKeyId;
    private String secretsManagerSecretId;
    private String vaultAddr;
    private String vaultToken;
    private String vaultAuthMethod;
    private String vaultAuthRole;
    private String vaultAuthMount;
    private String vaultApproleRoleId;
    private String vaultApproleSecretId;
    private String vaultClientCert;
    private String vaultClientKey;
    private String vaultK8sTokenPath;
    private String vaultTransitKey;
    private String vaultTransitMount;

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

    public Builder dynamoDbSigningRegion(final String value) {
      this.dynamoDbSigningRegion = value;
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

    public Builder staticMasterKeyHex(final String value) {
      this.staticMasterKeyHex = value;
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

    public Builder awsProfileName(final String value) {
      this.awsProfileName = value;
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

    public Builder poolMaxOpen(final Integer value) {
      this.poolMaxOpen = value;
      return this;
    }

    public Builder poolMaxIdle(final Integer value) {
      this.poolMaxIdle = value;
      return this;
    }

    public Builder poolMaxLifetime(final Long seconds) {
      this.poolMaxLifetime = seconds;
      return this;
    }

    public Builder poolMaxIdleTime(final Long seconds) {
      this.poolMaxIdleTime = seconds;
      return this;
    }

    public Builder kmsKeyId(final String value) {
      this.kmsKeyId = value;
      return this;
    }

    public Builder secretsManagerSecretId(final String value) {
      this.secretsManagerSecretId = value;
      return this;
    }

    public Builder vaultAddr(final String value) {
      this.vaultAddr = value;
      return this;
    }

    public Builder vaultToken(final String value) {
      this.vaultToken = value;
      return this;
    }

    public Builder vaultAuthMethod(final String value) {
      this.vaultAuthMethod = value;
      return this;
    }

    public Builder vaultAuthRole(final String value) {
      this.vaultAuthRole = value;
      return this;
    }

    public Builder vaultAuthMount(final String value) {
      this.vaultAuthMount = value;
      return this;
    }

    public Builder vaultApproleRoleId(final String value) {
      this.vaultApproleRoleId = value;
      return this;
    }

    public Builder vaultApproleSecretId(final String value) {
      this.vaultApproleSecretId = value;
      return this;
    }

    public Builder vaultClientCert(final String value) {
      this.vaultClientCert = value;
      return this;
    }

    public Builder vaultClientKey(final String value) {
      this.vaultClientKey = value;
      return this;
    }

    public Builder vaultK8sTokenPath(final String value) {
      this.vaultK8sTokenPath = value;
      return this;
    }

    public Builder vaultTransitKey(final String value) {
      this.vaultTransitKey = value;
      return this;
    }

    public Builder vaultTransitMount(final String value) {
      this.vaultTransitMount = value;
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
