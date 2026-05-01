# frozen_string_literal: true

require "json"

module Asherah
  # Configuration class compatible with the canonical godaddy/asherah-ruby gem.
  # Provides snake_case attr_accessors that map to PascalCase config keys
  # expected by the Rust FFI layer.
  #
  # Usage:
  #   Asherah.configure do |config|
  #     config.service_name = "MyService"
  #     config.product_id = "MyProduct"
  #     config.kms = "static"
  #     config.metastore = "memory"
  #   end
  class Config
    MAPPING = {
      service_name: :ServiceName,
      product_id: :ProductID,
      kms: :KMS,
      metastore: :Metastore,
      connection_string: :ConnectionString,
      replica_read_consistency: :ReplicaReadConsistency,
      sql_metastore_db_type: :SQLMetastoreDBType,
      dynamo_db_endpoint: :DynamoDBEndpoint,
      dynamo_db_region: :DynamoDBRegion,
      dynamo_db_signing_region: :DynamoDBSigningRegion,
      dynamo_db_table_name: :DynamoDBTableName,
      enable_region_suffix: :EnableRegionSuffix,
      region_map: :RegionMap,
      preferred_region: :PreferredRegion,
      aws_profile_name: :AwsProfileName,
      session_cache_max_size: :SessionCacheMaxSize,
      session_cache_duration: :SessionCacheDuration,
      enable_session_caching: :EnableSessionCaching,
      disable_zero_copy: :DisableZeroCopy,
      expire_after: :ExpireAfter,
      check_interval: :CheckInterval,
      verbose: :Verbose,
      # Connection pool
      pool_max_open: :PoolMaxOpen,
      pool_max_idle: :PoolMaxIdle,
      pool_max_lifetime: :PoolMaxLifetime,
      pool_max_idle_time: :PoolMaxIdleTime,
      # KMS: AWS
      kms_key_id: :KmsKeyId,
      # KMS: AWS Secrets Manager
      secrets_manager_secret_id: :SecretsManagerSecretId,
      # KMS: HashiCorp Vault Transit
      vault_addr: :VaultAddr,
      vault_token: :VaultToken,
      vault_auth_method: :VaultAuthMethod,
      vault_auth_role: :VaultAuthRole,
      vault_auth_mount: :VaultAuthMount,
      vault_approle_role_id: :VaultApproleRoleId,
      vault_approle_secret_id: :VaultApproleSecretId,
      vault_client_cert: :VaultClientCert,
      vault_client_key: :VaultClientKey,
      vault_k8s_token_path: :VaultK8sTokenPath,
      vault_transit_key: :VaultTransitKey,
      vault_transit_mount: :VaultTransitMount,
    }.freeze

    KMS_TYPES = ["static", "aws", "vault", "vault-transit", "secrets-manager", "test-debug-static"].freeze
    METASTORE_TYPES = ["rdbms", "dynamodb", "memory", "test-debug-memory"].freeze
    SQL_METASTORE_DB_TYPES = ["mysql", "postgres", "oracle"].freeze

    attr_accessor(*MAPPING.keys)

    def validate!
      raise Error::ConfigError, "config.service_name not set" if service_name.nil?
      raise Error::ConfigError, "config.product_id not set" if product_id.nil?
      raise Error::ConfigError, "config.kms not set" if kms.nil?
      unless KMS_TYPES.include?(kms)
        raise Error::ConfigError, "config.kms must be one of these: #{KMS_TYPES.join(", ")}"
      end
      raise Error::ConfigError, "config.metastore not set" if metastore.nil?
      unless METASTORE_TYPES.include?(metastore)
        raise Error::ConfigError, "config.metastore must be one of these: #{METASTORE_TYPES.join(", ")}"
      end
      if sql_metastore_db_type && !SQL_METASTORE_DB_TYPES.include?(sql_metastore_db_type)
        raise Error::ConfigError, "config.sql_metastore_db_type must be one of these: #{SQL_METASTORE_DB_TYPES.join(", ")}"
      end
      if kms == "aws"
        raise Error::ConfigError, "config.region_map not set" if region_map.nil?
        raise Error::ConfigError, "config.region_map must be a Hash" unless region_map.is_a?(Hash)
        raise Error::ConfigError, "config.preferred_region not set" if preferred_region.nil?
      end
    end

    def to_json(*args)
      JSON.generate(to_h, *args)
    end

    # Convert to the PascalCase Hash expected by Asherah.setup
    def to_h
      hash = {}
      MAPPING.each_pair do |attr, key|
        value = public_send(attr)
        hash[key] = value unless value.nil?
      end
      hash
    end
  end
end
