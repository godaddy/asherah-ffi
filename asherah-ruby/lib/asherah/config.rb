# frozen_string_literal: true

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
      service_name: "ServiceName",
      product_id: "ProductID",
      kms: "KMS",
      metastore: "Metastore",
      connection_string: "ConnectionString",
      replica_read_consistency: "ReplicaReadConsistency",
      sql_metastore_db_type: "SQLMetastoreDBType",
      dynamo_db_endpoint: "DynamoDBEndpoint",
      dynamo_db_region: "DynamoDBRegion",
      dynamo_db_table_name: "DynamoDBTableName",
      enable_region_suffix: "EnableRegionSuffix",
      region_map: "RegionMap",
      preferred_region: "PreferredRegion",
      session_cache_max_size: "SessionCacheMaxSize",
      session_cache_duration: "SessionCacheDuration",
      enable_session_caching: "EnableSessionCaching",
      expire_after: "ExpireAfter",
      check_interval: "CheckInterval",
      verbose: "Verbose",
    }.freeze

    attr_accessor(*MAPPING.keys)

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
