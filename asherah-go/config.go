package asherah

import "encoding/json"

// Config mirrors the configuration options supported by other Asherah bindings.
type Config struct {
	ServiceName            string            `json:"ServiceName"`
	ProductID              string            `json:"ProductID"`
	ExpireAfter            *int64            `json:"ExpireAfter,omitempty"`
	CheckInterval          *int64            `json:"CheckInterval,omitempty"`
	Metastore              string            `json:"Metastore"`
	ConnectionString       *string           `json:"ConnectionString,omitempty"`
	ReplicaReadConsistency *string           `json:"ReplicaReadConsistency,omitempty"`
	DynamoDBEndpoint       *string           `json:"DynamoDBEndpoint,omitempty"`
	DynamoDBRegion         *string           `json:"DynamoDBRegion,omitempty"`
	DynamoDBSigningRegion  *string           `json:"DynamoDBSigningRegion,omitempty"`
	DynamoDBTableName      *string           `json:"DynamoDBTableName,omitempty"`
	SessionCacheMaxSize    *int              `json:"SessionCacheMaxSize,omitempty"`
	SessionCacheDuration   *int64            `json:"SessionCacheDuration,omitempty"`
	KMS                    string            `json:"KMS,omitempty"`
	RegionMap              map[string]string `json:"RegionMap,omitempty"`
	PreferredRegion        *string           `json:"PreferredRegion,omitempty"`
	AwsProfileName         *string           `json:"AwsProfileName,omitempty"`
	EnableRegionSuffix     *bool             `json:"EnableRegionSuffix,omitempty"`
	EnableSessionCaching   *bool             `json:"EnableSessionCaching,omitempty"`
	Verbose                *bool             `json:"Verbose,omitempty"`

	// Connection pool
	PoolMaxOpen     *int    `json:"PoolMaxOpen,omitempty"`
	PoolMaxIdle     *int    `json:"PoolMaxIdle,omitempty"`
	PoolMaxLifetime *int64  `json:"PoolMaxLifetime,omitempty"`
	PoolMaxIdleTime *int64  `json:"PoolMaxIdleTime,omitempty"`

	// KMS: AWS
	KmsKeyID *string `json:"KmsKeyId,omitempty"`

	// KMS: AWS Secrets Manager
	SecretsManagerSecretID *string `json:"SecretsManagerSecretId,omitempty"`

	// KMS: HashiCorp Vault Transit
	VaultAddr            *string `json:"VaultAddr,omitempty"`
	VaultToken           *string `json:"VaultToken,omitempty"`
	VaultAuthMethod      *string `json:"VaultAuthMethod,omitempty"`
	VaultAuthRole        *string `json:"VaultAuthRole,omitempty"`
	VaultAuthMount       *string `json:"VaultAuthMount,omitempty"`
	VaultApproleRoleID   *string `json:"VaultApproleRoleId,omitempty"`
	VaultApproleSecretID *string `json:"VaultApproleSecretId,omitempty"`
	VaultClientCert      *string `json:"VaultClientCert,omitempty"`
	VaultClientKey       *string `json:"VaultClientKey,omitempty"`
	VaultK8sTokenPath    *string `json:"VaultK8sTokenPath,omitempty"`
	VaultTransitKey      *string `json:"VaultTransitKey,omitempty"`
	VaultTransitMount    *string `json:"VaultTransitMount,omitempty"`
}

func (c Config) toJSON() ([]byte, error) {
    cloned := c
    if cloned.KMS == "" {
        cloned.KMS = "static"
    }
    return json.Marshal(&cloned)
}
