package asherah

import (
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf8"
)

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
	StaticMasterKeyHex     *string           `json:"StaticMasterKeyHex,omitempty"`
	RegionMap              map[string]string `json:"RegionMap,omitempty"`
	PreferredRegion        *string           `json:"PreferredRegion,omitempty"`
	AwsProfileName         *string           `json:"AwsProfileName,omitempty"`
	EnableRegionSuffix     *bool             `json:"EnableRegionSuffix,omitempty"`
	EnableSessionCaching   *bool             `json:"EnableSessionCaching,omitempty"`
	Verbose                *bool             `json:"Verbose,omitempty"`

	// Connection pool
	PoolMaxOpen     *int   `json:"PoolMaxOpen,omitempty"`
	PoolMaxIdle     *int   `json:"PoolMaxIdle,omitempty"`
	PoolMaxLifetime *int64 `json:"PoolMaxLifetime,omitempty"`
	PoolMaxIdleTime *int64 `json:"PoolMaxIdleTime,omitempty"`

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
	if err := validateConfigUTF8(&cloned); err != nil {
		return nil, err
	}
	return json.Marshal(&cloned)
}

// validateConfigUTF8 rejects a Config containing invalid UTF-8 in any
// string field (or RegionMap key/value). encoding/json silently
// substitutes the U+FFFD replacement character for invalid UTF-8 on
// Marshal rather than erroring, which would otherwise send
// silently-corrupted config values (service name, connection strings,
// KMS key IDs, etc.) to the native core with no error surfaced to the
// caller. Uses reflection to cover every current and future string /
// *string / map[string]string field without hand-listing them.
func validateConfigUTF8(cfg *Config) error {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		switch field.Kind() {
		case reflect.String:
			if !utf8.ValidString(field.String()) {
				return fmt.Errorf("asherah-go: Config.%s contains invalid UTF-8", t.Field(i).Name)
			}
		case reflect.Pointer:
			if field.IsNil() || field.Elem().Kind() != reflect.String {
				continue
			}
			if !utf8.ValidString(field.Elem().String()) {
				return fmt.Errorf("asherah-go: Config.%s contains invalid UTF-8", t.Field(i).Name)
			}
		case reflect.Map:
			for _, key := range field.MapKeys() {
				if key.Kind() != reflect.String || field.MapIndex(key).Kind() != reflect.String {
					continue
				}
				if !utf8.ValidString(key.String()) || !utf8.ValidString(field.MapIndex(key).String()) {
					return fmt.Errorf("asherah-go: Config.%s contains invalid UTF-8", t.Field(i).Name)
				}
			}
		}
	}
	return nil
}
