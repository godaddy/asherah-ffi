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
    DynamoDBTableName      *string           `json:"DynamoDBTableName,omitempty"`
    SessionCacheMaxSize    *int              `json:"SessionCacheMaxSize,omitempty"`
    SessionCacheDuration   *int64            `json:"SessionCacheDuration,omitempty"`
    KMS                    string            `json:"KMS,omitempty"`
    RegionMap              map[string]string `json:"RegionMap,omitempty"`
    PreferredRegion        *string           `json:"PreferredRegion,omitempty"`
    EnableRegionSuffix     *bool             `json:"EnableRegionSuffix,omitempty"`
    EnableSessionCaching   *bool             `json:"EnableSessionCaching,omitempty"`
    Verbose                *bool             `json:"Verbose,omitempty"`
}

func (c Config) toJSON() ([]byte, error) {
    cloned := c
    if cloned.KMS == "" {
        cloned.KMS = "static"
    }
    return json.Marshal(&cloned)
}
