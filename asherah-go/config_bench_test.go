package asherah

import "testing"

// BenchmarkConfigToJSON exercises Config.toJSON with a realistically
// populated Config (a mix of plain strings, several *string pointer
// fields, and a small RegionMap). Comparable against main: toJSON's
// name and signature are unchanged; the only difference is the added
// validateConfigUTF8 reflection pass over the struct's ~35 fields
// before marshaling. toJSON runs once per NewFactory call (not a
// per-operation hot path), so this quantifies a one-time construction
// cost rather than anything on the encrypt/decrypt path.
func BenchmarkConfigToJSON(b *testing.B) {
	conn := "postgres://user:pass@host:5432/db"
	region := "us-east-1"
	keyID := "arn:aws:kms:us-east-1:123456789012:key/abc"

	cfg := Config{
		ServiceName:      "bench-service",
		ProductID:        "bench-product",
		Metastore:        "dynamodb",
		KMS:              "aws",
		ConnectionString: &conn,
		DynamoDBRegion:   &region,
		KmsKeyID:         &keyID,
		RegionMap: map[string]string{
			"us-east-1": "arn:aws:kms:us-east-1:123456789012:key/abc",
			"us-west-2": "arn:aws:kms:us-west-2:123456789012:key/def",
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := cfg.toJSON()
		if err != nil {
			b.Fatalf("toJSON: %v", err)
		}
	}
}
