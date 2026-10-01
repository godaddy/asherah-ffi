package asherah

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// FuzzConfigToJSON exercises Config.toJSON, the one choke point between
// arbitrary caller-supplied config and the JSON payload the native core
// parses. It fuzzes the plain string fields, KMS specifically (KMS
// defaulting to "static" when empty is the only non-trivial logic for
// plain-string fields), and — since validateConfigUTF8 has dedicated
// reflect.Pointer and reflect.Map branches that are otherwise
// unreachable from this test — a *string field (ConnectionString) and a
// map[string]string field (RegionMap) so a regression in either branch
// can't silently reintroduce the U+FFFD mangling bug undetected.
func FuzzConfigToJSON(f *testing.F) {
	f.Add("svc", "prod", "memory", "", "", "", "")
	f.Add("svc", "prod", "memory", "aws", "postgres://x", "us-east-1", "aws-us-east-1")
	f.Add("", "", "", "", "", "", "")
	f.Add("unicode-\u00e9\u4e2d", "prod\x00nul", "memory", "static", "conn\x00nul", "region\x00nul", "val\x00nul")
	f.Add("svc", "prod", "memory", "aws", "\xe2", "region", "value") // invalid UTF-8 in *string field
	f.Add("svc", "prod", "memory", "aws", "conn", "\xe2", "value")   // invalid UTF-8 in map key
	f.Add("svc", "prod", "memory", "aws", "conn", "region", "\xe2")  // invalid UTF-8 in map value

	f.Fuzz(func(t *testing.T, serviceName, productID, metastore, kms, connectionString, regionKey, regionVal string) {
		cfg := Config{
			ServiceName:      serviceName,
			ProductID:        productID,
			Metastore:        metastore,
			KMS:              kms,
			ConnectionString: &connectionString,
			RegionMap:        map[string]string{regionKey: regionVal},
		}

		data, err := cfg.toJSON()

		// toJSON must reject invalid UTF-8 with an error rather than
		// silently letting json.Marshal substitute U+FFFD for the bad
		// bytes — a round-trip check can't detect that corruption since
		// the *output* is well-formed JSON, just not equal to the input.
		if !utf8.ValidString(serviceName) || !utf8.ValidString(productID) ||
			!utf8.ValidString(metastore) || !utf8.ValidString(kms) ||
			!utf8.ValidString(connectionString) || !utf8.ValidString(regionKey) || !utf8.ValidString(regionVal) {
			if err == nil {
				t.Fatalf("toJSON() should reject invalid UTF-8 input, got data=%s", data)
			}
			return
		}
		if err != nil {
			t.Fatalf("toJSON() error on valid UTF-8 input: %v", err)
		}

		var got Config
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("round-trip unmarshal failed: %v (json=%s)", err, data)
		}

		if got.ServiceName != serviceName {
			t.Fatalf("ServiceName round-trip: got %q, want %q", got.ServiceName, serviceName)
		}
		if got.ProductID != productID {
			t.Fatalf("ProductID round-trip: got %q, want %q", got.ProductID, productID)
		}
		if got.Metastore != metastore {
			t.Fatalf("Metastore round-trip: got %q, want %q", got.Metastore, metastore)
		}
		if got.ConnectionString == nil || *got.ConnectionString != connectionString {
			t.Fatalf("ConnectionString round-trip: got %v, want %q", got.ConnectionString, connectionString)
		}
		if got.RegionMap[regionKey] != regionVal {
			t.Fatalf("RegionMap round-trip: got %v, want {%q: %q}", got.RegionMap, regionKey, regionVal)
		}

		wantKMS := kms
		if wantKMS == "" {
			wantKMS = "static"
		}
		if got.KMS != wantKMS {
			t.Fatalf("KMS default: got %q, want %q (input KMS=%q)", got.KMS, wantKMS, kms)
		}
	})
}
