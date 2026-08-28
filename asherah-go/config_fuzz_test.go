package asherah

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// FuzzConfigToJSON exercises Config.toJSON, the one choke point between
// arbitrary caller-supplied config and the JSON payload the native core
// parses. It fuzzes the plain string fields plus KMS specifically, since
// KMS-defaulting to "static" when empty is the only non-trivial logic in
// toJSON (every other field is a mechanical json.Marshal passthrough,
// already covered by encoding/json's own test suite).
func FuzzConfigToJSON(f *testing.F) {
	f.Add("svc", "prod", "memory", "")
	f.Add("svc", "prod", "memory", "aws")
	f.Add("", "", "", "")
	f.Add("unicode-\u00e9\u4e2d", "prod\x00nul", "memory", "static")

	f.Fuzz(func(t *testing.T, serviceName, productID, metastore, kms string) {
		cfg := Config{ServiceName: serviceName, ProductID: productID, Metastore: metastore, KMS: kms}

		data, err := cfg.toJSON()

		// toJSON must reject invalid UTF-8 with an error rather than
		// silently letting json.Marshal substitute U+FFFD for the bad
		// bytes — a round-trip check can't detect that corruption since
		// the *output* is well-formed JSON, just not equal to the input.
		if !utf8.ValidString(serviceName) || !utf8.ValidString(productID) ||
			!utf8.ValidString(metastore) || !utf8.ValidString(kms) {
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

		wantKMS := kms
		if wantKMS == "" {
			wantKMS = "static"
		}
		if got.KMS != wantKMS {
			t.Fatalf("KMS default: got %q, want %q (input KMS=%q)", got.KMS, wantKMS, kms)
		}
	})
}
