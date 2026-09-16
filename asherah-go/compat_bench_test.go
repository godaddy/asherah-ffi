package asherah

import "testing"

// BenchmarkStaticKMSApplyConfig exercises StaticKMS.applyConfig.
// Comparable against main: applyConfig's name and signature are
// unchanged; the only difference is the hex encoding now going through
// the extracted hexEncodeKey helper instead of an inline fmt.Sprintf.
func BenchmarkStaticKMSApplyConfig(b *testing.B) {
	kms := NewStaticKMS("a-reasonably-long-test-master-key-string")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cfg := &Config{}
		kms.applyConfig(cfg)
	}
}
