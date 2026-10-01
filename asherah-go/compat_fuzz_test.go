package asherah

import (
	"encoding/json"
	"testing"
)

// FuzzDataRowRecordUnmarshal exercises the JSON decode path CompatSession.
// Encrypt uses on the native library's response (compat.go), and
// CompatSession.Decrypt's inverse encode path. The native response is
// trusted content today, but a corrupted/mismatched native build must not
// crash the Go process.
func FuzzDataRowRecordUnmarshal(f *testing.F) {
	f.Add([]byte(`{"Key":{"Key":"AQID","Created":1},"Data":"AQID"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"Key":null,"Data":null}`))
	f.Add([]byte(`{"Key":{"ParentKeyMeta":{"KeyId":"x","Created":1}}}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, payload []byte) {
		var drr DataRowRecord
		if err := json.Unmarshal(payload, &drr); err != nil {
			return // error is fine; panic is not
		}
		// Round-trip through Marshal too, mirroring CompatSession.Decrypt.
		_, _ = json.Marshal(&drr)
	})
}
