package asherah

import "testing"

// FuzzSetEnvJSON exercises SetEnvJSON, a public entry point that unmarshals
// fully caller-controlled bytes into a map[string]*string. It must never
// panic, regardless of how malformed the JSON is.
func FuzzSetEnvJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"KMS":"static"}`))
	f.Add([]byte(`{"KMS":null}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = SetEnvJSON(payload) // error is fine; panic is not
	})
}
