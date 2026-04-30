package asherah

import (
	"encoding/json"
	"testing"
)

func TestConfigToJSONAwsProfileName(t *testing.T) {
	prof := "prod"
	cfg := Config{
		ServiceName:    "svc",
		ProductID:      "prod",
		Metastore:      "memory",
		AwsProfileName: &prof,
	}
	raw, err := cfg.toJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["AwsProfileName"].(string); !ok || v != "prod" {
		t.Fatalf("AwsProfileName = %q (%v), want prod", v, ok)
	}
}

func TestConfigToJSONAwsProfileNameOmittedWhenNil(t *testing.T) {
	cfg := Config{
		ServiceName: "svc",
		ProductID:   "prod",
		Metastore:   "memory",
	}
	raw, err := cfg.toJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["AwsProfileName"]; ok {
		t.Fatal("AwsProfileName should be omitted when nil")
	}
}
