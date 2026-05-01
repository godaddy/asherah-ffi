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

func TestConfigToJSONDynamoDBSigningRegion(t *testing.T) {
	region := "us-east-1"
	signing := "us-west-2"
	cfg := Config{
		ServiceName:           "svc",
		ProductID:             "prod",
		Metastore:             "dynamodb",
		DynamoDBRegion:        &region,
		DynamoDBSigningRegion: &signing,
	}
	raw, err := cfg.toJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["DynamoDBRegion"].(string); !ok || v != "us-east-1" {
		t.Fatalf("DynamoDBRegion = %q (%v), want us-east-1", v, ok)
	}
	if v, ok := m["DynamoDBSigningRegion"].(string); !ok || v != "us-west-2" {
		t.Fatalf("DynamoDBSigningRegion = %q (%v), want us-west-2", v, ok)
	}
}

func TestConfigToJSONDynamoDBSigningRegionOmittedWhenNil(t *testing.T) {
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
	if _, ok := m["DynamoDBSigningRegion"]; ok {
		t.Fatal("DynamoDBSigningRegion should be omitted when nil")
	}
}
