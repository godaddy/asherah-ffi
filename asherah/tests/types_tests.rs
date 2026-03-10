#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for types: KeyMeta, EnvelopeKeyRecord, DataRowRecord serialization.

use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

// ──────────────────────────── KeyMeta ────────────────────────────

#[test]
fn key_meta_is_latest_when_created_zero() {
    let m = KeyMeta {
        id: "k".into(),
        created: 0,
    };
    assert!(m.is_latest());
}

#[test]
fn key_meta_not_latest_when_created_nonzero() {
    let m = KeyMeta {
        id: "k".into(),
        created: 42,
    };
    assert!(!m.is_latest());
}

#[test]
fn key_meta_as_latest() {
    let m = KeyMeta {
        id: "k".into(),
        created: 42,
    };
    let latest = m.as_latest();
    assert_eq!(latest.id, "k");
    assert_eq!(latest.created, 0);
    assert!(latest.is_latest());
}

// ──────────────────────────── JSON field names ────────────────────────────

#[test]
fn key_meta_json_field_names() {
    let m = KeyMeta {
        id: "my-key".into(),
        created: 123,
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"KeyId\""), "expected KeyId, got {json}");
    assert!(json.contains("\"Created\""), "expected Created, got {json}");
    assert!(!json.contains("\"id\""), "should not have lowercase id");
}

#[test]
fn key_meta_json_roundtrip() {
    let m = KeyMeta {
        id: "test".into(),
        created: 999,
    };
    let json = serde_json::to_string(&m).unwrap();
    let m2: KeyMeta = serde_json::from_str(&json).unwrap();
    assert_eq!(m, m2);
}

// ──────────────────────────── EnvelopeKeyRecord ────────────────────────────

#[test]
fn ekr_json_base64_key() {
    let ekr = EnvelopeKeyRecord {
        id: "ignored".into(),
        created: 100,
        encrypted_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
        revoked: None,
        parent_key_meta: None,
    };
    let json = serde_json::to_string(&ekr).unwrap();
    // "Key" field should be base64 encoded
    assert!(json.contains("\"Key\":\""), "expected Key field: {json}");
    // "id" field is skipped in serialization
    assert!(!json.contains("\"id\""), "id should be skipped: {json}");
    // Revoked should be skipped when None
    assert!(
        !json.contains("Revoked"),
        "null revoked should be skipped: {json}"
    );
}

#[test]
fn ekr_json_roundtrip() {
    let ekr = EnvelopeKeyRecord {
        id: String::new(), // skipped in JSON
        created: 42,
        encrypted_key: vec![1, 2, 3, 4, 5],
        revoked: Some(true),
        parent_key_meta: Some(KeyMeta {
            id: "parent".into(),
            created: 10,
        }),
    };
    let json = serde_json::to_string(&ekr).unwrap();
    let ekr2: EnvelopeKeyRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ekr2.created, 42);
    assert_eq!(ekr2.encrypted_key, vec![1, 2, 3, 4, 5]);
    assert_eq!(ekr2.revoked, Some(true));
    assert_eq!(ekr2.parent_key_meta.as_ref().unwrap().id, "parent");
    // id is skipped so it defaults to empty
    assert_eq!(ekr2.id, "");
}

#[test]
fn ekr_revoked_false_serialized() {
    let ekr = EnvelopeKeyRecord {
        id: String::new(),
        created: 1,
        encrypted_key: vec![1],
        revoked: Some(false),
        parent_key_meta: None,
    };
    let json = serde_json::to_string(&ekr).unwrap();
    assert!(
        json.contains("\"Revoked\":false"),
        "false should be serialized: {json}"
    );
}

// ──────────────────────────── DataRowRecord ────────────────────────────

#[test]
fn drr_json_field_names() {
    let drr = DataRowRecord {
        key: None,
        data: vec![10, 20, 30],
    };
    let json = serde_json::to_string(&drr).unwrap();
    assert!(json.contains("\"Key\":null"), "expected Key:null: {json}");
    assert!(json.contains("\"Data\":\""), "expected Data field: {json}");
}

#[test]
fn drr_json_roundtrip_with_key() {
    let drr = DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created: 100,
            encrypted_key: vec![0xAA, 0xBB],
            revoked: None,
            parent_key_meta: Some(KeyMeta {
                id: "ik".into(),
                created: 50,
            }),
        }),
        data: vec![0xFF, 0x00, 0x42],
    };
    let json = serde_json::to_string(&drr).unwrap();
    let drr2: DataRowRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(drr2.data, vec![0xFF, 0x00, 0x42]);
    assert_eq!(drr2.key.as_ref().unwrap().created, 100);
    assert_eq!(drr2.key.as_ref().unwrap().encrypted_key, vec![0xAA, 0xBB]);
}

#[test]
fn drr_json_roundtrip_no_key() {
    let drr = DataRowRecord {
        key: None,
        data: vec![1, 2, 3],
    };
    let json = serde_json::to_string(&drr).unwrap();
    let drr2: DataRowRecord = serde_json::from_str(&json).unwrap();
    assert!(drr2.key.is_none());
    assert_eq!(drr2.data, vec![1, 2, 3]);
}

// ──────────────────────────── Base64 edge cases ────────────────────────────

#[test]
fn drr_empty_data_base64() {
    let drr = DataRowRecord {
        key: None,
        data: vec![],
    };
    let json = serde_json::to_string(&drr).unwrap();
    // Empty bytes should be encoded as empty base64 string
    assert!(json.contains("\"Data\":\"\""), "empty data: {json}");
    let drr2: DataRowRecord = serde_json::from_str(&json).unwrap();
    assert!(drr2.data.is_empty());
}

#[test]
fn drr_invalid_base64_in_data_fails() {
    let json = r#"{"Key":null,"Data":"not-valid-base64!!!"}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "invalid base64 should fail deserialization"
    );
}

#[test]
fn ekr_invalid_base64_in_key_fails() {
    let json = r#"{"Created":1,"Key":"!!!invalid!!!"}"#;
    let result: Result<EnvelopeKeyRecord, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ──────────────────────────── Go compatibility ────────────────────────────

#[test]
fn go_compatible_drr_deserialize() {
    // Simulate a DRR produced by the Go implementation
    let go_json = r#"{
        "Key": {
            "Created": 1709913600,
            "Key": "AQIDBA==",
            "ParentKeyMeta": {
                "KeyId": "_IK_user1_svc_prod",
                "Created": 1709913540
            }
        },
        "Data": "dGVzdA=="
    }"#;
    let drr: DataRowRecord = serde_json::from_str(go_json).unwrap();
    assert_eq!(drr.data, b"test");
    let key = drr.key.unwrap();
    assert_eq!(key.created, 1709913600);
    assert_eq!(key.encrypted_key, vec![1, 2, 3, 4]);
    let parent = key.parent_key_meta.unwrap();
    assert_eq!(parent.id, "_IK_user1_svc_prod");
    assert_eq!(parent.created, 1709913540);
}

// ──────────────────────────── Malformed JSON ────────────────────────────

#[test]
fn drr_from_invalid_json_fails() {
    let result: Result<DataRowRecord, _> = serde_json::from_str("{not json}");
    assert!(result.is_err(), "malformed JSON should fail");
}

#[test]
fn ekr_from_invalid_json_fails() {
    let result: Result<EnvelopeKeyRecord, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err(), "array should not deserialize as EKR");
}

#[test]
fn key_meta_from_invalid_json_fails() {
    let result: Result<KeyMeta, _> = serde_json::from_str("null");
    assert!(result.is_err(), "null should not deserialize as KeyMeta");
}

// ──────────────────────────── Missing required fields ────────────────────────────

#[test]
fn drr_missing_data_field_fails() {
    let json = r#"{"Key":null}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "missing Data field should fail");
}

#[test]
fn ekr_missing_created_field_fails() {
    let json = r#"{"Key":"AQID"}"#;
    let result: Result<EnvelopeKeyRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "missing Created field should fail");
}

#[test]
fn key_meta_missing_key_id_fails() {
    let json = r#"{"Created":1}"#;
    let result: Result<KeyMeta, _> = serde_json::from_str(json);
    assert!(result.is_err(), "missing KeyId field should fail");
}

// ──────────────────────────── Extra unknown fields ignored ────────────────────────────

#[test]
fn drr_extra_fields_ignored() {
    let json = r#"{"Key":null,"Data":"AQID","Extra":"ignored","Foo":42}"#;
    let drr: DataRowRecord = serde_json::from_str(json).unwrap();
    assert_eq!(drr.data, vec![1, 2, 3]);
    assert!(drr.key.is_none());
}

#[test]
fn ekr_extra_fields_ignored() {
    let json = r#"{"Created":1,"Key":"AQID","Unknown":"x"}"#;
    let ekr: EnvelopeKeyRecord = serde_json::from_str(json).unwrap();
    assert_eq!(ekr.created, 1);
    assert_eq!(ekr.encrypted_key, vec![1, 2, 3]);
}

#[test]
fn key_meta_extra_fields_ignored() {
    let json = r#"{"KeyId":"k","Created":1,"Bonus":true}"#;
    let m: KeyMeta = serde_json::from_str(json).unwrap();
    assert_eq!(m.id, "k");
    assert_eq!(m.created, 1);
}

// ──────────────────────────── Type mismatches ────────────────────────────

#[test]
fn drr_data_as_number_fails() {
    let json = r#"{"Key":null,"Data":123}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "Data as number should fail");
}

#[test]
fn ekr_created_as_string_fails() {
    let json = r#"{"Created":"not-a-number","Key":"AQID"}"#;
    let result: Result<EnvelopeKeyRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "Created as string should fail");
}

#[test]
fn key_meta_created_as_bool_fails() {
    let json = r#"{"KeyId":"k","Created":true}"#;
    let result: Result<KeyMeta, _> = serde_json::from_str(json);
    assert!(result.is_err(), "Created as bool should fail");
}

// ──────────────────────────── Null handling ────────────────────────────

#[test]
fn drr_null_data_fails() {
    let json = r#"{"Key":null,"Data":null}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "null Data should fail (base64 expects string)"
    );
}

#[test]
fn ekr_null_key_field() {
    let json = r#"{"Created":1,"Key":null}"#;
    let result: Result<EnvelopeKeyRecord, _> = serde_json::from_str(json);
    // Key uses a custom base64 deserializer that calls String::deserialize,
    // which will reject null.
    assert!(
        result.is_err(),
        "null Key should fail (base64 expects string)"
    );
}

#[test]
fn key_meta_null_id_fails() {
    let json = r#"{"KeyId":null,"Created":1}"#;
    let result: Result<KeyMeta, _> = serde_json::from_str(json);
    assert!(result.is_err(), "null KeyId should fail");
}

// ──────────────────────────── Empty string base64 ────────────────────────────

#[test]
fn ekr_empty_string_key_is_empty_vec() {
    let json = r#"{"Created":1,"Key":""}"#;
    let ekr: EnvelopeKeyRecord = serde_json::from_str(json).unwrap();
    assert!(
        ekr.encrypted_key.is_empty(),
        "empty base64 string should give empty vec"
    );
    assert_eq!(ekr.created, 1);
}

// ──────────────────────────── Base64 edge cases ────────────────────────────

#[test]
fn base64_with_whitespace_fails() {
    // STANDARD engine does not accept whitespace in base64
    let json = r#"{"Key":null,"Data":"AQ ID"}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "whitespace in base64 should fail");
}

#[test]
fn base64_with_newline_fails() {
    let json = "{\"Key\":null,\"Data\":\"AQ\\nID\"}";
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "newline in base64 should fail");
}

#[test]
fn base64_url_safe_chars_fail() {
    // URL-safe base64 uses - and _ instead of + and /
    // STANDARD engine should reject these
    let json = r#"{"Key":null,"Data":"ab-_"}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "URL-safe base64 chars should fail with STANDARD engine"
    );
}

#[test]
fn base64_standard_with_plus_and_slash() {
    // + and / are valid in STANDARD base64
    // "+/" decodes to [0xFB, 0xFF] (base64: +/8= for [0xFB, 0xFF])
    let json = r#"{"Key":null,"Data":"+/8="}"#;
    let drr: DataRowRecord = serde_json::from_str(json).unwrap();
    assert_eq!(drr.data, vec![0xFB, 0xFF]);
}

#[test]
fn base64_with_trailing_garbage_fails() {
    let json = r#"{"Key":null,"Data":"AQID!!!"}"#;
    let result: Result<DataRowRecord, _> = serde_json::from_str(json);
    assert!(result.is_err(), "trailing non-base64 chars should fail");
}

#[test]
fn base64_single_pad_char() {
    // "AQ==" is valid base64 for [0x01]
    let json = r#"{"Key":null,"Data":"AQ=="}"#;
    let drr: DataRowRecord = serde_json::from_str(json).unwrap();
    assert_eq!(drr.data, vec![0x01]);
}

#[test]
fn base64_double_pad_char() {
    // "AQI=" is valid base64 for [0x01, 0x02]
    let json = r#"{"Key":null,"Data":"AQI="}"#;
    let drr: DataRowRecord = serde_json::from_str(json).unwrap();
    assert_eq!(drr.data, vec![0x01, 0x02]);
}
