use asherah as ael;

#[test]
fn test_envelope_json_fields() {
    let ekr = ael::types::EnvelopeKeyRecord {
        revoked: Some(false),
        id: "_IK_id_svc_prod".into(),
        created: 1234,
        encrypted_key: vec![1, 2, 3],
        parent_key_meta: Some(ael::types::KeyMeta {
            id: "_SK_svc_prod".into(),
            created: 1000,
        }),
    };
    let drr = ael::types::DataRowRecord {
        key: Some(ekr),
        data: vec![9, 9, 9],
    };
    let j = serde_json::to_string(&drr).unwrap();
    assert!(j.contains("\"Key\""));
    assert!(j.contains("\"Data\""));
    assert!(j.contains("\"Created\""));
    assert!(j.contains("\"KeyId\""));
    // id field must not be serialized
    assert!(!j.contains("\"id\""));
}
