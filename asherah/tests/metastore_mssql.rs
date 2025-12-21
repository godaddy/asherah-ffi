#[cfg(feature = "mssql")]
#[test]
fn metastore_mssql_roundtrip_if_env() {
    use asherah::Metastore;
    let url = match std::env::var("MSSQL_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("MSSQL_URL not set; skipping");
            return;
        }
    };
    let store = match asherah::metastore_mssql::MssqlMetastore::connect(&url) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("MSSQL_URL connect failed: {err}");
            return;
        }
    };
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id = format!("mssql-test-{created}");
    let ekr = asherah::EnvelopeKeyRecord {
        revoked: None,
        id: id.clone(),
        created,
        encrypted_key: vec![1, 2, 3],
        parent_key_meta: None,
    };

    assert!(store.store(&id, created, &ekr).unwrap());
    let loaded = store.load(&id, created).unwrap().unwrap();
    assert_eq!(loaded.created, ekr.created);
    assert_eq!(loaded.encrypted_key, ekr.encrypted_key);
    assert_eq!(loaded.parent_key_meta, ekr.parent_key_meta);
    assert_eq!(loaded.revoked, ekr.revoked);

    let dup = store.store(&id, created, &ekr).unwrap();
    assert!(!dup);

    let latest = store.load_latest(&id).unwrap().unwrap();
    assert_eq!(latest.created, ekr.created);
    assert_eq!(latest.encrypted_key, ekr.encrypted_key);
}
