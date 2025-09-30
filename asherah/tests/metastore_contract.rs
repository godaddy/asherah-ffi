use ael::traits::Metastore;
use ael::types::{EnvelopeKeyRecord, KeyMeta};
use asherah as ael;

fn run_contract<M: Metastore>(store: M) {
    // store returns true on first insert, false on duplicate
    let ekr1 = EnvelopeKeyRecord {
        revoked: Some(false),
        id: "id1".into(),
        created: 100,
        encrypted_key: vec![1],
        parent_key_meta: Some(KeyMeta {
            id: "p".into(),
            created: 10,
        }),
    };
    assert!(store.store(&ekr1.id, ekr1.created, &ekr1).unwrap());
    assert!(!store.store(&ekr1.id, ekr1.created, &ekr1).unwrap());

    // load returns equivalent record; some backends (JSON-based) do not persist `id` inside the JSON payload
    let got = store.load(&ekr1.id, ekr1.created).unwrap().unwrap();
    assert_eq!(got.created, ekr1.created);
    assert_eq!(got.revoked, ekr1.revoked);
    assert_eq!(got.parent_key_meta, ekr1.parent_key_meta);
    assert_eq!(got.encrypted_key, ekr1.encrypted_key);

    // load_latest returns highest created
    let ekr2 = EnvelopeKeyRecord {
        created: 200,
        ..ekr1.clone()
    };
    assert!(store.store(&ekr2.id, ekr2.created, &ekr2).unwrap());
    let latest = store.load_latest(&ekr2.id).unwrap().unwrap();
    assert_eq!(latest.created, 200);
}

#[test]
fn contract_inmemory() {
    run_contract(ael::metastore::InMemoryMetastore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn contract_sqlite() {
    let s = ael::metastore_sqlite::SqliteMetastore::open(":memory:").unwrap();
    run_contract(s);
}

#[cfg(feature = "mysql")]
#[test]
fn contract_mysql() {
    let url = match std::env::var("MYSQL_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("set MYSQL_URL to run MySQL contract test");
            return;
        }
    };
    let s = ael::metastore_mysql::MySqlMetastore::connect(&url).unwrap();
    run_contract(s);
}

#[cfg(feature = "postgres")]
#[test]
fn contract_postgres() {
    let url = match std::env::var("POSTGRES_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("set POSTGRES_URL to run Postgres contract test");
            return;
        }
    };
    let s = ael::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
    run_contract(s);
}

#[cfg(feature = "dynamodb")]
#[test]
fn contract_dynamodb() {
    let table = match std::env::var("DDB_TABLE") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("set DDB_TABLE to run DynamoDB contract test");
            return;
        }
    };
    let region = std::env::var("AWS_REGION").ok();
    let s = ael::metastore_dynamodb::DynamoDbMetastore::new(&table, region).unwrap();
    run_contract(s);
}
