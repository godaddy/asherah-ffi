use std::sync::Once;

use asherah as ael;

static INIT: Once = Once::new();

fn setup_env() {
    INIT.call_once(|| {
        std::env::set_var("SERVICE_NAME", "svc");
        std::env::set_var("PRODUCT_ID", "prod");
        std::env::set_var("KMS", "static");
        std::env::set_var(
            "STATIC_MASTER_KEY_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var("Metastore", "memory");
    });
}

#[test]
fn factory_from_env_inmemory() {
    setup_env();
    let f = ael::builders::factory_from_env().expect("factory");
    let s = f.get_session("p1");
    let drr = s.encrypt(b"env-test").unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, b"env-test");
}
