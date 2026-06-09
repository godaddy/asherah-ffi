#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for the static KMS path. `KMS=static` and `KMS=test-debug-static`
//! are synonyms — the latter is the preferred identifier because its name
//! makes the non-production nature obvious, but both must behave
//! identically to preserve interop with the canonical Go implementation.
//! When no `key_hex` is supplied, both fall back to the publicly known
//! test key. The static-KMS builder log-warns loudly so an operator who
//! accidentally ships `static` without an explicit hex sees the warning.

use asherah::builders::{
    factory_from_resolved, KmsConfig, MetastoreConfig, PolicyConfig, ResolvedConfig,
    TEST_DEBUG_STATIC_MASTER_KEY_HEX,
};

fn resolved_with_kms(kms: KmsConfig) -> ResolvedConfig {
    ResolvedConfig {
        service_name: "svc".into(),
        product_id: "prod".into(),
        region_suffix: None,
        recovery_region_suffixes: Vec::new(),
        self_heal_recovered_keys: true,
        aws_profile_name: None,
        metastore: MetastoreConfig::Memory,
        kms,
        policy: PolicyConfig::default(),
    }
}

#[test]
fn static_kms_with_empty_key_hex_falls_back_to_test_key() {
    // Empty `key_hex` falls back to the publicly known test key
    // (Go-canonical behavior). The warning emitted by the builder is
    // the production-safety net — there is no hard rejection here.
    let cfg = resolved_with_kms(KmsConfig::Static {
        key_hex: String::new(),
    });
    factory_from_resolved(&cfg).expect("empty key_hex must fall back to test key, not error");
}

#[test]
fn static_kms_with_explicit_hex_succeeds() {
    let cfg = resolved_with_kms(KmsConfig::Static {
        key_hex: "00".repeat(32),
    });
    if factory_from_resolved(&cfg).is_err() {
        panic!("explicit non-empty key_hex must succeed");
    }
}

#[test]
fn test_debug_static_constant_decodes_to_canonical_ascii() {
    // The well-known fallback key is the ASCII bytes of
    // "thisIsAStaticMasterKeyForTesting" — verify the constant matches so a
    // future hex-typo regression is caught at the unit level.
    let bytes: Vec<u8> = (0..TEST_DEBUG_STATIC_MASTER_KEY_HEX.len() / 2)
        .map(|i| {
            u8::from_str_radix(&TEST_DEBUG_STATIC_MASTER_KEY_HEX[2 * i..2 * i + 2], 16).unwrap()
        })
        .collect();
    assert_eq!(bytes, b"thisIsAStaticMasterKeyForTesting");
}
