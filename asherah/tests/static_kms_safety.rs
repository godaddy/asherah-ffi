#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for the static KMS path. Legacy `KMS=static` requires explicit key
//! material. The `KMS=test-debug-static` resolver path can fill in the public
//! test key before constructing the static KMS.

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
fn static_kms_with_empty_key_hex_is_rejected() {
    let cfg = resolved_with_kms(KmsConfig::Static {
        key_hex: String::new(),
    });
    let err = match factory_from_resolved(&cfg) {
        Ok(_) => panic!("empty static key must be rejected"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("static master key hex is required"),
        "unexpected error: {err}"
    );
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
