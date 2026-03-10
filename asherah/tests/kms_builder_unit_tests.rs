#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Unit tests for `asherah::kms_builders::AwsKmsBuilder` and `aws_kms_from_env`.

use std::sync::{Arc, Mutex};

use asherah::aead::AES256GCM;
use asherah::kms_builders::{aws_kms_from_env, AwsKmsBuilder};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

const KMS_ENV_VARS: &[&str] = &["KMS_KEY_ID", "AWS_REGION"];

fn clear_kms_env() {
    for k in KMS_ENV_VARS {
        std::env::remove_var(k);
    }
}

// ──────────────────────── AwsKmsBuilder ────────────────────────

#[test]
fn builder_empty_entries_fails() {
    let aead = Arc::new(AES256GCM::new());
    let result = AwsKmsBuilder::new(aead).build();
    let err = result.err().expect("build with no entries should fail");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("no entries"),
        "expected 'no entries' error, got: {err_msg}"
    );
}

#[test]
fn builder_chain_api() {
    let aead = Arc::new(AES256GCM::new());
    // The builder itself should accept chained calls without panicking.
    // build() will fail because it tries to connect to AWS, but the error
    // should be about AWS connectivity, not about missing entries.
    let result = AwsKmsBuilder::new(aead)
        .add(
            "us-east-1",
            "arn:aws:kms:us-east-1:000000000000:key/fake-key-1",
        )
        .add(
            "us-west-2",
            "arn:aws:kms:us-west-2:000000000000:key/fake-key-2",
        )
        .preferred_region("us-east-1")
        .build();

    // It should either succeed (unlikely without real AWS creds) or fail
    // with an AWS error, not a "no entries" error.
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("no entries"),
            "should not fail with 'no entries' when entries were added, got: {msg}"
        );
    }
}

// ──────────────────────── aws_kms_from_env ────────────────────────

#[test]
fn aws_kms_from_env_missing_key_id_fails() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_kms_env();

    let aead = Arc::new(AES256GCM::new());
    let result = aws_kms_from_env(aead);
    assert!(result.is_err(), "should fail when KMS_KEY_ID is not set");

    clear_kms_env();
}

#[test]
fn aws_kms_from_env_with_key_id() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_kms_env();

    std::env::set_var(
        "KMS_KEY_ID",
        "arn:aws:kms:us-east-1:000000000000:key/test-key",
    );
    std::env::set_var("AWS_REGION", "us-east-1");

    let aead = Arc::new(AES256GCM::new());
    let result = aws_kms_from_env(aead);

    // The env var parsing should succeed. The call may succeed (creating a
    // client object) or fail at the AWS SDK level, but it should NOT fail
    // because of missing env vars.
    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("KMS_KEY_ID"),
            "should not fail due to missing KMS_KEY_ID when it is set, got: {msg}"
        );
    }

    clear_kms_env();
}
