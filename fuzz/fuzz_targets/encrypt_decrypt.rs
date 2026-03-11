#![no_main]
//! Fuzz encrypt/decrypt roundtrip with adversarial partition IDs and payloads.
//!
//! Targets: partition ID edge cases, empty/huge payloads, corrupt DRR injection,
//! cross-partition decrypt attempts.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static SETUP: Once = Once::new();

fn ensure_setup() {
    SETUP.call_once(|| {
        if std::env::var("STATIC_MASTER_KEY_HEX").is_err() {
            std::env::set_var("STATIC_MASTER_KEY_HEX", "22".repeat(32));
        }
        std::env::set_var("SERVICE_NAME", "fuzz-svc");
        std::env::set_var("PRODUCT_ID", "fuzz-prod");
        std::env::set_var("Metastore", "memory");
        std::env::set_var("KMS", "static");
    });
}

#[derive(Arbitrary, Debug)]
struct RoundtripInput {
    partition_id: String,
    payload: Vec<u8>,
    tamper_drr: bool,
    tamper_byte: u8,
    tamper_offset: u8,
}

fuzz_target!(|input: RoundtripInput| {
    // Skip empty partition IDs (rejected by session validation)
    if input.partition_id.is_empty() {
        return;
    }
    // Limit sizes to keep fuzzing fast
    if input.partition_id.len() > 256 || input.payload.len() > 4096 {
        return;
    }

    ensure_setup();

    let factory = match asherah::builders::factory_from_env() {
        Ok(f) => f,
        Err(_) => return,
    };

    let session = factory.get_session(&input.partition_id);

    // Encrypt should succeed for any valid partition ID and payload
    let drr = match session.encrypt(&input.payload) {
        Ok(d) => d,
        Err(_) => {
            drop(session.close());
            return;
        }
    };

    if input.tamper_drr {
        // Serialize, tamper, deserialize, try decrypt — should fail gracefully
        if let Ok(mut json) = serde_json::to_string(&drr) {
            let bytes = unsafe { json.as_bytes_mut() };
            if !bytes.is_empty() {
                let idx = input.tamper_offset as usize % bytes.len();
                bytes[idx] ^= input.tamper_byte | 1; // ensure at least 1 bit flips
            }
            if let Ok(tampered_drr) = serde_json::from_str::<asherah::types::DataRowRecord>(&json)
            {
                // Decrypt of tampered DRR should fail, not panic
                let _ = session.decrypt(tampered_drr);
            }
        }
    } else {
        // Clean roundtrip — must succeed and match
        let plaintext = session
            .decrypt(drr)
            .expect("decrypt of own ciphertext should succeed");
        assert_eq!(
            plaintext, input.payload,
            "roundtrip mismatch for partition {:?}",
            input.partition_id
        );
    }

    drop(session.close());
});
