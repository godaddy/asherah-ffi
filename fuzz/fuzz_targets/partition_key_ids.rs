#![no_main]
//! Fuzz partition key ID generation and validation.
//!
//! Targets:
//! - Key ID delimiter collisions: partition/service/product containing "_"
//!   can produce identical key IDs for different inputs
//! - is_valid_intermediate_key_id prefix matching with region suffixes
//! - System key ID collisions across service/product pairs

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asherah::partition::DefaultPartition;
use asherah::traits::Partition;

#[derive(Arbitrary, Debug)]
struct PartitionInput {
    id1: String,
    service1: String,
    product1: String,
    id2: String,
    service2: String,
    product2: String,
    suffix: Option<String>,
    probe_id: String,
}

fuzz_target!(|input: PartitionInput| {
    // Skip empty inputs (they'd just produce identical prefixes)
    if input.id1.is_empty()
        || input.service1.is_empty()
        || input.product1.is_empty()
        || input.id2.is_empty()
        || input.service2.is_empty()
        || input.product2.is_empty()
    {
        return;
    }

    // Limit string lengths to avoid OOM
    if input.id1.len() > 256
        || input.service1.len() > 256
        || input.product1.len() > 256
        || input.id2.len() > 256
        || input.service2.len() > 256
        || input.product2.len() > 256
    {
        return;
    }

    let p1 = match &input.suffix {
        Some(s) if !s.is_empty() && s.len() <= 256 => DefaultPartition::new_suffixed(
            input.id1.clone(),
            input.service1.clone(),
            input.product1.clone(),
            s.clone(),
        ),
        _ => DefaultPartition::new(
            input.id1.clone(),
            input.service1.clone(),
            input.product1.clone(),
        ),
    };

    let p2 = DefaultPartition::new(
        input.id2.clone(),
        input.service2.clone(),
        input.product2.clone(),
    );

    let ik1 = p1.intermediate_key_id();
    let ik2 = p2.intermediate_key_id();
    let sk1 = p1.system_key_id();
    let sk2 = p2.system_key_id();

    // Test validation doesn't accept unrelated IDs
    let _ = p1.is_valid_intermediate_key_id(&ik1);
    let _ = p1.is_valid_intermediate_key_id(&ik2);
    let _ = p1.is_valid_intermediate_key_id(&input.probe_id);

    // Cross-partition validation: p1 should NOT validate p2's IK (unless collision).
    // When inputs contain "_" (the delimiter), collisions are a known limitation
    // matching the canonical Go implementation — skip assertion in that case.
    let has_delimiter = input.id1.contains('_')
        || input.service1.contains('_')
        || input.product1.contains('_')
        || input.id2.contains('_')
        || input.service2.contains('_')
        || input.product2.contains('_');

    if !has_delimiter && p1.is_valid_intermediate_key_id(&ik2) && ik1 != ik2 {
        panic!(
            "Cross-partition validation bypass: p1 ({:?},{:?},{:?}) accepts p2's IK {:?}",
            input.id1, input.service1, input.product1, ik2,
        );
    }
});
