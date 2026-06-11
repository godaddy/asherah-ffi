/// Default maximum plaintext bytes accepted by public encrypt APIs.
///
/// Asherah is intended for application data row encryption, not bulk object
/// storage. Keeping an explicit cap prevents accidental unbounded allocation or
/// CPU work at FFI/server boundaries while staying far above normal row sizes.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Default maximum serialized envelope bytes accepted by FFI JSON APIs.
pub const MAX_ENVELOPE_BYTES: usize = MAX_PAYLOAD_BYTES + 1024 * 1024;

/// Maximum encrypted data-row key bytes accepted inside a data row record.
///
/// Normal AES-GCM-wrapped DRKs are much smaller. This headroom preserves
/// compatibility for future envelope metadata while preventing attackers from
/// hiding large allocations in nested key fields.
pub const MAX_DATA_ROW_ENCRYPTED_KEY_BYTES: usize = 16 * 1024;

/// Maximum key identifier bytes accepted inside a data row record.
pub const MAX_DATA_ROW_KEY_ID_BYTES: usize = 4 * 1024;

pub fn check_plaintext_len(len: usize) -> anyhow::Result<()> {
    if len > MAX_PAYLOAD_BYTES {
        anyhow::bail!(
            "plaintext length {len} exceeds maximum {} bytes",
            MAX_PAYLOAD_BYTES
        );
    }
    Ok(())
}

pub fn check_ciphertext_len(len: usize) -> anyhow::Result<()> {
    if len > MAX_ENVELOPE_BYTES {
        anyhow::bail!(
            "ciphertext/envelope length {len} exceeds maximum {} bytes",
            MAX_ENVELOPE_BYTES
        );
    }
    Ok(())
}

fn check_nested_len(label: &str, len: usize, max: usize) -> anyhow::Result<()> {
    if len > max {
        anyhow::bail!("{label} length {len} exceeds maximum {max} bytes");
    }
    Ok(())
}

pub fn check_data_row_record(drr: &crate::types::DataRowRecord) -> anyhow::Result<()> {
    check_ciphertext_len(drr.data.len())?;

    let mut total_len = drr.data.len();
    if let Some(key) = &drr.key {
        check_nested_len(
            "encrypted data-row key",
            key.encrypted_key.len(),
            MAX_DATA_ROW_ENCRYPTED_KEY_BYTES,
        )?;
        check_nested_len("data-row key id", key.id.len(), MAX_DATA_ROW_KEY_ID_BYTES)?;
        total_len = total_len
            .saturating_add(key.encrypted_key.len())
            .saturating_add(key.id.len());

        if let Some(parent) = &key.parent_key_meta {
            check_nested_len("parent key id", parent.id.len(), MAX_DATA_ROW_KEY_ID_BYTES)?;
            total_len = total_len.saturating_add(parent.id.len());
        }
    }

    check_ciphertext_len(total_len)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

    fn drr_with_nested_lengths(
        data_len: usize,
        encrypted_key_len: usize,
        key_id_len: usize,
    ) -> DataRowRecord {
        DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                revoked: None,
                id: "k".repeat(key_id_len),
                created: 1,
                encrypted_key: vec![0_u8; encrypted_key_len],
                parent_key_meta: Some(KeyMeta {
                    id: "p".repeat(key_id_len),
                    created: 1,
                }),
            }),
            data: vec![0_u8; data_len],
        }
    }

    #[test]
    fn plaintext_limit_accepts_boundary_and_rejects_oversize() {
        assert!(check_plaintext_len(MAX_PAYLOAD_BYTES).is_ok());
        assert!(check_plaintext_len(MAX_PAYLOAD_BYTES + 1).is_err());
    }

    #[test]
    fn ciphertext_limit_accepts_boundary_and_rejects_oversize() {
        assert!(check_ciphertext_len(MAX_ENVELOPE_BYTES).is_ok());
        assert!(check_ciphertext_len(MAX_ENVELOPE_BYTES + 1).is_err());
    }

    #[test]
    fn data_row_record_limit_rejects_oversize_nested_key() {
        let drr = drr_with_nested_lengths(0, MAX_DATA_ROW_ENCRYPTED_KEY_BYTES + 1, 0);
        assert!(check_data_row_record(&drr).is_err());
    }

    #[test]
    fn data_row_record_limit_rejects_oversize_key_ids() {
        let drr = drr_with_nested_lengths(0, 0, MAX_DATA_ROW_KEY_ID_BYTES + 1);
        assert!(check_data_row_record(&drr).is_err());
    }
}
