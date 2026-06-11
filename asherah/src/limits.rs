/// Default maximum plaintext bytes accepted by public encrypt APIs.
///
/// Asherah is intended for application data row encryption, not bulk object
/// storage. Keeping an explicit cap prevents accidental unbounded allocation or
/// CPU work at FFI/server boundaries while staying far above normal row sizes.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Default maximum serialized envelope bytes accepted by FFI JSON APIs.
pub const MAX_ENVELOPE_BYTES: usize = MAX_PAYLOAD_BYTES + 1024 * 1024;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
