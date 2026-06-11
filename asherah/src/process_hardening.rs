use std::sync::OnceLock;

static PROCESS_HARDENING: OnceLock<Result<(), String>> = OnceLock::new();

/// Apply process-level hardening and initialize the locked memory pool.
///
/// This is idempotent. A pre-initialized hardware-enclave pool is treated as
/// success so callers can invoke this from multiple language binding setup
/// paths without depending on global initialization order.
pub fn ensure_process_hardened() -> anyhow::Result<()> {
    let result = PROCESS_HARDENING.get_or_init(|| {
        hardware_enclave::harden_process();
        match hardware_enclave::init_pool(hardware_enclave::TieredPoolConfig::default()) {
            Ok(()) => Ok(()),
            Err(hardware_enclave::Error::Memory(message))
                if message == "pool already initialized" =>
            {
                Ok(())
            }
            Err(err) => Err(format!(
                "failed to initialize hardware-enclave memory pool: {err}"
            )),
        }
    });

    match result {
        Ok(()) => Ok(()),
        Err(message) => Err(anyhow::anyhow!(message.clone())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn process_hardening_is_idempotent() {
        ensure_process_hardened().unwrap();
        ensure_process_hardened().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_hardening_disables_core_dumps() {
        ensure_process_hardened().unwrap();

        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}
