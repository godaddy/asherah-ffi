//! AWS environment fence and log capture shared by the `AwsKmsEnvelope`
//! error-path test binaries (`kms_envelope_*.rs`).
//!
//! `fence_env` must run before any SDK client or config is built in the
//! process: the default credential, region and endpoint chains read the
//! environment when a client is constructed. Environment variables are
//! process-wide, so a binary that needs a different fence (no credentials,
//! no region, another endpoint) is a separate test binary, or runs its
//! scenarios sequentially from a single test.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use asherah::logging::{ensure_logger, set_sink, LogSink};
use aws_sdk_kms::config::ProvideCredentials;

pub const DUMMY_ACCESS_KEY_ID: &str = "AKIDFAKEKMSENVELOPE0";

/// Substrings that must never reach an error string or a log record: the
/// planted AWS message (principal and key ARNs, account id), configured
/// key ids, a key ARN placed where a region belongs, and the fake data
/// keys (base64 and hex of `[0x42; 32]` / `[0x24; 32]`).
pub const FORBIDDEN: &[&str] = &[
    "arn:",
    "123456789012",
    "000000000000",
    "111122223333",
    "swapped-map-key",
    "planted",
    "not authorized",
    "identity-based",
    "assumed-role",
    "kms:Decrypt",
    "QkJCQkJC",
    "42424242",
    "JCQkJCQk",
    "24242424",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Creds {
    Dummy,
    Absent,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionEnv {
    Set,
    Unset,
}

/// Neutralise every AWS configuration source the SDK's default chains
/// consult, then point the endpoint at `endpoint` (a 127.0.0.1 URL).
pub fn fence_env(endpoint: &str, creds: Creds, region: RegionEnv) {
    for k in [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ENDPOINT_URL_KMS",
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
        "AWS_USE_FIPS_ENDPOINT",
        "AWS_USE_DUALSTACK_ENDPOINT",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var(
        "AWS_CONFIG_FILE",
        "/nonexistent/asherah-kms-envelope-errors/config",
    );
    std::env::set_var(
        "AWS_SHARED_CREDENTIALS_FILE",
        "/nonexistent/asherah-kms-envelope-errors/credentials",
    );
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    if creds == Creds::Dummy {
        std::env::set_var("AWS_ACCESS_KEY_ID", DUMMY_ACCESS_KEY_ID);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake-kms-envelope-secret");
    }
    if region == RegionEnv::Set {
        std::env::set_var("AWS_REGION", "us-west-2");
    }
    std::env::set_var("AWS_MAX_ATTEMPTS", "1");
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
    std::env::set_var("AWS_ENDPOINT_URL", endpoint);
}

pub fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or("");
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

/// Fail unless the SDK, configured from this process's environment the
/// same way `AwsKmsEnvelope` configures it, resolves a loopback endpoint
/// and either the dummy credentials or (for `Creds::Absent`) none at all.
pub fn assert_loopback_only(expected_endpoint: &str, creds: Creds) {
    let env_ep = std::env::var("AWS_ENDPOINT_URL").expect("AWS_ENDPOINT_URL must be set");
    assert_eq!(env_ep, expected_endpoint);
    assert!(
        matches!(host_of(&env_ep), "127.0.0.1" | "localhost"),
        "refusing to run: AWS_ENDPOINT_URL {env_ep} is not loopback"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (sdk_ep, akid) = rt.block_on(async {
        let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new("us-west-2"))
            .load()
            .await;
        let ep = conf.endpoint_url().map(str::to_string);
        let creds = conf
            .credentials_provider()
            .expect("credentials provider")
            .provide_credentials()
            .await
            .map(|c| c.access_key_id().to_string());
        (ep, creds)
    });
    let sdk_ep = sdk_ep.expect("SDK config must carry the fake endpoint");
    let host = host_of(&sdk_ep);
    assert!(
        host == "127.0.0.1" || host == "localhost",
        "refusing to run: effective KMS endpoint {sdk_ep} is not loopback"
    );
    match creds {
        Creds::Dummy => assert_eq!(
            akid.as_deref().ok(),
            Some(DUMMY_ACCESS_KEY_ID),
            "refusing to run: credentials did not come from the dummy env values"
        ),
        Creds::Absent => assert!(
            akid.is_err(),
            "refusing to run: credentials resolved although none were configured"
        ),
    }
}

// ───────────────────────────── log capture ─────────────────────────────

pub struct Rec {
    pub thread: ThreadId,
    pub level: log::Level,
    pub target: String,
    pub message: String,
}

static RECORDS: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

struct Capture;

impl LogSink for Capture {
    fn min_level(&self) -> log::LevelFilter {
        log::LevelFilter::Trace
    }
    fn log(&self, r: &log::Record<'_>) {
        RECORDS.lock().unwrap().push(Rec {
            thread: std::thread::current().id(),
            level: r.level(),
            target: r.target().to_string(),
            message: r.args().to_string(),
        });
    }
}

/// Capture every log record at every level (installs the asherah logger).
pub fn install_capture() {
    ensure_logger().unwrap();
    set_sink("kms-envelope-errors-test", Some(Arc::new(Capture)));
}

/// Drain the records logged on the current thread. Sync KMS calls run
/// their future on the calling thread, so these are the caller's records.
pub fn take_thread_records() -> Vec<Rec> {
    let me = std::thread::current().id();
    let mut all = RECORDS.lock().unwrap();
    let (mine, rest): (Vec<Rec>, Vec<Rec>) = all.drain(..).partition(|r| r.thread == me);
    *all = rest;
    mine
}

/// Drain every captured record (for binaries that run one test).
pub fn take_all_records() -> Vec<Rec> {
    std::mem::take(&mut *RECORDS.lock().unwrap())
}

/// The single `asherah::kms_aws_envelope` Error record among `recs`.
pub fn envelope_error_line(recs: &[Rec]) -> String {
    let lines: Vec<&Rec> = recs
        .iter()
        .filter(|r| r.level == log::Level::Error && r.target == "asherah::kms_aws_envelope")
        .collect();
    assert_eq!(lines.len(), 1, "expected one envelope error line");
    lines[0].message.clone()
}

pub fn assert_clean(what: &str, s: &str) {
    for f in FORBIDDEN {
        assert!(!s.contains(f), "{what} leaks {f:?}: {s}");
    }
}

pub fn assert_records_clean(recs: &[Rec]) {
    for r in recs {
        assert_clean(
            &format!("[{} {}] log record", r.level, r.target),
            &r.message,
        );
    }
}

/// Run `f` on its own thread and fail if it has not finished in `secs`,
/// so a scenario that unexpectedly waits on the network fails instead of
/// hanging the test run.
pub fn bounded<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    drop(std::thread::spawn(move || drop(tx.send(f()))));
    match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("scenario did not finish within {secs}s")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("scenario thread panicked")
        }
    }
}
