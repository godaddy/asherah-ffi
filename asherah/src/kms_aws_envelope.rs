use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_kms::config::endpoint::InvalidParams;
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::operation::RequestId;
use aws_sdk_kms::{config::Region, primitives::Blob, types::DataKeySpec, Client};

use crate::traits::{KeyManagementService, AEAD};

// ─── KMS failure descriptions ────────────────────────────────────────────
//
// KMS failures are described only by fixed labels: the SdkError variant,
// the connector error kind, the HTTP status, a label for the first
// recognised cause on the error's source chain (credentials error variant,
// invalid endpoint parameters, `std::io::ErrorKind`), the KMS error code
// and the AWS request id. Nothing is taken from any error's Display or
// Debug: the operation error and `ProvideErrorMetadata::message()` carry
// the AWS message text, which embeds principal and key ARNs (and account
// ids); credential providers backed by STS or SSO can carry the same; and
// connector and DNS errors carry host names, addresses and URLs.
//
// Error codes and request ids are server-supplied, and region names come
// from configuration or from the stored envelope, so each passes only in a
// narrow shape and is otherwise replaced by a fixed placeholder: codes
// `[A-Za-z]{1,64}`, request ids the UUID form, regions
// `[a-z][a-z0-9-]{0,31}`. Neither shape admits `:` or `/`, so no ARN can
// pass. Remaining limit: an endpoint that answers as KMS (or a proxy in
// front of it) controls these tokens, and can still return a key UUID as
// the request id.

/// Longest server-supplied error code passed through.
const MAX_ERROR_CODE_LEN: usize = 64;
/// Longest region name passed through.
const MAX_REGION_LEN: usize = 32;
/// Envelope regions listed when no configured region matches.
const MAX_LISTED_ENVELOPE_REGIONS: usize = 8;
const UNRECOGNIZED_CODE: &str = "<unrecognized error code>";
const UNRECOGNIZED_REQUEST_ID: &str = "<unrecognized request id>";
const UNRECOGNIZED_REGION: &str = "<unrecognized region>";

/// Pass an error code only in the shape `[A-Za-z]{1,64}`. Every error code
/// aws-sdk-kms models matches; anything carrying digits, punctuation or
/// whitespace (an account id, an ARN, message text) does not.
fn safe_error_code(code: &str) -> &str {
    if !code.is_empty()
        && code.len() <= MAX_ERROR_CODE_LEN
        && code.bytes().all(|b| b.is_ascii_alphabetic())
    {
        code
    } else {
        UNRECOGNIZED_CODE
    }
}

/// Pass a request id only in the UUID shape
/// `[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`.
fn safe_request_id(id: &str) -> &str {
    let b = id.as_bytes();
    let is_uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        });
    if is_uuid {
        id
    } else {
        UNRECOGNIZED_REQUEST_ID
    }
}

/// Pass a region name only in the shape `[a-z][a-z0-9-]{0,31}`. Applied to
/// every region name this module prints, configured or read from an
/// envelope: a mis-ordered region map can put a key ARN where the region
/// belongs. Empty (no region resolved) prints as the placeholder too.
fn safe_region(region: &str) -> &str {
    let b = region.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= MAX_REGION_LEN
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    if ok {
        region
    } else {
        UNRECOGNIZED_REGION
    }
}

fn push_request_id(out: &mut String, request_id: Option<&str>) {
    if let Some(id) = request_id {
        out.push_str(", request id ");
        out.push_str(safe_request_id(id));
    }
}

fn credentials_error_label(err: &CredentialsError) -> &'static str {
    match err {
        CredentialsError::CredentialsNotLoaded(_) => "no credentials available",
        CredentialsError::ProviderTimedOut(_) => "credentials provider timed out",
        CredentialsError::InvalidConfiguration(_) => "invalid credentials configuration",
        CredentialsError::ProviderError(_) => "credentials provider error",
        CredentialsError::Unhandled(_) => "unexpected credentials provider failure",
        _ => "credentials error",
    }
}

/// Fixed label for the first recognised cause on `err`'s source chain:
/// a credentials error variant, invalid endpoint parameters (for example
/// a region that is not a valid host label), or an I/O error kind. Each
/// link is identified by downcasting; no link's Display or Debug is used.
fn source_label(err: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur = err.source();
    while let Some(e) = cur {
        if let Some(c) = e.downcast_ref::<CredentialsError>() {
            return Some(credentials_error_label(c).to_string());
        }
        if e.downcast_ref::<InvalidParams>().is_some() {
            return Some("invalid endpoint parameters".to_string());
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            // `ErrorKind`'s Display is a fixed description ("connection
            // refused", "timed out", …), unlike `io::Error`'s.
            return Some(io.kind().to_string());
        }
        cur = e.source();
    }
    None
}

/// Describe a KMS SDK failure as `<kind>[ <code>][, request id <id>]`,
/// e.g. `service error AccessDeniedException, request id 3f2c…`,
/// `dispatch failure (io: connection refused)` or
/// `dispatch failure (other: no credentials available)`.
fn describe_sdk_error<E>(err: &SdkError<E>) -> String
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    let mut out = String::with_capacity(96);
    match err {
        SdkError::ConstructionFailure(_) => {
            out.push_str("request construction failure");
            if let Some(label) = source_label(err) {
                out.push_str(&format!(" ({label})"));
            }
        }
        SdkError::TimeoutError(_) => out.push_str("timeout"),
        SdkError::DispatchFailure(d) => {
            out.push_str("dispatch failure");
            let label = source_label(err);
            let kind = if d.is_timeout() {
                "timeout"
            } else if d.is_io() {
                "io"
            } else if d.is_user() {
                "user"
            } else {
                "other"
            };
            match (label, d.as_other()) {
                (Some(label), _) => out.push_str(&format!(" ({kind}: {label})")),
                (None, Some(other)) => out.push_str(&format!(" ({kind}: {other})")),
                (None, None) => out.push_str(&format!(" ({kind})")),
            }
        }
        SdkError::ResponseError(r) => {
            out.push_str(&format!(
                "response error (HTTP {}",
                r.raw().status().as_u16()
            ));
            if let Some(label) = source_label(err) {
                out.push_str(&format!(", {label}"));
            }
            out.push(')');
        }
        SdkError::ServiceError(s) => match err.code() {
            Some(code) => {
                out.push_str("service error ");
                out.push_str(safe_error_code(code));
            }
            None => out.push_str(&format!(
                "service error (no error code, HTTP {})",
                s.raw().status().as_u16()
            )),
        },
        _ => out.push_str("unclassified SDK failure"),
    }
    push_request_id(&mut out, err.request_id());
    out
}

/// A client whose configuration resolved no region cannot sign a KMS
/// request. The SDK reports that as a dispatch failure whose cause
/// (`MissingSigningRegion`) is a crate-private type, so it is detected
/// from the client's configuration before the call instead.
fn has_region(c: &RegionalClient) -> bool {
    c.client.config().region().is_some()
}

const NO_REGION: &str = "not sent: no region configured";

/// Caller-facing error for a failed KMS call on the encrypt path. Built
/// from [`describe_sdk_error`] only, so the `SdkError` (and the AWS
/// message text its source chain would print under `{:#}`) is not kept.
fn kms_call_error<E>(op: &str, region: &str, err: &SdkError<E>) -> anyhow::Error
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    anyhow::anyhow!(
        "KMS {op} failed in region {}: {}",
        safe_region(region),
        describe_sdk_error(err)
    )
}

fn kms_missing_field_error(
    op: &str,
    field: &str,
    region: &str,
    request_id: Option<&str>,
) -> anyhow::Error {
    let mut msg = format!(
        "KMS {op} returned no {field} in region {}",
        safe_region(region)
    );
    push_request_id(&mut msg, request_id);
    anyhow::anyhow!(msg)
}

/// Process-wide fallback runtime — same role as `kms_aws::fallback_runtime()`
/// but lives here so the envelope module compiles without depending on a
/// sibling module's private item. Built once via `OnceLock`; transient init
/// failures surface as `anyhow::Error` instead of panicking. T4 in
/// `docs/review-2026-05-05-findings.md`.
fn fallback_runtime() -> Result<&'static tokio::runtime::Runtime, std::io::Error> {
    static FALLBACK: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = FALLBACK.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("asherah-kms-envelope-fallback")
        .enable_all()
        .build()?;
    Ok(FALLBACK.get_or_init(|| rt))
}

#[derive(Clone)]
struct RegionalClient {
    client: Client,
    region: String,
    key_arn: String, // provided key id/arn
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct AwsKmsEnvelope<A: AEAD + Send + Sync + 'static> {
    clients: Vec<RegionalClient>,
    preferred: usize,
    aead: Arc<A>,
    rt: Option<Arc<tokio::runtime::Runtime>>, // present when we created one
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KekEnvelope {
    #[serde(
        rename = "encryptedKey",
        serialize_with = "crate::types::serde_base64::serialize",
        deserialize_with = "crate::types::serde_base64::deserialize"
    )]
    encrypted_key: Vec<u8>,
    #[serde(rename = "kmsKeks")]
    keks: Vec<RegionalKek>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RegionalKek {
    #[serde(rename = "region")]
    region: String,
    #[serde(rename = "arn")]
    arn: String,
    #[serde(
        rename = "encryptedKek",
        serialize_with = "crate::types::serde_base64::serialize",
        deserialize_with = "crate::types::serde_base64::deserialize"
    )]
    encrypted_kek: Vec<u8>,
}

impl<A: AEAD + Send + Sync + 'static> AwsKmsEnvelope<A> {
    pub fn new_single(
        aead: Arc<A>,
        key_id: String,
        region: Option<String>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        let (client, resolved_region, rt) = new_kms_client(region, aws_profile_name)?;
        let rc = RegionalClient {
            client,
            region: resolved_region,
            key_arn: key_id,
        };
        Ok(Self {
            clients: vec![rc],
            preferred: 0,
            aead,
            rt,
        })
    }

    pub fn new_multi(
        aead: Arc<A>,
        preferred: usize,
        entries: Vec<(String, String)>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        if entries.is_empty() {
            return Err(anyhow::anyhow!("no kms entries provided"));
        }
        // Build clients per entry; share one runtime if needed
        let mut rt: Option<Arc<tokio::runtime::Runtime>> = None;
        let mut clients = Vec::with_capacity(entries.len());
        for (region, key) in entries.into_iter() {
            let (client, resolved_region, new_rt) =
                new_kms_client_with_rt(region.clone(), rt.clone(), aws_profile_name)?;
            if rt.is_none() {
                rt = new_rt;
            }
            clients.push(RegionalClient {
                client,
                region: resolved_region,
                key_arn: key,
            });
        }
        let pref = if preferred < clients.len() {
            preferred
        } else {
            0
        };
        Ok(Self {
            clients,
            preferred: pref,
            aead,
            rt,
        })
    }

    /// Async constructor — single region, loads config on caller's runtime.
    pub async fn new_single_async(
        aead: Arc<A>,
        key_id: String,
        region: Option<String>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        let (client, resolved_region) = new_kms_client_async(region, aws_profile_name).await?;
        let rc = RegionalClient {
            client,
            region: resolved_region,
            key_arn: key_id,
        };
        let rt = Some(Arc::new(tokio::runtime::Runtime::new()?));
        Ok(Self {
            clients: vec![rc],
            preferred: 0,
            aead,
            rt,
        })
    }

    /// Async constructor — multi region, loads config on caller's runtime.
    pub async fn new_multi_async(
        aead: Arc<A>,
        preferred: usize,
        entries: Vec<(String, String)>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        if entries.is_empty() {
            return Err(anyhow::anyhow!("no kms entries provided"));
        }
        let mut clients = Vec::with_capacity(entries.len());
        for (region, key) in entries.into_iter() {
            let (client, resolved_region) =
                new_kms_client_async(Some(region), aws_profile_name).await?;
            clients.push(RegionalClient {
                client,
                region: resolved_region,
                key_arn: key,
            });
        }
        let pref = if preferred < clients.len() {
            preferred
        } else {
            0
        };
        let rt = Some(Arc::new(tokio::runtime::Runtime::new()?));
        Ok(Self {
            clients,
            preferred: pref,
            aead,
            rt,
        })
    }

    /// Run a fallible future to completion from a sync caller. See
    /// `kms_aws::AwsKms::block_on_result` — same fallback ladder with
    /// runtime-init failures surfaced as `anyhow::Error` instead of
    /// `Runtime::new().expect(...)`.
    fn block_on_result<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        if let Some(rt) = &self.rt {
            return if tokio::runtime::Handle::try_current().is_ok() {
                tokio::task::block_in_place(|| rt.block_on(f))
            } else {
                rt.block_on(f)
            };
        }
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            return tokio::task::block_in_place(|| h.block_on(f));
        }
        let rt = fallback_runtime().map_err(|e| {
            anyhow::anyhow!(
                "AwsKmsEnvelope: failed to build fallback tokio runtime for sync KMS call: {e}"
            )
        })?;
        rt.block_on(f)
    }

    async fn encrypt_key_impl(&self, key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Generate data key in preferred region
        let pref = &self.clients[self.preferred];
        if !has_region(pref) {
            return Err(anyhow::anyhow!("KMS GenerateDataKey {NO_REGION}"));
        }
        let resp = pref
            .client
            .generate_data_key()
            .key_id(pref.key_arn.clone())
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| kms_call_error("GenerateDataKey", &pref.region, &e))?;
        let plaintext = resp.plaintext().ok_or_else(|| {
            kms_missing_field_error(
                "GenerateDataKey",
                "plaintext",
                &pref.region,
                resp.request_id(),
            )
        })?;
        let preferred_ciphertext = resp.ciphertext_blob().ok_or_else(|| {
            kms_missing_field_error(
                "GenerateDataKey",
                "ciphertext blob",
                &pref.region,
                resp.request_id(),
            )
        })?;
        let key_id = resp.key_id().unwrap_or("").to_string();

        // AEAD-encrypt the key with the plaintext data key
        let enc_key = self.aead.encrypt(key_bytes, plaintext.as_ref())?;

        // Encrypt KEK in all regions
        let mut keks: Vec<RegionalKek> = Vec::with_capacity(self.clients.len());
        for (i, c) in self.clients.iter().enumerate() {
            if i == self.preferred {
                keks.push(RegionalKek {
                    region: c.region.clone(),
                    arn: key_id.clone(),
                    encrypted_kek: preferred_ciphertext.as_ref().to_vec(),
                });
                continue;
            }
            if !has_region(c) {
                return Err(anyhow::anyhow!("KMS Encrypt {NO_REGION}"));
            }
            let out = c
                .client
                .encrypt()
                .key_id(&c.key_arn)
                .plaintext(Blob::new(plaintext.as_ref().to_vec()))
                .send()
                .await
                .map_err(|e| kms_call_error("Encrypt", &c.region, &e))?;
            let blob = out.ciphertext_blob().ok_or_else(|| {
                kms_missing_field_error("Encrypt", "ciphertext blob", &c.region, out.request_id())
            })?;
            keks.push(RegionalKek {
                region: c.region.clone(),
                arn: c.key_arn.clone(),
                encrypted_kek: blob.as_ref().to_vec(),
            });
        }

        let env = KekEnvelope {
            encrypted_key: enc_key,
            keks,
        };
        let bytes = serde_json::to_vec(&env)?;
        Ok(bytes)
    }

    async fn decrypt_key_impl(&self, blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Redact serde_json's error in the user-facing message — its
        // Display includes the offending input snippet ("at line N
        // column M near `...`"), which may expose envelope-structure
        // hints (region names, ARN prefixes, KEK byte boundaries) on
        // a corrupted or truncated envelope. The full chain still
        // goes to the operator log via `log::error!`. T-finding
        // "serde_json errors with `{e}` include offending input snippet"
        // in `docs/review-2026-05-05-findings.md`.
        let env: KekEnvelope = serde_json::from_slice(blob).map_err(|e| {
            log::error!("AwsKmsEnvelope decrypt_key: invalid envelope JSON: {e}");
            anyhow::anyhow!("invalid KMS envelope JSON")
        })?;
        // Build map region->kek
        let mut map = std::collections::HashMap::new();
        for k in &env.keks {
            map.insert(k.region.as_str(), k);
        }

        // Iterate configured regions in preferred-first order so the
        // preferred region's KMS bills first when the envelope has a
        // matching KEK. For each region attempted, the step that failed
        // is recorded: the Decrypt call (by SdkError kind, plus the KMS
        // error code for a service error), a Decrypt response with no
        // plaintext, or a data key that fails envelope authentication —
        // each with the AWS request id when a response carried one. The
        // aggregated error and its error-level log line carry these
        // per-region reasons; the per-region debug lines carry the same
        // text. None of them contains the AWS error message (it embeds
        // principal and key ARNs, hence account ids), the configured key
        // ARN, the envelope's `arn`, or AEAD error detail; error codes,
        // request ids and every region name pass only in a narrow shape
        // (see "KMS failure descriptions" above). The envelope's `arn` field is
        // informational only; AEAD's tag provides the integrity binding
        // for the actual data key, so an envelope with a mismatched `arn`
        // cannot trick us into returning a forged data key (the AEAD
        // decrypt fails for any wrong-key candidate). T-finding
        // "Multi-region decrypt fallthrough is silently permissive" in
        // `docs/review-2026-05-05-findings.md`.
        let mut order: Vec<usize> = (0..self.clients.len()).collect();
        if self.preferred < order.len() {
            order.swap(0, self.preferred);
        }
        let mut failures: Vec<(&str, String)> = Vec::new();
        for i in order {
            let c = &self.clients[i];
            let reg_kek = match map.get(c.region.as_str()) {
                Some(k) => *k,
                None => {
                    log::debug!(
                        "AwsKmsEnvelope decrypt_key: no KEK for region={}, skipping",
                        safe_region(&c.region)
                    );
                    continue;
                }
            };
            if !has_region(c) {
                let reason = format!("Decrypt {NO_REGION}");
                log::debug!(
                    "AwsKmsEnvelope decrypt_key: region={} failed: {reason}",
                    safe_region(&c.region)
                );
                failures.push((safe_region(&c.region), reason));
                continue;
            }
            let out = c
                .client
                .decrypt()
                .key_id(&c.key_arn)
                .ciphertext_blob(Blob::new(reg_kek.encrypted_kek.clone()))
                .send()
                .await;
            let out = match out {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("Decrypt {}", describe_sdk_error(&e));
                    log::debug!(
                        "AwsKmsEnvelope decrypt_key: region={} failed: {reason}",
                        safe_region(&c.region)
                    );
                    failures.push((safe_region(&c.region), reason));
                    continue;
                }
            };
            // Wrap the data-key plaintext returned by KMS in
            // `Zeroizing` so it is volatile-wiped when this iteration's
            // scope ends — whether the AEAD decrypt succeeds (we
            // return early), fails (we continue to the next region),
            // or the function bails. The previous unwrapped `Vec<u8>`
            // left ~32 bytes of plaintext data-key resident in the
            // allocator's free list per failed region attempt.
            let dk: zeroize::Zeroizing<Vec<u8>> = match out.plaintext() {
                Some(p) => zeroize::Zeroizing::new(p.as_ref().to_vec()),
                None => {
                    let mut reason = String::from("Decrypt returned no plaintext");
                    push_request_id(&mut reason, out.request_id());
                    log::debug!(
                        "AwsKmsEnvelope decrypt_key: region={} failed: {reason}",
                        safe_region(&c.region)
                    );
                    failures.push((safe_region(&c.region), reason));
                    continue;
                }
            };
            match self.aead.decrypt(&env.encrypted_key, &dk) {
                Ok(key) => return Ok(key),
                Err(_) => {
                    // AEAD failure here means the regional KEK decrypted
                    // to a value that doesn't match the data-key encryption.
                    // Either the envelope is corrupt or the regional KEK
                    // was rotated out of band. The AEAD error detail (which
                    // can include cipher state info) is not formatted
                    // anywhere — only this fixed label is recorded.
                    let mut reason = String::from("data key failed envelope authentication");
                    push_request_id(&mut reason, out.request_id());
                    log::debug!(
                        "AwsKmsEnvelope decrypt_key: region={} failed: {reason}",
                        safe_region(&c.region)
                    );
                    failures.push((safe_region(&c.region), reason));
                    // `dk` Zeroizing wrapper drops at end of loop
                    // iteration → wipes the data-key bytes.
                }
            }
        }
        let detail = if failures.is_empty() {
            no_matching_region_detail(&self.clients, &env)
        } else {
            let mut s = String::from("tried regions: ");
            for (n, (region, reason)) in failures.iter().enumerate() {
                if n > 0 {
                    s.push_str("; ");
                }
                s.push_str(region);
                s.push_str(" [");
                s.push_str(reason);
                s.push(']');
            }
            s
        };
        log::error!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}");
        Err(anyhow::anyhow!(
            "all KMS backends failed to decrypt ({detail})"
        ))
    }
}

/// Detail for a decrypt in which no configured region had a KEK in the
/// envelope: the configured regions and the envelope regions (both through
/// [`safe_region`]), so a region mismatch between writer and reader is
/// visible.
fn no_matching_region_detail(clients: &[RegionalClient], env: &KekEnvelope) -> String {
    let configured: Vec<&str> = clients.iter().map(|c| safe_region(&c.region)).collect();
    let in_envelope: Vec<&str> = env
        .keks
        .iter()
        .take(MAX_LISTED_ENVELOPE_REGIONS)
        .map(|k| safe_region(&k.region))
        .collect();
    let list = |v: &[&str]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    };
    let mut s = format!(
        "no matching regions found; configured regions: {}; envelope regions: {}",
        list(&configured),
        list(&in_envelope)
    );
    if env.keks.len() > MAX_LISTED_ENVELOPE_REGIONS {
        s.push_str(&format!(
            ", +{} more",
            env.keks.len() - MAX_LISTED_ENVELOPE_REGIONS
        ));
    }
    s
}

async fn new_kms_client_async(
    region: Option<String>,
    aws_profile_name: Option<&str>,
) -> anyhow::Result<(Client, String)> {
    let region_provider = if let Some(r) = region.clone() {
        RegionProviderChain::first_try(Region::new(r))
    } else {
        RegionProviderChain::default_provider()
    };
    let shared_config =
        crate::aws_sdk_load::load_sdk_config(region_provider, aws_profile_name).await;
    let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
    if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
        b = b.endpoint_url(url);
    }
    let conf = b.build();
    let client = Client::from_conf(conf.clone());
    let resolved_region = conf
        .region()
        .map(|r| r.to_string())
        .unwrap_or(region.unwrap_or_default());
    Ok((client, resolved_region))
}

fn new_kms_client(
    region: Option<String>,
    aws_profile_name: Option<&str>,
) -> anyhow::Result<(Client, String, Option<Arc<tokio::runtime::Runtime>>)> {
    let handle = tokio::runtime::Handle::try_current().ok();
    let rt = if handle.is_some() {
        None
    } else {
        Some(Arc::new(tokio::runtime::Runtime::new()?))
    };
    let region_provider = if let Some(r) = region.clone() {
        RegionProviderChain::first_try(Region::new(r))
    } else {
        RegionProviderChain::default_provider()
    };
    let conf_fut = async {
        let shared_config =
            crate::aws_sdk_load::load_sdk_config(region_provider, aws_profile_name).await;
        let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
        if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
            b = b.endpoint_url(url);
        }
        b.build()
    };
    // The (None, None) arm is rare but reachable: between the
    // `Handle::try_current().ok()` snapshot and this match, the outer
    // runtime can be torn down. Use the process-wide fallback rather than
    // panicking with `unreachable!()`.
    let conf = match (&rt, handle) {
        (Some(rt), _) => {
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::task::block_in_place(|| rt.block_on(conf_fut))
            } else {
                rt.block_on(conf_fut)
            }
        }
        (None, Some(h)) => tokio::task::block_in_place(|| h.block_on(conf_fut)),
        (None, None) => {
            let fb = fallback_runtime().map_err(|e| {
                anyhow::anyhow!(
                    "new_kms_client: tokio runtime unavailable and fallback build failed: {e}"
                )
            })?;
            fb.block_on(conf_fut)
        }
    };
    let client = Client::from_conf(conf.clone());
    let resolved_region = conf
        .region()
        .map(|r| r.to_string())
        .unwrap_or(region.unwrap_or_default());
    Ok((client, resolved_region, rt))
}

fn new_kms_client_with_rt(
    region: String,
    rt: Option<Arc<tokio::runtime::Runtime>>,
    aws_profile_name: Option<&str>,
) -> anyhow::Result<(Client, String, Option<Arc<tokio::runtime::Runtime>>)> {
    let handle = tokio::runtime::Handle::try_current().ok();
    let mut rt_local = rt;
    if handle.is_none() && rt_local.is_none() {
        rt_local = Some(Arc::new(tokio::runtime::Runtime::new()?));
    }
    let region_provider = RegionProviderChain::first_try(Region::new(region.clone()));
    let conf_fut = async {
        let shared_config =
            crate::aws_sdk_load::load_sdk_config(region_provider, aws_profile_name).await;
        let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
        if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
            b = b.endpoint_url(url);
        }
        b.build()
    };
    let conf = match (&rt_local, handle) {
        (Some(rt), _) => {
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::task::block_in_place(|| rt.block_on(conf_fut))
            } else {
                rt.block_on(conf_fut)
            }
        }
        (None, Some(h)) => tokio::task::block_in_place(|| h.block_on(conf_fut)),
        (None, None) => {
            let fb = fallback_runtime().map_err(|e| {
                anyhow::anyhow!(
                    "new_kms_client_with_rt: tokio runtime unavailable and fallback build failed: {e}"
                )
            })?;
            fb.block_on(conf_fut)
        }
    };
    let client = Client::from_conf(conf.clone());
    let resolved_region = conf.region().map(|r| r.to_string()).unwrap_or(region);
    Ok((client, resolved_region, rt_local))
}

#[async_trait]
impl<A: AEAD + Send + Sync + 'static> KeyManagementService for AwsKmsEnvelope<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.block_on_result(self.encrypt_key_impl(key_bytes))
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.block_on_result(self.decrypt_key_impl(blob))
    }

    async fn encrypt_key_async(
        &self,
        _ctx: &(),
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.encrypt_key_impl(key_bytes).await
    }

    async fn decrypt_key_async(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.decrypt_key_impl(blob).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_json_field_names_and_roundtrip() -> anyhow::Result<()> {
        let env = KekEnvelope {
            encrypted_key: vec![1, 2, 3],
            keks: vec![RegionalKek {
                region: "us-east-1".into(),
                arn: "arn:aws:kms:...".into(),
                encrypted_kek: vec![9, 8, 7],
            }],
        };
        let j = serde_json::to_string(&env)?;
        assert!(j.contains("\"encryptedKey\""));
        assert!(j.contains("\"kmsKeks\""));
        assert!(j.contains("\"region\""));
        assert!(j.contains("\"arn\""));
        assert!(j.contains("\"encryptedKek\""));
        assert!(
            j.contains("\"encryptedKey\":\""),
            "encryptedKey should be a base64 string, got: {j}"
        );
        assert!(
            j.contains("\"encryptedKek\":\""),
            "encryptedKek should be a base64 string, got: {j}"
        );
        let back: KekEnvelope = serde_json::from_str(&j)?;
        assert_eq!(back.encrypted_key, vec![1, 2, 3]);
        assert_eq!(back.keks.len(), 1);
        assert_eq!(back.keks[0].region, "us-east-1");
        assert_eq!(back.keks[0].arn, "arn:aws:kms:...");
        assert_eq!(back.keks[0].encrypted_kek, vec![9, 8, 7]);
        Ok(())
    }

    #[test]
    fn test_deserialize_go_produced_kms_envelope() {
        let go_json = r#"{
            "encryptedKey": "AQIDBAU=",
            "kmsKeks": [{
                "region": "us-west-2",
                "arn": "arn:aws:kms:us-west-2:111122223333:key/example",
                "encryptedKek": "CQgHBgU="
            }]
        }"#;
        let env: KekEnvelope =
            serde_json::from_str(go_json).expect("should deserialize Go-produced KMS envelope");
        assert_eq!(env.encrypted_key, vec![1, 2, 3, 4, 5]);
        assert_eq!(env.keks.len(), 1);
        assert_eq!(env.keks[0].region, "us-west-2");
        assert_eq!(
            env.keks[0].arn,
            "arn:aws:kms:us-west-2:111122223333:key/example"
        );
        assert_eq!(env.keks[0].encrypted_kek, vec![9, 8, 7, 6, 5]);
    }

    #[test]
    fn new_multi_empty_entries_fails() {
        let aead = Arc::new(crate::aead::AES256GCM::new());
        let result = AwsKmsEnvelope::new_multi(aead, 0, vec![], None);
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("no kms entries provided"),
            "expected 'no kms entries provided', got: {msg}"
        );
    }

    #[test]
    fn decrypt_key_invalid_envelope_json_fails() {
        let aead = Arc::new(crate::aead::AES256GCM::new());
        // Use current_thread runtime to avoid kqueue/epoll (Miri/Valgrind safe)
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let kms = AwsKmsEnvelope {
            clients: vec![],
            preferred: 0,
            aead,
            rt: Some(Arc::new(rt)),
        };
        let result = kms.decrypt_key(&(), b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_key_no_matching_region_fails() {
        let aead = Arc::new(crate::aead::AES256GCM::new());
        let env = KekEnvelope {
            encrypted_key: vec![1, 2, 3],
            keks: vec![RegionalKek {
                region: "us-east-1".into(),
                arn: "arn:...".into(),
                encrypted_kek: vec![9, 8, 7],
            }],
        };
        let blob = serde_json::to_vec(&env).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let kms = AwsKmsEnvelope {
            clients: vec![], // no clients
            preferred: 0,
            aead,
            rt: Some(Arc::new(rt)),
        };
        let err = kms.decrypt_key(&(), &blob).unwrap_err();
        assert!(
            err.to_string()
                .contains("all KMS backends failed to decrypt"),
            "expected 'all KMS backends failed to decrypt', got: {err}"
        );
        assert_eq!(
            err.to_string(),
            "all KMS backends failed to decrypt (no matching regions found; \
             configured regions: none; envelope regions: us-east-1)"
        );
    }

    #[test]
    fn no_matching_region_detail_sanitizes_and_caps_envelope_regions() {
        let mut keks: Vec<RegionalKek> = (0..10)
            .map(|i| RegionalKek {
                region: format!("r-{i}"),
                arn: "arn:aws:kms:r:123456789012:key/k".into(),
                encrypted_kek: vec![],
            })
            .collect();
        keks[1].region = "arn:aws:kms:us-west-2:123456789012".into();
        keks[2].region = "x".repeat(MAX_REGION_LEN + 1);
        let env = KekEnvelope {
            encrypted_key: vec![],
            keks,
        };
        let detail = no_matching_region_detail(&[], &env);
        assert_eq!(
            detail,
            "no matching regions found; configured regions: none; envelope regions: \
             r-0, <unrecognized region>, <unrecognized region>, r-3, r-4, r-5, r-6, r-7, \
             +2 more"
        );
    }

    /// Every error code aws-sdk-kms 1.114.0 models (49 names).
    const KMS_MODELED_CODES: &[&str] = &[
        "AlreadyExistsException",
        "CloudHsmClusterInUseException",
        "CloudHsmClusterInvalidConfigurationException",
        "CloudHsmClusterNotActiveException",
        "CloudHsmClusterNotFoundException",
        "CloudHsmClusterNotRelatedException",
        "ConflictException",
        "CustomKeyStoreHasCMKsException",
        "CustomKeyStoreInvalidStateException",
        "CustomKeyStoreNameInUseException",
        "CustomKeyStoreNotFoundException",
        "DependencyTimeoutException",
        "DisabledException",
        "DryRunOperationException",
        "ExpiredImportTokenException",
        "IncorrectKeyException",
        "IncorrectKeyMaterialException",
        "IncorrectTrustAnchorException",
        "InvalidAliasNameException",
        "InvalidArnException",
        "InvalidCiphertextException",
        "InvalidGrantIdException",
        "InvalidGrantTokenException",
        "InvalidImportTokenException",
        "InvalidKeyUsageException",
        "InvalidMarkerException",
        "KeyUnavailableException",
        "KMSInternalException",
        "KMSInvalidMacException",
        "KMSInvalidSignatureException",
        "KMSInvalidStateException",
        "LimitExceededException",
        "MalformedPolicyDocumentException",
        "NotFoundException",
        "ResourceNotFoundException",
        "TagException",
        "UnsupportedOperationException",
        "XksKeyAlreadyInUseException",
        "XksKeyInvalidConfigurationException",
        "XksKeyNotFoundException",
        "XksProxyIncorrectAuthenticationCredentialException",
        "XksProxyInvalidConfigurationException",
        "XksProxyInvalidResponseException",
        "XksProxyUriEndpointInUseException",
        "XksProxyUriInUseException",
        "XksProxyUriUnreachableException",
        "XksProxyVpcEndpointServiceInUseException",
        "XksProxyVpcEndpointServiceInvalidConfigurationException",
        "XksProxyVpcEndpointServiceNotFoundException",
    ];

    /// Request-level codes any AWS JSON service may return, including the
    /// SDK's throttling and transient code lists (aws-runtime 1.9.1) except
    /// `EC2ThrottledException`, which only EC2 returns.
    const COMMON_AWS_CODES: &[&str] = &[
        "AccessDeniedException",
        "UnrecognizedClientException",
        "ExpiredTokenException",
        "ExpiredToken",
        "InvalidSignatureException",
        "IncompleteSignature",
        "RequestExpired",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "MissingAuthenticationToken",
        "NotAuthorized",
        "OptInRequired",
        "InternalFailure",
        "ServiceUnavailable",
        "ValidationException",
        "ValidationError",
        "InvalidAction",
        "MalformedQueryString",
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "RequestLimitExceeded",
        "BandwidthLimitExceeded",
        "LimitExceededException",
        "RequestThrottled",
        "SlowDown",
        "PriorRequestNotComplete",
        "RequestTimeout",
        "RequestTimeoutException",
    ];

    /// Region names in the partitions data shipped with aws-sdk-kms 1.114.0.
    const SHIPPED_REGIONS: &[&str] = &[
        "af-south-1",
        "ap-east-1",
        "ap-east-2",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-southeast-5",
        "ap-southeast-6",
        "ap-southeast-7",
        "aws-global",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "mx-central-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "aws-cn-global",
        "cn-north-1",
        "cn-northwest-1",
        "eusc-de-east-1",
        "aws-iso-global",
        "us-iso-east-1",
        "us-iso-west-1",
        "aws-iso-b-global",
        "us-isob-east-1",
        "us-isob-west-1",
        "aws-iso-e-global",
        "eu-isoe-west-1",
        "aws-iso-f-global",
        "us-isof-east-1",
        "us-isof-south-1",
        "aws-us-gov-global",
        "us-gov-east-1",
        "us-gov-west-1",
    ];

    #[test]
    fn error_codes_are_letters_only() {
        assert_eq!(KMS_MODELED_CODES.len(), 49);
        for code in KMS_MODELED_CODES.iter().chain(COMMON_AWS_CODES) {
            assert_eq!(safe_error_code(code), *code, "{code}");
        }
        let max = "A".repeat(MAX_ERROR_CODE_LEN);
        assert_eq!(safe_error_code(&max), max.as_str());
        for bad in [
            "A".repeat(MAX_ERROR_CODE_LEN + 1),
            String::new(),
            "A123456789012".into(),
            "Acct#123456789012".into(),
            "123456789012".into(),
            "com.amazon#Err_1-x".into(),
            "key.1234abcd-12ab-34cd-56ef-1234567890ab".into(),
            "arn:aws:iam::123456789012".into(),
            "Access Denied".into(),
            "Bad/Code".into(),
            "Ünicode".into(),
            "EC2ThrottledException".into(),
        ] {
            assert_eq!(safe_error_code(&bad), UNRECOGNIZED_CODE, "{bad}");
        }
    }

    #[test]
    fn request_ids_are_uuid_shaped() {
        for rid in [
            "4f6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e6",
            "df4f9f10-0f83-4d61-9513-7c4617badd75",
            "BFE81A0A-9A08-4E71-9910-CDB5AB6EA3B6",
        ] {
            assert_eq!(safe_request_id(rid), rid);
        }
        for bad in [
            "",
            "123456789012",
            "4f6c8a1e2b3d4c5e9f7081a2b3c4d5e6",
            "4f6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e",
            "4f6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e6a",
            "4f6c8a1e-2b3d-4c5e-9f70_81a2b3c4d5e6",
            "zf6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e6",
            "id:1",
            "req id; arn:aws:iam::123456789012",
        ] {
            assert_eq!(safe_request_id(bad), UNRECOGNIZED_REQUEST_ID, "{bad}");
        }
    }

    #[test]
    fn region_names_are_bounded() {
        assert_eq!(SHIPPED_REGIONS.len(), 53);
        for region in SHIPPED_REGIONS {
            assert_eq!(safe_region(region), *region, "{region}");
        }
        let max = format!("a{}", "-".repeat(MAX_REGION_LEN - 1));
        assert_eq!(safe_region(&max), max.as_str());
        for bad in [
            String::new(),
            "x".repeat(MAX_REGION_LEN + 1),
            "arn:aws:kms:us-west-2:111122223333:key/swapped-map-key".into(),
            "123456789012".into(),
            "US-WEST-2".into(),
            "us_west_2".into(),
            "us west".into(),
            "-us-west-2".into(),
        ] {
            assert_eq!(safe_region(&bad), UNRECOGNIZED_REGION, "{bad:?}");
        }
    }
}
