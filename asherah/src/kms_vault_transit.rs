use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::traits::KeyManagementService;

/// Vault Transit KMS — uses HashiCorp Vault's Transit secrets engine as an
/// encryption oracle. The master key never leaves Vault.
///
/// # Authentication
///
/// Supports multiple auth methods via environment variables:
///
/// - **Token** (simplest, for dev): `VAULT_TOKEN`
/// - **Kubernetes** (pods): `VAULT_AUTH_METHOD=kubernetes` + `VAULT_AUTH_ROLE`
///   (uses the pod's service account JWT at `/var/run/secrets/kubernetes.io/serviceaccount/token`)
/// - **AppRole** (CI/automation): `VAULT_AUTH_METHOD=approle` + `VAULT_APPROLE_ROLE_ID` + `VAULT_APPROLE_SECRET_ID`
/// - **TLS Certificate** (machine identity): `VAULT_AUTH_METHOD=cert` + `VAULT_CLIENT_CERT` + `VAULT_CLIENT_KEY`
#[allow(missing_debug_implementations)]
pub struct VaultTransitKms {
    sync_client: reqwest::blocking::Client,
    async_client: reqwest::Client,
    encrypt_url: String,
    decrypt_url: String,
    /// Vault client token. Wrapped in `Zeroizing` so the bytes are
    /// volatile-wiped when the struct (and any clone) is dropped. T-finding
    /// "token: String cached for process life with no zeroize" in
    /// `docs/review-2026-05-05-findings.md`. The renewal/TTL gap is left
    /// as a documented follow-up — Vault tokens with finite TTL still
    /// fail at expiry; refresh logic requires plumbing through the auth
    /// method (Kubernetes JWT path / AppRole secret_id / explicit token).
    token: Arc<zeroize::Zeroizing<String>>,
}

impl Clone for VaultTransitKms {
    fn clone(&self) -> Self {
        Self {
            sync_client: self.sync_client.clone(),
            async_client: self.async_client.clone(),
            encrypt_url: self.encrypt_url.clone(),
            decrypt_url: self.decrypt_url.clone(),
            token: Arc::clone(&self.token),
        }
    }
}

#[derive(Serialize)]
struct EncryptRequest<'req> {
    plaintext: &'req str,
}

#[derive(Serialize)]
struct DecryptRequest<'req> {
    ciphertext: &'req str,
}

#[derive(Deserialize)]
struct VaultResponse<T> {
    data: Option<T>,
    errors: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

/// Vault auth response (shared across auth methods).
#[derive(Deserialize)]
struct AuthResponse {
    auth: Option<AuthData>,
    errors: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
}

/// Truncate a body snippet for inclusion in error logs. Vault server
/// errors can be small JSON or large HTML reverse-proxy pages; truncating
/// keeps error messages within a reasonable size for log aggregators.
fn truncate_for_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Don't slice in the middle of a UTF-8 codepoint.
        let cut = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max)
            .last()
            .unwrap_or(0);
        format!("{}…", &s[..cut])
    }
}

impl VaultTransitKms {
    /// Build Transit API URLs from components.
    fn build_urls(vault_addr: &str, transit_mount: &str, key_name: &str) -> (String, String) {
        let base = vault_addr.trim_end_matches('/');
        let mount = transit_mount.trim_matches('/');
        let encrypt_url = format!("{base}/v1/{mount}/encrypt/{key_name}");
        let decrypt_url = format!("{base}/v1/{mount}/decrypt/{key_name}");
        (encrypt_url, decrypt_url)
    }

    fn build_clients() -> anyhow::Result<(reqwest::blocking::Client, reqwest::Client)> {
        let mut sync_builder = reqwest::blocking::Client::builder().use_rustls_tls();
        let mut async_builder = reqwest::Client::builder().use_rustls_tls();

        // TLS client certificate auth: configure the HTTP client with the cert
        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("VAULT_CLIENT_CERT"),
            std::env::var("VAULT_CLIENT_KEY"),
        ) {
            let cert_pem = std::fs::read(&cert_path).map_err(|e| {
                anyhow::anyhow!("failed to read VAULT_CLIENT_CERT at {cert_path}: {e}")
            })?;
            // Wrap the private-key bytes in `Zeroizing` so the raw PEM
            // doesn't linger in the freed allocator slab. T-finding
            // "PEM body Vec not wiped; private key half should be
            // Zeroizing" in `docs/review-2026-05-05-findings.md`.
            let key_pem = zeroize::Zeroizing::new(std::fs::read(&key_path).map_err(|e| {
                anyhow::anyhow!("failed to read VAULT_CLIENT_KEY at {key_path}: {e}")
            })?);
            let mut combined = zeroize::Zeroizing::new(cert_pem.clone());
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| anyhow::anyhow!("invalid TLS client cert/key: {e}"))?;
            sync_builder = sync_builder.identity(identity.clone());
            async_builder = async_builder.identity(identity);
        }

        let sync_client = sync_builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build Vault HTTP client: {e}"))?;
        let async_client = async_builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build Vault async HTTP client: {e}"))?;
        Ok((sync_client, async_client))
    }

    /// Resolve a Vault token from environment configuration.
    /// Checks in order: VAULT_TOKEN, then VAULT_AUTH_METHOD (kubernetes, approle, cert).
    fn resolve_token_sync(
        client: &reqwest::blocking::Client,
        vault_addr: &str,
    ) -> anyhow::Result<String> {
        // 1. Explicit token
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            if !token.is_empty() {
                return Ok(token);
            }
        }

        let auth_method = std::env::var("VAULT_AUTH_METHOD")
            .unwrap_or_default()
            .to_lowercase();
        let base = vault_addr.trim_end_matches('/');

        match auth_method.as_str() {
            "kubernetes" | "k8s" => {
                let role = std::env::var("VAULT_AUTH_ROLE").map_err(|_| {
                    anyhow::anyhow!("VAULT_AUTH_ROLE required for Vault Kubernetes auth")
                })?;
                let jwt_path = std::env::var("VAULT_K8S_TOKEN_PATH").unwrap_or_else(|_| {
                    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
                });
                let jwt = std::fs::read_to_string(&jwt_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to read Kubernetes service account token at {jwt_path}: {e}"
                    )
                })?;
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "kubernetes".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let resp: AuthResponse = client
                    .post(&url)
                    .json(&serde_json::json!({"role": role, "jwt": jwt.trim()}))
                    .send()
                    .map_err(|e| anyhow::anyhow!("Vault Kubernetes auth failed: {e}"))?
                    .json()
                    .map_err(|e| anyhow::anyhow!("Vault Kubernetes auth: invalid response: {e}"))?;
                Self::extract_token(resp, "kubernetes")
            }
            "approle" => {
                let role_id = std::env::var("VAULT_APPROLE_ROLE_ID").map_err(|_| {
                    anyhow::anyhow!("VAULT_APPROLE_ROLE_ID required for Vault AppRole auth")
                })?;
                let secret_id = std::env::var("VAULT_APPROLE_SECRET_ID").unwrap_or_default();
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "approle".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let mut body = serde_json::json!({"role_id": role_id});
                if !secret_id.is_empty() {
                    body["secret_id"] = serde_json::Value::String(secret_id);
                }
                let resp: AuthResponse = client
                    .post(&url)
                    .json(&body)
                    .send()
                    .map_err(|e| anyhow::anyhow!("Vault AppRole auth failed: {e}"))?
                    .json()
                    .map_err(|e| anyhow::anyhow!("Vault AppRole auth: invalid response: {e}"))?;
                Self::extract_token(resp, "approle")
            }
            "cert" | "tls" => {
                // TLS cert auth uses the client certificate configured on the HTTP client
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "cert".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let resp: AuthResponse = client
                    .post(&url)
                    .send()
                    .map_err(|e| anyhow::anyhow!("Vault TLS cert auth failed: {e}"))?
                    .json()
                    .map_err(|e| anyhow::anyhow!("Vault TLS cert auth: invalid response: {e}"))?;
                Self::extract_token(resp, "cert")
            }
            "" => Err(anyhow::anyhow!(
                "Vault authentication required: set VAULT_TOKEN, or VAULT_AUTH_METHOD \
                 (kubernetes, approle, cert) with the appropriate credentials"
            )),
            other => Err(anyhow::anyhow!(
                "unsupported VAULT_AUTH_METHOD '{other}': expected kubernetes, approle, or cert"
            )),
        }
    }

    /// Async version of token resolution.
    async fn resolve_token_async(
        client: &reqwest::Client,
        vault_addr: &str,
    ) -> anyhow::Result<String> {
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            if !token.is_empty() {
                return Ok(token);
            }
        }

        let auth_method = std::env::var("VAULT_AUTH_METHOD")
            .unwrap_or_default()
            .to_lowercase();
        let base = vault_addr.trim_end_matches('/');

        match auth_method.as_str() {
            "kubernetes" | "k8s" => {
                let role = std::env::var("VAULT_AUTH_ROLE").map_err(|_| {
                    anyhow::anyhow!("VAULT_AUTH_ROLE required for Vault Kubernetes auth")
                })?;
                let jwt_path = std::env::var("VAULT_K8S_TOKEN_PATH").unwrap_or_else(|_| {
                    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
                });
                let jwt = std::fs::read_to_string(&jwt_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to read Kubernetes service account token at {jwt_path}: {e}"
                    )
                })?;
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "kubernetes".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let resp: AuthResponse = client
                    .post(&url)
                    .json(&serde_json::json!({"role": role, "jwt": jwt.trim()}))
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault Kubernetes auth failed: {e}"))?
                    .json()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault Kubernetes auth: invalid response: {e}"))?;
                Self::extract_token(resp, "kubernetes")
            }
            "approle" => {
                let role_id = std::env::var("VAULT_APPROLE_ROLE_ID").map_err(|_| {
                    anyhow::anyhow!("VAULT_APPROLE_ROLE_ID required for Vault AppRole auth")
                })?;
                let secret_id = std::env::var("VAULT_APPROLE_SECRET_ID").unwrap_or_default();
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "approle".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let mut body = serde_json::json!({"role_id": role_id});
                if !secret_id.is_empty() {
                    body["secret_id"] = serde_json::Value::String(secret_id);
                }
                let resp: AuthResponse = client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault AppRole auth failed: {e}"))?
                    .json()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault AppRole auth: invalid response: {e}"))?;
                Self::extract_token(resp, "approle")
            }
            "cert" | "tls" => {
                let mount =
                    std::env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "cert".to_string());
                let url = format!("{base}/v1/auth/{mount}/login");
                let resp: AuthResponse = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault TLS cert auth failed: {e}"))?
                    .json()
                    .await
                    .map_err(|e| anyhow::anyhow!("Vault TLS cert auth: invalid response: {e}"))?;
                Self::extract_token(resp, "cert")
            }
            "" => Err(anyhow::anyhow!(
                "Vault authentication required: set VAULT_TOKEN, or VAULT_AUTH_METHOD \
                 (kubernetes, approle, cert) with the appropriate credentials"
            )),
            other => Err(anyhow::anyhow!(
                "unsupported VAULT_AUTH_METHOD '{other}': expected kubernetes, approle, or cert"
            )),
        }
    }

    fn extract_token(resp: AuthResponse, method: &str) -> anyhow::Result<String> {
        if let Some(errs) = resp.errors {
            if !errs.is_empty() {
                return Err(anyhow::anyhow!(
                    "Vault {method} auth failed: {}",
                    errs.join("; ")
                ));
            }
        }
        resp.auth
            .map(|a| a.client_token)
            .ok_or_else(|| anyhow::anyhow!("Vault {method} auth returned no token"))
    }

    /// Sync constructor. Authenticates with Vault and creates HTTP clients.
    ///
    /// Token is resolved from: `VAULT_TOKEN` env var, or `VAULT_AUTH_METHOD`
    /// (kubernetes, approle, cert) with the appropriate credentials.
    pub fn new(
        vault_addr: impl Into<String>,
        key_name: impl AsRef<str>,
        transit_mount: Option<&str>,
    ) -> anyhow::Result<Self> {
        let addr = vault_addr.into();
        let mount = transit_mount.unwrap_or("transit");
        let (encrypt_url, decrypt_url) = Self::build_urls(&addr, mount, key_name.as_ref());
        let (sync_client, async_client) = Self::build_clients()?;
        let token = Self::resolve_token_sync(&sync_client, &addr)?;
        Ok(Self {
            sync_client,
            async_client,
            encrypt_url,
            decrypt_url,
            token: Arc::new(zeroize::Zeroizing::new(token)),
        })
    }

    /// Async constructor. Authenticates with Vault and creates HTTP clients.
    pub async fn new_async(
        vault_addr: impl Into<String>,
        key_name: impl AsRef<str>,
        transit_mount: Option<&str>,
    ) -> anyhow::Result<Self> {
        let addr = vault_addr.into();
        let mount = transit_mount.unwrap_or("transit");
        let (encrypt_url, decrypt_url) = Self::build_urls(&addr, mount, key_name.as_ref());
        let (sync_client, async_client) = Self::build_clients()?;
        let token = Self::resolve_token_async(&async_client, &addr).await?;
        Ok(Self {
            sync_client,
            async_client,
            encrypt_url,
            decrypt_url,
            token: Arc::new(zeroize::Zeroizing::new(token)),
        })
    }

    /// Check a Vault response for errors and return a descriptive message.
    fn check_vault_errors(errors: Option<Vec<String>>, operation: &str) -> anyhow::Result<()> {
        if let Some(errs) = errors {
            if !errs.is_empty() {
                return Err(anyhow::anyhow!(
                    "Vault Transit {operation} failed: {}",
                    errs.join("; ")
                ));
            }
        }
        Ok(())
    }

    // --- sync helpers ---

    fn encrypt_key_sync(&self, key_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let encoded = BASE64.encode(key_bytes);
        let body = EncryptRequest {
            plaintext: &encoded,
        };
        let resp = self
            .sync_client
            .post(&self.encrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&body)
            .send()
            .map_err(|e| {
                // `warn!` rather than `error!` because the error chain is
                // also propagated to the caller via the returned anyhow.
                // Transient Vault hiccups would otherwise spam `error!`
                // and trip on-call paging despite the application having
                // a chance to handle/retry. T-finding "Vault transit logs
                // full reqwest chain at error!" in
                // `docs/review-2026-05-05-findings.md`.
                log::warn!("VaultTransitKms encrypt HTTP error: {e:#}");
                anyhow::anyhow!("Vault Transit encrypt request failed: {e}")
            })?;
        let status = resp.status();
        if !status.is_success() {
            let snippet = resp.text().unwrap_or_default();
            let snippet = truncate_for_log(&snippet, 256);
            anyhow::bail!("Vault Transit encrypt: HTTP {status} (body: {snippet})");
        }
        let vault_resp: VaultResponse<EncryptData> = resp.json().map_err(|e| {
            anyhow::anyhow!(
                "Vault Transit encrypt: failed to parse response (status {status}): {e}"
            )
        })?;
        Self::check_vault_errors(vault_resp.errors, "encrypt")?;
        let data = vault_resp
            .data
            .ok_or_else(|| anyhow::anyhow!("Vault Transit encrypt returned no data"))?;
        Ok(data.ciphertext.into_bytes())
    }

    fn decrypt_key_sync(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ciphertext = std::str::from_utf8(blob)
            .map_err(|e| anyhow::anyhow!("Vault Transit decrypt: blob is not valid UTF-8: {e}"))?;
        // Vault transit ciphertexts are versioned with a `vault:v<n>:` prefix.
        // Reject anything else early — a corrupted or truncated metastore
        // value otherwise round-trips into Vault and produces a confusing
        // server-side error. T-finding "no validation of `vault:v` prefix"
        // in `docs/review-2026-05-05-findings.md`.
        if !ciphertext.starts_with("vault:v") {
            anyhow::bail!(
                "Vault Transit decrypt: ciphertext does not start with the expected \
                 `vault:v<n>:` version prefix (got {} bytes)",
                ciphertext.len()
            );
        }
        let body = DecryptRequest { ciphertext };
        let resp = self
            .sync_client
            .post(&self.decrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&body)
            .send()
            .map_err(|e| {
                // See the matching note in encrypt — `warn!` because the
                // error is also returned to the caller.
                log::warn!("VaultTransitKms decrypt HTTP error: {e:#}");
                anyhow::anyhow!("Vault Transit decrypt request failed: {e}")
            })?;
        // Check the HTTP status *before* parsing JSON. A 5xx with an HTML
        // body (or a 401/403 reverse-proxy challenge page) would otherwise
        // surface as an opaque "JSON parse failed" error and mask the real
        // status. T-finding "never inspects resp.status() before .json()"
        // in `docs/review-2026-05-05-findings.md`.
        let status = resp.status();
        if !status.is_success() {
            let snippet = resp.text().unwrap_or_default();
            let snippet = truncate_for_log(&snippet, 256);
            anyhow::bail!("Vault Transit decrypt: HTTP {status} (body: {snippet})");
        }
        let vault_resp: VaultResponse<DecryptData> = resp.json().map_err(|e| {
            anyhow::anyhow!(
                "Vault Transit decrypt: failed to parse response (status {status}): {e}"
            )
        })?;
        Self::check_vault_errors(vault_resp.errors, "decrypt")?;
        let data = vault_resp
            .data
            .ok_or_else(|| anyhow::anyhow!("Vault Transit decrypt returned no data"))?;
        BASE64
            .decode(&data.plaintext)
            .map_err(|e| anyhow::anyhow!("Vault Transit decrypt: invalid base64 in plaintext: {e}"))
    }

    // --- async helpers ---

    async fn encrypt_key_impl(&self, key_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let encoded = BASE64.encode(key_bytes);
        let body = EncryptRequest {
            plaintext: &encoded,
        };
        let resp = self
            .async_client
            .post(&self.encrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                log::warn!("VaultTransitKms encrypt HTTP error: {e:#}");
                anyhow::anyhow!("Vault Transit encrypt request failed: {e}")
            })?;
        let status = resp.status();
        if !status.is_success() {
            let snippet = resp.text().await.unwrap_or_default();
            let snippet = truncate_for_log(&snippet, 256);
            anyhow::bail!("Vault Transit encrypt: HTTP {status} (body: {snippet})");
        }
        let vault_resp: VaultResponse<EncryptData> = resp.json().await.map_err(|e| {
            anyhow::anyhow!(
                "Vault Transit encrypt: failed to parse response (status {status}): {e}"
            )
        })?;
        Self::check_vault_errors(vault_resp.errors, "encrypt")?;
        let data = vault_resp
            .data
            .ok_or_else(|| anyhow::anyhow!("Vault Transit encrypt returned no data"))?;
        Ok(data.ciphertext.into_bytes())
    }

    async fn decrypt_key_impl(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ciphertext = std::str::from_utf8(blob)
            .map_err(|e| anyhow::anyhow!("Vault Transit decrypt: blob is not valid UTF-8: {e}"))?;
        if !ciphertext.starts_with("vault:v") {
            anyhow::bail!(
                "Vault Transit decrypt: ciphertext does not start with the expected \
                 `vault:v<n>:` version prefix (got {} bytes)",
                ciphertext.len()
            );
        }
        let body = DecryptRequest { ciphertext };
        let resp = self
            .async_client
            .post(&self.decrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                // See the matching note in encrypt — `warn!` because the
                // error is also returned to the caller.
                log::warn!("VaultTransitKms decrypt HTTP error: {e:#}");
                anyhow::anyhow!("Vault Transit decrypt request failed: {e}")
            })?;
        let status = resp.status();
        if !status.is_success() {
            let snippet = resp.text().await.unwrap_or_default();
            let snippet = truncate_for_log(&snippet, 256);
            anyhow::bail!("Vault Transit decrypt: HTTP {status} (body: {snippet})");
        }
        let vault_resp: VaultResponse<DecryptData> = resp.json().await.map_err(|e| {
            anyhow::anyhow!(
                "Vault Transit decrypt: failed to parse response (status {status}): {e}"
            )
        })?;
        Self::check_vault_errors(vault_resp.errors, "decrypt")?;
        let data = vault_resp
            .data
            .ok_or_else(|| anyhow::anyhow!("Vault Transit decrypt returned no data"))?;
        BASE64
            .decode(&data.plaintext)
            .map_err(|e| anyhow::anyhow!("Vault Transit decrypt: invalid base64 in plaintext: {e}"))
    }
}

#[async_trait]
impl KeyManagementService for VaultTransitKms {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.encrypt_key_sync(key_bytes)
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.decrypt_key_sync(blob)
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
