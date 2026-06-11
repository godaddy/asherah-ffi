//! TOFU configuration drift guard stored in the existing metastore.
//!
//! The guard is an internal metadata record, not encryption key material. It is
//! stored through the metastore's regular `EnvelopeKeyRecord` shape so existing
//! SQL/DynamoDB schemas do not need a migration.

use std::collections::BTreeMap;

use anyhow::Context as _;
use base64::Engine as _;
use blake2::{Blake2b512, Digest as _};
use serde::{Deserialize, Serialize};

use crate::builders::{ConfigDriftGuardOptions, KmsConfig, MetastoreConfig, ResolvedConfig};
use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;

pub const CONFIG_DRIFT_GUARD_ID_PREFIX: &str = "__asherah_internal_config_drift_guard_v1__:";
pub const CONFIG_DRIFT_GUARD_CREATED: i64 = 946_684_800; // 2000-01-01T00:00:00Z
const MAX_CONFIG_DRIFT_GUARD_JSON_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConfigDriftGuardSnapshot {
    schema_version: u32,
    service_name: String,
    product_id: String,
    region_suffix_enabled: bool,
    effective_region_suffix: Option<String>,
    key_id_format_version: u32,
    aead_algorithm: String,
    data_row_record_format: String,
    metastore_identity: MetastoreIdentity,
    kms_identity: KmsIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum MetastoreIdentity {
    Memory,
    Sqlite {
        path: String,
    },
    Mysql,
    Postgres,
    DynamoDb {
        table: String,
        region: Option<String>,
        region_suffix_requested: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum KmsIdentity {
    Static,
    AwsKmsSingle {
        key_id: String,
        region: Option<String>,
    },
    AwsKmsEnvelope {
        preferred_region: String,
        regions: BTreeMap<String, String>,
    },
    SecretsManager {
        secret_id: String,
        region: Option<String>,
    },
    VaultTransit {
        addr: String,
        transit_mount: String,
        transit_key: String,
    },
}

impl ConfigDriftGuardSnapshot {
    fn from_resolved(
        config: &ResolvedConfig,
        effective_region_suffix: Option<&str>,
    ) -> anyhow::Result<Self> {
        let effective_region_suffix = effective_region_suffix
            .map(str::to_string)
            .filter(|suffix| !suffix.is_empty());
        Ok(Self {
            schema_version: 1,
            service_name: config.service_name.clone(),
            product_id: config.product_id.clone(),
            region_suffix_enabled: effective_region_suffix.is_some(),
            effective_region_suffix,
            key_id_format_version: 1,
            aead_algorithm: "AES-256-GCM".to_string(),
            data_row_record_format: "asherah-json-v1".to_string(),
            metastore_identity: MetastoreIdentity::from_config(&config.metastore),
            kms_identity: KmsIdentity::from_config(&config.kms)?,
        })
    }

    fn to_canonical_json_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).context("serialize config drift guard snapshot")?;
        if bytes.len() > MAX_CONFIG_DRIFT_GUARD_JSON_BYTES {
            anyhow::bail!(
                "config drift guard snapshot is too large: {} bytes exceeds {} byte limit",
                bytes.len(),
                MAX_CONFIG_DRIFT_GUARD_JSON_BYTES
            );
        }
        Ok(bytes)
    }
}

impl MetastoreIdentity {
    fn from_config(config: &MetastoreConfig) -> Self {
        match config {
            MetastoreConfig::Memory => Self::Memory,
            MetastoreConfig::Sqlite { path } => Self::Sqlite { path: path.clone() },
            MetastoreConfig::Postgres { .. } => Self::Postgres,
            MetastoreConfig::Mysql { .. } => Self::Mysql,
            MetastoreConfig::DynamoDb {
                table,
                region,
                region_suffix,
                ..
            } => Self::DynamoDb {
                table: table.clone(),
                region: region.clone(),
                region_suffix_requested: *region_suffix,
            },
        }
    }
}

impl KmsIdentity {
    fn from_config(config: &KmsConfig) -> anyhow::Result<Self> {
        match config {
            KmsConfig::Static { .. } => Ok(Self::Static),
            KmsConfig::Aws {
                region_map,
                preferred_region,
                key_id,
                region,
            } => {
                if let Some(region_map) = region_map {
                    let regions: BTreeMap<String, String> = region_map
                        .iter()
                        .map(|(region, key_id)| (region.clone(), key_id.clone()))
                        .collect();
                    let preferred_region = preferred_region
                        .clone()
                        .or_else(|| {
                            if regions.len() == 1 {
                                regions.keys().next().cloned()
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "preferred region is required for config drift guard identity"
                            )
                        })?;
                    Ok(Self::AwsKmsEnvelope {
                        preferred_region,
                        regions,
                    })
                } else {
                    let key_id = key_id.clone().ok_or_else(|| {
                        anyhow::anyhow!("KMS key id is required for config drift guard identity")
                    })?;
                    Ok(Self::AwsKmsSingle {
                        key_id,
                        region: region.clone(),
                    })
                }
            }
            KmsConfig::SecretsManager { secret_id, region } => Ok(Self::SecretsManager {
                secret_id: secret_id.clone(),
                region: region.clone(),
            }),
            KmsConfig::Vault {
                addr,
                transit_key,
                transit_mount,
            } => Ok(Self::VaultTransit {
                addr: addr.clone(),
                transit_mount: transit_mount
                    .clone()
                    .unwrap_or_else(|| "transit".to_string()),
                transit_key: transit_key.clone(),
            }),
        }
    }
}

fn config_drift_guard_id(service_name: &str, product_id: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(service_name.as_bytes());
    hasher.update([0]);
    hasher.update(product_id.as_bytes());
    let digest = hasher.finalize();
    let scope = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..32]);
    format!("{CONFIG_DRIFT_GUARD_ID_PREFIX}{scope}")
}

fn envelope_for(id: &str, bytes: Vec<u8>) -> EnvelopeKeyRecord {
    EnvelopeKeyRecord {
        revoked: None,
        id: id.to_string(),
        created: CONFIG_DRIFT_GUARD_CREATED,
        encrypted_key: bytes,
        parent_key_meta: None,
    }
}

fn snapshot_from_envelope(ekr: &EnvelopeKeyRecord) -> anyhow::Result<ConfigDriftGuardSnapshot> {
    if ekr.parent_key_meta.is_some() {
        anyhow::bail!("config drift guard record must not have parent key metadata");
    }
    if ekr.encrypted_key.len() > MAX_CONFIG_DRIFT_GUARD_JSON_BYTES {
        anyhow::bail!(
            "config drift guard record is too large: {} bytes exceeds {} byte limit",
            ekr.encrypted_key.len(),
            MAX_CONFIG_DRIFT_GUARD_JSON_BYTES
        );
    }
    serde_json::from_slice(&ekr.encrypted_key).context("parse config drift guard snapshot")
}

fn handle_existing(
    stored: &ConfigDriftGuardSnapshot,
    current: &ConfigDriftGuardSnapshot,
    options: ConfigDriftGuardOptions,
) -> anyhow::Result<bool> {
    if stored == current {
        return Ok(true);
    }
    if options.force_update {
        return Ok(false);
    }
    if options.allow_mismatch {
        log::error!(
            "config drift guard mismatch detected for service={} product={}; \
             continuing because force-run override is enabled",
            current.service_name,
            current.product_id
        );
        return Ok(true);
    }
    anyhow::bail!(
        "config drift guard mismatch detected for service={} product={}; \
         startup refused before key writes. Set ASHERAH_CONFIG_DRIFT_FORCE_RUN=true \
         to run without changing the guard, or ASHERAH_CONFIG_DRIFT_FORCE_UPDATE=true \
         to replace the guard after validating this configuration is correct.",
        current.service_name,
        current.product_id
    );
}

fn handle_load_error(
    err: anyhow::Error,
    current: &ConfigDriftGuardSnapshot,
    options: ConfigDriftGuardOptions,
) -> anyhow::Result<bool> {
    if options.force_update {
        log::error!(
            "config drift guard could not be loaded for service={} product={}; \
             replacing it because force-update override is enabled: {err:#}",
            current.service_name,
            current.product_id
        );
        return Ok(false);
    }
    if options.allow_mismatch {
        log::error!(
            "config drift guard could not be loaded for service={} product={}; \
             continuing because force-run override is enabled: {err:#}",
            current.service_name,
            current.product_id
        );
        return Ok(true);
    }
    Err(err).context("load config drift guard")
}

pub fn enforce_config_drift_guard(
    metastore: &dyn Metastore,
    config: &ResolvedConfig,
    options: ConfigDriftGuardOptions,
    effective_region_suffix: Option<&str>,
) -> anyhow::Result<()> {
    let current = ConfigDriftGuardSnapshot::from_resolved(config, effective_region_suffix)?;
    let current_bytes = current.to_canonical_json_bytes()?;
    let guard_id = config_drift_guard_id(&current.service_name, &current.product_id);
    let current_envelope = envelope_for(&guard_id, current_bytes);

    match metastore.load(&guard_id, CONFIG_DRIFT_GUARD_CREATED) {
        Ok(Some(existing)) => {
            let stored = match snapshot_from_envelope(&existing) {
                Ok(stored) => stored,
                Err(err) => {
                    if handle_load_error(err, &current, options)? {
                        return Ok(());
                    }
                    metastore.upsert_config_drift_guard(
                        &guard_id,
                        CONFIG_DRIFT_GUARD_CREATED,
                        &current_envelope,
                    )?;
                    log::error!(
                        "config drift guard replaced for service={} product={} by force-update override",
                        current.service_name,
                        current.product_id
                    );
                    return Ok(());
                }
            };
            if handle_existing(&stored, &current, options)? {
                return Ok(());
            }
            metastore.upsert_config_drift_guard(
                &guard_id,
                CONFIG_DRIFT_GUARD_CREATED,
                &current_envelope,
            )?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
        Ok(None) => {
            if metastore.store(&guard_id, CONFIG_DRIFT_GUARD_CREATED, &current_envelope)? {
                log::info!(
                    "config drift guard initialized for service={} product={}",
                    current.service_name,
                    current.product_id
                );
                return Ok(());
            }
            let Some(raced) = metastore.load(&guard_id, CONFIG_DRIFT_GUARD_CREATED)? else {
                anyhow::bail!("config drift guard TOFU insert raced but reload missed the record");
            };
            let stored = snapshot_from_envelope(&raced)?;
            if handle_existing(&stored, &current, options)? {
                return Ok(());
            }
            metastore.upsert_config_drift_guard(
                &guard_id,
                CONFIG_DRIFT_GUARD_CREATED,
                &current_envelope,
            )?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
        Err(err) => {
            if handle_load_error(err, &current, options)? {
                return Ok(());
            }
            metastore.upsert_config_drift_guard(
                &guard_id,
                CONFIG_DRIFT_GUARD_CREATED,
                &current_envelope,
            )?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
    }
}

pub async fn enforce_config_drift_guard_async(
    metastore: &dyn Metastore,
    config: &ResolvedConfig,
    options: ConfigDriftGuardOptions,
    effective_region_suffix: Option<&str>,
) -> anyhow::Result<()> {
    let current = ConfigDriftGuardSnapshot::from_resolved(config, effective_region_suffix)?;
    let current_bytes = current.to_canonical_json_bytes()?;
    let guard_id = config_drift_guard_id(&current.service_name, &current.product_id);
    let current_envelope = envelope_for(&guard_id, current_bytes);

    match metastore
        .load_async(&guard_id, CONFIG_DRIFT_GUARD_CREATED)
        .await
    {
        Ok(Some(existing)) => {
            let stored = match snapshot_from_envelope(&existing) {
                Ok(stored) => stored,
                Err(err) => {
                    if handle_load_error(err, &current, options)? {
                        return Ok(());
                    }
                    metastore
                        .upsert_config_drift_guard_async(
                            &guard_id,
                            CONFIG_DRIFT_GUARD_CREATED,
                            &current_envelope,
                        )
                        .await?;
                    log::error!(
                        "config drift guard replaced for service={} product={} by force-update override",
                        current.service_name,
                        current.product_id
                    );
                    return Ok(());
                }
            };
            if handle_existing(&stored, &current, options)? {
                return Ok(());
            }
            metastore
                .upsert_config_drift_guard_async(
                    &guard_id,
                    CONFIG_DRIFT_GUARD_CREATED,
                    &current_envelope,
                )
                .await?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
        Ok(None) => {
            if metastore
                .store_async(&guard_id, CONFIG_DRIFT_GUARD_CREATED, &current_envelope)
                .await?
            {
                log::info!(
                    "config drift guard initialized for service={} product={}",
                    current.service_name,
                    current.product_id
                );
                return Ok(());
            }
            let Some(raced) = metastore
                .load_async(&guard_id, CONFIG_DRIFT_GUARD_CREATED)
                .await?
            else {
                anyhow::bail!("config drift guard TOFU insert raced but reload missed the record");
            };
            let stored = snapshot_from_envelope(&raced)?;
            if handle_existing(&stored, &current, options)? {
                return Ok(());
            }
            metastore
                .upsert_config_drift_guard_async(
                    &guard_id,
                    CONFIG_DRIFT_GUARD_CREATED,
                    &current_envelope,
                )
                .await?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
        Err(err) => {
            if handle_load_error(err, &current, options)? {
                return Ok(());
            }
            metastore
                .upsert_config_drift_guard_async(
                    &guard_id,
                    CONFIG_DRIFT_GUARD_CREATED,
                    &current_envelope,
                )
                .await?;
            log::error!(
                "config drift guard replaced for service={} product={} by force-update override",
                current.service_name,
                current.product_id
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::builders::{KmsConfig, MetastoreConfig, PoolConfig};
    use crate::metastore::InMemoryMetastore;

    fn base_config() -> ResolvedConfig {
        ResolvedConfig {
            service_name: "svc".to_string(),
            product_id: "prod".to_string(),
            region_suffix: None,
            recovery_region_suffixes: Vec::new(),
            self_heal_recovered_keys: true,
            aws_profile_name: None,
            metastore: MetastoreConfig::Memory,
            kms: KmsConfig::Aws {
                region_map: None,
                preferred_region: None,
                key_id: Some("arn:aws:kms:us-east-1:123:key/abc".to_string()),
                region: Some("us-east-1".to_string()),
            },
            policy: Default::default(),
        }
    }

    #[test]
    fn tofu_initializes_guard_record() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();

        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();

        let id = config_drift_guard_id("svc", "prod");
        let stored = store
            .load(&id, CONFIG_DRIFT_GUARD_CREATED)
            .unwrap()
            .expect("guard must be seeded");
        let snapshot = snapshot_from_envelope(&stored).unwrap();
        assert_eq!(snapshot.service_name, "svc");
        assert_eq!(snapshot.product_id, "prod");
        assert_eq!(snapshot.effective_region_suffix, None);
    }

    #[test]
    fn matching_guard_allows_startup() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();

        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();
        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();
    }

    #[test]
    fn mismatch_fails_closed() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();
        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();

        let mut drifted = cfg.clone();
        drifted.kms = KmsConfig::Aws {
            region_map: None,
            preferred_region: None,
            key_id: Some("arn:aws:kms:us-east-1:123:key/other".to_string()),
            region: Some("us-east-1".to_string()),
        };

        let err =
            enforce_config_drift_guard(&store, &drifted, ConfigDriftGuardOptions::default(), None)
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("config drift guard mismatch"),
            "{err:#}"
        );
    }

    #[test]
    fn force_run_allows_mismatch_without_rewriting() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();
        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();

        let mut drifted = cfg.clone();
        drifted.kms = KmsConfig::Aws {
            region_map: None,
            preferred_region: None,
            key_id: Some("arn:aws:kms:us-east-1:123:key/other".to_string()),
            region: Some("us-east-1".to_string()),
        };

        enforce_config_drift_guard(
            &store,
            &drifted,
            ConfigDriftGuardOptions {
                allow_mismatch: true,
                force_update: false,
            },
            None,
        )
        .unwrap();
        let id = config_drift_guard_id("svc", "prod");
        let stored = store
            .load(&id, CONFIG_DRIFT_GUARD_CREATED)
            .unwrap()
            .expect("guard must remain");
        let snapshot = snapshot_from_envelope(&stored).unwrap();
        assert_eq!(
            snapshot.kms_identity,
            KmsIdentity::AwsKmsSingle {
                key_id: "arn:aws:kms:us-east-1:123:key/abc".to_string(),
                region: Some("us-east-1".to_string())
            }
        );
    }

    #[test]
    fn force_update_replaces_mismatched_guard() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();
        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();

        let mut drifted = cfg.clone();
        drifted.kms = KmsConfig::Aws {
            region_map: None,
            preferred_region: None,
            key_id: Some("arn:aws:kms:us-east-1:123:key/other".to_string()),
            region: Some("us-east-1".to_string()),
        };

        enforce_config_drift_guard(
            &store,
            &drifted,
            ConfigDriftGuardOptions {
                allow_mismatch: false,
                force_update: true,
            },
            None,
        )
        .unwrap();
        enforce_config_drift_guard(&store, &drifted, ConfigDriftGuardOptions::default(), None)
            .unwrap();
    }

    #[test]
    fn force_update_repairs_malformed_guard() {
        let store = InMemoryMetastore::new();
        let cfg = base_config();
        let id = config_drift_guard_id("svc", "prod");
        let bad = envelope_for(&id, b"not json".to_vec());
        assert!(store.store(&id, CONFIG_DRIFT_GUARD_CREATED, &bad).unwrap());

        let err =
            enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None)
                .unwrap_err();
        assert!(format!("{err:#}").contains("parse config drift guard"));

        enforce_config_drift_guard(
            &store,
            &cfg,
            ConfigDriftGuardOptions {
                allow_mismatch: false,
                force_update: true,
            },
            None,
        )
        .unwrap();
        enforce_config_drift_guard(&store, &cfg, ConfigDriftGuardOptions::default(), None).unwrap();
    }

    #[test]
    fn reserved_id_fits_mysql_schema_bound() {
        let id = config_drift_guard_id("svc", "prod");
        assert!(id.len() < 255, "{id}");
    }

    #[test]
    fn canonical_payload_fits_text_schema_with_large_region_map() {
        let mut regions = std::collections::HashMap::new();
        for i in 0..20 {
            regions.insert(
                format!("us-test-{i}"),
                format!(
                    "arn:aws:kms:us-test-{i}:123456789012:key/{i:08}-0000-0000-0000-000000000000"
                ),
            );
        }
        let mut cfg = base_config();
        cfg.metastore = MetastoreConfig::Mysql {
            url: "mysql://user:password@example.invalid/db".to_string(),
            tls_mode: None,
            replica_consistency: None,
            pool: PoolConfig::default(),
        };
        cfg.kms = KmsConfig::Aws {
            region_map: Some(regions),
            preferred_region: Some("us-test-0".to_string()),
            key_id: None,
            region: None,
        };

        let snapshot = ConfigDriftGuardSnapshot::from_resolved(&cfg, Some("us-test-0")).unwrap();
        let bytes = snapshot.to_canonical_json_bytes().unwrap();
        let outer = envelope_for("id", bytes).to_json_fast();
        assert!(
            outer.len() < 16 * 1024,
            "outer record should fit well below MySQL TEXT: {}",
            outer.len()
        );
    }

    #[tokio::test]
    async fn async_tofu_initializes_guard_record() {
        let store = Arc::new(InMemoryMetastore::new());
        let cfg = base_config();

        enforce_config_drift_guard_async(
            store.as_ref(),
            &cfg,
            ConfigDriftGuardOptions::default(),
            None,
        )
        .await
        .unwrap();

        let id = config_drift_guard_id("svc", "prod");
        assert!(store
            .load(&id, CONFIG_DRIFT_GUARD_CREATED)
            .unwrap()
            .is_some());
    }
}
