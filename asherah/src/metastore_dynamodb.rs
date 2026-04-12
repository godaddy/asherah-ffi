use std::sync::Arc;

use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{config::Region, types::AttributeValue, Client};
use base64::Engine;
use tokio::sync::OnceCell;

use crate::traits::Metastore;
use crate::types::{EnvelopeKeyRecord, KeyMeta};
use anyhow::Context;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DynamoDbMetastore {
    /// Client for sync callers — created on the private runtime.
    sync_client: Client,
    /// Lazily-created client for async callers — created on the caller's
    /// runtime on first async use. This avoids the hyper HTTP connector
    /// being bound to the wrong runtime when setup() is sync but
    /// decrypt_async() runs on a different runtime (e.g., napi's).
    async_client: Arc<OnceCell<Client>>,
    /// SDK config saved for lazy async client creation.
    sdk_conf: aws_sdk_dynamodb::Config,
    table: String,
    /// Private runtime for sync callers (Python, Java, Go, etc.)
    rt: Arc<tokio::runtime::Runtime>,
    region_suffix_enabled: bool,
    region_suffix: Option<String>,
}

impl DynamoDbMetastore {
    /// Construct with explicit config — no env var reads.
    pub fn new_with(
        table: impl Into<String>,
        region: Option<String>,
        endpoint: Option<String>,
        region_suffix: bool,
    ) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Runtime::new()?;
        let region_provider = if let Some(r) = region.clone() {
            RegionProviderChain::first_try(Region::new(r))
        } else {
            RegionProviderChain::default_provider()
        };
        let conf = Self::block_on_maybe(&rt, async {
            let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let mut b = aws_sdk_dynamodb::config::Builder::from(&cfg);
            if let Some(ref url) = endpoint {
                b = b.endpoint_url(url);
            }
            b.build()
        });
        let client = Client::from_conf(conf.clone());
        let suffix = if region_suffix {
            conf.region().map(|r| r.to_string())
        } else {
            None
        };
        let table_name = {
            let t = table.into();
            if t.is_empty() {
                "EncryptionKey".to_string()
            } else {
                t
            }
        };
        Ok(Self {
            sync_client: client,
            async_client: Arc::new(OnceCell::new()),
            sdk_conf: conf,
            table: table_name,
            rt: Arc::new(rt),
            region_suffix_enabled: region_suffix,
            region_suffix: suffix,
        })
    }

    /// Construct using env vars for endpoint/region_suffix (legacy entry point).
    pub fn new(table: impl Into<String>, region: Option<String>) -> anyhow::Result<Self> {
        let endpoint = std::env::var("AWS_ENDPOINT_URL").ok();
        let with_suffix = std::env::var("DDB_REGION_SUFFIX")
            .ok()
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        Self::new_with(table, region, endpoint, with_suffix)
    }

    /// Async constructor with explicit config — no env var reads.
    pub async fn new_with_async(
        table: impl Into<String>,
        region: Option<String>,
        endpoint: Option<String>,
        region_suffix: bool,
    ) -> anyhow::Result<Self> {
        let region_provider = if let Some(r) = region.clone() {
            RegionProviderChain::first_try(Region::new(r))
        } else {
            RegionProviderChain::default_provider()
        };
        let conf = {
            let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let mut b = aws_sdk_dynamodb::config::Builder::from(&cfg);
            if let Some(ref url) = endpoint {
                b = b.endpoint_url(url);
            }
            b.build()
        };
        let client = Client::from_conf(conf.clone());
        let rt = tokio::runtime::Runtime::new()?;
        let sync_client = Client::from_conf(conf.clone());
        let suffix = if region_suffix {
            conf.region().map(|r| r.to_string())
        } else {
            None
        };
        let table_name = {
            let t = table.into();
            if t.is_empty() {
                "EncryptionKey".to_string()
            } else {
                t
            }
        };
        // Pre-populate async_client since we're already on the right runtime
        let async_cell = Arc::new(OnceCell::new());
        async_cell
            .set(client)
            .unwrap_or_else(|_| unreachable!("OnceCell was just created"));
        Ok(Self {
            sync_client,
            async_client: async_cell,
            sdk_conf: conf,
            table: table_name,
            rt: Arc::new(rt),
            region_suffix_enabled: region_suffix,
            region_suffix: suffix,
        })
    }

    /// Async constructor using env vars (legacy entry point).
    pub async fn new_async(
        table: impl Into<String>,
        region: Option<String>,
    ) -> anyhow::Result<Self> {
        let endpoint = std::env::var("AWS_ENDPOINT_URL").ok();
        let with_suffix = std::env::var("DDB_REGION_SUFFIX")
            .ok()
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        Self::new_with_async(table, region, endpoint, with_suffix).await
    }

    /// Get the client for async operations. If we were constructed sync,
    /// lazily creates a new client on the caller's runtime.
    async fn async_client(&self) -> &Client {
        self.async_client
            .get_or_init(async || Client::from_conf(self.sdk_conf.clone()))
            .await
    }

    /// Block on a future, handling both tokio-worker and plain-thread contexts.
    fn block_on_maybe<F: std::future::Future>(rt: &tokio::runtime::Runtime, f: F) -> F::Output {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| rt.block_on(f))
        } else {
            rt.block_on(f)
        }
    }

    // ── Sync implementations (use sync_client on private runtime) ──

    async fn load_impl_sync(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!(
            "dynamodb load: table={} id={id} created={created}",
            self.table
        );
        let out = self
            .sync_client
            .get_item()
            .table_name(&self.table)
            .key("Id", AttributeValue::S(id.to_string()))
            .key("Created", AttributeValue::N(created.to_string()))
            .consistent_read(true)
            .send()
            .await
            .with_context(|| {
                format!(
                    "DynamoDB GetItem failed for table={} id={id} created={created}",
                    self.table
                )
            })?;
        Self::parse_item(out.item(), id)
    }

    async fn load_latest_impl_sync(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("dynamodb load_latest: table={} id={id}", self.table);
        let out = self
            .sync_client
            .query()
            .table_name(&self.table)
            .key_condition_expression("Id = :id")
            .expression_attribute_values(":id", AttributeValue::S(id.to_string()))
            .scan_index_forward(false)
            .limit(1)
            .consistent_read(true)
            .send()
            .await
            .with_context(|| format!("DynamoDB Query failed for table={} id={id}", self.table))?;
        if let Some(item) = out.items().first() {
            if let Some(kr) = item.get("KeyRecord").and_then(|v| v.as_m().ok()) {
                return Ok(Some(Self::decode_key_record(kr, id)?));
            }
        }
        Ok(None)
    }

    async fn store_impl_sync(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        Self::do_store(&self.sync_client, &self.table, id, created, ekr).await
    }

    // ── Async implementations (use async_client on caller's runtime) ──

    async fn load_impl_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let client = self.async_client().await;
        log::debug!(
            "dynamodb load_async: table={} id={id} created={created}",
            self.table
        );
        let out = client
            .get_item()
            .table_name(&self.table)
            .key("Id", AttributeValue::S(id.to_string()))
            .key("Created", AttributeValue::N(created.to_string()))
            .consistent_read(true)
            .send()
            .await
            .with_context(|| {
                format!(
                    "DynamoDB GetItem failed for table={} id={id} created={created}",
                    self.table
                )
            })?;
        Self::parse_item(out.item(), id)
    }

    async fn load_latest_impl_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let client = self.async_client().await;
        log::debug!("dynamodb load_latest_async: table={} id={id}", self.table);
        let out = client
            .query()
            .table_name(&self.table)
            .key_condition_expression("Id = :id")
            .expression_attribute_values(":id", AttributeValue::S(id.to_string()))
            .scan_index_forward(false)
            .limit(1)
            .consistent_read(true)
            .send()
            .await
            .with_context(|| format!("DynamoDB Query failed for table={} id={id}", self.table))?;
        if let Some(item) = out.items().first() {
            if let Some(kr) = item.get("KeyRecord").and_then(|v| v.as_m().ok()) {
                return Ok(Some(Self::decode_key_record(kr, id)?));
            }
        }
        Ok(None)
    }

    async fn store_impl_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let client = self.async_client().await;
        Self::do_store(client, &self.table, id, created, ekr).await
    }

    // ── Shared helpers ──

    fn parse_item(
        item: Option<&std::collections::HashMap<String, AttributeValue>>,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        if let Some(item) = item {
            if let Some(kr) = item.get("KeyRecord") {
                if let Ok(m) = kr.as_m() {
                    return Ok(Some(Self::decode_key_record(m, id)?));
                }
            }
        }
        Ok(None)
    }

    async fn do_store(
        client: &Client,
        table: &str,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let mut key_record: std::collections::HashMap<String, AttributeValue> =
            std::collections::HashMap::new();
        if let Some(rv) = ekr.revoked {
            key_record.insert("Revoked".to_string(), AttributeValue::Bool(rv));
        }
        key_record.insert(
            "Created".to_string(),
            AttributeValue::N(ekr.created.to_string()),
        );
        key_record.insert(
            "Key".to_string(),
            AttributeValue::S(base64::engine::general_purpose::STANDARD.encode(&ekr.encrypted_key)),
        );
        if let Some(pk) = &ekr.parent_key_meta {
            let mut m: std::collections::HashMap<String, AttributeValue> =
                std::collections::HashMap::new();
            m.insert("KeyId".to_string(), AttributeValue::S(pk.id.clone()));
            m.insert(
                "Created".to_string(),
                AttributeValue::N(pk.created.to_string()),
            );
            key_record.insert("ParentKeyMeta".to_string(), AttributeValue::M(m));
        }
        log::debug!("dynamodb store: table={table} id={id} created={created}");
        let out = client
            .put_item()
            .table_name(table)
            .item("Id", AttributeValue::S(id.to_string()))
            .item("Created", AttributeValue::N(created.to_string()))
            .item("KeyRecord", AttributeValue::M(key_record))
            .condition_expression("attribute_not_exists(Id)")
            .send()
            .await;
        match out {
            Ok(_) => {
                log::debug!("dynamodb store: success id={id} created={created}");
                Ok(true)
            }
            Err(e) => {
                let msg = format!("{e:?}");
                if msg.contains("ConditionalCheckFailed") {
                    log::debug!("dynamodb store: duplicate key id={id} created={created}");
                    Ok(false)
                } else {
                    log::error!(
                        "dynamodb store failed: table={table} id={id} created={created}: {e:#}"
                    );
                    Err(anyhow::anyhow!(
                        "DynamoDB PutItem failed for table={table} id={id}: {e}"
                    ))
                }
            }
        }
    }

    fn decode_key_record(
        m: &std::collections::HashMap<String, AttributeValue>,
        id: &str,
    ) -> anyhow::Result<EnvelopeKeyRecord> {
        let revoked = m
            .get("Revoked")
            .and_then(|v| v.as_bool().ok().copied())
            .unwrap_or(false);
        let created_v = m
            .get("Created")
            .and_then(|v| v.as_n().ok())
            .ok_or_else(|| anyhow::anyhow!("missing Created in KeyRecord"))?;
        let created_num: i64 = created_v.parse::<i64>()?;
        let key_b64 = m
            .get("Key")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| anyhow::anyhow!("missing Key in KeyRecord"))?;
        let encrypted_key = base64::engine::general_purpose::STANDARD.decode(key_b64)?;
        let parent_key_meta = if let Some(pk) = m.get("ParentKeyMeta").and_then(|v| v.as_m().ok()) {
            let kid = pk
                .get("KeyId")
                .and_then(|v| v.as_s().ok())
                .ok_or_else(|| anyhow::anyhow!("missing KeyId in ParentKeyMeta"))?;
            let c = pk
                .get("Created")
                .and_then(|v| v.as_n().ok())
                .ok_or_else(|| anyhow::anyhow!("missing Created in ParentKeyMeta"))?;
            let c_num: i64 = c.parse::<i64>()?;
            Some(KeyMeta {
                id: kid.to_owned(),
                created: c_num,
            })
        } else {
            None
        };
        Ok(EnvelopeKeyRecord {
            revoked: Some(revoked),
            id: id.to_owned(),
            created: created_num,
            encrypted_key,
            parent_key_meta,
        })
    }
}

#[async_trait]
impl Metastore for DynamoDbMetastore {
    // Sync methods — use sync_client on private runtime
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        Self::block_on_maybe(&self.rt, self.load_impl_sync(id, created))
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        Self::block_on_maybe(&self.rt, self.load_latest_impl_sync(id))
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        Self::block_on_maybe(&self.rt, self.store_impl_sync(id, created, ekr))
    }

    fn region_suffix(&self) -> Option<String> {
        if self.region_suffix_enabled {
            self.region_suffix.clone()
        } else {
            None
        }
    }

    // Async methods — use async_client (lazily created on caller's runtime)
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load_impl_async(id, created).await
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load_latest_impl_async(id).await
    }

    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.store_impl_async(id, created, ekr).await
    }
}
