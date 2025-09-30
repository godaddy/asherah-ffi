use std::sync::Arc;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{config::Region, types::AttributeValue, Client};
use base64::Engine;

use crate::traits::Metastore;
use crate::types::{EnvelopeKeyRecord, KeyMeta};

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DynamoDbMetastore {
    client: Client,
    table: String,
    rt: Arc<tokio::runtime::Runtime>,
    region_suffix_enabled: bool,
    region_suffix: Option<String>,
}

impl DynamoDbMetastore {
    pub fn new(table: impl Into<String>, region: Option<String>) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Runtime::new()?;
        let region_provider = if let Some(r) = region.clone() {
            RegionProviderChain::first_try(Region::new(r))
        } else {
            RegionProviderChain::default_provider()
        };
        let conf = rt.block_on(async {
            let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let mut b = aws_sdk_dynamodb::config::Builder::from(&cfg);
            if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
                b = b.endpoint_url(url);
            }
            b.build()
        });
        let client = Client::from_conf(conf.clone());
        // Optionally enable region suffix via env flag DDB_REGION_SUFFIX (truthy values: 1,true,yes,on)
        let with_suffix = std::env::var("DDB_REGION_SUFFIX")
            .ok()
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let suffix = if with_suffix {
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
            client,
            table: table_name,
            rt: Arc::new(rt),
            region_suffix_enabled: with_suffix,
            region_suffix: suffix,
        })
    }
}

impl Metastore for DynamoDbMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let out = self.rt.block_on(async {
            self.client
                .get_item()
                .table_name(&self.table)
                .key("Id", AttributeValue::S(id.to_string()))
                .key("Created", AttributeValue::N(created.to_string()))
                .consistent_read(true)
                .send()
                .await
        })?;
        if let Some(item) = out.item() {
            if let Some(kr) = item.get("KeyRecord") {
                if let Ok(m) = kr.as_m() {
                    // Decode DynamoDB map to EnvelopeKeyRecord (Go-compatible shape)
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
                    let encrypted_key =
                        base64::engine::general_purpose::STANDARD.decode(key_b64)?;

                    let parent_key_meta = if let Some(pk) =
                        m.get("ParentKeyMeta").and_then(|v| v.as_m().ok())
                    {
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

                    return Ok(Some(EnvelopeKeyRecord {
                        revoked: Some(revoked),
                        id: id.to_owned(),
                        created: created_num,
                        encrypted_key,
                        parent_key_meta,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        // Query by Id, descending on Created, limit 1
        let out = self.rt.block_on(async {
            self.client
                .query()
                .table_name(&self.table)
                .key_condition_expression("Id = :id")
                .expression_attribute_values(":id", AttributeValue::S(id.to_string()))
                .scan_index_forward(false)
                .limit(1)
                .consistent_read(true)
                .send()
                .await
        })?;
        let items = out.items();
        if let Some(item) = items.first() {
            if let Some(kr) = item.get("KeyRecord").and_then(|v| v.as_m().ok()) {
                let revoked = kr
                    .get("Revoked")
                    .and_then(|v| v.as_bool().ok().copied())
                    .unwrap_or(false);
                let created_v = kr
                    .get("Created")
                    .and_then(|v| v.as_n().ok())
                    .ok_or_else(|| anyhow::anyhow!("missing Created in KeyRecord"))?;
                let created_num: i64 = created_v.parse::<i64>()?;
                let key_b64 = kr
                    .get("Key")
                    .and_then(|v| v.as_s().ok())
                    .ok_or_else(|| anyhow::anyhow!("missing Key in KeyRecord"))?;
                let encrypted_key = base64::engine::general_purpose::STANDARD.decode(key_b64)?;
                let parent_key_meta =
                    if let Some(pk) = kr.get("ParentKeyMeta").and_then(|v| v.as_m().ok()) {
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
                return Ok(Some(EnvelopeKeyRecord {
                    revoked: Some(revoked),
                    id: id.to_owned(),
                    created: created_num,
                    encrypted_key,
                    parent_key_meta,
                }));
            }
        }
        Ok(None)
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        // Build Go-compatible KeyRecord map; Encrypted Key stored as base64 string
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
        let out = self.rt.block_on(async {
            self.client
                .put_item()
                .table_name(&self.table)
                .item("Id", AttributeValue::S(id.to_string()))
                .item("Created", AttributeValue::N(created.to_string()))
                .item("KeyRecord", AttributeValue::M(key_record))
                .condition_expression("attribute_not_exists(Id)")
                .send()
                .await
        });
        match out {
            Ok(_) => Ok(true),
            Err(e) => {
                // ConditionalCheckFailedException => already exists => return false
                let msg = format!("{e}");
                if msg.contains("ConditionalCheckFailed") {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!(e))
                }
            }
        }
    }

    fn region_suffix(&self) -> Option<String> {
        if self.region_suffix_enabled {
            self.region_suffix.clone()
        } else {
            None
        }
    }
}
