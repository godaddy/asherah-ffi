use serde::{Deserialize, Serialize};

// Matches Go JSON field names for compatibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyMeta {
    #[serde(rename = "KeyId")]
    pub id: String,
    #[serde(rename = "Created")]
    pub created: i64,
}

impl KeyMeta {
    pub fn is_latest(&self) -> bool {
        self.created == 0
    }
    pub fn as_latest(&self) -> KeyMeta {
        KeyMeta {
            id: self.id.clone(),
            created: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeKeyRecord {
    #[serde(rename = "Revoked", skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(skip)]
    pub id: String,
    #[serde(rename = "Created")]
    pub created: i64,
    #[serde(rename = "Key")]
    pub encrypted_key: Vec<u8>,
    #[serde(rename = "ParentKeyMeta", skip_serializing_if = "Option::is_none")]
    pub parent_key_meta: Option<KeyMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataRowRecord {
    #[serde(rename = "Key")]
    pub key: Option<EnvelopeKeyRecord>,
    #[serde(rename = "Data")]
    pub data: Vec<u8>,
}
