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
    #[serde(
        rename = "Key",
        serialize_with = "serde_base64::serialize",
        deserialize_with = "serde_base64::deserialize"
    )]
    pub encrypted_key: Vec<u8>,
    #[serde(rename = "ParentKeyMeta", skip_serializing_if = "Option::is_none")]
    pub parent_key_meta: Option<KeyMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataRowRecord {
    #[serde(rename = "Key")]
    pub key: Option<EnvelopeKeyRecord>,
    #[serde(
        rename = "Data",
        serialize_with = "serde_base64::serialize",
        deserialize_with = "serde_base64::deserialize"
    )]
    pub data: Vec<u8>,
}

mod serde_base64 {
    use base64::Engine;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_row_record_uses_base64_for_bytes() {
        let record = DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                revoked: None,
                id: "key-id".into(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: None,
            }),
            data: vec![4, 5, 6],
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"Data\":\""), "data not base64: {json}");
        assert!(json.contains("\"Key\":\""), "key not base64: {json}");
    }
}
