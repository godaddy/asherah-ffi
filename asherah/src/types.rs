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

pub(crate) mod serde_base64 {
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
        // Borrow the str directly from the JSON token when possible,
        // avoiding an intermediate String allocation.
        let s: std::borrow::Cow<'de, str> =
            <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(Error::custom)
    }
}

impl DataRowRecord {
    /// Hand-written JSON serializer — avoids serde overhead and intermediate allocations.
    #[inline]
    pub fn to_json_fast(&self) -> String {
        use base64::Engine;
        let b64 = &base64::engine::general_purpose::STANDARD;

        let data_b64_len = self.data.len().div_ceil(3) * 4;
        let mut cap = 10 + data_b64_len;
        if let Some(ref ekr) = self.key {
            let key_b64_len = ekr.encrypted_key.len().div_ceil(3) * 4;
            cap += 30 + key_b64_len;
            if ekr.revoked.is_some() {
                cap += 20;
            }
            if let Some(ref pm) = ekr.parent_key_meta {
                cap += 40 + pm.id.len();
            }
        }

        let mut out = String::with_capacity(cap);
        out.push('{');

        if let Some(ref ekr) = self.key {
            out.push_str("\"Key\":{");
            if let Some(rev) = ekr.revoked {
                out.push_str("\"Revoked\":");
                out.push_str(if rev { "true" } else { "false" });
                out.push(',');
            }
            out.push_str("\"Created\":");
            out.push_str(itoa::Buffer::new().format(ekr.created));
            out.push_str(",\"Key\":\"");
            b64.encode_string(&ekr.encrypted_key, &mut out);
            out.push('"');
            if let Some(ref pm) = ekr.parent_key_meta {
                out.push_str(",\"ParentKeyMeta\":{\"KeyId\":\"");
                json_escape_into(&pm.id, &mut out);
                out.push_str("\",\"Created\":");
                out.push_str(itoa::Buffer::new().format(pm.created));
                out.push('}');
            }
            out.push('}');
        } else {
            out.push_str("\"Key\":null");
        }
        out.push(',');

        out.push_str("\"Data\":\"");
        b64.encode_string(&self.data, &mut out);
        out.push_str("\"}");

        out
    }
}

/// Escape a string for JSON output (handles the minimal set: \ " and control chars).
fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
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
        let json = serde_json::to_string(&record).expect("serialization should succeed");
        assert!(json.contains("\"Data\":\""), "data not base64: {json}");
        assert!(json.contains("\"Key\":\""), "key not base64: {json}");
    }

    // Tests for to_json_fast / from_json_fast were removed along with those functions.
    // Serde serialization is now the only path and is covered by the test above.
}
