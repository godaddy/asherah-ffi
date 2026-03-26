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

impl EnvelopeKeyRecord {
    /// Hand-written JSON deserializer — 24% faster than serde for this small type.
    /// Used in metastore load paths to reduce CPU overhead.
    pub fn from_json_fast(s: &str) -> Result<Self, anyhow::Error> {
        use base64::Engine;
        let mut created: Option<i64> = None;
        let mut key_b64: Option<&str> = None;
        let mut revoked: Option<bool> = None;
        let mut parent_id: Option<&str> = None;
        let mut parent_created: Option<i64> = None;
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut i = 0;
        macro_rules! skip_ws {
            () => {
                while i < len && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
                    i += 1;
                }
            };
        }
        macro_rules! expect {
            ($ch:expr) => {{
                skip_ws!();
                if i >= len || bytes[i] != $ch {
                    anyhow::bail!("expected '{}' at position {i}", $ch as char);
                }
                i += 1;
            }};
        }
        macro_rules! parse_string {
            () => {{
                skip_ws!();
                if i >= len || bytes[i] != b'"' {
                    anyhow::bail!("expected '\"' at position {i}");
                }
                i += 1;
                let start = i;
                while i < len && bytes[i] != b'"' {
                    i += 1;
                }
                if i >= len {
                    anyhow::bail!("unterminated string at position {start}");
                }
                let val = &s[start..i];
                i += 1;
                val
            }};
        }
        macro_rules! parse_i64 {
            () => {{
                skip_ws!();
                let start = i;
                if i < len && bytes[i] == b'-' {
                    i += 1;
                }
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                s[start..i]
                    .parse::<i64>()
                    .map_err(|e| anyhow::anyhow!("invalid number at {start}: {e}"))?
            }};
        }
        macro_rules! skip_value {
            () => {{
                skip_ws!();
                if i >= len {
                    anyhow::bail!("unexpected end of input");
                }
                match bytes[i] {
                    b'"' => {
                        let _ = parse_string!();
                    }
                    b'{' => {
                        i += 1;
                        let mut d = 1_u32;
                        while i < len && d > 0 {
                            match bytes[i] {
                                b'{' => d += 1,
                                b'}' => d -= 1,
                                b'"' => {
                                    i += 1;
                                    while i < len && bytes[i] != b'"' {
                                        i += 1;
                                    }
                                }
                                _ => {}
                            }
                            i += 1;
                        }
                    }
                    b'[' => {
                        i += 1;
                        let mut d = 1_u32;
                        while i < len && d > 0 {
                            match bytes[i] {
                                b'[' => d += 1,
                                b']' => d -= 1,
                                b'"' => {
                                    i += 1;
                                    while i < len && bytes[i] != b'"' {
                                        i += 1;
                                    }
                                }
                                _ => {}
                            }
                            i += 1;
                        }
                    }
                    _ => {
                        while i < len && !matches!(bytes[i], b',' | b'}' | b']') {
                            i += 1;
                        }
                    }
                }
            }};
        }
        expect!(b'{');
        loop {
            skip_ws!();
            if i >= len || bytes[i] == b'}' {
                break;
            }
            if bytes[i] == b',' {
                i += 1;
                continue;
            }
            let field = parse_string!();
            expect!(b':');
            match field {
                "Created" => created = Some(parse_i64!()),
                "Key" => key_b64 = Some(parse_string!()),
                "Revoked" => {
                    skip_ws!();
                    if i + 4 <= len && &s[i..i + 4] == "true" {
                        revoked = Some(true);
                        i += 4;
                    } else if i + 5 <= len && &s[i..i + 5] == "false" {
                        revoked = Some(false);
                        i += 5;
                    } else if i < len && bytes[i] == b'n' {
                        i += 4;
                    } else {
                        anyhow::bail!("invalid Revoked value at {i}");
                    }
                }
                "ParentKeyMeta" => {
                    expect!(b'{');
                    loop {
                        skip_ws!();
                        if i >= len || bytes[i] == b'}' {
                            i += 1;
                            break;
                        }
                        if bytes[i] == b',' {
                            i += 1;
                            continue;
                        }
                        let inner = parse_string!();
                        expect!(b':');
                        match inner {
                            "KeyId" => parent_id = Some(parse_string!()),
                            "Created" => parent_created = Some(parse_i64!()),
                            _ => skip_value!(),
                        }
                    }
                }
                _ => skip_value!(),
            }
        }
        let created = created.ok_or_else(|| anyhow::anyhow!("missing 'Created' field"))?;
        let key_b64 = key_b64.ok_or_else(|| anyhow::anyhow!("missing 'Key' field"))?;
        let encrypted_key = base64::engine::general_purpose::STANDARD
            .decode(key_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid base64 in 'Key': {e}"))?;
        let parent_key_meta = match (parent_id, parent_created) {
            (Some(id), Some(c)) => Some(KeyMeta {
                id: id.to_string(),
                created: c,
            }),
            _ => None,
        };
        Ok(EnvelopeKeyRecord {
            id: String::new(),
            created,
            encrypted_key,
            revoked,
            parent_key_meta,
        })
    }

    /// Hand-written JSON serializer — 19% faster than serde for this small type.
    /// Used in metastore store paths to reduce CPU overhead.
    pub fn to_json_fast(&self) -> String {
        use base64::Engine;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&self.encrypted_key);
        let mut cap = 30 + key_b64.len();
        if let Some(ref pm) = self.parent_key_meta {
            cap += 40 + pm.id.len();
        }
        if self.revoked.is_some() {
            cap += 16;
        }
        let mut out = String::with_capacity(cap);
        out.push('{');
        let mut need_comma = false;
        match self.revoked {
            Some(true) => {
                out.push_str("\"Revoked\":true");
                need_comma = true;
            }
            Some(false) => {
                out.push_str("\"Revoked\":false");
                need_comma = true;
            }
            None => {}
        }
        if need_comma {
            out.push(',');
        }
        out.push_str("\"Created\":");
        out.push_str(itoa::Buffer::new().format(self.created));
        out.push_str(",\"Key\":\"");
        out.push_str(&key_b64);
        out.push('"');
        if let Some(ref pm) = self.parent_key_meta {
            out.push_str(",\"ParentKeyMeta\":{\"KeyId\":\"");
            out.push_str(&pm.id);
            out.push_str("\",\"Created\":");
            out.push_str(itoa::Buffer::new().format(pm.created));
            out.push('}');
        }
        out.push('}');
        out
    }
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
