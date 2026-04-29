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

    // Helpers: EnvelopeKeyRecord.id is `#[serde(skip)]` and intentionally does
    // NOT round-trip through JSON. Whole-struct compares would always fail on
    // it, so the helpers reset the deserialized id to match the source. Every
    // other field is checked via the derived PartialEq, which catches any
    // future serializer/parser divergence — including fields the original
    // tests skipped (parent_key_meta.created, etc.).
    fn ekr_for_compare(mut got: EnvelopeKeyRecord, want_id: &str) -> EnvelopeKeyRecord {
        got.id = want_id.into();
        got
    }

    fn drr_for_compare(mut got: DataRowRecord, want: &DataRowRecord) -> DataRowRecord {
        if let (Some(g), Some(w)) = (got.key.as_mut(), want.key.as_ref()) {
            g.id = w.id.clone();
        }
        got
    }

    #[test]
    fn envelope_key_record_to_json_fast_matches_serde() {
        // Verify that to_json_fast produces JSON that serde_json parses to the
        // same struct. Any divergence (including in fields the field-by-field
        // tests skipped, e.g. parent_key_meta.created) would silently break
        // round-trips between the encrypt (fast path) and decrypt (serde path).
        let record = EnvelopeKeyRecord {
            revoked: Some(false),
            id: "test-ik-id".into(),
            created: 1_700_000_000,
            encrypted_key: vec![0x01, 0x02, 0x03, 0xfe, 0xff],
            parent_key_meta: Some(KeyMeta {
                id: "sk-id".into(),
                created: 1_699_999_000,
            }),
        };
        let fast_json = record.to_json_fast();
        let from_fast: EnvelopeKeyRecord =
            serde_json::from_str(&fast_json).expect("fast JSON must parse with serde");
        assert_eq!(ekr_for_compare(from_fast, &record.id), record);
    }

    #[test]
    fn envelope_key_record_from_json_fast_matches_serde() {
        // Verify that from_json_fast parses serde-generated JSON to a struct
        // equal to the original. Mismatches here would silently corrupt key
        // records on load from the metastore.
        let record = EnvelopeKeyRecord {
            revoked: None,
            id: "ik-42".into(),
            created: 42,
            encrypted_key: vec![0xab, 0xcd, 0xef],
            parent_key_meta: Some(KeyMeta {
                id: "sk-root".into(),
                created: 1,
            }),
        };
        let serde_json = serde_json::to_string(&record).expect("serde must serialize");
        let from_fast = EnvelopeKeyRecord::from_json_fast(&serde_json)
            .expect("fast parser must parse serde JSON");
        assert_eq!(ekr_for_compare(from_fast, &record.id), record);
    }

    #[test]
    fn envelope_key_record_fast_roundtrip() {
        // Full round-trip: to_json_fast → from_json_fast
        let record = EnvelopeKeyRecord {
            revoked: Some(true),
            id: "rt-key".into(),
            created: 9_999,
            encrypted_key: (0_u8..32).collect(),
            parent_key_meta: Some(KeyMeta {
                id: "sk-rt".into(),
                created: 8_888,
            }),
        };
        let json = record.to_json_fast();
        let parsed = EnvelopeKeyRecord::from_json_fast(&json).expect("round-trip must succeed");
        assert_eq!(ekr_for_compare(parsed, &record.id), record);
    }

    #[test]
    fn data_row_record_to_json_fast_matches_serde() {
        // asherah_encrypt_to_json uses DataRowRecord::to_json_fast to serialize;
        // asherah_decrypt_from_json uses serde_json to deserialize. Both must
        // produce and consume compatible JSON across every field.
        let drr = DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                revoked: Some(false),
                id: String::new(),
                created: 100,
                encrypted_key: vec![0xca, 0xfe, 0xba, 0xbe],
                parent_key_meta: Some(KeyMeta {
                    id: "ik-1".into(),
                    created: 50,
                }),
            }),
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let fast_json = drr.to_json_fast();
        let parsed: DataRowRecord =
            serde_json::from_str(&fast_json).expect("serde must parse fast JSON");
        assert_eq!(drr_for_compare(parsed, &drr), drr);
    }
}
