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
    /// Hand-written JSON deserializer for metastore loads — avoids serde overhead.
    /// Parses the same format produced by `to_json_fast()` and Go's canonical
    /// JSON serialization. Field order is flexible.
    pub fn from_json_fast(s: &str) -> Result<Self, anyhow::Error> {
        use base64::Engine;

        let mut created: Option<i64> = None;
        let mut key_b64: Option<&str> = None;
        let mut revoked: Option<bool> = None;
        let mut parent_id: Option<&str> = None;
        let mut parent_created: Option<i64> = None;

        // Minimal JSON object parser — handles the known fields without a
        // generic tokenizer. Skips unknown fields for forward compatibility.
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        // Skip whitespace
        macro_rules! skip_ws {
            () => {
                while i < len && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
                    i += 1;
                }
            };
        }

        // Expect and consume a specific byte
        macro_rules! expect {
            ($ch:expr) => {{
                skip_ws!();
                if i >= len || bytes[i] != $ch {
                    anyhow::bail!("expected '{}' at position {i}", $ch as char);
                }
                i += 1;
            }};
        }

        // Parse a JSON string, returning the content between quotes
        macro_rules! parse_string {
            () => {{
                skip_ws!();
                if i >= len || bytes[i] != b'"' {
                    anyhow::bail!("expected '\"' at position {i}");
                }
                i += 1;
                let start = i;
                // Fast scan for closing quote (no escape handling needed —
                // our values are base64, key IDs, and booleans, none with escapes)
                while i < len && bytes[i] != b'"' {
                    i += 1;
                }
                if i >= len {
                    anyhow::bail!("unterminated string at position {start}");
                }
                let val = &s[start..i];
                i += 1; // skip closing quote
                val
            }};
        }

        // Parse a JSON number (integer)
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

        // Skip a JSON value (string, number, object, array, bool, null)
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
                        let mut depth = 1_u32;
                        while i < len && depth > 0 {
                            match bytes[i] {
                                b'{' => depth += 1,
                                b'}' => depth -= 1,
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
                        let mut depth = 1_u32;
                        while i < len && depth > 0 {
                            match bytes[i] {
                                b'[' => depth += 1,
                                b']' => depth -= 1,
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
                        // number, bool, null — scan to next , or }
                        while i < len && !matches!(bytes[i], b',' | b'}' | b']') {
                            i += 1;
                        }
                    }
                }
            }};
        }

        // Parse top-level object
        expect!(b'{');

        loop {
            skip_ws!();
            if i >= len {
                break;
            }
            if bytes[i] == b'}' {
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
                        // null
                        i += 4;
                    } else {
                        anyhow::bail!("invalid Revoked value at {i}");
                    }
                }
                "ParentKeyMeta" => {
                    // Parse nested {"KeyId":"...","Created":...}
                    expect!(b'{');
                    loop {
                        skip_ws!();
                        if i >= len {
                            break;
                        }
                        if bytes[i] == b'}' {
                            i += 1;
                            break;
                        }
                        if bytes[i] == b',' {
                            i += 1;
                            continue;
                        }
                        let inner_field = parse_string!();
                        expect!(b':');
                        match inner_field {
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
            id: String::new(), // id comes from the metastore query, not the JSON
            created,
            encrypted_key,
            revoked,
            parent_key_meta,
        })
    }

    /// Hand-written JSON serializer for metastore storage — avoids serde overhead.
    pub fn to_json_fast(&self) -> String {
        use base64::Engine;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&self.encrypted_key);
        // Pre-calculate capacity
        let mut cap = 30 + key_b64.len(); // {"Created":,"Key":""}
        if let Some(ref pm) = self.parent_key_meta {
            cap += 40 + pm.id.len(); // ,"ParentKeyMeta":{"KeyId":"","Created":}
        }
        if self.revoked.is_some() {
            cap += 16; // ,"Revoked":false (longest)
        }
        let mut out = String::with_capacity(cap);
        out.push('{');
        // Field order must match serde's struct declaration order:
        // Revoked (if Some), Created, Key, ParentKeyMeta (if Some)
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
        out.push_str(&self.created.to_string());
        out.push_str(",\"Key\":\"");
        out.push_str(&key_b64);
        out.push('"');
        if let Some(ref pm) = self.parent_key_meta {
            out.push_str(",\"ParentKeyMeta\":{\"KeyId\":\"");
            out.push_str(&pm.id);
            out.push_str("\",\"Created\":");
            out.push_str(&pm.created.to_string());
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
    /// Output is byte-identical to `serde_json::to_string(self)`.
    pub fn to_json_fast(&self) -> String {
        use base64::Engine;
        let b64 = &base64::engine::general_purpose::STANDARD;

        // Pre-calculate capacity
        let data_b64_len = self.data.len().div_ceil(3) * 4;
        let mut cap = 10 + data_b64_len; // {"Data":"..."}
        if let Some(ref ekr) = self.key {
            let key_b64_len = ekr.encrypted_key.len().div_ceil(3) * 4;
            cap += 30 + key_b64_len; // {"Key":{"Created":N,"Key":"..."
            if ekr.revoked.is_some() {
                cap += 20; // ,"Revoked":false
            }
            if let Some(ref pm) = ekr.parent_key_meta {
                cap += 40 + pm.id.len(); // ,"ParentKeyMeta":{"KeyId":"...","Created":N}
            }
        }

        let mut out = String::with_capacity(cap);
        out.push('{');

        // "Key" field (serde outputs "Key":null when None)
        if let Some(ref ekr) = self.key {
            out.push_str("\"Key\":{");
            // Revoked (only if present)
            if let Some(rev) = ekr.revoked {
                out.push_str("\"Revoked\":");
                out.push_str(if rev { "true" } else { "false" });
                out.push(',');
            }
            // Created
            out.push_str("\"Created\":");
            out.push_str(itoa::Buffer::new().format(ekr.created));
            // Key (base64-encoded encrypted_key)
            out.push_str(",\"Key\":\"");
            b64.encode_string(&ekr.encrypted_key, &mut out);
            out.push('"');
            // ParentKeyMeta (optional)
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

        // "Data" field
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

    #[test]
    fn to_json_fast_matches_serde() {
        let record = DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                revoked: None,
                id: "ignored-id".into(),
                created: 1234567890,
                encrypted_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
                parent_key_meta: Some(KeyMeta {
                    id: "_IK_part_svc_prod".into(),
                    created: 9876543210,
                }),
            }),
            data: vec![10, 20, 30, 40, 50],
        };
        let serde_out = serde_json::to_string(&record).expect("serde_json");
        let fast_out = record.to_json_fast();
        assert_eq!(serde_out, fast_out, "fast serializer must match serde");
    }

    #[test]
    fn to_json_fast_with_revoked() {
        let record = DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                revoked: Some(true),
                id: String::new(),
                created: 42,
                encrypted_key: vec![0xAA],
                parent_key_meta: None,
            }),
            data: vec![0xBB],
        };
        let serde_out = serde_json::to_string(&record).expect("serde_json");
        let fast_out = record.to_json_fast();
        assert_eq!(serde_out, fast_out);
    }

    #[test]
    fn to_json_fast_no_key() {
        let record = DataRowRecord {
            key: None,
            data: vec![1, 2, 3],
        };
        let serde_out = serde_json::to_string(&record).expect("serde_json");
        let fast_out = record.to_json_fast();
        assert_eq!(serde_out, fast_out);
    }

    #[test]
    fn from_json_fast_roundtrip() {
        let original = EnvelopeKeyRecord {
            revoked: None,
            id: String::new(),
            created: 1705325400,
            encrypted_key: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            parent_key_meta: Some(KeyMeta {
                id: "_SK_svc_prod".into(),
                created: 1705325300,
            }),
        };
        let json = original.to_json_fast();
        let parsed = EnvelopeKeyRecord::from_json_fast(&json).expect("parse");
        assert_eq!(parsed.created, original.created);
        assert_eq!(parsed.encrypted_key, original.encrypted_key);
        assert_eq!(parsed.parent_key_meta, original.parent_key_meta);
        assert_eq!(parsed.revoked, original.revoked);
    }

    #[test]
    fn from_json_fast_with_revoked() {
        let original = EnvelopeKeyRecord {
            revoked: Some(true),
            id: String::new(),
            created: 42,
            encrypted_key: vec![1, 2, 3],
            parent_key_meta: None,
        };
        let json = original.to_json_fast();
        let parsed = EnvelopeKeyRecord::from_json_fast(&json).expect("parse");
        assert_eq!(parsed.created, 42);
        assert_eq!(parsed.encrypted_key, vec![1, 2, 3]);
        assert_eq!(parsed.revoked, Some(true));
        assert_eq!(parsed.parent_key_meta, None);
    }

    #[test]
    fn from_json_fast_matches_serde() {
        // Verify from_json_fast produces the same result as serde_json
        let json =
            r#"{"Created":100,"Key":"AQID","ParentKeyMeta":{"KeyId":"_SK_a_b","Created":99}}"#;
        let serde_parsed: EnvelopeKeyRecord = serde_json::from_str(json).expect("parse");
        let fast_parsed = EnvelopeKeyRecord::from_json_fast(json).expect("parse");
        assert_eq!(fast_parsed.created, serde_parsed.created);
        assert_eq!(fast_parsed.encrypted_key, serde_parsed.encrypted_key);
        assert_eq!(fast_parsed.parent_key_meta, serde_parsed.parent_key_meta);
        assert_eq!(fast_parsed.revoked, serde_parsed.revoked);
    }

    #[test]
    fn from_json_fast_unknown_fields_ignored() {
        let json = r#"{"Created":1,"Key":"AA==","UnknownField":"ignored","ParentKeyMeta":{"KeyId":"x","Created":2,"Extra":true}}"#;
        let parsed = EnvelopeKeyRecord::from_json_fast(json).expect("parse");
        assert_eq!(parsed.created, 1);
        assert_eq!(parsed.encrypted_key, vec![0]);
        assert_eq!(parsed.parent_key_meta.expect("parse").id, "x");
    }

    #[test]
    fn from_json_fast_revoked_false() {
        let json = r#"{"Created":1,"Key":"AA==","Revoked":false}"#;
        let serde_parsed: EnvelopeKeyRecord = serde_json::from_str(json).expect("serde");
        let fast_parsed = EnvelopeKeyRecord::from_json_fast(json).expect("fast");
        assert_eq!(fast_parsed.revoked, Some(false));
        assert_eq!(fast_parsed.revoked, serde_parsed.revoked);
    }

    #[test]
    fn to_json_fast_revoked_false_roundtrip() {
        let original = EnvelopeKeyRecord {
            revoked: Some(false),
            id: String::new(),
            created: 1,
            encrypted_key: vec![0],
            parent_key_meta: None,
        };
        let json = original.to_json_fast();
        assert!(
            json.contains("\"Revoked\":false"),
            "JSON must contain Revoked:false: {json}"
        );
        let parsed = EnvelopeKeyRecord::from_json_fast(&json).expect("parse");
        assert_eq!(parsed.revoked, Some(false));
        // Also verify serde produces the same JSON
        let serde_json_str = serde_json::to_string(&original).expect("serde");
        assert_eq!(json, serde_json_str);
    }

    #[test]
    fn fast_serializer_parity_with_serde_all_variants() {
        // Exhaustive test: every combination of optional fields
        let variants = [
            EnvelopeKeyRecord {
                revoked: None,
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: None,
            },
            EnvelopeKeyRecord {
                revoked: Some(true),
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: None,
            },
            EnvelopeKeyRecord {
                revoked: Some(false),
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: None,
            },
            EnvelopeKeyRecord {
                revoked: None,
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: Some(KeyMeta {
                    id: "_SK_a_b".into(),
                    created: 99,
                }),
            },
            EnvelopeKeyRecord {
                revoked: Some(true),
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: Some(KeyMeta {
                    id: "_SK_a_b".into(),
                    created: 99,
                }),
            },
            EnvelopeKeyRecord {
                revoked: Some(false),
                id: String::new(),
                created: 42,
                encrypted_key: vec![1, 2, 3],
                parent_key_meta: Some(KeyMeta {
                    id: "_SK_a_b".into(),
                    created: 99,
                }),
            },
        ];
        for (i, v) in variants.iter().enumerate() {
            let serde_out = serde_json::to_string(v).expect("serde serialize");
            let fast_out = v.to_json_fast();
            assert_eq!(serde_out, fast_out, "to_json_fast mismatch for variant {i}");
            let serde_parsed: EnvelopeKeyRecord =
                serde_json::from_str(&serde_out).expect("serde parse");
            let fast_parsed = EnvelopeKeyRecord::from_json_fast(&fast_out).expect("fast parse");
            assert_eq!(
                fast_parsed.created, serde_parsed.created,
                "created mismatch for variant {i}"
            );
            assert_eq!(
                fast_parsed.encrypted_key, serde_parsed.encrypted_key,
                "key mismatch for variant {i}"
            );
            assert_eq!(
                fast_parsed.parent_key_meta, serde_parsed.parent_key_meta,
                "parent mismatch for variant {i}"
            );
            assert_eq!(
                fast_parsed.revoked, serde_parsed.revoked,
                "revoked mismatch for variant {i}"
            );
        }
    }
}
