use crate::proto;

pub(crate) fn proto_to_drr(p: proto::DataRowRecord) -> asherah::DataRowRecord {
    asherah::DataRowRecord {
        key: p.key.map(|k| asherah::EnvelopeKeyRecord {
            revoked: None,
            id: String::new(),
            created: k.created,
            encrypted_key: k.key,
            parent_key_meta: k.parent_key_meta.map(|m| asherah::KeyMeta {
                id: m.key_id,
                created: m.created,
            }),
        }),
        data: p.data,
    }
}

pub(crate) fn drr_to_proto(d: asherah::DataRowRecord) -> proto::DataRowRecord {
    proto::DataRowRecord {
        key: d.key.map(|k| proto::EnvelopeKeyRecord {
            created: k.created,
            key: k.encrypted_key,
            parent_key_meta: k.parent_key_meta.map(|m| proto::KeyMeta {
                key_id: m.id,
                created: m.created,
            }),
        }),
        data: d.data,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn proto_to_drr_all_fields() {
        let p = proto::DataRowRecord {
            key: Some(proto::EnvelopeKeyRecord {
                created: 1709913600,
                key: vec![1, 2, 3, 4],
                parent_key_meta: Some(proto::KeyMeta {
                    key_id: "_IK_user1_svc_prod".to_string(),
                    created: 1709913540,
                }),
            }),
            data: vec![5, 6, 7, 8],
        };
        let drr = proto_to_drr(p);

        assert_eq!(drr.data, vec![5, 6, 7, 8]);
        let key = drr.key.unwrap();
        assert_eq!(key.created, 1709913600);
        assert_eq!(key.encrypted_key, vec![1, 2, 3, 4]);
        assert!(key.revoked.is_none(), "proto has no revoked field");
        assert!(key.id.is_empty(), "proto has no id field");
        let meta = key.parent_key_meta.unwrap();
        assert_eq!(meta.id, "_IK_user1_svc_prod");
        assert_eq!(meta.created, 1709913540);
    }

    #[test]
    fn proto_to_drr_no_key() {
        let p = proto::DataRowRecord {
            key: None,
            data: vec![1, 2, 3],
        };
        let drr = proto_to_drr(p);
        assert!(drr.key.is_none());
        assert_eq!(drr.data, vec![1, 2, 3]);
    }

    #[test]
    fn proto_to_drr_no_parent_key_meta() {
        let p = proto::DataRowRecord {
            key: Some(proto::EnvelopeKeyRecord {
                created: 100,
                key: vec![42],
                parent_key_meta: None,
            }),
            data: vec![],
        };
        let drr = proto_to_drr(p);
        let key = drr.key.unwrap();
        assert!(key.parent_key_meta.is_none());
        assert_eq!(key.created, 100);
        assert_eq!(key.encrypted_key, vec![42]);
    }

    #[test]
    fn drr_to_proto_all_fields() {
        let drr = asherah::DataRowRecord {
            key: Some(asherah::EnvelopeKeyRecord {
                revoked: Some(true),
                id: "should-be-dropped".to_string(),
                created: 12345,
                encrypted_key: vec![10, 20, 30],
                parent_key_meta: Some(asherah::KeyMeta {
                    id: "key-meta-id".to_string(),
                    created: 12300,
                }),
            }),
            data: vec![99, 100],
        };
        let p = drr_to_proto(drr);

        assert_eq!(p.data, vec![99, 100]);
        let key = p.key.unwrap();
        assert_eq!(key.created, 12345);
        assert_eq!(key.key, vec![10, 20, 30]);
        // revoked and id are not represented in proto
        let meta = key.parent_key_meta.unwrap();
        assert_eq!(meta.key_id, "key-meta-id");
        assert_eq!(meta.created, 12300);
    }

    #[test]
    fn drr_to_proto_no_key() {
        let drr = asherah::DataRowRecord {
            key: None,
            data: vec![1],
        };
        let p = drr_to_proto(drr);
        assert!(p.key.is_none());
        assert_eq!(p.data, vec![1]);
    }

    #[test]
    fn drr_to_proto_no_parent_key_meta() {
        let drr = asherah::DataRowRecord {
            key: Some(asherah::EnvelopeKeyRecord {
                revoked: None,
                id: String::new(),
                created: 50,
                encrypted_key: vec![7],
                parent_key_meta: None,
            }),
            data: vec![],
        };
        let p = drr_to_proto(drr);
        let key = p.key.unwrap();
        assert!(key.parent_key_meta.is_none());
    }

    #[test]
    fn roundtrip_asherah_to_proto_and_back() {
        let original = asherah::DataRowRecord {
            key: Some(asherah::EnvelopeKeyRecord {
                revoked: None,
                id: String::new(),
                created: 999,
                encrypted_key: vec![1, 2, 3, 4, 5],
                parent_key_meta: Some(asherah::KeyMeta {
                    id: "test-key".to_string(),
                    created: 998,
                }),
            }),
            data: vec![10, 20, 30, 40, 50],
        };
        let roundtripped = proto_to_drr(drr_to_proto(original.clone()));

        assert_eq!(roundtripped.data, original.data);
        let orig_key = original.key.unwrap();
        let rt_key = roundtripped.key.unwrap();
        assert_eq!(rt_key.created, orig_key.created);
        assert_eq!(rt_key.encrypted_key, orig_key.encrypted_key);
        assert!(rt_key.revoked.is_none());
        assert!(rt_key.id.is_empty());
        let orig_meta = orig_key.parent_key_meta.unwrap();
        let rt_meta = rt_key.parent_key_meta.unwrap();
        assert_eq!(rt_meta.id, orig_meta.id);
        assert_eq!(rt_meta.created, orig_meta.created);
    }

    #[test]
    fn roundtrip_proto_to_asherah_and_back() {
        let original = proto::DataRowRecord {
            key: Some(proto::EnvelopeKeyRecord {
                created: 777,
                key: vec![0xDE, 0xAD, 0xBE, 0xEF],
                parent_key_meta: Some(proto::KeyMeta {
                    key_id: "ik-id".to_string(),
                    created: 776,
                }),
            }),
            data: vec![0xCA, 0xFE],
        };
        let roundtripped = drr_to_proto(proto_to_drr(original.clone()));

        assert_eq!(roundtripped.data, original.data);
        let orig_key = original.key.unwrap();
        let rt_key = roundtripped.key.unwrap();
        assert_eq!(rt_key.created, orig_key.created);
        assert_eq!(rt_key.key, orig_key.key);
        let orig_meta = orig_key.parent_key_meta.unwrap();
        let rt_meta = rt_key.parent_key_meta.unwrap();
        assert_eq!(rt_meta.key_id, orig_meta.key_id);
        assert_eq!(rt_meta.created, orig_meta.created);
    }

    #[test]
    fn empty_data_roundtrip() {
        let p = proto::DataRowRecord {
            key: None,
            data: vec![],
        };
        let drr = proto_to_drr(p);
        assert!(drr.data.is_empty());
        assert!(drr.key.is_none());
        let back = drr_to_proto(drr);
        assert!(back.data.is_empty());
        assert!(back.key.is_none());
    }

    #[test]
    fn large_data_conversion() {
        let big_data = vec![0xAB_u8; 1024 * 1024];
        let big_key = vec![0xCD_u8; 256];
        let p = proto::DataRowRecord {
            key: Some(proto::EnvelopeKeyRecord {
                created: 1,
                key: big_key.clone(),
                parent_key_meta: None,
            }),
            data: big_data.clone(),
        };
        let drr = proto_to_drr(p);
        assert_eq!(drr.data.len(), 1024 * 1024);
        assert_eq!(drr.key.as_ref().unwrap().encrypted_key.len(), 256);
        let back = drr_to_proto(drr);
        assert_eq!(back.data, big_data);
        assert_eq!(back.key.unwrap().key, big_key);
    }
}
