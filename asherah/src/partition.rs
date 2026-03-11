use crate::traits::Partition;

#[derive(Clone, Debug)]
pub struct DefaultPartition {
    id: String,
    service: String,
    product: String,
    suffix: Option<String>,
}

impl DefaultPartition {
    pub fn new(id: String, service: String, product: String) -> Self {
        Self {
            id,
            service,
            product,
            suffix: None,
        }
    }
    pub fn new_suffixed(id: String, service: String, product: String, suffix: String) -> Self {
        Self {
            id,
            service,
            product,
            suffix: Some(suffix),
        }
    }
}

impl Partition for DefaultPartition {
    fn system_key_id(&self) -> String {
        match &self.suffix {
            Some(s) => format!("_SK_{}_{}_{}", self.service, self.product, s),
            None => format!("_SK_{}_{}", self.service, self.product),
        }
    }
    fn intermediate_key_id(&self) -> String {
        match &self.suffix {
            Some(s) => format!("_IK_{}_{}_{}_{}", self.id, self.service, self.product, s),
            None => format!("_IK_{}_{}_{}", self.id, self.service, self.product),
        }
    }
    fn is_valid_intermediate_key_id(&self, id: &str) -> bool {
        if self.suffix.is_some() {
            id == self.intermediate_key_id()
                || id.starts_with(&format!(
                    "_IK_{}_{}_{}_",
                    self.id, self.service, self.product
                ))
        } else {
            id == self.intermediate_key_id()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_key_id_without_suffix() {
        let p = DefaultPartition::new("user1".into(), "svc".into(), "prod".into());
        assert_eq!(p.system_key_id(), "_SK_svc_prod");
    }

    #[test]
    fn system_key_id_with_suffix() {
        let p = DefaultPartition::new_suffixed(
            "user1".into(),
            "svc".into(),
            "prod".into(),
            "us-east-1".into(),
        );
        assert_eq!(p.system_key_id(), "_SK_svc_prod_us-east-1");
    }

    #[test]
    fn intermediate_key_id_without_suffix() {
        let p = DefaultPartition::new("user1".into(), "svc".into(), "prod".into());
        assert_eq!(p.intermediate_key_id(), "_IK_user1_svc_prod");
    }

    #[test]
    fn intermediate_key_id_with_suffix() {
        let p = DefaultPartition::new_suffixed(
            "user1".into(),
            "svc".into(),
            "prod".into(),
            "us-west-2".into(),
        );
        assert_eq!(p.intermediate_key_id(), "_IK_user1_svc_prod_us-west-2");
    }

    #[test]
    fn is_valid_ik_id_exact_match_no_suffix() {
        let p = DefaultPartition::new("u".into(), "s".into(), "p".into());
        assert!(p.is_valid_intermediate_key_id("_IK_u_s_p"));
        assert!(!p.is_valid_intermediate_key_id("_IK_u_s_p_extra"));
        assert!(!p.is_valid_intermediate_key_id("_IK_other_s_p"));
        assert!(!p.is_valid_intermediate_key_id(""));
    }

    #[test]
    fn is_valid_ik_id_with_suffix_accepts_prefix() {
        let p = DefaultPartition::new_suffixed("u".into(), "s".into(), "p".into(), "r1".into());
        // Exact match
        assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_r1"));
        // Prefix match (different suffix)
        assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_r2"));
        // Wrong partition id
        assert!(!p.is_valid_intermediate_key_id("_IK_other_s_p_r1"));
        // Must not accept non-suffixed IK (missing trailing delimiter)
        assert!(!p.is_valid_intermediate_key_id("_IK_u_s_p"));
    }

    #[test]
    fn different_partitions_produce_different_key_ids() {
        let p1 = DefaultPartition::new("a".into(), "svc".into(), "prod".into());
        let p2 = DefaultPartition::new("b".into(), "svc".into(), "prod".into());
        assert_eq!(p1.system_key_id(), p2.system_key_id());
        assert_ne!(p1.intermediate_key_id(), p2.intermediate_key_id());
    }
}
