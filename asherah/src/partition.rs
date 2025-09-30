use crate::traits::Partition;

#[derive(Clone)]
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
                    "_IK_{}_{}_{}",
                    self.id, self.service, self.product
                ))
        } else {
            id == self.intermediate_key_id()
        }
    }
}
