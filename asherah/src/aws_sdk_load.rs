//! Shared [`aws_config::defaults`] loader for KMS, DynamoDB, Secrets Manager.

use aws_config::meta::region::RegionProviderChain;
use aws_types::SdkConfig;

/// Load SDK config with optional named profile (`aws-config` credential chain).
pub(crate) async fn load_sdk_config(
    region_provider: RegionProviderChain,
    profile_name: Option<&str>,
) -> SdkConfig {
    let mut loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);
    if let Some(p) = profile_name {
        loader = loader.profile_name(p);
    }
    loader.load().await
}
