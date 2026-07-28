use crate::model::instance::{Instance, WalletProviderType};
use crate::service::managed_instance::dto::IssueWalletUnitAttestationResponseDTO;

#[derive(Clone, Debug)]
pub enum IssueWalletAttestationResponse {
    Active(IssueWalletUnitAttestationResponseDTO),
    Revoked,
}

#[derive(Clone, Debug)]
pub struct MetadataTarget {
    pub r#type: WalletProviderType,
    pub metadata_url: String,
}

impl From<Instance> for MetadataTarget {
    fn from(value: Instance) -> Self {
        let Instance {
            provider_url,
            provider_type,
            provider_name,
            ..
        } = value;
        Self {
            r#type: provider_type,
            metadata_url: format!("{provider_url}/ssi/wallet-provider/v1/{provider_name}"),
        }
    }
}
