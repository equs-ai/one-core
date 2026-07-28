use serde::Deserialize;
use shared_types::TrustCollectionId;

use crate::provider::verifier::model::VerifierAppVersion;
use crate::service::managed_instance::dto::{
    UserAuthenticationDTO, WalletUnitAttestationMetadataDTO,
};

#[derive(Clone, Debug)]
pub struct VerifierProviderMetadataResponseDTO {
    pub name: String,
    pub app_version: Option<VerifierAppVersion>,
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub feature_flags: FeatureFlags,
    pub verifier_app_attestation: WalletUnitAttestationMetadataDTO,
    pub user_authentication: Option<UserAuthenticationDTO>,
    pub proof_schemas: Option<Vec<String>>,
    pub credential_schemas: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    pub trust_ecosystems_enabled: bool,
    pub access_certificate_provisioning_enabled: bool,
}

#[derive(Clone, Debug)]
pub struct ProviderTrustCollectionDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
    pub default_selected: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct DisplayNameDTO {
    pub lang: String,
    pub value: String,
}
