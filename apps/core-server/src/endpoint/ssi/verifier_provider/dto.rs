use one_core::provider::verifier::model::{VerifierAppVersion, VerifierUpdateScreen};
use one_core::service::verifier_provider::dto::{
    DisplayNameDTO, FeatureFlags, ProviderTrustCollectionDTO, VerifierProviderMetadataResponseDTO,
};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use shared_types::TrustCollectionId;
use utoipa::ToSchema;

use crate::endpoint::ssi::wallet_provider::dto::{
    UserAuthenticationRestDTO, WalletUnitAttestationMetadataRestDTO,
};

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierProviderMetadataResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifierProviderResponseRestDTO {
    // ONE-9505: only present for backwards compatibility with old verifier apps
    // can be removed once all verifier apps updated with latest core
    #[deprecated]
    #[from(replace = "\"PROCIVIS_ONE\"")]
    pub verifier_name: String,

    pub name: String,
    #[from(with_fn = convert_inner)]
    pub app_version: Option<VerifierProviderAppVersionResponseDTO>,
    #[from(with_fn = convert_inner)]
    pub trust_collections: Vec<ProviderTrustCollectionRestDTO>,
    pub feature_flags: VerifierFeatureFlagsRestDTO,

    pub verifier_app_attestation: WalletUnitAttestationMetadataRestDTO,
    #[from(with_fn = convert_inner)]
    pub user_authentication: Option<UserAuthenticationRestDTO>,
    /// proof schema `importSourceUrl`'s
    pub proof_schemas: Option<Vec<String>>,
    /// credential schema `importSourceUrl`'s
    pub credential_schemas: Option<Vec<String>>,
}

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierAppVersion)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderAppVersionResponseDTO {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub update_screen: Option<VerifierProviderUpdateScreenResponseDTO>,
}

#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierUpdateScreen)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderUpdateScreenResponseDTO {
    pub link: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(FeatureFlags)]
pub struct VerifierFeatureFlagsRestDTO {
    pub trust_ecosystems_enabled: bool,
    pub access_certificate_provisioning_enabled: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProviderTrustCollectionDTO)]
pub(crate) struct ProviderTrustCollectionRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
    pub default_selected: Option<bool>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DisplayNameDTO)]
pub(crate) struct DisplayNameRestDTO {
    pub lang: String,
    pub value: String,
}
