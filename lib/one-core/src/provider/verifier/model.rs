use std::collections::HashMap;

use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{
    CredentialSchemaId, IdentifierId, OrganisationId, ProofSchemaId, TrustCollectionId,
};
use time::Duration;

use crate::service::managed_instance::dto::{
    UserAuthenticationParams, WalletInstanceAttestationParams,
};

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifierParams {
    pub app_version: Option<VerifierAppVersion>,
    #[serde(default)]
    pub trust_collections: HashMap<TrustCollectionId, TrustCollectionParams>,
    pub feature_flags: ConfigFeatureFlags,
    pub verifier_instance_attestation: Option<WalletInstanceAttestationParams>,
    pub user_authentication: Option<UserAuthenticationParams>,
    #[serde(default)]
    pub proof_schemas: Vec<ProofSchemaId>,
    #[serde(default)]
    pub credential_schemas: Vec<CredentialSchemaId>,
    pub access_certificate_configuration: Option<AccessCertificateConfiguration>,
    // Defaulted so existing verifierProvider config entries without this key keep working.
    #[serde(default = "default_device_auth_leeway")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway: Duration,
}

fn default_device_auth_leeway() -> Duration {
    Duration::seconds(60)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigFeatureFlags {
    pub trust_ecosystems_enabled: bool,
}

#[expect(unused)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessCertificateConfiguration {
    pub provider_url: String,
    pub organisation_id: OrganisationId,
    pub relying_party_public_identifier: String,
    pub relying_party_national_registry: String,
    pub issuer_id: IdentifierId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierAppVersion {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    pub update_screen: Option<VerifierUpdateScreen>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierUpdateScreen {
    pub link: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustCollectionParams {
    pub logo: String,
    pub display_name: HashMap<String, String>,
    pub description: HashMap<String, String>,
    pub default_selected: Option<bool>,
}
