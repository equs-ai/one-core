use async_trait::async_trait;
use proc_macros::Provider;
use serde::Deserialize;
use shared_types::{EcosystemId, OrganisationId};

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, IssuerTrustDetails, ProtocolArtifact, SchemaFilter,
    VerifierTrustDetails,
};
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::list_filter::ListFilterCondition;
use crate::provider::provider_directory::InitializationError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    // TODO
}

#[derive(Provider)]
pub struct EudiEcosystem {
    config_id: EcosystemId,
    params: Params,
}

impl EudiEcosystem {
    pub(crate) fn new(
        config_id: EcosystemId,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self { config_id, params })
    }
}

#[async_trait]
impl Ecosystem for EudiEcosystem {
    fn config_name(&self) -> &EcosystemId {
        &self.config_id
    }

    fn get_capabilities(&self) -> EcosystemCapabilities {
        EcosystemCapabilities {
            ecosystem_roles: vec![
                EcosystemRole::Holder,
                EcosystemRole::Issuer,
                EcosystemRole::Verifier,
                EcosystemRole::PidProvider,
                EcosystemRole::NationalRegistryRegistrar,
                EcosystemRole::WalletProvider,
            ],
        }
    }

    fn is_ecosystem_interaction(&self, _protocol_artifact: &ProtocolArtifact) -> bool {
        todo!()
    }

    async fn validate_interaction(
        &self,
        _interaction_artifact: &ProtocolArtifact,
        _organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        todo!()
    }

    fn identifier_filter(
        &self,
        _role: EcosystemRole,
        _schema: Option<SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        todo!()
    }

    fn issuer_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError> {
        todo!()
    }

    fn verifier_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError> {
        todo!()
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        todo!()
    }
}
