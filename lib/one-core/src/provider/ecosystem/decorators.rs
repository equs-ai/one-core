use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
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
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn Ecosystem {
    fn decorate(self: Arc<dyn Ecosystem>) -> Arc<dyn Ecosystem> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait]
impl<T: Ecosystem + Display + ?Sized> Ecosystem for DisabledProvider<T> {
    fn config_name(&self) -> &EcosystemId {
        self.inner().config_name()
    }

    fn get_capabilities(&self) -> EcosystemCapabilities {
        self.inner().get_capabilities()
    }

    fn is_ecosystem_interaction(&self, _protocol_artifact: &ProtocolArtifact) -> bool {
        false
    }

    async fn validate_interaction(
        &self,
        _interaction_artifact: &ProtocolArtifact,
        _organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        self.disabled_error()
    }

    fn identifier_filter(
        &self,
        _role: EcosystemRole,
        _schema: Option<SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        self.disabled_error()
    }

    fn issuer_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError> {
        self.disabled_error()
    }

    fn verifier_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError> {
        self.disabled_error()
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        self.disabled_error()
    }
}
