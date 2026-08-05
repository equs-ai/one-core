#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::{EcosystemId, OrganisationId};

use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::list_filter::ListFilterCondition;
use crate::provider::Provider;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{
    EcosystemCapabilities, EcosystemRole, IssuerTrustDetails, ProtocolArtifact, SchemaFilter,
    VerifierTrustDetails,
};

pub(crate) mod decorators;
pub(crate) mod directory;
pub mod error;
pub mod model;

pub(crate) mod eudi;

#[provider_mock]
#[async_trait]
pub trait Ecosystem: Provider + Send + Sync {
    fn config_name(&self) -> &EcosystemId;

    fn get_capabilities(&self) -> EcosystemCapabilities;

    fn is_ecosystem_interaction(&self, protocol_artifact: &ProtocolArtifact) -> bool;

    async fn validate_interaction(
        &self,
        interaction_artifact: &ProtocolArtifact,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError>;

    fn identifier_filter(
        &self,
        role: EcosystemRole,
        schema: Option<SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError>;

    fn issuer_trust_details(
        &self,
        credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError>;

    fn verifier_trust_details(
        &self,
        credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError>;

    fn lifecycle_hook(&self) -> Result<(), EcosystemError>;
}

impl Display for dyn Ecosystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ecosystem `{}`", self.config_name())
    }
}
