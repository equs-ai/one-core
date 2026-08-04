use std::sync::Arc;

use async_trait::async_trait;
use shared_types::EcosystemId;

use crate::config::core_config::{EcosystemProviderType, Fields};
use crate::error::NestedError;
use crate::provider::ecosystem::Ecosystem;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::provider_directory::{ProviderDirectory, ProviderError};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub(crate) trait EcosystemDirectory: Send + Sync {
    fn get(&self, name: &EcosystemId) -> Result<Arc<dyn Ecosystem>, NestedError>;

    fn auto_detect(
        &self,
        protocol_artifact: &ProtocolArtifact,
    ) -> Result<Arc<dyn Ecosystem>, NestedError>;
}

impl EcosystemDirectory
    for ProviderDirectory<EcosystemId, Fields<EcosystemProviderType>, dyn Ecosystem>
{
    fn get(&self, name: &EcosystemId) -> Result<Arc<dyn Ecosystem>, NestedError> {
        self.provider(name)
    }

    fn auto_detect(
        &self,
        protocol_artifact: &ProtocolArtifact,
    ) -> Result<Arc<dyn Ecosystem>, NestedError> {
        let (_, ecosystem) = self
            .iter()
            .find(|(_, e)| e.is_ecosystem_interaction(protocol_artifact))
            .ok_or(ProviderError::NoSuitableProvider {
                context: protocol_artifact.to_string(),
                provider_type: std::any::type_name::<dyn Ecosystem>().to_string(),
            })?;
        Ok(ecosystem.clone())
    }
}
