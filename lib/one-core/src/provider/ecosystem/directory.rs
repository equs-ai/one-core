use std::sync::Arc;

use async_trait::async_trait;
use shared_types::EcosystemId;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, EcosystemProviderType, Fields};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::provider::ecosystem::Ecosystem;
use crate::provider::ecosystem::eudi::EudiEcosystem;
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

pub(crate) fn ecosystem_directory_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn EcosystemDirectory>, ConfigValidationError> {
    let directory = ProviderDirectory::initialize(
        config.ecosystem.iter_mut(),
        |name: &EcosystemId, fields: &Fields<EcosystemProviderType>| {
            let ecosystem: Arc<dyn Ecosystem> = match fields.r#type {
                EcosystemProviderType::Eudi => {
                    Arc::new(EudiEcosystem::new(name.clone(), fields.merge_fields())?)
                }
            };

            Ok(ecosystem)
        },
    )
    .error_while("initializing ecosystem providers")?;

    Ok(Arc::new(directory))
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::config::core_config::{ConfigEntryDisplay, Params};
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::provider::ecosystem::model::EcosystemRole;

    fn fields() -> Fields<EcosystemProviderType> {
        Fields {
            r#type: EcosystemProviderType::Eudi,
            display: ConfigEntryDisplay::from("ecosystem.eudi"),
            order: Some(1),
            priority: None,
            enabled: false,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({ "logo": "logo", "description": { "en": "EUDI ecosystem" } })),
                private: None,
            }),
        }
    }

    fn config() -> CoreConfig {
        let mut config = CoreConfig::default();
        config.ecosystem.insert("EUDI".into(), fields());
        config
    }

    #[test]
    fn disabled_ecosystem_rejects_interactions() {
        let mut config = config();

        let directory = ecosystem_directory_from_config(&mut config).unwrap();

        let ecosystem = directory.get(&"EUDI".into()).unwrap();
        assert_eq!(
            ecosystem.lifecycle_hook().unwrap_err().error_code(),
            ErrorCode::BR_0431
        );
        assert_eq!(
            ecosystem.get_capabilities().ecosystem_roles.first(),
            Some(&EcosystemRole::Holder)
        );
    }

    #[test]
    fn disabled_ecosystem_is_not_auto_detected() {
        let mut config = config();

        let directory = ecosystem_directory_from_config(&mut config).unwrap();

        let Err(error) = directory.auto_detect(&ProtocolArtifact::IssuerIssuance {}) else {
            panic!("expected no suitable provider error");
        };
        assert_eq!(error.error_code(), ErrorCode::BR_0478);
    }
}
