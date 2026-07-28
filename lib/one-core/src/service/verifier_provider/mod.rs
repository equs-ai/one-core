use std::sync::Arc;

use dto::{ProviderTrustCollectionDTO, VerifierProviderMetadataResponseDTO};
use error::VerifierProviderError;
use mapper::params_into_display_names;
use one_dto_mapper::convert_inner;

use crate::error::ContextWithErrorCode;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::trust_collection::TrustCollectionFilterValue;
use crate::provider::verifier::provider::VerifierProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::managed_instance::dto::WalletUnitAttestationMetadataDTO;
use crate::service::proof_schema::dto::ProofSchemaFilterValue;
use crate::service::verifier_provider::dto::FeatureFlags;

pub mod dto;
pub mod error;
mod mapper;

pub struct VerifierProviderService {
    verifier_provider: Arc<dyn VerifierProvider>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
}

impl VerifierProviderService {
    pub(crate) fn new(
        verifier_provider: Arc<dyn VerifierProvider>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    ) -> Self {
        Self {
            verifier_provider,
            trust_collection_repository,
            credential_schema_repository,
            proof_schema_repository,
        }
    }

    pub async fn get_verifier_by_id(
        &self,
        id: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        let verifier = self
            .verifier_provider
            .get_by_id(id)
            .error_while("getting verifier provider")?;

        let trust_collections = if verifier.trust_collections.is_empty() {
            vec![]
        } else {
            let models = self
                .trust_collection_repository
                .list(ListQuery {
                    filtering: Some(
                        TrustCollectionFilterValue::Ids(
                            verifier.trust_collections.keys().cloned().collect(),
                        )
                        .condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting trust collections")?
                .values;

            verifier
                .trust_collections
                .into_iter()
                .map(|(collection_id, params)| {
                    let model = models.iter().find(|m| m.id == collection_id).ok_or(
                        VerifierProviderError::MappingError(format!(
                            "Missing collection {}",
                            collection_id
                        )),
                    )?;

                    Ok(ProviderTrustCollectionDTO {
                        id: collection_id,
                        name: model.name.to_owned(),
                        logo: params.logo,
                        display_name: params_into_display_names(params.display_name),
                        description: params_into_display_names(params.description),
                        default_selected: params.default_selected,
                    })
                })
                .collect::<Result<_, VerifierProviderError>>()?
        };

        let credential_schemas = if verifier.credential_schemas.is_empty() {
            None
        } else {
            let models = self
                .credential_schema_repository
                .get_credential_schema_list(ListQuery {
                    filtering: Some(
                        CredentialSchemaFilterValue::CredentialSchemaIds(
                            verifier.credential_schemas,
                        )
                        .condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting credential schemas")?
                .values;

            let result: Vec<String> = models.into_iter().map(|m| m.imported_source_url).collect();
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        };

        let proof_schemas = if verifier.proof_schemas.is_empty() {
            None
        } else {
            let models = self
                .proof_schema_repository
                .get_proof_schema_list(ListQuery {
                    filtering: Some(
                        ProofSchemaFilterValue::ProofSchemaIds(verifier.proof_schemas).condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting proof schemas")?
                .values;

            let result: Vec<String> = models
                .into_iter()
                .flat_map(|m| m.imported_source_url)
                .collect();
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        };

        let verifier_app_attestation = {
            let (enabled, app_integrity_check_required) =
                match verifier.verifier_instance_attestation {
                    Some(attestation) => (true, attestation.integrity_check.enabled),
                    None => (false, false),
                };
            WalletUnitAttestationMetadataDTO {
                app_integrity_check_required,
                enabled,
                required: false,
            }
        };

        Ok(VerifierProviderMetadataResponseDTO {
            name: id.to_string(),
            app_version: verifier.app_version,
            trust_collections,
            verifier_app_attestation,
            user_authentication: convert_inner(verifier.user_authentication),
            feature_flags: FeatureFlags {
                trust_ecosystems_enabled: verifier.feature_flags.trust_ecosystems_enabled,
                access_certificate_provisioning_enabled: verifier
                    .access_certificate_configuration
                    .is_some(),
            },
            credential_schemas,
            proof_schemas,
        })
    }
}
