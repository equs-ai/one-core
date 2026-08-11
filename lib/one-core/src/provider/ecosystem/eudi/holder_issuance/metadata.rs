use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use standardized_types::etsi_119_475;
use standardized_types::openid4vci::{
    CredentialConfiguration, CredentialIssuerMetadata, IssuerInfoAttestation,
};
use standardized_types::openid4vp::dcql;
use url::Url;

use super::{HolderIssuanceError, HolderIssuanceResolver};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::proto::wrp_validator::model::AccessCertificateResult;
use crate::provider::ecosystem::model::IssuerMetadataRepresentation;
use crate::provider::issuance_protocol::serialize_interaction_data;

#[derive(Debug, PartialEq)]
struct ConfigurationTrustInfo {
    pub registration_certificate: Option<String>,
    pub national_registry_data: Option<String>,
    pub relying_party_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct MetadataInteractionData {
    pub registration_certificate: Option<String>,
    pub national_registry_data: Option<String>,
    pub relying_party_name: String,
    pub access_certificate: String,
}

impl HolderIssuanceResolver {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn resolve_metadata_trust(
        &self,
        interaction: &Interaction,
        issuer_metadata: &IssuerMetadataRepresentation,
        credential_configuration_ids: &[String],
    ) -> Result<(), HolderIssuanceError> {
        // only signed metadata allowed
        let (access_certificate_pem_chain, metadata) = match issuer_metadata {
            IssuerMetadataRepresentation::Unsigned(_) => {
                return Err(HolderIssuanceError::MissingIdentifier);
            }
            IssuerMetadataRepresentation::Signed(jwt) => {
                let Some(x5c) = &jwt.header.x5c else {
                    return Err(HolderIssuanceError::MissingIdentifier);
                };

                (
                    x5c_into_pem_chain(x5c).error_while("converting x5c")?,
                    &jwt.payload.custom,
                )
            }
        };

        let access_certificate = self
            .wrp_validator
            .validate_access_certificate(
                &access_certificate_pem_chain,
                Some(interaction.organisation.id()),
            )
            .await
            .error_while("validating access certificate")?;

        let mut configurations_info = None;
        for configuration_id in credential_configuration_ids {
            let configuration = metadata
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or(HolderIssuanceError::MissingIdentifier)?;

            let info = self
                .validate_credential_configuration(
                    configuration,
                    metadata,
                    interaction.organisation.id(),
                    &access_certificate,
                )
                .await?;

            if let Some(current_info) = &configurations_info {
                if current_info != &info {
                    return Err(HolderIssuanceError::InconsistentTrustInfo);
                }
            } else {
                configurations_info = Some(info);
            };
        }

        let Some(configurations_info) = configurations_info else {
            return Err(HolderIssuanceError::NoCredentialConfiguration);
        };

        let interaction_data = MetadataInteractionData {
            registration_certificate: configurations_info.registration_certificate,
            national_registry_data: configurations_info.national_registry_data,
            relying_party_name: configurations_info.relying_party_name,
            access_certificate: access_certificate_pem_chain,
        };

        let ecosystem_data = serialize_interaction_data(&interaction_data)
            .error_while("serializing interaction data")?;

        self.interaction_repository
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    ecosystem_data: Some(Some(ecosystem_data)),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;

        Ok(())
    }

    async fn validate_credential_configuration(
        &self,
        configuration: &CredentialConfiguration,
        metadata: &CredentialIssuerMetadata,
        organisation_id: OrganisationId,
        access_certificate: &AccessCertificateResult,
    ) -> Result<ConfigurationTrustInfo, HolderIssuanceError> {
        Ok(if metadata.issuer_info.is_empty() {
            let (national_registry_data, relying_party_name) = self
                .validate_credential_config_trust_against_registry(
                    configuration,
                    &access_certificate.relying_party_id,
                    access_certificate
                        .registry_url
                        .as_ref()
                        .ok_or(HolderIssuanceError::MissingRegistryUrl)?,
                    organisation_id,
                )
                .await?;

            ConfigurationTrustInfo {
                registration_certificate: None,
                national_registry_data: Some(national_registry_data),
                relying_party_name,
            }
        } else {
            let (registration_certificate, relying_party_name) = self
                .validate_credential_config_trust_with_registration_certificate(
                    configuration,
                    &metadata.issuer_info,
                    &access_certificate.relying_party_id,
                    organisation_id,
                )
                .await?;

            ConfigurationTrustInfo {
                registration_certificate: Some(registration_certificate),
                national_registry_data: None,
                relying_party_name,
            }
        })
    }

    async fn validate_credential_config_trust_against_registry(
        &self,
        credential_config: &CredentialConfiguration,
        relying_party_id: &str,
        registry_url: &Url,
        organisation_id: OrganisationId,
    ) -> Result<(String, String), HolderIssuanceError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(organisation_id),
                self.leeway,
            )
            .await
            .error_while("fetching from WRP registry")?;

        if !info
            .payload
            .custom
            .data
            .provides_attestations
            .iter()
            .any(|attestation| {
                credential_config_matches_reg_cert_attestation(credential_config, attestation)
            })
        {
            return Err(HolderIssuanceError::DisallowedCredentialConfiguration);
        };

        Ok((
            info.jwt,
            info.payload.custom.data.trade_name.unwrap_or_default(),
        ))
    }

    async fn validate_credential_config_trust_with_registration_certificate(
        &self,
        credential_config: &CredentialConfiguration,
        issuer_info: &[IssuerInfoAttestation],
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Result<(String, String), HolderIssuanceError> {
        for reg_cert in issuer_info {
            if let Some(relying_party_name) = self
                .credential_config_matches_reg_cert(
                    credential_config,
                    reg_cert,
                    expected_relying_party_id,
                    organisation_id,
                )
                .await
            {
                return Ok((reg_cert.data.to_owned(), relying_party_name));
            }
        }

        Err(HolderIssuanceError::DisallowedCredentialConfiguration)
    }

    async fn credential_config_matches_reg_cert(
        &self,
        credential_config: &CredentialConfiguration,
        issuer_info: &IssuerInfoAttestation,
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Option<String> {
        let Ok(reg_cert) = self
            .wrp_validator
            .validate_registration_certificate(
                &issuer_info.data,
                expected_relying_party_id,
                Some(organisation_id),
                self.leeway,
            )
            .await
        else {
            return None;
        };

        let provides_attestations = reg_cert.payload.custom.provides_attestations?;

        if provides_attestations.iter().any(|attestation| {
            credential_config_matches_reg_cert_attestation(credential_config, attestation)
        }) {
            Some(reg_cert.payload.custom.name)
        } else {
            None
        }
    }
}

fn credential_config_matches_reg_cert_attestation(
    credential_config: &CredentialConfiguration,
    reg_cert_attestation: &etsi_119_475::Credential,
) -> bool {
    if credential_config.format != reg_cert_attestation.format.dcql_format() {
        return false;
    }

    match &reg_cert_attestation.format {
        dcql::CredentialFormat::MsoMdoc(meta) => credential_config
            .doctype
            .as_ref()
            .is_some_and(|doctype| doctype == &meta.doctype_value),
        dcql::CredentialFormat::SdJwt(meta) => credential_config
            .vct
            .as_ref()
            .is_some_and(|vct| meta.vct_values.contains(vct)),
        dcql::CredentialFormat::JwtVc(meta)
        | dcql::CredentialFormat::W3cSdJwt(meta)
        | dcql::CredentialFormat::LdpVc(meta) => credential_config
            .credential_definition
            .as_ref()
            .is_some_and(|credential_definition| {
                // TODO: support context expansion
                meta.type_values.iter().any(|types| {
                    credential_definition
                        .r#type
                        .iter()
                        .all(|r#type| types.contains(r#type))
                })
            }),
    }
}
