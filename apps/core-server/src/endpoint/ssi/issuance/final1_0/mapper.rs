use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    CredentialConfigurationData, CredentialDisplayWithDesign, IssuerMetadata,
    OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign,
};
use one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum;
use one_core::service::oid4vci_final1_0::dto::OpenID4VCICredentialResponseDTO;
use one_core::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use standardized_types::oauth2::token::TokenRequest;

use super::dto::{
    OpenID4VCIFinal1CredentialResponseRestDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO,
    OpenID4VCIIssuerMetadataResponseRestDTO, OpenID4VCITokenRequestRestDTO,
};
use crate::endpoint::ssi::issuance::final1_0::dto::OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO;

impl From<IssuerMetadata> for OpenID4VCIIssuerMetadataResponseRestDTO {
    fn from(value: IssuerMetadata) -> Self {
        Self {
            credential_issuer: value.credential_issuer,
            authorization_servers: value.authorization_servers,
            credential_endpoint: value.credential_endpoint,
            notification_endpoint: value.notification_endpoint,
            credential_configurations_supported: value
                .credential_configurations_supported
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            display: convert_inner_of_inner(value.display),
            nonce_endpoint: value.nonce_endpoint,
            issuer_info: value.issuer_info,
            batch_credential_issuance: convert_inner(value.batch_credential_issuance),
        }
    }
}

impl From<OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign>
    for OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO
{
    fn from(value: OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign) -> Self {
        Self {
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code_attribute: value.code_attribute,
            code_type: convert_inner(value.code_type.map(CredentialSchemaCodeTypeEnum::from)),
        }
    }
}

impl TryFrom<OpenID4VCITokenRequestRestDTO> for TokenRequest {
    type Error = OID4VCIFinal1_0ServiceError;

    fn try_from(value: OpenID4VCITokenRequestRestDTO) -> Result<Self, Self::Error> {
        match (
            value.grant_type.as_str(),
            value.pre_authorized_code,
            value.refresh_token,
            value.tx_code,
        ) {
            (
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                Some(pre_authorized_code),
                None,
                tx_code,
            ) => Ok(Self::PreAuthorizedCode {
                pre_authorized_code,
                tx_code,
            }),
            ("refresh_token", None, Some(refresh_token), None) => {
                Ok(Self::RefreshToken { refresh_token })
            }
            ("urn:ietf:params:oauth:grant-type:pre-authorized_code" | "refresh_token", _, _, _) => {
                Err(OpenID4VCIError::InvalidRequest.into())
            }
            (grant, _, _, _) if !grant.is_empty() => {
                Err(OpenID4VCIError::UnsupportedGrantType.into())
            }
            _ => Err(OpenID4VCIError::InvalidRequest.into()),
        }
    }
}

impl From<CredentialConfigurationData>
    for OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO
{
    fn from(value: CredentialConfigurationData) -> Self {
        Self {
            format: value.format,
            doctype: value.doctype,
            vct: value.vct,
            credential_metadata: convert_inner(value.credential_metadata),
            scope: value.scope,
            cryptographic_binding_methods_supported: value.cryptographic_binding_methods_supported,
            credential_signing_alg_values_supported: convert_inner_of_inner(
                value.credential_signing_alg_values_supported,
            ),
            proof_types_supported: value.proof_types_supported,
            credential_definition: convert_inner(value.credential_definition),
            disclosure_policy: value.disclosure_policy,
        }
    }
}

impl From<CredentialDisplayWithDesign>
    for OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO
{
    fn from(value: CredentialDisplayWithDesign) -> Self {
        let procivis_design = value.procivis_design;
        let value = value.standard;
        Self {
            name: value.name,
            locale: value.locale,
            logo: convert_inner(value.logo),
            description: value.description,
            background_color: value.background_color,
            background_image: convert_inner(value.background_image),
            text_color: value.text_color,
            procivis_design: convert_inner(procivis_design),
        }
    }
}

impl From<OpenID4VCICredentialResponseDTO> for OpenID4VCIFinal1CredentialResponseRestDTO {
    fn from(value: OpenID4VCICredentialResponseDTO) -> Self {
        let redirect_uri = value.redirect_uri;
        let value = value.standard;
        Self {
            redirect_uri,
            credentials: convert_inner_of_inner(value.credentials),
            transaction_id: value.transaction_id,
            interval: value.interval,
            notification_id: value.notification_id,
        }
    }
}
