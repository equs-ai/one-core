use serde::Deserialize;
use standardized_types::openid4vci::CredentialResponse;

use crate::provider::issuance_protocol::openid4vci_final1_0::model::IssuerMetadata;

/// Credential Response, extended with the Procivis-specific `redirectUri` parameter.
#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCICredentialResponseDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    #[serde(flatten)]
    pub standard: CredentialResponse,
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0IssuerMetadataResponseTypeEnum {
    Model,
    Jwt,
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0IssuerMetadataResponseEnum {
    Model(Box<IssuerMetadata>),
    Jwt(String),
}
