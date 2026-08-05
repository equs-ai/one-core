use std::fmt::{Display, Formatter};

use serde::Serialize;
use shared_types::{CredentialSchemaId, EcosystemId, ProofSchemaId};
use standardized_types::openid4vci::CredentialIssuerMetadata;
use standardized_types::openid4vp::VerifierInfoAttestation;
use standardized_types::openid4vp::dcql::DcqlQuery;

use crate::model::credential::Credential;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::service::common_dto::EudiTrustInformationResponseDTO;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemCapabilities {
    pub ecosystem_roles: Vec<EcosystemRole>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EcosystemRole {
    Holder,
    Issuer,
    Verifier,
    PidProvider,
    NationalRegistryRegistrar,
    WalletProvider,
}

#[derive(Debug)]
pub enum IssuerMetadataRepresentation {
    Signed(Box<DecomposedJwt<CredentialIssuerMetadata>>),
    Unsigned(Box<CredentialIssuerMetadata>),
}

impl IssuerMetadataRepresentation {
    fn metadata(&self) -> &CredentialIssuerMetadata {
        match &self {
            Self::Signed(jwt) => &jwt.payload.custom,
            Self::Unsigned(metadata) => metadata,
        }
    }
}

#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ProtocolArtifact {
    /// As holder, protocol artifacts about the issuance & issuer
    HolderIssuanceInvitation {
        issuer_metadata: IssuerMetadataRepresentation,
        credential_configuration_ids: Vec<String>,
    },
    HolderIssuanceCredential {
        credential: Credential,
    },
    /// As holder, protocol artifacts about the proof-request & verifier
    HolderProof {
        verifier_details: Option<IdentifierDetails>,
        dcql_query: DcqlQuery,
        verifier_info: Vec<VerifierInfoAttestation>,
    },
    /// As issuer, protocol artifacts of the holder
    IssuerIssuance {
        // todo wallet unit attestation
    },
    /// As verifier, protocol artifacts of a proof-request
    Verifier {
        // todo presentation
    },
}

impl Display for ProtocolArtifact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolArtifact::HolderIssuanceInvitation { .. }
            | ProtocolArtifact::HolderIssuanceCredential { .. } => {
                write!(f, "Protocol interaction holder -> issuer")
            }
            ProtocolArtifact::HolderProof { .. } => {
                write!(f, "Protocol interaction holder -> verifier")
            }
            ProtocolArtifact::IssuerIssuance { .. } => {
                write!(f, "Protocol interaction issuer -> holder")
            }
            ProtocolArtifact::Verifier { .. } => {
                write!(f, "Protocol interaction verifier -> issuer")
            }
        }
    }
}

pub enum SchemaFilter {
    CredentialSchema(CredentialSchemaId),
    ProofSchema(ProofSchemaId),
}

pub struct IssuerTrustDetails {
    pub ecosystem: EcosystemId,
    pub issuer: EcosystemTrustDetail,
}

pub struct VerifierTrustDetails {
    pub ecosystem: EcosystemId,
    pub verifier: EcosystemTrustDetail,
}

pub enum EcosystemTrustDetail {
    Eudi(EudiTrustInformationResponseDTO),
}
