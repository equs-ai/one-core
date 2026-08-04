use std::fmt::{Display, Formatter};

use serde::Serialize;
use shared_types::{CredentialSchemaId, EcosystemId, ProofSchemaId};

use crate::service::common_dto::EudiTrustInformationResponseDTO;

#[derive(Debug, Serialize, PartialEq, Eq)]
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

pub enum ProtocolArtifact {
    /// As holder, protocol artifacts about the issuance & issuer
    HolderIssuance {
        // todo issuer metadata / access cert
    },
    /// As holder, protocol artifacts about the proof-request & verifier
    HolderProof {
        // todo verifier access cert
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
            ProtocolArtifact::HolderIssuance { .. } => {
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
