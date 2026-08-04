//! Credential Request
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::iana::EncryptionAlgorithm;
use crate::jwe::CompressionAlgorithm;
use crate::jwk::PublicJwk;

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialRequest {
    #[serde(flatten)]
    pub credential: CredentialRequestIdentifier,
    pub proofs: Option<Proofs>,
    pub credential_response_encryption: Option<ResponseEncryption>,
}

/// Exactly one of `credential_configuration_id` or `credential_identifier` identifies the
/// requested Credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum CredentialRequestIdentifier {
    CredentialConfigurationId(String),
    CredentialIdentifier(String),
}

/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Proofs {
    Jwt(Vec<String>),
    DiVp(Vec<String>),
    Attestation([String; 1]),
}

/// Encryption parameters the Wallet requests the Credential Response to be encrypted with.
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ResponseEncryption {
    pub jwk: PublicJwk,
    pub enc: EncryptionAlgorithm,
    pub zip: Option<CompressionAlgorithm>,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_credential_request_identifier_is_flattened() {
        let request = CredentialRequest {
            credential: CredentialRequestIdentifier::CredentialConfigurationId(
                "UniversityDegree".to_string(),
            ),
            proofs: Some(Proofs::Jwt(vec!["eyJ0eXAi".to_string()])),
            credential_response_encryption: None,
        };

        assert_eq!(
            serde_json::json!({
                "credential_configuration_id": "UniversityDegree",
                "proofs": { "jwt": ["eyJ0eXAi"] }
            }),
            serde_json::to_value(&request).unwrap()
        );
    }

    #[test]
    fn test_proofs_variant_names() {
        assert_eq!(
            serde_json::json!({ "di_vp": ["proof"] }),
            serde_json::to_value(Proofs::DiVp(vec!["proof".to_string()])).unwrap()
        );
        assert_eq!(
            serde_json::json!({ "attestation": ["attestation-jwt"] }),
            serde_json::to_value(Proofs::Attestation(["attestation-jwt".to_string()])).unwrap()
        );
    }

    #[test]
    fn test_unrecognized_request_parameters_are_accepted() {
        // "Additional Credential Request parameters MAY be defined and used."
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
        let request: CredentialRequest = serde_json::from_value(serde_json::json!({
            "credential_configuration_id": "UniversityDegree",
            "proofs": { "jwt": ["eyJ0eXAi"] },
            "some_future_extension": { "a": 1 }
        }))
        .unwrap();

        assert_eq!(
            CredentialRequestIdentifier::CredentialConfigurationId("UniversityDegree".to_string()),
            request.credential
        );
        assert_eq!(
            Some(Proofs::Jwt(vec!["eyJ0eXAi".to_string()])),
            request.proofs
        );
    }

    #[test]
    fn test_credential_identifier_variant_name() {
        let identifier: CredentialRequestIdentifier =
            serde_json::from_value(serde_json::json!({ "credential_identifier": "cred-1" }))
                .unwrap();
        assert_eq!(
            CredentialRequestIdentifier::CredentialIdentifier("cred-1".to_string()),
            identifier
        );
    }
}
